//! Per-channel audio isolation for Discord <-> SIP audio routing
//!
//! This module handles:
//! - Custom buffer ports for per-channel Discord->SIP audio
//! - Channel registration and call mapping
//! - Audio buffer management

use super::ffi::frame_utils::get_conference_bridge;
use super::ffi::types::*;
use crate::services::snowflake::Snowflake;
use dashmap::DashMap;
use parking_lot::{Mutex, RwLock};
use pjsua::*;
use rtrb::Consumer;
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

// Discord→SIP ring buffer consumers (written by Discord, read by audio thread)

/// Per-channel ring buffer consumers for the Discord→SIP audio path.
/// VoiceReceiver writes resampled i16 mono @ 16kHz directly to the producer side.
/// channel_port_get_frame reads from the consumer side here.
static DISCORD_TO_SIP_CONSUMERS: OnceLock<DashMap<Snowflake, Mutex<Consumer<i16>>>> =
    OnceLock::new();

fn get_discord_to_sip_consumers() -> &'static DashMap<Snowflake, Mutex<Consumer<i16>>> {
    DISCORD_TO_SIP_CONSUMERS.get_or_init(DashMap::new)
}

/// Register a ring buffer consumer for Discord→SIP audio on a channel.
pub fn register_discord_to_sip(channel_id: Snowflake, consumer: Consumer<i16>) {
    tracing::debug!(
        "Registering Discord→SIP ring buffer consumer for channel {}",
        channel_id
    );
    get_discord_to_sip_consumers().insert(channel_id, Mutex::new(consumer));
}

/// Unregister the ring buffer consumer for a channel.
pub fn unregister_discord_to_sip(channel_id: Snowflake) {
    tracing::debug!(
        "Unregistering Discord→SIP ring buffer consumer for channel {}",
        channel_id
    );
    get_discord_to_sip_consumers().remove(&channel_id);
}

// Custom buffer port callbacks for per-channel Discord->SIP audio

/// Custom get_frame callback for channel buffer ports
/// Called by PJSUA/conference bridge to pull audio for RTP transmission
///
/// This is called by PJSUA from its own thread during RTP transmission.
/// With multiple callers in the same channel, PJSUA calls this multiple times
/// (once per call) within microseconds. Without caching, N callers would drain
/// N*320 samples per 20ms tick, emptying the buffer N times faster than it fills.
///
/// Time-based caching ensures all callers in the same tick share the same audio frame.
pub unsafe extern "C" fn channel_port_get_frame(
    this_port: *mut pjmedia_port,
    frame: *mut pjmedia_frame,
) -> pj_status_t {
    use std::sync::atomic::AtomicU64;

    static GET_FRAME_CALL_COUNT: AtomicU64 = AtomicU64::new(0);
    static CACHE_HIT_COUNT: AtomicU64 = AtomicU64::new(0);
    let call_count = GET_FRAME_CALL_COUNT.fetch_add(1, Ordering::Relaxed);

    // Log first 10 calls to confirm this callback is being invoked
    if call_count < 10 {
        tracing::trace!(
            "channel_port_get_frame called (call #{}, port={:p})",
            call_count,
            this_port
        );
    } else if call_count == 10 {
        tracing::trace!("channel_port_get_frame: suppressing further per-call logs");
    }

    if this_port.is_null() || frame.is_null() {
        return -1; // PJ_EINVAL
    }

    let channel_id = unsafe { Snowflake::new((*this_port).port_data.ldata as u64) };
    if *channel_id == 0 {
        unsafe {
            (*frame).type_ = pjmedia_frame_type_PJMEDIA_FRAME_TYPE_NONE;
            (*frame).size = 0;
        }
        return pj_constants__PJ_SUCCESS as pj_status_t;
    }

    // Time-based caching to prevent multi-caller drain
    // If called within 15ms of last drain, return cached samples
    let now = Instant::now();
    let cache_window = Duration::from_millis(15); // PJSUA sends RTP every 20ms

    let cache = CHANNEL_DRAIN_CACHE.get_or_init(DashMap::new);

    // Stack-allocated buffer for fresh samples (zero heap allocation on miss path)
    let mut stack_buf = [0i16; SAMPLES_PER_FRAME];

    // Check cache first - if valid, return cached samples (cheap Arc::clone)
    let (samples_ptr, samples_len): (*const i16, usize) = if let Some(entry) =
        cache.get(&channel_id)
    {
        let (last_time, cached, cached_len) = entry.value();
        if now.duration_since(*last_time) < cache_window {
            // Cache hit - use cached Arc data directly (zero-copy)
            let hits = CACHE_HIT_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
            if call_count.is_multiple_of(500) {
                tracing::trace!(
                    "channel_port_get_frame #{}: CACHE HIT for channel={} ({}ms since last drain, {} total hits)",
                    call_count,
                    channel_id,
                    now.duration_since(*last_time).as_millis(),
                    hits
                );
            }
            (cached.as_ptr(), *cached_len)
        } else {
            // Cache expired - need to drop the read ref before draining
            drop(entry);

            // Drain fresh samples into stack buffer
            let n = get_samples_from_buffer(channel_id, &mut stack_buf);
            // Store in cache as Arc<[i16]> (single allocation for Arc+data)
            let fresh_arc: Arc<[i16]> = Arc::from(&stack_buf[..n]);
            cache.insert(channel_id, (now, fresh_arc, n));

            if call_count.is_multiple_of(500) {
                tracing::trace!(
                    "channel_port_get_frame #{}: channel={}, drained {} samples (cache expired)",
                    call_count,
                    channel_id,
                    n
                );
            }
            (stack_buf.as_ptr(), n)
        }
    } else {
        // No cache entry - drain fresh samples into stack buffer
        let n = get_samples_from_buffer(channel_id, &mut stack_buf);
        let fresh_arc: Arc<[i16]> = Arc::from(&stack_buf[..n]);
        cache.insert(channel_id, (now, fresh_arc, n));

        if call_count.is_multiple_of(500) {
            tracing::trace!(
                "channel_port_get_frame #{}: channel={}, drained {} samples (no cache)",
                call_count,
                channel_id,
                n
            );
        }
        (stack_buf.as_ptr(), n)
    };

    // Log cache statistics periodically (every 10 seconds at 50 calls/sec)
    if call_count.is_multiple_of(500) {
        let hits = CACHE_HIT_COUNT.load(Ordering::Relaxed);
        let hit_rate = (hits * 100).checked_div(call_count).unwrap_or(0);
        tracing::trace!(
            "channel_port_get_frame stats: {} calls, {} cache hits ({}% hit rate)",
            call_count,
            hits,
            hit_rate
        );
    }

    if samples_len > 0 {
        let samples = unsafe { std::slice::from_raw_parts(samples_ptr, samples_len) };
        unsafe { super::ffi::frame_utils::fill_audio_frame(frame, samples) };
    } else {
        unsafe { super::ffi::frame_utils::fill_silence_frame(frame) };
    }

    pj_constants__PJ_SUCCESS as pj_status_t
}

/// Get samples from the Discord→SIP ring buffer for a channel.
/// Fills the caller-provided buffer and returns the number of samples written.
/// `buf` must be at least SAMPLES_PER_FRAME in length.
fn get_samples_from_buffer(channel_id: Snowflake, buf: &mut [i16; SAMPLES_PER_FRAME]) -> usize {
    use std::sync::atomic::AtomicU64;
    static DRAIN_COUNT: AtomicU64 = AtomicU64::new(0);
    static UNDERRUN_COUNT: AtomicU64 = AtomicU64::new(0);

    if let Some(consumer_entry) = get_discord_to_sip_consumers().get(&channel_id)
        && let Some(mut consumer) = consumer_entry.try_lock()
    {
        let available = consumer.slots();
        if available >= SAMPLES_PER_FRAME {
            let count = DRAIN_COUNT.fetch_add(1, Ordering::Relaxed);
            if count.is_multiple_of(250) {
                tracing::debug!(
                    "Discord->SIP drain: channel={}, available={}, draining {}",
                    channel_id,
                    available,
                    SAMPLES_PER_FRAME
                );
            }
            if let Ok(chunk) = consumer.read_chunk(SAMPLES_PER_FRAME) {
                let (first, second) = chunk.as_slices();
                buf[..first.len()].copy_from_slice(first);
                if !second.is_empty() {
                    buf[first.len()..first.len() + second.len()].copy_from_slice(second);
                }
                chunk.commit_all();
            }
            return SAMPLES_PER_FRAME;
        } else if available > 0 {
            // Partial buffer - drain what we have, zero-fill the rest
            let underruns = UNDERRUN_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
            if underruns <= 10 || underruns.is_multiple_of(100) {
                tracing::warn!(
                    "BUFFER UNDERRUN (Discord->SIP): channel={}, only {} available (need {}), total: {}",
                    channel_id,
                    available,
                    SAMPLES_PER_FRAME,
                    underruns
                );
            }
            buf[available..].fill(0);
            if let Ok(chunk) = consumer.read_chunk(available) {
                let (first, second) = chunk.as_slices();
                buf[..first.len()].copy_from_slice(first);
                if !second.is_empty() {
                    buf[first.len()..first.len() + second.len()].copy_from_slice(second);
                }
                chunk.commit_all();
            }
            return available;
        }
    }

    0 // No audio available
}

/// Custom put_frame callback for channel buffer ports
/// Called by PJSUA/conference bridge when sending audio TO this port (SIP -> Discord)
/// This captures audio from calls connected to this channel's port
pub unsafe extern "C" fn channel_port_put_frame(
    this_port: *mut pjmedia_port,
    frame: *mut pjmedia_frame,
) -> pj_status_t {
    use std::sync::atomic::AtomicU64;

    static PUT_FRAME_CALL_COUNT: AtomicU64 = AtomicU64::new(0);
    let call_count = PUT_FRAME_CALL_COUNT.fetch_add(1, Ordering::Relaxed);

    if this_port.is_null() || frame.is_null() {
        return pj_constants__PJ_SUCCESS as pj_status_t;
    }

    // Only process audio frames with data
    if unsafe {
        (*frame).type_ != pjmedia_frame_type_PJMEDIA_FRAME_TYPE_AUDIO || (*frame).size == 0
    } {
        return pj_constants__PJ_SUCCESS as pj_status_t;
    }

    let channel_id = unsafe { Snowflake::new((*this_port).port_data.ldata as u64) };
    if *channel_id == 0 {
        return pj_constants__PJ_SUCCESS as pj_status_t;
    }

    // Log first 10 calls to confirm this callback is being invoked
    if call_count < 10 {
        tracing::trace!(
            "channel_port_put_frame called (call #{}, port={:p}, channel={}, frame_size={})",
            call_count,
            this_port,
            channel_id,
            unsafe { (*frame).size }
        );
    } else if call_count == 10 {
        tracing::trace!("channel_port_put_frame: suppressing further per-call logs");
    }

    // View frame buffer as i16 slice (zero-copy)
    let samples = unsafe {
        let num_samples = (*frame).size / 2;
        let frame_buf = (*frame).buf as *const i16;
        std::slice::from_raw_parts(frame_buf, num_samples)
    };

    // Store in the SIP->Discord buffer for this channel
    let buffers = CHANNEL_AUDIO_IN.get_or_init(DashMap::new);
    let mut buffer = buffers
        .entry(channel_id)
        .or_insert_with(|| VecDeque::with_capacity(max_channel_buffer_samples()));

    // Limit buffer size (same as Discord->SIP direction)
    let max_buffer = max_channel_buffer_samples();
    let buf_len = buffer.len();
    if buf_len + samples.len() > max_buffer {
        let to_drop = (buf_len + samples.len()).saturating_sub(max_buffer);
        if to_drop > 0 {
            let drop_count = to_drop.min(buf_len);
            buffer.drain(..drop_count);
            if call_count.is_multiple_of(250) {
                tracing::warn!(
                    "SIP->Discord buffer overflow: channel {} dropping {} samples",
                    channel_id,
                    to_drop
                );
            }
        }
    }

    buffer.extend(samples.iter().copied());

    // Log periodically
    if call_count.is_multiple_of(500) {
        tracing::debug!(
            "channel_port_put_frame #{}: channel={}, added {} samples, buffer now {}",
            call_count,
            channel_id,
            samples.len(),
            buffer.len()
        );
    }

    pj_constants__PJ_SUCCESS as pj_status_t
}

/// Custom on_destroy callback for channel buffer ports
pub unsafe extern "C" fn channel_port_on_destroy(this_port: *mut pjmedia_port) -> pj_status_t {
    if !this_port.is_null() {
        // Remove from reverse mapping (no unsafe ops needed here, just pointer-to-usize cast)
        let port_key = this_port as usize;
        if let Some(mapping) = PORT_TO_CHANNEL.get() {
            mapping.lock().remove(&port_key);
        }
    }
    pj_constants__PJ_SUCCESS as pj_status_t
}

// Conference connection helpers (shared by connect/disconnect paths)

/// Connect a call bidirectionally to other calls in the channel + channel port.
///
/// Uses `pjmedia_conf_connect_port` directly to bypass PJSUA_LOCK.
/// `other_calls` should be (call_id, conf_port) pairs for existing calls in the channel.
unsafe fn connect_call_to_channel(
    conf: *mut pjmedia_conf,
    call_id: CallId,
    conf_port: ConfPort,
    channel_id: Snowflake,
    other_calls: &[(CallId, ConfPort)],
) {
    // Connect this call to other calls in the same channel
    for &(other_call_id, other_conf_port) in other_calls {
        let (status1, status2) = unsafe {
            (
                pjmedia_conf_connect_port(conf, *conf_port as u32, *other_conf_port as u32, 0),
                pjmedia_conf_connect_port(conf, *other_conf_port as u32, *conf_port as u32, 0),
            )
        };

        if status1 == pj_constants__PJ_SUCCESS as i32 && status2 == pj_constants__PJ_SUCCESS as i32
        {
            tracing::debug!(
                "Connected call {} (port {}) <-> call {} (port {}) in channel {}",
                call_id,
                conf_port,
                other_call_id,
                other_conf_port,
                channel_id
            );
        } else {
            tracing::warn!(
                "Failed to connect calls {} and {} in channel {}: status1={}, status2={}",
                call_id,
                other_call_id,
                channel_id,
                status1,
                status2
            );
        }
    }

    // Connect call to channel's conference port bidirectionally
    if let Some(channel_slot) = get_or_create_channel_port(channel_id) {
        let (status1, status2) = unsafe {
            (
                // Channel port -> call (Discord audio reaches this call)
                pjmedia_conf_connect_port(conf, *channel_slot as u32, *conf_port as u32, 0),
                // Call -> channel port (SIP audio goes to channel for Discord)
                pjmedia_conf_connect_port(conf, *conf_port as u32, *channel_slot as u32, 0),
            )
        };

        if status1 != pj_constants__PJ_SUCCESS as i32 {
            tracing::warn!(
                "Failed to connect channel {} slot {} -> call {}: {}",
                channel_id,
                channel_slot,
                call_id,
                status1
            );
        }
        if status2 != pj_constants__PJ_SUCCESS as i32 {
            tracing::warn!(
                "Failed to connect call {} -> channel {} slot {}: {}",
                call_id,
                channel_id,
                channel_slot,
                status2
            );
        }
        if status1 == pj_constants__PJ_SUCCESS as i32 && status2 == pj_constants__PJ_SUCCESS as i32
        {
            tracing::debug!(
                "Connected channel {} port (slot {}) <-> call {} (port {}) bidirectionally",
                channel_id,
                channel_slot,
                call_id,
                conf_port
            );
        }
    }
}

/// Disconnect a call from other calls in the channel + channel port.
///
/// Uses `pjmedia_conf_disconnect_port` directly to bypass PJSUA_LOCK.
/// `remaining_calls` should be call IDs still in the channel (excluding the departing call).
unsafe fn disconnect_call_from_channel(
    conf: *mut pjmedia_conf,
    call_id: CallId,
    conf_port: ConfPort,
    channel_id: Snowflake,
    remaining_calls: &[CallId],
) {
    let conf_ports = CALL_CONF_PORTS.get_or_init(DashMap::new);

    // Disconnect from other calls in the channel (both directions)
    for &other_call_id in remaining_calls {
        if let Some(other_conf_port) = conf_ports.get(&other_call_id).map(|r| *r) {
            unsafe {
                pjmedia_conf_disconnect_port(conf, *conf_port as u32, *other_conf_port as u32);
                pjmedia_conf_disconnect_port(conf, *other_conf_port as u32, *conf_port as u32);
            }
            tracing::debug!(
                "Disconnected call {} from call {} in channel {}",
                call_id,
                other_call_id,
                channel_id
            );
        }
    }

    // Disconnect from channel port (both directions)
    if let Some(channel_slot) = get_channel_slot(channel_id) {
        unsafe {
            pjmedia_conf_disconnect_port(conf, *channel_slot as u32, *conf_port as u32);
            pjmedia_conf_disconnect_port(conf, *conf_port as u32, *channel_slot as u32);
        }
        tracing::debug!(
            "Disconnected channel {} slot {} <-> call {} (port {}) bidirectionally",
            channel_id,
            channel_slot,
            call_id,
            conf_port
        );
    }
}

// Per-channel audio isolation functions

/// Register a call with its Discord channel for audio isolation
///
/// This function:
/// 1. Stores the call -> channel mapping (always, even if media not ready)
/// 2. Adds the call to the channel's call set
/// 3. Queues the conference connections for the audio thread to process
///    (pjsua_conf_connect conflicts with pjmedia_port_get_frame if called from different threads)
pub fn register_call_channel(call_id: CallId, channel_id: Snowflake) {
    // Always store the call -> channel mapping first, even if media isn't ready yet
    // This allows complete_pending_channel_registration to finish the job when media becomes active
    {
        let channels = CALL_CHANNELS.get_or_init(DashMap::new);
        channels.insert(call_id, channel_id);
        tracing::debug!("Stored call {} -> channel {} mapping", call_id, channel_id);
    }

    // Get the conf_port for this call
    let conf_port = {
        let ports = CALL_CONF_PORTS.get_or_init(DashMap::new);
        ports.get(&call_id).map(|r| *r)
    };

    let Some(_conf_port) = conf_port else {
        tracing::debug!(
            "Call {} registered for channel {} but media not active yet - will connect when ready",
            call_id,
            channel_id
        );
        return;
    };

    // Add call to channel's call set (this enables audio buffering for this channel)
    {
        let channel_calls = CHANNEL_CALLS.get_or_init(|| RwLock::new(HashMap::new()));
        let mut map = channel_calls.write();
        let calls = map.entry(channel_id).or_default();
        calls.insert(call_id);
        tracing::debug!(
            "Added call {} to channel {} ({} calls in channel)",
            call_id,
            channel_id,
            calls.len()
        );
    }

    // Queue the conference connections to be made by the audio thread
    // This is necessary because pjsua_conf_connect conflicts with the audio thread's
    // pjmedia_port_get_frame calls if made from a different thread
    PENDING_CONF_CONNECTIONS.push((call_id, channel_id));
    tracing::debug!(
        "Queued conference connections for call {} -> channel {} (will be processed by audio thread)",
        call_id,
        channel_id
    );
}

/// Complete the conference connections for a call (called from audio thread)
///
/// This makes the actual conference connections that were queued by register_call_channel.
/// Must be called from the audio thread to avoid conflicts with pjmedia_port_get_frame.
/// Uses pjmedia_conf_connect_port directly to bypass PJSUA_LOCK (avoiding deadlocks).
pub fn complete_conf_connections(call_id: CallId, channel_id: Snowflake) {
    // Get the conf_port for this call
    let conf_port = {
        let ports = CALL_CONF_PORTS.get_or_init(DashMap::new);
        ports.get(&call_id).map(|r| *r)
    };

    let Some(conf_port) = conf_port else {
        tracing::warn!(
            "complete_conf_connections: call {} has no conf_port - skipping",
            call_id
        );
        return;
    };

    // Get the conference bridge pointer (needed for pjmedia_conf_connect_port)
    let conf = unsafe { get_conference_bridge() };
    let Some(conf) = conf else {
        tracing::error!(
            "complete_conf_connections: could not get conference bridge pointer for call {}",
            call_id
        );
        return;
    };

    // Get other calls in this channel to connect bidirectionally
    let other_calls: Vec<(CallId, ConfPort)> = {
        let channel_calls = CHANNEL_CALLS.get_or_init(|| RwLock::new(HashMap::new()));
        let conf_ports = CALL_CONF_PORTS.get_or_init(DashMap::new);
        let map = channel_calls.read();
        if let Some(calls) = map.get(&channel_id) {
            calls
                .iter()
                .filter(|&&other_id| other_id != call_id)
                .filter_map(|&other_id| conf_ports.get(&other_id).map(|r| (other_id, *r)))
                .collect()
        } else {
            vec![]
        }
    };

    unsafe {
        connect_call_to_channel(conf, call_id, conf_port, channel_id, &other_calls);
    }

    tracing::debug!(
        "Completed conference connections for call {} (port {}) in channel {}",
        call_id,
        conf_port,
        channel_id
    );
}

/// Complete a pending channel registration when media becomes active
///
/// Called from on_call_media_state_cb when a call's media becomes ACTIVE.
/// If the call was already registered with a channel (via register_call_channel)
/// but media wasn't ready at that time, this completes the audio connections.
pub fn complete_pending_channel_registration(call_id: CallId, conf_port: ConfPort) {
    // Check if this call has a pending channel registration
    let channel_id = {
        let channels = CALL_CHANNELS.get_or_init(DashMap::new);
        channels.get(&call_id).map(|r| *r)
    };

    let Some(channel_id) = channel_id else {
        // No pending registration - call hasn't been assigned to a channel yet
        tracing::debug!(
            "complete_pending_channel_registration: call {} has no pending channel registration (will be registered later)",
            call_id
        );
        return;
    };

    // Check if already in CHANNEL_CALLS (already connected)
    let already_connected = {
        let channel_calls = CHANNEL_CALLS.get_or_init(|| RwLock::new(HashMap::new()));
        let map = channel_calls.read();
        map.get(&channel_id)
            .map(|calls| calls.contains(&call_id))
            .unwrap_or(false)
    };

    if already_connected {
        tracing::debug!(
            "Call {} already connected to channel {} - skipping",
            call_id,
            channel_id
        );
        return;
    }

    tracing::debug!(
        "Completing pending channel registration: call {} -> channel {} (conf_port {})",
        call_id,
        channel_id,
        conf_port
    );

    // Get existing calls in this channel and add our call
    let existing_calls: Vec<CallId> = {
        let channel_calls = CHANNEL_CALLS.get_or_init(|| RwLock::new(HashMap::new()));
        let mut map = channel_calls.write();
        let calls = map.entry(channel_id).or_default();
        let existing: Vec<CallId> = calls.iter().copied().collect();
        calls.insert(call_id);
        existing
    };

    // Get the conference bridge pointer (needed for pjmedia_conf_connect_port)
    let conf = unsafe { get_conference_bridge() };
    let Some(conf) = conf else {
        tracing::error!(
            "complete_pending_channel_registration: could not get conference bridge pointer for call {}",
            call_id
        );
        return;
    };

    // Connect this call to other calls in the same channel + channel port
    let conf_ports = CALL_CONF_PORTS.get_or_init(DashMap::new);
    let other_calls: Vec<(CallId, ConfPort)> = existing_calls
        .iter()
        .filter_map(|&other_id| conf_ports.get(&other_id).map(|r| (other_id, *r)))
        .collect();

    unsafe {
        connect_call_to_channel(conf, call_id, conf_port, channel_id, &other_calls);
    }

    tracing::debug!(
        "Completed pending registration: call {} (port {}) for channel {} ({} total calls)",
        call_id,
        conf_port,
        channel_id,
        existing_calls.len() + 1
    );
}

/// Temporarily disconnect a held call from its channel without full teardown
///
/// Unlike unregister_call_channel(), this keeps CALL_CHANNELS and CALL_CONF_PORTS
/// mappings intact so the call can be reconnected when it comes off hold.
/// The existing ACTIVE code path in on_call_media_state_cb handles reconnection
/// via complete_pending_channel_registration().
///
/// This function:
/// 1. Removes the call from CHANNEL_CALLS (stops audio buffering for this channel if empty)
/// 2. Disconnects conf_port from channel port (both directions)
/// 3. Disconnects conf_port from other calls in the channel (both directions)
/// 4. Clears audio buffers and drain cache if no other calls remain in the channel
pub fn disconnect_call_for_hold(call_id: CallId) {
    // Look up channel_id from CALL_CHANNELS (keep the mapping for reconnection)
    let channel_id = {
        let channels = CALL_CHANNELS.get_or_init(DashMap::new);
        channels.get(&call_id).map(|r| *r)
    };

    let Some(channel_id) = channel_id else {
        tracing::debug!(
            "disconnect_call_for_hold: call {} not registered with any channel",
            call_id
        );
        return;
    };

    // Look up conf_port from CALL_CONF_PORTS (keep the mapping for reconnection)
    let conf_port = {
        let ports = CALL_CONF_PORTS.get_or_init(DashMap::new);
        ports.get(&call_id).map(|r| *r)
    };

    // Remove call from CHANNEL_CALLS and get remaining calls
    let remaining_calls: Vec<CallId> = {
        let channel_calls = CHANNEL_CALLS.get_or_init(|| RwLock::new(HashMap::new()));
        let mut map = channel_calls.write();
        if let Some(calls) = map.get_mut(&channel_id) {
            calls.remove(&call_id);
            let remaining: Vec<CallId> = calls.iter().copied().collect();
            // If set becomes empty, remove the key so get_active_channels_into() excludes it
            // and send_audio_to_channel() stops buffering
            if calls.is_empty() {
                map.remove(&channel_id);
            }
            remaining
        } else {
            Vec::new()
        }
    };

    // Disconnect conference ports
    if let Some(conf_port) = conf_port {
        let conf = unsafe { get_conference_bridge() };

        if let Some(conf) = conf {
            unsafe {
                disconnect_call_from_channel(
                    conf,
                    call_id,
                    conf_port,
                    channel_id,
                    &remaining_calls,
                );
            }
        } else {
            tracing::warn!(
                "disconnect_call_for_hold: could not get conference bridge pointer for call {}",
                call_id
            );
        }
    }

    // If no other calls remain in the channel, clear stale buffers
    if remaining_calls.is_empty() {
        if let Some(audio_in) = CHANNEL_AUDIO_IN.get() {
            audio_in.remove(&channel_id);
        }
        if let Some(drain_cache) = CHANNEL_DRAIN_CACHE.get() {
            drain_cache.remove(&channel_id);
        }
        tracing::debug!(
            "Hold: cleared audio buffers for channel {} (no remaining calls)",
            channel_id
        );
    }

    tracing::info!(
        "Call {} put on hold - disconnected from channel {} ({} calls remaining)",
        call_id,
        channel_id,
        remaining_calls.len()
    );
}

/// Unregister a call from its Discord channel
///
/// This function:
/// 1. Removes the call from channel mappings
/// 2. Disconnects this call from other calls in the same channel
/// 3. Disconnects from channel port
/// 4. Cleans up the conf_port mapping
///
/// Does NOT clean up the channel port automatically.
/// The bridge code should call cleanup_channel_port() when the bridge is destroyed
/// to avoid race conditions with other calls joining the same channel.
pub fn unregister_call_channel(call_id: CallId) {
    // Get and remove the channel_id for this call
    let channel_id = {
        let channels = CALL_CHANNELS.get_or_init(DashMap::new);
        channels.remove(&call_id).map(|(_, v)| v)
    };

    // Get and remove the conf_port for this call
    let conf_port = {
        let ports = CALL_CONF_PORTS.get_or_init(DashMap::new);
        ports.remove(&call_id).map(|(_, v)| v)
    };

    let Some(channel_id) = channel_id else {
        // Call wasn't registered with a channel (e.g., hung up before auth)
        tracing::debug!("Call {} was not registered with any channel", call_id);
        return;
    };

    // Remove call from channel's call set and get remaining calls
    let remaining_calls: Vec<CallId> = {
        let channel_calls = CHANNEL_CALLS.get_or_init(|| RwLock::new(HashMap::new()));
        let mut map = channel_calls.write();
        if let Some(calls) = map.get_mut(&channel_id) {
            calls.remove(&call_id);
            let remaining: Vec<CallId> = calls.iter().copied().collect();
            // Clean up empty channels
            if calls.is_empty() {
                map.remove(&channel_id);
                // Also clean up the channel's audio input buffer
                if let Some(audio_in) = CHANNEL_AUDIO_IN.get() {
                    audio_in.remove(&channel_id);
                }
            }
            remaining
        } else {
            Vec::new()
        }
    };

    // Disconnect this call from other calls in the channel and from channel/master ports
    if let Some(conf_port) = conf_port {
        let conf = unsafe { get_conference_bridge() };

        if let Some(conf) = conf {
            unsafe {
                disconnect_call_from_channel(
                    conf,
                    call_id,
                    conf_port,
                    channel_id,
                    &remaining_calls,
                );
            }
        } else {
            tracing::warn!(
                "unregister_call_channel: could not get conference bridge pointer for call {}",
                call_id
            );
        }
    }

    tracing::debug!(
        "Unregistered call {} from channel {} ({} calls remaining)",
        call_id,
        channel_id,
        remaining_calls.len()
    );
}

/// Get or create the conference port for a channel
/// Returns the conf_slot for this channel's port
///
/// Creates a CUSTOM BUFFER PORT (not a null port) that:
/// - Provides audio to the conference via get_frame (pulls from Discord→SIP ring buffer)
/// - Discards put_frame (we only provide audio, not receive it)
pub fn get_or_create_channel_port(channel_id: Snowflake) -> Option<ConfPort> {
    let ports = CHANNEL_CONF_PORTS.get_or_init(|| Mutex::new(HashMap::new()));
    let mut ports = ports.lock();

    if let Some(&(_, slot)) = ports.get(&channel_id) {
        return Some(slot);
    }

    // Create a new custom buffer port for this channel
    unsafe {
        // Get or create the memory pool
        let pool = CHANNEL_PORT_POOL.get_or_init(|| {
            let pool = pjsua_pool_create(c"channel_ports".as_ptr() as *const _, 4096, 4096);
            Mutex::new(SendablePool(pool))
        });
        let pool_ptr = pool.lock().0;

        // Allocate pjmedia_port structure (zero-initialized)
        let port_size = std::mem::size_of::<pjmedia_port>();
        let port = pj_pool_alloc(pool_ptr, port_size) as *mut pjmedia_port;
        if port.is_null() {
            tracing::error!("Failed to allocate channel port for {}", channel_id);
            return None;
        }
        // Zero-initialize the port structure
        std::ptr::write_bytes(port as *mut u8, 0, port_size);

        // Create port name
        let port_name = format!("ch{}", channel_id);
        let port_name_cstr = std::ffi::CString::new(port_name).ok()?;

        // Initialize port info using pjmedia_port_info_init
        // Signature: we use a custom one to identify our ports
        let signature = 0x4348_414E; // "CHAN" in hex
        pjmedia_port_info_init(
            &mut (*port).info,
            &pj_str(port_name_cstr.as_ptr() as *mut _),
            signature,
            CONF_SAMPLE_RATE,
            CONF_CHANNELS,
            16, // bits per sample
            SAMPLES_PER_FRAME as u32,
        );

        // Set our custom callbacks
        (*port).get_frame = Some(channel_port_get_frame);
        (*port).put_frame = Some(channel_port_put_frame);
        (*port).on_destroy = Some(channel_port_on_destroy);

        // Add to conference
        let mut slot: i32 = 0;
        let status = pjsua_conf_add_port(pool_ptr, port, &mut slot);

        if status != pj_constants__PJ_SUCCESS as i32 {
            tracing::error!(
                "Failed to add channel port to conference for {}: {}",
                channel_id,
                status
            );
            return None;
        }

        // Store channel_id in port_data.ldata for O(1) lookup in callbacks
        // (avoids Mutex acquisition on every get_frame/put_frame call)
        (*port).port_data.ldata = *channel_id as i64;

        // Also register in reverse mapping for on_destroy callback cleanup
        let port_to_channel = PORT_TO_CHANNEL.get_or_init(|| Mutex::new(HashMap::new()));
        port_to_channel.lock().insert(port as usize, channel_id);

        let conf_slot = ConfPort::new(slot);
        tracing::debug!(
            "Created custom buffer port for channel {} at slot {} (port_ptr={:p})",
            channel_id,
            conf_slot,
            port
        );
        ports.insert(channel_id, (SendablePort(port), conf_slot));
        Some(conf_slot)
    }
}

/// Get the conf_slot for a channel (if it exists)
pub fn get_channel_slot(channel_id: Snowflake) -> Option<ConfPort> {
    let ports = CHANNEL_CONF_PORTS.get()?;
    let ports = ports.lock();
    ports.get(&channel_id).map(|&(_, slot)| slot)
}

/// Clean up a channel's conference port
/// This should be called by the bridge code when it's certain no calls remain
/// (not automatically when CHANNEL_CALLS is empty, to avoid race conditions)
pub fn cleanup_channel_port(channel_id: Snowflake) {
    let Some(ports) = CHANNEL_CONF_PORTS.get() else {
        return;
    };

    let removed = {
        let mut ports = ports.lock();
        ports.remove(&channel_id)
    };

    if let Some((port, slot)) = removed {
        // Remove from reverse mapping first
        if let Some(mapping) = PORT_TO_CHANNEL.get() {
            mapping.lock().remove(&(port.0 as usize));
        }

        unsafe {
            // Remove from conference bridge
            let status = pjsua_conf_remove_port(*slot);
            if status != pj_constants__PJ_SUCCESS as i32 {
                tracing::warn!(
                    "Failed to remove channel port {} from conference: {}",
                    slot,
                    status
                );
            }

            // Destroy the port (calls on_destroy callback)
            if !port.0.is_null() {
                pjmedia_port_destroy(port.0);
            }
        }
        tracing::debug!(
            "Cleaned up channel port for channel {} (slot {})",
            channel_id,
            slot
        );
    }
}

/// Drain one frame of SIP->Discord audio for a channel into a provided buffer.
/// Returns the number of samples written (0 if no audio available).
/// `buf` must be at least SAMPLES_PER_FRAME in length.
pub fn drain_sip_to_discord_audio(channel_id: Snowflake, buf: &mut [i16]) -> usize {
    use std::sync::atomic::AtomicU64;
    static DRAIN_COUNT: AtomicU64 = AtomicU64::new(0);

    let Some(buffers) = CHANNEL_AUDIO_IN.get() else {
        return 0;
    };

    let Some(mut buffer) = buffers.get_mut(&channel_id) else {
        return 0;
    };

    if buffer.len() >= SAMPLES_PER_FRAME {
        let count = DRAIN_COUNT.fetch_add(1, Ordering::Relaxed);
        if count.is_multiple_of(250) {
            tracing::debug!(
                "SIP->Discord drain #{}: channel={}, buffer has {} samples, draining {}",
                count,
                channel_id,
                buffer.len(),
                SAMPLES_PER_FRAME
            );
        }
        // Drain directly into the provided buffer
        let (front, back) = buffer.as_slices();
        if front.len() >= SAMPLES_PER_FRAME {
            buf[..SAMPLES_PER_FRAME].copy_from_slice(&front[..SAMPLES_PER_FRAME]);
        } else {
            buf[..front.len()].copy_from_slice(front);
            let remaining = SAMPLES_PER_FRAME - front.len();
            buf[front.len()..SAMPLES_PER_FRAME].copy_from_slice(&back[..remaining]);
        }
        buffer.drain(..SAMPLES_PER_FRAME);
        SAMPLES_PER_FRAME
    } else if !buffer.is_empty() {
        // Return what we have (partial frame) - better than nothing
        let available = buffer.len();
        tracing::trace!(
            "SIP->Discord partial drain: channel={}, only {} samples available",
            channel_id,
            available
        );
        let (front, back) = buffer.as_slices();
        if front.len() >= available {
            buf[..available].copy_from_slice(&front[..available]);
        } else {
            buf[..front.len()].copy_from_slice(front);
            let remaining = available - front.len();
            buf[front.len()..available].copy_from_slice(&back[..remaining]);
        }
        buffer.drain(..available);
        available
    } else {
        0
    }
}

/// Clear stale audio buffers and drain cache for a channel.
/// Called during reconnection teardown to ensure fresh audio state.
pub fn clear_channel_stale_audio(channel_id: Snowflake) {
    if let Some(audio_in) = CHANNEL_AUDIO_IN.get() {
        audio_in.remove(&channel_id);
    }
    if let Some(drain_cache) = CHANNEL_DRAIN_CACHE.get() {
        drain_cache.remove(&channel_id);
    }
}

/// Fill a provided Vec with the active channel IDs (reuses allocation).
/// Uses RwLock::read() — non-exclusive, never blocks other readers (audio thread).
pub fn get_active_channels_into(out: &mut Vec<Snowflake>) {
    out.clear();
    let channel_calls = CHANNEL_CALLS.get_or_init(|| RwLock::new(HashMap::new()));
    let map = channel_calls.read();
    out.extend(map.keys());
}
