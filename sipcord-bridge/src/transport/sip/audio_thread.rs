//! Audio processing thread and RTP activity tracking
//!
//! This module handles:
//! - Audio thread lifecycle (start/stop)
//! - Per-frame audio processing for SIP <-> Discord
//! - RTP inactivity timeout detection

use super::channel_audio::{complete_pending_channel_registration, get_active_channels_into};
use super::ffi::types::*;
use crate::audio::simd;
use crate::services::snowflake::Snowflake;
use crossbeam_channel::Sender;
use crossbeam_queue::SegQueue;
use parking_lot::Mutex;
use pjsua::*;
use std::mem::MaybeUninit;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

/// Frame counter for when we first see active channels (for debug logging)
/// This is reset when the audio thread starts to prevent subtraction overflow
static FIRST_ACTIVE_CHANNEL_FRAME: AtomicU64 = AtomicU64::new(0);

fn drain_queue<T>(queue: &SegQueue<T>, name: &str) {
    let mut count = 0;
    while queue.pop().is_some() {
        count += 1;
    }
    if count > 0 {
        tracing::warn!(
            "Drained {} stale {} from previous audio thread",
            count,
            name
        );
    }
}

/// Start the audio processing thread
///
/// This thread periodically:
/// - Gets audio frames from the conference (SIP -> callback)
/// - Puts audio frames to the conference (from AUDIO_OUT_BUFFERS -> SIP)
pub fn start_audio_thread() {
    if AUDIO_THREAD_RUNNING.swap(true, Ordering::SeqCst) {
        tracing::warn!("Audio thread already running");
        return;
    }

    // Reset the "ready" flag - we'll set it after processing the first frame
    AUDIO_THREAD_READY.store(false, Ordering::SeqCst);

    // Reset the first-active-channel frame counter to prevent subtraction overflow
    // when the audio thread restarts with a new frame_count
    FIRST_ACTIVE_CHANNEL_FRAME.store(0, Ordering::SeqCst);

    let handle = std::thread::spawn(|| {
        // Catch any panics in the audio thread
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            tracing::info!(
                "Audio processing thread started [thread: {:?}]",
                std::thread::current().id()
            );

            // Drain stale ops from previous audio thread lifecycle
            drain_queue(&PENDING_PJSUA_OPS, "PENDING_PJSUA_OPS");
            drain_queue(&PENDING_CONF_CONNECTIONS, "PENDING_CONF_CONNECTIONS");
            drain_queue(&PENDING_CHANNEL_COMPLETIONS, "PENDING_CHANNEL_COMPLETIONS");

            // Register this thread with PJLIB so we can call PJSUA functions
            // The thread descriptor must remain valid for the thread's lifetime
            let mut thread_desc: pj_thread_desc = [0; 64];
            let mut thread_ptr: *mut pj_thread_t = std::ptr::null_mut();
            let thread_name = c"audio_thread";

            unsafe {
                let is_registered = pj_thread_is_registered();
                if is_registered == 0 {
                    let status = pj_thread_register(
                        thread_name.as_ptr(),
                        thread_desc.as_mut_ptr(),
                        &mut thread_ptr,
                    );
                    if status != pj_constants__PJ_SUCCESS as i32 {
                        tracing::error!("Failed to register audio thread with PJLIB: {}", status);
                        return;
                    }
                    tracing::debug!("Audio thread registered with PJLIB successfully");
                } else {
                    tracing::debug!("Audio thread already registered with PJLIB");
                }
            }

            // Allocate frame buffer (16-bit samples)
            let frame_size_bytes = SAMPLES_PER_FRAME * 2; // 2 bytes per i16 sample
            let mut frame_buffer: Vec<u8> = vec![0u8; frame_size_bytes];
            let mut timestamp: u64 = 0;
            let mut frame_count: u64 = 0;

            let mut active_channels: Vec<Snowflake> = Vec::with_capacity(32);
            let mut drain_buf: Vec<i16> = vec![0i16; SAMPLES_PER_FRAME];
            let silence: Vec<i16> = vec![0i16; SAMPLES_PER_FRAME];

            // Use deadline-based timing instead of duration-based timing.
            // This prevents sleep overrun from accumulating frame after frame.
            let frame_duration = std::time::Duration::from_millis(FRAME_PTIME_MS as u64);
            let mut next_frame_deadline = Instant::now() + frame_duration;

            while AUDIO_THREAD_RUNNING.load(Ordering::SeqCst) {
                let start = std::time::Instant::now();

                // Process one frame
                unsafe {
                    process_audio_frame(
                        &mut frame_buffer,
                        &mut timestamp,
                        &mut frame_count,
                        &mut active_channels,
                        &mut drain_buf,
                        &silence,
                    );
                }

                // After the first frame, mark audio thread as ready and process any pending
                // channel registrations. This ensures the conference bridge is actively being
                // clocked when we make connections via pjsua_conf_connect.
                if frame_count == 1 {
                    AUDIO_THREAD_READY.store(true, Ordering::SeqCst);
                    tracing::debug!(
                        "Audio thread ready after first frame, processing pending channel completions"
                    );
                    process_pending_channel_completions();
                }

                // Process any pending conference connections (must be done in audio thread
                // to avoid conflicts with pjmedia_port_get_frame)
                process_pending_conf_connections(frame_count);

                // Process any pending PJSUA operations (answer, hangup, play)
                // These must run in the audio thread to avoid deadlocks with conf_connect/disconnect
                process_pending_pjsua_ops();

                // Track frame processing time for latency diagnostics
                let processing_elapsed = start.elapsed();
                let processing_ms = processing_elapsed.as_secs_f64() * 1000.0;

                // Warn if processing took longer than frame time (20ms) - this causes audio crunch
                if processing_ms > FRAME_PTIME_MS as f64 {
                    tracing::warn!(
                        "AUDIO OVERRUN: Frame #{} processing took {:.2}ms (>{}ms), audio will crunch!",
                        frame_count,
                        processing_ms,
                        FRAME_PTIME_MS
                    );
                } else if processing_ms > (FRAME_PTIME_MS as f64 * 0.8) {
                    // Warn if approaching the limit (>80% of frame time)
                    tracing::debug!(
                        "Audio frame #{} processing took {:.2}ms (approaching {}ms limit)",
                        frame_count,
                        processing_ms,
                        FRAME_PTIME_MS
                    );
                }

                // Log every 5 seconds (250 frames at 20ms each) that we're still alive
                if frame_count.is_multiple_of(250) {
                    let call_ids: Vec<CallId> = COUNTED_CALL_IDS
                        .get()
                        .map(|ids| ids.lock().iter().copied().collect())
                        .unwrap_or_default();

                    tracing::debug!(
                        "Audio thread: frame #{}, active_calls={}, call_ids={:?}",
                        frame_count,
                        call_ids.len(),
                        call_ids
                    );
                }

                // Deadline-based sleep: sleep until the next frame deadline, not for a duration.
                // This compensates for any sleep overrun on the next frame.
                let now = Instant::now();
                if next_frame_deadline > now {
                    std::thread::sleep(next_frame_deadline - now);
                }
                // Advance deadline for next frame (even if we're behind, keep the cadence)
                next_frame_deadline += frame_duration;

                // If we've fallen more than 5 frames behind (100ms), reset the deadline
                // to avoid a burst of catch-up frames that would cause audio glitches
                if next_frame_deadline + std::time::Duration::from_millis(100) < Instant::now() {
                    tracing::warn!(
                        "Audio thread fell behind by >100ms, resetting deadline (frame #{})",
                        frame_count
                    );
                    next_frame_deadline = Instant::now() + frame_duration;
                }
            }

            tracing::debug!(
                "Audio processing thread exiting - AUDIO_THREAD_RUNNING is false, frame_count={}",
                frame_count
            );
        }));

        if let Err(e) = result {
            tracing::error!("AUDIO THREAD PANICKED: {:?}", e);
        }
    });

    // Store the handle for joining later
    let handle_storage = AUDIO_THREAD_HANDLE.get_or_init(|| Mutex::new(None));
    *handle_storage.lock() = Some(handle);
}

/// Stop the audio processing thread
pub fn stop_audio_thread() {
    let active_calls = COUNTED_CALL_IDS
        .get()
        .map(|ids| ids.lock().len())
        .unwrap_or(0);
    tracing::debug!(
        "Stopping audio thread (active_media_calls={}, was_running={})",
        active_calls,
        AUDIO_THREAD_RUNNING.load(Ordering::SeqCst)
    );
    AUDIO_THREAD_RUNNING.store(false, Ordering::SeqCst);
    AUDIO_THREAD_READY.store(false, Ordering::SeqCst);

    // Wait for the thread to stop with a bounded timeout.
    // If the thread is blocked on a conference bridge lock, we don't want
    // shutdown to hang indefinitely. The 2s force-exit timer in main.rs
    // is a final backstop, but this avoids relying on a hard process exit.
    if let Some(handle_storage) = AUDIO_THREAD_HANDLE.get()
        && let Some(handle) = handle_storage.lock().take()
    {
        tracing::debug!("Joining audio thread (2s timeout)...");
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let join_thread = std::thread::spawn(move || {
            let result = handle.join();
            let _ = done_tx.send(result);
        });
        match done_rx.recv_timeout(std::time::Duration::from_secs(2)) {
            Ok(Ok(())) => {
                tracing::debug!("Audio thread joined successfully");
            }
            Ok(Err(e)) => {
                tracing::error!("Audio thread panicked: {:?}", e);
            }
            Err(_) => {
                tracing::warn!("Audio thread join timed out after 2s, detaching");
                // Detach the join thread — the audio thread will be
                // cleaned up by process exit
                drop(join_thread);
            }
        }
    }
}

/// Process any pending channel registration completions
/// Called from the audio thread after it has processed its first frame
fn process_pending_channel_completions() {
    let mut count = 0;
    while let Some((call_id, conf_port)) = PENDING_CHANNEL_COMPLETIONS.pop() {
        tracing::debug!(
            "Completing deferred channel registration: call {} -> conf_port {}",
            call_id,
            conf_port
        );
        complete_pending_channel_registration(call_id, conf_port);
        count += 1;
    }

    if count > 0 {
        tracing::debug!("Processed {} pending channel completions", count);
    } else {
        tracing::debug!("No pending channel completions to process");
    }
}

/// Process any pending conference connections
/// Called from the audio thread every frame to handle newly registered calls
fn process_pending_conf_connections(_frame_count: u64) {
    use super::channel_audio::complete_conf_connections;

    let mut count = 0;
    while let Some((call_id, channel_id)) = PENDING_CONF_CONNECTIONS.pop() {
        tracing::debug!(
            "Audio thread making conference connections: call {} -> channel {}",
            call_id,
            channel_id
        );
        complete_conf_connections(call_id, channel_id);
        count += 1;
    }

    if count > 0 {
        tracing::debug!(
            "Audio thread processed {} pending conference connections",
            count
        );
    }
}

/// Process any pending PJSUA operations
/// Called from the audio thread every frame to handle queued operations
/// that would deadlock if called from other threads during audio processing
fn is_call_valid(call_id: CallId) -> bool {
    unsafe {
        let mut ci = MaybeUninit::<pjsua_call_info>::uninit();
        let status = pjsua_call_get_info(*call_id, ci.as_mut_ptr());
        if status != pj_constants__PJ_SUCCESS as i32 {
            return false;
        }
        let ci = ci.assume_init();
        ci.state != pjsip_inv_state_PJSIP_INV_STATE_DISCONNECTED
    }
}

fn process_pending_pjsua_ops() {
    use super::ffi::direct_player::play_audio_to_call_direct_internal;
    use super::ffi::streaming_player::start_streaming_to_call;

    let mut count = 0;
    while let Some(op) = PENDING_PJSUA_OPS.pop() {
        // Validate that the call still exists before processing the op
        let call_id = match &op {
            PendingPjsuaOp::PlayDirect { call_id, .. } => Some(*call_id),
            PendingPjsuaOp::StartLoop { call_id, .. } => Some(*call_id),
            PendingPjsuaOp::StartStreaming { call_id, .. } => Some(*call_id),
            PendingPjsuaOp::StartTestTone { call_id } => Some(*call_id),
            PendingPjsuaOp::Hangup { call_id } => Some(*call_id),
            PendingPjsuaOp::ConnectFaxPort { call_id, .. } => Some(*call_id),
        };
        if let Some(cid) = call_id
            && !is_call_valid(cid)
        {
            tracing::warn!("Skipping stale op for dead call {}: {:?}", cid, op);
            // For ConnectFaxPort, signal failure so the caller doesn't hang
            if let PendingPjsuaOp::ConnectFaxPort { done_tx, .. } = op {
                let _ = done_tx.send(false);
            }
            continue;
        }
        count += 1;
        match op {
            PendingPjsuaOp::PlayDirect { call_id, samples } => {
                tracing::debug!(
                    "Audio thread: executing PlayDirect for call {} ({} samples)",
                    call_id,
                    samples.len()
                );
                // Stop any active looping player for this call first
                // This ensures a seamless transition from connecting sound to join sound
                super::ffi::looping_player::stop_loop(call_id);

                if let Err(e) = play_audio_to_call_direct_internal(call_id, &samples) {
                    tracing::warn!("Failed to play direct audio to call {}: {}", call_id, e);
                }
            }
            PendingPjsuaOp::StartStreaming {
                call_id,
                path,
                hangup_on_complete,
            } => {
                tracing::debug!(
                    "Audio thread: executing StartStreaming for call {} ({})",
                    call_id,
                    path.display()
                );
                // Stop any active looping player for this call first
                super::ffi::looping_player::stop_loop(call_id);

                if let Err(e) = start_streaming_to_call(call_id, &path, hangup_on_complete) {
                    tracing::warn!("Failed to start streaming for call {}: {}", call_id, e);
                }
            }
            PendingPjsuaOp::StartTestTone { call_id } => {
                tracing::debug!("Audio thread: executing StartTestTone for call {}", call_id);
                // Stop any active looping player for this call first
                super::ffi::looping_player::stop_loop(call_id);

                if let Err(e) = super::ffi::test_tone::start_test_tone_to_call(call_id) {
                    tracing::warn!("Failed to start test tone for call {}: {}", call_id, e);
                }
            }
            PendingPjsuaOp::Hangup { call_id } => {
                tracing::debug!("Audio thread: executing Hangup for call {}", call_id);
                // Stop any active looping player for this call first
                super::ffi::looping_player::stop_loop(call_id);
                // Hangup the call
                unsafe {
                    pjsua::pjsua_call_hangup(*call_id, 200, std::ptr::null(), std::ptr::null());
                }
            }
            PendingPjsuaOp::StartLoop { call_id, samples } => {
                tracing::debug!("Audio thread: executing StartLoop for call {}", call_id);
                if let Err(e) = super::ffi::looping_player::start_loop(call_id, samples) {
                    tracing::error!(
                        "Failed to start connecting loop for call {}: {}",
                        call_id,
                        e
                    );
                }
            }
            PendingPjsuaOp::ConnectFaxPort {
                call_id,
                fax_slot,
                call_conf_port,
                done_tx,
            } => {
                tracing::debug!(
                    "Audio thread: connecting fax port for call {} (fax_slot={}, call_port={})",
                    call_id,
                    fax_slot,
                    call_conf_port
                );
                let success = unsafe {
                    let conf = super::ffi::frame_utils::get_conference_bridge();
                    if let Some(conf) = conf {
                        let s1 = pjmedia_conf_connect_port(
                            conf,
                            *call_conf_port as u32,
                            *fax_slot as u32,
                            0,
                        );
                        let s2 = pjmedia_conf_connect_port(
                            conf,
                            *fax_slot as u32,
                            *call_conf_port as u32,
                            0,
                        );
                        if s1 != pj_constants__PJ_SUCCESS as i32 {
                            tracing::error!(
                                "Failed to connect call {} -> fax slot {}: {}",
                                call_id,
                                fax_slot,
                                s1
                            );
                        }
                        if s2 != pj_constants__PJ_SUCCESS as i32 {
                            tracing::error!(
                                "Failed to connect fax slot {} -> call {}: {}",
                                fax_slot,
                                call_id,
                                s2
                            );
                        }
                        s1 == pj_constants__PJ_SUCCESS as i32
                            && s2 == pj_constants__PJ_SUCCESS as i32
                    } else {
                        tracing::error!("Cannot get conference bridge for fax port connection");
                        false
                    }
                };
                let _ = done_tx.send(success);
            }
        }
    }

    if count > 0 {
        tracing::debug!("Audio thread processed {} pending PJSUA operations", count);
    }
}

/// Queue a channel registration completion for when the audio thread is ready
/// Returns true if queued, false if audio thread is ready (caller should complete immediately)
pub fn queue_pending_channel_completion(call_id: CallId, conf_port: ConfPort) -> bool {
    if AUDIO_THREAD_READY.load(Ordering::SeqCst) {
        // Audio thread is ready, caller should complete immediately
        return false;
    }

    // Queue for later processing
    PENDING_CHANNEL_COMPLETIONS.push((call_id, conf_port));
    tracing::debug!(
        "Queued pending channel completion: call {} -> conf_port {} (audio thread not ready yet)",
        call_id,
        conf_port
    );
    true
}

/// Process one audio frame (called from audio thread)
///
/// This function handles per-channel audio isolation using a SINGLE clock tick:
/// 1. Clock the conference ONCE via pjmedia_port_get_frame (runs all codecs, jitter buffers, etc.)
/// 2. During that tick, channel_port_put_frame callbacks receive audio from connected calls
/// 3. Drain the per-channel SIP->Discord buffers and send to Discord
///
/// This architecture ensures the conference only advances once per 20ms frame, regardless of
/// how many channels are active. Previously, we clocked once PER CHANNEL which caused audio
/// to run at N*speed (stuttering, delays) when N channels were active.
unsafe fn process_audio_frame(
    frame_buffer: &mut [u8],
    timestamp: &mut u64,
    frame_count: &mut u64,
    active_channels: &mut Vec<Snowflake>,
    drain_buf: &mut [i16],
    silence: &[i16],
) {
    use super::channel_audio::drain_sip_to_discord_audio;

    *frame_count += 1;

    // Increment global frame counter for channel port caching
    // This ensures channel_port_get_frame only drains buffers once per tick
    AUDIO_FRAME_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

    let port_guard = match CONF_MASTER_PORT.get() {
        Some(guard) => guard,
        None => {
            if (*frame_count).is_multiple_of(500) {
                tracing::warn!("Audio thread: No master port configured");
            }
            return;
        }
    };

    let master_port = port_guard.lock().0;
    if master_port.is_null() {
        if (*frame_count).is_multiple_of(500) {
            tracing::warn!("Audio thread: Master port is null");
        }
        return;
    }

    // Log every 5 seconds (250 frames at 20ms each)
    let should_log = (*frame_count).is_multiple_of(250);

    // Get snapshots of channel mappings (reuses allocation)
    get_active_channels_into(active_channels);

    if should_log {
        tracing::trace!("Audio thread: {} active channels", active_channels.len());
    }

    // Log when we first start processing active channels
    let first_active = FIRST_ACTIVE_CHANNEL_FRAME.load(Ordering::Relaxed);
    if first_active == 0 && !active_channels.is_empty() {
        FIRST_ACTIVE_CHANNEL_FRAME.store(*frame_count, Ordering::Relaxed);
        tracing::info!(
            "Audio thread frame #{}: FIRST frame with active channels: {:?}",
            *frame_count,
            active_channels
        );
    }

    // CRITICAL: Clock the conference EXACTLY ONCE per frame
    // This runs ALL the internal processing:
    // - Jitter buffers for all calls
    // - Codec decode/encode for all calls
    // - Mixing for all connected ports
    // - Calls channel_port_get_frame for Discord->SIP (provides audio TO calls)
    // - Calls channel_port_put_frame for SIP->Discord (receives audio FROM calls)
    let mut clock_frame = pjmedia_frame {
        type_: pjmedia_frame_type_PJMEDIA_FRAME_TYPE_AUDIO,
        buf: frame_buffer.as_mut_ptr() as *mut _,
        size: frame_buffer.len() as pj_size_t,
        timestamp: pj_timestamp { u64_: *timestamp },
        bit_info: 0,
    };
    unsafe { pjmedia_port_get_frame(master_port, &mut clock_frame) };

    // Now drain the SIP->Discord buffers that were filled by channel_port_put_frame callbacks
    // during the conference tick above.
    // Lock callbacks ONCE per frame (not per channel) to avoid N Mutex acquisitions.
    if !active_channels.is_empty() {
        let callbacks_guard = CALLBACKS.get().map(|c| c.lock());
        let on_audio_frame = callbacks_guard
            .as_ref()
            .and_then(|g| g.as_ref())
            .map(|h| &h.on_audio_frame);

        for &channel_id in active_channels.iter() {
            // Drain one frame's worth of audio into pre-allocated buffer
            let n = drain_sip_to_discord_audio(channel_id, drain_buf);

            // ALWAYS send something to keep Discord stream alive (even if just silence)
            let samples: &[i16] = if n > 0 { &drain_buf[..n] } else { silence };

            // Log periodically
            if should_log {
                let max_sample = simd::max_abs_i16(samples);
                tracing::trace!(
                    "SIP->Discord: {} samples from channel {}, max_amp={}",
                    samples.len(),
                    channel_id,
                    max_sample
                );
            }

            // Emit audio for THIS channel specifically
            if let Some(on_audio_frame) = on_audio_frame {
                on_audio_frame(channel_id, samples, CONF_SAMPLE_RATE);
            }
        }
    }

    // Increment timestamp
    *timestamp += SAMPLES_PER_FRAME as u64;
}

// RTP activity tracking

/// Get the total RTP packets received for a call
/// Returns None if call doesn't exist or stats unavailable
fn get_call_rtp_rx_count(call_id: CallId) -> Option<u64> {
    unsafe {
        let mut stat = MaybeUninit::<pjsua_stream_stat>::uninit();
        let status = pjsua_call_get_stream_stat(*call_id, 0, stat.as_mut_ptr());
        if status != pj_constants__PJ_SUCCESS as i32 {
            return None;
        }
        let stat = stat.assume_init();
        // rtcp.rx.pkt contains total RTP packets received
        Some(stat.rtcp.rx.pkt as u64)
    }
}

/// Set the event sender for timeout events
pub fn set_timeout_event_sender(tx: Sender<super::SipEvent>) {
    let sender = TIMEOUT_EVENT_TX.get_or_init(|| Mutex::new(None));
    *sender.lock() = Some(tx);
}

/// Initialize RTP activity tracking for a call
pub fn init_call_rtp_tracking(call_id: CallId) {
    let activity_map =
        CALL_RTP_ACTIVITY.get_or_init(|| Mutex::new(std::collections::HashMap::new()));
    // Start with count 0 - the periodic check will update with actual values
    activity_map.lock().insert(call_id, (0, Instant::now()));
    tracing::debug!("Initialized RTP tracking for call {}", call_id);
}

/// Remove RTP activity tracking for a call
pub fn remove_call_rtp_tracking(call_id: CallId) {
    if let Some(activity_map) = CALL_RTP_ACTIVITY.get() {
        activity_map.lock().remove(&call_id);
        tracing::debug!("Removed RTP tracking for call {}", call_id);
    }
}

/// Check all tracked calls for RTP inactivity and emit timeout events
///
/// This must be called from the PJSUA thread context, not from the audio thread,
/// because it calls pjsua_call_get_stream_stat() which requires PJSUA thread synchronization.
pub fn check_rtp_inactivity() {
    let Some(activity_map) = CALL_RTP_ACTIVITY.get() else {
        return;
    };

    // Collect all tracked calls first, then release the lock before calling PJSUA
    let tracked_calls: Vec<(CallId, u64, Instant)> = {
        let map = activity_map.lock();
        map.iter()
            .map(|(&call_id, &(rx_count, last_activity))| (call_id, rx_count, last_activity))
            .collect()
    };

    let mut timed_out_calls: Vec<(CallId, u64)> = Vec::new();
    let mut updates = Vec::new();

    // Now iterate without holding the lock
    for (call_id, last_rx_count, last_activity) in tracked_calls {
        let current_rx = match get_call_rtp_rx_count(call_id) {
            Some(count) => count,
            None => {
                // Call stats unavailable - likely dead call
                // Don't wait for on_call_state_cb which may never fire
                tracing::warn!(
                    "Call {} RTP stats unavailable, treating as timed out",
                    call_id
                );
                timed_out_calls.push((call_id, 0));
                continue;
            }
        };

        if current_rx > last_rx_count {
            // Activity detected - queue update
            updates.push((call_id, current_rx));
        } else {
            // No new packets — use a shorter timeout if we never received any audio
            let timeout = if current_rx == 0 {
                no_audio_timeout_secs()
            } else {
                rtp_inactivity_timeout_secs()
            };
            let elapsed = last_activity.elapsed().as_secs();
            if elapsed > timeout {
                tracing::warn!(
                    "Call {} timed out: no RTP activity for {}s (rx_count={}, timeout={}s)",
                    call_id,
                    elapsed,
                    current_rx,
                    timeout
                );
                timed_out_calls.push((call_id, current_rx));
            }
        }
    }

    // Apply updates
    if !updates.is_empty() {
        let mut map = activity_map.lock();
        for (call_id, rx_count) in updates {
            map.insert(call_id, (rx_count, Instant::now()));
        }
    }

    // Emit timeout events for dead calls
    if !timed_out_calls.is_empty() {
        // Remove timed out calls from tracking
        {
            let mut map = activity_map.lock();
            for &(call_id, _) in &timed_out_calls {
                map.remove(&call_id);
            }
        }

        if let Some(sender_lock) = TIMEOUT_EVENT_TX.get()
            && let Some(ref tx) = *sender_lock.lock()
        {
            for (call_id, rx_count) in timed_out_calls {
                let _ = tx.send(super::SipEvent::CallTimeout { call_id, rx_count });
            }
        }
    }
}

/// Validate all entries in COUNTED_CALL_IDS are still valid PJSUA calls
/// Removes stale entries and returns the number removed.
/// This should be called periodically from the SIP event loop.
pub fn validate_counted_calls() -> usize {
    let Some(counted_ids) = COUNTED_CALL_IDS.get() else {
        return 0;
    };

    let call_ids: Vec<CallId> = counted_ids.lock().iter().copied().collect();
    let mut removed = 0;

    // Get RTP tracking info for cross-reference
    let rtp_tracked_calls: std::collections::HashSet<CallId> = CALL_RTP_ACTIVITY
        .get()
        .map(|m| m.lock().keys().copied().collect())
        .unwrap_or_default();

    for call_id in call_ids {
        unsafe {
            let mut ci = MaybeUninit::<pjsua_call_info>::uninit();
            let status = pjsua_call_get_info(*call_id, ci.as_mut_ptr());

            let should_remove = if status != pj_constants__PJ_SUCCESS as i32 {
                tracing::warn!(
                    "Stale call {} in COUNTED_CALL_IDS: pjsua_call_get_info failed (status={})",
                    call_id,
                    status
                );
                true
            } else {
                let ci = ci.assume_init();
                if ci.state == pjsip_inv_state_PJSIP_INV_STATE_DISCONNECTED {
                    tracing::warn!(
                        "Stale call {} in COUNTED_CALL_IDS: already DISCONNECTED",
                        call_id
                    );
                    true
                } else if !rtp_tracked_calls.contains(&call_id) {
                    // Call is in COUNTED but NOT being tracked for RTP activity.
                    // However, REMOTE_HOLD intentionally removes RTP tracking
                    // (phones send no RTP during hold), so don't treat those as stale.
                    if ci.media_status == pjsua_call_media_status_PJSUA_CALL_MEDIA_REMOTE_HOLD {
                        false
                    } else {
                        tracing::warn!(
                            "Stale call {} in COUNTED_CALL_IDS: not in RTP tracking (state={}, media={})",
                            call_id,
                            ci.state,
                            ci.media_status
                        );
                        true
                    }
                } else {
                    false
                }
            };

            if should_remove {
                counted_ids.lock().remove(&call_id);
                remove_call_rtp_tracking(call_id);
                removed += 1;
            }
        }
    }

    if removed > 0 {
        let remaining = counted_ids.lock().len();
        tracing::warn!(
            "Removed {} stale calls from COUNTED_CALL_IDS, {} remaining",
            removed,
            remaining
        );
        if remaining == 0 {
            stop_audio_thread();
        }
    }

    removed
}

/// Scan all pjsua call slots and force-hangup zombie calls.
///
/// Unlike `validate_counted_calls()` which only checks COUNTED_CALL_IDS (authenticated calls),
/// this scans the raw pjsua call array for slots that are stuck — e.g. calls rejected early
/// (banned IPs, 401 challenges, spam) where the SIP transaction never completed and the slot
/// was never freed.
///
/// A call is considered a zombie if:
/// - It's been in a non-CONFIRMED state (NULL, CALLING, INCOMING, EARLY, CONNECTING) for
///   more than 2 minutes (SIP transaction timeout is 32s, so 2min is very generous)
/// - It's in DISCONNECTED state but the slot hasn't been freed (shouldn't happen, but safety net)
pub fn cleanup_zombie_pjsua_calls() -> usize {
    let max_calls: u32 = 128; // Must match cfg_ptr.max_calls in init.rs
    let mut cleaned = 0;

    unsafe {
        for i in 0..max_calls {
            let call_id = i as pjsua_call_id;
            let mut ci = MaybeUninit::<pjsua_call_info>::uninit();
            let status = pjsua_call_get_info(call_id, ci.as_mut_ptr());

            if status != pj_constants__PJ_SUCCESS as i32 {
                // Slot is free (no inv), this is fine
                continue;
            }

            let ci = ci.assume_init();

            // Skip calls that are actively connected (CONFIRMED state) — those are real calls
            if ci.state == pjsip_inv_state_PJSIP_INV_STATE_CONFIRMED {
                continue;
            }

            // For non-CONFIRMED calls, check how long they've been alive.
            // total_duration is time since call->start_time for non-CONFIRMED/DISCONNECTED calls.
            let age = ci.total_duration.sec as u64;

            // 2 minutes is very generous — SIP transaction timeout (Timer B) is 32 seconds,
            // and even slow auth flows should complete within 30 seconds
            if age > 120 {
                let state_name = super::ffi::init::InvState::from(ci.state);

                tracing::warn!(
                    "Zombie pjsua call slot {}: state={}, age={}s — force hanging up",
                    call_id,
                    state_name,
                    age
                );

                pjsua_call_hangup(call_id, 500, std::ptr::null(), std::ptr::null());
                cleaned += 1;
            }
        }
    }

    if cleaned > 0 {
        tracing::warn!("Force-cleaned {} zombie pjsua call slots", cleaned);
    }

    cleaned
}
