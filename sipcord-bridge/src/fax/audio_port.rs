//! Fax audio port — bidirectional audio between SIP and SpanDSP.
//!
//! For each fax call, we create a custom conference port that:
//! - Receives audio from the SIP call via `put_frame` → RX ring buffer → fax processing task
//! - Sends SpanDSP transmit audio (CED, T.30) via TX ring buffer → `get_frame` → SIP call
//!
//! This is analogous to the channel_audio.rs ports used for Discord↔SIP audio.

use crate::transport::sip::CallId;
use crate::transport::sip::ffi::types::{
    CALL_CONF_PORTS, CONF_CHANNELS, CONF_SAMPLE_RATE, ConfPort, SAMPLES_PER_FRAME, SendablePool,
    SendablePort,
};
use dashmap::DashMap;
use parking_lot::Mutex;
use pjsua::*;
use rtrb::{Consumer, Producer};
use std::collections::HashMap;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::{debug, error, warn};

/// Ring buffer capacity for fax audio (i16 mono @ 16kHz).
/// 16000 samples = 1 second of audio, generous buffer for fax processing.
const FAX_AUDIO_RING_BUFFER_SIZE: usize = 16000;

/// Ring buffer capacity for fax TX audio (SpanDSP → SIP).
/// 3200 samples = 200ms — enough for timing jitter.
const FAX_TX_RING_BUFFER_SIZE: usize = 3200;

/// Map from CallId → RX ring buffer producer (SIP audio → fax processing task).
/// The put_frame callback pushes audio samples here.
static FAX_RX_PRODUCERS: OnceLock<DashMap<i64, Mutex<Producer<i16>>>> = OnceLock::new();

fn get_fax_rx_producers() -> &'static DashMap<i64, Mutex<Producer<i16>>> {
    FAX_RX_PRODUCERS.get_or_init(DashMap::new)
}

/// Map from CallId → TX ring buffer consumer (fax processing task → SIP caller).
/// The get_frame callback reads SpanDSP transmit audio from here.
static FAX_TX_CONSUMERS: OnceLock<DashMap<i64, Mutex<Consumer<i16>>>> = OnceLock::new();

fn get_fax_tx_consumers() -> &'static DashMap<i64, Mutex<Consumer<i16>>> {
    FAX_TX_CONSUMERS.get_or_init(DashMap::new)
}

/// Map from CallId → RX frame drop count (incremented in put_frame when buffer is full).
static FAX_RX_DROP_COUNTS: OnceLock<DashMap<i64, AtomicU64>> = OnceLock::new();

fn get_fax_rx_drop_counts() -> &'static DashMap<i64, AtomicU64> {
    FAX_RX_DROP_COUNTS.get_or_init(DashMap::new)
}

/// Get the number of RX audio frames dropped for a call (buffer full).
/// Returns 0 if no drops have been recorded.
pub fn get_rx_drop_count(call_id: CallId) -> u64 {
    get_fax_rx_drop_counts()
        .get(&(*call_id as i64))
        .map(|c| c.load(Ordering::Relaxed))
        .unwrap_or(0)
}

/// Map from CallId → conference slot (for cleanup).
static FAX_CONF_SLOTS: OnceLock<Mutex<HashMap<CallId, (SendablePort, ConfPort)>>> = OnceLock::new();

fn get_fax_slots() -> &'static Mutex<HashMap<CallId, (SendablePort, ConfPort)>> {
    FAX_CONF_SLOTS.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Memory pool for fax ports
static FAX_PORT_POOL: OnceLock<Mutex<SendablePool>> = OnceLock::new();

/// Bidirectional ring buffer handles for a fax audio port.
pub struct FaxAudioPorts {
    /// RX: SIP audio from caller → fax processing task (feeds SpanDSP fax_rx)
    pub rx_consumer: Consumer<i16>,
    /// TX: SpanDSP transmit audio → SIP caller (CED tones, T.30 signaling)
    pub tx_producer: Producer<i16>,
}

/// Create a bidirectional fax audio port for a call and connect it to the call's conference slot.
///
/// Port creation and conference addition happen on the calling thread.
/// The bidirectional `pjmedia_conf_connect_port` calls are queued to the audio thread
/// to avoid racing with `pjmedia_port_get_frame`.
///
/// Returns `FaxAudioPorts` with:
/// - `rx_consumer`: reads SIP audio (16kHz mono, 320 samples/20ms frames)
/// - `tx_producer`: writes SpanDSP transmit audio back to the caller
pub async fn create_fax_audio_port(call_id: CallId) -> Option<FaxAudioPorts> {
    // Get the call's conference port
    let call_conf_port = {
        let ports = CALL_CONF_PORTS.get_or_init(DashMap::new);
        ports.get(&call_id).map(|r| *r)
    };

    let call_conf_port: ConfPort = match call_conf_port {
        Some(p) if p.is_valid() => p,
        _ => {
            warn!(
                "Cannot create fax audio port for call {} — no valid conference port",
                call_id
            );
            return None;
        }
    };

    // Create RX ring buffer (SIP → fax processing)
    let (rx_producer, rx_consumer) = rtrb::RingBuffer::new(FAX_AUDIO_RING_BUFFER_SIZE);

    // Create TX ring buffer (fax processing → SIP)
    let (tx_producer, tx_consumer) = rtrb::RingBuffer::new(FAX_TX_RING_BUFFER_SIZE);

    let conf_slot = unsafe {
        // Get or create the memory pool for fax ports
        let pool = FAX_PORT_POOL.get_or_init(|| {
            let pool = pjsua_pool_create(c"fax_ports".as_ptr() as *const _, 4096, 4096);
            Mutex::new(SendablePool(pool))
        });
        let pool_ptr = pool.lock().0;

        // Allocate pjmedia_port structure
        let port_size = std::mem::size_of::<pjmedia_port>();
        let port = pj_pool_alloc(pool_ptr, port_size) as *mut pjmedia_port;
        if port.is_null() {
            error!("Failed to allocate fax audio port for call {}", call_id);
            return None;
        }
        std::ptr::write_bytes(port as *mut u8, 0, port_size);

        // Initialize port info
        let port_name = format!("fax{}", *call_id);
        let port_name_cstr = std::ffi::CString::new(port_name).ok()?;
        let signature = 0x4641_5852; // "FAXR" in hex

        pjmedia_port_info_init(
            &mut (*port).info,
            &pj_str(port_name_cstr.as_ptr() as *mut _),
            signature,
            CONF_SAMPLE_RATE,
            CONF_CHANNELS,
            16, // bits per sample
            SAMPLES_PER_FRAME as u32,
        );

        // Set callbacks
        (*port).get_frame = Some(fax_port_get_frame); // Sends SpanDSP TX audio back to caller
        (*port).put_frame = Some(fax_port_put_frame); // Captures SIP audio for SpanDSP
        (*port).on_destroy = Some(fax_port_on_destroy);

        // Store call_id in port_data.ldata for O(1) lookup in callbacks
        (*port).port_data.ldata = *call_id as i64;

        // Add to conference bridge
        let mut slot: i32 = 0;
        let status = pjsua_conf_add_port(pool_ptr, port, &mut slot);
        if status != pj_constants__PJ_SUCCESS as i32 {
            error!(
                "Failed to add fax port to conference for call {}: {}",
                call_id, status
            );
            return None;
        }

        let conf_slot = ConfPort::new(slot);

        // Store ring buffer handles for callbacks
        get_fax_rx_producers().insert(*call_id as i64, Mutex::new(rx_producer));
        get_fax_tx_consumers().insert(*call_id as i64, Mutex::new(tx_consumer));
        get_fax_rx_drop_counts().insert(*call_id as i64, AtomicU64::new(0));

        // Store slot for cleanup
        get_fax_slots()
            .lock()
            .insert(call_id, (SendablePort(port), conf_slot));

        conf_slot
    };

    // Queue the bidirectional conference connection to the audio thread
    // This avoids racing with pjmedia_port_get_frame
    let (done_tx, done_rx) = tokio::sync::oneshot::channel();
    use crate::transport::sip::ffi::types::{PendingPjsuaOp, queue_pjsua_op};
    queue_pjsua_op(PendingPjsuaOp::ConnectFaxPort {
        call_id,
        fax_slot: conf_slot,
        call_conf_port,
        done_tx,
    });

    match done_rx.await {
        Ok(true) => {
            debug!(
                "Created fax audio port for call {} at slot {} (bidirectional with call conf_port {})",
                call_id, conf_slot, call_conf_port
            );
            Some(FaxAudioPorts {
                rx_consumer,
                tx_producer,
            })
        }
        Ok(false) => {
            error!(
                "Audio thread failed to connect fax port for call {} — cleaning up",
                call_id
            );
            remove_fax_audio_port(call_id);
            None
        }
        Err(_) => {
            error!(
                "Audio thread dropped fax port connection signal for call {} — cleaning up",
                call_id
            );
            remove_fax_audio_port(call_id);
            None
        }
    }
}

/// Remove and clean up the fax audio port for a call.
pub fn remove_fax_audio_port(call_id: CallId) {
    // Remove ring buffer handles first (stops callbacks from reading/writing)
    get_fax_rx_producers().remove(&(*call_id as i64));
    get_fax_tx_consumers().remove(&(*call_id as i64));
    get_fax_rx_drop_counts().remove(&(*call_id as i64));

    // Remove and clean up the conference port
    let removed = get_fax_slots().lock().remove(&call_id);
    if let Some((port, slot)) = removed {
        unsafe {
            // Disconnect from conference
            pjsua_conf_remove_port(*slot);

            // Destroy the port
            if !port.0.is_null() {
                pjmedia_port_destroy(port.0);
            }
        }
        debug!(
            "Removed fax audio port for call {} (slot {})",
            call_id, slot
        );
    }
}

/// get_frame callback — sends SpanDSP transmit audio (CED, T.30) back to the SIP caller.
///
/// Reads from the TX ring buffer filled by the fax processing task.
/// Returns silence if no TX audio is available.
unsafe extern "C" fn fax_port_get_frame(
    this_port: *mut pjmedia_port,
    frame: *mut pjmedia_frame,
) -> pj_status_t {
    if this_port.is_null() || frame.is_null() {
        return pj_constants__PJ_SUCCESS as pj_status_t;
    }

    let call_id_ldata = unsafe { (*this_port).port_data.ldata };

    if let Some(consumer_entry) = get_fax_tx_consumers().get(&call_id_ldata)
        && let Some(mut consumer) = consumer_entry.try_lock()
    {
        let available = consumer.slots();
        if available >= SAMPLES_PER_FRAME
            && let Ok(chunk) = consumer.read_chunk(SAMPLES_PER_FRAME)
        {
            let (first, second) = chunk.as_slices();
            let out = unsafe {
                let buf = (*frame).buf as *mut i16;
                std::slice::from_raw_parts_mut(buf, SAMPLES_PER_FRAME)
            };
            out[..first.len()].copy_from_slice(first);
            if !second.is_empty() {
                out[first.len()..first.len() + second.len()].copy_from_slice(second);
            }
            chunk.commit_all();
            unsafe {
                (*frame).type_ = pjmedia_frame_type_PJMEDIA_FRAME_TYPE_AUDIO;
                (*frame).size = SAMPLES_PER_FRAME * 2;
            }
            return pj_constants__PJ_SUCCESS as pj_status_t;
        }
    }

    // No TX audio available — return silence audio frame (not NONE).
    // Returning FRAME_TYPE_NONE can cause PJSIP's conference bridge to
    // exclude this port from the audio mix, breaking the TX path.
    unsafe {
        let buf = (*frame).buf as *mut i16;
        let out = std::slice::from_raw_parts_mut(buf, SAMPLES_PER_FRAME);
        out.fill(0);
        (*frame).type_ = pjmedia_frame_type_PJMEDIA_FRAME_TYPE_AUDIO;
        (*frame).size = SAMPLES_PER_FRAME * 2;
    }
    pj_constants__PJ_SUCCESS as pj_status_t
}

/// on_destroy callback — no-op since cleanup is done in remove_fax_audio_port().
/// Required by PJSIP to avoid "on_destroy() not found" warning.
unsafe extern "C" fn fax_port_on_destroy(_this_port: *mut pjmedia_port) -> pj_status_t {
    pj_constants__PJ_SUCCESS as pj_status_t // no unsafe ops needed
}

/// put_frame callback — captures SIP audio and pushes to RX ring buffer for SpanDSP.
unsafe extern "C" fn fax_port_put_frame(
    this_port: *mut pjmedia_port,
    frame: *mut pjmedia_frame,
) -> pj_status_t {
    if this_port.is_null() || frame.is_null() {
        return pj_constants__PJ_SUCCESS as pj_status_t;
    }

    // Only process audio frames with data
    if unsafe {
        (*frame).type_ != pjmedia_frame_type_PJMEDIA_FRAME_TYPE_AUDIO || (*frame).size == 0
    } {
        return pj_constants__PJ_SUCCESS as pj_status_t;
    }

    let call_id_ldata = unsafe { (*this_port).port_data.ldata };

    // View frame buffer as i16 slice
    let samples = unsafe {
        let num_samples = (*frame).size / 2;
        let frame_buf = (*frame).buf as *const i16;
        std::slice::from_raw_parts(frame_buf, num_samples)
    };

    // Push to RX ring buffer
    if let Some(producer_entry) = get_fax_rx_producers().get(&call_id_ldata)
        && let Some(mut producer) = producer_entry.try_lock()
    {
        let available = producer.slots();
        if available >= samples.len() {
            if let Ok(mut chunk) = producer.write_chunk(samples.len()) {
                let (first, second) = chunk.as_mut_slices();
                let first_len = first.len().min(samples.len());
                first[..first_len].copy_from_slice(&samples[..first_len]);
                if first_len < samples.len() {
                    second[..samples.len() - first_len].copy_from_slice(&samples[first_len..]);
                }
                chunk.commit_all();
            }
        } else {
            // Buffer full — fax processing is falling behind. Track the drop.
            if let Some(counter) = get_fax_rx_drop_counts().get(&call_id_ldata) {
                counter.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    pj_constants__PJ_SUCCESS as pj_status_t
}
