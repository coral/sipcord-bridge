//! Test tone player for diagnostic audio
//!
//! Provides a 440Hz sine wave generator that plays to a specific call
//! until the caller hangs up. Used for audio pipeline testing.

use super::streaming_player::STREAMING_PLAYER_POOL;
use super::types::*;
use anyhow::Result;
use parking_lot::Mutex;
use pjsua::*;
use std::collections::HashMap;
use std::sync::OnceLock;

/// Precomputed 440Hz tone lookup table (one exact period = 400 samples at 16kHz)
/// gcd(16000, 440) = 40, so period = 16000/40 = 400 samples
static TONE_LUT: OnceLock<Vec<i16>> = OnceLock::new();

fn tone_lut() -> &'static [i16] {
    TONE_LUT.get_or_init(|| {
        (0..400)
            .map(|i| {
                let t = i as f64 / CONF_SAMPLE_RATE as f64;
                (f64::sin(2.0 * std::f64::consts::PI * 440.0 * t) * 16000.0) as i16
            })
            .collect()
    })
}

/// Global state for test tone players: port_ptr -> TestToneState
pub static TEST_TONE_STATE: OnceLock<Mutex<HashMap<usize, TestToneState>>> = OnceLock::new();

/// State for a test tone player port
pub struct TestToneState {
    /// Call ID (for hangup detection)
    pub call_id: CallId,
    /// Current phase of the sine wave (in samples)
    pub phase: u64,
    /// Whether playback is finished (call ended)
    pub finished: bool,
}

/// Custom get_frame callback for test tone player ports
///
/// Generates a 440Hz sine wave until the call ends.
pub unsafe extern "C" fn test_tone_get_frame(
    this_port: *mut pjmedia_port,
    frame: *mut pjmedia_frame,
) -> pj_status_t {
    if this_port.is_null() || frame.is_null() {
        return -1; // PJ_EINVAL
    }

    let port_key = this_port as usize;

    // Get samples from precomputed LUT and fill frame directly
    {
        let state = TEST_TONE_STATE.get_or_init(|| Mutex::new(HashMap::new()));
        let mut state = state.lock();

        if let Some(tone_state) = state.get_mut(&port_key) {
            // Check if call still exists (hangup detection)
            if !tone_state.finished {
                let call_exists = CALL_CONF_PORTS
                    .get()
                    .map(|p| p.contains_key(&tone_state.call_id))
                    .unwrap_or(false);

                if !call_exists {
                    tracing::debug!(
                        "Call {} ended, stopping test tone (port {:p})",
                        tone_state.call_id,
                        this_port
                    );
                    tone_state.finished = true;
                }
            }

            if tone_state.finished {
                unsafe { super::frame_utils::fill_silence_frame(frame) };
            } else {
                // Copy from precomputed LUT with wraparound (two memcpy calls max)
                let lut = tone_lut();
                let lut_len = lut.len();
                let phase = (tone_state.phase as usize) % lut_len;
                tone_state.phase += SAMPLES_PER_FRAME as u64;

                let first_chunk = (lut_len - phase).min(SAMPLES_PER_FRAME);
                unsafe {
                    let frame_buf = (*frame).buf as *mut i16;
                    std::ptr::copy_nonoverlapping(
                        lut[phase..phase + first_chunk].as_ptr(),
                        frame_buf,
                        first_chunk,
                    );

                    if first_chunk < SAMPLES_PER_FRAME {
                        let remaining = SAMPLES_PER_FRAME - first_chunk;
                        std::ptr::copy_nonoverlapping(
                            lut.as_ptr(),
                            frame_buf.add(first_chunk),
                            remaining,
                        );
                    }

                    (*frame).size = (SAMPLES_PER_FRAME * 2) as pj_size_t;
                    (*frame).type_ = pjmedia_frame_type_PJMEDIA_FRAME_TYPE_AUDIO;
                }
            }
        } else {
            unsafe { super::frame_utils::fill_silence_frame(frame) };
        }
    }

    pj_constants__PJ_SUCCESS as pj_status_t
}

/// Custom on_destroy callback for test tone player ports
pub unsafe extern "C" fn test_tone_on_destroy(this_port: *mut pjmedia_port) -> pj_status_t {
    if !this_port.is_null() {
        let port_key = this_port as usize;
        if let Some(state) = TEST_TONE_STATE.get() {
            state.lock().remove(&port_key);
        }
        tracing::debug!("Test tone player port destroyed: {:p}", this_port);
    }
    pj_constants__PJ_SUCCESS as pj_status_t
}

/// Start playing a 440Hz test tone to a call
///
/// The tone plays indefinitely until the caller hangs up. No automatic hangup.
pub fn start_test_tone_to_call(call_id: CallId) -> Result<()> {
    use super::frame_utils::{PortCallbacks, create_and_connect_port};

    // Get call's conference port
    let call_conf_port = CALL_CONF_PORTS
        .get()
        .and_then(|p| p.get(&call_id).map(|r| *r))
        .ok_or_else(|| {
            anyhow::anyhow!("No conf_port for call {} - media not ready yet", call_id)
        })?;

    let guard = unsafe {
        let callbacks = PortCallbacks {
            get_frame: test_tone_get_frame,
            put_frame: super::frame_utils::noop_put_frame,
            on_destroy: Some(test_tone_on_destroy),
        };

        let guard = create_and_connect_port(
            &STREAMING_PLAYER_POOL,
            b"streaming_players\0",
            "tone",
            call_id,
            0x544F_4E45, // "TONE"
            callbacks,
            call_conf_port,
        )?;

        // Store player state with the actual port key
        {
            let state = TEST_TONE_STATE.get_or_init(|| Mutex::new(HashMap::new()));
            state.lock().insert(
                guard.port_key,
                TestToneState {
                    call_id,
                    phase: 0,
                    finished: false,
                },
            );
        }

        tracing::info!(
            "Started 440Hz test tone for call {} (player_slot={}, call_port={})",
            call_id,
            guard.slot,
            call_conf_port
        );

        guard
    };

    let port_key = guard.port_key;

    // Spawn a cleanup thread that watches for when the call ends
    // The ConfPortGuard handles pjsua_conf_remove_port when dropped
    std::thread::spawn(move || {
        loop {
            std::thread::sleep(std::time::Duration::from_millis(100));

            let finished = {
                let state = TEST_TONE_STATE.get_or_init(|| Mutex::new(HashMap::new()));
                let state = state.lock();

                if let Some(tone_state) = state.get(&port_key) {
                    tone_state.finished
                } else {
                    // State already removed - we're done
                    break;
                }
            };

            if finished {
                // Small delay to ensure last frame is sent
                std::thread::sleep(std::time::Duration::from_millis(50));

                // Drop guard to remove from conference
                // on_destroy callback will clean up TEST_TONE_STATE
                drop(guard);

                tracing::debug!(
                    "Cleaned up test tone player (port={:p})",
                    port_key as *const ()
                );

                break;
            }
        }
    });

    Ok(())
}
