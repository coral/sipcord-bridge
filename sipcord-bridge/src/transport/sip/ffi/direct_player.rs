//! Direct player port for playing audio to a single call
//!
//! This module provides one-shot audio playback (e.g., join sounds) that
//! bypasses the channel buffer and plays directly to a specific call.

use super::types::*;
use anyhow::Result;
use parking_lot::Mutex;
use pjsua::*;
use std::collections::HashMap;

/// Custom get_frame callback for direct player ports
/// Returns samples from the player's buffer, advancing position each call
///
/// # Safety
/// Called by the pjmedia conference bridge. `this_port` and `frame` must be
/// valid, non-null pointers to pjmedia structures owned by pjsua.
pub unsafe extern "C" fn direct_player_get_frame(
    this_port: *mut pjmedia_port,
    frame: *mut pjmedia_frame,
) -> pj_status_t {
    use std::sync::atomic::{AtomicU64, Ordering};

    static GET_FRAME_CALL_COUNT: AtomicU64 = AtomicU64::new(0);
    let call_count = GET_FRAME_CALL_COUNT.fetch_add(1, Ordering::Relaxed);

    // Log first 10 calls to confirm this callback is being invoked
    if call_count < 10 {
        tracing::trace!(
            "direct_player_get_frame called (call #{}, port={:p})",
            call_count,
            this_port
        );
    } else if call_count == 10 {
        tracing::trace!("direct_player_get_frame: suppressing further per-call logs");
    }

    if this_port.is_null() || frame.is_null() {
        return -1; // PJ_EINVAL
    }

    let port_key = this_port as usize;

    // Get samples from the player's buffer and fill frame directly (no intermediate Vec)
    {
        let state = DIRECT_PLAYER_STATE.get_or_init(|| Mutex::new(HashMap::new()));
        let mut state = state.lock();

        if let Some((buffer, pos)) = state.get_mut(&port_key) {
            if *pos < buffer.len() {
                let end = (*pos + SAMPLES_PER_FRAME).min(buffer.len());
                unsafe { super::frame_utils::fill_audio_frame(frame, &buffer[*pos..end]) };
                *pos = end;
            } else {
                unsafe { super::frame_utils::fill_silence_frame(frame) }; // Playback complete
            }
        } else {
            unsafe { super::frame_utils::fill_silence_frame(frame) };
        }
    }

    pj_constants__PJ_SUCCESS as pj_status_t
}

/// Custom on_destroy callback for direct player ports
///
/// # Safety
/// Called by pjmedia when the port is being destroyed. `this_port` must be
/// a valid pointer to a pjmedia_port that was previously created by this module.
pub unsafe extern "C" fn direct_player_on_destroy(this_port: *mut pjmedia_port) -> pj_status_t {
    if !this_port.is_null() {
        let port_key = this_port as usize;
        if let Some(state) = DIRECT_PLAYER_STATE.get() {
            state.lock().remove(&port_key);
        }
        tracing::debug!("Direct player port destroyed: {:p}", this_port);
    }
    pj_constants__PJ_SUCCESS as pj_status_t
}

/// Play audio directly to a specific call's conference port using a custom player port.
/// This bypasses the channel buffer - used for join sounds to avoid overflow.
///
/// The player port connects directly to the call's conf_port, so only that caller
/// hears the audio. Other callers and Discord users don't hear it.
///
/// This queues the operation to be executed by the audio thread to avoid
/// deadlocks with the audio thread's pjsua_conf_connect/disconnect calls.
pub fn play_audio_to_call_direct(call_id: CallId, samples: &[i16]) -> Result<()> {
    use super::types::{PendingPjsuaOp, queue_pjsua_op};

    tracing::debug!(
        "Queueing PlayDirect for call {} ({} samples)",
        call_id,
        samples.len()
    );
    queue_pjsua_op(PendingPjsuaOp::PlayDirect {
        call_id,
        samples: samples.to_vec(),
    });
    Ok(())
}

/// Internal implementation of play_audio_to_call_direct
/// Called from the audio thread to actually create and connect the player
pub fn play_audio_to_call_direct_internal(call_id: CallId, samples: &[i16]) -> Result<()> {
    use super::frame_utils::{PortCallbacks, create_and_connect_port};

    // Get call's conference port
    let call_conf_port = CALL_CONF_PORTS
        .get()
        .and_then(|p| p.get(&call_id).map(|r| *r))
        .ok_or_else(|| anyhow::anyhow!("No conf_port for call {}", call_id))?;

    // Store samples in the player state BEFORE creating port (get_frame needs them)
    // We'll clean up if port creation fails
    let guard = unsafe {
        let callbacks = PortCallbacks {
            get_frame: direct_player_get_frame,
            put_frame: super::frame_utils::noop_put_frame,
            on_destroy: Some(direct_player_on_destroy),
        };

        // Pre-store samples so get_frame can find them even during pjsua_conf_add_port
        // We'll use a temporary key (0) and fix it after we get the actual port pointer
        let guard = create_and_connect_port(
            &DIRECT_PLAYER_POOL,
            b"direct_players\0",
            "dplay",
            call_id,
            0x4450_4C59, // "DPLY"
            callbacks,
            call_conf_port,
        );

        match guard {
            Ok(guard) => {
                // Now store samples with the actual port key
                let state = DIRECT_PLAYER_STATE.get_or_init(|| Mutex::new(HashMap::new()));
                state.lock().insert(guard.port_key, (samples.to_vec(), 0));

                tracing::debug!(
                    "Playing {} samples directly to call {} (player_slot={}, call_port={})",
                    samples.len(),
                    call_id,
                    guard.slot,
                    call_conf_port
                );

                guard
            }
            Err(e) => return Err(e),
        }
    };

    // Schedule cleanup after playback duration
    // The ConfPortGuard handles pjsua_conf_remove_port when dropped
    let sample_count = samples.len();
    let duration_ms = (sample_count as u64 * 1000) / CONF_SAMPLE_RATE as u64 + 100;

    std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_millis(duration_ms));
        // Drop the guard to remove from conference
        // on_destroy callback will clean up DIRECT_PLAYER_STATE
        drop(guard);
    });

    Ok(())
}
