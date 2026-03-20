//! Streaming audio player port for large files
//!
//! This module provides a PJSUA conference port that streams audio from a FLAC file
//! to a specific call. Unlike direct_player (which buffers all samples in memory),
//! this reads from disk on-demand for large files (e.g., easter egg audio).
//!
//! ## Design: Pull Model
//!
//! The streaming player uses a "pull" model where PJSUA's conference bridge calls
//! `streaming_get_frame` when it needs audio samples. This ensures precise timing
//! controlled by the audio thread's deadline-based scheduler, avoiding the timing
//! drift issues of tokio::sleep-based "push" models.
//!
//! ## Hangup Detection
//!
//! The `streaming_get_frame` callback checks if the call still exists in
//! `CALL_CONF_PORTS`. If the call has ended, it marks the player as finished
//! and returns silence. This handles mid-stream hangups cleanly.

use super::types::*;
use crate::services::sound::StreamingPlayer;
use anyhow::Result;
use parking_lot::Mutex;
use pjsua::*;
use std::collections::HashMap;
use std::path::Path;
use std::sync::OnceLock;

/// Global state for streaming players: port_ptr -> StreamingPlayerState
pub static STREAMING_PLAYER_STATE: OnceLock<Mutex<HashMap<usize, StreamingPlayerState>>> =
    OnceLock::new();

/// Memory pool for streaming player ports
pub static STREAMING_PLAYER_POOL: OnceLock<Mutex<SendablePool>> = OnceLock::new();

/// State for a streaming player port
pub struct StreamingPlayerState {
    /// The file-backed streaming player
    pub player: StreamingPlayer,
    /// Call ID (for hangup detection)
    pub call_id: CallId,
    /// Whether playback is finished (EOF or call ended)
    pub finished: bool,
    /// Whether to hangup when playback completes
    pub hangup_on_complete: bool,
}

/// Custom get_frame callback for streaming player ports
///
/// This is called by the PJSUA conference bridge when it needs audio samples.
/// The timing is controlled by the audio thread's deadline-based scheduler,
/// ensuring precise 20ms frame intervals.
pub unsafe extern "C" fn streaming_get_frame(
    this_port: *mut pjmedia_port,
    frame: *mut pjmedia_frame,
) -> pj_status_t {
    if this_port.is_null() || frame.is_null() {
        return -1; // PJ_EINVAL
    }

    let port_key = this_port as usize;

    // Get samples from the streaming player
    let samples = {
        let state = STREAMING_PLAYER_STATE.get_or_init(|| Mutex::new(HashMap::new()));
        let mut state = state.lock();

        if let Some(player_state) = state.get_mut(&port_key) {
            // Check if call still exists (hangup detection)
            if !player_state.finished {
                let call_exists = CALL_CONF_PORTS
                    .get()
                    .map(|p| p.contains_key(&player_state.call_id))
                    .unwrap_or(false);

                if !call_exists {
                    tracing::debug!(
                        "Call {} ended, stopping streaming (port {:p})",
                        player_state.call_id,
                        this_port
                    );
                    player_state.finished = true;
                }
            }

            if player_state.finished {
                // Already finished - return silence
                Vec::new()
            } else {
                // Try to get the next frame from the streaming player
                match player_state.player.get_frame(SAMPLES_PER_FRAME) {
                    Some(samples) => {
                        // Check if this was the last frame
                        if player_state.player.is_finished() {
                            player_state.finished = true;
                            tracing::debug!(
                                "Streaming playback finished for call {} (EOF)",
                                player_state.call_id
                            );
                        }
                        samples
                    }
                    None => {
                        // No more samples - mark finished
                        player_state.finished = true;
                        tracing::debug!(
                            "Streaming playback finished for call {} (no more samples)",
                            player_state.call_id
                        );
                        Vec::new()
                    }
                }
            }
        } else {
            Vec::new()
        }
    };

    // Fill frame buffer
    if !samples.is_empty() {
        unsafe { super::frame_utils::fill_audio_frame(frame, &samples) };
    } else {
        unsafe { super::frame_utils::fill_silence_frame(frame) };
    }

    pj_constants__PJ_SUCCESS as pj_status_t
}

/// Custom on_destroy callback for streaming player ports
pub unsafe extern "C" fn streaming_on_destroy(this_port: *mut pjmedia_port) -> pj_status_t {
    if !this_port.is_null() {
        let port_key = this_port as usize;
        if let Some(state) = STREAMING_PLAYER_STATE.get() {
            state.lock().remove(&port_key);
        }
        tracing::debug!("Streaming player port destroyed: {:p}", this_port);
    }
    pj_constants__PJ_SUCCESS as pj_status_t
}

/// Start streaming audio from a file to a call
///
/// This creates a PJSUA conference port backed by a StreamingPlayer and connects
/// it to the specified call. The audio thread's conference bridge will call
/// `streaming_get_frame` every 20ms to pull samples.
///
/// # Arguments
/// * `call_id` - The call to stream audio to
/// * `path` - Path to the FLAC file
/// * `hangup_on_complete` - Whether to hangup the call when playback finishes
pub fn start_streaming_to_call(
    call_id: CallId,
    path: &Path,
    hangup_on_complete: bool,
) -> Result<()> {
    use super::frame_utils::{PortCallbacks, create_and_connect_port};

    // Create the streaming player
    let player = StreamingPlayer::new(path)?;

    // Get call's conference port
    let call_conf_port = CALL_CONF_PORTS
        .get()
        .and_then(|p| p.get(&call_id).map(|r| *r))
        .ok_or_else(|| {
            anyhow::anyhow!("No conf_port for call {} - media not ready yet", call_id)
        })?;

    let guard = unsafe {
        let callbacks = PortCallbacks {
            get_frame: streaming_get_frame,
            put_frame: super::frame_utils::noop_put_frame,
            on_destroy: Some(streaming_on_destroy),
        };

        let guard = create_and_connect_port(
            &STREAMING_PLAYER_POOL,
            b"streaming_players\0",
            "strm",
            call_id,
            0x5354_524D, // "STRM"
            callbacks,
            call_conf_port,
        )?;

        // Store player state with the actual port key
        {
            let state = STREAMING_PLAYER_STATE.get_or_init(|| Mutex::new(HashMap::new()));
            state.lock().insert(
                guard.port_key,
                StreamingPlayerState {
                    player,
                    call_id,
                    finished: false,
                    hangup_on_complete,
                },
            );
        }

        tracing::info!(
            "Started streaming {} to call {} (player_slot={}, call_port={})",
            path.display(),
            call_id,
            guard.slot,
            call_conf_port
        );

        guard
    };

    let port_key = guard.port_key;

    // Spawn a cleanup thread that watches for completion
    // The ConfPortGuard handles pjsua_conf_remove_port when dropped
    std::thread::spawn(move || {
        loop {
            std::thread::sleep(std::time::Duration::from_millis(100));

            let (finished, hangup, call_id) = {
                let state = STREAMING_PLAYER_STATE.get_or_init(|| Mutex::new(HashMap::new()));
                let state = state.lock();

                if let Some(player_state) = state.get(&port_key) {
                    (
                        player_state.finished,
                        player_state.hangup_on_complete,
                        player_state.call_id,
                    )
                } else {
                    // State already removed - we're done
                    break;
                }
            };

            if finished {
                // Small delay to ensure last frame is sent
                std::thread::sleep(std::time::Duration::from_millis(50));

                // Drop guard to remove from conference
                // on_destroy callback will clean up STREAMING_PLAYER_STATE
                drop(guard);

                tracing::debug!(
                    "Cleaned up streaming player (port={:p})",
                    port_key as *const ()
                );

                // Hangup if requested
                if hangup {
                    tracing::info!("Hanging up call {} after streaming playback", call_id);
                    use super::types::queue_pjsua_op;
                    queue_pjsua_op(PendingPjsuaOp::Hangup { call_id });
                }

                break;
            }
        }
    });

    Ok(())
}
