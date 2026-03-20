//! Looping audio player for early media
//!
//! Provides a looping player that plays audio repeatedly until stopped.
//! Used for the "connecting" sound during call setup (183 Session Progress).

use super::types::*;
use anyhow::Result;
use parking_lot::Mutex;
use pjsua::*;
use std::collections::HashMap;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, Ordering};

/// Global state for looping players: call_id -> LoopingPlayerState
pub static LOOPING_PLAYERS: OnceLock<Mutex<HashMap<CallId, LoopingPlayerState>>> = OnceLock::new();

/// Memory pool for looping player ports
pub static LOOPING_PLAYER_POOL: OnceLock<Mutex<SendablePool>> = OnceLock::new();

/// Port key -> (samples, position, is_active) mapping for get_frame callback
pub static LOOPING_PLAYER_DATA: OnceLock<Mutex<HashMap<usize, LoopingPlayerData>>> =
    OnceLock::new();

/// Data needed by the get_frame callback
pub struct LoopingPlayerData {
    pub samples: Vec<i16>,
    pub position: usize,
    pub is_active: AtomicBool,
}

/// State for a looping player
pub struct LoopingPlayerState {
    /// Conference slot for this player
    pub conf_slot: ConfPort,
    /// Port pointer (for cleanup)
    pub port_key: usize,
}

/// Custom get_frame callback for looping player ports
/// Returns samples from the player's buffer, looping back to start when reaching end
///
/// # Safety
/// Called by the pjmedia conference bridge. `this_port` and `frame` must be
/// valid, non-null pointers to pjmedia structures owned by pjsua.
pub unsafe extern "C" fn looping_player_get_frame(
    this_port: *mut pjmedia_port,
    frame: *mut pjmedia_frame,
) -> pj_status_t {
    use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};

    static GET_FRAME_CALL_COUNT: AtomicU64 = AtomicU64::new(0);
    let call_count = GET_FRAME_CALL_COUNT.fetch_add(1, AtomicOrdering::Relaxed);

    // Log first 10 calls to confirm this callback is being invoked
    if call_count < 10 {
        tracing::trace!(
            "looping_player_get_frame called (call #{}, port={:p})",
            call_count,
            this_port
        );
    } else if call_count == 10 {
        tracing::trace!("looping_player_get_frame: suppressing further per-call logs");
    }

    if this_port.is_null() || frame.is_null() {
        return -1;
    }

    let port_key = this_port as usize;

    // Get samples from the player's buffer and fill frame directly (no intermediate Vec)
    {
        let data = LOOPING_PLAYER_DATA.get_or_init(|| Mutex::new(HashMap::new()));
        let mut data = data.lock();

        if let Some(player_data) = data.get_mut(&port_key) {
            if player_data.is_active.load(Ordering::SeqCst) && !player_data.samples.is_empty() {
                let pos = player_data.position;
                let end = (pos + SAMPLES_PER_FRAME).min(player_data.samples.len());
                unsafe {
                    super::frame_utils::fill_audio_frame(frame, &player_data.samples[pos..end])
                };

                // Advance position, loop back if at end
                player_data.position = if end >= player_data.samples.len() {
                    0
                } else {
                    end
                };
            } else {
                unsafe { super::frame_utils::fill_silence_frame(frame) };
            }
        } else {
            unsafe { super::frame_utils::fill_silence_frame(frame) };
        }
    }

    pj_constants__PJ_SUCCESS as pj_status_t
}

/// Custom on_destroy callback for looping player ports
///
/// # Safety
/// Called by pjmedia when the port is being destroyed. `this_port` must be
/// a valid pointer to a pjmedia_port that was previously created by this module.
pub unsafe extern "C" fn looping_player_on_destroy(this_port: *mut pjmedia_port) -> pj_status_t {
    if !this_port.is_null() {
        let port_key = this_port as usize;
        if let Some(data) = LOOPING_PLAYER_DATA.get() {
            data.lock().remove(&port_key);
        }
        tracing::debug!("Looping player port destroyed: {:p}", this_port);
    }
    pj_constants__PJ_SUCCESS as pj_status_t
}

/// Start a looping player for a call
///
/// Creates a pjmedia_port that loops the given samples and connects it to the call.
/// The loop continues until stop_loop is called.
pub fn start_loop(call_id: CallId, samples: Vec<i16>) -> Result<()> {
    use super::frame_utils::{PortCallbacks, create_and_connect_port};

    // Check if already looping for this call
    {
        let players = LOOPING_PLAYERS.get_or_init(|| Mutex::new(HashMap::new()));
        if players.lock().contains_key(&call_id) {
            tracing::warn!("Looping player already exists for call {}", call_id);
            return Ok(());
        }
    }

    // Get call's conference port
    let call_conf_port = CALL_CONF_PORTS
        .get()
        .and_then(|p| p.get(&call_id).map(|r| *r))
        .ok_or_else(|| {
            anyhow::anyhow!("No conf_port for call {} - media not ready yet", call_id)
        })?;

    let guard = unsafe {
        let callbacks = PortCallbacks {
            get_frame: looping_player_get_frame,
            put_frame: super::frame_utils::noop_put_frame,
            on_destroy: Some(looping_player_on_destroy),
        };

        let guard = create_and_connect_port(
            &LOOPING_PLAYER_POOL,
            b"looping_players\0",
            "loop",
            call_id,
            0x4C4F_4F50, // "LOOP"
            callbacks,
            call_conf_port,
        )?;

        // Store samples in the player data with the actual port key
        {
            let data = LOOPING_PLAYER_DATA.get_or_init(|| Mutex::new(HashMap::new()));
            data.lock().insert(
                guard.port_key,
                LoopingPlayerData {
                    samples,
                    position: 0,
                    is_active: AtomicBool::new(true),
                },
            );
        }

        tracing::debug!(
            "Started looping player for call {} (player_slot={}, call_port={})",
            call_id,
            guard.slot,
            call_conf_port
        );

        guard
    };

    // Store player state (we manually manage the guard via stop_loop)
    let players = LOOPING_PLAYERS.get_or_init(|| Mutex::new(HashMap::new()));
    players.lock().insert(
        call_id,
        LoopingPlayerState {
            conf_slot: guard.slot,
            port_key: guard.port_key,
        },
    );

    // Forget the guard - stop_loop will handle cleanup manually
    // (looping player needs explicit stop, not drop-based cleanup)
    std::mem::forget(guard);

    Ok(())
}

/// Stop and clean up looping player for a call
pub fn stop_loop(call_id: CallId) {
    let state = {
        let players = LOOPING_PLAYERS.get_or_init(|| Mutex::new(HashMap::new()));
        players.lock().remove(&call_id)
    };

    if let Some(state) = state {
        // Mark as inactive (get_frame will return silence)
        if let Some(data) = LOOPING_PLAYER_DATA.get()
            && let Some(player_data) = data.lock().get(&state.port_key)
        {
            player_data.is_active.store(false, Ordering::SeqCst);
        }

        // Remove from conference
        tracing::trace!(
            "stop_loop: BEFORE pjsua_conf_remove_port({}) for call {} [thread: {:?}]",
            state.conf_slot,
            call_id,
            std::thread::current().id()
        );
        unsafe {
            pjsua_conf_remove_port(*state.conf_slot);
        }
        tracing::trace!(
            "stop_loop: AFTER pjsua_conf_remove_port({}) for call {}",
            state.conf_slot,
            call_id
        );

        tracing::debug!(
            "Stopped looping player for call {} (slot={})",
            call_id,
            state.conf_slot
        );
    } else {
        tracing::debug!("No looping player to stop for call {}", call_id);
    }
}
