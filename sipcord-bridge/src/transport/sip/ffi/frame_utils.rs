//! Shared frame utilities for pjmedia ports
//!
//! Provides common helpers for filling audio frames and a shared no-op
//! put_frame callback used by ports that only produce audio.

use super::types::{
    CONF_CHANNELS, CONF_MASTER_PORT, CONF_SAMPLE_RATE, CallId, ConfPort, SAMPLES_PER_FRAME,
    SendablePool,
};
use anyhow::Result;
use parking_lot::Mutex;
use pjsua::*;
use std::sync::OnceLock;

/// Get the pjmedia_conf pointer from the master port
/// The conference bridge pointer is stored in master_port->port_data.pdata
/// Returns None if master port is not initialized
///
/// This is public so other modules (direct_player, looping_player) can use it
/// to bypass PJSUA_LOCK when connecting/disconnecting ports.
pub unsafe fn get_conference_bridge() -> Option<*mut pjmedia_conf> {
    let port_guard = CONF_MASTER_PORT.get()?;
    let master_port = port_guard.lock().0;
    if master_port.is_null() {
        return None;
    }
    let conf = unsafe { (*master_port).port_data.pdata as *mut pjmedia_conf };
    if conf.is_null() {
        return None;
    }
    Some(conf)
}

/// Write audio samples into a pjmedia_frame, padding with silence if fewer
/// than SAMPLES_PER_FRAME samples are provided.
///
/// # Safety
/// `frame` must be a valid, non-null pointer to a pjmedia_frame with a buffer
/// large enough for SAMPLES_PER_FRAME i16 samples.
pub unsafe fn fill_audio_frame(frame: *mut pjmedia_frame, samples: &[i16]) {
    unsafe {
        let frame_buf = (*frame).buf as *mut i16;
        std::ptr::copy_nonoverlapping(samples.as_ptr(), frame_buf, samples.len());
        // Pad with silence if we got fewer samples than a full frame
        if samples.len() < SAMPLES_PER_FRAME {
            std::ptr::write_bytes(
                frame_buf.add(samples.len()),
                0,
                SAMPLES_PER_FRAME - samples.len(),
            );
        }
        (*frame).size = (SAMPLES_PER_FRAME * 2) as pj_size_t;
        (*frame).type_ = pjmedia_frame_type_PJMEDIA_FRAME_TYPE_AUDIO;
    }
}

/// Fill a pjmedia_frame with silence.
///
/// # Safety
/// `frame` must be a valid, non-null pointer to a pjmedia_frame with a buffer
/// large enough for SAMPLES_PER_FRAME i16 samples.
pub unsafe fn fill_silence_frame(frame: *mut pjmedia_frame) {
    unsafe {
        let frame_buf = (*frame).buf as *mut u8;
        std::ptr::write_bytes(frame_buf, 0, SAMPLES_PER_FRAME * 2);
        (*frame).size = (SAMPLES_PER_FRAME * 2) as pj_size_t;
        (*frame).type_ = pjmedia_frame_type_PJMEDIA_FRAME_TYPE_AUDIO;
    }
}

/// No-op put_frame callback for ports that only produce audio.
///
/// # Safety
/// Called by the pjmedia conference bridge.
pub unsafe extern "C" fn noop_put_frame(
    _this_port: *mut pjmedia_port,
    _frame: *mut pjmedia_frame,
) -> pj_status_t {
    pj_constants__PJ_SUCCESS as pj_status_t
}

// Conference port guard and creation helper

/// Callbacks for a custom pjmedia port.
pub struct PortCallbacks {
    pub get_frame: unsafe extern "C" fn(*mut pjmedia_port, *mut pjmedia_frame) -> pj_status_t,
    pub put_frame: unsafe extern "C" fn(*mut pjmedia_port, *mut pjmedia_frame) -> pj_status_t,
    pub on_destroy: Option<unsafe extern "C" fn(*mut pjmedia_port) -> pj_status_t>,
}

/// RAII guard for a conference port. Removes port from conference on drop.
pub struct ConfPortGuard {
    pub slot: ConfPort,
    pub port_key: usize,
}

impl Drop for ConfPortGuard {
    fn drop(&mut self) {
        unsafe {
            pjsua_conf_remove_port(*self.slot);
        }
        tracing::debug!(
            "ConfPortGuard: removed conf port slot={} (port={:p})",
            self.slot,
            self.port_key as *const ()
        );
    }
}

/// Allocate a pjmedia port, init it, add to conference, and connect to a call's conf port.
/// Returns a `ConfPortGuard` that auto-cleans-up on drop.
///
/// # Safety
/// Must be called from the audio thread or while holding appropriate locks.
pub unsafe fn create_and_connect_port(
    pool: &OnceLock<Mutex<SendablePool>>,
    pool_name: &[u8],
    name_prefix: &str,
    call_id: CallId,
    signature: u32,
    callbacks: PortCallbacks,
    call_conf_port: ConfPort,
) -> Result<ConfPortGuard> {
    // Get or create the memory pool
    let pool = pool.get_or_init(|| {
        let p = unsafe { pjsua_pool_create(pool_name.as_ptr() as *const _, 4096, 4096) };
        Mutex::new(SendablePool(p))
    });
    let pool_ptr = pool.lock().0;

    // Allocate pjmedia_port structure
    let port_size = std::mem::size_of::<pjmedia_port>();
    let port = unsafe { pj_pool_alloc(pool_ptr, port_size) as *mut pjmedia_port };
    if port.is_null() {
        anyhow::bail!(
            "Failed to allocate {} port for call {}",
            name_prefix,
            call_id
        );
    }
    unsafe { std::ptr::write_bytes(port as *mut u8, 0, port_size) };

    // Create port name
    let port_name = format!("{}{}", name_prefix, call_id);
    let port_name_cstr = std::ffi::CString::new(port_name)
        .map_err(|e| anyhow::anyhow!("Invalid port name: {}", e))?;

    // Initialize port info
    unsafe {
        pjmedia_port_info_init(
            &mut (*port).info,
            &pj_str(port_name_cstr.as_ptr() as *mut _),
            signature,
            CONF_SAMPLE_RATE,
            CONF_CHANNELS,
            16,
            SAMPLES_PER_FRAME as u32,
        );

        // Set callbacks
        (*port).get_frame = Some(callbacks.get_frame);
        (*port).put_frame = Some(callbacks.put_frame);
        (*port).on_destroy = callbacks.on_destroy;
    }

    // Add to conference
    let mut player_slot: i32 = 0;
    let status = unsafe { pjsua_conf_add_port(pool_ptr, port, &mut player_slot) };
    if status != pj_constants__PJ_SUCCESS as i32 {
        anyhow::bail!("Failed to add {} port to conf: {}", name_prefix, status);
    }

    // Connect player port to the target call's port
    let conf = unsafe { get_conference_bridge() };
    let Some(conf) = conf else {
        unsafe { pjsua_conf_remove_port(player_slot) };
        anyhow::bail!("Failed to get conference bridge for {} port", name_prefix);
    };

    let status =
        unsafe { pjmedia_conf_connect_port(conf, player_slot as u32, *call_conf_port as u32, 0) };
    if status != pj_constants__PJ_SUCCESS as i32 {
        unsafe { pjsua_conf_remove_port(player_slot) };
        anyhow::bail!("Failed to connect {} port to call: {}", name_prefix, status);
    }

    Ok(ConfPortGuard {
        slot: ConfPort::new(player_slot),
        port_key: port as usize,
    })
}
