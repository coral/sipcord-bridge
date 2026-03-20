pub mod ffi;

mod audio_thread;
mod callbacks;
mod channel_audio;
pub mod fork_group;
mod nat;
mod register_handler;

// Re-export everything from the pjsua FFI module
pub use self::ffi::*;

// Re-export from mixed/application-level modules
pub use audio_thread::{
    check_rtp_inactivity, cleanup_zombie_pjsua_calls, set_timeout_event_sender,
    validate_counted_calls,
};
pub use callbacks::{T38_PRESOCKETS, set_outbound_event_sender};
pub use channel_audio::{
    cleanup_channel_port, clear_channel_stale_audio, register_call_channel,
    register_discord_to_sip, unregister_call_channel, unregister_discord_to_sip,
};
pub use register_handler::{PendingRegisterTsx, set_register_event_sender, set_sip_command_sender};

use crate::config::{SipConfig, TlsConfig};
use crate::transport::discord::send_audio_to_discord_direct;
use anyhow::Result;
use crossbeam_channel::{Receiver, Sender, bounded};
use dashmap::DashMap;
use parking_lot::RwLock;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::{debug, error, info, trace};

/// Events emitted by the SIP module
#[derive(Debug, Clone)]
pub enum SipEvent {
    /// Incoming call received with SIP Digest auth params and extension
    IncomingCall {
        call_id: CallId,
        /// SIP Digest auth parameters (boxed to reduce enum size)
        digest_auth: Box<DigestAuthParams>,
        /// Extension being called (from To header)
        extension: String,
        /// Source IP address of the caller
        source_ip: Option<IpAddr>,
    },
    /// Call ended
    CallEnded { call_id: CallId },
    /// Call timed out due to RTP inactivity (no audio received for extended period)
    /// rx_count is the total RTP packets received before timeout (0 = never got any audio)
    CallTimeout { call_id: CallId, rx_count: u64 },
    /// Outbound call was answered
    OutboundCallAnswered {
        tracking_id: String,
        call_id: CallId,
    },
    /// Outbound call failed (rejected, timeout, error)
    OutboundCallFailed {
        tracking_id: String,
        call_id: Option<CallId>,
        reason: String,
    },
    /// Remote sent a T.38 re-INVITE (fax switching from G.711 to T.38 UDPTL)
    /// The re-INVITE has already been answered synchronously with a 200 OK;
    /// the pre-bound UDPTL socket is stored in T38_PRESOCKETS.
    T38Offered {
        call_id: CallId,
        /// Remote IP for UDPTL packets
        remote_ip: String,
        /// Remote UDPTL port
        remote_port: u16,
        /// T.38 version from SDP (typically 0)
        t38_version: u8,
        /// Max bit rate from SDP (typically 14400)
        max_bit_rate: u32,
        /// Rate management method ("transferredTCF" or "localTCF")
        rate_management: String,
        /// UDP error correction ("t38UDPRedundancy" or "t38UDPFEC")
        udp_ec: String,
        /// Our local UDPTL port (pre-bound in callback)
        local_port: u16,
    },
}

/// Commands that can be sent to the SIP module
#[derive(Debug)]
pub enum SipCommand {
    /// Play audio directly to a call (bypasses channel buffer)
    /// Used for join sounds to avoid buffer overflow with Discord audio
    PlayDirectToCall { call_id: CallId, samples: Vec<i16> },
    /// Start a looping audio player for early media (183 Session Progress)
    StartConnectingLoop { call_id: CallId, samples: Vec<i16> },
    /// Hangup a call
    Hangup { call_id: CallId },
    /// Answer a call with 200 OK (after Discord connects successfully)
    Answer { call_id: CallId },
    /// Send 183 Session Progress (establishes early media for connecting sound)
    Send183 { call_id: CallId },
    /// Start streaming audio from a file to a call (for large files like easter eggs)
    /// Uses pull model for precise timing - hangs up automatically when done
    StartStreaming { call_id: CallId, path: PathBuf },
    /// Start playing a 440Hz test tone to a call
    /// Plays until the caller hangs up
    StartTestTone { call_id: CallId },
    /// Send 302 redirect to another bridge server
    /// Must be processed in the PJSUA thread to avoid deadlocking with internal PJSIP state
    Redirect {
        call_id: CallId,
        domain: String,
        extension: String,
    },
    /// Make an outbound call to a SIP URI (for inbound Discord->SIP calls)
    MakeOutboundCall {
        tracking_id: String,
        sip_uri: String,
        caller_display_name: Option<String>,
        /// Total number of fork legs for this tracking_id (for multi-contact forking)
        fork_total: usize,
    },
    /// Complete a deferred REGISTER response via a UAS transaction.
    /// Sent by the async auth handler after API verification.
    RespondRegister {
        pending: PendingRegisterTsx,
        auth_ok: bool,
    },
}

/// Active call state (tracked by SIP module before authentication completes)
#[derive(Debug)]
pub struct CallState;

/// SIP transport — owns the pjsua event loop and all SIP state.
///
/// Creates its own event/command channels internally. Use `events()` and `commands()`
/// to get handles for communication with the bridge coordinator.
pub struct SipTransport {
    config: SipConfig,
    tls_config: Option<TlsConfig>,
    event_tx: Sender<SipEvent>,
    event_rx: Receiver<SipEvent>,
    command_tx: Sender<SipCommand>,
    command_rx: Receiver<SipCommand>,
    calls: Arc<DashMap<CallId, CallState>>,
    pjsua_initialized: Arc<RwLock<bool>>,
}

impl SipTransport {
    pub fn new(config: SipConfig, tls_config: Option<TlsConfig>) -> Self {
        let (event_tx, event_rx) = bounded(1000);
        let (command_tx, command_rx) = bounded(1000);
        Self {
            config,
            tls_config,
            event_tx,
            event_rx,
            command_tx,
            command_rx,
            calls: Arc::new(DashMap::new()),
            pjsua_initialized: Arc::new(RwLock::new(false)),
        }
    }

    /// Get a receiver for SIP events (incoming calls, call ended, etc.)
    pub fn events(&self) -> Receiver<SipEvent> {
        self.event_rx.clone()
    }

    /// Get a sender for SIP commands (hangup, answer, send audio, etc.)
    pub fn commands(&self) -> Sender<SipCommand> {
        self.command_tx.clone()
    }

    /// Get a sender for SIP events (used to inject outbound call events)
    pub fn event_sender(&self) -> Sender<SipEvent> {
        self.event_tx.clone()
    }

    /// Start the SIP transport
    pub async fn run(&self) -> Result<()> {
        info!(
            "Starting SIP server on {}:{}",
            self.config.public_host, self.config.port
        );

        if let Some(ref tls) = self.tls_config {
            info!("TLS enabled on port {}", tls.port);
        }

        // Initialize pjsua in a blocking task since it's not async-safe
        let config = self.config.clone();
        let tls_config = self.tls_config.clone();
        let calls = self.calls.clone();
        let event_tx = self.event_tx.clone();
        let initialized = self.pjsua_initialized.clone();
        let command_rx = self.command_rx.clone();

        // Spawn pjsua event loop in a blocking thread
        // IMPORTANT: All PJSUA calls must be made from this thread to avoid deadlocks
        let pjsua_handle = tokio::task::spawn_blocking(move || {
            if let Err(e) =
                run_pjsua_loop(config, tls_config, calls, event_tx, initialized, command_rx)
            {
                error!("pjsua loop error: {}", e);
            }
        });

        pjsua_handle.await?;
        Ok(())
    }
}

/// Run the pjsua event loop (blocking)
///
/// IMPORTANT: All PJSUA calls (answer, hangup, etc.) must be made from this thread
/// to avoid deadlocks with PJSIP's internal worker threads.
fn run_pjsua_loop(
    config: SipConfig,
    tls_config: Option<TlsConfig>,
    calls: Arc<DashMap<CallId, CallState>>,
    event_tx: Sender<SipEvent>,
    initialized: Arc<RwLock<bool>>,
    command_rx: Receiver<SipCommand>,
) -> Result<()> {
    // Initialize pjsua with optional TLS
    init_pjsua(&config, tls_config.as_ref())?;
    *initialized.write() = true;

    // Register this thread with PJLIB so we can safely call PJSUA functions.
    // This is required because tokio::task::spawn_blocking creates a new thread
    // that isn't automatically registered with PJLIB.
    if !register_thread_with_pjlib("pjsua_event_loop") {
        tracing::warn!("Failed to register event loop thread with PJLIB");
    }

    // Note: Audio thread is started on-demand when first call becomes active
    // (see on_call_media_state_cb in callbacks.rs)

    info!("pjsua initialized, waiting for calls...");

    // Set up timeout event sender for RTP inactivity detection
    set_timeout_event_sender(event_tx.clone());

    // Set up callbacks
    set_callbacks(CallbackHandlers {
        on_incoming_call: Box::new({
            let calls = calls.clone();
            move |call_id, sip_username, extension, source_ip| {
                debug!(
                    "Incoming call {} from {} to extension {} (IP: {:?})",
                    call_id, sip_username, extension, source_ip
                );

                // Track call (actual state is managed via events after authentication)
                calls.insert(call_id, CallState);
            }
        }),
        on_call_authenticated: Box::new({
            let event_tx = event_tx.clone();
            move |call_id, digest_auth, extension, source_ip| {
                info!(
                    "Call {} authenticated: user={}",
                    call_id, digest_auth.username
                );

                let _ = event_tx.send(SipEvent::IncomingCall {
                    call_id,
                    digest_auth: Box::new(digest_auth),
                    extension,
                    source_ip,
                });
            }
        }),
        on_dtmf: Box::new({
            move |call_id, digit| {
                debug!(
                    "DTMF {} on call {} (ignored - using dialed number)",
                    digit, call_id
                );
            }
        }),
        on_call_ended: Box::new({
            let calls = calls.clone();
            let event_tx = event_tx.clone();
            move |call_id| {
                calls.remove(&call_id);
                let _ = event_tx.send(SipEvent::CallEnded { call_id });
            }
        }),
        on_audio_frame: Box::new({
            move |channel_id, samples, sample_rate| {
                // DIRECT PATH: Send audio directly to Discord, bypassing tokio entirely.
                // This is called from the pjsua audio thread and sends directly to the
                // crossbeam channel that feeds Songbird's StreamingAudioSource.
                use std::sync::atomic::{AtomicU64, Ordering};
                static DIRECT_AUDIO_COUNT: AtomicU64 = AtomicU64::new(0);
                let count = DIRECT_AUDIO_COUNT.fetch_add(1, Ordering::Relaxed);

                let sent = send_audio_to_discord_direct(channel_id, samples, sample_rate);

                if !sent && count.is_multiple_of(250) {
                    // No sender registered for this channel - bridge might not be ready yet
                    trace!(
                        "No Discord sender for channel {} (direct audio dropped, count={})",
                        channel_id, count
                    );
                }
            }
        }),
    });

    // Run pjsua event loop
    let mut loop_count: u64 = 0;
    loop {
        // Process any pending SIP commands (non-blocking)
        // These must be processed in the PJSUA thread to avoid deadlocks
        while let Ok(cmd) = command_rx.try_recv() {
            process_sip_command(cmd, &calls);
        }

        // Sleep briefly to allow PJSIP worker threads to process events
        // Note: PJSIP has its own internal worker threads that handle the ioqueue
        process_pjsua_events(10)?;

        loop_count += 1;

        // Every ~5 seconds (500 iterations at 10ms each), check for RTP inactivity
        // This must be done from the PJSUA thread, not the audio thread
        if loop_count.is_multiple_of(500) {
            check_rtp_inactivity();
        }

        // Every ~30 seconds (3000 iterations at 10ms each), validate COUNTED_CALL_IDS
        // This catches stale calls that weren't properly cleaned up by on_call_state_cb
        if loop_count.is_multiple_of(3000) {
            validate_counted_calls();
        }

        // Every ~60 seconds (6000 iterations at 10ms each), scan ALL pjsua call slots
        // for zombie calls that are stuck (rejected calls where the SIP transaction
        // never completed, or calls where handle_incoming_call panicked/hung)
        if loop_count.is_multiple_of(6000) {
            cleanup_zombie_pjsua_calls();
        }
    }
}

/// Process a SIP command in the PJSUA thread
///
/// This must be called from the PJSUA event loop thread to avoid deadlocks.
fn process_sip_command(cmd: SipCommand, calls: &Arc<DashMap<CallId, CallState>>) {
    match cmd {
        SipCommand::PlayDirectToCall { call_id, samples } => {
            // Play audio directly to a call (bypasses channel buffer)
            if let Err(e) = play_audio_to_call_direct(call_id, &samples) {
                tracing::error!("Failed to play direct audio to call {}: {}", call_id, e);
            }
        }
        SipCommand::StartConnectingLoop { call_id, samples } => {
            // Queue to audio thread to avoid race with pjmedia_port_get_frame
            queue_pjsua_op(PendingPjsuaOp::StartLoop { call_id, samples });
        }
        SipCommand::Hangup { call_id } => {
            // Stop any looping audio first
            stop_loop(call_id);
            // Always try to hangup - PJSUA will handle if call doesn't exist
            // Remove from our tracking if present
            calls.remove(&call_id);
            hangup_call(call_id);
        }
        SipCommand::Answer { call_id } => {
            answer_call(call_id);
        }
        SipCommand::Send183 { call_id } => {
            send_183_session_progress(call_id);
        }
        SipCommand::StartStreaming { call_id, path } => {
            // Queue streaming to audio thread (handles timing and hangup detection)
            queue_pjsua_op(PendingPjsuaOp::StartStreaming {
                call_id,
                path,
                hangup_on_complete: true, // Easter egg calls hangup when done
            });
        }
        SipCommand::StartTestTone { call_id } => {
            // Queue test tone to audio thread
            queue_pjsua_op(PendingPjsuaOp::StartTestTone { call_id });
        }
        SipCommand::Redirect {
            call_id,
            domain,
            extension,
        } => {
            // Stop any connecting loop first
            stop_loop(call_id);
            // Send 302 from the PJSUA thread (safe - no deadlock with PJSIP internals)
            unsafe {
                callbacks::send_302_redirect(call_id, &domain, &extension);
            }
            calls.remove(&call_id);
        }
        SipCommand::MakeOutboundCall {
            tracking_id,
            sip_uri,
            caller_display_name,
            fork_total,
        } => {
            info!(
                "Making outbound call: tracking_id={}, uri={}, caller={:?}, fork={}/{}",
                tracking_id, sip_uri, caller_display_name, fork_total, fork_total
            );
            match make_outbound_call(&sip_uri, caller_display_name.as_deref()) {
                Ok(call_id) => {
                    // Store tracking_id -> call_id mapping
                    let outbound_calls = OUTBOUND_CALL_TRACKING.get_or_init(DashMap::new);
                    outbound_calls.insert(call_id, tracking_id.clone());
                    // Register in fork group
                    fork_group::add_member(&tracking_id, call_id, fork_total);
                    info!(
                        "Outbound call started: tracking_id={}, call_id={}",
                        tracking_id, call_id
                    );
                    calls.insert(call_id, CallState);
                }
                Err(e) => {
                    error!(
                        "Failed to make outbound call (tracking_id={}): {}",
                        tracking_id, e
                    );
                    // Track the initial failure in fork group
                    fork_group::add_initial_failure(&tracking_id, fork_total);
                }
            }
        }
        SipCommand::RespondRegister { pending, auth_ok } => {
            // Complete a deferred REGISTER response. Must run on the pjsua
            // thread because pjsip_tsx_send_msg is not thread-safe.
            unsafe {
                use pjsua::*;
                use std::os::raw::c_char;

                let tsx = pending.tsx.0;
                let tdata = pending.tdata.0;

                if tsx.is_null() || tdata.is_null() {
                    tracing::warn!("RespondRegister: null tsx or tdata");
                    return;
                }

                if auth_ok {
                    // Add Expires header to the pre-built 200 OK
                    let expires_str = format!("{}", pending.expires);
                    let hdr_name = std::ffi::CString::new("Expires").unwrap();
                    let hdr_value = std::ffi::CString::new(expires_str).unwrap();

                    let name = pj_str(hdr_name.as_ptr() as *mut c_char);
                    let value = pj_str(hdr_value.as_ptr() as *mut c_char);
                    let hdr = pjsip_generic_string_hdr_create((*tdata).pool, &name, &value);
                    if !hdr.is_null() {
                        pj_list_insert_before(
                            &mut (*(*tdata).msg).hdr as *mut pjsip_hdr as *mut pj_list_type,
                            hdr as *mut pj_list_type,
                        );
                    }
                } else {
                    // Rewrite the pre-built 200 to a 403 Forbidden
                    (*(*tdata).msg).line.status.code = 403;
                    let reason = b"Forbidden\0";
                    let ptr = pj_pool_alloc((*tdata).pool, reason.len()) as *mut u8;
                    std::ptr::copy_nonoverlapping(reason.as_ptr(), ptr, reason.len());
                    (*(*tdata).msg).line.status.reason.ptr = ptr as *mut c_char;
                    (*(*tdata).msg).line.status.reason.slen =
                        (reason.len() - 1) as std::os::raw::c_long;
                }

                let status = pjsip_tsx_send_msg(tsx, tdata);
                if status != pj_constants__PJ_SUCCESS as i32 {
                    tracing::warn!(
                        "Failed to send deferred REGISTER response ({}): {}",
                        if auth_ok { 200 } else { 403 },
                        status
                    );
                }
            }
        }
    }
}

/// Tracking map for outbound calls: pjsua call_id -> tracking_id
static OUTBOUND_CALL_TRACKING: std::sync::OnceLock<DashMap<CallId, String>> =
    std::sync::OnceLock::new();

/// Get the tracking ID for an outbound call (if any)
pub fn get_outbound_tracking_id(call_id: CallId) -> Option<String> {
    OUTBOUND_CALL_TRACKING
        .get()
        .and_then(|m| m.get(&call_id).map(|v| v.clone()))
}

/// Remove and return the tracking ID for an outbound call
pub fn remove_outbound_tracking(call_id: CallId) -> Option<String> {
    OUTBOUND_CALL_TRACKING
        .get()
        .and_then(|m| m.remove(&call_id).map(|(_, v)| v))
}

/// Make an outbound SIP call using pjsua
///
/// If `caller_display_name` is provided, it sets the From header display name
/// to show who initiated the call from Discord (e.g., "Discord: username").
fn make_outbound_call(sip_uri: &str, caller_display_name: Option<&str>) -> Result<CallId, String> {
    unsafe {
        let uri = std::ffi::CString::new(sip_uri).map_err(|e| e.to_string())?;
        let mut call_id: ::pjsua::pjsua_call_id = -1;

        // Explicit call settings: audio only, no video, no T.140 text.
        // The default txt_cnt=1 adds an m=text stream to the SDP, bloating
        // the INVITE beyond the ~1300-byte UDP fragmentation threshold.
        let mut opt = std::mem::MaybeUninit::<::pjsua::pjsua_call_setting>::uninit();
        ::pjsua::pjsua_call_setting_default(opt.as_mut_ptr());
        let opt_ptr = opt.assume_init_mut();
        opt_ptr.aud_cnt = 1;
        opt_ptr.vid_cnt = 0;
        opt_ptr.txt_cnt = 0;

        // Set up msg_data with custom From header if caller display name provided
        let mut msg_data = std::mem::MaybeUninit::<::pjsua::pjsua_msg_data>::uninit();
        ::pjsua::pjsua_msg_data_init(msg_data.as_mut_ptr());
        let msg_data_ptr = msg_data.assume_init_mut();

        // Build the From URI with display name: "name" <sip:sipcord@host>
        // The local_uri field overrides the From header in the outgoing INVITE
        let from_uri_cstring;
        if let Some(name) = caller_display_name {
            // Get the account's SIP URI to use as the address part
            let mut acc_info = std::mem::MaybeUninit::<::pjsua::pjsua_acc_info>::uninit();
            let acc_uri = if ::pjsua::pjsua_acc_get_info(0, acc_info.as_mut_ptr())
                == ::pjsua::pj_constants__PJ_SUCCESS as i32
            {
                let ai = acc_info.assume_init();
                std::ffi::CStr::from_ptr(ai.acc_uri.ptr)
                    .to_string_lossy()
                    .into_owned()
            } else {
                "sip:sipcord@localhost".to_string()
            };

            // Sanitize display name: whitelist printable ASCII, strip control chars
            // and characters that could break SIP header parsing or enable injection
            let sanitized: String = name
                .chars()
                .filter(|c| *c >= ' ' && *c != '"' && *c != '<' && *c != '>' && *c != '\\')
                .take(64)
                .collect();
            let from_uri = format!("\"{}\" <{}>", sanitized, acc_uri);
            from_uri_cstring = std::ffi::CString::new(from_uri).map_err(|e| e.to_string())?;
            msg_data_ptr.local_uri =
                ::pjsua::pj_str(from_uri_cstring.as_ptr() as *mut std::os::raw::c_char);
        }

        let status = ::pjsua::pjsua_call_make_call(
            0, // default account
            &::pjsua::pj_str(uri.as_ptr() as *mut std::os::raw::c_char),
            opt_ptr,              // call settings (no text stream)
            std::ptr::null_mut(), // user data
            msg_data_ptr,         // msg_data with custom From header
            &mut call_id,
        );

        if status != ::pjsua::pj_constants__PJ_SUCCESS as i32 {
            return Err(format!("pjsua_call_make_call failed: {}", status));
        }

        Ok(CallId::new(call_id))
    }
}
