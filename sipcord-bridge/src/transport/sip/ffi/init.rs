//! PJSUA initialization and core control functions
//!
//! This module handles:
//! - PJSUA initialization and configuration
//! - TLS transport creation and hot-reload
//! - Shutdown and thread registration

use super::super::audio_thread::stop_audio_thread;
use std::fmt;

/// SIP invite session state (Rust wrapper for pjsip_inv_state)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvState {
    Null,
    Calling,
    Incoming,
    Early,
    Connecting,
    Confirmed,
    Disconnected,
    Unknown(u32),
}

impl From<u32> for InvState {
    fn from(state: u32) -> Self {
        match state {
            x if x == pjsip_inv_state_PJSIP_INV_STATE_NULL => InvState::Null,
            x if x == pjsip_inv_state_PJSIP_INV_STATE_CALLING => InvState::Calling,
            x if x == pjsip_inv_state_PJSIP_INV_STATE_INCOMING => InvState::Incoming,
            x if x == pjsip_inv_state_PJSIP_INV_STATE_EARLY => InvState::Early,
            x if x == pjsip_inv_state_PJSIP_INV_STATE_CONNECTING => InvState::Connecting,
            x if x == pjsip_inv_state_PJSIP_INV_STATE_CONFIRMED => InvState::Confirmed,
            x if x == pjsip_inv_state_PJSIP_INV_STATE_DISCONNECTED => InvState::Disconnected,
            x => InvState::Unknown(x),
        }
    }
}

impl fmt::Display for InvState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InvState::Null => write!(f, "NULL"),
            InvState::Calling => write!(f, "CALLING"),
            InvState::Incoming => write!(f, "INCOMING"),
            InvState::Early => write!(f, "EARLY"),
            InvState::Connecting => write!(f, "CONNECTING"),
            InvState::Confirmed => write!(f, "CONFIRMED"),
            InvState::Disconnected => write!(f, "DISCONNECTED"),
            InvState::Unknown(x) => write!(f, "UNKNOWN({})", x),
        }
    }
}
use super::super::callbacks::{
    on_call_media_state_cb, on_call_rx_reinvite_cb, on_call_state_cb, on_dtmf_digit_cb,
    on_incoming_call_cb,
};
use super::super::nat::{
    on_rx_request_nat_fixup_cb, on_rx_response_nat_fixup_cb, on_tx_request_cb, on_tx_response_cb,
};
use super::super::register_handler::on_rx_request_cb;
use super::types::*;
use crate::config::{SipConfig, TlsConfig};
use anyhow::{Context, Result};
use ipnet::Ipv4Net;
use parking_lot::Mutex;
use pjsua::*;
use std::ffi::CString;
use std::mem::MaybeUninit;
use std::os::raw::{c_char, c_int};
use std::ptr;
use std::sync::atomic::Ordering;

/// Known PJSIP error conditions detected from log messages.
///
/// PJSIP's log callback only provides (level, string) — no structured error codes.
/// We pattern-match known messages to classify them into actionable variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PjsipEvent {
    /// All call slots exhausted — new INVITEs are rejected with 486 Busy Here
    TooManyCalls,
    /// SSL/TLS handshake failed with a remote peer
    SslHandshakeError,
    /// Failed to send a SIP response
    SendResponseFailed,
    /// ICE negotiation failed
    IceNegotiationFailed,
    /// Transport error (TCP/UDP)
    TransportError,
    /// No matching codec for call
    NoMatchingCodec,
    /// SIP SUBSCRIBE for an unsupported event package (e.g. presence, dialog)
    /// — pjsip responds 489 Bad Event, which is correct; just noisy at ERROR level
    BadEventSubscription,
    /// Unclassified message — logged at pjsip's original level
    Unclassified,
}

impl PjsipEvent {
    /// Try to classify a pjsip log message into a known event.
    /// Returns the event variant and optionally an upgraded log level
    /// (None = use pjsip's original level).
    fn classify(msg: &str) -> (Self, Option<u8>) {
        // Level overrides: 0=error, 1=error, 2=warn, 3=info
        if msg.contains("too many calls") {
            (Self::TooManyCalls, Some(0))
        } else if msg.contains("SSL_ERROR_SSL") || msg.contains("SSL_ERROR_SYSCALL") {
            (Self::SslHandshakeError, None)
        } else if msg.contains("Unable to send") && msg.contains("response") {
            (Self::SendResponseFailed, Some(1))
        } else if msg.contains("ICE") && msg.contains("failed") {
            (Self::IceNegotiationFailed, None)
        } else if msg.contains("Transport") && msg.contains("error") {
            (Self::TransportError, Some(1))
        } else if msg.contains("No matching codec") {
            (Self::NoMatchingCodec, None)
        } else if msg.contains("Unable to create server subscription") {
            // SIP clients SUBSCRIBE to presence/dialog after REGISTER — expected and harmless
            (Self::BadEventSubscription, Some(4))
        } else {
            (Self::Unclassified, None)
        }
    }

    /// Short tag for structured logging
    fn as_str(self) -> &'static str {
        match self {
            Self::TooManyCalls => "TOO_MANY_CALLS",
            Self::SslHandshakeError => "SSL_HANDSHAKE_ERROR",
            Self::SendResponseFailed => "SEND_RESPONSE_FAILED",
            Self::IceNegotiationFailed => "ICE_NEGOTIATION_FAILED",
            Self::TransportError => "TRANSPORT_ERROR",
            Self::NoMatchingCodec => "NO_MATCHING_CODEC",
            Self::BadEventSubscription => "BAD_EVENT_SUBSCRIBE",
            Self::Unclassified => "UNCLASSIFIED",
        }
    }
}

/// Extract "IP:PORT" from a PJSIP SSL error message.
///
/// PJSIP ssl_sock logs include `peer: IP:PORT` at the end of the message.
/// Returns the "IP:PORT" substring, or None if not found.
fn extract_ssl_peer(msg: &str) -> Option<&str> {
    let idx = msg.find("peer: ")?;
    let rest = &msg[idx + 6..];
    let trimmed = rest.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed)
    }
}

/// PJSIP log callback - redirects logs to Rust tracing
///
/// This function is called by PJSIP for each log message instead of printing to stdout.
/// We map PJSIP log levels to tracing levels, with overrides for known critical messages
/// that pjsip under-reports (e.g. "too many calls" logged at level 2/warn → upgraded to error).
unsafe extern "C" fn pjsip_log_callback(level: c_int, data: *const c_char, _len: c_int) {
    if data.is_null() {
        return;
    }

    let c_str = unsafe { std::ffi::CStr::from_ptr(data) };
    let msg = c_str.to_string_lossy();
    let msg = msg.trim_end();

    let (event, level_override) = PjsipEvent::classify(msg);
    let effective_level = level_override.unwrap_or(level as u8);

    if event == PjsipEvent::SslHandshakeError {
        // Extract peer IP for structured logging context
        let peer = extract_ssl_peer(msg).unwrap_or("unknown");
        tracing::warn!(target: "pjsip", event = "SSL_HANDSHAKE_ERROR", peer = peer, "{}", msg);
        return;
    }

    if event != PjsipEvent::Unclassified {
        let tag = event.as_str();
        match effective_level {
            0 | 1 => tracing::error!(target: "pjsip", event = tag, "{}", msg),
            2 => tracing::warn!(target: "pjsip", event = tag, "{}", msg),
            3 => tracing::info!(target: "pjsip", event = tag, "{}", msg),
            4 => tracing::debug!(target: "pjsip", event = tag, "{}", msg),
            _ => tracing::trace!(target: "pjsip", event = tag, "{}", msg),
        }
    } else {
        match effective_level {
            0 | 1 => tracing::error!(target: "pjsip", "{}", msg),
            2 => tracing::warn!(target: "pjsip", "{}", msg),
            3 => tracing::info!(target: "pjsip", "{}", msg),
            4 => tracing::debug!(target: "pjsip", "{}", msg),
            _ => tracing::trace!(target: "pjsip", "{}", msg),
        }
    }
}

/// Set the global callback handlers
pub fn set_callbacks(handlers: CallbackHandlers) {
    let callbacks = CALLBACKS.get_or_init(|| Mutex::new(None));
    *callbacks.lock() = Some(handlers);
}

/// Initialize pjsua with optional TLS support
pub fn init_pjsua(config: &SipConfig, tls_config: Option<&TlsConfig>) -> Result<()> {
    // Initialize public host config for Contact header rewriting on outgoing responses.
    // pjsua derives Contact from the TCP connection's local address (private IP), but
    // external clients need the public hostname to route BYE back to us.
    PUBLIC_HOST_CONFIG.get_or_init(|| {
        if !config.public_host.is_empty() {
            tracing::info!(
                "Public host Contact rewriting enabled: {}:{}",
                config.public_host,
                config.port
            );
            Some((config.public_host.clone(), config.port))
        } else {
            None
        }
    });

    // Initialize local network config for Contact header and SDP rewriting
    LOCAL_NET_CONFIG.get_or_init(|| {
        config.local_net.as_ref().and_then(|ln| {
            match ln.cidr.parse::<Ipv4Net>() {
                Ok(net) => {
                    tracing::info!(
                        "Local network rewriting enabled: {} -> {} for CIDR {}, RTP public IP: {:?}",
                        config.public_host, ln.host, ln.cidr, config.rtp_public_ip
                    );
                    Some((ln.host.clone(), net, config.port, config.rtp_public_ip.clone()))
                }
                Err(e) => {
                    tracing::error!("Invalid SIP_LOCAL_CIDR '{}': {}", ln.cidr, e);
                    None
                }
            }
        })
    });

    unsafe {
        // Create pjsua instance
        let status = pjsua_create();
        if status != pj_constants__PJ_SUCCESS as i32 {
            anyhow::bail!("Failed to create pjsua: {}", status);
        }

        // Disable automatic UDP->TCP switch for large SIP messages.
        // pjsip switches to TCP when a request exceeds 1300 bytes, but for
        // outbound calls to NATted clients, the client's UDP NAT mapping
        // won't accept TCP connections. We must respect the transport the
        // client registered with.
        {
            unsafe extern "C" {
                static mut pjsip_sip_cfg_var: pjsip_cfg_t;
            }
            pjsip_sip_cfg_var.endpt.disable_tcp_switch = pj_constants__PJ_TRUE as _;
            tracing::info!("Disabled automatic UDP->TCP switch for large SIP messages");
        }

        // Configure pjsua
        let mut cfg = MaybeUninit::<pjsua_config>::uninit();
        pjsua_config_default(cfg.as_mut_ptr());
        let cfg_ptr = cfg.assume_init_mut();

        // Allow enough concurrent call slots for real calls + spam that's being rejected.
        // Compile-time PJSUA_MAX_CALLS is set to 128 in config_site.h.
        cfg_ptr.max_calls = 128;

        // Set callbacks
        cfg_ptr.cb.on_incoming_call = Some(on_incoming_call_cb);
        cfg_ptr.cb.on_call_state = Some(on_call_state_cb);
        cfg_ptr.cb.on_call_media_state = Some(on_call_media_state_cb);
        cfg_ptr.cb.on_dtmf_digit = Some(on_dtmf_digit_cb);
        cfg_ptr.cb.on_call_rx_reinvite = Some(on_call_rx_reinvite_cb);

        // Logging config - redirect PJSIP logs to Rust tracing
        let mut log_cfg = MaybeUninit::<pjsua_logging_config>::uninit();
        pjsua_logging_config_default(log_cfg.as_mut_ptr());
        let log_cfg_ptr = log_cfg.assume_init_mut();
        let configured_level = crate::config::AppConfig::bridge().pjsip_log_level;
        tracing::info!("PJSIP log level from config: {}", configured_level);
        log_cfg_ptr.level = configured_level as _;
        log_cfg_ptr.console_level = configured_level as _; // Must match level — cb is gated by console_level
        log_cfg_ptr.cb = Some(pjsip_log_callback); // Our callback replaces default console output

        // Media config
        let mut media_cfg = MaybeUninit::<pjsua_media_config>::uninit();
        pjsua_media_config_default(media_cfg.as_mut_ptr());
        let media_cfg_ptr = media_cfg.assume_init_mut();

        // Configure conference bridge for 16kHz mono
        // This is the internal sample rate - pjsua will resample from codecs as needed
        media_cfg_ptr.clock_rate = CONF_SAMPLE_RATE;
        media_cfg_ptr.snd_clock_rate = CONF_SAMPLE_RATE;
        media_cfg_ptr.channel_count = CONF_CHANNELS;
        media_cfg_ptr.audio_frame_ptime = FRAME_PTIME_MS;
        // Set default SDP ptime to match internal frame ptime
        // If these differ, there can be timing mismatches
        media_cfg_ptr.ptime = FRAME_PTIME_MS;

        // Log the media config
        tracing::info!(
            "Media config: clock_rate={}, snd_clock_rate={}, audio_frame_ptime={}, ptime={}",
            media_cfg_ptr.clock_rate,
            media_cfg_ptr.snd_clock_rate,
            media_cfg_ptr.audio_frame_ptime,
            media_cfg_ptr.ptime
        );

        // Initialize pjsua
        let status = pjsua_init(cfg_ptr, log_cfg_ptr, media_cfg_ptr);
        if status != pj_constants__PJ_SUCCESS as i32 {
            anyhow::bail!("Failed to init pjsua: {}", status);
        }

        // Create UDP transport
        let mut t_cfg = MaybeUninit::<pjsua_transport_config>::uninit();
        pjsua_transport_config_default(t_cfg.as_mut_ptr());
        let t_cfg_ptr = t_cfg.assume_init_mut();
        t_cfg_ptr.port = config.port as u32;

        // Set public address if specified - keep CString alive until transport is created
        let public_host_cstring = if !config.public_host.is_empty() {
            let host = CString::new(config.public_host.as_str()).context("Invalid public host")?;
            t_cfg_ptr.public_addr = pj_str(host.as_ptr() as *mut c_char);
            Some(host)
        } else {
            None
        };

        let mut transport_id: c_int = 0;
        let status = pjsua_transport_create(
            pjsip_transport_type_e_PJSIP_TRANSPORT_UDP,
            t_cfg_ptr,
            &mut transport_id,
        );

        // CString can be dropped now
        drop(public_host_cstring);

        if status != pj_constants__PJ_SUCCESS as i32 {
            anyhow::bail!("Failed to create UDP transport: {}", status);
        }

        // Create TCP transport on the same port
        let mut tcp_cfg = MaybeUninit::<pjsua_transport_config>::uninit();
        pjsua_transport_config_default(tcp_cfg.as_mut_ptr());
        let tcp_cfg_ptr = tcp_cfg.assume_init_mut();
        tcp_cfg_ptr.port = config.port as u32;

        // Set public address for TCP - keep CString alive
        let tcp_public_host_cstring = if !config.public_host.is_empty() {
            let host =
                CString::new(config.public_host.as_str()).context("Invalid public host for TCP")?;
            tcp_cfg_ptr.public_addr = pj_str(host.as_ptr() as *mut c_char);
            Some(host)
        } else {
            None
        };

        let mut tcp_transport_id: c_int = 0;
        let status = pjsua_transport_create(
            pjsip_transport_type_e_PJSIP_TRANSPORT_TCP,
            tcp_cfg_ptr,
            &mut tcp_transport_id,
        );

        drop(tcp_public_host_cstring);

        if status != pj_constants__PJ_SUCCESS as i32 {
            anyhow::bail!("Failed to create TCP transport: {}", status);
        }

        tracing::info!("TCP transport created on port {}", config.port);

        // Create TLS transport if configured (skip gracefully if certs missing)
        if let Some(tls) = tls_config
            && !create_tls_transport(tls, &config.public_host)?
        {
            tracing::warn!("TLS transport not created - running without TLS");
        }

        // Start pjsua
        let status = pjsua_start();
        if status != pj_constants__PJ_SUCCESS as i32 {
            anyhow::bail!("Failed to start pjsua: {}", status);
        }

        // Configure codec priorities to keep INVITE SDP small.
        // Without this, PJSUA offers every compiled codec (~16 entries) plus a
        // T.140 text stream, producing an INVITE of ~1750 bytes. UDP packets
        // over ~1300 bytes get IP-fragmented and are silently dropped by many
        // NAT routers, which completely breaks outbound calls.
        //
        // Strategy: disable everything, then re-enable only what we need,
        // ordered by quality (highest priority = preferred in SDP negotiation).
        {
            // Disable all audio codecs first
            let all = CString::new("*").unwrap();
            pjsua_codec_set_priority(&pj_str(all.as_ptr() as *mut c_char), 0);

            // Re-enable desired codecs (highest priority = preferred in negotiation).
            // NOTE: G722 is registered internally at 16000Hz in PJSIP despite the
            // RFC 3551 SDP convention of advertising clock_rate=8000.
            let codecs: &[(&str, u8)] = &[
                ("opus/48000", 255),      // Best quality: adaptive, wideband/fullband
                ("G722/16000", 254),      // Wideband 16kHz, widely supported
                ("AMR/8000", 252),        // Adaptive narrowband
                ("PCMU/8000", 200),       // G.711 mu-law, ubiquitous fallback
                ("PCMA/8000", 199),       // G.711 A-law, ubiquitous fallback
                ("telephone-event", 200), // DTMF support (all sample rates)
            ];

            for (name, priority) in codecs {
                let codec_id = CString::new(*name).unwrap();
                let status =
                    pjsua_codec_set_priority(&pj_str(codec_id.as_ptr() as *mut c_char), *priority);
                if status != pj_constants__PJ_SUCCESS as i32 {
                    tracing::warn!("Failed to set codec priority for {}: {}", name, status);
                }
            }

            tracing::info!(
                "Codec priorities configured: {}",
                codecs
                    .iter()
                    .map(|(n, p)| format!("{}={}", n, p))
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }

        // Register custom module to handle REGISTER requests and Contact header rewriting
        // pjsua's high-level API only handles call-related events, but SIP clients
        // send REGISTER to register with the server. We intercept these at the PJSIP level.
        // We also intercept outgoing responses to rewrite Contact headers for local clients.
        static mut REGISTER_MODULE: pjsip_module = pjsip_module {
            prev: ptr::null_mut(),
            next: ptr::null_mut(),
            name: pj_str_t {
                ptr: ptr::null_mut(),
                slen: 0,
            },
            id: -1,
            priority: pjsip_module_priority_PJSIP_MOD_PRIORITY_APPLICATION as i32,
            load: None,
            start: None,
            stop: None,
            unload: None,
            on_rx_request: Some(on_rx_request_cb),
            on_rx_response: None,
            on_tx_request: Some(on_tx_request_cb),
            on_tx_response: Some(on_tx_response_cb),
            on_tsx_state: None,
        };

        // Set module name (must be done at runtime since pj_str needs mutable ptr)
        static MOD_NAME: &[u8] = b"mod-sipcord\0";
        REGISTER_MODULE.name = pj_str(MOD_NAME.as_ptr() as *mut c_char);

        // Get endpoint and register module
        let endpt = pjsua_get_pjsip_endpt();
        if !endpt.is_null() {
            let status = pjsip_endpt_register_module(endpt, &raw mut REGISTER_MODULE);
            if status != pj_constants__PJ_SUCCESS as i32 {
                tracing::warn!("Failed to register REGISTER handler module: {}", status);
            } else {
                tracing::info!("Registered REGISTER handler module");
                // Store the module pointer so register_handler can create
                // UAS transactions for deferred REGISTER responses.
                super::super::register_handler::set_register_module_ptr(&raw mut REGISTER_MODULE);
            }
        } else {
            tracing::warn!("Could not get PJSIP endpoint for module registration");
        }

        // Register NAT fixup module for far-end NAT traversal
        // This rewrites private IPs in Contact headers and SDP bodies of incoming
        // requests (INVITEs from NATted phones) and responses (for outbound calls)
        // to the actual public source IP, fixing RTP delivery for phones behind NAT.
        //
        // Priority 15 = runs BEFORE TSX_LAYER(16). This is critical because the
        // TSX layer's on_rx_response matches responses to transactions and then
        // synchronously triggers the full dialog + invite session processing chain
        // (updating remote target from Contact, SDP negotiation, ACK sending).
        // If NAT fixup ran after the TSX layer (as it did at priority 28), the
        // dialog would see the original private IPs, causing ACK and RTP to be
        // sent to unreachable private addresses.
        static mut NAT_FIXUP_MODULE: pjsip_module = pjsip_module {
            prev: ptr::null_mut(),
            next: ptr::null_mut(),
            name: pj_str_t {
                ptr: ptr::null_mut(),
                slen: 0,
            },
            id: -1,
            priority: 15, // Just before TSX_LAYER(16), after TRANSPORT_LAYER(8)
            load: None,
            start: None,
            stop: None,
            unload: None,
            on_rx_request: Some(on_rx_request_nat_fixup_cb),
            on_rx_response: Some(on_rx_response_nat_fixup_cb),
            on_tx_request: None,
            on_tx_response: None,
            on_tsx_state: None,
        };

        static NAT_FIXUP_MOD_NAME: &[u8] = b"mod-nat-fixup\0";
        NAT_FIXUP_MODULE.name = pj_str(NAT_FIXUP_MOD_NAME.as_ptr() as *mut c_char);

        if !endpt.is_null() {
            let status = pjsip_endpt_register_module(endpt, &raw mut NAT_FIXUP_MODULE);
            if status != pj_constants__PJ_SUCCESS as i32 {
                tracing::warn!("Failed to register NAT fixup module: {}", status);
            } else {
                tracing::info!("Registered NAT fixup module (priority 15, before TSX layer)");
            }
        }

        // Disable sound device and get the conference master port
        // This allows us to manually control audio I/O
        let master_port = pjsua_set_no_snd_dev();
        if master_port.is_null() {
            anyhow::bail!("Failed to set null sound device");
        }

        // Verify the master port's actual sample rate
        let master_port_info = &(*master_port).info;
        let aud_fmt = &master_port_info.fmt.det.aud;
        let actual_clock_rate = aud_fmt.clock_rate;
        let actual_channel_count = aud_fmt.channel_count;
        let actual_frame_time_usec = aud_fmt.frame_time_usec;
        let actual_bits_per_sample = aud_fmt.bits_per_sample;
        // Calculate samples per frame from frame time
        let actual_samples_per_frame = (actual_clock_rate * actual_frame_time_usec) / 1_000_000;

        tracing::info!(
            "Master port ACTUAL config: clock_rate={}, channels={}, frame_time={}us, bits={}, samples_per_frame={}",
            actual_clock_rate,
            actual_channel_count,
            actual_frame_time_usec,
            actual_bits_per_sample,
            actual_samples_per_frame
        );

        // CRITICAL: Verify the conference bridge is actually at our configured rate
        if actual_clock_rate != CONF_SAMPLE_RATE {
            tracing::error!(
                "SAMPLE RATE MISMATCH! Requested {}Hz but got {}Hz - audio will play at wrong speed!",
                CONF_SAMPLE_RATE,
                actual_clock_rate
            );
        }

        // Store the master port for audio thread access
        let conf_port = CONF_MASTER_PORT.get_or_init(|| Mutex::new(SendablePort(ptr::null_mut())));
        conf_port.lock().0 = master_port;

        tracing::info!(
            "Conference bridge configured: {}Hz, {} channel(s), {}ms frames ({} samples/frame)",
            CONF_SAMPLE_RATE,
            CONF_CHANNELS,
            FRAME_PTIME_MS,
            SAMPLES_PER_FRAME
        );

        // Create a local account for receiving calls
        let mut acc_cfg = MaybeUninit::<pjsua_acc_config>::uninit();
        pjsua_acc_config_default(acc_cfg.as_mut_ptr());
        let acc_cfg_ptr = acc_cfg.assume_init_mut();

        // Local account ID - keep CString alive until account is added
        let local_uri = CString::new(format!("sip:sipcord@{}", config.public_host))
            .context("Invalid local URI")?;
        acc_cfg_ptr.id = pj_str(local_uri.as_ptr() as *mut c_char);

        // Enable incoming calls without registration
        acc_cfg_ptr.register_on_acc_add = pj_constants__PJ_FALSE as i32;

        // Disable SIP session timers (RFC 4028). The bridge has its own RTP
        // inactivity timeouts, and session timer UPDATEs break when the remote
        // side is behind NAT (the UPDATE targets the Contact URI which may be
        // unreachable, causing retransmit storms and eventual 408 disconnect).
        acc_cfg_ptr.use_timer = pjsua_sip_timer_use_PJSUA_SIP_TIMER_INACTIVE;

        // Configure RTP port range for media
        // port is the starting port, port_range is how many consecutive ports to try
        acc_cfg_ptr.rtp_cfg.port = config.rtp_port_start as u32;
        acc_cfg_ptr.rtp_cfg.port_range = (config.rtp_port_end - config.rtp_port_start) as u32;

        // Set public IP for RTP if configured - this is advertised in SDP c= line
        // Without this, pjsua uses the local interface IP which won't work for NAT
        let rtp_public_ip_cstring = if let Some(ref public_ip) = config.rtp_public_ip {
            let ip_cstr = CString::new(public_ip.as_str()).context("Invalid RTP public IP")?;
            acc_cfg_ptr.rtp_cfg.public_addr = pj_str(ip_cstr.as_ptr() as *mut c_char);
            tracing::info!(
                "Account RTP config: port={}, port_range={} (ports {}-{}), public_addr={}",
                acc_cfg_ptr.rtp_cfg.port,
                acc_cfg_ptr.rtp_cfg.port_range,
                config.rtp_port_start,
                config.rtp_port_end,
                public_ip
            );
            Some(ip_cstr)
        } else {
            tracing::warn!(
                "RTP_PUBLIC_IP not set - SDP will advertise local IP, external calls won't work!"
            );
            tracing::info!(
                "Account RTP config: port={}, port_range={} (ports {}-{})",
                acc_cfg_ptr.rtp_cfg.port,
                acc_cfg_ptr.rtp_cfg.port_range,
                config.rtp_port_start,
                config.rtp_port_end
            );
            None
        };

        let mut acc_id: pjsua_acc_id = 0;
        let status = pjsua_acc_add(acc_cfg_ptr, pj_constants__PJ_TRUE as i32, &mut acc_id);

        // CStrings can be dropped now
        drop(local_uri);
        drop(rtp_public_ip_cstring);

        if status != pj_constants__PJ_SUCCESS as i32 {
            anyhow::bail!("Failed to add account: {}", status);
        }

        Ok(())
    }
}

/// Create TLS transport for SIP-over-TLS
/// Returns Ok(true) if created, Ok(false) if skipped due to missing certs
fn create_tls_transport(tls_config: &TlsConfig, public_host: &str) -> Result<bool> {
    // Check cert files exist before doing anything
    let cert_path = tls_config.cert_path();
    let key_path = tls_config.key_path();

    if !cert_path.exists() {
        tracing::warn!(
            "TLS certificate not found: {} - TLS disabled until cert is obtained",
            cert_path.display()
        );
        return Ok(false);
    }
    if !key_path.exists() {
        tracing::warn!(
            "TLS private key not found: {} - TLS disabled until cert is obtained",
            key_path.display()
        );
        return Ok(false);
    }

    tracing::info!("TLS cert path: {}", cert_path.display());
    tracing::info!("TLS key path: {}", key_path.display());

    unsafe {
        let mut t_cfg = MaybeUninit::<pjsua_transport_config>::uninit();
        pjsua_transport_config_default(t_cfg.as_mut_ptr());
        let t_cfg_ptr = t_cfg.assume_init_mut();

        // Set TLS port
        t_cfg_ptr.port = tls_config.port as u32;

        // Set public address
        let public_host_cstring = CString::new(public_host).context("Invalid public host")?;
        t_cfg_ptr.public_addr = pj_str(public_host_cstring.as_ptr() as *mut c_char);

        let cert_path_cstring =
            CString::new(cert_path.to_str().unwrap()).context("Invalid cert path")?;
        let key_path_cstring =
            CString::new(key_path.to_str().unwrap()).context("Invalid key path")?;

        // Set certificate and key
        t_cfg_ptr.tls_setting.cert_file = pj_str(cert_path_cstring.as_ptr() as *mut c_char);
        t_cfg_ptr.tls_setting.privkey_file = pj_str(key_path_cstring.as_ptr() as *mut c_char);

        // Also set CA list to the cert file (contains the chain) so pjsip sends full chain
        t_cfg_ptr.tls_setting.ca_list_file = pj_str(cert_path_cstring.as_ptr() as *mut c_char);

        // Create TLS transport
        let mut transport_id: c_int = 0;
        let status = pjsua_transport_create(
            pjsip_transport_type_e_PJSIP_TRANSPORT_TLS,
            t_cfg_ptr,
            &mut transport_id,
        );

        // CStrings can be dropped now
        drop(public_host_cstring);
        drop(cert_path_cstring);
        drop(key_path_cstring);

        if status != pj_constants__PJ_SUCCESS as i32 {
            anyhow::bail!("Failed to create TLS transport: {}", status);
        }

        // Store transport ID for potential reload
        let tls_id = TLS_TRANSPORT_ID.get_or_init(|| Mutex::new(None));
        *tls_id.lock() = Some(transport_id);

        tracing::info!(
            "TLS transport created on port {} (transport_id={})",
            tls_config.port,
            transport_id
        );

        Ok(true)
    }
}

/// Reload TLS transport with updated certificates, or create it if it didn't exist
///
/// This should only be called when there are no active calls.
/// Returns Ok(true) if reload/create was successful, Ok(false) if skipped (certs missing or calls active).
pub fn reload_tls_transport(tls_config: &TlsConfig, public_host: &str) -> Result<bool> {
    // Check active calls - don't reload if calls are active
    let active_calls = COUNTED_CALL_IDS
        .get()
        .map(|ids| ids.lock().len())
        .unwrap_or(0);
    if active_calls > 0 {
        tracing::info!("Skipping TLS reload: {} active calls", active_calls);
        return Ok(false);
    }

    // Check if we have an existing TLS transport to close first
    let tls_id_lock = TLS_TRANSPORT_ID.get_or_init(|| Mutex::new(None));
    let old_transport_id = {
        let guard = tls_id_lock.lock();
        *guard
    };

    if let Some(old_id) = old_transport_id {
        tracing::info!("Closing existing TLS transport (id={})", old_id);

        unsafe {
            // Close old transport
            let status = pjsua_transport_close(old_id, pj_constants__PJ_FALSE as i32);
            if status != pj_constants__PJ_SUCCESS as i32 {
                tracing::warn!("Failed to close old TLS transport: {}", status);
                // Continue anyway - we'll try to create a new one
            }
        }

        // Clear the stored transport ID
        {
            let mut guard = tls_id_lock.lock();
            *guard = None;
        }
    } else {
        tracing::info!("No existing TLS transport - creating new one");
    }

    // Create new TLS transport (returns false if certs missing)
    let created = create_tls_transport(tls_config, public_host)?;

    if created {
        // Clear reload pending flag
        TLS_RELOAD_PENDING.store(false, Ordering::SeqCst);
        tracing::info!("TLS transport created/reloaded successfully");
    }

    Ok(created)
}

/// Set TLS reload pending flag
pub fn set_tls_reload_pending(pending: bool) {
    TLS_RELOAD_PENDING.store(pending, Ordering::SeqCst);
}

/// Get the count of active media calls
pub fn active_media_call_count() -> usize {
    COUNTED_CALL_IDS
        .get()
        .map(|ids| ids.lock().len())
        .unwrap_or(0)
}

/// Process pjsua events (call from event loop)
pub fn process_pjsua_events(timeout_ms: u32) -> Result<()> {
    unsafe {
        pj_thread_sleep(timeout_ms);
    }
    Ok(())
}

/// Answer an incoming call with 200 OK
///
/// This calls pjsua_call_answer directly. We previously queued this to the audio
/// thread to avoid deadlocks, but the actual deadlock was with pjsua_conf_connect
/// (now fixed by using pjmedia_conf_connect_port). Calling answer from the SIP
/// command thread is safe and avoids blocking the audio thread.
pub fn answer_call(call_id: CallId) {
    unsafe {
        // Get call info to check state before answering
        let mut ci = MaybeUninit::<pjsua_call_info>::uninit();
        if pjsua_call_get_info(*call_id, ci.as_mut_ptr()) == pj_constants__PJ_SUCCESS as i32 {
            let ci = ci.assume_init();
            let state = InvState::from(ci.state);
            tracing::info!(
                "Answering call {} with 200 OK (current_state={}, media_status={})",
                call_id,
                state,
                ci.media_status
            );
        } else {
            tracing::info!(
                "Answering call {} with 200 OK (couldn't get call info)",
                call_id
            );
        }

        // Call directly - this is safe now that we use pjmedia_conf_connect_port
        // instead of pjsua_conf_connect in the audio thread
        let status = pjsua_call_answer(*call_id, 200, ptr::null(), ptr::null());
        if status != pj_constants__PJ_SUCCESS as i32 {
            tracing::warn!("Failed to answer call {}: status={}", call_id, status);
        } else {
            tracing::info!("Call {} answered with 200 OK successfully", call_id);
        }
    }
}

/// Send 183 Session Progress (establishes early media for connecting sound)
///
/// This sends SDP to the caller, allowing them to hear audio before the call is
/// fully answered with 200 OK. Used to play the "connecting" sound while we
/// wait for Discord to connect.
pub fn send_183_session_progress(call_id: CallId) {
    unsafe {
        // Get call info to check state before sending 183
        let mut ci = MaybeUninit::<pjsua_call_info>::uninit();
        if pjsua_call_get_info(*call_id, ci.as_mut_ptr()) == pj_constants__PJ_SUCCESS as i32 {
            let ci = ci.assume_init();
            let state = InvState::from(ci.state);
            tracing::info!(
                "Sending 183 Session Progress for call {} (current_state={}, media_status={})",
                call_id,
                state,
                ci.media_status
            );
        } else {
            tracing::info!(
                "Sending 183 Session Progress for call {} (couldn't get call info)",
                call_id
            );
        }

        // Create reason string
        let reason = CString::new("Session Progress").unwrap();
        let reason_pj = pj_str(reason.as_ptr() as *mut c_char);

        let status = pjsua_call_answer(*call_id, 183, &reason_pj, ptr::null());
        if status != pj_constants__PJ_SUCCESS as i32 {
            tracing::warn!("Failed to send 183 for call {}: status={}", call_id, status);
        } else {
            tracing::info!("Call {} sent 183 Session Progress successfully", call_id);
        }
    }
}

/// Hangup a call
pub fn hangup_call(call_id: CallId) {
    unsafe {
        pjsua_call_hangup(*call_id, 0, ptr::null(), ptr::null());
    }
}

/// Shutdown pjsua and clean up resources
pub fn shutdown_pjsua() {
    tracing::info!("Shutting down pjsua...");

    // Stop and join audio thread first (must complete before pjsua_destroy)
    stop_audio_thread();

    unsafe {
        // Destroy pjsua
        tracing::info!("Calling pjsua_destroy...");
        pjsua_destroy();
    }

    tracing::info!("pjsua shutdown complete");
}

/// Register the current thread with PJLIB so it can safely call PJSUA functions.
///
/// Must be called once per thread before any PJSUA calls (except from the main thread
/// that called pjsua_create, which is already registered).
///
/// Returns true if registration succeeded (or thread was already registered).
pub fn register_thread_with_pjlib(thread_name: &str) -> bool {
    unsafe {
        // Check if already registered
        if pj_thread_is_registered() == pj_constants__PJ_TRUE as i32 {
            return true;
        }

        // Thread descriptor must live for the lifetime of the thread.
        // Using a thread-local static to ensure it stays alive.
        thread_local! {
            static THREAD_DESC: std::cell::UnsafeCell<pj_thread_desc> =
                const { std::cell::UnsafeCell::new([0; 64]) };
        }

        THREAD_DESC.with(|desc| {
            let name = CString::new(thread_name).unwrap_or_default();
            let mut thread_handle: *mut pj_thread_t = std::ptr::null_mut();

            let status = pj_thread_register(
                name.as_ptr() as *mut c_char,
                (*desc.get()).as_mut_ptr(),
                &mut thread_handle,
            );

            status == pj_constants__PJ_SUCCESS as i32
        })
    }
}
