//! PJSUA C callbacks for incoming calls, call state, media state, and DTMF
//!
//! This module handles the C callbacks that PJSUA invokes for SIP events.

use super::audio_thread::{
    init_call_rtp_tracking, queue_pending_channel_completion, remove_call_rtp_tracking,
    start_audio_thread, stop_audio_thread,
};
use std::fmt;

/// Media direction (Rust wrapper for pjmedia_dir)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MediaDir {
    None,
    Encoding,
    Decoding,
    EncodingDecoding,
    Unknown(u32),
}

impl From<u32> for MediaDir {
    fn from(dir: u32) -> Self {
        match dir {
            x if x == pjmedia_dir_PJMEDIA_DIR_NONE => MediaDir::None,
            x if x == pjmedia_dir_PJMEDIA_DIR_ENCODING => MediaDir::Encoding,
            x if x == pjmedia_dir_PJMEDIA_DIR_DECODING => MediaDir::Decoding,
            x if x == pjmedia_dir_PJMEDIA_DIR_ENCODING_DECODING => MediaDir::EncodingDecoding,
            x => MediaDir::Unknown(x),
        }
    }
}

impl fmt::Display for MediaDir {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MediaDir::None => write!(f, "NONE"),
            MediaDir::Encoding => write!(f, "ENCODING"),
            MediaDir::Decoding => write!(f, "DECODING"),
            MediaDir::EncodingDecoding => write!(f, "ENCODING_DECODING"),
            MediaDir::Unknown(x) => write!(f, "UNKNOWN({})", x),
        }
    }
}
use super::channel_audio::{
    complete_pending_channel_registration, disconnect_call_for_hold, get_channel_slot,
};
use super::ffi::types::*;
use super::ffi::utils::{extract_sip_username, pj_str_to_string};
use dashmap::DashMap;
use parking_lot::Mutex;
use pjsua::*;
use std::ffi::CString;
use std::mem::MaybeUninit;
use std::net::IpAddr;
use std::os::raw::{c_char, c_int};
use std::ptr;

/// Global sender for outbound call events (set during initialization)
static OUTBOUND_EVENT_TX: std::sync::OnceLock<tokio::sync::mpsc::Sender<super::SipEvent>> =
    std::sync::OnceLock::new();

/// Pre-bound UDPTL sockets from synchronous T.38 re-INVITE handling.
/// Keyed by raw pjsua_call_id (i32). The async handler takes the socket
/// from this map to create the tokio UdptlSocket.
pub static T38_PRESOCKETS: std::sync::LazyLock<DashMap<i32, std::net::UdpSocket>> =
    std::sync::LazyLock::new(DashMap::new);

/// Set the outbound event sender (called from main.rs)
pub fn set_outbound_event_sender(tx: tokio::sync::mpsc::Sender<super::SipEvent>) {
    let _ = OUTBOUND_EVENT_TX.set(tx);
}

/// Extract source IP address from pjsip_rx_data
pub unsafe fn extract_source_ip(rdata: *const pjsip_rx_data) -> Option<IpAddr> {
    if rdata.is_null() {
        return None;
    }

    unsafe {
        // pjsip stores source info in pkt_info.src_name as a C string (null-terminated char array)
        let src_name = &(*rdata).pkt_info.src_name;

        // Find the null terminator
        let len = src_name
            .iter()
            .position(|&c| c == 0)
            .unwrap_or(src_name.len());

        // Convert to Rust string
        let ip_str = std::str::from_utf8(std::slice::from_raw_parts(
            src_name.as_ptr() as *const u8,
            len,
        ))
        .ok()?;

        // pjsip's src_name contains only the IP address (port is in src_port),
        // so parse directly as IpAddr. This handles both IPv4 and IPv6.
        ip_str.parse().ok()
    }
}

/// Extract User-Agent header from pjsip_rx_data
pub unsafe fn extract_user_agent(rdata: *const pjsip_rx_data) -> Option<String> {
    if rdata.is_null() {
        return None;
    }

    unsafe {
        let msg = (*rdata).msg_info.msg;
        if msg.is_null() {
            return None;
        }

        // Find User-Agent header by name
        let hdr_name = CString::new("User-Agent").ok()?;
        let name = pj_str(hdr_name.as_ptr() as *mut c_char);

        let hdr = pjsip_msg_find_hdr_by_name(msg, &name, ptr::null_mut());
        if hdr.is_null() {
            return None;
        }

        // Cast to generic string header
        let str_hdr = hdr as *const pjsip_generic_string_hdr;
        if str_hdr.is_null() {
            return None;
        }

        // Extract the header value
        let value = pj_str_to_string(&(*str_hdr).hvalue);
        if value.is_empty() { None } else { Some(value) }
    }
}

/// Check if User-Agent indicates a SIPVicious scanner or similar tool
pub fn is_sipvicious_scanner(user_agent: &str) -> bool {
    let ua_lower = user_agent.to_lowercase();
    ua_lower.contains("friendly-scanner")
        || ua_lower.contains("sipvicious")
        || ua_lower.contains("scanner")
}

/// Extract SIP Digest auth parameters from Authorization header
pub unsafe fn extract_digest_auth_from_rdata(
    rdata: *mut pjsip_rx_data,
) -> Option<DigestAuthParams> {
    if rdata.is_null() {
        return None;
    }

    unsafe {
        let rdata = &*rdata;
        let msg = rdata.msg_info.msg;
        if msg.is_null() {
            return None;
        }

        // Find Authorization header by type (pjsip parses it into a structured format)
        let hdr = pjsip_msg_find_hdr(msg, pjsip_hdr_e_PJSIP_H_AUTHORIZATION, ptr::null_mut());

        if hdr.is_null() {
            tracing::debug!("No Authorization header found");
            return None;
        }

        // Cast to authorization header type
        let auth_hdr = hdr as *const pjsip_authorization_hdr;
        if auth_hdr.is_null() {
            return None;
        }

        // Check the scheme is Digest
        let scheme = pj_str_to_string(&(*auth_hdr).scheme);
        tracing::debug!("Authorization scheme: {}", scheme);

        if scheme.to_lowercase() != "digest" {
            tracing::debug!(
                "Authorization header is not Digest auth (scheme: {})",
                scheme
            );
            return None;
        }

        // Extract digest credentials from the parsed structure
        let digest = &(*auth_hdr).credential.digest;

        let params = DigestAuthParams {
            username: pj_str_to_string(&digest.username),
            realm: pj_str_to_string(&digest.realm),
            nonce: pj_str_to_string(&digest.nonce),
            uri: pj_str_to_string(&digest.uri),
            response: pj_str_to_string(&digest.response),
            method: String::new(), // Will be set by caller
            qop: {
                let qop = pj_str_to_string(&digest.qop);
                if qop.is_empty() { None } else { Some(qop) }
            },
            nc: {
                let nc = pj_str_to_string(&digest.nc);
                if nc.is_empty() { None } else { Some(nc) }
            },
            cnonce: {
                let cnonce = pj_str_to_string(&digest.cnonce);
                if cnonce.is_empty() {
                    None
                } else {
                    Some(cnonce)
                }
            },
        };

        tracing::debug!(
            "Extracted Digest auth: user={}, realm={}, nonce={}, uri={}, response={}",
            params.username,
            params.realm,
            params.nonce,
            params.uri,
            params.response
        );

        // Validate we have the required fields
        if params.username.is_empty()
            || params.realm.is_empty()
            || params.nonce.is_empty()
            || params.uri.is_empty()
            || params.response.is_empty()
        {
            tracing::warn!("Digest auth missing required fields: {:?}", params);
            return None;
        }

        Some(params)
    }
}

/// Send 401 Unauthorized response with WWW-Authenticate header
pub unsafe fn send_401_challenge(call_id: CallId, www_auth: &str) {
    unsafe {
        // Create the WWW-Authenticate header
        let hdr_name = CString::new("WWW-Authenticate").unwrap();
        let hdr_value = CString::new(www_auth).unwrap();

        // Create msg_data with the WWW-Authenticate header
        let mut msg_data = MaybeUninit::<pjsua_msg_data>::uninit();
        pjsua_msg_data_init(msg_data.as_mut_ptr());
        let msg_data_ptr = msg_data.assume_init_mut();

        // Create a pool for the header
        let pool = pjsua_pool_create(c"auth".as_ptr(), 512, 512);
        if pool.is_null() {
            tracing::error!("Failed to create pool for 401 challenge");
            pjsua_call_hangup(*call_id, 500, ptr::null(), ptr::null());
            return;
        }

        // Create the header
        let name = pj_str(hdr_name.as_ptr() as *mut c_char);
        let value = pj_str(hdr_value.as_ptr() as *mut c_char);

        let hdr = pjsip_generic_string_hdr_create(pool, &name, &value);

        if !hdr.is_null() {
            // Add header to the list using pj_list_insert_before (insert at end of list)
            pj_list_insert_before(
                &mut msg_data_ptr.hdr_list as *mut _ as *mut pj_list_type,
                hdr as *mut pj_list_type,
            );
        }

        // Send 401 response - this will cause pjsua to send the response and then
        // the client should retry with Authorization header
        let reason = CString::new("Unauthorized").unwrap();
        let reason_pj = pj_str(reason.as_ptr() as *mut c_char);

        let status = pjsua_call_answer(*call_id, 401, &reason_pj, msg_data_ptr);
        if status != pj_constants__PJ_SUCCESS as i32 {
            tracing::warn!(
                "Failed to send 401 challenge for call {}: {}",
                call_id,
                status
            );
            // Hangup if we can't send challenge
            pjsua_call_hangup(*call_id, 500, ptr::null(), ptr::null());
        }

        // DO NOT release the pool here - PJSUA may still need the header data
        // after pjsua_call_answer returns. The pool will be cleaned up when
        // pjsua is destroyed. This leaks ~512 bytes per 401 challenge but
        // prevents use-after-free crashes.
        // TODO: Track pools per-call and release them in on_call_state when call ends
    }
}

/// Send 302 Moved Temporarily response with Contact header pointing to another bridge
/// Used for multi-region channel conflict resolution - redirects caller to the active region
pub unsafe fn send_302_redirect(call_id: CallId, target_domain: &str, extension: &str) {
    unsafe {
        // CRITICAL: Check if call is still valid and in a state that can receive responses
        // Race condition: caller may hang up during async API auth, causing the call to be
        // DISCONNECTED before we get here. Calling pjsua_call_answer on a disconnected call
        // can corrupt PJSUA internal state and deadlock the SIP worker thread.
        let mut ci = MaybeUninit::<pjsua_call_info>::uninit();
        if pjsua_call_get_info(*call_id, ci.as_mut_ptr()) != pj_constants__PJ_SUCCESS as i32 {
            tracing::warn!("Call {} no longer valid, skipping 302 redirect", call_id);
            return;
        }
        let ci = ci.assume_init();

        // Only send redirect if call is in INCOMING or EARLY state
        // (i.e., we haven't sent a final response yet and call hasn't been disconnected)
        if ci.state == pjsip_inv_state_PJSIP_INV_STATE_DISCONNECTED {
            tracing::warn!(
                "Call {} already disconnected, skipping 302 redirect to {}",
                call_id,
                target_domain
            );
            return;
        }
        if ci.state != pjsip_inv_state_PJSIP_INV_STATE_INCOMING
            && ci.state != pjsip_inv_state_PJSIP_INV_STATE_EARLY
        {
            tracing::warn!(
                "Call {} in unexpected state {} for 302 redirect, skipping",
                call_id,
                ci.state
            );
            return;
        }

        // Create the Contact header: sip:extension@target_domain
        let contact_uri = format!("sip:{}@{}", extension, target_domain);
        let hdr_name = CString::new("Contact").unwrap();
        let hdr_value = CString::new(contact_uri).unwrap();

        // Create msg_data with the Contact header
        let mut msg_data = MaybeUninit::<pjsua_msg_data>::uninit();
        pjsua_msg_data_init(msg_data.as_mut_ptr());
        let msg_data_ptr = msg_data.assume_init_mut();

        // Create a pool for the header
        let pool = pjsua_pool_create(c"redirect".as_ptr(), 512, 512);
        if pool.is_null() {
            tracing::error!("Failed to create pool for 302 redirect");
            pjsua_call_hangup(*call_id, 500, ptr::null(), ptr::null());
            return;
        }

        // Create the header
        let name = pj_str(hdr_name.as_ptr() as *mut c_char);
        let value = pj_str(hdr_value.as_ptr() as *mut c_char);

        let hdr = pjsip_generic_string_hdr_create(pool, &name, &value);

        if !hdr.is_null() {
            // Add header to the list using pj_list_insert_before (insert at end of list)
            pj_list_insert_before(
                &mut msg_data_ptr.hdr_list as *mut _ as *mut pj_list_type,
                hdr as *mut pj_list_type,
            );
        }

        // Send 302 response
        let reason = CString::new("Moved Temporarily").unwrap();
        let reason_pj = pj_str(reason.as_ptr() as *mut c_char);

        let status = pjsua_call_answer(*call_id, 302, &reason_pj, msg_data_ptr);
        if status != pj_constants__PJ_SUCCESS as i32 {
            tracing::warn!(
                "Failed to send 302 redirect for call {}: {}",
                call_id,
                status
            );
            // Hangup if we can't send redirect
            pjsua_call_hangup(*call_id, 500, ptr::null(), ptr::null());
        } else {
            tracing::info!(
                "Sent 302 redirect for call {} to {}",
                call_id,
                target_domain
            );
        }

        // DO NOT release the pool here - PJSUA may still need the header data
        // after pjsua_call_answer returns. Same issue as send_401_challenge.
    }
}

// PJSUA C callbacks

pub unsafe extern "C" fn on_incoming_call_cb(
    _acc_id: pjsua_acc_id,
    raw_call_id: pjsua_call_id,
    rdata: *mut pjsip_rx_data,
) {
    unsafe {
        let call_id = CallId::new(raw_call_id);
        let mut ci = MaybeUninit::<pjsua_call_info>::uninit();
        if pjsua_call_get_info(*call_id, ci.as_mut_ptr()) != pj_constants__PJ_SUCCESS as i32 {
            return;
        }
        let ci = ci.assume_init();

        // Extract From and To URIs
        let from_uri = pj_str_to_string(&ci.remote_info);
        let to_uri = pj_str_to_string(&ci.local_info);

        // Extract username from From URI (caller's SIP username)
        let sip_username = extract_sip_username(&from_uri);

        // Extract extension from To URI (the number they dialed)
        let extension = extract_sip_username(&to_uri);

        // Extract source IP for ban checking
        let source_ip = extract_source_ip(rdata);

        // Check if IP is banned or timed out - silently drop
        if let Some(ip) = source_ip
            && let Some(ban_mgr) = crate::services::ban::global()
            && ban_mgr.is_enabled()
            && !ban_mgr.is_whitelisted(&ip)
        {
            let result = ban_mgr.check_banned(&ip);
            if result.is_banned {
                if result.should_log {
                    let ban_type = if result.is_permanent {
                        "permanently banned"
                    } else {
                        "timed out"
                    };
                    tracing::debug!(
                        "Blocked {} IP: {} (call {}, offense_level={})",
                        ban_type,
                        ip,
                        call_id,
                        result.offense_level
                    );
                }
                pjsua_call_hangup(*call_id, 403, ptr::null(), ptr::null());
                return;
            }
        }

        // Check User-Agent for SIPVicious scanners - instant permaban
        if let Some(user_agent) = extract_user_agent(rdata)
            && is_sipvicious_scanner(&user_agent)
        {
            if let Some(ip) = source_ip {
                if let Some(ban_mgr) = crate::services::ban::global()
                    && ban_mgr.is_enabled()
                    && !ban_mgr.is_whitelisted(&ip)
                {
                    let result = ban_mgr.record_permanent_ban(ip, "sipvicious_scanner");
                    if result.should_log {
                        tracing::warn!(
                            "PERMABAN IP {} - SIPVicious scanner detected: User-Agent='{}' (call {})",
                            ip,
                            user_agent,
                            call_id
                        );
                    }
                }
            } else {
                tracing::warn!(
                    "SIPVicious scanner detected but no IP available: User-Agent='{}' (call {})",
                    user_agent,
                    call_id
                );
            }
            pjsua_call_hangup(*call_id, 403, ptr::null(), ptr::null());
            return;
        }

        // Extension-length ban checks use config values
        if let Some(ban_mgr) = crate::services::ban::global() {
            let ext_len = extension.len();
            let is_numeric = extension.chars().all(|c: char| c.is_ascii_digit());

            // Check for very long extension (permaban, likely fraud)
            if ext_len >= ban_mgr.permaban_extension_min_length() && is_numeric {
                if let Some(ip) = source_ip {
                    if ban_mgr.is_enabled() && !ban_mgr.is_whitelisted(&ip) {
                        let result = ban_mgr.record_permanent_ban(ip, "very_long_extension");
                        if result.should_log {
                            tracing::warn!(
                                "PERMABAN IP {} for very long extension: {} ({} digits, call {})",
                                ip,
                                extension,
                                ext_len,
                                call_id
                            );
                        }
                    }
                } else {
                    tracing::warn!(
                        "Rejecting very long extension: {} ({} digits, call {})",
                        extension,
                        ext_len,
                        call_id
                    );
                }
                pjsua_call_hangup(*call_id, 404, ptr::null(), ptr::null());
                return;
            }

            // Check for mid-length suspicious extension (progressive timeout)
            if ext_len >= ban_mgr.suspicious_extension_min_length()
                && ext_len <= ban_mgr.suspicious_extension_max_length()
                && is_numeric
            {
                if let Some(ip) = source_ip {
                    if ban_mgr.is_enabled() && !ban_mgr.is_whitelisted(&ip) {
                        let result = ban_mgr.record_offense(ip, "suspicious_extension");
                        if result.should_log {
                            tracing::warn!(
                                "Timed out IP {} for suspicious extension: {} (call {}, offense_level={}, timeout={}s)",
                                ip,
                                extension,
                                call_id,
                                result.offense_level,
                                result.timeout_secs
                            );
                        }
                    }
                } else {
                    tracing::warn!(
                        "Rejecting suspicious extension: {} ({} digits, call {})",
                        extension,
                        ext_len,
                        call_id
                    );
                }
                pjsua_call_hangup(*call_id, 404, ptr::null(), ptr::null());
                return;
            }
        }

        // Try to extract Digest auth params from Authorization header
        let digest_params = extract_digest_auth_from_rdata(rdata);

        tracing::info!(
            "Incoming call {} from {} to extension {} (auth: {})",
            call_id,
            sip_username,
            extension,
            if digest_params.is_some() {
                "present"
            } else {
                "none"
            }
        );

        // Check if we have Authorization header with Digest auth
        if let Some(mut params) = digest_params {
            // We have Digest auth, fill in remaining fields
            params.method = "INVITE".to_string();

            tracing::info!(
                "Digest auth: user={}, realm={}, nonce={}, response={}",
                params.username,
                params.realm,
                params.nonce,
                params.response
            );

            // NOTE: We no longer answer with 200 OK here.
            // The bridge coordinator will:
            // 1. Send 183 Session Progress (early media) to start playing connecting sound
            // 2. Connect to Discord
            // 3. Send 200 OK once Discord is ready
            //
            // This allows the caller to hear "connecting..." while waiting for Discord.

            // Trigger callbacks with Digest auth params
            // The bridge coordinator handles the call flow from here
            if let Some(callbacks) = CALLBACKS.get()
                && let Some(ref handlers) = *callbacks.lock()
            {
                (handlers.on_incoming_call)(call_id, sip_username, extension.clone(), source_ip);
                (handlers.on_call_authenticated)(call_id, params, extension, source_ip);
            }
        } else {
            // No Authorization header - send 401 challenge
            tracing::info!("No auth header, sending 401 challenge for call {}", call_id);

            // Generate a cryptographically random nonce
            let nonce = {
                let bytes: [u8; 16] = rand::random();
                bytes
                    .iter()
                    .map(|b| format!("{:02x}", b))
                    .collect::<String>()
            };

            // Create WWW-Authenticate header value
            // Format: Digest realm="sipcord", nonce="xxx", algorithm=MD5, qop="auth"
            let www_auth = format!(
                "Digest realm=\"{}\", nonce=\"{}\", algorithm=MD5, qop=\"auth\"",
                SIP_REALM, nonce
            );

            // Send 401 Unauthorized with WWW-Authenticate header
            send_401_challenge(call_id, &www_auth);
        }
    }
}

pub unsafe extern "C" fn on_dtmf_digit_cb(raw_call_id: pjsua_call_id, digit: c_int) {
    let call_id = CallId::new(raw_call_id);
    let digit_char = char::from_u32(digit as u32).unwrap_or('?');

    // Forward DTMF to callback handler (buffering done in mod.rs)
    if let Some(callbacks) = CALLBACKS.get()
        && let Some(ref handlers) = *callbacks.lock()
    {
        (handlers.on_dtmf)(call_id, digit_char);
    }
}

pub unsafe extern "C" fn on_call_state_cb(raw_call_id: pjsua_call_id, _e: *mut pjsip_event) {
    unsafe {
        let call_id = CallId::new(raw_call_id);
        let mut ci = MaybeUninit::<pjsua_call_info>::uninit();
        if pjsua_call_get_info(*call_id, ci.as_mut_ptr()) != pj_constants__PJ_SUCCESS as i32 {
            return;
        }
        let ci = ci.assume_init();

        // Check for outbound call state changes
        if let Some(tracking_id) = super::get_outbound_tracking_id(call_id) {
            // This is an outbound call (Discord -> SIP)
            if ci.state == pjsip_inv_state_PJSIP_INV_STATE_EARLY {
                // Ringing (180 Ringing or 183 Session Progress)
                // Ringing is tracked via ws_client::report_call_status from the bridge coordinator
                tracing::info!(
                    "Outbound call {} ringing (tracking_id={})",
                    call_id,
                    tracking_id
                );
            } else if ci.state == pjsip_inv_state_PJSIP_INV_STATE_CONFIRMED {
                tracing::info!(
                    "Outbound call {} answered (tracking_id={})",
                    call_id,
                    tracking_id
                );
                // Emit answered event - the SIP event handler in bridge/mod.rs picks this up
                if let Some(event_tx) = OUTBOUND_EVENT_TX.get() {
                    let _ = event_tx.try_send(super::SipEvent::OutboundCallAnswered {
                        tracking_id: tracking_id.clone(),
                        call_id,
                    });
                }
            } else if ci.state == pjsip_inv_state_PJSIP_INV_STATE_DISCONNECTED {
                let tracking_id = super::remove_outbound_tracking(call_id);
                if let Some(tid) = tracking_id {
                    let last_status = ci.last_status;
                    let last_status_text = pj_str_to_string(&ci.last_status_text);
                    tracing::info!(
                        "Outbound call {} disconnected (tracking_id={}, status={} {})",
                        call_id,
                        tid,
                        last_status,
                        last_status_text
                    );
                    if let Some(event_tx) = OUTBOUND_EVENT_TX.get() {
                        let _ = event_tx.try_send(super::SipEvent::OutboundCallFailed {
                            tracking_id: tid,
                            call_id: Some(call_id),
                            reason: format!("{} {}", last_status, last_status_text),
                        });
                    }
                }
                // Fall through to normal disconnect handling below —
                // outbound calls ARE tracked in sip_calls/bridges and need
                // proper cleanup (on_call_ended → CallEnded event).
            }
            // For non-disconnect states, return early - outbound calls don't use the normal flow
            if ci.state != pjsip_inv_state_PJSIP_INV_STATE_DISCONNECTED {
                return;
            }
        }

        // Check if call ended
        if ci.state == pjsip_inv_state_PJSIP_INV_STATE_DISCONNECTED {
            // Clean up audio buffer
            if let Some(buffers) = AUDIO_OUT_BUFFERS.get() {
                buffers.remove(&call_id);
            }

            // Clean up RTP activity tracking
            remove_call_rtp_tracking(call_id);

            let counted_ids =
                COUNTED_CALL_IDS.get_or_init(|| Mutex::new(std::collections::HashSet::new()));
            let (was_counted, new_count) = {
                let mut ids = counted_ids.lock();
                let was_counted = ids.remove(&call_id);
                (was_counted, ids.len())
            };

            // An authenticated call needs cleanup if it was in COUNTED_CALL_IDS (normal
            // case, or REMOTE_HOLD which now stays counted) OR if it has a CALL_CHANNELS
            // entry (which persists through LOCAL_HOLD). Without this, calls that
            // disconnect during LOCAL_HOLD would skip cleanup, leaving the bridge and
            // Discord connection alive forever.
            let was_authenticated = was_counted
                || CALL_CHANNELS
                    .get()
                    .map(|c| c.contains_key(&call_id))
                    .unwrap_or(false);

            if was_authenticated {
                tracing::info!("Call {} ended (active_media_calls={})", call_id, new_count);

                if let Some(callbacks) = CALLBACKS.get()
                    && let Some(ref handlers) = *callbacks.lock()
                {
                    (handlers.on_call_ended)(call_id);
                }

                if new_count == 0 {
                    tracing::debug!("Last call ended, stopping audio thread");
                    stop_audio_thread();
                }
            }
            // Spam/unauthenticated calls - no logging, no callbacks
        }
    }
}

pub unsafe extern "C" fn on_call_media_state_cb(raw_call_id: pjsua_call_id) {
    unsafe {
        let call_id = CallId::new(raw_call_id);
        let mut ci = MaybeUninit::<pjsua_call_info>::uninit();
        if pjsua_call_get_info(*call_id, ci.as_mut_ptr()) != pj_constants__PJ_SUCCESS as i32 {
            return;
        }
        let ci = ci.assume_init();

        // Log media state changes (debug level for general changes, specific states logged at info)
        let media_status_str = if ci.media_status == pjsua_call_media_status_PJSUA_CALL_MEDIA_NONE {
            "NONE"
        } else if ci.media_status == pjsua_call_media_status_PJSUA_CALL_MEDIA_ACTIVE {
            "ACTIVE"
        } else if ci.media_status == pjsua_call_media_status_PJSUA_CALL_MEDIA_LOCAL_HOLD {
            "LOCAL_HOLD"
        } else if ci.media_status == pjsua_call_media_status_PJSUA_CALL_MEDIA_REMOTE_HOLD {
            "REMOTE_HOLD"
        } else if ci.media_status == pjsua_call_media_status_PJSUA_CALL_MEDIA_ERROR {
            "ERROR"
        } else {
            "UNKNOWN"
        };

        tracing::info!(
            "Call {} media state changed to: {} (status={})",
            call_id,
            media_status_str,
            ci.media_status
        );

        // Check if media is active
        if ci.media_status == pjsua_call_media_status_PJSUA_CALL_MEDIA_ACTIVE {
            // Get the conference port for this call
            let conf_port = ConfPort::new(pjsua_call_get_conf_port(*call_id));

            // Log media direction for diagnostics
            let media_dir = if ci.media_cnt > 0 { ci.media[0].dir } else { 0 };
            let dir = MediaDir::from(media_dir);

            // Check if call is already registered with a channel
            let pending_channel = CALL_CHANNELS
                .get()
                .and_then(|c| c.get(&call_id).map(|r| *r));

            // Get codec info including ptime
            let mut stream_info = MaybeUninit::<pjsua_stream_info>::uninit();
            let codec_info = if pjsua_call_get_stream_info(*call_id, 0, stream_info.as_mut_ptr())
                == pj_constants__PJ_SUCCESS as i32
            {
                let si = stream_info.assume_init();
                // si.info is a union, for audio it's pjmedia_stream_info
                let audio_info = si.info.aud;
                let codec_name = std::ffi::CStr::from_ptr(
                    audio_info.fmt.encoding_name.ptr as *const std::ffi::c_char,
                )
                .to_string_lossy();
                let clock_rate = audio_info.fmt.clock_rate;
                let channel_cnt = audio_info.fmt.channel_cnt;
                // Get ptime from the param field (need to dereference pointer)
                let param = &*audio_info.param;
                let ptime = param.setting.frm_per_pkt as u32 * param.info.frm_ptime as u32;
                format!(
                    "{} @ {}Hz {}ch, ptime={}ms, frm_per_pkt={}, frm_ptime={}",
                    codec_name,
                    clock_rate,
                    channel_cnt,
                    ptime,
                    param.setting.frm_per_pkt,
                    param.info.frm_ptime
                )
            } else {
                "unknown".to_string()
            };

            tracing::info!(
                "Call {} MEDIA ACTIVE: conf_port={}, media_dir={}, media_cnt={}, call_state={}, pending_channel={:?}, codec={}",
                call_id,
                conf_port,
                dir,
                ci.media_cnt,
                ci.state,
                pending_channel,
                codec_info
            );

            if conf_port.is_valid() {
                tracing::info!(
                    "Call {} media active, storing conference port {} (NOT connecting to master yet)",
                    call_id,
                    conf_port
                );

                // Store the conf_port for this call - connections will be made when
                // the channel is assigned via register_call_channel()
                // This enables per-channel audio isolation: calls in different channels
                // won't hear each other.
                //
                // If this call is already registered with a channel and the
                // conf_port changed (due to re-INVITE/media renegotiation), we must
                // reconnect it to maintain audio flow.
                let old_conf_port = {
                    let ports = CALL_CONF_PORTS.get_or_init(DashMap::new);
                    let old = ports.get(&call_id).map(|r| *r);
                    ports.insert(call_id, conf_port);
                    old
                };

                // If conf_port changed and call is registered with a channel, reconnect it
                if let Some(old_port) = old_conf_port
                    && old_port != conf_port
                {
                    tracing::info!(
                        "Call {} conf_port changed from {} to {} (media renegotiation), reconnecting",
                        call_id,
                        old_port,
                        conf_port
                    );

                    // Get the channel this call is registered with
                    let channel_id = {
                        if let Some(channels) = CALL_CHANNELS.get() {
                            channels.get(&call_id).map(|r| *r)
                        } else {
                            None
                        }
                    };

                    if let Some(channel_id) = channel_id {
                        // Reconnect to channel port (bidirectional)
                        if let Some(channel_slot) = get_channel_slot(channel_id) {
                            // Disconnect old (both directions)
                            pjsua_conf_disconnect(*channel_slot, *old_port);
                            pjsua_conf_disconnect(*old_port, *channel_slot);
                            // Connect new (both directions)
                            pjsua_conf_connect(*channel_slot, *conf_port);
                            pjsua_conf_connect(*conf_port, *channel_slot);
                            tracing::info!(
                                "Reconnected channel {} port (slot {}) <-> call {} (new port {})",
                                channel_id,
                                channel_slot,
                                call_id,
                                conf_port
                            );
                        }

                        // Reconnect to other calls in the same channel
                        let other_calls: Vec<(CallId, ConfPort)> = {
                            let channel_calls = CHANNEL_CALLS.get();
                            let call_ports = CALL_CONF_PORTS.get();
                            if let (Some(cc), Some(cp)) = (channel_calls, call_ports) {
                                let cc_guard = cc.read();
                                if let Some(calls) = cc_guard.get(&channel_id) {
                                    calls
                                        .iter()
                                        .filter(|&&other_id| other_id != call_id)
                                        .filter_map(|&other_id| {
                                            cp.get(&other_id).map(|r| (other_id, *r))
                                        })
                                        .collect()
                                } else {
                                    vec![]
                                }
                            } else {
                                vec![]
                            }
                        };

                        for (other_id, other_port) in other_calls {
                            // Disconnect old bidirectional connections
                            pjsua_conf_disconnect(*old_port, *other_port);
                            pjsua_conf_disconnect(*other_port, *old_port);

                            // Connect new bidirectional connections
                            pjsua_conf_connect(*conf_port, *other_port);
                            pjsua_conf_connect(*other_port, *conf_port);

                            tracing::info!(
                                "Reconnected call {} (new port {}) <-> call {} (port {}) in channel {}",
                                call_id,
                                conf_port,
                                other_id,
                                other_port,
                                channel_id
                            );
                        }
                    }
                }

                tracing::info!(
                    "Call {} conf_port {} stored, awaiting channel registration",
                    call_id,
                    conf_port
                );

                // Initialize RTP activity tracking for this call
                init_call_rtp_tracking(call_id);

                // Track this call_id and start audio thread if this is the first active call
                // IMPORTANT: Start audio thread BEFORE completing pending channel registration!
                // The PJMEDIA conference bridge needs to be actively clocked when connections
                // are made, otherwise the connections may not work properly.
                let counted_ids =
                    COUNTED_CALL_IDS.get_or_init(|| Mutex::new(std::collections::HashSet::new()));
                let (is_new, count) = {
                    let mut ids = counted_ids.lock();
                    let is_new = ids.insert(call_id);
                    (is_new, ids.len())
                };

                // Only count this call if we haven't already (prevents double-counting on re-INVITE)
                if is_new {
                    tracing::info!(
                        "Call {} media ACTIVE, active_media_calls={}",
                        call_id,
                        count
                    );

                    if count == 1 {
                        tracing::info!("First active call, starting audio thread");
                        start_audio_thread();
                    }
                } else {
                    tracing::warn!(
                        "Call {} media ACTIVE but already counted! Skipping.",
                        call_id
                    );
                }

                // If returning from hold (is_new=true but call already in CHANNEL_CALLS),
                // remove from CHANNEL_CALLS so complete_pending_channel_registration does
                // a full fresh bidirectional reconnection. PJSUA may have changed the
                // underlying media stream during the hold/unhold re-INVITE cycle.
                // For first-time active calls, the call won't be in CHANNEL_CALLS yet,
                // so this is a no-op.
                if is_new
                    && let Some(channel_id) = CALL_CHANNELS
                        .get()
                        .and_then(|c| c.get(&call_id).map(|r| *r))
                {
                    let channel_calls = CHANNEL_CALLS
                        .get_or_init(|| parking_lot::RwLock::new(std::collections::HashMap::new()));
                    let mut map = channel_calls.write();
                    if let Some(calls) = map.get_mut(&channel_id)
                        && calls.remove(&call_id)
                    {
                        if calls.is_empty() {
                            map.remove(&channel_id);
                        }
                        tracing::info!(
                            "Call {} returning from hold - removed from CHANNEL_CALLS for fresh reconnection",
                            call_id
                        );
                    }
                }

                // If the call was already registered with a channel (Discord connected before
                // media was ready), complete the registration now. This must happen AFTER
                // the audio thread has actually started processing (not just spawned).
                // queue_pending_channel_completion returns true if queued (thread not ready),
                // false if we should complete immediately (thread is ready).
                if !queue_pending_channel_completion(call_id, conf_port) {
                    tracing::info!(
                        "Audio thread already ready, completing channel registration immediately for call {}",
                        call_id
                    );
                    complete_pending_channel_registration(call_id, conf_port);
                }
            } else {
                tracing::warn!("Call {} has invalid conference port", call_id);
            }
        } else if ci.media_status == pjsua_call_media_status_PJSUA_CALL_MEDIA_NONE {
            // Media went to NONE - this could happen during call setup/teardown
            let active_calls = COUNTED_CALL_IDS
                .get()
                .map(|ids| ids.lock().len())
                .unwrap_or(0);
            tracing::warn!(
                "Call {} media went to NONE, active_media_calls={}",
                call_id,
                active_calls
            );
        } else if ci.media_status == pjsua_call_media_status_PJSUA_CALL_MEDIA_ERROR {
            // Media error - this is bad!
            let active_calls = COUNTED_CALL_IDS
                .get()
                .map(|ids| ids.lock().len())
                .unwrap_or(0);
            tracing::error!(
                "Call {} media ERROR! active_media_calls={}",
                call_id,
                active_calls
            );
        } else if ci.media_status == pjsua_call_media_status_PJSUA_CALL_MEDIA_LOCAL_HOLD {
            tracing::info!("Call {} put on LOCAL_HOLD - disconnecting audio", call_id);

            // Disconnect the call from its channel without full teardown.
            // CALL_CHANNELS and CALL_CONF_PORTS are preserved so the existing
            // ACTIVE code path can reconnect when the call comes off hold.
            disconnect_call_for_hold(call_id);

            // Remove from COUNTED_CALL_IDS and stop audio thread if no other active calls
            let counted_ids =
                COUNTED_CALL_IDS.get_or_init(|| Mutex::new(std::collections::HashSet::new()));
            let (was_counted, new_count) = {
                let mut ids = counted_ids.lock();
                let was_counted = ids.remove(&call_id);
                (was_counted, ids.len())
            };

            if was_counted {
                tracing::info!(
                    "Call {} removed from active calls on hold (active_media_calls={})",
                    call_id,
                    new_count
                );
                if new_count == 0 {
                    tracing::debug!("No active calls remaining after hold, stopping audio thread");
                    stop_audio_thread();
                }
            }
        } else if ci.media_status == pjsua_call_media_status_PJSUA_CALL_MEDIA_REMOTE_HOLD {
            // Remote end put us on hold (e.g., Cisco hold button).
            // Keep conference connections AND audio thread running — many phones resume
            // RTP without sending a re-INVITE, so we never get an ACTIVE callback.
            // By keeping everything connected, audio naturally resumes when RTP flows again.
            //
            // Do NOT send re-INVITE or UPDATE — some phones (Cisco 7960G) reject UPDATE
            // with 405 and disconnect the call, and re-INVITE fails with 70013 because
            // the hold transaction is still active.
            //
            // Pause RTP inactivity tracking — phones send no RTP during hold.
            remove_call_rtp_tracking(call_id);

            tracing::info!(
                "Call {} put on REMOTE_HOLD - keeping audio connected (RTP tracking paused)",
                call_id
            );
        }
    }
}

/// T.38 offer parameters extracted from SDP
#[derive(Debug)]
pub struct T38OfferParams {
    pub remote_ip: String,
    pub remote_port: u16,
    pub t38_version: u8,
    pub max_bit_rate: u32,
    pub rate_management: String,
    pub udp_ec: String,
}

/// Check if an SDP offer contains a T.38 media line (`m=image ... udptl t38`).
unsafe fn sdp_has_t38(offer: *const pjmedia_sdp_session) -> Option<T38OfferParams> {
    if offer.is_null() {
        return None;
    }

    unsafe {
        for i in 0..(*offer).media_count {
            let m = (*offer).media[i as usize];
            if m.is_null() {
                continue;
            }

            // Check media type == "image"
            let media_type = pj_str_to_string(&(*m).desc.media);
            if media_type != "image" {
                continue;
            }

            // Check transport contains "udptl"
            let transport = pj_str_to_string(&(*m).desc.transport);
            if !transport.to_lowercase().contains("udptl") {
                continue;
            }

            // This is a T.38 media line
            let remote_port = (*m).desc.port;
            if remote_port == 0 {
                continue; // Disabled media line
            }

            // Extract IP from connection line (media-level c= or session-level c=)
            let conn = if !(*m).conn.is_null() {
                (*m).conn
            } else if !(*offer).conn.is_null() {
                (*offer).conn
            } else {
                tracing::warn!("T.38 SDP offer has no connection line");
                continue;
            };
            let remote_ip = pj_str_to_string(&(*conn).addr);

            // Extract T.38 attributes with defaults
            let mut t38_version: u8 = 0;
            let mut max_bit_rate: u32 = 14400;
            let mut rate_management = "transferredTCF".to_string();
            let mut udp_ec = "t38UDPRedundancy".to_string();

            for j in 0..(*m).attr_count {
                let attr = (*m).attr[j as usize];
                if attr.is_null() {
                    continue;
                }
                let name = pj_str_to_string(&(*attr).name);
                let value = pj_str_to_string(&(*attr).value);

                match name.as_str() {
                    "T38FaxVersion" => {
                        t38_version = value.parse().unwrap_or(0);
                    }
                    "T38MaxBitRate" => {
                        max_bit_rate = value.parse().unwrap_or(14400);
                    }
                    "T38FaxRateManagement" => {
                        rate_management = value;
                    }
                    "T38FaxUdpEC" => {
                        udp_ec = value;
                    }
                    _ => {}
                }
            }

            return Some(T38OfferParams {
                remote_ip,
                remote_port,
                t38_version,
                max_bit_rate,
                rate_management,
                udp_ec,
            });
        }

        None
    }
}

/// Callback for incoming re-INVITE with SDP offer.
///
/// When a phone sends a hold re-INVITE (with `a=sendonly`), pjsua would normally
/// respond with `a=recvonly` and enter REMOTE_HOLD, stopping RTP. Since we're a
/// bridge (not a PBX), we don't want hold semantics — we want audio to keep flowing.
///
/// Also detects T.38 re-INVITEs (`m=image udptl t38`) and emits a T38Offered event
/// to the bridge coordinator, which handles the mode switch.
///
/// Two-pronged fix for hold:
/// 1. Set PJSUA_CALL_SET_MEDIA_DIR flag to force def_dir to ENCODING_DECODING
/// 2. Strip hold direction attributes (sendonly/recvonly/inactive) from the SDP
///    negotiator's cloned remote offer. Without this, the negotiator rewrites our
///    answer to recvonly per RFC 3264, regardless of the flag.
pub unsafe extern "C" fn on_call_rx_reinvite_cb(
    raw_call_id: pjsua_call_id,
    offer: *const pjmedia_sdp_session,
    rdata: *mut pjsip_rx_data,
    _reserved: *mut std::os::raw::c_void,
    _async: *mut pj_bool_t,
    code: *mut pjsip_status_code,
    opt: *mut pjsua_call_setting,
) {
    unsafe {
        let call_id = CallId::new(raw_call_id);

        // Check for T.38 offer BEFORE applying hold-stripping logic
        if let Some(t38_params) = sdp_has_t38(offer) {
            tracing::info!(
                "Call {} received T.38 re-INVITE: remote={}:{}, version={}, rate={}, ec={}",
                call_id,
                t38_params.remote_ip,
                t38_params.remote_port,
                t38_params.t38_version,
                t38_params.max_bit_rate,
                t38_params.udp_ec
            );

            // Handle T.38 re-INVITE by sending 200 OK at the dialog level,
            // completely bypassing pjsip's inv session and pjsua's media handling.
            //
            // Why dialog-level? Three layers of pjsip fight us:
            //   1. pjsua_media_channel_init() crashes on T.38 (not audio)
            //   2. pjsip_inv_answer() asserts inv->last_answer (not set yet)
            //   3. pjsip_inv_send_msg() triggers on_media_update → crash
            //
            // By using pjsip_dlg_send_response() directly, we send the 200 OK
            // without touching the inv session's media machinery. We then cancel
            // the SDP offer and set code=488 so pjsua skips all media processing.

            // 1. Bind a std::net::UdpSocket within the configured RTP port range
            //    so firewall rules (which typically allow only the RTP range) also pass fax traffic.
            let env_config = crate::config::EnvConfig::global();
            let rtp_start = env_config.rtp_port_start;
            let rtp_end = env_config.rtp_port_end;
            let std_socket = {
                let mut bound = None;
                for port in rtp_start..=rtp_end {
                    match std::net::UdpSocket::bind(("0.0.0.0", port)) {
                        Ok(s) => {
                            bound = Some(s);
                            break;
                        }
                        Err(_) => continue,
                    }
                }
                match bound {
                    Some(s) => s,
                    None => {
                        tracing::error!(
                            "Call {}: failed to bind UDPTL socket in RTP range {}-{}",
                            call_id,
                            rtp_start,
                            rtp_end
                        );
                        pjsua_call_hangup(*call_id, 500, ptr::null(), ptr::null());
                        return;
                    }
                }
            };
            let local_port = match std_socket.local_addr() {
                Ok(addr) => addr.port(),
                Err(e) => {
                    tracing::error!("Call {}: failed to get UDPTL local addr: {}", call_id, e);
                    pjsua_call_hangup(*call_id, 500, ptr::null(), ptr::null());
                    return;
                }
            };

            // 2. Navigate rdata → tsx → dlg → inv
            if rdata.is_null() {
                tracing::error!("Call {}: rdata null for T.38 re-INVITE", call_id);
                pjsua_call_hangup(*call_id, 500, ptr::null(), ptr::null());
                return;
            }
            let tsx = pjsip_rdata_get_tsx(rdata);
            if tsx.is_null() {
                tracing::error!("Call {}: no transaction for T.38 re-INVITE", call_id);
                pjsua_call_hangup(*call_id, 500, ptr::null(), ptr::null());
                return;
            }
            let dlg = pjsip_tsx_get_dlg(tsx);
            if dlg.is_null() {
                tracing::error!("Call {}: no dialog for T.38 re-INVITE", call_id);
                pjsua_call_hangup(*call_id, 500, ptr::null(), ptr::null());
                return;
            }
            let inv = pjsip_dlg_get_inv_session(dlg);
            if inv.is_null() {
                tracing::error!("Call {}: no inv session for T.38 re-INVITE", call_id);
                pjsua_call_hangup(*call_id, 500, ptr::null(), ptr::null());
                return;
            }

            // 3. Build and parse T.38 SDP
            // Use RTP_PUBLIC_IP for the SDP c= line, matching what pjsua uses for audio SDP.
            // Many SIP devices (e.g. Cisco ATAs) cannot resolve hostnames in SDP and will
            // silently fall back to the audio endpoint, sending UDPTL to the wrong port.
            let config = crate::config::EnvConfig::global();
            let local_ip = config
                .rtp_public_ip
                .clone()
                .unwrap_or_else(|| config.sip_public_host_or_default().to_string());
            tracing::debug!("Using {} for T.38 SDP c= line", local_ip);
            let sess_id = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let sdp_str = format!(
                "v=0\r\n\
             o=- {} {} IN IP4 {}\r\n\
             s=T.38 Fax\r\n\
             c=IN IP4 {}\r\n\
             t=0 0\r\n\
             m=image {} udptl t38\r\n\
             a=T38FaxVersion:0\r\n\
             a=T38MaxBitRate:14400\r\n\
             a=T38FaxRateManagement:transferredTCF\r\n\
             a=T38FaxMaxBuffer:260\r\n\
             a=T38FaxMaxDatagram:316\r\n\
             a=T38FaxUdpEC:t38UDPRedundancy\r\n",
                sess_id, sess_id, local_ip, local_ip, local_port
            );

            let pool = pjsua_pool_create(c"t38sdp".as_ptr(), 1024, 256);
            if pool.is_null() {
                tracing::error!("Call {}: failed to create pool for T.38 SDP", call_id);
                pjsua_call_hangup(*call_id, 500, ptr::null(), ptr::null());
                return;
            }

            let sdp_bytes = sdp_str.as_bytes();
            let mut sdp: *mut pjmedia_sdp_session = ptr::null_mut();
            let status = pjmedia_sdp_parse(
                pool,
                sdp_bytes.as_ptr() as *mut std::os::raw::c_char,
                sdp_bytes.len(),
                &mut sdp,
            );
            if status != pj_constants__PJ_SUCCESS as i32 || sdp.is_null() {
                tracing::error!(
                    "Call {}: failed to parse T.38 SDP (status={})",
                    call_id,
                    status
                );
                pj_pool_release(pool);
                pjsua_call_hangup(*call_id, 500, ptr::null(), ptr::null());
                return;
            }

            // 4. Create 200 OK at dialog level (bypasses inv session media handling)
            let mut tdata: *mut pjsip_tx_data = ptr::null_mut();
            let status = pjsip_dlg_create_response(dlg, rdata, 200, ptr::null(), &mut tdata);
            if status != pj_constants__PJ_SUCCESS as i32 || tdata.is_null() {
                tracing::error!(
                    "Call {}: pjsip_dlg_create_response failed (status={})",
                    call_id,
                    status
                );
                pj_pool_release(pool);
                pjsua_call_hangup(*call_id, 500, ptr::null(), ptr::null());
                return;
            }

            // Attach SDP body to the 200 OK
            let mut body: *mut pjsip_msg_body = ptr::null_mut();
            let status = pjsip_create_sdp_body((*tdata).pool, sdp, &mut body);
            if status != pj_constants__PJ_SUCCESS as i32 || body.is_null() {
                tracing::error!(
                    "Call {}: pjsip_create_sdp_body failed (status={})",
                    call_id,
                    status
                );
                pjsip_tx_data_dec_ref(tdata);
                pj_pool_release(pool);
                pjsua_call_hangup(*call_id, 500, ptr::null(), ptr::null());
                return;
            }
            (*(*tdata).msg).body = body;

            // 5. Send 200 OK directly through the dialog transaction
            let status = pjsip_dlg_send_response(dlg, tsx, tdata);
            if status != pj_constants__PJ_SUCCESS as i32 {
                tracing::error!(
                    "Call {}: pjsip_dlg_send_response failed (status={})",
                    call_id,
                    status
                );
                pj_pool_release(pool);
                pjsua_call_hangup(*call_id, 500, ptr::null(), ptr::null());
                return;
            }

            // 6. Cancel the SDP offer on the negotiator (REMOTE_OFFER → DONE).
            //    This prevents pjsip from trying to negotiate or reject later.
            if !(*inv).neg.is_null() {
                pjmedia_sdp_neg_cancel_offer((*inv).neg);
            }

            // 7. Tell pjsua to skip ALL media processing for this re-INVITE.
            //    Setting code != 200 makes pjsua_call_on_rx_offer goto on_return
            //    immediately, avoiding apply_call_setting/pjsua_media_channel_init.
            //
            //    After this, pjsip's inv session will try to send a 488 rejection
            //    via pjsip_dlg_send_response(dlg, tsx, tdata). But the transaction
            //    was already terminated by our 200 OK above (INVITE UAS tsx →
            //    TERMINATED after 2xx per sip_transaction.c:3172). The terminated
            //    tsx's state handler returns PJ_EIGNORED for TX_MSG events, so the
            //    488 is never sent on the wire.
            if !code.is_null() {
                *code = 488;
            }

            tracing::info!(
                "Sent T.38 200 OK for call {} (local={}:{}) via dialog",
                call_id,
                local_ip,
                local_port
            );

            // 8. Store pre-bound socket for async UDPTL handler
            T38_PRESOCKETS.insert(raw_call_id, std_socket);

            // 9. Emit T38Offered event (with local_port so handler knows which port)
            if let Some(event_tx) = OUTBOUND_EVENT_TX.get() {
                let _ = event_tx.try_send(super::SipEvent::T38Offered {
                    call_id,
                    remote_ip: t38_params.remote_ip,
                    remote_port: t38_params.remote_port,
                    t38_version: t38_params.t38_version,
                    max_bit_rate: t38_params.max_bit_rate,
                    rate_management: t38_params.rate_management,
                    udp_ec: t38_params.udp_ec,
                    local_port,
                });
            }

            return;
        }

        // Normal re-INVITE (audio): apply hold-stripping logic
        // Set MEDIA_DIR flag to force sendrecv as default direction
        if !opt.is_null() {
            (*opt).flag |= pjsua_call_flag_PJSUA_CALL_SET_MEDIA_DIR;
            (*opt).media_dir[0] = pjmedia_dir_PJMEDIA_DIR_ENCODING_DECODING;
        }

        // Strip hold direction from the SDP negotiator's cloned remote offer.
        // The negotiator clones the offer before this callback, so we must modify
        // the clone (via rdata → tsx → dlg → inv → neg → neg_remote_sdp).
        // Without this, update_media_direction() in sdp_neg.c rewrites our answer
        // from sendrecv to recvonly when the remote offer has sendonly.
        let stripped = strip_hold_from_neg_remote(call_id, rdata);

        tracing::info!(
            "Call {} received re-INVITE, forcing sendrecv (sdp_stripped={})",
            call_id,
            stripped
        );
    }
}

/// Strip hold direction attributes from the SDP negotiator's remote offer clone.
/// Returns true if any hold attributes were found and removed.
unsafe fn strip_hold_from_neg_remote(call_id: CallId, rdata: *mut pjsip_rx_data) -> bool {
    if rdata.is_null() {
        tracing::warn!("Call {}: rdata null, cannot strip hold from offer", call_id);
        return false;
    }

    unsafe {
        // rdata → transaction → dialog → inv session → SDP negotiator
        let tsx = pjsip_rdata_get_tsx(rdata);
        if tsx.is_null() {
            tracing::warn!("Call {}: no transaction for re-INVITE", call_id);
            return false;
        }

        let dlg = pjsip_tsx_get_dlg(tsx);
        if dlg.is_null() {
            tracing::warn!("Call {}: no dialog for re-INVITE", call_id);
            return false;
        }

        let inv = pjsip_dlg_get_inv_session(dlg);
        if inv.is_null() {
            tracing::warn!("Call {}: no inv session for re-INVITE", call_id);
            return false;
        }

        let neg = (*inv).neg;
        if neg.is_null() {
            tracing::warn!("Call {}: no SDP negotiator", call_id);
            return false;
        }

        // Get the negotiator's cloned remote offer
        let mut remote: *const pjmedia_sdp_session = ptr::null();
        let status = pjmedia_sdp_neg_get_neg_remote(neg, &mut remote);
        if status != pj_constants__PJ_SUCCESS as i32 || remote.is_null() {
            tracing::warn!(
                "Call {}: failed to get remote SDP from negotiator (status={})",
                call_id,
                status
            );
            return false;
        }

        // Modify the clone in-place: strip hold direction attributes.
        // Cast away const — safe because neg_remote_sdp is a deep clone, not the original.
        // Removing these makes the SDP negotiator treat the offer as sendrecv (RFC 3264 default).
        let remote_mut = remote as *mut pjmedia_sdp_session;
        let mut stripped_any = false;

        for i in 0..(*remote_mut).media_count {
            let m = (*remote_mut).media[i as usize];
            if m.is_null() {
                continue;
            }

            let sendonly = c"sendonly".as_ptr();
            let recvonly = c"recvonly".as_ptr();
            let inactive = c"inactive".as_ptr();

            let had_sendonly = !pjmedia_sdp_media_find_attr2(m, sendonly, ptr::null()).is_null();
            let had_recvonly = !pjmedia_sdp_media_find_attr2(m, recvonly, ptr::null()).is_null();
            let had_inactive = !pjmedia_sdp_media_find_attr2(m, inactive, ptr::null()).is_null();

            if had_sendonly || had_recvonly || had_inactive {
                pjmedia_sdp_media_remove_all_attr(m, sendonly);
                pjmedia_sdp_media_remove_all_attr(m, recvonly);
                pjmedia_sdp_media_remove_all_attr(m, inactive);
                stripped_any = true;

                tracing::debug!(
                    "Call {} media {}: stripped hold direction (sendonly={}, recvonly={}, inactive={})",
                    call_id,
                    i,
                    had_sendonly,
                    had_recvonly,
                    had_inactive
                );
            }
        }

        stripped_any
    }
}
