//! PJSIP module for REGISTER request handling
//!
//! This module handles:
//! - REGISTER requests with 401 challenge / Digest auth verification
//! - Storing registrations in the Registrar for inbound call routing

use super::callbacks::{
    extract_digest_auth_from_rdata, extract_source_ip, extract_user_agent, is_sipvicious_scanner,
};
use super::ffi::types::*;
use super::ffi::utils::pj_str_to_string;
use pjsua::*;
use std::ffi::CString;
use std::net::SocketAddr;
use std::os::raw::c_char;
use std::ptr;
use std::sync::atomic::{AtomicPtr, Ordering};

// Sendable pointer wrappers for pjsip types (used to move tsx/tdata across
// threads via the SipCommand channel). These MUST only be dereferenced from
// the pjsua event-loop thread.

pub struct SendableTsx(pub *mut pjsip_transaction);
unsafe impl Send for SendableTsx {}

pub struct SendableTdata(pub *mut pjsip_tx_data);
unsafe impl Send for SendableTdata {}

/// A REGISTER transaction awaiting async auth verification.
/// Created in the pjsip callback, consumed in `process_sip_command`.
pub struct PendingRegisterTsx {
    pub tsx: SendableTsx,
    pub tdata: SendableTdata,
    pub expires: u32,
}

impl std::fmt::Debug for PendingRegisterTsx {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PendingRegisterTsx")
            .field("expires", &self.expires)
            .finish()
    }
}

// Globals

/// Channel for sending register events to the async verification task.
static REGISTER_EVENT_TX: std::sync::OnceLock<tokio::sync::mpsc::Sender<RegisterRequest>> =
    std::sync::OnceLock::new();

/// Sender half of the SIP command channel (for deferred REGISTER responses).
static SIP_COMMAND_TX: std::sync::OnceLock<crossbeam_channel::Sender<super::SipCommand>> =
    std::sync::OnceLock::new();

/// Pointer to the registered pjsip_module, needed for `pjsip_tsx_create_uas2`.
static REGISTER_MODULE_PTR: AtomicPtr<pjsip_module> = AtomicPtr::new(ptr::null_mut());

pub fn set_register_event_sender(tx: tokio::sync::mpsc::Sender<RegisterRequest>) {
    let _ = REGISTER_EVENT_TX.set(tx);
}

pub fn set_sip_command_sender(tx: crossbeam_channel::Sender<super::SipCommand>) {
    let _ = SIP_COMMAND_TX.set(tx);
}

pub fn set_register_module_ptr(ptr: *mut pjsip_module) {
    REGISTER_MODULE_PTR.store(ptr, Ordering::Release);
}

// Helpers

/// Initialize a pjsip_hdr as a list head (equivalent to pj_list_init C macro).
#[inline]
unsafe fn pj_list_init_hdr(hdr: *mut pjsip_hdr) {
    unsafe {
        (*hdr).next = hdr as *mut _;
        (*hdr).prev = hdr as *mut _;
    }
}

/// Send a simple stateless SIP response (no custom headers).
unsafe fn send_simple_response(rdata: *mut pjsip_rx_data, status_code: u16, reason: &str) {
    unsafe {
        let endpt = pjsua_get_pjsip_endpt();
        if !endpt.is_null() {
            let reason_cstr = CString::new(reason).unwrap();
            let reason_pj = pj_str(reason_cstr.as_ptr() as *mut c_char);
            pjsip_endpt_respond_stateless(
                endpt,
                rdata,
                status_code.into(),
                &reason_pj,
                ptr::null(),
                ptr::null(),
            );
        }
    }
}

/// Send a stateless 200 OK with an Expires header.
unsafe fn send_register_ok(rdata: *mut pjsip_rx_data, expires: u32) {
    unsafe {
        let endpt = pjsua_get_pjsip_endpt();
        if endpt.is_null() {
            return;
        }

        let expires_str = format!("{}", expires);
        let hdr_name = CString::new("Expires").unwrap();
        let hdr_value = CString::new(expires_str).unwrap();

        let pool = pjsua_pool_create(c"register_ok".as_ptr(), 512, 512);
        if !pool.is_null() {
            let name = pj_str(hdr_name.as_ptr() as *mut c_char);
            let value = pj_str(hdr_value.as_ptr() as *mut c_char);
            let hdr = pjsip_generic_string_hdr_create(pool, &name, &value);

            if !hdr.is_null() {
                let hdr_list =
                    pj_pool_alloc(pool, std::mem::size_of::<pjsip_hdr>()) as *mut pjsip_hdr;
                if !hdr_list.is_null() {
                    pj_list_init_hdr(hdr_list);
                    pj_list_insert_before(hdr_list as *mut pj_list_type, hdr as *mut pj_list_type);

                    let status = pjsip_endpt_respond_stateless(
                        endpt,
                        rdata,
                        200,
                        ptr::null(),
                        hdr_list,
                        ptr::null(),
                    );
                    if status != pj_constants__PJ_SUCCESS as i32 {
                        tracing::warn!("Failed to respond 200 OK to REGISTER: {}", status);
                    }
                    // Release pool — pjsip_endpt_respond_stateless clones what it
                    // needs into rdata's pool, so our header pool can be freed now.
                    pj_pool_release(pool);
                    return;
                }
            }
            // Header creation failed — release the pool before falling through
            pj_pool_release(pool);
        }

        // Fallback: respond without Expires header
        let status =
            pjsip_endpt_respond_stateless(endpt, rdata, 200, ptr::null(), ptr::null(), ptr::null());
        if status != pj_constants__PJ_SUCCESS as i32 {
            tracing::warn!("Failed to respond 200 OK to REGISTER: {}", status);
        }
    }
}

/// Detect transport type (UDP/TCP/TLS) from the incoming request.
unsafe fn detect_transport(rdata: *mut pjsip_rx_data) -> crate::services::registrar::SipTransport {
    unsafe {
        if !(*rdata).tp_info.transport.is_null() {
            let tp_type = (*(*rdata).tp_info.transport).key.type_ as u32;
            if tp_type == pjsip_transport_type_e_PJSIP_TRANSPORT_TLS {
                crate::services::registrar::SipTransport::Tls
            } else if tp_type == pjsip_transport_type_e_PJSIP_TRANSPORT_TCP {
                crate::services::registrar::SipTransport::Tcp
            } else {
                crate::services::registrar::SipTransport::Udp
            }
        } else {
            crate::services::registrar::SipTransport::Udp
        }
    }
}

/// Create a UAS transaction + pre-built response tdata for deferred REGISTER
/// responses. Returns `None` if transaction creation fails (caller should fall
/// back to stateless response).
unsafe fn create_register_tsx(
    rdata: *mut pjsip_rx_data,
    expires: u32,
) -> Option<PendingRegisterTsx> {
    unsafe {
        let endpt = pjsua_get_pjsip_endpt();
        let module_ptr = REGISTER_MODULE_PTR.load(Ordering::Acquire);

        if endpt.is_null() || module_ptr.is_null() {
            return None;
        }

        // Create UAS transaction
        let mut tsx: *mut pjsip_transaction = ptr::null_mut();
        let status = pjsip_tsx_create_uas2(module_ptr, rdata, ptr::null_mut(), &mut tsx);
        if status != pj_constants__PJ_SUCCESS as i32 || tsx.is_null() {
            return None;
        }

        // Feed the request to the transaction (starts Timer F, stores headers)
        pjsip_tsx_recv_msg(tsx, rdata);

        // Pre-build a 200 OK response while rdata is still valid.
        // The status code / reason will be modified before sending if auth fails.
        let mut tdata: *mut pjsip_tx_data = ptr::null_mut();
        let status = pjsip_endpt_create_response(endpt, rdata, 200, ptr::null(), &mut tdata);
        if status != pj_constants__PJ_SUCCESS as i32 || tdata.is_null() {
            pjsip_tsx_terminate(tsx, 500);
            return None;
        }

        Some(PendingRegisterTsx {
            tsx: SendableTsx(tsx),
            tdata: SendableTdata(tdata),
            expires,
        })
    }
}

// Main callback

/// Callback to handle incoming SIP requests (for REGISTER support)
///
/// SIP clients send REGISTER requests to register with the server. pjsua's high-level
/// API doesn't handle REGISTER since it's designed as a client library. We intercept
/// REGISTER requests here.
///
/// Flow:
/// 1. REGISTER without Authorization header -> 401 with WWW-Authenticate challenge
/// 2. REGISTER with Authorization header:
///    a. Cache hit + verified  -> immediate 200 OK (stateless)
///    b. Cache hit + mismatch  -> immediate 403 Forbidden (stateless)
///    c. Cache miss            -> defer via UAS transaction, verify via API, respond later
pub unsafe extern "C" fn on_rx_request_cb(rdata: *mut pjsip_rx_data) -> pj_bool_t {
    unsafe {
        if rdata.is_null() {
            return pj_constants__PJ_FALSE as pj_bool_t;
        }

        let msg = (*rdata).msg_info.msg;
        if msg.is_null() {
            return pj_constants__PJ_FALSE as pj_bool_t;
        }

        // Check if this is a REGISTER request
        let method_id = (*msg).line.req.method.id;
        if method_id != pjsip_method_e_PJSIP_REGISTER_METHOD {
            // Not REGISTER, let other modules handle it
            return pj_constants__PJ_FALSE as pj_bool_t;
        }

        // Extract source IP for logging and ban checking
        let source_ip = extract_source_ip(rdata);
        let ip_str = source_ip
            .map(|ip| ip.to_string())
            .unwrap_or_else(|| "unknown".to_string());

        // Extract source port
        let source_port = (*rdata).pkt_info.src_port as u16;

        // Ban checks: skip if banning disabled or IP is whitelisted
        if let Some(ip) = source_ip
            && let Some(ban_mgr) = crate::services::ban::global()
            && ban_mgr.is_enabled()
            && !ban_mgr.is_whitelisted(&ip)
        {
            // Check if IP is banned
            let result = ban_mgr.check_banned(&ip);
            if result.is_banned {
                tracing::debug!("Rejecting REGISTER from banned IP {}", ip);
                send_simple_response(rdata, 403, "Forbidden");
                return pj_constants__PJ_TRUE as pj_bool_t;
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
                    let result = ban_mgr.record_permanent_ban(ip, "sipvicious_scanner_register");
                    if result.should_log {
                        tracing::warn!(
                            "PERMABAN IP {} - SIPVicious scanner detected in REGISTER: User-Agent='{}'",
                            ip,
                            user_agent
                        );
                    }
                }
            } else {
                tracing::warn!(
                    "SIPVicious scanner detected in REGISTER but no IP available: User-Agent='{}'",
                    user_agent
                );
            }
            send_simple_response(rdata, 403, "Forbidden");
            return pj_constants__PJ_TRUE as pj_bool_t;
        }

        // Rate limit REGISTER requests
        if let Some(ip) = source_ip
            && let Some(ban_mgr) = crate::services::ban::global()
            && ban_mgr.is_enabled()
            && !ban_mgr.is_whitelisted(&ip)
            && ban_mgr.record_register(ip)
        {
            tracing::debug!("Rejecting REGISTER from {} - rate limit exceeded", ip);
            send_simple_response(rdata, 429, "Too Many Requests");
            return pj_constants__PJ_TRUE as pj_bool_t;
        }

        // Try to extract Digest auth params from Authorization header
        let digest_params = extract_digest_auth_from_rdata(rdata);

        if let Some(mut params) = digest_params {
            // Has auth - fill in REGISTER method
            params.method = "REGISTER".to_string();

            // Check auth failure cooldown before processing
            if let Some(cache) = crate::services::auth_cache::AuthCache::global()
                && cache.is_in_cooldown(&params.username)
            {
                tracing::debug!(
                    "Rejecting REGISTER from {} (user={}) - auth cooldown active",
                    ip_str,
                    params.username
                );
                send_simple_response(rdata, 429, "Too Many Requests");
                return pj_constants__PJ_TRUE as pj_bool_t;
            }

            // Extract fields needed for all code paths
            let contact_uri = extract_contact_uri(rdata);
            let expires = extract_expires(rdata);
            let source_addr = source_ip.map(|ip| SocketAddr::new(ip, source_port));
            let transport = detect_transport(rdata);

            // Auth cache verification
            if let Some(cache) = crate::services::auth_cache::AuthCache::global() {
                use crate::services::auth_cache::VerifyResult;
                match cache.check(&params) {
                    VerifyResult::Verified => {
                        // Cache hit, auth OK — fast-path 200 OK
                        tracing::debug!(
                            "REGISTER auth OK (cached): user={} from {}",
                            params.username,
                            ip_str
                        );
                        send_register_ok(rdata, expires);
                        // Send to async handler for registrar update
                        if let Some(tx) = REGISTER_EVENT_TX.get() {
                            let _ = tx.try_send(RegisterRequest {
                                digest_auth: params,
                                contact_uri: contact_uri.unwrap_or_default(),
                                source_addr,
                                transport,
                                expires,
                                pending_tsx: None,
                            });
                        }
                        return pj_constants__PJ_TRUE as pj_bool_t;
                    }
                    VerifyResult::Mismatch => {
                        // Wrong password (cached HA1 didn't match) — 403
                        tracing::debug!(
                            "REGISTER auth mismatch (cached): user={} from {}",
                            params.username,
                            ip_str
                        );
                        send_simple_response(rdata, 403, "Forbidden");
                        // Send to async so API can re-verify (cache may be stale
                        // after a password change) and update failure counts
                        if let Some(tx) = REGISTER_EVENT_TX.get() {
                            let _ = tx.try_send(RegisterRequest {
                                digest_auth: params,
                                contact_uri: contact_uri.unwrap_or_default(),
                                source_addr,
                                transport,
                                expires,
                                pending_tsx: None,
                            });
                        }
                        return pj_constants__PJ_TRUE as pj_bool_t;
                    }
                    VerifyResult::Miss => {
                        // No cached HA1 — need API round-trip.
                        // Create a UAS transaction so we can respond after the
                        // async handler completes, without blocking pjsip.
                        tracing::debug!(
                            "REGISTER cache miss: user={} from {}, deferring to API",
                            params.username,
                            ip_str
                        );
                        if let Some(pending) = create_register_tsx(rdata, expires) {
                            if let Some(tx) = REGISTER_EVENT_TX.get() {
                                let _ = tx.try_send(RegisterRequest {
                                    digest_auth: params,
                                    contact_uri: contact_uri.unwrap_or_default(),
                                    source_addr,
                                    transport,
                                    expires,
                                    pending_tsx: Some(pending),
                                });
                            }
                            return pj_constants__PJ_TRUE as pj_bool_t;
                        }
                        // Transaction creation failed — fall through to stateless
                        // 200 OK below (same behaviour as before this change).
                        tracing::warn!(
                            "Failed to create tsx for deferred REGISTER, falling back to stateless 200"
                        );
                    }
                }
            }

            // Default path: stateless 200 OK + async verification
            // (non-sipcord builds, auth cache unavailable, or tsx creation failed)
            tracing::debug!(
                "REGISTER with auth from {} (user={}), responding 200 OK (stateless)",
                ip_str,
                params.username
            );
            if let Some(tx) = REGISTER_EVENT_TX.get() {
                let _ = tx.try_send(RegisterRequest {
                    digest_auth: params,
                    contact_uri: contact_uri.unwrap_or_default(),
                    source_addr,
                    transport,
                    expires,
                    pending_tsx: None,
                });
            }
            send_register_ok(rdata, expires);
        } else {
            // No Authorization header - send 401 challenge
            tracing::debug!(
                "REGISTER without auth from {}, sending 401 challenge",
                ip_str
            );

            let endpt = pjsua_get_pjsip_endpt();
            if endpt.is_null() {
                tracing::error!("Failed to get PJSIP endpoint for REGISTER 401 response");
                return pj_constants__PJ_TRUE as pj_bool_t;
            }

            // Generate a cryptographically random nonce
            let nonce = {
                let bytes: [u8; 16] = rand::random();
                bytes
                    .iter()
                    .map(|b| format!("{:02x}", b))
                    .collect::<String>()
            };

            let www_auth = format!(
                "Digest realm=\"{}\", nonce=\"{}\", algorithm=MD5, qop=\"auth\"",
                SIP_REALM, nonce
            );

            // Create WWW-Authenticate header
            let hdr_name = CString::new("WWW-Authenticate").unwrap();
            let hdr_value = CString::new(www_auth).unwrap();

            let pool = pjsua_pool_create(c"register_401".as_ptr(), 512, 512);
            if pool.is_null() {
                tracing::error!("Failed to create pool for REGISTER 401 response");
                return pj_constants__PJ_TRUE as pj_bool_t;
            }

            let name = pj_str(hdr_name.as_ptr() as *mut c_char);
            let value = pj_str(hdr_value.as_ptr() as *mut c_char);
            let hdr = pjsip_generic_string_hdr_create(pool, &name, &value);

            if !hdr.is_null() {
                let hdr_list =
                    pj_pool_alloc(pool, std::mem::size_of::<pjsip_hdr>()) as *mut pjsip_hdr;
                if !hdr_list.is_null() {
                    pj_list_init_hdr(hdr_list);
                    pj_list_insert_before(hdr_list as *mut pj_list_type, hdr as *mut pj_list_type);

                    let status = pjsip_endpt_respond_stateless(
                        endpt,
                        rdata,
                        401,
                        ptr::null(),
                        hdr_list,
                        ptr::null(),
                    );

                    if status != pj_constants__PJ_SUCCESS as i32 {
                        tracing::warn!("Failed to respond 401 to REGISTER: {}", status);
                    }
                }
            }
            // Release pool — pjsip_endpt_respond_stateless clones headers internally
            pj_pool_release(pool);
        }

        // Return TRUE to indicate we handled this request
        pj_constants__PJ_TRUE as pj_bool_t
    }
}

// Extraction helpers

/// Extract Contact URI from REGISTER request
unsafe fn extract_contact_uri(rdata: *mut pjsip_rx_data) -> Option<String> {
    if rdata.is_null() {
        return None;
    }

    unsafe {
        let msg = (*rdata).msg_info.msg;
        if msg.is_null() {
            return None;
        }

        let contact_hdr = pjsip_msg_find_hdr(msg, pjsip_hdr_e_PJSIP_H_CONTACT, ptr::null_mut())
            as *const pjsip_contact_hdr;

        if contact_hdr.is_null() {
            return None;
        }

        let uri = (*contact_hdr).uri;
        if uri.is_null() {
            return None;
        }

        // The Contact header URI is typically a pjsip_name_addr wrapping a pjsip_sip_uri.
        // We must unwrap it via the vtable's p_get_uri (equivalent to pjsip_uri_get_uri()
        // which is an inline C function not available through FFI).
        let uri_vptr = (*(uri as *const pjsip_uri)).vptr;
        if uri_vptr.is_null() {
            return None;
        }
        let get_uri_fn = (*uri_vptr).p_get_uri?;
        let sip_uri_raw = get_uri_fn(uri as *mut std::os::raw::c_void);
        if sip_uri_raw.is_null() {
            return None;
        }
        let sip_uri = sip_uri_raw as *const pjsip_sip_uri;
        if (*sip_uri).host.ptr.is_null() || (*sip_uri).host.slen <= 0 {
            return None;
        }

        let host = pj_str_to_string(&(*sip_uri).host);
        let port = (*sip_uri).port;
        let user = if !(*sip_uri).user.ptr.is_null() && (*sip_uri).user.slen > 0 {
            Some(pj_str_to_string(&(*sip_uri).user))
        } else {
            None
        };

        let uri_str = match (user, port) {
            (Some(u), p) if p > 0 => format!("sip:{}@{}:{}", u, host, p),
            (Some(u), _) => format!("sip:{}@{}", u, host),
            (None, p) if p > 0 => format!("sip:{}:{}", host, p),
            (None, _) => format!("sip:{}", host),
        };

        Some(uri_str)
    }
}

/// Extract Expires value from REGISTER request (header or Contact param)
unsafe fn extract_expires(rdata: *mut pjsip_rx_data) -> u32 {
    if rdata.is_null() {
        return 3600;
    }

    unsafe {
        let msg = (*rdata).msg_info.msg;
        if msg.is_null() {
            return 3600;
        }

        // Try Expires header first
        let expires_hdr = pjsip_msg_find_hdr(msg, pjsip_hdr_e_PJSIP_H_EXPIRES, ptr::null_mut())
            as *const pjsip_expires_hdr;

        if !expires_hdr.is_null() {
            return (*expires_hdr).ivalue as u32;
        }

        // Default
        3600
    }
}

// Types

/// Data passed to the async register verification task
#[derive(Debug)]
pub struct RegisterRequest {
    pub digest_auth: DigestAuthParams,
    pub contact_uri: String,
    pub source_addr: Option<SocketAddr>,
    pub transport: crate::services::registrar::SipTransport,
    pub expires: u32,
    /// When set, the async handler must send the auth result back via
    /// `SipCommand::RespondRegister` so the pjsip thread can complete
    /// the UAS transaction.
    pub pending_tsx: Option<PendingRegisterTsx>,
}
