//! PJSIP module for REGISTER request handling
//!
//! This module handles:
//! - REGISTER requests with 401 challenge / Digest auth verification
//! - Storing registrations in the Registrar for inbound call routing

use super::callbacks::{
    extract_digest_auth_from_rdata, extract_source_ip, extract_user_agent, is_sipvicious_scanner,
};
use super::contact::ContactHeaderRef;
use super::error::SipResponseError;
use super::ffi::pj_str::respond_stateless_with_headers;
use super::ffi::types::*;
use crate::services::registrar::{RegisteredContact, SipTransport};
use pjsua::*;
use std::ffi::CStr;
use std::net::SocketAddr;
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
    /// Complete Contact value echoed back in the 200 OK per RFC 3261 §10.3.
    /// Strict clients (3CX) treat the response as a forced-unregister when
    /// their binding isn't listed.
    pub contact_value: Option<String>,
}

struct ParsedRegisterContact {
    registration: RegisteredContact,
    response_value: String,
}

impl std::fmt::Debug for PendingRegisterTsx {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PendingRegisterTsx")
            .field("expires", &self.expires)
            .field("has_contact", &self.contact_value.is_some())
            .finish()
    }
}

// Globals

/// Channel for sending register events to the async verification task.
static REGISTER_EVENT_TX: std::sync::OnceLock<tokio::sync::mpsc::UnboundedSender<RegisterRequest>> =
    std::sync::OnceLock::new();

/// Sender half of the SIP command channel (for deferred REGISTER responses).
static SIP_COMMAND_TX: std::sync::OnceLock<crossbeam_channel::Sender<super::SipCommand>> =
    std::sync::OnceLock::new();

/// Pointer to the registered pjsip_module, needed for `pjsip_tsx_create_uas2`.
static REGISTER_MODULE_PTR: AtomicPtr<pjsip_module> = AtomicPtr::new(ptr::null_mut());

pub fn set_register_event_sender(tx: tokio::sync::mpsc::UnboundedSender<RegisterRequest>) {
    let _ = REGISTER_EVENT_TX.set(tx);
}

pub fn set_sip_command_sender(tx: crossbeam_channel::Sender<super::SipCommand>) {
    let _ = SIP_COMMAND_TX.set(tx);
}

pub fn set_register_module_ptr(ptr: *mut pjsip_module) {
    REGISTER_MODULE_PTR.store(ptr, Ordering::Release);
}

fn dispatch_register_request(
    request: RegisterRequest,
    event_tx: Option<&tokio::sync::mpsc::UnboundedSender<RegisterRequest>>,
    command_tx: Option<&crossbeam_channel::Sender<super::SipCommand>>,
) {
    let result = match event_tx {
        Some(tx) => tx.send(request).map_err(|error| error.0),
        None => Err(request),
    };
    let Err(mut request) = result else {
        return;
    };

    tracing::error!(
        "REGISTER verification queue is unavailable for user {}",
        request.digest_auth.username
    );
    if let Some(pending) = request.pending_tsx.take() {
        if let Some(tx) = command_tx {
            let _ = tx.send(super::SipCommand::RespondRegister {
                pending,
                auth_ok: false,
            });
        } else {
            tracing::error!(
                "SIP command queue is unavailable; deferred REGISTER cannot be rejected"
            );
        }
    }
}

fn queue_register_request(request: RegisterRequest) {
    dispatch_register_request(request, REGISTER_EVENT_TX.get(), SIP_COMMAND_TX.get());
}

// Helpers

/// Send a stateless SIP response with a status code and reason phrase but no
/// extra headers. Logs (and otherwise swallows) any pjsip failure — these
/// responses are best-effort from inside an FFI callback.
unsafe fn send_simple_response(rdata: *mut pjsip_rx_data, status_code: u16, reason: &CStr) {
    unsafe {
        if let Err(e) = respond_stateless_with_headers(rdata, status_code, Some(reason), &[]) {
            tracing::warn!(
                "Failed to respond {} {:?} to SIP request: {}",
                status_code,
                reason,
                e
            );
        }
    }
}

/// Send a stateless 200 OK with Expires + Contact headers.
///
/// RFC 3261 §10.3 step 8 requires the registrar's 200 OK to enumerate the
/// client's current bindings via Contact header(s). Strict clients like 3CX
/// interpret a Contact-less response as "forced unregister" and tear down the
/// trunk even though the binding was accepted server-side.
unsafe fn send_register_ok(
    rdata: *mut pjsip_rx_data,
    expires: u32,
    contact_value: Option<&str>,
) -> Result<(), SipResponseError> {
    unsafe {
        let expires_str = expires.to_string();

        // Two-header common case
        if let Some(contact) = contact_value {
            respond_stateless_with_headers(
                rdata,
                200,
                None,
                &[(c"Expires", expires_str.as_str()), (c"Contact", contact)],
            )
        } else {
            respond_stateless_with_headers(rdata, 200, None, &[(c"Expires", expires_str.as_str())])
        }
    }
}

/// Detect transport type (UDP/TCP/TLS) from the incoming request.
unsafe fn detect_transport(rdata: *mut pjsip_rx_data) -> SipTransport {
    unsafe {
        if !(*rdata).tp_info.transport.is_null() {
            let tp_type = (*(*rdata).tp_info.transport).key.type_ as u32;
            if tp_type == pjsip_transport_type_e_PJSIP_TRANSPORT_TLS
                || tp_type == pjsip_transport_type_e_PJSIP_TRANSPORT_TLS6
            {
                SipTransport::Tls
            } else if tp_type == pjsip_transport_type_e_PJSIP_TRANSPORT_TCP
                || tp_type == pjsip_transport_type_e_PJSIP_TRANSPORT_TCP6
            {
                SipTransport::Tcp
            } else {
                SipTransport::Udp
            }
        } else {
            SipTransport::Udp
        }
    }
}

fn needs_symmetric_register_response(
    transport_type: pjsip_transport_type_e,
    rport: i32,
    source_port: i32,
) -> bool {
    (transport_type == pjsip_transport_type_e_PJSIP_TRANSPORT_UDP
        || transport_type == pjsip_transport_type_e_PJSIP_TRANSPORT_UDP6)
        && rport < 0
        && source_port > 0
}

/// Broken UDP phones frequently omit RFC 3581 `rport` while sending from a
/// translated source port. For REGISTER only, make PJSIP's normal response
/// machinery use the actual packet source tuple. This happens before both
/// stateless responses and UAS transaction creation.
unsafe fn normalize_register_response_route(rdata: *mut pjsip_rx_data) {
    if rdata.is_null() {
        return;
    }

    let transport = unsafe { (*rdata).tp_info.transport };
    let via = unsafe { (*rdata).msg_info.via };
    if transport.is_null() || via.is_null() {
        return;
    }

    let transport_type = unsafe { (*transport).key.type_ as pjsip_transport_type_e };
    let source_port = unsafe { (*rdata).pkt_info.src_port };
    let rport = unsafe { (*via).rport_param };
    if !needs_symmetric_register_response(transport_type, rport, source_port) {
        return;
    }

    let advertised_port = unsafe { (*via).sent_by.port };
    let ignored_maddr = unsafe { (*via).maddr_param.slen > 0 };
    unsafe {
        (*via).rport_param = source_port;
        // PJSIP gives Via maddr precedence over rport. SIPcord is a unicast
        // registrar, so a missing-rport REGISTER must not redirect its reply
        // away from the packet source.
        (*via).maddr_param.ptr = ptr::null_mut();
        (*via).maddr_param.slen = 0;
    }
    tracing::debug!(
        source_port,
        advertised_port,
        ignored_maddr,
        "Using symmetric response routing for UDP REGISTER without rport"
    );
}

/// Create a UAS transaction + pre-built response tdata for deferred REGISTER
/// responses. Caller falls back to a stateless 200 if this errors.
unsafe fn create_register_tsx(
    rdata: *mut pjsip_rx_data,
    expires: u32,
    contact_value: Option<String>,
) -> Result<PendingRegisterTsx, SipResponseError> {
    unsafe {
        let endpt = pjsua_get_pjsip_endpt();
        if endpt.is_null() {
            return Err(SipResponseError::EndpointNull);
        }
        let module_ptr = REGISTER_MODULE_PTR.load(Ordering::Acquire);
        if module_ptr.is_null() {
            return Err(SipResponseError::EndpointNull);
        }

        // Create UAS transaction
        let mut tsx: *mut pjsip_transaction = ptr::null_mut();
        let status = pjsip_tsx_create_uas2(module_ptr, rdata, ptr::null_mut(), &mut tsx);
        if status != pj_constants__PJ_SUCCESS as i32 || tsx.is_null() {
            return Err(SipResponseError::TsxCreate(status));
        }

        // Feed the request to the transaction (starts Timer F, stores headers)
        pjsip_tsx_recv_msg(tsx, rdata);

        // Pre-build a 200 OK response while rdata is still valid.
        // The status code / reason will be modified before sending if auth fails.
        let mut tdata: *mut pjsip_tx_data = ptr::null_mut();
        let status = pjsip_endpt_create_response(endpt, rdata, 200, ptr::null(), &mut tdata);
        if status != pj_constants__PJ_SUCCESS as i32 || tdata.is_null() {
            pjsip_tsx_terminate(tsx, 500);
            return Err(SipResponseError::ResponseBuild(status));
        }

        Ok(PendingRegisterTsx {
            tsx: SendableTsx(tsx),
            tdata: SendableTdata(tdata),
            expires,
            contact_value,
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

        normalize_register_response_route(rdata);

        // Extract source IP for logging and ban checking
        let source_ip = extract_source_ip(rdata);
        let ip_str = source_ip
            .map(|ip| ip.to_string())
            .unwrap_or_else(|| "unknown".to_string());

        // Extract source port
        let source_port = u16::try_from((*rdata).pkt_info.src_port).unwrap_or_default();

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
                send_simple_response(rdata, 403, c"Forbidden");
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
            send_simple_response(rdata, 403, c"Forbidden");
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
            send_simple_response(rdata, 429, c"Too Many Requests");
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
                send_simple_response(rdata, 429, c"Too Many Requests");
                return pj_constants__PJ_TRUE as pj_bool_t;
            }

            // Extract fields needed for all code paths
            let expires = extract_expires(rdata);
            let source_addr = source_ip.map(|ip| SocketAddr::new(ip, source_port));
            let transport = detect_transport(rdata);
            let contact = extract_registered_contact(rdata, source_addr, transport, expires);

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
                        if let Err(e) = send_register_ok(
                            rdata,
                            expires,
                            contact
                                .as_ref()
                                .map(|contact| contact.response_value.as_str()),
                        ) {
                            tracing::warn!(
                                "REGISTER 200 OK (cached) send failed for {}: {} — strict clients may reject",
                                params.username,
                                e
                            );
                        }
                        // Send to async handler for registrar update
                        queue_register_request(RegisterRequest {
                            digest_auth: params,
                            contact: contact.map(|contact| contact.registration),
                            source_addr,
                            transport,
                            expires,
                            pending_tsx: None,
                        });
                        return pj_constants__PJ_TRUE as pj_bool_t;
                    }
                    VerifyResult::Mismatch => {
                        // Wrong password (cached HA1 didn't match) — 403
                        tracing::debug!(
                            "REGISTER auth mismatch (cached): user={} from {}",
                            params.username,
                            ip_str
                        );
                        send_simple_response(rdata, 403, c"Forbidden");
                        // Send to async so API can re-verify (cache may be stale
                        // after a password change) and update failure counts
                        queue_register_request(RegisterRequest {
                            digest_auth: params,
                            contact: contact.map(|contact| contact.registration),
                            source_addr,
                            transport,
                            expires,
                            pending_tsx: None,
                        });
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
                        let response_contact = contact
                            .as_ref()
                            .map(|contact| contact.response_value.clone());
                        match create_register_tsx(rdata, expires, response_contact) {
                            Ok(pending) => {
                                queue_register_request(RegisterRequest {
                                    digest_auth: params,
                                    contact: contact.map(|contact| contact.registration),
                                    source_addr,
                                    transport,
                                    expires,
                                    pending_tsx: Some(pending),
                                });
                                return pj_constants__PJ_TRUE as pj_bool_t;
                            }
                            Err(e) => {
                                // Transaction creation failed — fall through to
                                // stateless 200 OK below.
                                tracing::warn!(
                                    "Failed to create tsx for deferred REGISTER ({}), falling back to stateless 200",
                                    e
                                );
                            }
                        }
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
            let contact_value_for_response = contact
                .as_ref()
                .map(|contact| contact.response_value.clone());
            let user_for_log = params.username.clone();
            queue_register_request(RegisterRequest {
                digest_auth: params,
                contact: contact.map(|contact| contact.registration),
                source_addr,
                transport,
                expires,
                pending_tsx: None,
            });
            if let Err(e) = send_register_ok(rdata, expires, contact_value_for_response.as_deref())
            {
                tracing::warn!(
                    "REGISTER 200 OK (stateless) send failed for {}: {} — strict clients may reject",
                    user_for_log,
                    e
                );
            }
        } else {
            // No Authorization header - send 401 challenge
            tracing::debug!(
                "REGISTER without auth from {}, sending 401 challenge",
                ip_str
            );

            // Generate a cryptographically random nonce
            let nonce: String = {
                let bytes: [u8; 16] = rand::random();
                bytes.iter().map(|b| format!("{:02x}", b)).collect()
            };
            let www_auth = format!(
                "Digest realm=\"{}\", nonce=\"{}\", algorithm=MD5, qop=\"auth\"",
                SIP_REALM, nonce
            );

            if let Err(e) = respond_stateless_with_headers(
                rdata,
                401,
                None,
                &[(c"WWW-Authenticate", www_auth.as_str())],
            ) {
                tracing::warn!("Failed to send 401 challenge to REGISTER: {}", e);
            }
        }

        // Return TRUE to indicate we handled this request
        pj_constants__PJ_TRUE as pj_bool_t
    }
}

// Extraction helpers

/// Parse the first non-wildcard REGISTER Contact into owned data before the
/// request leaves the PJSIP thread.
unsafe fn extract_registered_contact(
    rdata: *mut pjsip_rx_data,
    source_addr: Option<SocketAddr>,
    transport: SipTransport,
    expires: u32,
) -> Option<ParsedRegisterContact> {
    if rdata.is_null() {
        return None;
    }

    unsafe {
        let msg = (*rdata).msg_info.msg;
        if msg.is_null() {
            return None;
        }

        let contact_header = ContactHeaderRef::find(msg)?;
        let uri = match contact_header.sip_uri() {
            Ok(Some(uri)) => uri,
            Ok(None) => return None,
            Err(error) => {
                tracing::warn!(%error, "Ignoring malformed REGISTER Contact");
                return None;
            }
        };

        let legacy_base_uri = uri.legacy_base_uri();
        let line = uri.parameter("line");
        let advertised_uri = match uri.print(pjsip_uri_context_e_PJSIP_URI_IN_CONTACT_HDR) {
            Ok(uri) => uri,
            Err(error) => {
                tracing::warn!(
                    %error,
                    contact = %legacy_base_uri,
                    "Falling back to legacy REGISTER Contact serialization"
                );
                legacy_base_uri.clone()
            }
        };
        let response_value = match contact_header.response_value((*rdata).tp_info.pool, expires) {
            Ok(value) => value,
            Err(error) => {
                tracing::warn!(
                    %error,
                    contact = %legacy_base_uri,
                    "Falling back to URI-only REGISTER Contact response"
                );
                format!("<{advertised_uri}>;expires={expires}")
            }
        };

        let callback_uri = source_addr
            .and_then(|source_addr| {
                let result = uri.callback_uri((*rdata).tp_info.pool, source_addr, transport);
                match result {
                    Ok(callback_uri) => Some(callback_uri),
                    Err(error) => {
                        tracing::warn!(
                            %error,
                            contact = %legacy_base_uri,
                            "Falling back to legacy callback URI construction"
                        );
                        None
                    }
                }
            })
            .or_else(|| {
                source_addr.map(|source_addr| {
                    build_legacy_callback_uri(&legacy_base_uri, source_addr, transport)
                })
            })
            .unwrap_or_else(|| advertised_uri.clone());

        Some(ParsedRegisterContact {
            registration: RegisteredContact::new(
                advertised_uri,
                legacy_base_uri,
                line,
                callback_uri,
            ),
            response_value,
        })
    }
}

fn build_legacy_callback_uri(
    contact_uri: &str,
    source_addr: SocketAddr,
    transport: SipTransport,
) -> String {
    let user = contact_uri
        .strip_prefix("sip:")
        .or_else(|| contact_uri.strip_prefix("sips:"))
        .and_then(|rest| rest.split_once('@').map(|(user, _)| user));
    let authority = user
        .map(|user| format!("{user}@{source_addr}"))
        .unwrap_or_else(|| source_addr.to_string());
    match transport {
        SipTransport::Tls => format!("sips:{authority}"),
        SipTransport::Tcp => format!("sip:{authority};transport=tcp"),
        SipTransport::Udp => format!("sip:{authority};transport=udp"),
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

        // A Contact-level expires parameter overrides the Expires header.
        // Many phones use only `Contact: <...>;expires=0` to unregister.
        if let Some(contact) = ContactHeaderRef::find(msg)
            && let Some(expires) = contact.expires()
        {
            return expires;
        }

        // Fall back to the request-wide Expires header.
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
    pub contact: Option<RegisteredContact>,
    pub source_addr: Option<SocketAddr>,
    pub transport: crate::services::registrar::SipTransport,
    pub expires: u32,
    /// When set, the async handler must send the auth result back via
    /// `SipCommand::RespondRegister` so the pjsip thread can complete
    /// the UAS transaction.
    pub pending_tsx: Option<PendingRegisterTsx>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(pending: bool) -> RegisterRequest {
        RegisterRequest {
            digest_auth: DigestAuthParams {
                username: "alice".into(),
                ..DigestAuthParams::default()
            },
            contact: Some(RegisteredContact::new(
                "sip:alice@phone.local".into(),
                "sip:alice@phone.local".into(),
                None,
                "sip:alice@203.0.113.5:5060;transport=udp".into(),
            )),
            source_addr: None,
            transport: SipTransport::Udp,
            expires: 300,
            pending_tsx: pending.then_some(PendingRegisterTsx {
                tsx: SendableTsx(ptr::null_mut()),
                tdata: SendableTdata(ptr::null_mut()),
                expires: 300,
                contact_value: Some("<sip:alice@phone.local>;expires=300".into()),
            }),
        }
    }

    #[test]
    fn live_verification_queue_receives_register() {
        let (event_tx, mut event_rx) = tokio::sync::mpsc::unbounded_channel();
        dispatch_register_request(request(false), Some(&event_tx), None);
        assert_eq!(event_rx.try_recv().unwrap().digest_auth.username, "alice");
    }

    #[test]
    fn closed_verification_queue_rejects_deferred_register() {
        let (event_tx, event_rx) = tokio::sync::mpsc::unbounded_channel();
        drop(event_rx);
        let (command_tx, command_rx) = crossbeam_channel::unbounded();

        dispatch_register_request(request(true), Some(&event_tx), Some(&command_tx));

        assert!(matches!(
            command_rx.try_recv(),
            Ok(super::super::SipCommand::RespondRegister { auth_ok: false, .. })
        ));
    }

    #[test]
    fn only_udp_without_rport_uses_symmetric_response_routing() {
        assert!(needs_symmetric_register_response(
            pjsip_transport_type_e_PJSIP_TRANSPORT_UDP,
            -1,
            51_896,
        ));
        assert!(needs_symmetric_register_response(
            pjsip_transport_type_e_PJSIP_TRANSPORT_UDP6,
            -1,
            51_896,
        ));
        assert!(!needs_symmetric_register_response(
            pjsip_transport_type_e_PJSIP_TRANSPORT_UDP,
            51_896,
            51_896,
        ));
        assert!(!needs_symmetric_register_response(
            pjsip_transport_type_e_PJSIP_TRANSPORT_TCP,
            -1,
            51_896,
        ));
        assert!(!needs_symmetric_register_response(
            pjsip_transport_type_e_PJSIP_TRANSPORT_TLS,
            -1,
            51_896,
        ));
        assert!(!needs_symmetric_register_response(
            pjsip_transport_type_e_PJSIP_TRANSPORT_UDP,
            -1,
            0,
        ));
    }

    #[test]
    fn symmetric_register_response_uses_packet_port_and_ignores_maddr() {
        let mut transport: pjsip_transport = unsafe { std::mem::zeroed() };
        transport.key.type_ = i64::from(pjsip_transport_type_e_PJSIP_TRANSPORT_UDP);

        let mut maddr = b"192.0.2.99".to_vec();
        let mut via: pjsip_via_hdr = unsafe { std::mem::zeroed() };
        via.rport_param = -1;
        via.sent_by.port = 5060;
        via.maddr_param = pj_str_t {
            ptr: maddr.as_mut_ptr().cast(),
            slen: maddr.len() as _,
        };

        let mut rdata: pjsip_rx_data = unsafe { std::mem::zeroed() };
        rdata.tp_info.transport = &mut transport;
        rdata.msg_info.via = &mut via;
        rdata.pkt_info.src_port = 51_896;

        unsafe { normalize_register_response_route(&mut rdata) };

        assert_eq!(via.rport_param, 51_896);
        assert!(via.maddr_param.ptr.is_null());
        assert_eq!(via.maddr_param.slen, 0);
        assert_eq!(via.sent_by.port, 5060);
    }

    #[test]
    fn legacy_callback_uri_keeps_observed_transport_and_source() {
        let source: SocketAddr = "203.0.113.8:51896".parse().unwrap();
        assert_eq!(
            build_legacy_callback_uri(
                "sip:sipcord-inbound@192.168.1.10:5060",
                source,
                SipTransport::Udp
            ),
            "sip:sipcord-inbound@203.0.113.8:51896;transport=udp"
        );
        assert_eq!(
            build_legacy_callback_uri(
                "sip:sipcord-inbound@192.168.1.10:5060",
                source,
                SipTransport::Tcp
            ),
            "sip:sipcord-inbound@203.0.113.8:51896;transport=tcp"
        );
        assert_eq!(
            build_legacy_callback_uri(
                "sip:sipcord-inbound@192.168.1.10:5060",
                source,
                SipTransport::Tls
            ),
            "sips:sipcord-inbound@203.0.113.8:51896"
        );
    }
}
