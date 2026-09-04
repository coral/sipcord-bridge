//! Shared PJSIP Contact header and SIP URI handling.
//!
//! PJSIP represents a Contact URI either directly as a `pjsip_sip_uri` or
//! wrapped in a `pjsip_name_addr`.  Keeping the lookup, unwrapping, validation,
//! serialization, and pool-backed mutation here avoids subtly different FFI
//! handling in the REGISTER and NAT paths.

use super::ffi::utils::pj_str_to_string;
use crate::services::registrar::SipTransport;
use pjsua::*;
use std::ffi::{CString, NulError};
use std::net::SocketAddr;
use std::os::raw::{c_char, c_void};
use std::ptr::{self, NonNull};
use std::string::FromUtf8Error;

#[derive(thiserror::Error, Debug)]
pub(super) enum ContactError {
    #[error("Contact header has no URI")]
    MissingUri,

    #[error("Contact URI has no PJSIP vtable")]
    MissingVtable,

    #[error("Contact URI does not provide {0}")]
    MissingOperation(&'static str),

    #[error("unsupported Contact URI scheme {0}")]
    UnsupportedScheme(String),

    #[error("Contact SIP URI has no host")]
    MissingHost,

    #[error("PJSIP pool is null")]
    PoolNull,

    #[error("PJSIP could not clone the Contact URI")]
    UriCloneFailed,

    #[error("PJSIP could not clone the Contact header")]
    HeaderCloneFailed,

    #[error("PJSIP could not serialize the Contact URI")]
    UriPrintFailed,

    #[error("PJSIP could not serialize the Contact header")]
    HeaderPrintFailed,

    #[error("serialized Contact header has no value")]
    MissingHeaderValue,

    #[error("Contact URI contains an interior NUL")]
    InvalidString(#[from] NulError),

    #[error("Contact URI allocation failed")]
    PoolAllocation,

    #[error("serialized Contact URI is not valid UTF-8")]
    InvalidUtf8(#[from] FromUtf8Error),
}

/// A Contact header borrowed from a live PJSIP message.
///
/// The constructor is unsafe because the message pool must remain alive while
/// this value is used.  Callers keep it inside the synchronous PJSIP callback.
#[derive(Clone, Copy)]
pub(super) struct ContactHeaderRef {
    ptr: NonNull<pjsip_contact_hdr>,
}

impl ContactHeaderRef {
    /// Find the first Contact header in `msg`.
    ///
    /// # Safety
    /// `msg` must point to a live PJSIP message for the duration of the
    /// returned reference's use.
    pub(super) unsafe fn find(msg: *mut pjsip_msg) -> Option<Self> {
        if msg.is_null() {
            return None;
        }

        let header = unsafe {
            pjsip_msg_find_hdr(msg, pjsip_hdr_e_PJSIP_H_CONTACT, ptr::null_mut())
                as *mut pjsip_contact_hdr
        };
        NonNull::new(header).map(|ptr| Self { ptr })
    }

    fn is_wildcard(self) -> bool {
        unsafe { self.ptr.as_ref().star != 0 }
    }

    pub(super) fn expires(self) -> Option<u32> {
        let expires = unsafe { self.ptr.as_ref().expires };
        (expires != u32::MAX).then_some(expires)
    }

    pub(super) fn sip_uri(self) -> Result<Option<SipContactUriRef>, ContactError> {
        if self.is_wildcard() {
            return Ok(None);
        }

        let uri = unsafe { self.ptr.as_ref().uri };
        let uri = NonNull::new(uri).ok_or(ContactError::MissingUri)?;
        let outer_vtable =
            NonNull::new(unsafe { uri.as_ref().vptr }).ok_or(ContactError::MissingVtable)?;
        let get_uri = unsafe { outer_vtable.as_ref().p_get_uri }
            .ok_or(ContactError::MissingOperation("URI unwrapping"))?;
        let inner = unsafe { get_uri(uri.as_ptr().cast::<c_void>()) };
        let inner = NonNull::new(inner.cast::<pjsip_uri>()).ok_or(ContactError::MissingUri)?;
        let inner_vtable =
            NonNull::new(unsafe { inner.as_ref().vptr }).ok_or(ContactError::MissingVtable)?;
        let get_scheme = unsafe { inner_vtable.as_ref().p_get_scheme }
            .ok_or(ContactError::MissingOperation("scheme lookup"))?;
        let scheme = unsafe { get_scheme(inner.as_ptr().cast::<c_void>()) };
        if scheme.is_null() {
            return Err(ContactError::MissingOperation("scheme lookup"));
        }
        let scheme = unsafe { pj_str_to_string(&*scheme) };
        if !scheme.eq_ignore_ascii_case("sip") && !scheme.eq_ignore_ascii_case("sips") {
            return Err(ContactError::UnsupportedScheme(scheme));
        }

        let sip_uri =
            NonNull::new(inner.as_ptr().cast::<pjsip_sip_uri>()).ok_or(ContactError::MissingUri)?;
        let host = unsafe { &sip_uri.as_ref().host };
        if host.ptr.is_null() || host.slen <= 0 {
            return Err(ContactError::MissingHost);
        }

        Ok(Some(SipContactUriRef { ptr: sip_uri }))
    }

    /// Serialize the complete Contact value for a successful REGISTER
    /// response, including display name, URI parameters, `q`, and extension
    /// parameters. The effective expiration is supplied by the registrar.
    pub(super) fn response_value(
        self,
        pool: *mut pj_pool_t,
        expires: u32,
    ) -> Result<String, ContactError> {
        if pool.is_null() {
            return Err(ContactError::PoolNull);
        }

        let cloned = unsafe { pjsip_hdr_clone(pool, self.ptr.as_ptr().cast::<c_void>()) };
        let mut cloned = NonNull::new(cloned.cast::<pjsip_contact_hdr>())
            .ok_or(ContactError::HeaderCloneFailed)?;
        unsafe { cloned.as_mut().expires = expires };

        let mut buffer = vec![0_u8; PJSIP_MAX_PKT_LEN as usize + 1];
        let written = unsafe {
            pjsip_hdr_print_on(
                cloned.as_ptr().cast::<c_void>(),
                buffer.as_mut_ptr().cast::<c_char>(),
                buffer.len(),
            )
        };
        if written <= 0 {
            return Err(ContactError::HeaderPrintFailed);
        }
        let written = usize::try_from(written).map_err(|_| ContactError::HeaderPrintFailed)?;
        if written > buffer.len() {
            return Err(ContactError::HeaderPrintFailed);
        }
        buffer.truncate(written);
        let header = String::from_utf8(buffer)?;
        let (_, value) = header
            .split_once(':')
            .ok_or(ContactError::MissingHeaderValue)?;
        let value = value.trim_start();
        if value.is_empty() {
            return Err(ContactError::MissingHeaderValue);
        }
        Ok(value.to_owned())
    }
}

/// A SIP/SIPS URI borrowed from a live PJSIP message pool.
#[derive(Clone, Copy)]
pub(super) struct SipContactUriRef {
    ptr: NonNull<pjsip_sip_uri>,
}

impl SipContactUriRef {
    fn user(self) -> Option<String> {
        let user = unsafe { &self.ptr.as_ref().user };
        (!user.ptr.is_null() && user.slen > 0).then(|| unsafe { pj_str_to_string(user) })
    }

    pub(super) fn host(self) -> String {
        unsafe { pj_str_to_string(&self.ptr.as_ref().host) }
    }

    fn port(self) -> i32 {
        unsafe { self.ptr.as_ref().port }
    }

    /// Return an opaque URI parameter. PJSIP compares parameter names
    /// case-insensitively; values are returned byte-for-byte.
    pub(super) fn parameter(self, name: &str) -> Option<String> {
        let name = pj_str_t {
            ptr: name.as_ptr() as *mut c_char,
            slen: name.len() as _,
        };
        let list = unsafe { &self.ptr.as_ref().other_param };
        let parameter = unsafe { pjsip_param_find(list, &name) };
        NonNull::new(parameter)
            .map(|parameter| unsafe { pj_str_to_string(&parameter.as_ref().value) })
    }

    /// Reproduce the parameter-free URI shape historically used as SIPcord's
    /// registrar binding key.  Keeping this separate from the full advertised
    /// URI prevents incidental phone parameter changes from creating phantom
    /// registrations.
    pub(super) fn legacy_base_uri(self) -> String {
        let host = self.host();
        match (self.user(), self.port()) {
            (Some(user), port) if port > 0 => format!("sip:{user}@{host}:{port}"),
            (Some(user), _) => format!("sip:{user}@{host}"),
            (None, port) if port > 0 => format!("sip:{host}:{port}"),
            (None, _) => format!("sip:{host}"),
        }
    }

    pub(super) fn print(self, context: pjsip_uri_context_e) -> Result<String, ContactError> {
        let vtable =
            NonNull::new(unsafe { self.ptr.as_ref().vptr }).ok_or(ContactError::MissingVtable)?;
        let print = unsafe { vtable.as_ref().p_print }
            .ok_or(ContactError::MissingOperation("URI serialization"))?;
        let mut buffer = vec![0_u8; PJSIP_MAX_PKT_LEN as usize + 1];
        let written = unsafe {
            print(
                context,
                self.ptr.as_ptr().cast::<c_void>(),
                buffer.as_mut_ptr().cast::<c_char>(),
                buffer.len(),
            )
        };
        if written <= 0 {
            return Err(ContactError::UriPrintFailed);
        }
        let written = usize::try_from(written).map_err(|_| ContactError::UriPrintFailed)?;
        if written > buffer.len() {
            return Err(ContactError::UriPrintFailed);
        }
        buffer.truncate(written);
        Ok(String::from_utf8(buffer)?)
    }

    fn clone_into(self, pool: *mut pj_pool_t) -> Result<SipContactUriRef, ContactError> {
        if pool.is_null() {
            return Err(ContactError::PoolNull);
        }
        let vtable =
            NonNull::new(unsafe { self.ptr.as_ref().vptr }).ok_or(ContactError::MissingVtable)?;
        let clone = unsafe { vtable.as_ref().p_clone }
            .ok_or(ContactError::MissingOperation("URI cloning"))?;
        let cloned = unsafe { clone(pool, self.ptr.as_ptr().cast::<c_void>()) };
        let ptr =
            NonNull::new(cloned.cast::<pjsip_sip_uri>()).ok_or(ContactError::UriCloneFailed)?;
        Ok(SipContactUriRef { ptr })
    }

    pub(super) fn rewrite_host(
        self,
        pool: *mut pj_pool_t,
        host: &str,
        port: u16,
    ) -> Result<(), ContactError> {
        let uri = unsafe { &mut *self.ptr.as_ptr() };
        replace_pool_string(pool, &mut uri.host, host)?;
        uri.port = i32::from(port);
        Ok(())
    }

    /// Build the Request-URI used for a callback without mutating the received
    /// Contact. The observed source tuple remains authoritative while safe,
    /// endpoint-specific URI parameters such as Asterisk's `line` survive.
    pub(super) fn callback_uri(
        self,
        pool: *mut pj_pool_t,
        source_addr: SocketAddr,
        transport: SipTransport,
    ) -> Result<String, ContactError> {
        let callback = self.clone_into(pool)?;
        callback.rewrite_for_callback(pool, source_addr, transport)?;
        callback.print(pjsip_uri_context_e_PJSIP_URI_IN_REQ_URI)
    }

    /// Rewrite a cloned Contact into the safe Request-URI used for a callback.
    /// The observed socket tuple and transport remain authoritative, while
    /// endpoint-selection parameters such as Asterisk's `line` survive.
    fn rewrite_for_callback(
        self,
        pool: *mut pj_pool_t,
        source_addr: SocketAddr,
        transport: SipTransport,
    ) -> Result<(), ContactError> {
        self.rewrite_host(pool, &source_addr.ip().to_string(), source_addr.port())?;

        let uri = unsafe { &mut *self.ptr.as_ptr() };
        match transport {
            SipTransport::Udp => {
                unsafe { pjsip_sip_uri_set_secure(uri, pj_constants__PJ_FALSE as pj_bool_t) };
                replace_pool_string(pool, &mut uri.transport_param, "udp")?;
            }
            SipTransport::Tcp => {
                unsafe { pjsip_sip_uri_set_secure(uri, pj_constants__PJ_FALSE as pj_bool_t) };
                replace_pool_string(pool, &mut uri.transport_param, "tcp")?;
            }
            SipTransport::Tls => {
                unsafe { pjsip_sip_uri_set_secure(uri, pj_constants__PJ_TRUE as pj_bool_t) };
                clear_string(&mut uri.transport_param);
            }
        }

        // These fields can disclose credentials or redirect the request away
        // from the observed NAT binding. URI user parameters and `other_param`
        // (including `line`) intentionally remain untouched.
        clear_string(&mut uri.passwd);
        clear_string(&mut uri.method_param);
        clear_string(&mut uri.maddr_param);
        uri.ttl_param = -1;
        uri.lr_param = 0;
        clear_parameter_list(&mut uri.header_param);
        Ok(())
    }
}

fn clear_string(value: &mut pj_str_t) {
    value.ptr = ptr::null_mut();
    value.slen = 0;
}

fn clear_parameter_list(list: &mut pjsip_param) {
    let list_ptr = list as *mut pjsip_param;
    list.next = list_ptr;
    list.prev = list_ptr;
}

fn replace_pool_string(
    pool: *mut pj_pool_t,
    destination: &mut pj_str_t,
    value: &str,
) -> Result<(), ContactError> {
    if pool.is_null() {
        return Err(ContactError::PoolNull);
    }
    let value = CString::new(value)?;
    let length = value.as_bytes().len();
    let allocated = unsafe { pj_pool_alloc(pool, length + 1) }.cast::<c_char>();
    if allocated.is_null() {
        return Err(ContactError::PoolAllocation);
    }
    unsafe { ptr::copy_nonoverlapping(value.as_ptr(), allocated, length + 1) };
    destination.ptr = allocated;
    destination.slen = length as _;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pj_string(value: &mut [u8]) -> pj_str_t {
        pj_str_t {
            ptr: value.as_mut_ptr().cast::<c_char>(),
            slen: value.len() as _,
        }
    }

    #[test]
    fn unwraps_name_address_and_finds_line_case_insensitively() {
        let mut uri: pjsip_sip_uri = unsafe { std::mem::zeroed() };
        unsafe { pjsip_sip_uri_init(&mut uri, pj_constants__PJ_FALSE as pj_bool_t) };

        let mut user = b"sipcord-inbound".to_vec();
        let mut host = b"pbx.local".to_vec();
        uri.user = pj_string(&mut user);
        uri.host = pj_string(&mut host);
        uri.port = 5060;

        let mut line_name = b"LiNe".to_vec();
        let mut line_value = b"AbC123".to_vec();
        let list = &mut uri.other_param as *mut pjsip_param;
        let mut line_parameter = pjsip_param {
            prev: list,
            next: list,
            name: pj_string(&mut line_name),
            value: pj_string(&mut line_value),
        };
        uri.other_param.next = &mut line_parameter;
        uri.other_param.prev = &mut line_parameter;

        let mut name_address: pjsip_name_addr = unsafe { std::mem::zeroed() };
        unsafe { pjsip_name_addr_init(&mut name_address) };
        name_address.uri = (&mut uri as *mut pjsip_sip_uri).cast::<pjsip_uri>();

        let mut header: pjsip_contact_hdr = unsafe { std::mem::zeroed() };
        header.uri = (&mut name_address as *mut pjsip_name_addr).cast::<pjsip_uri>();
        let contact = ContactHeaderRef {
            ptr: NonNull::from(&mut header),
        };
        let parsed = contact.sip_uri().unwrap().unwrap();

        assert_eq!(parsed.user().as_deref(), Some("sipcord-inbound"));
        assert_eq!(parsed.host(), "pbx.local");
        assert_eq!(parsed.port(), 5060);
        assert_eq!(parsed.parameter("line").as_deref(), Some("AbC123"));
        assert_eq!(
            parsed.legacy_base_uri(),
            "sip:sipcord-inbound@pbx.local:5060"
        );
    }

    #[test]
    fn wildcard_contact_has_no_sip_uri() {
        let mut header: pjsip_contact_hdr = unsafe { std::mem::zeroed() };
        header.star = pj_constants__PJ_TRUE as pj_bool_t;
        let contact = ContactHeaderRef {
            ptr: NonNull::from(&mut header),
        };

        assert!(contact.is_wildcard());
        assert!(contact.sip_uri().unwrap().is_none());
    }
}
