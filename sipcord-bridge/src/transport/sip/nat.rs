//! NAT-related SIP rewriting for Contact headers and SDP bodies
//!
//! This module consolidates all NAT rewriting logic:
//! - Local-network rewriting (tx path): rewrites Contact + SDP in outgoing
//!   requests/responses so that local-network clients use the local IP
//! - Far-end NAT fixup (rx path): rewrites private IPs in incoming responses
//!   to the actual public source IP

use super::ffi::types::*;
use super::ffi::utils::pj_str_to_string;
use pjsua::*;
use std::ffi::CString;
use std::net::Ipv4Addr;
use std::os::raw::c_char;
use std::ptr;

// Private helpers

/// Remove dynamic payload types (96+) from `m=` lines when they lack a corresponding
/// `a=rtpmap:<PT>` attribute in that media section. This prevents PJSIP's SDP validator
/// from rejecting the SDP with PJMEDIA_SDP_EMISSINGRTPMAP.
///
/// Returns `Some(sanitized)` if any orphan dynamic PTs were stripped, `None` if no changes.
fn sanitize_sdp_missing_rtpmap(sdp: &str) -> Option<String> {
    // Split SDP into lines, grouping by media sections.
    // Session-level lines come before the first m= line.
    // Each m= line starts a new media section that includes all following a=/b=/c= lines
    // until the next m= line or end of SDP.

    let lines: Vec<&str> = sdp.lines().collect();
    let mut result_lines: Vec<String> = Vec::with_capacity(lines.len());
    let mut changed = false;

    // Find media section boundaries (indices of m= lines)
    let mut section_starts: Vec<usize> = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        if line.starts_with("m=") {
            section_starts.push(i);
        }
    }

    // Session-level lines (before first m= line) pass through unchanged
    let first_m = section_starts.first().copied().unwrap_or(lines.len());
    for line in &lines[..first_m] {
        result_lines.push(line.to_string());
    }

    // Process each media section
    for (sec_idx, &start) in section_starts.iter().enumerate() {
        let end = section_starts
            .get(sec_idx + 1)
            .copied()
            .unwrap_or(lines.len());

        let m_line = lines[start];
        let section_lines = &lines[start + 1..end];

        // Parse m= line: m=<media> <port> <transport> <fmt1> <fmt2> ...
        let parts: Vec<&str> = m_line.split_whitespace().collect();
        if parts.len() < 4 {
            // Malformed m= line, pass through
            for line in &lines[start..end] {
                result_lines.push(line.to_string());
            }
            continue;
        }

        let transport = parts[2];

        // Only sanitize RTP-based transports (not UDPTL for T.38, etc.)
        if !transport.starts_with("RTP/") {
            for line in &lines[start..end] {
                result_lines.push(line.to_string());
            }
            continue;
        }

        // Collect rtpmap PTs declared in this section
        let mut rtpmap_pts: std::collections::HashSet<u32> = std::collections::HashSet::new();
        for line in section_lines {
            // a=rtpmap:96 opus/48000/2
            if let Some(rest) = line.strip_prefix("a=rtpmap:")
                && let Some(pt_str) = rest.split_whitespace().next()
                && let Ok(pt) = pt_str.parse::<u32>()
            {
                rtpmap_pts.insert(pt);
            }
        }

        // Check which PTs in the m= line need stripping
        let payload_types = &parts[3..];
        let mut kept_pts: Vec<&str> = Vec::new();
        let mut stripped_pts: Vec<u32> = Vec::new();

        for pt_str in payload_types {
            if let Ok(pt) = pt_str.parse::<u32>()
                && pt >= 96
                && !rtpmap_pts.contains(&pt)
            {
                stripped_pts.push(pt);
                continue;
            }
            kept_pts.push(pt_str);
        }

        if stripped_pts.is_empty() {
            // No changes needed for this section
            for line in &lines[start..end] {
                result_lines.push(line.to_string());
            }
            continue;
        }

        // If stripping all PTs would leave none, leave the m= line unchanged
        if kept_pts.is_empty() {
            for line in &lines[start..end] {
                result_lines.push(line.to_string());
            }
            continue;
        }

        changed = true;

        // Rebuild m= line with kept PTs only
        let new_m_line = format!(
            "{} {} {} {}",
            parts[0],
            parts[1],
            parts[2],
            kept_pts.join(" ")
        );
        result_lines.push(new_m_line);

        // Copy section attribute lines, stripping a=fmtp: for removed PTs
        let stripped_set: std::collections::HashSet<u32> = stripped_pts.into_iter().collect();
        for line in section_lines {
            if let Some(rest) = line.strip_prefix("a=fmtp:")
                && let Some(pt_str) = rest.split_whitespace().next()
                && let Ok(pt) = pt_str.parse::<u32>()
                && stripped_set.contains(&pt)
            {
                continue; // skip fmtp for stripped PT
            }
            result_lines.push(line.to_string());
        }
    }

    if changed {
        Some(result_lines.join("\r\n") + "\r\n")
    } else {
        None
    }
}

/// Check if an IPv4 address is in RFC 1918 private space
fn is_rfc1918(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    (o[0] == 10) || (o[0] == 172 && (16..=31).contains(&o[1])) || (o[0] == 192 && o[1] == 168)
}

/// Extract the destination IPv4 address from `pjsip_tx_data` transport info.
///
/// Returns `None` if transport info is invalid or the address is not IPv4.
unsafe fn extract_dst_ipv4(tdata: *const pjsip_tx_data) -> Option<Ipv4Addr> {
    if unsafe { (*tdata).tp_info.transport.is_null() || (*tdata).tp_info.dst_addr_len <= 0 } {
        return None;
    }

    let dst_addr = unsafe { &(*tdata).tp_info.dst_addr };
    // PJ_AF_INET is typically 2 (same as AF_INET on most systems)
    if unsafe { dst_addr.addr.sa_family } == 2 {
        let addr_in = unsafe { &dst_addr.ipv4 };
        let ip_bytes = addr_in.sin_addr.s_addr.to_ne_bytes();
        Some(Ipv4Addr::new(
            ip_bytes[0],
            ip_bytes[1],
            ip_bytes[2],
            ip_bytes[3],
        ))
    } else {
        None
    }
}

/// Rewrite the Contact header's host and port via pool allocation.
///
/// Uses vtable-based URI unwrapping (`p_get_uri`) to safely handle both
/// bare `pjsip_sip_uri` and `pjsip_name_addr`-wrapped URIs.
/// Returns `true` if the rewrite succeeded.
unsafe fn rewrite_contact_host(
    pool: *mut pj_pool_t,
    msg: *mut pjsip_msg,
    new_host: &str,
    new_port: u16,
) -> bool {
    let contact_hdr =
        unsafe { pjsip_msg_find_hdr(msg, pjsip_hdr_e_PJSIP_H_CONTACT, ptr::null_mut()) }
            as *mut pjsip_contact_hdr;
    if contact_hdr.is_null() {
        return false;
    }

    let uri = unsafe { (*contact_hdr).uri };
    if uri.is_null() {
        return false;
    }

    // Unwrap via vtable to handle pjsip_name_addr wrapping
    let uri_vptr = unsafe { (*(uri as *const pjsip_uri)).vptr };
    if uri_vptr.is_null() {
        return false;
    }
    let get_uri_fn = match unsafe { (*uri_vptr).p_get_uri } {
        Some(f) => f,
        None => return false,
    };
    let sip_uri_raw = unsafe { get_uri_fn(uri as *mut std::os::raw::c_void) };
    if sip_uri_raw.is_null() {
        return false;
    }
    let sip_uri = sip_uri_raw as *mut pjsip_sip_uri;
    if unsafe { (*sip_uri).host.ptr.is_null() || (*sip_uri).host.slen <= 0 } {
        return false;
    }

    let Ok(host_cstr) = CString::new(new_host) else {
        return false;
    };
    let host_len = new_host.len();
    let pool_str = unsafe { pj_pool_alloc(pool, host_len + 1) } as *mut c_char;
    if pool_str.is_null() {
        return false;
    }

    unsafe {
        ptr::copy_nonoverlapping(host_cstr.as_ptr(), pool_str, host_len + 1);
        (*sip_uri).host.ptr = pool_str;
        (*sip_uri).host.slen = host_len as i64;
        (*sip_uri).port = new_port as i32;
    }
    true
}

/// Replace `old_ip` with `new_ip` inside the SDP body of `msg`, allocating
/// the replacement string from `pool`.  Only rewrites `c=` (connection) and
/// `o=` (origin) lines to avoid corrupting attribute values that may
/// coincidentally contain the same IP string.  Returns `true` if a
/// substitution was made.
unsafe fn rewrite_sdp_body(
    pool: *mut pj_pool_t,
    msg: *mut pjsip_msg,
    old_ip: &str,
    new_ip: &str,
) -> bool {
    let body = unsafe { (*msg).body };
    if body.is_null() || unsafe { (*body).len == 0 || (*body).data.is_null() } {
        return false;
    }

    let body_slice =
        unsafe { std::slice::from_raw_parts((*body).data as *const u8, (*body).len as usize) };
    let Ok(sdp_str) = std::str::from_utf8(body_slice) else {
        return false;
    };

    // Line-by-line replacement: only rewrite c= and o= lines
    let mut changed = false;
    let new_sdp: String = sdp_str
        .lines()
        .map(|line| {
            if (line.starts_with("c=") || line.starts_with("o=")) && line.contains(old_ip) {
                changed = true;
                line.replace(old_ip, new_ip)
            } else {
                line.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\r\n");

    // Preserve trailing CRLF
    let new_sdp = new_sdp + "\r\n";

    if !changed {
        return false;
    }

    let new_len = new_sdp.len();
    let new_body_ptr = unsafe { pj_pool_alloc(pool, new_len) } as *mut u8;
    if new_body_ptr.is_null() {
        return false;
    }

    unsafe {
        ptr::copy_nonoverlapping(new_sdp.as_ptr(), new_body_ptr, new_len);
        (*body).data = new_body_ptr as *mut _;
        (*body).len = new_len as u32;
    }
    true
}

/// Unified local-network rewriting for outgoing tx data.
///
/// Checks `LOCAL_NET_CONFIG`, verifies the destination is in the configured
/// CIDR, and rewrites the Contact header + SDP body.
///
/// `direction` is used only for log messages ("request" or "response").
unsafe fn rewrite_local_network_tdata(tdata: *mut pjsip_tx_data, direction: &str) -> bool {
    let Some(Some((local_host, local_cidr, port, rtp_public_ip))) = LOCAL_NET_CONFIG.get() else {
        return false;
    };

    if tdata.is_null() {
        return false;
    }

    let Some(dst_ip) = (unsafe { extract_dst_ipv4(tdata) }) else {
        return false;
    };

    if !local_cidr.contains(&dst_ip) {
        return false;
    }

    let msg = unsafe { (*tdata).msg };
    if msg.is_null() {
        return false;
    }

    let mut changed = false;

    // Rewrite Contact header
    if unsafe { rewrite_contact_host((*tdata).pool, msg, local_host, *port) } {
        tracing::debug!(
            "Rewrote {} Contact header for local client {}: host -> {}:{}",
            direction,
            dst_ip,
            local_host,
            port
        );
        changed = true;
    }

    // Rewrite SDP body if we have an RTP public IP to replace
    if let Some(public_ip) = rtp_public_ip
        && unsafe { rewrite_sdp_body((*tdata).pool, msg, public_ip, local_host) }
    {
        tracing::debug!(
            "Rewrote {} SDP for local client {}: {} -> {}",
            direction,
            dst_ip,
            public_ip,
            local_host
        );
        changed = true;
    }

    changed
}

/// Rewrite private IPs in Contact headers for external (non-local) clients.
///
/// pjsua derives the Contact URI from the TCP/UDP connection's local address,
/// which is the bridge's private IP (e.g. 10.0.1.7) when running behind NAT.
/// External clients need the public hostname (e.g. bridge-usw1.sipcord.net) so
/// they can route in-dialog requests like BYE back to us. Without this fix,
/// phones that try to send BYE to the private IP will silently fail.
unsafe fn rewrite_private_contact_for_external(tdata: *mut pjsip_tx_data, direction: &str) -> bool {
    let Some(Some((public_host, port))) = PUBLIC_HOST_CONFIG.get() else {
        return false;
    };

    if tdata.is_null() {
        return false;
    }

    let msg = unsafe { (*tdata).msg };
    if msg.is_null() {
        return false;
    }

    // Find Contact header
    let contact_hdr =
        unsafe { pjsip_msg_find_hdr(msg, pjsip_hdr_e_PJSIP_H_CONTACT, ptr::null_mut()) }
            as *mut pjsip_contact_hdr;
    if contact_hdr.is_null() {
        return false;
    }

    let uri = unsafe { (*contact_hdr).uri };
    if uri.is_null() {
        return false;
    }

    // Unwrap via vtable to handle pjsip_name_addr wrapping
    let uri_vptr = unsafe { (*(uri as *const pjsip_uri)).vptr };
    if uri_vptr.is_null() {
        return false;
    }
    let get_uri_fn = match unsafe { (*uri_vptr).p_get_uri } {
        Some(f) => f,
        None => return false,
    };
    let sip_uri_raw = unsafe { get_uri_fn(uri as *mut std::os::raw::c_void) };
    if sip_uri_raw.is_null() {
        return false;
    }
    let sip_uri = sip_uri_raw as *mut pjsip_sip_uri;
    if unsafe { (*sip_uri).host.ptr.is_null() || (*sip_uri).host.slen <= 0 } {
        return false;
    }

    let host = unsafe { pj_str_to_string(&(*sip_uri).host) };

    // Only rewrite if Contact host is a private (RFC 1918) IP
    let contact_ip: Ipv4Addr = match host.parse() {
        Ok(ip) => ip,
        Err(_) => return false, // Already a hostname, no rewrite needed
    };

    if !is_rfc1918(contact_ip) {
        return false; // Public IP, no rewrite needed
    }

    // Skip if destination is also private (local-network rewrite handles that)
    if let Some(dst_ip) = unsafe { extract_dst_ipv4(tdata) }
        && is_rfc1918(dst_ip)
    {
        return false;
    }

    // Rewrite Contact to public host
    if unsafe { rewrite_contact_host((*tdata).pool, msg, public_host, *port) } {
        tracing::debug!(
            "Rewrote {} Contact for external client: {} -> {}:{}",
            direction,
            host,
            public_host,
            port
        );
        return true;
    }

    false
}

// Public callbacks

/// Callback to rewrite Contact header and SDP body in outgoing responses.
///
/// Two rewrites are applied in order:
/// 1. Local-network rewrite: for clients on the local CIDR, use the local IP
/// 2. Public-host rewrite: for external clients, replace private Contact IPs
///    with the public hostname so they can route BYE back to us
pub unsafe extern "C" fn on_tx_response_cb(tdata: *mut pjsip_tx_data) -> pj_status_t {
    let local_rewrite = unsafe { rewrite_local_network_tdata(tdata, "response") };
    let public_rewrite = unsafe { rewrite_private_contact_for_external(tdata, "response") };

    // If we modified headers, the buffer was already serialized by mod-msg-print
    // (priority 8, before our module at priority 32). Invalidate and re-encode
    // so the changes actually reach the wire.
    if local_rewrite || public_rewrite {
        unsafe {
            pjsip_tx_data_invalidate_msg(tdata);
            pjsip_tx_data_encode(tdata);
        }
    }

    pj_constants__PJ_SUCCESS as pj_status_t
}

/// Callback to rewrite Contact header and SDP body in outgoing requests.
/// Same dual-rewrite logic as the response path.
pub unsafe extern "C" fn on_tx_request_cb(tdata: *mut pjsip_tx_data) -> pj_status_t {
    let local_rewrite = unsafe { rewrite_local_network_tdata(tdata, "request") };
    let public_rewrite = unsafe { rewrite_private_contact_for_external(tdata, "request") };

    // If we modified headers, the buffer was already serialized by mod-msg-print
    // (priority 8, before our module at priority 32). Invalidate and re-encode
    // so the changes actually reach the wire.
    if local_rewrite || public_rewrite {
        unsafe {
            pjsip_tx_data_invalidate_msg(tdata);
            pjsip_tx_data_encode(tdata);
        }
    }

    pj_constants__PJ_SUCCESS as pj_status_t
}

/// Callback to fix far-end NAT traversal in incoming SIP requests (INVITEs).
///
/// When a phone behind NAT sends an INVITE, its SDP body contains private IPs:
/// - SDP `c=IN IP4 192.168.x.x` -> We'd send RTP to an unreachable private IP
///
/// This callback detects the NAT condition (private SDP IP != packet source IP)
/// and rewrites the SDP before PJSIP's invite/dialog layer processes it,
/// so the media session uses the correct public address.
pub unsafe extern "C" fn on_rx_request_nat_fixup_cb(rdata: *mut pjsip_rx_data) -> pj_bool_t {
    if rdata.is_null() {
        return pj_constants__PJ_FALSE as pj_bool_t;
    }

    let msg = unsafe { (*rdata).msg_info.msg };
    if msg.is_null() {
        return pj_constants__PJ_FALSE as pj_bool_t;
    }

    // Only process requests (safety check)
    if unsafe { (*msg).type_ } != pjsip_msg_type_e_PJSIP_REQUEST_MSG {
        return pj_constants__PJ_FALSE as pj_bool_t;
    }

    // Only process INVITE and re-INVITE (they carry SDP with media addresses)
    let method_id = unsafe { (*msg).line.req.method.id };
    if method_id != pjsip_method_e_PJSIP_INVITE_METHOD {
        return pj_constants__PJ_FALSE as pj_bool_t;
    }

    // Check if there's a body (SDP)
    let body = unsafe { (*msg).body };
    if body.is_null() || unsafe { (*body).len == 0 || (*body).data.is_null() } {
        return pj_constants__PJ_FALSE as pj_bool_t;
    }

    // Extract source IP from packet info
    let src_name = unsafe { &(*rdata).pkt_info.src_name };
    let name_len = src_name
        .iter()
        .position(|&c| c == 0)
        .unwrap_or(src_name.len());
    let src_ip_str = match std::str::from_utf8(unsafe {
        std::slice::from_raw_parts(src_name.as_ptr() as *const u8, name_len)
    }) {
        Ok(s) => s,
        Err(_) => return pj_constants__PJ_FALSE as pj_bool_t,
    };
    let src_ip: Ipv4Addr = match src_ip_str.parse() {
        Ok(ip) => ip,
        Err(_) => return pj_constants__PJ_FALSE as pj_bool_t,
    };

    // Parse SDP to find c= line IP and check if it's a private address
    let body_slice =
        unsafe { std::slice::from_raw_parts((*body).data as *const u8, (*body).len as usize) };
    let sdp_str = match std::str::from_utf8(body_slice) {
        Ok(s) => s,
        Err(_) => return pj_constants__PJ_FALSE as pj_bool_t,
    };

    // Find any connection address in the SDP that needs NAT fixup.
    // Check ALL c= lines (session-level and per-media) -- if any contain a
    // private IP different from the packet source, rewrite the SDP.
    let mut needs_rewrite = false;
    let mut private_ip_str: Option<&str> = None;
    for line in sdp_str.lines() {
        if let Some(addr_str) = line.strip_prefix("c=IN IP4 ") {
            let addr_str = addr_str.trim();
            if let Ok(sdp_ip) = addr_str.parse::<Ipv4Addr>()
                && is_rfc1918(sdp_ip)
                && sdp_ip != src_ip
            {
                needs_rewrite = true;
                private_ip_str = Some(addr_str);
                break;
            }
        }
    }

    if needs_rewrite && let Some(private_ip) = private_ip_str {
        let pool = unsafe { (*rdata).tp_info.pool };
        if !pool.is_null() && unsafe { rewrite_sdp_body(pool, msg, private_ip, src_ip_str) } {
            tracing::debug!(
                "NAT fixup (INVITE): SDP rewritten {} -> {} (from {}:{})",
                private_ip,
                src_ip_str,
                src_ip_str,
                unsafe { (*rdata).pkt_info.src_port }
            );
        }
    }

    // Also rewrite Contact header if present and has private IP
    let contact_hdr =
        unsafe { pjsip_msg_find_hdr(msg, pjsip_hdr_e_PJSIP_H_CONTACT, ptr::null_mut()) }
            as *mut pjsip_contact_hdr;
    if !contact_hdr.is_null() {
        let uri = unsafe { (*contact_hdr).uri };
        if !uri.is_null() {
            let uri_vptr = unsafe { (*(uri as *const pjsip_uri)).vptr };
            if !uri_vptr.is_null()
                && let Some(get_uri_fn) = unsafe { (*uri_vptr).p_get_uri }
            {
                let sip_uri_raw = unsafe { get_uri_fn(uri as *mut std::os::raw::c_void) };
                if !sip_uri_raw.is_null() {
                    let sip_uri = sip_uri_raw as *mut pjsip_sip_uri;
                    let contact_host = unsafe { pj_str_to_string(&(*sip_uri).host) };
                    if let Ok(contact_ip) = contact_host.parse::<Ipv4Addr>()
                        && is_rfc1918(contact_ip)
                        && contact_ip != src_ip
                    {
                        let src_port = unsafe { (*rdata).pkt_info.src_port } as u16;
                        let pool = unsafe { (*rdata).tp_info.pool };
                        if !pool.is_null()
                            && let Ok(new_host_cstr) = CString::new(src_ip_str)
                        {
                            let host_len = src_ip_str.len();
                            let pool_str =
                                unsafe { pj_pool_alloc(pool, host_len + 1) } as *mut c_char;
                            if !pool_str.is_null() {
                                unsafe {
                                    ptr::copy_nonoverlapping(
                                        new_host_cstr.as_ptr(),
                                        pool_str,
                                        host_len + 1,
                                    );
                                    (*sip_uri).host.ptr = pool_str;
                                    (*sip_uri).host.slen = host_len as i64;
                                    (*sip_uri).port = src_port as i32;
                                }
                                tracing::debug!(
                                    "NAT fixup (INVITE): Contact rewritten {} -> {}:{}",
                                    contact_host,
                                    src_ip_str,
                                    src_port
                                );
                            }
                        }
                    }
                }
            }
        }
    }

    // Sanitize SDP: strip dynamic payload types (96+) that lack a=rtpmap attributes.
    // Without this, PJSIP's SDP validator rejects these INVITEs with EMISSINGRTPMAP.
    let body = unsafe { (*msg).body };
    if !body.is_null() && unsafe { (*body).len > 0 && !(*body).data.is_null() } {
        let body_slice =
            unsafe { std::slice::from_raw_parts((*body).data as *const u8, (*body).len as usize) };
        if let Ok(sdp_str) = std::str::from_utf8(body_slice)
            && let Some(sanitized) = sanitize_sdp_missing_rtpmap(sdp_str)
        {
            let pool = unsafe { (*rdata).tp_info.pool };
            if !pool.is_null() {
                let new_len = sanitized.len();
                let new_body_ptr = unsafe { pj_pool_alloc(pool, new_len) } as *mut u8;
                if !new_body_ptr.is_null() {
                    unsafe {
                        ptr::copy_nonoverlapping(sanitized.as_ptr(), new_body_ptr, new_len);
                        (*body).data = new_body_ptr as *mut _;
                        (*body).len = new_len as u32;
                    }
                    tracing::debug!(
                        "SDP sanitized: stripped orphan dynamic payload types (from {}:{})",
                        src_ip_str,
                        unsafe { (*rdata).pkt_info.src_port }
                    );
                }
            }
        }
    }

    pj_constants__PJ_FALSE as pj_bool_t
}

/// Callback to fix far-end NAT traversal in incoming SIP responses.
///
/// When the remote party (phone) is behind NAT, their responses contain
/// private IPs in the Contact header and SDP body:
/// - Contact: `<sip:user@192.168.x.x>` -> PRACK/ACK routed to unreachable private IP
/// - SDP `c=IN IP4 192.168.x.x` -> RTP sent to unreachable private IP
///
/// This callback detects NAT (private Contact IP != packet source IP) and
/// rewrites both to the actual public source IP before PJSIP processes the
/// response, so the dialog target and media address are correct.
///
/// Registered at priority 28 (before dialog/invite layer at 32) to ensure
/// the dialog's remote target uses the corrected address.
pub unsafe extern "C" fn on_rx_response_nat_fixup_cb(rdata: *mut pjsip_rx_data) -> pj_bool_t {
    if rdata.is_null() {
        return pj_constants__PJ_FALSE as pj_bool_t;
    }

    let msg = unsafe { (*rdata).msg_info.msg };
    if msg.is_null() {
        return pj_constants__PJ_FALSE as pj_bool_t;
    }

    // Only process 1xx/2xx responses (provisional and success)
    let status_code = unsafe { (*msg).line.status.code };
    if !(100..300).contains(&status_code) {
        return pj_constants__PJ_FALSE as pj_bool_t;
    }

    // Extract source IP from pkt_info.src_name (null-terminated char array)
    let src_name = unsafe { &(*rdata).pkt_info.src_name };
    let name_len = src_name
        .iter()
        .position(|&c| c == 0)
        .unwrap_or(src_name.len());
    let src_ip_str = match std::str::from_utf8(unsafe {
        std::slice::from_raw_parts(src_name.as_ptr() as *const u8, name_len)
    }) {
        Ok(s) => s,
        Err(_) => return pj_constants__PJ_FALSE as pj_bool_t,
    };
    let src_ip: Ipv4Addr = match src_ip_str.parse() {
        Ok(ip) => ip,
        Err(_) => return pj_constants__PJ_FALSE as pj_bool_t, // IPv6 or invalid
    };
    let src_port = unsafe { (*rdata).pkt_info.src_port } as u16;

    // Find Contact header in the response
    let contact_hdr =
        unsafe { pjsip_msg_find_hdr(msg, pjsip_hdr_e_PJSIP_H_CONTACT, ptr::null_mut()) }
            as *mut pjsip_contact_hdr;
    if contact_hdr.is_null() {
        return pj_constants__PJ_FALSE as pj_bool_t;
    }

    // Get the SIP URI from the Contact (unwrap name_addr via vtable).
    // The rx path requires vtable-based URI unwrapping (p_get_uri) because
    // the Contact URI may be wrapped in a pjsip_name_addr, unlike the tx
    // path where we can cast directly.
    let uri = unsafe { (*contact_hdr).uri };
    if uri.is_null() {
        return pj_constants__PJ_FALSE as pj_bool_t;
    }
    let uri_vptr = unsafe { (*(uri as *const pjsip_uri)).vptr };
    if uri_vptr.is_null() {
        return pj_constants__PJ_FALSE as pj_bool_t;
    }
    let get_uri_fn = match unsafe { (*uri_vptr).p_get_uri } {
        Some(f) => f,
        None => return pj_constants__PJ_FALSE as pj_bool_t,
    };
    let sip_uri_raw = unsafe { get_uri_fn(uri as *mut std::os::raw::c_void) };
    if sip_uri_raw.is_null() {
        return pj_constants__PJ_FALSE as pj_bool_t;
    }
    let sip_uri = sip_uri_raw as *mut pjsip_sip_uri;

    // Parse Contact host as IPv4
    let contact_host = unsafe { pj_str_to_string(&(*sip_uri).host) };
    let contact_ip: Ipv4Addr = match contact_host.parse() {
        Ok(ip) => ip,
        Err(_) => return pj_constants__PJ_FALSE as pj_bool_t, // Hostname, skip
    };

    // Only rewrite if Contact has a private IP that differs from the source
    if !is_rfc1918(contact_ip) || contact_ip == src_ip {
        return pj_constants__PJ_FALSE as pj_bool_t;
    }

    // NAT detected: Contact has private IP, packet came from different (public) IP
    tracing::debug!(
        "NAT fixup: rewriting Contact {} -> {}:{} (response {} from {}:{})",
        contact_host,
        src_ip,
        src_port,
        status_code,
        src_ip,
        src_port
    );

    // Rewrite Contact URI host to the public source IP
    let pool = unsafe { (*rdata).tp_info.pool };
    if !pool.is_null()
        && let Ok(new_host_cstr) = CString::new(src_ip_str)
    {
        let host_len = src_ip_str.len();
        let pool_str = unsafe { pj_pool_alloc(pool, host_len + 1) } as *mut c_char;
        if !pool_str.is_null() {
            unsafe {
                ptr::copy_nonoverlapping(new_host_cstr.as_ptr(), pool_str, host_len + 1);
                (*sip_uri).host.ptr = pool_str;
                (*sip_uri).host.slen = host_len as i64;
                (*sip_uri).port = src_port as i32;
            }
        }
    }

    // Rewrite SDP body: replace private IP with public source IP.
    // Parse the SDP c= line directly to get the actual media IP -- it may differ
    // from the Contact header IP (e.g., dual-homed phone or double NAT).
    let body = unsafe { (*msg).body };
    if !body.is_null() && unsafe { (*body).len > 0 && !(*body).data.is_null() } {
        let body_slice =
            unsafe { std::slice::from_raw_parts((*body).data as *const u8, (*body).len as usize) };
        if let Ok(sdp_str) = std::str::from_utf8(body_slice) {
            for line in sdp_str.lines() {
                if let Some(addr_str) = line.strip_prefix("c=IN IP4 ") {
                    let addr_str = addr_str.trim();
                    if let Ok(sdp_ip) = addr_str.parse::<Ipv4Addr>()
                        && is_rfc1918(sdp_ip)
                        && sdp_ip != src_ip
                    {
                        if unsafe { rewrite_sdp_body(pool, msg, addr_str, src_ip_str) } {
                            tracing::debug!(
                                "NAT fixup: SDP rewritten {} -> {}",
                                addr_str,
                                src_ip_str
                            );
                        }
                        break;
                    }
                }
            }
        }
    }

    // Return FALSE to let other modules also process this response
    pj_constants__PJ_FALSE as pj_bool_t
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_rfc1918_10_network() {
        assert!(is_rfc1918(Ipv4Addr::new(10, 0, 0, 1)));
        assert!(is_rfc1918(Ipv4Addr::new(10, 255, 255, 255)));
    }

    #[test]
    fn test_is_rfc1918_172_16_network() {
        assert!(is_rfc1918(Ipv4Addr::new(172, 16, 0, 1)));
        assert!(is_rfc1918(Ipv4Addr::new(172, 31, 255, 255)));
    }

    #[test]
    fn test_is_rfc1918_192_168_network() {
        assert!(is_rfc1918(Ipv4Addr::new(192, 168, 1, 1)));
        assert!(is_rfc1918(Ipv4Addr::new(192, 168, 0, 0)));
    }

    #[test]
    fn test_is_rfc1918_public_addresses() {
        assert!(!is_rfc1918(Ipv4Addr::new(8, 8, 8, 8)));
        assert!(!is_rfc1918(Ipv4Addr::new(172, 15, 0, 1)));
        assert!(!is_rfc1918(Ipv4Addr::new(172, 32, 0, 1)));
        assert!(!is_rfc1918(Ipv4Addr::new(192, 167, 1, 1)));
        assert!(!is_rfc1918(Ipv4Addr::new(1, 1, 1, 1)));
    }

    #[test]
    fn test_sanitize_sdp_orphan_dynamic_pt_stripped() {
        let sdp = "v=0\r\n\
                    o=- 0 0 IN IP4 0.0.0.0\r\n\
                    s=-\r\n\
                    c=IN IP4 10.0.0.1\r\n\
                    m=audio 5000 RTP/AVP 0 8 96\r\n\
                    a=rtpmap:0 PCMU/8000\r\n\
                    a=rtpmap:8 PCMA/8000\r\n";
        // PT 96 has no rtpmap -> should be stripped
        let result = sanitize_sdp_missing_rtpmap(sdp).unwrap();
        assert!(result.contains("m=audio 5000 RTP/AVP 0 8\r\n"));
        assert!(!result.contains("96"));
    }

    #[test]
    fn test_sanitize_sdp_all_valid_pts_unchanged() {
        let sdp = "v=0\r\n\
                    o=- 0 0 IN IP4 0.0.0.0\r\n\
                    s=-\r\n\
                    m=audio 5000 RTP/AVP 0 96\r\n\
                    a=rtpmap:0 PCMU/8000\r\n\
                    a=rtpmap:96 opus/48000/2\r\n";
        assert!(sanitize_sdp_missing_rtpmap(sdp).is_none());
    }

    #[test]
    fn test_sanitize_sdp_non_rtp_transport_skipped() {
        let sdp = "v=0\r\n\
                    o=- 0 0 IN IP4 0.0.0.0\r\n\
                    s=-\r\n\
                    m=image 5000 udptl t38\r\n\
                    a=T38FaxVersion:0\r\n";
        assert!(sanitize_sdp_missing_rtpmap(sdp).is_none());
    }

    #[test]
    fn test_sanitize_sdp_all_pts_orphaned_unchanged() {
        // If stripping all dynamic PTs would leave none, m= line stays unchanged
        let sdp = "v=0\r\n\
                    o=- 0 0 IN IP4 0.0.0.0\r\n\
                    s=-\r\n\
                    m=audio 5000 RTP/AVP 96 97\r\n";
        // Both 96 and 97 are dynamic with no rtpmap, but stripping both would leave no PTs
        assert!(sanitize_sdp_missing_rtpmap(sdp).is_none());
    }

    #[test]
    fn test_sanitize_sdp_mixed_valid_and_orphan() {
        let sdp = "v=0\r\n\
                    o=- 0 0 IN IP4 0.0.0.0\r\n\
                    s=-\r\n\
                    m=audio 5000 RTP/AVP 0 96 97\r\n\
                    a=rtpmap:0 PCMU/8000\r\n\
                    a=rtpmap:96 opus/48000/2\r\n\
                    a=fmtp:97 mode=20\r\n";
        // PT 97 has no rtpmap -> stripped, its fmtp line also removed
        let result = sanitize_sdp_missing_rtpmap(sdp).unwrap();
        assert!(result.contains("m=audio 5000 RTP/AVP 0 96\r\n"));
        assert!(!result.contains("97"));
        assert!(!result.contains("fmtp:97"));
        // fmtp for 96 would be kept if it existed; rtpmap:96 should still be there
        assert!(result.contains("a=rtpmap:96 opus/48000/2"));
    }

    #[test]
    fn test_sanitize_sdp_malformed_m_line() {
        let sdp = "v=0\r\n\
                    o=- 0 0 IN IP4 0.0.0.0\r\n\
                    s=-\r\n\
                    m=audio 5000\r\n";
        // Malformed m= line (< 4 parts) -> passes through unchanged
        assert!(sanitize_sdp_missing_rtpmap(sdp).is_none());
    }
}
