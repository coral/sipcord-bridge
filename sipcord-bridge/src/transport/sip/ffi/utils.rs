//! Utility functions for pjsua wrapper

use pjsua::pj_str_t;

/// Convert a pj_str_t to a Rust String
///
/// # Safety
/// The pj_str_t must point to valid memory for `slen` bytes.
pub unsafe fn pj_str_to_string(s: &pj_str_t) -> String {
    if s.ptr.is_null() || s.slen <= 0 {
        return String::new();
    }

    let slice = unsafe { std::slice::from_raw_parts(s.ptr as *const u8, s.slen as usize) };
    String::from_utf8_lossy(slice).to_string()
}

/// Extract username from SIP URI (e.g., "<sip:username@domain>" -> "username")
pub fn extract_sip_username(uri: &str) -> String {
    // Remove angle brackets if present
    let uri = uri.trim_start_matches('<').trim_end_matches('>');

    // Remove "sip:" prefix
    let uri = uri.strip_prefix("sip:").unwrap_or(uri);

    // Take everything before @ as username
    if let Some(at_pos) = uri.find('@') {
        uri[..at_pos].to_string()
    } else {
        uri.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_sip_username_full_uri() {
        assert_eq!(extract_sip_username("<sip:alice@example.com>"), "alice");
    }

    #[test]
    fn test_extract_sip_username_no_brackets() {
        assert_eq!(extract_sip_username("sip:bob@domain"), "bob");
    }

    #[test]
    fn test_extract_sip_username_no_sip_prefix() {
        assert_eq!(extract_sip_username("charlie@host"), "charlie");
    }

    #[test]
    fn test_extract_sip_username_no_at() {
        assert_eq!(extract_sip_username("sip:dave"), "dave");
    }

    #[test]
    fn test_extract_sip_username_with_port() {
        assert_eq!(extract_sip_username("<sip:eve@host:5060>"), "eve");
    }

    #[test]
    fn test_extract_sip_username_empty() {
        assert_eq!(extract_sip_username(""), "");
    }
}
