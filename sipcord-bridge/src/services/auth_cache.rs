//! SIP credential cache for local digest auth verification
//!
//! Caches HA1 hashes returned by the API so that repeat REGISTER requests
//! can be verified locally without an API round-trip. On cache miss or
//! verification failure, falls through to the API.
//!
//! Also tracks consecutive auth failures per username to rate-limit
//! users with bad credentials (429 cooldown after N failures).

use md5::{Digest, Md5};
use moka::sync::Cache;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use crate::transport::sip::DigestAuthParams;

/// Global auth cache instance accessible from C callbacks
static AUTH_CACHE: OnceLock<Arc<AuthCache>> = OnceLock::new();

/// Result of checking digest auth against the cache
pub enum VerifyResult {
    /// Cache hit and credentials verified successfully
    Verified,
    /// Cache had an entry but credentials didn't match (wrong password or stale cache)
    Mismatch,
    /// No cache entry for this username
    Miss,
}

/// Data returned from a successful REGISTER authentication
#[derive(Clone, Debug)]
pub struct RegisterData {
    pub sip_username: String,
    /// Stable Discord snowflake used for inbound `/call` routing.
    pub discord_user_id: String,
    /// Pre-computed HA1 hash for caching
    pub ha1: Option<String>,
}

/// Cached credential entry for a SIP user
#[derive(Clone, Debug)]
pub struct CachedAuth {
    /// Pre-computed MD5(username:sipcord:password)
    pub ha1: String,
    /// Cached registration data
    pub register_data: RegisterData,
}

/// In-memory credential cache with TTL
pub struct AuthCache {
    cache: Cache<String, CachedAuth>,
    /// Consecutive auth failure count per username (TTL = cooldown period)
    failures: Cache<String, u32>,
    /// Number of failures before cooldown kicks in
    max_failures: u32,
}

impl AuthCache {
    /// Create a new cache with the given TTL for entries
    pub fn new(ttl: Duration, failure_cooldown: Duration, max_failures: u32) -> Self {
        Self {
            cache: Cache::builder()
                .time_to_live(ttl)
                .max_capacity(10_000)
                .build(),
            failures: Cache::builder()
                .time_to_live(failure_cooldown)
                .max_capacity(10_000)
                .build(),
            max_failures,
        }
    }

    /// Set this cache as the global instance
    pub fn set_global(cache: Arc<AuthCache>) {
        let _ = AUTH_CACHE.set(cache);
    }

    /// Get the global auth cache instance
    pub fn global() -> Option<&'static Arc<AuthCache>> {
        AUTH_CACHE.get()
    }

    /// Record a failed auth attempt, returns the new failure count
    pub fn record_failure(&self, username: &str) -> u32 {
        let count = self.failures.get(username).unwrap_or(0) + 1;
        self.failures.insert(username.to_string(), count);
        count
    }

    /// Clear failure count on successful auth
    pub fn clear_failures(&self, username: &str) {
        self.failures.invalidate(username);
    }

    /// Check if a username is in auth cooldown (too many failures)
    pub fn is_in_cooldown(&self, username: &str) -> bool {
        self.failures.get(username).unwrap_or(0) >= self.max_failures
    }

    /// Try to verify digest auth locally using cached HA1.
    /// Returns Some(cached_data) on success, None on miss or mismatch.
    pub fn verify(&self, digest: &DigestAuthParams) -> Option<CachedAuth> {
        let cached = self.cache.get(&digest.username)?;

        if verify_digest_with_ha1(&cached.ha1, digest) {
            Some(cached)
        } else {
            // Mismatch - password may have changed, evict stale entry
            self.cache.invalidate(&digest.username);
            None
        }
    }

    /// Check digest auth against the cache, distinguishing miss from mismatch.
    pub fn check(&self, digest: &DigestAuthParams) -> VerifyResult {
        match self.cache.get(&digest.username) {
            Some(cached) => {
                if verify_digest_with_ha1(&cached.ha1, digest) {
                    VerifyResult::Verified
                } else {
                    self.cache.invalidate(&digest.username);
                    VerifyResult::Mismatch
                }
            }
            None => VerifyResult::Miss,
        }
    }

    /// Store a successful auth result in the cache
    pub fn insert(&self, username: &str, ha1: &str, register_data: RegisterData) {
        self.cache.insert(
            username.to_string(),
            CachedAuth {
                ha1: ha1.to_string(),
                register_data,
            },
        );
    }
}

/// Compute MD5 hex digest of a string
fn md5_hex(input: &str) -> String {
    let mut hasher = Md5::new();
    hasher.update(input.as_bytes());
    let digest = hasher.finalize();
    let mut out = String::with_capacity(digest.len() * 2);
    for b in digest.iter() {
        use std::fmt::Write;
        let _ = write!(out, "{:02x}", b);
    }
    out
}

/// Verify SIP digest auth using a pre-computed HA1 hash
fn verify_digest_with_ha1(ha1: &str, params: &DigestAuthParams) -> bool {
    let ha2 = md5_hex(&format!("{}:{}", params.method, params.uri));

    let expected = match (&params.qop, &params.nc, &params.cnonce) {
        (Some(qop), Some(nc), Some(cnonce)) if qop == "auth" => md5_hex(&format!(
            "{}:{}:{}:{}:{}:{}",
            ha1, params.nonce, nc, cnonce, qop, ha2
        )),
        _ => md5_hex(&format!("{}:{}:{}", ha1, params.nonce, ha2)),
    };

    params.response.eq_ignore_ascii_case(&expected)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_md5_hex_empty() {
        assert_eq!(md5_hex(""), "d41d8cd98f00b204e9800998ecf8427e");
    }

    #[test]
    fn test_md5_hex_hello() {
        assert_eq!(md5_hex("hello"), "5d41402abc4b2a76b9719d911017c592");
    }

    #[test]
    fn test_verify_digest_without_qop() {
        // Compute expected values manually
        let ha1 = md5_hex("alice:sipcord:password123");
        let ha2 = md5_hex("REGISTER:sip:sipcord");
        let nonce = "dcd98b7102dd2f0e8b11d0f600bfb0c093";
        let response = md5_hex(&format!("{}:{}:{}", ha1, nonce, ha2));

        let params = DigestAuthParams {
            username: "alice".to_string(),
            realm: "sipcord".to_string(),
            nonce: nonce.to_string(),
            uri: "sip:sipcord".to_string(),
            response,
            method: "REGISTER".to_string(),
            qop: None,
            nc: None,
            cnonce: None,
        };

        assert!(verify_digest_with_ha1(&ha1, &params));
    }

    #[test]
    fn test_verify_digest_with_qop_auth() {
        let ha1 = md5_hex("bob:sipcord:secret");
        let ha2 = md5_hex("REGISTER:sip:sipcord");
        let nonce = "abc123";
        let nc = "00000001";
        let cnonce = "0a4f113b";
        let response = md5_hex(&format!("{}:{}:{}:{}:auth:{}", ha1, nonce, nc, cnonce, ha2));

        let params = DigestAuthParams {
            username: "bob".to_string(),
            realm: "sipcord".to_string(),
            nonce: nonce.to_string(),
            uri: "sip:sipcord".to_string(),
            response,
            method: "REGISTER".to_string(),
            qop: Some("auth".to_string()),
            nc: Some(nc.to_string()),
            cnonce: Some(cnonce.to_string()),
        };

        assert!(verify_digest_with_ha1(&ha1, &params));
    }

    #[test]
    fn test_verify_digest_wrong_response() {
        let ha1 = md5_hex("alice:sipcord:password123");
        let params = DigestAuthParams {
            username: "alice".to_string(),
            realm: "sipcord".to_string(),
            nonce: "nonce".to_string(),
            uri: "sip:sipcord".to_string(),
            response: "0000000000000000000000000000dead".to_string(),
            method: "REGISTER".to_string(),
            qop: None,
            nc: None,
            cnonce: None,
        };

        assert!(!verify_digest_with_ha1(&ha1, &params));
    }

    #[test]
    fn test_auth_cache_record_failure() {
        let cache = AuthCache::new(Duration::from_secs(300), Duration::from_secs(60), 3);
        assert_eq!(cache.record_failure("user1"), 1);
        assert_eq!(cache.record_failure("user1"), 2);
        assert_eq!(cache.record_failure("user1"), 3);
    }

    #[test]
    fn test_auth_cache_clear_failures() {
        let cache = AuthCache::new(Duration::from_secs(300), Duration::from_secs(60), 3);
        cache.record_failure("user1");
        cache.record_failure("user1");
        cache.clear_failures("user1");
        assert!(!cache.is_in_cooldown("user1"));
    }

    #[test]
    fn test_auth_cache_cooldown_threshold() {
        let cache = AuthCache::new(Duration::from_secs(300), Duration::from_secs(60), 3);
        assert!(!cache.is_in_cooldown("user1"));
        cache.record_failure("user1");
        cache.record_failure("user1");
        assert!(!cache.is_in_cooldown("user1"));
        cache.record_failure("user1");
        assert!(cache.is_in_cooldown("user1"));
    }
}
