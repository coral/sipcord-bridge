//! SIP Registration Storage
//!
//! Tracks SIP REGISTER'ed users so we know which phones are online
//! and can route inbound calls (Discord -> SIP) to them.

use dashmap::DashMap;
use std::net::SocketAddr;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};
use tracing::debug;

/// Global registrar instance (set during initialization)
pub static GLOBAL_REGISTRAR: OnceLock<Arc<Registrar>> = OnceLock::new();

/// Transport protocol used for a SIP registration
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SipTransport {
    Udp,
    Tcp,
    Tls,
}

/// A single SIP registration (one phone/device)
#[derive(Debug, Clone)]
pub struct Registration {
    pub sip_username: String,
    /// None if user has allow_inbound_calls disabled
    pub discord_username: Option<String>,
    /// From Contact header (client-advertised URI)
    pub contact_uri: String,
    /// Actual transport source (for NAT traversal)
    pub source_addr: SocketAddr,
    /// Transport protocol used to register
    pub transport: SipTransport,
    /// When this registration expires
    pub expires_at: Instant,
    /// When this registration was created/refreshed
    pub registered_at: Instant,
}

/// Manages SIP registrations for all users
pub struct Registrar {
    /// SIP username -> list of registrations (multiple phones per user)
    registrations: DashMap<String, Vec<Registration>>,
    /// Discord username -> SIP username (reverse lookup for inbound calls)
    discord_to_sip: DashMap<String, String>,
}

impl Default for Registrar {
    fn default() -> Self {
        Self::new()
    }
}

impl Registrar {
    pub fn new() -> Self {
        Self {
            registrations: DashMap::new(),
            discord_to_sip: DashMap::new(),
        }
    }

    /// Add or update a registration.
    pub fn add_registration(&self, reg: Registration) {
        let sip_username = reg.sip_username.clone();
        let discord_username = reg.discord_username.clone();

        // Update or insert into registrations
        let mut regs = self.registrations.entry(sip_username.clone()).or_default();

        // Check if this source_addr already has a registration - update it
        if let Some(existing) = regs
            .iter_mut()
            .find(|r| r.source_addr == reg.source_addr && r.contact_uri == reg.contact_uri)
        {
            // If discord_username changed, remove the old reverse mapping
            if existing.discord_username != reg.discord_username
                && let Some(ref old_du) = existing.discord_username
            {
                self.discord_to_sip.remove(old_du);
            }

            existing.expires_at = reg.expires_at;
            existing.registered_at = reg.registered_at;
            existing.contact_uri = reg.contact_uri.clone();
            existing.discord_username = reg.discord_username.clone();

            // Update reverse lookup if discord_username is set
            if let Some(ref du) = discord_username {
                self.discord_to_sip.insert(du.clone(), sip_username.clone());
            }

            return;
        }

        regs.push(reg);
        drop(regs);

        // Update reverse lookup
        if let Some(ref du) = discord_username {
            self.discord_to_sip.insert(du.clone(), sip_username.clone());
        }
    }

    /// Remove expired registrations.
    pub fn remove_expired(&self) {
        let now = Instant::now();

        let mut to_clean = Vec::new();
        for entry in self.registrations.iter() {
            let sip_username = entry.key().clone();
            let has_expired = entry.value().iter().any(|r| r.expires_at <= now);
            if has_expired {
                to_clean.push(sip_username);
            }
        }

        for sip_username in to_clean {
            if let Some(mut regs) = self.registrations.get_mut(&sip_username) {
                let discord_username_before = regs.iter().find_map(|r| r.discord_username.clone());

                regs.retain(|r| r.expires_at > now);

                if regs.is_empty() {
                    drop(regs);
                    self.registrations.remove(&sip_username);

                    // Clean up reverse lookup
                    if let Some(du) = discord_username_before {
                        self.discord_to_sip.remove(&du);
                    }
                }
            }
        }
    }

    /// Get source addresses for a SIP user (for debug capture)
    pub fn get_source_addrs_for_sip_user(&self, sip_username: &str) -> Vec<SocketAddr> {
        let now = Instant::now();
        match self.registrations.get(sip_username) {
            Some(regs) => regs
                .iter()
                .filter(|r| r.expires_at > now)
                .map(|r| r.source_addr)
                .collect(),
            None => Vec::new(),
        }
    }

    /// Get contacts for a Discord user (for inbound calling)
    pub fn get_contacts_for_discord_user(
        &self,
        discord_username: &str,
    ) -> Vec<(String, SocketAddr, SipTransport)> {
        let sip_username = match self.discord_to_sip.get(discord_username) {
            Some(entry) => entry.value().clone(),
            None => return Vec::new(),
        };

        let now = Instant::now();
        match self.registrations.get(&sip_username) {
            Some(regs) => regs
                .iter()
                .filter(|r| r.expires_at > now)
                .map(|r| (r.contact_uri.clone(), r.source_addr, r.transport))
                .collect(),
            None => Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    fn make_reg(
        sip_user: &str,
        discord_user: Option<&str>,
        addr: &str,
        contact: &str,
        expires_secs: u64,
    ) -> Registration {
        Registration {
            sip_username: sip_user.to_string(),
            discord_username: discord_user.map(|s| s.to_string()),
            contact_uri: contact.to_string(),
            source_addr: addr.parse::<SocketAddr>().unwrap(),
            transport: SipTransport::Udp,
            expires_at: Instant::now() + Duration::from_secs(expires_secs),
            registered_at: Instant::now(),
        }
    }

    #[test]
    fn test_add_and_lookup() {
        let reg = Registrar::new();
        reg.add_registration(make_reg(
            "alice",
            None,
            "1.2.3.4:5060",
            "sip:alice@1.2.3.4",
            300,
        ));
        let addrs = reg.get_source_addrs_for_sip_user("alice");
        assert_eq!(addrs.len(), 1);
        assert_eq!(addrs[0], "1.2.3.4:5060".parse::<SocketAddr>().unwrap());
    }

    #[test]
    fn test_discord_reverse_lookup() {
        let reg = Registrar::new();
        reg.add_registration(make_reg(
            "bob",
            Some("bob#1234"),
            "5.6.7.8:5060",
            "sip:bob@5.6.7.8",
            300,
        ));
        let contacts = reg.get_contacts_for_discord_user("bob#1234");
        assert_eq!(contacts.len(), 1);
        assert_eq!(contacts[0].0, "sip:bob@5.6.7.8");
    }

    #[test]
    fn test_update_existing_registration() {
        let reg = Registrar::new();
        reg.add_registration(make_reg(
            "alice",
            None,
            "1.2.3.4:5060",
            "sip:alice@1.2.3.4",
            300,
        ));
        // Same source_addr + contact_uri -> update in place
        reg.add_registration(make_reg(
            "alice",
            None,
            "1.2.3.4:5060",
            "sip:alice@1.2.3.4",
            600,
        ));
        let addrs = reg.get_source_addrs_for_sip_user("alice");
        assert_eq!(addrs.len(), 1); // Should not duplicate
    }

    #[test]
    fn test_multiple_registrations_per_user() {
        let reg = Registrar::new();
        reg.add_registration(make_reg(
            "alice",
            None,
            "1.2.3.4:5060",
            "sip:alice@1.2.3.4",
            300,
        ));
        reg.add_registration(make_reg(
            "alice",
            None,
            "5.6.7.8:5060",
            "sip:alice@5.6.7.8",
            300,
        ));
        let addrs = reg.get_source_addrs_for_sip_user("alice");
        assert_eq!(addrs.len(), 2);
    }

    #[test]
    fn test_remove_expired() {
        let reg = Registrar::new();
        // Add one that expires immediately
        let mut expired_reg = make_reg("alice", None, "1.2.3.4:5060", "sip:alice@1.2.3.4", 0);
        expired_reg.expires_at = Instant::now() - Duration::from_secs(1);
        reg.add_registration(expired_reg);
        // Add one that's still valid
        reg.add_registration(make_reg(
            "alice",
            None,
            "5.6.7.8:5060",
            "sip:alice@5.6.7.8",
            300,
        ));

        reg.remove_expired();
        let addrs = reg.get_source_addrs_for_sip_user("alice");
        assert_eq!(addrs.len(), 1);
        assert_eq!(addrs[0], "5.6.7.8:5060".parse::<SocketAddr>().unwrap());
    }

    #[test]
    fn test_get_contacts_for_discord_user_expired_filtered() {
        let reg = Registrar::new();
        let mut expired_reg = make_reg(
            "charlie",
            Some("charlie#0001"),
            "1.2.3.4:5060",
            "sip:charlie@1.2.3.4",
            0,
        );
        expired_reg.expires_at = Instant::now() - Duration::from_secs(1);
        reg.add_registration(expired_reg);

        reg.add_registration(make_reg(
            "charlie",
            Some("charlie#0001"),
            "5.6.7.8:5060",
            "sip:charlie@5.6.7.8",
            300,
        ));

        let contacts = reg.get_contacts_for_discord_user("charlie#0001");
        assert_eq!(contacts.len(), 1);
        assert_eq!(contacts[0].0, "sip:charlie@5.6.7.8");
    }
}

/// Start the periodic cleanup task
pub fn spawn_cleanup_task(registrar: Arc<Registrar>) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(30));
        loop {
            interval.tick().await;
            registrar.remove_expired();
            debug!("Registrar cleanup complete");
        }
    });
}
