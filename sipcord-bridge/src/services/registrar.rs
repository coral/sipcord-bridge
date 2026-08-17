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
    /// Stable Discord user snowflake. Display names are deliberately not used
    /// for routing because they can change while a phone remains registered.
    pub discord_user_id: String,
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
    /// Discord user ID -> SIP username (reverse lookup for inbound calls)
    user_to_sip: DashMap<String, String>,
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
            user_to_sip: DashMap::new(),
        }
    }

    /// Add or update a registration.
    pub fn add_registration(&self, reg: Registration) {
        let sip_username = reg.sip_username.clone();
        let discord_user_id = reg.discord_user_id.clone();

        // Update or insert into registrations
        let mut regs = self.registrations.entry(sip_username.clone()).or_default();

        // Check if this source_addr already has a registration - update it
        if let Some(existing) = regs
            .iter_mut()
            .find(|r| r.source_addr == reg.source_addr && r.contact_uri == reg.contact_uri)
        {
            let old_user_id = existing.discord_user_id.clone();

            existing.expires_at = reg.expires_at;
            existing.registered_at = reg.registered_at;
            existing.contact_uri = reg.contact_uri.clone();
            existing.discord_user_id = reg.discord_user_id.clone();
            existing.transport = reg.transport;
            let user_changed = old_user_id != existing.discord_user_id;

            drop(regs);
            self.user_to_sip
                .insert(discord_user_id, sip_username.clone());
            if user_changed {
                self.remove_user_mapping_if_unused(&old_user_id, &sip_username);
            }

            return;
        }

        regs.push(reg);
        drop(regs);

        self.user_to_sip.insert(discord_user_id, sip_username);
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
                let user_ids_before: Vec<String> =
                    regs.iter().map(|r| r.discord_user_id.clone()).collect();

                regs.retain(|r| r.expires_at > now);

                if regs.is_empty() {
                    drop(regs);
                    self.registrations.remove(&sip_username);

                    for user_id in user_ids_before {
                        self.remove_user_mapping_if_unused(&user_id, &sip_username);
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
    pub fn get_contacts_for_discord_user_id(
        &self,
        discord_user_id: &str,
    ) -> Vec<(String, SocketAddr, SipTransport)> {
        let sip_username = match self.user_to_sip.get(discord_user_id) {
            Some(entry) => entry.value().clone(),
            None => return Vec::new(),
        };

        let now = Instant::now();
        match self.registrations.get(&sip_username) {
            Some(regs) => regs
                .iter()
                .filter(|r| r.expires_at > now && r.discord_user_id == discord_user_id)
                .map(|r| (r.contact_uri.clone(), r.source_addr, r.transport))
                .collect(),
            None => Vec::new(),
        }
    }

    fn remove_user_mapping_if_unused(&self, discord_user_id: &str, sip_username: &str) {
        let still_registered = self
            .registrations
            .get(sip_username)
            .is_some_and(|regs| regs.iter().any(|r| r.discord_user_id == discord_user_id));
        if !still_registered
            && self
                .user_to_sip
                .get(discord_user_id)
                .is_some_and(|mapped| mapped.value() == sip_username)
        {
            self.user_to_sip.remove(discord_user_id);
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use std::thread;

    fn make_reg(
        sip_user: &str,
        discord_user_id: &str,
        addr: &str,
        contact: &str,
        expires_secs: u64,
    ) -> Registration {
        Registration {
            sip_username: sip_user.to_string(),
            discord_user_id: discord_user_id.to_string(),
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
            "1001",
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
            "1002",
            "5.6.7.8:5060",
            "sip:bob@5.6.7.8",
            300,
        ));
        let contacts = reg.get_contacts_for_discord_user_id("1002");
        assert_eq!(contacts.len(), 1);
        assert_eq!(contacts[0].0, "sip:bob@5.6.7.8");
    }

    #[test]
    fn test_update_existing_registration() {
        let reg = Registrar::new();
        reg.add_registration(make_reg(
            "alice",
            "1001",
            "1.2.3.4:5060",
            "sip:alice@1.2.3.4",
            300,
        ));
        // Same source_addr + contact_uri -> update in place
        reg.add_registration(make_reg(
            "alice",
            "1001",
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
            "1001",
            "1.2.3.4:5060",
            "sip:alice@1.2.3.4",
            300,
        ));
        reg.add_registration(make_reg(
            "alice",
            "1001",
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
        let mut expired_reg =
            make_reg("alice", "1001", "1.2.3.4:5060", "sip:alice@1.2.3.4", 0);
        expired_reg.expires_at = Instant::now() - Duration::from_secs(1);
        reg.add_registration(expired_reg);
        // Add one that's still valid
        reg.add_registration(make_reg(
            "alice",
            "1001",
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
            "1003",
            "1.2.3.4:5060",
            "sip:charlie@1.2.3.4",
            0,
        );
        expired_reg.expires_at = Instant::now() - Duration::from_secs(1);
        reg.add_registration(expired_reg);

        reg.add_registration(make_reg(
            "charlie",
            "1003",
            "5.6.7.8:5060",
            "sip:charlie@5.6.7.8",
            300,
        ));

        let contacts = reg.get_contacts_for_discord_user_id("1003");
        assert_eq!(contacts.len(), 1);
        assert_eq!(contacts[0].0, "sip:charlie@5.6.7.8");
    }

    #[test]
    fn expiring_one_phone_preserves_other_contacts() {
        let reg = Registrar::new();
        let mut expired =
            make_reg("alice", "1001", "1.2.3.4:5060", "sip:alice@1.2.3.4", 0);
        expired.expires_at = Instant::now() - Duration::from_secs(1);
        reg.add_registration(expired);
        reg.add_registration(make_reg(
            "alice",
            "1001",
            "5.6.7.8:5060",
            "sip:alice@5.6.7.8",
            300,
        ));

        reg.remove_expired();

        let contacts = reg.get_contacts_for_discord_user_id("1001");
        assert_eq!(contacts.len(), 1);
        assert_eq!(contacts[0].1, "5.6.7.8:5060".parse().unwrap());
    }

    #[test]
    fn many_phones_registered_concurrently_are_all_routable() {
        const PHONES: usize = 128;
        let registrar = Arc::new(Registrar::new());
        let handles: Vec<_> = (0..PHONES)
            .map(|index| {
                let registrar = registrar.clone();
                thread::spawn(move || {
                    registrar.add_registration(make_reg(
                        "alice",
                        "1001",
                        &format!("10.0.0.{}:{}", index / 250 + 1, 5_000 + index),
                        &format!("sip:alice@phone-{index}.local"),
                        300,
                    ));
                })
            })
            .collect();
        for handle in handles {
            handle.join().unwrap();
        }

        let contacts = registrar.get_contacts_for_discord_user_id("1001");
        assert_eq!(contacts.len(), PHONES);
        for index in 0..PHONES {
            assert!(
                contacts
                    .iter()
                    .any(|contact| contact.0 == format!("sip:alice@phone-{index}.local"))
            );
        }
    }

    #[test]
    fn concurrent_refreshes_of_one_phone_do_not_duplicate_it() {
        let registrar = Arc::new(Registrar::new());
        let handles: Vec<_> = (0..64)
            .map(|_| {
                let registrar = registrar.clone();
                thread::spawn(move || {
                    registrar.add_registration(make_reg(
                        "alice",
                        "1001",
                        "10.0.0.1:5060",
                        "sip:alice@phone.local",
                        300,
                    ));
                })
            })
            .collect();
        for handle in handles {
            handle.join().unwrap();
        }

        assert_eq!(registrar.get_contacts_for_discord_user_id("1001").len(), 1);
    }

    #[test]
    fn users_sharing_a_sip_name_never_receive_each_others_contacts() {
        let registrar = Registrar::new();
        registrar.add_registration(make_reg(
            "shared",
            "1001",
            "10.0.0.1:5060",
            "sip:shared@phone-a.local",
            300,
        ));
        registrar.add_registration(make_reg(
            "shared",
            "1002",
            "10.0.0.2:5060",
            "sip:shared@phone-b.local",
            300,
        ));

        let alice = registrar.get_contacts_for_discord_user_id("1001");
        let bob = registrar.get_contacts_for_discord_user_id("1002");
        assert_eq!(alice.len(), 1);
        assert_eq!(alice[0].0, "sip:shared@phone-a.local");
        assert_eq!(bob.len(), 1);
        assert_eq!(bob[0].0, "sip:shared@phone-b.local");
    }

    #[test]
    fn refresh_updates_transport_and_user_mapping_atomically() {
        let registrar = Registrar::new();
        registrar.add_registration(make_reg(
            "alice",
            "old-user",
            "10.0.0.1:5060",
            "sip:alice@phone.local",
            300,
        ));
        let mut refreshed = make_reg(
            "alice",
            "new-user",
            "10.0.0.1:5060",
            "sip:alice@phone.local",
            300,
        );
        refreshed.transport = SipTransport::Tls;
        registrar.add_registration(refreshed);

        assert!(registrar.get_contacts_for_discord_user_id("old-user").is_empty());
        let contacts = registrar.get_contacts_for_discord_user_id("new-user");
        assert_eq!(contacts.len(), 1);
        assert_eq!(contacts[0].2, SipTransport::Tls);
    }
}
