//! SIP Registration Storage
//!
//! Tracks SIP REGISTER'ed users so we know which phones are online
//! and can route inbound calls (Discord -> SIP) to them.

use dashmap::DashMap;
use std::net::SocketAddr;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};
use tracing::debug;

use crate::routing::{RegistrationContactDiagnostics, RegistrationDiagnostics};

/// Global registrar instance (set during initialization)
pub static GLOBAL_REGISTRAR: OnceLock<Arc<Registrar>> = OnceLock::new();

/// Transport protocol used for a SIP registration
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SipTransport {
    Udp,
    Tcp,
    Tls,
}

/// The stable identity used to refresh or remove one Contact binding.
///
/// SIPcord historically ignored Contact URI parameters. Retaining that base
/// identity keeps parameter-churning phones working, while Asterisk's opaque
/// `line` token is included so multiple outbound registrations do not merge.
#[derive(Debug, Clone, PartialEq, Eq)]
struct RegistrationBindingIdentity {
    legacy_base_uri: String,
    line: Option<String>,
}

/// Parsed data from a REGISTER Contact.
#[derive(Clone)]
pub struct RegisteredContact {
    advertised_uri: String,
    callback_uri: String,
    identity: RegistrationBindingIdentity,
}

impl RegisteredContact {
    pub(crate) fn new(
        advertised_uri: String,
        legacy_base_uri: String,
        line: Option<String>,
        callback_uri: String,
    ) -> Self {
        Self {
            advertised_uri,
            callback_uri,
            identity: RegistrationBindingIdentity {
                legacy_base_uri,
                line,
            },
        }
    }

    pub(crate) fn advertised_uri(&self) -> &str {
        &self.advertised_uri
    }
}

impl std::fmt::Debug for RegisteredContact {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RegisteredContact")
            .field(
                "advertised_uri",
                &redact_sip_uri_credentials(&self.advertised_uri),
            )
            .field(
                "callback_uri",
                &redact_sip_uri_credentials(&self.callback_uri),
            )
            .finish_non_exhaustive()
    }
}

impl std::fmt::Display for RegisteredContact {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&redact_sip_uri_credentials(&self.advertised_uri))
    }
}

/// A single SIP registration (one phone/device)
#[derive(Debug, Clone)]
pub struct Registration {
    pub sip_username: String,
    /// Stable Discord user snowflake. Display names are deliberately not used
    /// for routing because they can change while a phone remains registered.
    pub discord_user_id: String,
    /// Advertised Contact, stable binding identity, and NAT-safe callback URI.
    pub contact: RegisteredContact,
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

        // The compatibility identity ignores incidental URI parameter churn
        // but includes Asterisk's `line` token. The observed source address is
        // allowed to change when a NAT mapping is refreshed.
        if let Some(existing) = regs
            .iter_mut()
            .find(|registration| registration.contact.identity == reg.contact.identity)
        {
            let old_user_id = existing.discord_user_id.clone();

            existing.expires_at = reg.expires_at;
            existing.registered_at = reg.registered_at;
            existing.contact = reg.contact.clone();
            existing.source_addr = reg.source_addr;
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

    /// Remove one Contact binding, or every binding for the SIP username when
    /// `contact` is absent (the REGISTER `Contact: *;expires=0` form).
    /// Returns the number of bindings removed.
    pub fn remove_registration(
        &self,
        sip_username: &str,
        contact: Option<&RegisteredContact>,
    ) -> usize {
        let Some(mut regs) = self.registrations.get_mut(sip_username) else {
            return 0;
        };
        let user_ids_before: Vec<String> = regs
            .iter()
            .map(|registration| registration.discord_user_id.clone())
            .collect();
        let before = regs.len();
        match contact {
            Some(contact) => {
                regs.retain(|registration| registration.contact.identity != contact.identity)
            }
            None => regs.clear(),
        }
        let removed = before - regs.len();
        let empty = regs.is_empty();
        drop(regs);

        if empty {
            self.registrations.remove(sip_username);
        }
        if removed > 0 {
            for user_id in user_ids_before {
                self.remove_user_mapping_if_unused(&user_id, sip_username);
            }
        }
        removed
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

    /// Get client-advertised contacts for a Discord user.
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
                .map(|registration| {
                    (
                        registration.contact.advertised_uri.clone(),
                        registration.source_addr,
                        registration.transport,
                    )
                })
                .collect(),
            None => Vec::new(),
        }
    }

    /// Get NAT-safe Request-URIs for callback calls to a Discord user.
    pub(crate) fn get_callback_uris_for_discord_user_id(
        &self,
        discord_user_id: &str,
    ) -> Vec<String> {
        let sip_username = match self.user_to_sip.get(discord_user_id) {
            Some(entry) => entry.value().clone(),
            None => return Vec::new(),
        };

        let now = Instant::now();
        match self.registrations.get(&sip_username) {
            Some(registrations) => registrations
                .iter()
                .filter(|registration| {
                    registration.expires_at > now
                        && registration.discord_user_id == discord_user_id
                })
                .map(|registration| registration.contact.callback_uri.clone())
                .collect(),
            None => Vec::new(),
        }
    }

    /// Take an operator-facing snapshot of the registrar for a target user.
    /// Contact URIs and observed source addresses are intentionally included so
    /// stale NAT bindings and cross-region registration problems can be diagnosed.
    pub fn diagnostics_for_discord_user_id(
        &self,
        discord_user_id: &str,
    ) -> RegistrationDiagnostics {
        let now = Instant::now();
        let mapped_sip_username = self
            .user_to_sip
            .get(discord_user_id)
            .map(|entry| entry.value().clone());
        let registrar_registrations = self
            .registrations
            .iter()
            .map(|entry| entry.value().len())
            .sum();

        // Scan the registrations as well as the reverse index. If the index is
        // ever missing or stale, the snapshot will make that discrepancy visible.
        let mut registrations: Vec<RegistrationContactDiagnostics> = self
            .registrations
            .iter()
            .flat_map(|entry| {
                entry
                    .value()
                    .iter()
                    .filter(|registration| registration.discord_user_id == discord_user_id)
                    .map(|registration| RegistrationContactDiagnostics {
                        contact_uri: redact_sip_uri_credentials(
                            registration.contact.advertised_uri(),
                        ),
                        source_addr: registration.source_addr.to_string(),
                        transport: match registration.transport {
                            SipTransport::Udp => "udp",
                            SipTransport::Tcp => "tcp",
                            SipTransport::Tls => "tls",
                        }
                        .to_string(),
                        active: registration.expires_at > now,
                        registered_age_ms: duration_ms(
                            now.saturating_duration_since(registration.registered_at),
                        ),
                        expires_in_ms: if registration.expires_at > now {
                            duration_ms(registration.expires_at.duration_since(now)) as i64
                        } else {
                            -(duration_ms(now.duration_since(registration.expires_at)) as i64)
                        },
                    })
                    .collect::<Vec<_>>()
            })
            .collect();
        let target_active_registration_count = registrations
            .iter()
            .filter(|registration| registration.active)
            .count();
        let target_registration_count = registrations.len();
        const MAX_DIAGNOSTIC_REGISTRATIONS: usize = 32;
        let registrations_truncated = target_registration_count > MAX_DIAGNOSTIC_REGISTRATIONS;
        registrations.truncate(MAX_DIAGNOSTIC_REGISTRATIONS);

        RegistrationDiagnostics {
            registrar_sip_users: self.registrations.len(),
            registrar_user_mappings: self.user_to_sip.len(),
            registrar_registrations,
            mapped_sip_username,
            target_registration_count,
            target_active_registration_count,
            target_expired_registration_count: target_registration_count
                - target_active_registration_count,
            registrations_truncated,
            registrations,
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

fn duration_ms(duration: Duration) -> u64 {
    duration.as_millis().min(u64::MAX as u128) as u64
}

fn redact_sip_uri_credentials(uri: &str) -> String {
    let lower = uri.to_ascii_lowercase();
    let Some(scheme_start) = lower.find("sips:").or_else(|| lower.find("sip:")) else {
        return uri.to_string();
    };
    let user_info_start = scheme_start
        + if lower[scheme_start..].starts_with("sips:") {
            5
        } else {
            4
        };
    let Some(at_offset) = uri[user_info_start..].find('@') else {
        return uri.to_string();
    };
    let at = user_info_start + at_offset;
    let Some(password_separator) = uri[user_info_start..at].find(':') else {
        return uri.to_string();
    };
    let password_start = user_info_start + password_separator + 1;
    format!("{}[redacted]{}", &uri[..password_start], &uri[at..])
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
        make_reg_with_contact(
            sip_user,
            discord_user_id,
            addr,
            contact,
            contact,
            None,
            contact,
            expires_secs,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn make_reg_with_contact(
        sip_user: &str,
        discord_user_id: &str,
        addr: &str,
        advertised_uri: &str,
        legacy_base_uri: &str,
        line: Option<&str>,
        callback_uri: &str,
        expires_secs: u64,
    ) -> Registration {
        Registration {
            sip_username: sip_user.to_string(),
            discord_user_id: discord_user_id.to_string(),
            contact: RegisteredContact::new(
                advertised_uri.to_string(),
                legacy_base_uri.to_string(),
                line.map(str::to_string),
                callback_uri.to_string(),
            ),
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
        // Same Contact URI -> update in place
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
    fn refresh_updates_nat_source_without_duplicating_contact() {
        let reg = Registrar::new();
        reg.add_registration(make_reg(
            "alice",
            "1001",
            "1.2.3.4:5060",
            "sip:alice@phone.local:5060",
            300,
        ));
        reg.add_registration(make_reg(
            "alice",
            "1001",
            "1.2.3.4:62000",
            "sip:alice@phone.local:5060",
            300,
        ));

        let contacts = reg.get_contacts_for_discord_user_id("1001");
        assert_eq!(contacts.len(), 1);
        assert_eq!(
            contacts[0].1,
            "1.2.3.4:62000".parse::<SocketAddr>().unwrap()
        );
    }

    #[test]
    fn refresh_ignores_non_line_contact_parameter_churn() {
        let reg = Registrar::new();
        let base = "sip:alice@phone.local:5060";
        reg.add_registration(make_reg_with_contact(
            "alice",
            "1001",
            "1.2.3.4:5060",
            "sip:alice@phone.local:5060;vendor-state=one",
            base,
            None,
            "sip:alice@1.2.3.4:5060;transport=udp;vendor-state=one",
            300,
        ));
        reg.add_registration(make_reg_with_contact(
            "alice",
            "1001",
            "1.2.3.4:62000",
            "sip:alice@phone.local:5060;vendor-state=two",
            base,
            None,
            "sip:alice@1.2.3.4:62000;transport=udp;vendor-state=two",
            300,
        ));

        let contacts = reg.get_contacts_for_discord_user_id("1001");
        assert_eq!(contacts.len(), 1);
        assert_eq!(contacts[0].1, "1.2.3.4:62000".parse().unwrap());
        assert_eq!(
            contacts[0].0,
            "sip:alice@phone.local:5060;vendor-state=two"
        );
        let callback_uris = reg.get_callback_uris_for_discord_user_id("1001");
        assert_eq!(
            callback_uris[0],
            "sip:alice@1.2.3.4:62000;transport=udp;vendor-state=two"
        );
    }

    #[test]
    fn refresh_with_same_line_token_updates_nat_callback_without_duplication() {
        let reg = Registrar::new();
        let base = "sip:sipcord-inbound@pbx.local:5060";
        reg.add_registration(make_reg_with_contact(
            "alice",
            "1001",
            "1.2.3.4:51000",
            "sip:sipcord-inbound@pbx.local:5060;line=opaque",
            base,
            Some("opaque"),
            "sip:sipcord-inbound@1.2.3.4:51000;transport=udp;line=opaque",
            300,
        ));
        reg.add_registration(make_reg_with_contact(
            "alice",
            "1001",
            "1.2.3.4:62000",
            "sip:sipcord-inbound@pbx.local:5060;line=opaque",
            base,
            Some("opaque"),
            "sip:sipcord-inbound@1.2.3.4:62000;transport=udp;line=opaque",
            300,
        ));

        let contacts = reg.get_contacts_for_discord_user_id("1001");
        assert_eq!(contacts.len(), 1);
        assert_eq!(contacts[0].1, "1.2.3.4:62000".parse().unwrap());
        let callback_uris = reg.get_callback_uris_for_discord_user_id("1001");
        assert_eq!(
            callback_uris[0],
            "sip:sipcord-inbound@1.2.3.4:62000;transport=udp;line=opaque"
        );
    }

    #[test]
    fn line_tokens_distinguish_bindings_and_targeted_unregister() {
        let reg = Registrar::new();
        let base = "sip:sipcord-inbound@pbx.local:5060";
        let first = make_reg_with_contact(
            "alice",
            "1001",
            "1.2.3.4:51000",
            "sip:sipcord-inbound@pbx.local:5060;line=first",
            base,
            Some("first"),
            "sip:sipcord-inbound@1.2.3.4:51000;transport=udp;line=first",
            300,
        );
        let first_contact = first.contact.clone();
        reg.add_registration(first);
        reg.add_registration(make_reg_with_contact(
            "alice",
            "1001",
            "1.2.3.4:52000",
            "sip:sipcord-inbound@pbx.local:5060;line=second",
            base,
            Some("second"),
            "sip:sipcord-inbound@1.2.3.4:52000;transport=udp;line=second",
            300,
        ));

        let callback_uris = reg.get_callback_uris_for_discord_user_id("1001");
        assert_eq!(callback_uris.len(), 2);
        assert!(
            callback_uris
                .iter()
                .any(|request_uri| request_uri.ends_with(";line=first"))
        );
        assert!(
            callback_uris
                .iter()
                .any(|request_uri| request_uri.ends_with(";line=second"))
        );

        assert_eq!(reg.remove_registration("alice", Some(&first_contact)), 1);
        let callback_uris = reg.get_callback_uris_for_discord_user_id("1001");
        assert_eq!(callback_uris.len(), 1);
        assert!(callback_uris[0].ends_with(";line=second"));
    }

    #[test]
    fn unregister_removes_every_stale_source_for_contact() {
        let reg = Registrar::new();
        // Seed the duplicate state produced by the old source+Contact keying.
        let contact = "sip:alice@phone.local:5060";
        let mut registrations = vec![
            make_reg("alice", "1001", "1.2.3.4:5060", contact, 300),
            make_reg("alice", "1001", "1.2.3.4:62000", contact, 300),
        ];
        let registered_contact = registrations[0].contact.clone();
        reg.registrations
            .insert("alice".to_string(), std::mem::take(&mut registrations));
        reg.user_to_sip
            .insert("1001".to_string(), "alice".to_string());

        assert_eq!(
            reg.remove_registration("alice", Some(&registered_contact)),
            2
        );
        assert!(reg.get_contacts_for_discord_user_id("1001").is_empty());
        assert!(!reg.user_to_sip.contains_key("1001"));
    }

    #[test]
    fn wildcard_unregister_removes_all_contacts() {
        let reg = Registrar::new();
        reg.add_registration(make_reg(
            "alice",
            "1001",
            "1.2.3.4:5060",
            "sip:alice@phone-a.local",
            300,
        ));
        reg.add_registration(make_reg(
            "alice",
            "1001",
            "5.6.7.8:5060",
            "sip:alice@phone-b.local",
            300,
        ));

        assert_eq!(reg.remove_registration("alice", None), 2);
        assert!(reg.get_contacts_for_discord_user_id("1001").is_empty());
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
    fn diagnostics_include_active_and_expired_contacts() {
        let reg = Registrar::new();
        let mut expired = make_reg("charlie", "1003", "1.2.3.4:5060", "sip:charlie@1.2.3.4", 0);
        expired.expires_at = Instant::now() - Duration::from_secs(1);
        reg.add_registration(expired);
        let mut active = make_reg(
            "charlie",
            "1003",
            "5.6.7.8:5061",
            "sips:charlie@5.6.7.8:5061",
            300,
        );
        active.transport = SipTransport::Tls;
        reg.add_registration(active);

        let diagnostics = reg.diagnostics_for_discord_user_id("1003");
        assert_eq!(diagnostics.mapped_sip_username.as_deref(), Some("charlie"));
        assert_eq!(diagnostics.target_registration_count, 2);
        assert_eq!(diagnostics.target_active_registration_count, 1);
        assert_eq!(diagnostics.target_expired_registration_count, 1);
        assert!(!diagnostics.registrations_truncated);
        assert!(diagnostics.registrations.iter().any(|contact| {
            contact.active && contact.transport == "tls" && contact.source_addr == "5.6.7.8:5061"
        }));
        assert!(
            diagnostics
                .registrations
                .iter()
                .any(|contact| { !contact.active && contact.contact_uri == "sip:charlie@1.2.3.4" })
        );
    }

    #[test]
    fn diagnostics_expose_a_missing_reverse_index() {
        let reg = Registrar::new();
        reg.add_registration(make_reg(
            "alice",
            "1001",
            "1.2.3.4:5060",
            "sip:alice@1.2.3.4",
            300,
        ));
        reg.user_to_sip.remove("1001");

        let diagnostics = reg.diagnostics_for_discord_user_id("1001");
        assert_eq!(diagnostics.mapped_sip_username, None);
        assert_eq!(diagnostics.target_registration_count, 1);
        assert_eq!(diagnostics.target_active_registration_count, 1);
    }

    #[test]
    fn diagnostics_redact_sip_uri_passwords() {
        assert_eq!(
            redact_sip_uri_credentials("<sips:alice:super-secret@example.com:5061;transport=tls>"),
            "<sips:alice:[redacted]@example.com:5061;transport=tls>"
        );
        assert_eq!(
            redact_sip_uri_credentials("sip:alice@example.com"),
            "sip:alice@example.com"
        );
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
