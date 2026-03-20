//! Audio bridge between SIP and Discord
//!
//! Architecture:
//! - ChannelBridge: One per Discord voice channel, shared by multiple SIP callers
//! - SipCallInfo: Tracks which channel each SIP call is connected to
//!
//! New Call Flow (with 183 Session Progress):
//! 1. SIP call comes in with Digest auth → SipEvent::IncomingCall
//! 2. Send 183 Session Progress (establishes early media)
//! 3. Start playing "connecting" sound in loop
//! 4. Bridge routes call via Backend → gets channel_id and bot_token
//! 5. Connect to Discord
//! 6. Stop connecting loop, play discord_join sound, send 200 OK
//! 7. When caller hangs up, remove from bridge
//! 8. When last caller leaves, destroy the bridge (disconnect bot)

use crate::fax::session::FaxSession;
use crate::fax::spandsp::FaxT38Receiver;
use crate::routing::{Backend, CallError, CallStartedInfo, OutboundCallRequest, RouteDecision};
use crate::services::snowflake::Snowflake;
use crate::services::sound::{SoundManager, create_sound_manager};
use crate::transport::discord::{
    DiscordEvent, DiscordVoiceConnection, SharedDiscordClient, register_discord_to_sip_producer,
    unregister_discord_to_sip_producer,
};
use crate::transport::sip::{
    CONF_SAMPLE_RATE, CallId, SipCommand, SipEvent, cleanup_channel_port,
    clear_channel_stale_audio, empty_bridge_grace_period_secs, register_call_channel,
    register_discord_to_sip, stop_loop, unregister_call_channel, unregister_discord_to_sip,
};
use anyhow::Result;
use crossbeam_channel::{Receiver, Sender, bounded};
use dashmap::{DashMap, DashSet};
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, trace, warn};
use udptl::AsyncUdptlSocket;

/// Type alias for fax session entries stored in the DashMap.
type FaxSessionEntry = (Arc<tokio::sync::Mutex<FaxSession>>, CancellationToken);

/// Ring buffer capacity for Discord→SIP audio (i16 mono @ 16kHz).
/// 3200 samples = 200ms of audio, enough for timing jitter.
const DISCORD_TO_SIP_RING_BUFFER_SIZE: usize = 3200;

/// Create and register bidirectional ring buffers for a channel.
/// Call this when a new ChannelBridge is created (after Discord connects).
fn setup_channel_ring_buffers(channel_id: Snowflake) {
    let (producer, consumer) = rtrb::RingBuffer::new(DISCORD_TO_SIP_RING_BUFFER_SIZE);
    register_discord_to_sip_producer(channel_id, producer);
    register_discord_to_sip(channel_id, consumer);
    info!(
        "Created Discord→SIP ring buffer for channel {} (capacity={})",
        channel_id, DISCORD_TO_SIP_RING_BUFFER_SIZE
    );
}

/// Tear down ring buffers for a channel. Call when a ChannelBridge is destroyed.
fn teardown_channel_ring_buffers(channel_id: Snowflake) {
    unregister_discord_to_sip_producer(channel_id);
    unregister_discord_to_sip(channel_id);
    clear_channel_stale_audio(channel_id);
    debug!("Removed Discord→SIP ring buffer for channel {}", channel_id);
}

/// A bridge to a Discord voice channel (shared by multiple SIP callers)
pub struct ChannelBridge {
    /// Guild ID (needed for API call on bridge destruction)
    pub guild_id: Snowflake,
    /// The Discord voice connection (one per channel)
    pub discord_connection: DiscordVoiceConnection,
    /// SIP call IDs currently connected to this bridge
    pub sip_calls: HashSet<CallId>,
    /// Bot token (stored for reference, no longer used for per-call client creation)
    pub bot_token: String,
    /// Last time a SIP call was active on this bridge (for orphan detection)
    pub last_call_time: Instant,
    /// When this bridge was created
    pub created_at: Instant,
    /// Number of reconnection attempts for this channel
    pub reconnect_attempts: u32,
    /// When the last reconnection attempt was made
    pub last_reconnect_at: Option<Instant>,
}

/// Info about an active SIP call
pub struct SipCallInfo {
    /// Which Discord channel this call is connected to (None if still authenticating)
    pub channel_id: Option<Snowflake>,
    /// User ID from API authentication (for call tracking)
    pub _user_id: Option<String>,
    /// Guild ID (for call tracking)
    pub _guild_id: Option<Snowflake>,
    /// Tracking ID for outbound calls (used to report no_audio status back to DO)
    pub tracking_id: Option<String>,
}

/// Shared state passed to per-call task handlers
#[derive(Clone)]
struct BridgeContext {
    backend: Arc<dyn Backend>,
    bridges: Arc<DashMap<Snowflake, ChannelBridge>>,
    pending_bridges: Arc<DashSet<Snowflake>>,
    /// Notify waiters when a pending bridge completes (or fails)
    bridge_ready_notifiers: Arc<DashMap<Snowflake, Arc<Notify>>>,
    sip_calls: Arc<DashMap<CallId, SipCallInfo>>,
    /// Active fax sessions keyed by SIP call ID.
    /// Each entry holds the session and a cancellation token for the T.38 processing task.
    fax_sessions: Arc<DashMap<CallId, FaxSessionEntry>>,
    discord_event_tx: Sender<DiscordEvent>,
    sip_cmd_tx: Sender<SipCommand>,
    sound_manager: Arc<SoundManager>,
    shared_discord: Arc<SharedDiscordClient>,
    /// Wakes the health check loop immediately when a Songbird driver disconnects unexpectedly.
    health_check_notify: Arc<Notify>,
}

/// The main bridge coordinator
pub struct BridgeCoordinator {
    backend: Arc<dyn Backend>,
    sip_cmd_tx: Sender<SipCommand>,
    sip_event_rx: Receiver<SipEvent>,
    bridges: Arc<DashMap<Snowflake, ChannelBridge>>,
    pending_bridges: Arc<DashSet<Snowflake>>,
    bridge_ready_notifiers: Arc<DashMap<Snowflake, Arc<Notify>>>,
    sip_calls: Arc<DashMap<CallId, SipCallInfo>>,
    /// Active fax sessions keyed by SIP call ID.
    /// Each entry holds the session and a cancellation token for the T.38 processing task.
    fax_sessions: Arc<DashMap<CallId, FaxSessionEntry>>,
    /// Stores outbound call requests by tracking_id so the answered handler can retrieve them.
    /// Entries are cleaned on answer/fail and periodically swept for stale entries.
    outbound_requests: Arc<DashMap<String, OutboundCallRequest>>,
    discord_event_tx: Sender<DiscordEvent>,
    discord_event_rx: Receiver<DiscordEvent>,
    sound_manager: Arc<SoundManager>,
    shared_discord: Arc<SharedDiscordClient>,
}

impl BridgeCoordinator {
    pub fn new(
        backend: Arc<dyn Backend>,
        sip_cmd_tx: Sender<SipCommand>,
        sip_event_rx: Receiver<SipEvent>,
        shared_discord: Arc<SharedDiscordClient>,
    ) -> Self {
        let (discord_event_tx, discord_event_rx) = bounded(1000);

        // Load sounds from config.toml
        let sounds_dir = PathBuf::from(&crate::config::EnvConfig::global().sounds_dir);

        let sound_manager = create_sound_manager(sounds_dir)
            .expect("Failed to create SoundManager - check config.toml and sound files");

        Self {
            backend,
            sip_cmd_tx,
            sip_event_rx,
            bridges: Arc::new(DashMap::new()),
            pending_bridges: Arc::new(DashSet::new()),
            bridge_ready_notifiers: Arc::new(DashMap::new()),
            sip_calls: Arc::new(DashMap::new()),
            fax_sessions: Arc::new(DashMap::new()),
            outbound_requests: Arc::new(DashMap::new()),
            discord_event_tx,
            discord_event_rx,
            sound_manager,
            shared_discord,
        }
    }

    /// Run the bridge coordinator (consumes self)
    pub async fn run(self) -> Result<()> {
        info!("Bridge coordinator started");

        // Shared notify: VoiceReceiver signals this on unexpected DriverDisconnect,
        // waking the health check loop immediately instead of waiting for the next tick.
        let health_check_notify = Arc::new(Notify::new());

        // Build shared context for per-call task handlers
        let ctx = BridgeContext {
            backend: self.backend.clone(),
            bridges: self.bridges.clone(),
            pending_bridges: self.pending_bridges.clone(),
            bridge_ready_notifiers: self.bridge_ready_notifiers.clone(),
            sip_calls: self.sip_calls.clone(),
            fax_sessions: self.fax_sessions.clone(),
            discord_event_tx: self.discord_event_tx.clone(),
            sip_cmd_tx: self.sip_cmd_tx.clone(),
            sound_manager: self.sound_manager.clone(),
            shared_discord: self.shared_discord.clone(),
            health_check_notify: health_check_notify.clone(),
        };

        // Clone what we need for the SIP event handler
        let backend_for_sip = ctx.backend.clone();
        let bridges = ctx.bridges.clone();
        let sip_calls = ctx.sip_calls.clone();
        let sip_cmd_tx = ctx.sip_cmd_tx.clone();
        let sip_event_rx = self.sip_event_rx.clone();
        let sound_manager = ctx.sound_manager.clone();
        let outbound_requests = self.outbound_requests.clone();

        let sip_handle = tokio::spawn(async move {
            let mut event_count: u64 = 0;
            loop {
                let Some(event) = poll_recv(&sip_event_rx, "SIP", &mut event_count).await else {
                    break;
                };

                match event {
                    SipEvent::IncomingCall {
                        call_id,
                        digest_auth,
                        extension,
                        source_ip,
                    } => {
                        info!(
                            "Incoming call {} from user={} to ext={} (IP: {:?})",
                            call_id, digest_auth.username, extension, source_ip
                        );

                        // Check for config-based extension sounds (easter eggs)
                        if let Ok(ext_num) = extension.parse::<u32>()
                            && let Some(sound_name) = sound_manager.get_extension_sound(ext_num)
                        {
                            info!(
                                "Extension {} maps to sound '{}' (call {})",
                                ext_num, sound_name, call_id
                            );

                            let sound_manager = sound_manager.clone();
                            let sip_cmd_tx = sip_cmd_tx.clone();
                            let sound_name = sound_name.to_string();

                            tokio::spawn(async move {
                                play_extension_sound_and_hangup(
                                    call_id,
                                    &sound_name,
                                    &sound_manager,
                                    &sip_cmd_tx,
                                )
                                .await;
                            });
                            continue;
                        }

                        // Track this call
                        sip_calls.insert(
                            call_id,
                            SipCallInfo {
                                channel_id: None,
                                _user_id: None,
                                _guild_id: None,
                                tracking_id: None,
                            },
                        );

                        // Verify auth with API and get channel info
                        let ctx = ctx.clone();

                        tokio::spawn(async move {
                            handle_incoming_call(ctx, call_id, *digest_auth, extension, source_ip)
                                .await;
                        });
                    }

                    SipEvent::CallEnded { call_id } => {
                        unregister_call_channel(call_id);
                        stop_loop(call_id);

                        // Check if this was a fax call — clean up fax session
                        // Fax calls skip on_call_ended (no "hung up" notification)
                        if let Some((_, (fax_session, cancel_token))) =
                            ctx.fax_sessions.remove(&call_id)
                        {
                            // Cancel the T.38 processing task (if running) before locking
                            cancel_token.cancel();

                            // Clean up fax audio port
                            crate::fax::audio_port::remove_fax_audio_port(call_id);

                            let mut session = fax_session.lock().await;
                            debug!(
                                "Fax call {} ended (channel={}, duration={:.1}s, audio={:.1}s)",
                                call_id,
                                session.text_channel_id,
                                session.created_at.elapsed().as_secs_f64(),
                                session.audio_duration_secs()
                            );
                            if !session.is_finished() {
                                // If we received at least one page, the fax data is in the TIFF.
                                // The remote may have hung up after sending all pages but before
                                // the T.30 phase E disconnect handshake completed — this is normal.
                                let pages = session.pages_received();
                                if pages > 0 {
                                    debug!(
                                        "Fax call {} ended with {} page(s) received, converting",
                                        call_id, pages
                                    );
                                    session.state = crate::fax::session::FaxState::Received;
                                    if let Err(e) = session.convert_and_post().await {
                                        error!(
                                            "Failed to convert/post fax for call {}: {}",
                                            call_id, e
                                        );
                                        session
                                            .post_failure("Failed to process received fax")
                                            .await;
                                    }
                                } else {
                                    session
                                        .post_failure("Caller hung up before fax completed")
                                        .await;
                                }
                            }
                            sip_calls.remove(&call_id);
                            continue;
                        }

                        // Voice call ended — notify backend ("hung up" notification)
                        let backend = backend_for_sip.clone();
                        let sip_call_id_str = call_id.to_string();
                        tokio::spawn(async move {
                            backend.on_call_ended(&sip_call_id_str).await;
                        });

                        if let Some((_, call_info)) = sip_calls.remove(&call_id)
                            && let Some(channel_id) = call_info.channel_id
                        {
                            let should_destroy = {
                                if let Some(mut bridge) = bridges.get_mut(&channel_id) {
                                    bridge.sip_calls.remove(&call_id);
                                    info!(
                                        "Removed call {} from bridge for channel {} ({} callers remaining)",
                                        call_id,
                                        channel_id,
                                        bridge.sip_calls.len()
                                    );
                                    bridge.sip_calls.is_empty()
                                } else {
                                    false
                                }
                            };

                            if should_destroy {
                                info!(
                                    "Last caller left, destroying bridge for channel {}",
                                    channel_id
                                );
                                cleanup_channel_port(channel_id);
                                teardown_channel_ring_buffers(channel_id);

                                if let Some((_, bridge)) = bridges.remove(&channel_id) {
                                    bridge.discord_connection.disconnect().await;
                                }
                            }
                        }
                    }

                    SipEvent::CallTimeout { call_id, rx_count } => {
                        warn!(
                            "Call {} timed out due to RTP inactivity (rx_count={}), forcing hangup",
                            call_id, rx_count
                        );

                        // If no audio was ever received, report no_audio to the coordinator
                        // so the Discord embed can show a diagnostic message
                        if rx_count == 0
                            && let Some(call_info) = sip_calls.get(&call_id)
                            && let Some(ref tracking_id) = call_info.tracking_id
                        {
                            info!(
                                "Call {} had zero RTP packets, reporting no_audio (tracking_id={})",
                                call_id, tracking_id
                            );
                            backend_for_sip.report_call_status(tracking_id, "no_audio");
                        }

                        let _ = sip_cmd_tx.send(SipCommand::Hangup { call_id });
                    }

                    SipEvent::OutboundCallAnswered {
                        tracking_id,
                        call_id,
                    } => {
                        info!(
                            "Outbound call answered: tracking_id={}, call_id={}",
                            tracking_id, call_id
                        );

                        // Check fork group: cancel sibling legs
                        if let Some(siblings) =
                            crate::transport::sip::fork_group::mark_answered(&tracking_id, call_id)
                        {
                            for sib_id in siblings {
                                info!(
                                    "Cancelling sibling fork leg: call_id={} (tracking_id={})",
                                    sib_id, tracking_id
                                );
                                // Remove from outbound tracking so its disconnect
                                // callback won't emit OutboundCallFailed
                                crate::transport::sip::remove_outbound_tracking(sib_id);
                                let _ = sip_cmd_tx.send(SipCommand::Hangup { call_id: sib_id });
                            }
                        }

                        backend_for_sip.report_call_status(&tracking_id, "answered");

                        let ctx = ctx.clone();
                        let outbound_requests = outbound_requests.clone();
                        tokio::spawn(async move {
                            handle_outbound_call_answered(
                                ctx,
                                outbound_requests,
                                tracking_id,
                                call_id,
                            )
                            .await;
                        });
                    }

                    SipEvent::OutboundCallFailed {
                        tracking_id,
                        call_id: failed_call_id,
                        reason,
                    } => {
                        warn!(
                            "Outbound call failed: tracking_id={}, call_id={:?}, reason={}",
                            tracking_id, failed_call_id, reason
                        );

                        // Check fork group: only report failure when ALL legs fail
                        let all_failed = if let Some(cid) = failed_call_id {
                            crate::transport::sip::fork_group::mark_failed(&tracking_id, cid)
                        } else {
                            // No call_id means it never started - check if this was a single-contact call
                            true
                        };

                        if all_failed {
                            info!(
                                "All fork legs failed for tracking_id={}, reporting failure",
                                tracking_id
                            );
                            outbound_requests.remove(&tracking_id);
                            backend_for_sip.report_call_status(&tracking_id, "failed");
                        } else {
                            debug!(
                                "Fork leg failed but other legs still active for tracking_id={}",
                                tracking_id
                            );
                        }
                    }

                    SipEvent::T38Offered {
                        call_id,
                        remote_ip,
                        remote_port,
                        t38_version,
                        max_bit_rate,
                        rate_management,
                        udp_ec,
                        local_port,
                    } => {
                        info!(
                            "T.38 re-INVITE for call {}: remote={}:{}, local_port={}, version={}, rate={}bps, mgmt={}, ec={}",
                            call_id,
                            remote_ip,
                            remote_port,
                            local_port,
                            t38_version,
                            max_bit_rate,
                            rate_management,
                            udp_ec
                        );

                        // Check if this call has a fax session
                        if let Some(entry) = ctx.fax_sessions.get(&call_id) {
                            let (fax_session, cancel_token) = entry.value();
                            let fax_session = fax_session.clone();
                            let cancel_token = cancel_token.clone();
                            let sip_cmd_tx = sip_cmd_tx.clone();

                            tokio::spawn(async move {
                                handle_t38_switch(
                                    call_id,
                                    remote_ip,
                                    remote_port,
                                    local_port,
                                    fax_session,
                                    cancel_token,
                                    sip_cmd_tx,
                                )
                                .await;
                            });
                        } else {
                            warn!(
                                "T.38 re-INVITE for call {} but no fax session — rejecting",
                                call_id
                            );
                            // Hang up since we can't handle T.38 without a fax session
                            let _ = sip_cmd_tx.send(SipCommand::Hangup { call_id });
                        }
                    }
                }
            }
        });

        // Handle outbound call requests from the backend
        let outbound_backend = self.backend.clone();
        let outbound_sip_cmd_tx = self.sip_cmd_tx.clone();
        let outbound_registrar = crate::services::registrar::GLOBAL_REGISTRAR.get().cloned();
        let outbound_requests_for_handler = self.outbound_requests.clone();

        let outbound_handle = tokio::spawn(async move {
            while let Some(req) = outbound_backend.next_outbound_request().await {
                info!(
                    "Processing outbound call request: call_id={}, user={}",
                    req.call_id, req.discord_username
                );

                // Look up the user's SIP contact from the registrar
                let contacts = if let Some(ref registrar) = outbound_registrar {
                    registrar.get_contacts_for_discord_user(&req.discord_username)
                } else {
                    Vec::new()
                };

                if contacts.is_empty() {
                    warn!(
                        "No SIP contacts for user {} (call_id={})",
                        req.discord_username, req.call_id
                    );
                    outbound_backend.report_call_status(&req.call_id, "failed");
                    continue;
                }

                // Store the request so handle_outbound_call_answered can retrieve it
                outbound_requests_for_handler.insert(req.call_id.clone(), req.clone());

                let fork_total = contacts.len();
                info!(
                    "Forking outbound call to {} contacts for user {} (call_id={})",
                    fork_total, req.discord_username, req.call_id
                );

                // Ring ALL registered contacts simultaneously
                for (contact_uri, source_addr, transport) in &contacts {
                    // Extract the user part from the Contact URI (e.g., "sip:3001@10.0.1.151:5060" -> "3001")
                    // The contact_uri has the correct SIP username/extension; source_addr is the NAT'd public address
                    let user_part = contact_uri
                        .strip_prefix("sip:")
                        .or_else(|| contact_uri.strip_prefix("sips:"))
                        .and_then(|rest| rest.split('@').next())
                        .unwrap_or(&req.discord_username);

                    let sip_uri = match transport {
                        crate::services::registrar::SipTransport::Tls => {
                            format!("sips:{}@{}", user_part, source_addr)
                        }
                        crate::services::registrar::SipTransport::Tcp => {
                            format!("sip:{}@{};transport=tcp", user_part, source_addr)
                        }
                        crate::services::registrar::SipTransport::Udp => {
                            format!("sip:{}@{};transport=udp", user_part, source_addr)
                        }
                    };

                    let _ = outbound_sip_cmd_tx.send(SipCommand::MakeOutboundCall {
                        tracking_id: req.call_id.clone(),
                        sip_uri,
                        caller_display_name: Some(req.caller_username.clone()),
                        fork_total,
                    });
                }

                outbound_backend.report_call_status(&req.call_id, "ringing");
            }
        });

        // Handle Discord events
        let discord_event_rx = self.discord_event_rx.clone();

        let discord_handle = tokio::spawn(async move {
            let mut event_count: u64 = 0;
            loop {
                let Some(event) = poll_recv(&discord_event_rx, "Discord", &mut event_count).await
                else {
                    break;
                };

                match event {
                    DiscordEvent::VoiceConnected {
                        bridge_id,
                        guild_id,
                        channel_id,
                    } => {
                        info!(
                            "Discord voice connected: bridge={}, guild={}, channel={}",
                            bridge_id, guild_id, channel_id
                        );
                    }

                    DiscordEvent::VoiceDisconnected { bridge_id } => {
                        debug!("Discord voice disconnected: bridge={}", bridge_id);
                    }
                }
            }
        });

        // Health check task
        let bridges = self.bridges.clone();
        let pending_bridges = self.pending_bridges.clone();
        let bridge_ready_notifiers = self.bridge_ready_notifiers.clone();
        let discord_event_tx = self.discord_event_tx.clone();
        let backend_for_health = self.backend.clone();
        let sip_calls_for_health = self.sip_calls.clone();
        let shared_discord_for_health = self.shared_discord.clone();
        let outbound_requests_for_health = self.outbound_requests.clone();
        let sip_cmd_tx_for_health = self.sip_cmd_tx.clone();

        let health_check_notify_for_loop = health_check_notify.clone();
        let health_check_handle = tokio::spawn(async move {
            let mut check_count: u64 = 0;
            loop {
                let interval = crate::config::AppConfig::bridge().health_check_interval_secs;
                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_secs(interval)) => {},
                    _ = health_check_notify_for_loop.notified() => {
                        info!("Health check woken early by driver disconnect");
                    },
                }
                check_count += 1;

                // Sweep stale outbound requests (leaked if fork group never resolves)
                let before = outbound_requests_for_health.len();
                outbound_requests_for_health
                    .retain(|_, req| req.created_at.elapsed() < Duration::from_secs(60));
                let swept = before - outbound_requests_for_health.len();
                if swept > 0 {
                    warn!("Swept {} stale outbound requests (>60s old)", swept);
                }

                let active_channel_ids: Vec<String> = bridges
                    .iter()
                    .map(|entry| entry.key().to_string())
                    .collect();

                if !active_channel_ids.is_empty() {
                    let backend = backend_for_health.clone();
                    tokio::spawn(async move {
                        backend.heartbeat(&active_channel_ids).await;
                    });
                }

                let bridge_cfg = crate::config::AppConfig::bridge();

                // Collect unhealthy bridges with their reconnection state
                // Tuple: (channel_id, guild_id, bridge_id, prev_attempts, prev_reconnect_at)
                let mut unhealthy_bridges: Vec<(
                    Snowflake,
                    Snowflake,
                    String,
                    u32,
                    Option<Instant>,
                )> = Vec::new();
                // Bridges that exceeded max reconnection attempts — tear them down
                let mut exhausted_bridges: Vec<Snowflake> = Vec::new();

                for entry in bridges.iter() {
                    let channel_id = *entry.key();
                    let bridge = entry.value();

                    let is_healthy = bridge.discord_connection.is_healthy();
                    let queue_fill = bridge.discord_connection.queue_fill_percent();
                    let consecutive_overflows = bridge.discord_connection.consecutive_overflows();

                    if check_count.is_multiple_of(12) {
                        info!(
                            "Health check #{}: channel={}, healthy={}, queue={}%, overflows={}, reconnects={}",
                            check_count,
                            channel_id,
                            is_healthy,
                            queue_fill,
                            consecutive_overflows,
                            bridge.reconnect_attempts
                        );
                    }

                    let needs_reconnect =
                        !is_healthy || (queue_fill > 90 && consecutive_overflows > 50);

                    if needs_reconnect {
                        // Cooldown: skip if bridge was created/reconnected too recently
                        let age_secs = bridge.created_at.elapsed().as_secs();
                        if age_secs < bridge_cfg.reconnect_min_age_secs {
                            debug!(
                                "Bridge for channel {} is unhealthy but too young ({}s < {}s cooldown), skipping",
                                channel_id, age_secs, bridge_cfg.reconnect_min_age_secs
                            );
                            continue;
                        }

                        // Max attempts: if exceeded, tear down instead of reconnecting
                        if bridge.reconnect_attempts >= bridge_cfg.reconnect_max_attempts {
                            error!(
                                "Bridge for channel {} exceeded max reconnection attempts ({}/{}), tearing down",
                                channel_id,
                                bridge.reconnect_attempts,
                                bridge_cfg.reconnect_max_attempts
                            );
                            exhausted_bridges.push(channel_id);
                            continue;
                        }

                        // Exponential backoff: check if enough time has passed since last reconnect
                        if let Some(last_reconnect) = bridge.last_reconnect_at {
                            let backoff_secs = bridge_cfg.reconnect_base_delay_secs
                                * 2u64.saturating_pow(bridge.reconnect_attempts.saturating_sub(1));
                            let backoff_secs =
                                backoff_secs.min(bridge_cfg.reconnect_max_delay_secs);
                            let elapsed = last_reconnect.elapsed().as_secs();
                            if elapsed < backoff_secs {
                                debug!(
                                    "Bridge for channel {} is unhealthy but in backoff ({}s < {}s), skipping",
                                    channel_id, elapsed, backoff_secs
                                );
                                continue;
                            }
                        }

                        warn!(
                            "Bridge for channel {} is UNHEALTHY (attempt {}/{})",
                            channel_id,
                            bridge.reconnect_attempts + 1,
                            bridge_cfg.reconnect_max_attempts
                        );
                        unhealthy_bridges.push((
                            channel_id,
                            bridge.guild_id,
                            bridge.discord_connection.bridge_id().to_string(),
                            bridge.reconnect_attempts,
                            bridge.last_reconnect_at,
                        ));
                    }
                }

                // Tear down bridges that exhausted reconnection attempts
                for channel_id in exhausted_bridges {
                    if let Some((_, bridge)) = bridges.remove(&channel_id) {
                        let orphaned_count = bridge.sip_calls.len();
                        error!(
                            "Destroying bridge for channel {} after {} failed reconnection attempts — hanging up {} orphaned calls",
                            channel_id, bridge.reconnect_attempts, orphaned_count
                        );
                        // Hang up all SIP calls that were on this bridge
                        for &orphaned_call_id in &bridge.sip_calls {
                            warn!(
                                "Hanging up orphaned call {} (bridge for channel {} exhausted reconnects)",
                                orphaned_call_id, channel_id
                            );
                            let _ = sip_cmd_tx_for_health.send(SipCommand::Hangup {
                                call_id: orphaned_call_id,
                            });
                        }
                        cleanup_channel_port(channel_id);
                        teardown_channel_ring_buffers(channel_id);
                        bridge.discord_connection.disconnect().await;
                    }
                }

                // Check for orphaned bridges (no SIP calls for grace period)
                let mut orphaned_bridges: Vec<Snowflake> = Vec::new();
                for entry in bridges.iter() {
                    let channel_id = *entry.key();
                    let bridge = entry.value();

                    if bridge.sip_calls.is_empty() {
                        let empty_duration = bridge.last_call_time.elapsed().as_secs();
                        if empty_duration > empty_bridge_grace_period_secs() {
                            warn!(
                                "Bridge for channel {} has no SIP calls for {}s, marking for cleanup",
                                channel_id, empty_duration
                            );
                            orphaned_bridges.push(channel_id);
                        }
                    } else {
                        // Cross-reference: bridge has sip_calls entries, but do any
                        // of them actually exist in the coordinator's sip_calls map?
                        // If none exist, the entries are stale (calls ended without cleanup).
                        let any_call_exists = bridge
                            .sip_calls
                            .iter()
                            .any(|call_id| sip_calls_for_health.contains_key(call_id));

                        if !any_call_exists
                            && bridge.last_call_time.elapsed().as_secs() > 30
                            && bridge.created_at.elapsed().as_secs() > 60
                        {
                            warn!(
                                "Bridge for channel {} has {} stale sip_calls entries (none exist in coordinator), \
                                 last_call={}s ago, age={}s — marking for cleanup",
                                channel_id,
                                bridge.sip_calls.len(),
                                bridge.last_call_time.elapsed().as_secs(),
                                bridge.created_at.elapsed().as_secs(),
                            );
                            orphaned_bridges.push(channel_id);
                        }
                    }
                }

                // Destroy orphaned bridges
                for channel_id in orphaned_bridges {
                    if let Some((_, bridge)) = bridges.remove(&channel_id) {
                        info!(
                            "Destroying orphaned bridge for channel {} (no SIP calls)",
                            channel_id
                        );
                        cleanup_channel_port(channel_id);
                        teardown_channel_ring_buffers(channel_id);
                        bridge.discord_connection.disconnect().await;
                    }
                }

                // Rate limit: cap reconnections per cycle
                let max_per_cycle = bridge_cfg.reconnect_max_per_cycle;
                if unhealthy_bridges.len() > max_per_cycle {
                    warn!(
                        "Rate limiting reconnections: {} unhealthy bridges but only processing {} per cycle",
                        unhealthy_bridges.len(),
                        max_per_cycle
                    );
                    unhealthy_bridges.truncate(max_per_cycle);
                }

                for (channel_id, guild_id, bridge_id, prev_attempts, _prev_reconnect_at) in
                    unhealthy_bridges
                {
                    if pending_bridges.contains(&channel_id) {
                        continue;
                    }

                    let attempt_num = prev_attempts + 1;
                    warn!(
                        "Attempting reconnection for unhealthy bridge {} (channel {}, attempt {}/{})",
                        bridge_id, channel_id, attempt_num, bridge_cfg.reconnect_max_attempts
                    );
                    pending_bridges.insert(channel_id);

                    if let Some((_, old_bridge)) = bridges.remove(&channel_id) {
                        let sip_calls = old_bridge.sip_calls.clone();
                        let bot_token = old_bridge.bot_token.clone();
                        let old_last_call_time = old_bridge.last_call_time;
                        teardown_channel_ring_buffers(channel_id);
                        old_bridge.discord_connection.disconnect().await;

                        let new_bridge_id = format!("bridge_{}", channel_id);
                        match DiscordVoiceConnection::connect(
                            new_bridge_id.clone(),
                            &shared_discord_for_health,
                            guild_id,
                            channel_id,
                            discord_event_tx.clone(),
                            health_check_notify_for_loop.clone(),
                        )
                        .await
                        {
                            Ok(new_connection) => {
                                info!(
                                    "Successfully reconnected bridge {} for channel {} (attempt {}/{})",
                                    new_bridge_id,
                                    channel_id,
                                    attempt_num,
                                    bridge_cfg.reconnect_max_attempts
                                );
                                // Set up fresh ring buffers for reconnected channel
                                setup_channel_ring_buffers(channel_id);
                                bridges.insert(
                                    channel_id,
                                    ChannelBridge {
                                        guild_id,
                                        discord_connection: new_connection,
                                        sip_calls: sip_calls.clone(),
                                        bot_token,
                                        last_call_time: old_last_call_time,
                                        created_at: Instant::now(),
                                        reconnect_attempts: attempt_num,
                                        last_reconnect_at: Some(Instant::now()),
                                    },
                                );

                                // Cross-reference carried-over sip_calls against the
                                // coordinator's sip_calls map. If CallEnded fired while
                                // the bridge was removed from the DashMap, entries will
                                // be stale — remove them now.
                                if let Some(mut bridge) = bridges.get_mut(&channel_id) {
                                    let stale: Vec<CallId> = bridge
                                        .sip_calls
                                        .iter()
                                        .filter(|id| !sip_calls_for_health.contains_key(id))
                                        .copied()
                                        .collect();
                                    for id in &stale {
                                        bridge.sip_calls.remove(id);
                                    }
                                    if !stale.is_empty() {
                                        warn!(
                                            "Removed {} stale sip_calls from reconnected bridge {}: {:?}",
                                            stale.len(),
                                            channel_id,
                                            stale
                                        );
                                    }
                                }
                            }
                            Err(e) => {
                                error!(
                                    "Failed to reconnect bridge for channel {} (attempt {}/{}): {}. \
                                     Bridge removed — {} SIP calls orphaned.",
                                    channel_id,
                                    attempt_num,
                                    bridge_cfg.reconnect_max_attempts,
                                    e,
                                    sip_calls.len()
                                );
                                // Re-insert the bridge entry (without connection) so calls
                                // aren't silently orphaned — the next health check cycle
                                // will either retry or tear down after max attempts.
                                // Since we can't re-insert without a connection, clean up
                                // the channel port so calls can detect the loss.
                                cleanup_channel_port(channel_id);
                            }
                        }

                        pending_bridges.remove(&channel_id);
                        notify_bridge_ready(&bridge_ready_notifiers, channel_id);
                    }
                }
            }
        });

        tokio::select! {
            _ = sip_handle => { info!("SIP event handler finished"); }
            _ = discord_handle => { info!("Discord event handler finished"); }
            _ = health_check_handle => { info!("Health check handler finished"); }
            _ = outbound_handle => { info!("Outbound call handler finished"); }
        }

        Ok(())
    }
}

/// Handle an incoming authenticated call
async fn handle_incoming_call(
    ctx: BridgeContext,
    call_id: CallId,
    digest_auth: crate::transport::sip::DigestAuthParams,
    extension: String,
    source_ip: Option<std::net::IpAddr>,
) {
    let BridgeContext {
        backend,
        bridges,
        pending_bridges,
        bridge_ready_notifiers,
        sip_calls,
        fax_sessions,
        discord_event_tx,
        sip_cmd_tx,
        sound_manager,
        shared_discord,
        health_check_notify,
    } = ctx;
    // Route the call via the backend FIRST to determine call type
    let decision = backend.route_call(&digest_auth, &extension).await;

    // For non-fax calls: send 183 Session Progress and play connecting sound
    let is_fax = matches!(decision, RouteDecision::ConnectFax { .. });
    if !is_fax {
        let _ = sip_cmd_tx.send(SipCommand::Send183 { call_id });
        tokio::time::sleep(Duration::from_millis(100)).await;

        if let Some(connecting_samples) = sound_manager.get_connecting_samples() {
            let _ = sip_cmd_tx.send(SipCommand::StartConnectingLoop {
                call_id,
                samples: (*connecting_samples).clone(),
            });
        } else {
            warn!("No connecting sound configured - caller will hear silence during setup");
        }
    }

    match decision {
        RouteDecision::Redirect { domain, extension } => {
            info!("Call {} needs redirect to {}", call_id, domain);
            let _ = sip_cmd_tx.send(SipCommand::Redirect {
                call_id,
                domain,
                extension,
            });
            sip_calls.remove(&call_id);
        }

        RouteDecision::RejectInvalidCredentials => {
            warn!(
                "Invalid credentials for call {} (IP: {:?}) - hanging up",
                call_id, source_ip
            );
            let _ = sip_cmd_tx.send(SipCommand::Hangup { call_id });
            sip_calls.remove(&call_id);
        }

        RouteDecision::RejectWithError { error } => {
            error!("Call {} rejected: {:?}", call_id, error);
            play_error_and_hangup(call_id, error, &sound_manager, &sip_cmd_tx).await;
            sip_calls.remove(&call_id);
        }

        RouteDecision::ConnectFax {
            text_channel_id,
            guild_id,
            user_id,
            bot_token,
        } => {
            debug!(
                "Fax route decision for call {}: text_channel={}, guild={}, user={}",
                call_id, text_channel_id, guild_id, user_id
            );

            // Fax calls: answer the SIP call but DON'T connect to Discord voice.
            // Instead, create a FaxSession that will receive audio and post to Discord text channel.

            let mut fax_session = match FaxSession::new(
                call_id,
                text_channel_id,
                guild_id,
                user_id.clone(),
                bot_token,
            ) {
                Ok(session) => session,
                Err(e) => {
                    error!("Failed to create fax session for call {}: {}", call_id, e);
                    let _ = sip_cmd_tx.send(SipCommand::Hangup { call_id });
                    sip_calls.remove(&call_id);
                    return;
                }
            };

            // Answer the call to establish audio path
            let _ = sip_cmd_tx.send(SipCommand::Answer { call_id });

            // Post "Receiving fax..." message to Discord
            if let Err(e) = fax_session.post_receiving_message().await {
                error!("Failed to post fax receiving message: {}", e);
                let _ = sip_cmd_tx.send(SipCommand::Hangup { call_id });
                sip_calls.remove(&call_id);
                return;
            }

            // Store fax session with cancellation token for T.38 task shutdown
            let fax_session = Arc::new(tokio::sync::Mutex::new(fax_session));
            let cancel_token = CancellationToken::new();
            fax_sessions.insert(call_id, (fax_session.clone(), cancel_token));

            // Wait briefly for PJSUA to establish media (conf_port assignment)
            tokio::time::sleep(Duration::from_millis(500)).await;

            // Create bidirectional fax audio port
            let audio_ports = crate::fax::audio_port::create_fax_audio_port(call_id).await;
            if audio_ports.is_none() {
                warn!(
                    "Could not create fax audio port for call {} — media may not be ready yet. \
                     Will retry when media becomes active.",
                    call_id
                );
            }

            // Spawn fax audio processing task
            let fax_session_clone = fax_session.clone();
            let sip_cmd_tx_clone = sip_cmd_tx.clone();
            tokio::spawn(async move {
                process_fax_audio(call_id, fax_session_clone, audio_ports, sip_cmd_tx_clone).await;
            });

            debug!(
                "Fax session created for call {} -> text channel {}",
                call_id, text_channel_id
            );

            // NOTE: No on_call_started notification for fax calls — the "called in" / "hung up"
            // Discord embeds are only relevant for voice calls. Fax has its own notifications.
        }

        RouteDecision::Connect {
            channel_id,
            guild_id,
            user_id,
            bot_token,
        } => {
            info!(
                "Route decision for call {}: channel={}, guild={}, user={}",
                call_id, channel_id, guild_id, user_id
            );

            // Check if bot is already connected to a DIFFERENT channel in the SAME guild
            // Discord bots can only be in one voice channel per guild
            let mut conflicting_channel: Option<Snowflake> = None;
            for entry in bridges.iter() {
                let existing_channel_id = *entry.key();
                let existing_bridge = entry.value();

                if existing_bridge.guild_id == guild_id && existing_channel_id != channel_id {
                    conflicting_channel = Some(existing_channel_id);
                    break;
                }
            }

            if let Some(existing_channel_id) = conflicting_channel {
                warn!(
                    "Guild {} already has active bridge to channel {} (call {} tried to join channel {})",
                    guild_id, existing_channel_id, call_id, channel_id
                );
                play_error_and_hangup(call_id, CallError::ServerBusy, &sound_manager, &sip_cmd_tx)
                    .await;
                sip_calls.remove(&call_id);
                return;
            }

            // Check if bridge already exists
            let bridge_exists = bridges.contains_key(&channel_id);
            let bridge_pending = pending_bridges.contains(&channel_id);

            if bridge_pending && !bridge_exists {
                info!(
                    "Call {} waiting for pending bridge for channel {}",
                    call_id, channel_id
                );

                // Get or create a Notify for this channel (zero-cost when not waiting)
                let notify = bridge_ready_notifiers
                    .entry(channel_id)
                    .or_insert_with(|| Arc::new(Notify::new()))
                    .clone();

                // Wait for notification with timeout (instant wake-up when bridge is ready)
                let wait_result = tokio::time::timeout(Duration::from_secs(15), async {
                    loop {
                        // Check if bridge is ready or pending cleared
                        if bridges.contains_key(&channel_id)
                            || !pending_bridges.contains(&channel_id)
                        {
                            return true;
                        }
                        // Check if call ended while waiting
                        if !sip_calls.contains_key(&call_id) {
                            return false;
                        }
                        notify.notified().await;
                    }
                })
                .await;

                match wait_result {
                    Ok(true) => {
                        info!(
                            "Call {} finished waiting, bridge ready for channel {}",
                            call_id, channel_id
                        );
                    }
                    Ok(false) => {
                        warn!("Call {} ended while waiting for pending bridge", call_id);
                        return;
                    }
                    Err(_) => {
                        error!(
                            "Timeout waiting for pending bridge for channel {} (call {})",
                            channel_id, call_id
                        );
                        play_error_and_hangup(
                            call_id,
                            CallError::Unknown,
                            &sound_manager,
                            &sip_cmd_tx,
                        )
                        .await;
                        sip_calls.remove(&call_id);
                        return;
                    }
                }
            }

            let bridge_exists = bridges.contains_key(&channel_id);

            if bridge_exists {
                // Join existing bridge
                if !sip_calls.contains_key(&call_id) {
                    warn!("Call {} ended during routing, not joining bridge", call_id);
                    return;
                }

                info!(
                    "Call {} joining existing bridge for channel {}",
                    call_id, channel_id
                );

                if let Some(mut call) = sip_calls.get_mut(&call_id) {
                    call.channel_id = Some(channel_id);
                    call._user_id = Some(user_id.clone());
                    call._guild_id = Some(guild_id);
                }

                if let Some(mut bridge) = bridges.get_mut(&channel_id) {
                    bridge.sip_calls.insert(call_id);
                    bridge.last_call_time = Instant::now();
                    info!(
                        "Bridge for channel {} now has {} callers",
                        channel_id,
                        bridge.sip_calls.len()
                    );
                }

                register_call_channel(call_id, channel_id);

                // Notify backend
                let backend = backend.clone();
                let info = CallStartedInfo {
                    sip_call_id: call_id.to_string(),
                    user_id: user_id.clone(),
                    guild_id: guild_id.to_string(),
                    channel_id: channel_id.to_string(),
                    extension: extension.clone(),
                };
                tokio::spawn(async move {
                    backend.on_call_started(&info).await;
                });

                // Answer call first, then play join sound
                let _ = sip_cmd_tx.send(SipCommand::Answer { call_id });
                play_discord_join(call_id, &sound_manager, &sip_cmd_tx).await;
            } else {
                // Create new bridge
                if !sip_calls.contains_key(&call_id) {
                    warn!("Call {} ended during routing, not creating bridge", call_id);
                    return;
                }

                pending_bridges.insert(channel_id);
                info!(
                    "Creating new bridge for channel {} (call {})",
                    channel_id, call_id
                );

                let bridge_id = format!("bridge_{}", channel_id);
                match DiscordVoiceConnection::connect(
                    bridge_id.clone(),
                    &shared_discord,
                    guild_id,
                    channel_id,
                    discord_event_tx.clone(),
                    health_check_notify.clone(),
                )
                .await
                {
                    Ok(connection) => {
                        if !sip_calls.contains_key(&call_id) {
                            warn!("Call {} ended while connecting to Discord", call_id);
                            connection.disconnect().await;
                            pending_bridges.remove(&channel_id);
                            notify_bridge_ready(&bridge_ready_notifiers, channel_id);
                            return;
                        }

                        info!("Discord connection established for channel {}", channel_id);

                        // Set up Discord→SIP ring buffers for this channel
                        setup_channel_ring_buffers(channel_id);

                        let mut sip_calls_set = HashSet::new();
                        sip_calls_set.insert(call_id);

                        bridges.insert(
                            channel_id,
                            ChannelBridge {
                                guild_id,
                                discord_connection: connection,
                                sip_calls: sip_calls_set,
                                bot_token: bot_token.clone(),
                                last_call_time: Instant::now(),
                                created_at: Instant::now(),
                                reconnect_attempts: 0,
                                last_reconnect_at: None,
                            },
                        );

                        pending_bridges.remove(&channel_id);
                        notify_bridge_ready(&bridge_ready_notifiers, channel_id);

                        if let Some(mut call) = sip_calls.get_mut(&call_id) {
                            call.channel_id = Some(channel_id);
                            call._user_id = Some(user_id.clone());
                            call._guild_id = Some(guild_id);
                        }

                        register_call_channel(call_id, channel_id);

                        // Notify backend
                        let backend = backend.clone();
                        let info = CallStartedInfo {
                            sip_call_id: call_id.to_string(),
                            user_id: user_id.clone(),
                            guild_id: guild_id.to_string(),
                            channel_id: channel_id.to_string(),
                            extension: extension.clone(),
                        };
                        tokio::spawn(async move {
                            backend.on_call_started(&info).await;
                        });

                        // Answer call first, then play join sound
                        let _ = sip_cmd_tx.send(SipCommand::Answer { call_id });
                        play_discord_join(call_id, &sound_manager, &sip_cmd_tx).await;
                    }
                    Err(e) => {
                        pending_bridges.remove(&channel_id);
                        notify_bridge_ready(&bridge_ready_notifiers, channel_id);
                        error!("Failed to connect to Discord for call {}: {}", call_id, e);

                        play_error_and_hangup(
                            call_id,
                            CallError::Unknown,
                            &sound_manager,
                            &sip_cmd_tx,
                        )
                        .await;
                        sip_calls.remove(&call_id);
                    }
                }
            }
        }
    }
}

/// Handle an outbound call that was answered (phone picked up)
///
/// This mirrors handle_incoming_call but skips authentication (already done by the DO)
/// and doesn't need 183/Answer (the SIP call is already established).
async fn handle_outbound_call_answered(
    ctx: BridgeContext,
    outbound_requests: Arc<DashMap<String, OutboundCallRequest>>,
    tracking_id: String,
    call_id: CallId,
) {
    let BridgeContext {
        backend,
        bridges,
        pending_bridges,
        bridge_ready_notifiers,
        sip_calls,
        fax_sessions: _,
        discord_event_tx,
        sip_cmd_tx,
        sound_manager,
        shared_discord,
        health_check_notify,
    } = ctx;

    // Step 1: Retrieve and consume the stored outbound request
    let req = match outbound_requests.remove(&tracking_id) {
        Some((_, req)) => req,
        None => {
            error!(
                "No stored outbound request for tracking_id={} (call {})",
                tracking_id, call_id
            );
            let _ = sip_cmd_tx.send(SipCommand::Hangup { call_id });
            return;
        }
    };

    // Step 2: Parse guild_id and channel_id
    let guild_id: Snowflake = match req.guild_id.parse() {
        Ok(id) => id,
        Err(e) => {
            error!(
                "Invalid guild_id '{}' in outbound request: {}",
                req.guild_id, e
            );
            backend.report_call_status(&req.call_id, "failed");
            let _ = sip_cmd_tx.send(SipCommand::Hangup { call_id });
            return;
        }
    };
    let channel_id: Snowflake = match req.channel_id.parse() {
        Ok(id) => id,
        Err(e) => {
            error!(
                "Invalid channel_id '{}' in outbound request: {}",
                req.channel_id, e
            );
            backend.report_call_status(&req.call_id, "failed");
            let _ = sip_cmd_tx.send(SipCommand::Hangup { call_id });
            return;
        }
    };

    info!(
        "Outbound call {} answered, connecting to Discord: guild={}, channel={}",
        call_id, guild_id, channel_id
    );

    // Step 3: Track the SIP call
    sip_calls.insert(
        call_id,
        SipCallInfo {
            channel_id: None,
            _user_id: None,
            _guild_id: Some(guild_id),
            tracking_id: Some(tracking_id.clone()),
        },
    );

    // Step 4: Play connecting sound loop
    if let Some(connecting_samples) = sound_manager.get_connecting_samples() {
        let _ = sip_cmd_tx.send(SipCommand::StartConnectingLoop {
            call_id,
            samples: (*connecting_samples).clone(),
        });
    }

    // Step 5: Check for guild conflict (bot already active in this guild)
    // For outbound calls, don't try to override the bot if it's already connected
    // to any channel in this guild (whether same or different channel).
    let mut conflicting_channel: Option<Snowflake> = None;
    for entry in bridges.iter() {
        let existing_channel_id = *entry.key();
        let existing_bridge = entry.value();

        if existing_bridge.guild_id == guild_id {
            conflicting_channel = Some(existing_channel_id);
            break;
        }
    }
    // Also check pending bridges (bridge creation in progress)
    if conflicting_channel.is_none() && pending_bridges.contains(&channel_id) {
        conflicting_channel = Some(channel_id);
    }

    if let Some(existing_channel_id) = conflicting_channel {
        warn!(
            "Guild {} already has active bridge to channel {} (outbound call {} tried channel {})",
            guild_id, existing_channel_id, call_id, channel_id
        );
        backend.report_call_status(&req.call_id, "failed");
        let _ = sip_cmd_tx.send(SipCommand::Hangup { call_id });
        sip_calls.remove(&call_id);
        return;
    }

    // Step 6: Create new bridge (no existing bridge in this guild — checked above)
    {
        pending_bridges.insert(channel_id);
        info!(
            "Creating new bridge for channel {} (outbound call {})",
            channel_id, call_id
        );

        let bridge_id = format!("bridge_{}", channel_id);
        match DiscordVoiceConnection::connect(
            bridge_id.clone(),
            &shared_discord,
            guild_id,
            channel_id,
            discord_event_tx.clone(),
            health_check_notify.clone(),
        )
        .await
        {
            Ok(connection) => {
                if !sip_calls.contains_key(&call_id) {
                    warn!(
                        "Outbound call {} ended while connecting to Discord",
                        call_id
                    );
                    connection.disconnect().await;
                    pending_bridges.remove(&channel_id);
                    notify_bridge_ready(&bridge_ready_notifiers, channel_id);
                    return;
                }

                info!(
                    "Discord connection established for channel {} (outbound call {})",
                    channel_id, call_id
                );

                // Set up Discord→SIP ring buffers for this channel
                setup_channel_ring_buffers(channel_id);

                let mut sip_calls_set = HashSet::new();
                sip_calls_set.insert(call_id);

                bridges.insert(
                    channel_id,
                    ChannelBridge {
                        guild_id,
                        discord_connection: connection,
                        sip_calls: sip_calls_set,
                        bot_token: req.bot_token.clone(),
                        last_call_time: Instant::now(),
                        created_at: Instant::now(),
                        reconnect_attempts: 0,
                        last_reconnect_at: None,
                    },
                );

                pending_bridges.remove(&channel_id);
                notify_bridge_ready(&bridge_ready_notifiers, channel_id);

                if let Some(mut call) = sip_calls.get_mut(&call_id) {
                    call.channel_id = Some(channel_id);
                    call._guild_id = Some(guild_id);
                }

                register_call_channel(call_id, channel_id);
                play_discord_join(call_id, &sound_manager, &sip_cmd_tx).await;
            }
            Err(e) => {
                pending_bridges.remove(&channel_id);
                notify_bridge_ready(&bridge_ready_notifiers, channel_id);
                error!(
                    "Failed to connect to Discord for outbound call {}: {}",
                    call_id, e
                );
                backend.report_call_status(&req.call_id, "failed");
                let _ = sip_cmd_tx.send(SipCommand::Hangup { call_id });
                sip_calls.remove(&call_id);
            }
        }
    }
}

/// Play the discord join sound
async fn play_discord_join(
    call_id: CallId,
    sound_manager: &SoundManager,
    sip_cmd_tx: &Sender<SipCommand>,
) {
    if let Some(samples) = sound_manager.get_discord_join_samples() {
        info!("Playing Discord join sound for call {}", call_id);
        let _ = sip_cmd_tx.send(SipCommand::PlayDirectToCall {
            call_id,
            samples: (*samples).clone(),
        });
    } else {
        warn!("No discord_join sound configured");
    }
}

/// Play an error sound and hangup
async fn play_error_and_hangup(
    call_id: CallId,
    error: CallError,
    sound_manager: &SoundManager,
    sip_cmd_tx: &Sender<SipCommand>,
) {
    info!("Playing error audio for call {}: {:?}", call_id, error);

    // The call was already answered with 183, so we can play audio
    // Send 200 OK to fully answer before playing error
    let _ = sip_cmd_tx.send(SipCommand::Answer { call_id });
    tokio::time::sleep(Duration::from_millis(200)).await;

    if let Some(samples) = sound_manager.get_error_samples(error.sound_name()) {
        let _ = sip_cmd_tx.send(SipCommand::PlayDirectToCall {
            call_id,
            samples: (*samples).clone(),
        });

        // Wait for playback
        let duration_ms = (samples.len() as u64 * 1000) / CONF_SAMPLE_RATE as u64;
        tokio::time::sleep(Duration::from_millis(duration_ms + 200)).await;
    } else {
        warn!("No error sound '{}' configured", error.sound_name());
    }

    info!("Hanging up call {} after error audio", call_id);
    let _ = sip_cmd_tx.send(SipCommand::Hangup { call_id });
}

/// Play an extension-based sound (easter egg) and hangup
///
/// For streaming sounds (large files), this uses the port-based pull model
/// which provides precise timing controlled by the audio thread. The hangup
/// is handled automatically when playback completes.
///
/// For test tones, this plays a 440Hz sine wave until the caller hangs up.
async fn play_extension_sound_and_hangup(
    call_id: CallId,
    sound_name: &str,
    sound_manager: &SoundManager,
    sip_cmd_tx: &Sender<SipCommand>,
) {
    info!(
        "Playing extension sound '{}' for call {}",
        sound_name, call_id
    );

    // Answer the call first
    // NOTE: Previously had 200ms delay here which caused RTP timestamp debt
    // and initial burst of packets. Now we start streaming immediately.
    let _ = sip_cmd_tx.send(SipCommand::Answer { call_id });

    // Check if this is a test tone (virtual sound)
    if sound_manager.is_test_tone(sound_name) {
        info!("Starting 440Hz test tone for call {}", call_id);
        let _ = sip_cmd_tx.send(SipCommand::StartTestTone { call_id });
        // Don't hangup - plays until caller hangs up
        return;
    }

    // Check if this is a streaming sound (large file)
    if sound_manager.is_streaming(sound_name)
        && let Some(config) = sound_manager.get_streaming(sound_name)
    {
        info!(
            "Starting streaming playback '{}' from {} for call {}",
            sound_name,
            config.path.display(),
            call_id
        );

        // Use the new port-based streaming approach
        // The audio thread handles timing and the hangup happens automatically when done
        let _ = sip_cmd_tx.send(SipCommand::StartStreaming {
            call_id,
            path: config.path.clone(),
        });

        // Don't hangup here - the streaming player will hangup when done
        // or when the call ends (detected via CALL_CONF_PORTS check)
        return;
    }

    // Preloaded sound - play all at once
    if let Some(sound) = sound_manager.get_preloaded(sound_name) {
        let _ = sip_cmd_tx.send(SipCommand::PlayDirectToCall {
            call_id,
            samples: (*sound.samples).clone(),
        });

        // Wait for playback
        tokio::time::sleep(Duration::from_millis(sound.duration_ms + 200)).await;
    } else {
        warn!("Sound '{}' not found", sound_name);
    }

    info!("Hanging up call {} after extension sound", call_id);
    let _ = sip_cmd_tx.send(SipCommand::Hangup { call_id });
}

/// Wake up any tasks waiting for a bridge to become ready for the given channel.
/// Also cleans up the Notify entry since it's no longer needed.
fn notify_bridge_ready(notifiers: &DashMap<Snowflake, Arc<Notify>>, channel_id: Snowflake) {
    if let Some((_, notify)) = notifiers.remove(&channel_id) {
        notify.notify_waiters();
    }
}

/// Poll a crossbeam channel for the next event, with queue monitoring and periodic logging.
///
/// Returns `Some(event)` when an event is received, or `None` when the channel is disconnected.
/// Sleeps 10ms when the channel is empty to avoid busy-waiting.
async fn poll_recv<T>(rx: &Receiver<T>, name: &str, event_count: &mut u64) -> Option<T> {
    loop {
        let queue_len = rx.len();
        if queue_len > 50 && event_count.is_multiple_of(50) {
            warn!("{} event queue HIGH: {} events pending", name, queue_len);
        }

        match rx.try_recv() {
            Ok(event) => {
                *event_count += 1;

                if event_count.is_multiple_of(500) {
                    trace!(
                        "{} event handler: processed {} events, queue depth: {}",
                        name, event_count, queue_len
                    );
                }

                return Some(event);
            }
            Err(crossbeam_channel::TryRecvError::Empty) => {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            Err(crossbeam_channel::TryRecvError::Disconnected) => return None,
        }
    }
}

/// Fax audio processing task.
///
/// Runs on a 20ms timer tick (matching the audio frame rate). Each tick:
/// 1. Drains all available RX audio and feeds it to SpanDSP
/// 2. Generates exactly one frame of TX audio from SpanDSP (CED, T.30 signaling)
///
/// The timer pacing is critical — SpanDSP's fax_tx() advances its internal clock
/// by the number of samples generated. Without pacing, TX runs at >100x real-time
/// and the T.30 state machine expires prematurely.
async fn process_fax_audio(
    call_id: CallId,
    fax_session: Arc<tokio::sync::Mutex<FaxSession>>,
    audio_ports: Option<crate::fax::audio_port::FaxAudioPorts>,
    sip_cmd_tx: Sender<SipCommand>,
) {
    use crate::transport::sip::CONF_SAMPLE_RATE;

    let samples_per_frame = (CONF_SAMPLE_RATE * 20 / 1000) as usize; // 320 samples = 20ms
    let mut read_buf = vec![0i16; samples_per_frame];
    let mut tx_buf = vec![0i16; samples_per_frame];

    let (mut rx_consumer, mut tx_producer) = match audio_ports {
        Some(ports) => (ports.rx_consumer, ports.tx_producer),
        None => {
            // If we couldn't create the audio port initially, wait and retry
            debug!(
                "Fax call {} — waiting for audio port to become available...",
                call_id
            );
            tokio::time::sleep(Duration::from_secs(2)).await;

            match crate::fax::audio_port::create_fax_audio_port(call_id).await {
                Some(ports) => (ports.rx_consumer, ports.tx_producer),
                None => {
                    error!(
                        "Failed to create fax audio port for call {} after retry",
                        call_id
                    );
                    let mut session = fax_session.lock().await;
                    session
                        .post_failure("Failed to establish audio path for fax reception")
                        .await;
                    let _ = sip_cmd_tx.send(SipCommand::Hangup { call_id });
                    return;
                }
            }
        }
    };

    debug!("Fax audio processing started for call {}", call_id);

    // 20ms interval — matches the conference bridge frame rate.
    // This paces TX generation at real-time so SpanDSP's internal clock stays in sync.
    let mut interval = tokio::time::interval(Duration::from_millis(20));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    let mut tx_audio_frames: u64 = 0;
    let mut tx_silent_frames: u64 = 0;
    let mut rx_frames: u64 = 0;
    let mut tick_count: u64 = 0;

    loop {
        interval.tick().await;
        tick_count += 1;

        let mut session = fax_session.lock().await;

        // 1. Drain all available RX audio and feed to SpanDSP
        loop {
            if rx_consumer.slots() < samples_per_frame {
                break;
            }
            match rx_consumer.read_chunk(samples_per_frame) {
                Ok(chunk) => {
                    let (first, second) = chunk.as_slices();
                    read_buf[..first.len()].copy_from_slice(first);
                    if !second.is_empty() {
                        read_buf[first.len()..first.len() + second.len()].copy_from_slice(second);
                    }
                    chunk.commit_all();
                    session.feed_audio(&read_buf[..samples_per_frame]);
                    rx_frames += 1;
                }
                Err(_) => {
                    debug!("Fax RX ring buffer closed for call {}", call_id);
                    drop(session);
                    let _ = sip_cmd_tx.send(SipCommand::Hangup { call_id });
                    debug!("Fax audio processing ended for call {}", call_id);
                    return;
                }
            }
        }

        // 2. Generate exactly one frame of TX audio (20ms at 16kHz = 320 samples)
        let tx_generated = session.generate_tx_16k(&mut tx_buf);
        if tx_generated > 0 {
            tx_audio_frames += 1;
            if tx_audio_frames == 1 {
                debug!(
                    "Fax {} TX: first audio frame generated (tick {})",
                    call_id, tick_count
                );
            }
            let tx_available = tx_producer.slots();
            let to_write = tx_generated.min(tx_available);
            if to_write > 0
                && let Ok(mut chunk) = tx_producer.write_chunk(to_write)
            {
                let (first, second) = chunk.as_mut_slices();
                let first_len = first.len().min(to_write);
                first[..first_len].copy_from_slice(&tx_buf[..first_len]);
                if first_len < to_write {
                    second[..to_write - first_len].copy_from_slice(&tx_buf[first_len..to_write]);
                }
                chunk.commit_all();
            }
        } else {
            tx_silent_frames += 1;
        }

        // Log diagnostics every 5 seconds (250 ticks)
        if tick_count.is_multiple_of(250) {
            let rx_drops = crate::fax::audio_port::get_rx_drop_count(call_id);
            if rx_drops > 0 {
                warn!(
                    "Fax {} audio: tick={}, rx={} frames, tx={} audio/{} silent, RX DROPS={}",
                    call_id, tick_count, rx_frames, tx_audio_frames, tx_silent_frames, rx_drops
                );
            } else {
                debug!(
                    "Fax {} audio: tick={}, rx={} frames, tx={} audio/{} silent",
                    call_id, tick_count, rx_frames, tx_audio_frames, tx_silent_frames
                );
            }
        }

        // 3. Check for completion / errors / timeout
        if session.is_finished() {
            if matches!(
                session.state,
                crate::fax::session::FaxState::Received | crate::fax::session::FaxState::Complete
            ) {
                debug!("Fax {} reception complete, converting and posting", call_id);
                if let Err(e) = session.convert_and_post().await {
                    error!("Failed to convert/post fax for call {}: {}", call_id, e);
                    session.post_failure("Failed to process received fax").await;
                }
            }
            let _ = sip_cmd_tx.send(SipCommand::Hangup { call_id });
            break;
        }

        if session.is_timed_out() {
            warn!("Fax {} timed out during processing", call_id);
            session.post_failure("Fax reception timed out").await;
            let _ = sip_cmd_tx.send(SipCommand::Hangup { call_id });
            break;
        }
    }

    debug!("Fax audio processing ended for call {}", call_id);
}

/// Handle switching a fax session from G.711 to T.38.
///
/// The T.38 re-INVITE has already been answered synchronously in the PJSUA
/// callback. The pre-bound UDPTL socket is in T38_PRESOCKETS.
///
/// 1. Takes pre-bound socket from T38_PRESOCKETS, converts to tokio
/// 2. Creates FaxT38Receiver
/// 3. Switches the FaxSession from audio to T.38 mode
/// 4. Removes fax audio port (stops audio capture)
/// 5. Spawns UDPTL processing tasks (rx, tx, timer)
async fn handle_t38_switch(
    call_id: CallId,
    remote_ip: String,
    remote_port: u16,
    local_port: u16,
    fax_session: Arc<tokio::sync::Mutex<FaxSession>>,
    cancel_token: CancellationToken,
    sip_cmd_tx: Sender<SipCommand>,
) {
    // 1. Take pre-bound socket from the global map (placed there by the PJSUA callback)
    let std_socket = match crate::transport::sip::T38_PRESOCKETS.remove(&*call_id) {
        Some((_key, socket)) => socket,
        None => {
            error!(
                "No pre-bound UDPTL socket for call {} in T38_PRESOCKETS",
                call_id
            );
            let _ = sip_cmd_tx.send(SipCommand::Hangup { call_id });
            return;
        }
    };

    // Convert std::net::UdpSocket → tokio::net::UdpSocket
    std_socket.set_nonblocking(true).ok();
    let tokio_socket = match tokio::net::UdpSocket::from_std(std_socket) {
        Ok(s) => s,
        Err(e) => {
            error!(
                "Failed to convert UDPTL socket to tokio for call {}: {}",
                call_id, e
            );
            let _ = sip_cmd_tx.send(SipCommand::Hangup { call_id });
            return;
        }
    };
    let udptl_socket = AsyncUdptlSocket::new(tokio_socket);

    // Connect to remote UDPTL endpoint
    let remote_addr = match format!("{}:{}", remote_ip, remote_port).parse() {
        Ok(addr) => addr,
        Err(e) => {
            error!(
                "Invalid remote UDPTL address {}:{} for call {}: {}",
                remote_ip, remote_port, call_id, e
            );
            let _ = sip_cmd_tx.send(SipCommand::Hangup { call_id });
            return;
        }
    };
    udptl_socket.connect(remote_addr);

    // 2. Create T.38 IFP sender channel
    let (tx_ifp_sender, tx_ifp_receiver) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();

    // 3. Create FaxT38Receiver
    let t38_receiver = {
        let session = fax_session.lock().await;
        let tiff_path = session.tiff_dir.join("received.tiff");
        match FaxT38Receiver::new(&tiff_path, tx_ifp_sender) {
            Ok(r) => r,
            Err(e) => {
                error!(
                    "Failed to create FaxT38Receiver for call {}: {}",
                    call_id, e
                );
                let _ = sip_cmd_tx.send(SipCommand::Hangup { call_id });
                return;
            }
        }
    };

    // 4. Switch the session from audio to T.38
    {
        let mut session = fax_session.lock().await;
        session.switch_to_t38(t38_receiver);
    }

    // 5. Remove fax audio port (stop G.711 audio capture)
    crate::fax::audio_port::remove_fax_audio_port(call_id);

    info!(
        "T.38 switch complete for call {}: local_port={}, remote={}:{}",
        call_id, local_port, remote_ip, remote_port
    );

    // 6. Spawn UDPTL processing task
    let udptl_socket = Arc::new(udptl_socket);
    process_fax_t38(
        call_id,
        fax_session,
        udptl_socket,
        tx_ifp_receiver,
        cancel_token,
        sip_cmd_tx,
    )
    .await;
}

/// T.38 fax processing task.
///
/// Runs the UDPTL receive loop, timer loop, and TX loop concurrently.
/// Feeds IFP packets to FaxSession (which feeds SpanDSP T38Terminal),
/// and handles completion/errors.
async fn process_fax_t38(
    call_id: CallId,
    fax_session: Arc<tokio::sync::Mutex<FaxSession>>,
    udptl_socket: Arc<AsyncUdptlSocket>,
    mut tx_ifp_receiver: tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>,
    cancel_token: CancellationToken,
    sip_cmd_tx: Sender<SipCommand>,
) {
    info!("T.38 fax processing started for call {}", call_id);

    // TX task: Send outgoing IFP packets from SpanDSP to the UDPTL socket
    let udptl_tx = udptl_socket.clone();
    let tx_call_id = call_id;
    let tx_handle = tokio::spawn(async move {
        let mut tx_count: u64 = 0;
        while let Some(ifp_data) = tx_ifp_receiver.recv().await {
            tx_count += 1;
            debug!(
                "UDPTL TX #{} for call {}: {}B IFP",
                tx_count,
                tx_call_id,
                ifp_data.len()
            );
            if let Err(e) = udptl_tx.send_ifp(&ifp_data).await {
                warn!("UDPTL TX error for call {}: {}", tx_call_id, e);
                break;
            }
        }
        info!(
            "UDPTL TX task ended for call {} after {} packets",
            tx_call_id, tx_count
        );
    });

    // RX + Timer loop (combined to avoid lock contention)
    let udptl_rx = udptl_socket.clone();
    let mut timer_interval = tokio::time::interval(Duration::from_millis(20));
    timer_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            // Cancelled by CallEnded handler — exit cleanly
            _ = cancel_token.cancelled() => {
                debug!("T.38 task for call {} cancelled by CallEnded", call_id);
                break;
            }

            // Receive UDPTL packets
            result = udptl_rx.recv_packet() => {
                match result {
                    Ok(packet) => {
                        debug!(
                            "UDPTL RX seq={} for call {}: {}B primary + {} redundant",
                            packet.seq_number, call_id, packet.primary_ifp.len(), packet.redundant_ifps().len()
                        );

                        let mut session = fax_session.lock().await;

                        let completed = session.feed_t38_ifp(
                            &packet.primary_ifp,
                            packet.seq_number,
                        );

                        if completed {
                            debug!("Fax {} T.38 reception complete, converting and posting", call_id);
                            if let Err(e) = session.convert_and_post().await {
                                error!("Failed to convert/post fax for call {}: {}", call_id, e);
                                session.post_failure("Failed to process received fax").await;
                            }
                            let _ = sip_cmd_tx.send(SipCommand::Hangup { call_id });
                            break;
                        }

                        if session.is_finished() {
                            let _ = sip_cmd_tx.send(SipCommand::Hangup { call_id });
                            break;
                        }
                    }
                    Err(e) => {
                        warn!("UDPTL RX error for call {}: {}", call_id, e);
                        // Single packet errors are OK — continue receiving
                    }
                }
            }

            // Timer tick: drive T.38 state machine
            _ = timer_interval.tick() => {
                let mut session = fax_session.lock().await;

                let completed = session.drive_t38_timer();

                if completed {
                    debug!("Fax {} T.38 timer-driven completion", call_id);
                    if let Err(e) = session.convert_and_post().await {
                        error!("Failed to convert/post fax for call {}: {}", call_id, e);
                        session.post_failure("Failed to process received fax").await;
                    }
                    let _ = sip_cmd_tx.send(SipCommand::Hangup { call_id });
                    break;
                }

                if session.is_finished() {
                    let _ = sip_cmd_tx.send(SipCommand::Hangup { call_id });
                    break;
                }

                if session.is_timed_out() {
                    warn!("Fax {} T.38 timed out during processing", call_id);
                    session.post_failure("Fax reception timed out").await;
                    let _ = sip_cmd_tx.send(SipCommand::Hangup { call_id });
                    break;
                }
            }
        }
    }

    // Clean up TX task
    tx_handle.abort();

    debug!("T.38 fax processing ended for call {}", call_id);
}
