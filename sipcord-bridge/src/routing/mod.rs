pub mod static_router;

use crate::services::snowflake::Snowflake;
use crate::transport::sip::DigestAuthParams;
use async_trait::async_trait;
use serde::Serialize;

/// Outbound call request from the backend (e.g., Discord /call command)
#[derive(Debug, Clone)]
pub struct OutboundCallRequest {
    pub call_id: String,
    pub discord_user_id: String,
    /// Display-only username used in logs and SIP caller context.
    pub discord_username: String,
    pub guild_id: String,
    pub channel_id: String,
    pub bot_token: String,
    pub caller_username: String,
    pub created_at: std::time::Instant,
}

#[derive(Debug, Clone)]
pub enum OutboundCallCommand {
    Start(OutboundCallRequest),
    Cancel { call_id: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutboundCallFailureReason {
    Busy,
    Declined,
    NoAnswer,
    Transport,
    Internal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutboundCallStatus {
    Unavailable,
    Ringing,
    Answered,
    Connected,
    Failed(OutboundCallFailureReason),
    NoAudio,
    Ended,
}

/// Internal diagnostics attached to outbound call status updates.
///
/// These values are sent to the private backend for operator troubleshooting;
/// they must never contain credentials or Discord bot tokens.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct OutboundCallDiagnostics {
    pub phase: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub elapsed_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registration: Option<RegistrationDiagnostics>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub leg_failures: Vec<OutboundCallLegFailure>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct RegistrationDiagnostics {
    pub registrar_sip_users: usize,
    pub registrar_user_mappings: usize,
    pub registrar_registrations: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mapped_sip_username: Option<String>,
    pub target_registration_count: usize,
    pub target_active_registration_count: usize,
    pub target_expired_registration_count: usize,
    pub registrations_truncated: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub registrations: Vec<RegistrationContactDiagnostics>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RegistrationContactDiagnostics {
    pub contact_uri: String,
    pub source_addr: String,
    pub transport: String,
    pub active: bool,
    pub registered_age_ms: u64,
    pub expires_in_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OutboundCallLegFailure {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sip_call_id: Option<String>,
    pub detail: String,
}

/// Result of routing an incoming SIP call
pub enum RouteDecision {
    /// Connect to this Discord voice channel
    Connect {
        channel_id: Snowflake,
        guild_id: Snowflake,
        user_id: String,
        bot_token: String,
    },
    /// Handle as incoming fax — post to a Discord text channel
    ConnectFax {
        text_channel_id: Snowflake,
        guild_id: Snowflake,
        user_id: String,
        bot_token: String,
    },
    /// Redirect to another bridge server
    Redirect { domain: String, extension: String },
    /// Reject with invalid credentials (no error sound, just hangup)
    RejectInvalidCredentials,
    /// Play an error sound and hangup
    RejectWithError { error: CallError },
}

/// Errors that trigger audio playback before hangup
#[derive(thiserror::Error, Debug, Clone, Copy)]
pub enum CallError {
    #[error("no channel mapping for the dialed extension")]
    NoChannelMapping,
    #[error("user lacks permission for the target Discord channel")]
    NoPermissions,
    #[error("Discord API error")]
    DiscordApiError,
    #[error("server is busy")]
    ServerBusy,
    #[error("unknown call error")]
    Unknown,
}

impl CallError {
    /// Get the sound name for this error type
    pub fn sound_name(&self) -> &'static str {
        match self {
            CallError::NoChannelMapping => "no_channel_mapping",
            CallError::NoPermissions => "no_permissions",
            CallError::DiscordApiError => "server_is_busy",
            CallError::ServerBusy => "server_is_busy",
            CallError::Unknown => "unknown_error",
        }
    }
}

/// Info about a call that just started (for backend tracking)
pub struct CallStartedInfo {
    pub sip_call_id: String,
    pub user_id: String,
    pub guild_id: String,
    pub channel_id: String,
    pub extension: String,
}

/// The routing backend — tells the bridge who to connect and when.
///
/// This is the open-source boundary: the core bridge knows how to connect
/// SIP <-> Discord audio. The Backend tells it *who* to connect and *when*.
#[async_trait]
pub trait Backend: Send + Sync {
    /// Get the Discord bot token
    fn bot_token(&self) -> &str;

    /// Route an incoming SIP call (authenticate + get destination)
    async fn route_call(&self, digest_auth: &DigestAuthParams, extension: &str) -> RouteDecision;

    /// Notify that a call has started
    async fn on_call_started(&self, info: &CallStartedInfo);

    /// Notify that a call has ended
    async fn on_call_ended(&self, sip_call_id: &str);

    /// Send heartbeat for active channels
    async fn heartbeat(&self, active_channel_ids: &[String]);

    /// Report outbound call status back to the backend
    fn report_call_status(&self, call_id: &str, status: OutboundCallStatus);

    /// Report outbound call status with operator-only diagnostic context.
    fn report_call_status_with_diagnostics(
        &self,
        call_id: &str,
        status: OutboundCallStatus,
        _diagnostics: OutboundCallDiagnostics,
    ) {
        self.report_call_status(call_id, status);
    }

    /// Get the next outbound call command (None if backend doesn't support outbound)
    async fn next_outbound_command(&self) -> Option<OutboundCallCommand>;
}
