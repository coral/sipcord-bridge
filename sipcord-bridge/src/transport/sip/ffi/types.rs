//! Low-level pjsua wrapper types and constants
//!
//! This module provides safe(r) Rust wrappers around the pjsua C library.
//!
//! ## Audio Architecture
//!
//! When using `pjsua_set_no_snd_dev()`, we take control of audio I/O:
//! - pjsua's conference bridge handles codec negotiation and mixing
//! - We periodically call `get_frame`/`put_frame` to exchange audio with the conference
//! - The conference outputs 16kHz mono PCM regardless of call codec (G.711, Opus, etc.)
//! - We resample to/from Discord's 48kHz stereo

use crate::services::snowflake::Snowflake;
use crossbeam_channel::Sender;
use crossbeam_queue::SegQueue;
use dashmap::DashMap;
use ipnet::Ipv4Net;
use parking_lot::{Mutex, RwLock};
use pjsua::*;
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::ops::Deref;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::atomic::AtomicBool;
use std::time::Instant;

// CallId newtype

/// Type-safe wrapper around `pjsua_call_id` (i32).
///
/// Prevents accidental confusion with conference port IDs, account IDs,
/// and other bare `i32` values in the pjsua API.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CallId(i32);

impl CallId {
    /// Sentinel for "no call" / invalid call ID.
    pub const INVALID: CallId = CallId(-1);

    pub const fn new(value: i32) -> Self {
        Self(value)
    }

    pub const fn get(self) -> i32 {
        self.0
    }

    pub const fn is_valid(self) -> bool {
        self.0 >= 0
    }
}

impl Deref for CallId {
    type Target = i32;
    fn deref(&self) -> &i32 {
        &self.0
    }
}

impl From<i32> for CallId {
    fn from(v: i32) -> Self {
        Self(v)
    }
}

impl From<CallId> for i32 {
    fn from(c: CallId) -> i32 {
        c.0
    }
}

impl std::fmt::Display for CallId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::fmt::Debug for CallId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "CallId({})", self.0)
    }
}

// ConfPort newtype

/// Type-safe wrapper around conference port slot IDs (`i32`).
///
/// Prevents accidental confusion with `CallId`, account IDs,
/// and other bare `i32` values in the pjsua API.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ConfPort(i32);

impl ConfPort {
    /// Sentinel for "no port" / invalid conf port.
    pub const INVALID: ConfPort = ConfPort(-1);

    pub const fn new(value: i32) -> Self {
        Self(value)
    }

    pub const fn get(self) -> i32 {
        self.0
    }

    pub const fn is_valid(self) -> bool {
        self.0 >= 0
    }
}

impl Deref for ConfPort {
    type Target = i32;
    fn deref(&self) -> &i32 {
        &self.0
    }
}

impl From<i32> for ConfPort {
    fn from(v: i32) -> Self {
        Self(v)
    }
}

impl From<ConfPort> for i32 {
    fn from(c: ConfPort) -> i32 {
        c.0
    }
}

impl std::fmt::Display for ConfPort {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::fmt::Debug for ConfPort {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ConfPort({})", self.0)
    }
}

/// SIP Digest auth parameters extracted from Authorization header
#[derive(Debug, Clone, Default)]
pub struct DigestAuthParams {
    pub username: String,
    pub realm: String,
    pub nonce: String,
    pub uri: String,
    pub response: String,
    pub method: String,
    pub qop: Option<String>,
    pub nc: Option<String>,
    pub cnonce: Option<String>,
}

/// Callback handlers for SIP events
pub struct CallbackHandlers {
    pub on_incoming_call: Box<dyn Fn(CallId, String, String, Option<IpAddr>) + Send + Sync>,
    pub on_call_authenticated:
        Box<dyn Fn(CallId, DigestAuthParams, String, Option<IpAddr>) + Send + Sync>,
    pub on_dtmf: Box<dyn Fn(CallId, char) + Send + Sync>,
    pub on_call_ended: Box<dyn Fn(CallId) + Send + Sync>,
    /// Audio frame callback: (channel_id, samples, sample_rate)
    /// channel_id is the Discord channel ID (Snowflake) for per-channel routing
    pub on_audio_frame: AudioFrameCallback,
}

/// Callback type for audio frame delivery: (channel_id, samples, sample_rate)
pub type AudioFrameCallback = Box<dyn Fn(Snowflake, &[i16], u32) + Send + Sync>;

/// Realm for our SIP server
pub const SIP_REALM: &str = "sipcord";

/// Conference bridge sample rate (16kHz)
pub const CONF_SAMPLE_RATE: u32 = 16000;

/// Conference bridge channels (mono)
pub const CONF_CHANNELS: u32 = 1;

/// Audio frame duration in ms
pub const FRAME_PTIME_MS: u32 = 20;

/// Samples per frame = sample_rate * ptime / 1000
pub const SAMPLES_PER_FRAME: usize = (CONF_SAMPLE_RATE * FRAME_PTIME_MS / 1000) as usize;

// Config accessors — cached on first call via OnceLock (config is immutable at runtime).

pub fn rtp_inactivity_timeout_secs() -> u64 {
    static CACHED: OnceLock<u64> = OnceLock::new();
    *CACHED.get_or_init(|| crate::config::AppConfig::bridge().rtp_inactivity_timeout_secs)
}

/// Shorter timeout for calls that never receive any RTP at all
pub fn no_audio_timeout_secs() -> u64 {
    static CACHED: OnceLock<u64> = OnceLock::new();
    *CACHED.get_or_init(|| crate::config::AppConfig::bridge().no_audio_timeout_secs)
}

pub fn empty_bridge_grace_period_secs() -> u64 {
    static CACHED: OnceLock<u64> = OnceLock::new();
    *CACHED.get_or_init(|| crate::config::AppConfig::bridge().empty_bridge_grace_period_secs)
}

pub fn max_channel_buffer_samples() -> usize {
    static CACHED: OnceLock<usize> = OnceLock::new();
    *CACHED.get_or_init(|| crate::config::AppConfig::bridge().max_channel_buffer_samples)
}

/// Wrapper for pjmedia_port pointer that is Send
/// Safety: pjsua is single-threaded and we only access this from the audio thread
pub struct SendablePort(pub *mut pjmedia_port);
unsafe impl Send for SendablePort {}
unsafe impl Sync for SendablePort {}

/// Wrapper for pj_pool_t pointer
pub struct SendablePool(pub *mut pj_pool_t);
unsafe impl Send for SendablePool {}
unsafe impl Sync for SendablePool {}

/// Type alias for local network config: (local_host, parsed_cidr, port, rtp_public_ip)
pub type LocalNetConfig = (String, Ipv4Net, u16, Option<String>);

/// Type alias for drain cache entry: (last_drain_time, cached_samples, sample_count)
/// Using Arc<[i16]> for single allocation (no separate Vec header).
/// Cache hit becomes Arc::clone() (zero-copy).
pub type DrainCacheEntry = (Instant, Arc<[i16]>, usize);

/// Type alias for direct player entry: (samples buffer, current read position)
pub type DirectPlayerEntry = (Vec<i16>, usize);

// Global statics

/// Global callback handlers (pjsua uses global callbacks)
pub static CALLBACKS: OnceLock<Mutex<Option<CallbackHandlers>>> = OnceLock::new();

/// Audio output buffers per call (Discord -> SIP)
/// Using DashMap for lock-free concurrent access on audio hot path
pub static AUDIO_OUT_BUFFERS: OnceLock<DashMap<CallId, VecDeque<i16>>> = OnceLock::new();

/// Master conference port (returned by pjsua_set_no_snd_dev)
pub static CONF_MASTER_PORT: OnceLock<Mutex<SendablePort>> = OnceLock::new();

/// Local network config for Contact header and SDP rewriting
/// Stored as (local_host, parsed_cidr, port, rtp_public_ip) for efficient lookup in the callback
/// rtp_public_ip is the IP that pjsua advertises in SDP - we replace it with local_host for local clients
pub static LOCAL_NET_CONFIG: OnceLock<Option<LocalNetConfig>> = OnceLock::new();

/// Public host config for rewriting private IPs in Contact headers sent to external clients.
/// pjsua derives Contact from the TCP connection's local address (e.g. 10.0.1.7), but external
/// clients need the public hostname to route in-dialog requests (BYE) back to us.
/// Stored as (public_host, sip_port).
pub static PUBLIC_HOST_CONFIG: OnceLock<Option<(String, u16)>> = OnceLock::new();

/// Flag to indicate audio thread should stop
pub static AUDIO_THREAD_RUNNING: AtomicBool = AtomicBool::new(false);

/// Audio thread handle for joining on shutdown
pub static AUDIO_THREAD_HANDLE: OnceLock<Mutex<Option<std::thread::JoinHandle<()>>>> =
    OnceLock::new();

/// Flag indicating the audio thread has processed at least one frame
/// This is used to defer channel registration completions until the conference
/// bridge is actively being clocked.
pub static AUDIO_THREAD_READY: AtomicBool = AtomicBool::new(false);

/// Queue of pending channel registrations to complete once audio thread is ready
/// Stores (call_id, conf_port) pairs that need complete_pending_channel_registration called
/// Uses lock-free SegQueue for zero-contention push/pop on the 50Hz audio thread
pub static PENDING_CHANNEL_COMPLETIONS: SegQueue<(CallId, ConfPort)> = SegQueue::new();

/// One conference connection attempt owned by the audio thread.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PendingConfConnection {
    pub call_id: CallId,
    pub channel_id: Snowflake,
    pub registration_id: u64,
    pub attempts: u16,
    pub not_before_frame: u64,
}

impl PendingConfConnection {
    pub fn new(call_id: CallId, channel_id: Snowflake, registration_id: u64) -> Self {
        Self {
            call_id,
            channel_id,
            registration_id,
            attempts: 0,
            not_before_frame: 0,
        }
    }
}

/// Queue of pending conference connections to be made by the audio thread.
/// Entries carry retry state so transient PJSUA failures cannot silently strand a call.
/// This is used because pjsua_conf_connect conflicts with the audio thread's
/// pjmedia_port_get_frame calls if made from a different thread
/// Uses lock-free SegQueue for zero-contention push/pop on the 50Hz audio thread
pub static PENDING_CONF_CONNECTIONS: SegQueue<PendingConfConnection> = SegQueue::new();

/// Pending PJSUA operations that must be executed by the audio thread
/// These operations modify the conference bridge and must be synchronized with get_frame
#[derive(Debug)]
pub enum PendingPjsuaOp {
    /// Play samples directly to a call (for join sounds)
    /// Note: This also stops any active looping player for the call first
    PlayDirect { call_id: CallId, samples: Vec<i16> },
    /// Start streaming audio from a file to a call (for large easter egg files)
    /// Uses pull model for precise timing - audio thread pulls frames as needed
    StartStreaming {
        call_id: CallId,
        path: PathBuf,
        hangup_on_complete: bool,
    },
    /// Start playing a 440Hz test tone to a call (plays until caller hangs up)
    StartTestTone { call_id: CallId },
    /// Hangup a call (used internally for cleanup after streaming)
    Hangup { call_id: CallId },
    /// Start a looping audio player for early media (connecting sound)
    /// Must run on audio thread to avoid race with pjmedia_port_get_frame
    StartLoop { call_id: CallId, samples: Vec<i16> },
    /// Connect a fax audio port bidirectionally in the conference bridge.
    /// Must run on the audio thread to avoid racing with pjmedia_port_get_frame.
    /// The oneshot sender signals completion back to the async caller.
    ConnectFaxPort {
        call_id: CallId,
        fax_slot: ConfPort,
        call_conf_port: ConfPort,
        done_tx: tokio::sync::oneshot::Sender<bool>,
    },
}

/// Queue of pending PJSUA operations to be executed by the audio thread
/// Uses lock-free SegQueue for zero-contention push/pop on the 50Hz audio thread
pub static PENDING_PJSUA_OPS: SegQueue<PendingPjsuaOp> = SegQueue::new();

/// Set of call_ids with active media (used to start/stop audio thread)
/// This prevents double-counting or decrementing calls that were never counted
pub static COUNTED_CALL_IDS: OnceLock<Mutex<HashSet<CallId>>> = OnceLock::new();

/// TLS transport ID (for reload support)
pub static TLS_TRANSPORT_ID: OnceLock<Mutex<Option<std::os::raw::c_int>>> = OnceLock::new();

/// Flag indicating TLS reload is pending
pub static TLS_RELOAD_PENDING: AtomicBool = AtomicBool::new(false);

/// Per-call RTP activity tracking: call_id -> (last_rx_packet_count, last_activity_time)
/// Used to detect dead calls when SIP BYE is not received
pub static CALL_RTP_ACTIVITY: OnceLock<Mutex<HashMap<CallId, (u64, Instant)>>> = OnceLock::new();

/// Event sender for timeout events (set during callback setup)
pub static TIMEOUT_EVENT_TX: OnceLock<Mutex<Option<Sender<crate::transport::sip::SipEvent>>>> =
    OnceLock::new();

// Per-channel audio isolation statics

/// call_id -> conf_port mapping (for connecting/disconnecting calls)
/// Using DashMap for lock-free concurrent access on audio hot path
pub static CALL_CONF_PORTS: OnceLock<DashMap<CallId, ConfPort>> = OnceLock::new();

/// call_id -> channel_id mapping (which Discord channel each call belongs to)
/// Using DashMap for lock-free concurrent access on audio hot path
pub static CALL_CHANNELS: OnceLock<DashMap<CallId, Snowflake>> = OnceLock::new();

/// Generation of each call -> channel registration. Numeric PJSUA call IDs are
/// reused, so queued conference work must also match this generation.
pub static CALL_CHANNEL_REGISTRATIONS: OnceLock<DashMap<CallId, u64>> = OnceLock::new();

/// channel_id -> set of call_ids (all calls in each channel)
/// Uses RwLock: audio thread takes .read() (non-exclusive, 50Hz), call lifecycle takes .write()
pub static CHANNEL_CALLS: OnceLock<RwLock<HashMap<Snowflake, HashSet<CallId>>>> = OnceLock::new();

/// channel_id -> audio INPUT buffer (SIP -> Discord, per-channel)
/// Filled by channel_port_put_frame callback, drained by audio thread for Discord
/// Using DashMap for lock-free concurrent access on audio hot path
pub static CHANNEL_AUDIO_IN: OnceLock<DashMap<Snowflake, VecDeque<i16>>> = OnceLock::new();

/// Per-channel conference ports: channel_id -> (pjmedia_port*, conf_slot)
/// Each channel gets its own CUSTOM BUFFER port for isolated Discord->SIP audio routing
/// Unlike null ports, these actually provide audio to the conference via get_frame callback
pub static CHANNEL_CONF_PORTS: OnceLock<Mutex<HashMap<Snowflake, (SendablePort, ConfPort)>>> =
    OnceLock::new();

/// Reverse mapping: port_ptr -> channel_id (for get_frame callback to find the right buffer)
pub static PORT_TO_CHANNEL: OnceLock<Mutex<HashMap<usize, Snowflake>>> = OnceLock::new();

/// Memory pool for creating channel ports
pub static CHANNEL_PORT_POOL: OnceLock<Mutex<SendablePool>> = OnceLock::new();

/// Global audio frame counter (incremented once per audio thread tick)
/// Used to prevent channel ports from being drained multiple times per frame
pub static AUDIO_FRAME_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Per-channel time-based cache: channel_id -> (last_drain_time, cached_samples)
/// If get_frame is called multiple times within 15ms (same PJSUA tick), we return the cached samples.
/// This prevents N callers from draining N*320 samples when they should all share the same frame.
/// Using DashMap for lock-free concurrent access on audio hot path
pub static CHANNEL_DRAIN_CACHE: OnceLock<DashMap<Snowflake, DrainCacheEntry>> = OnceLock::new();

// Direct player statics

/// Direct player state: port_ptr -> (samples buffer, current read position)
/// Used for playing audio directly to a single call without going through channel buffer
pub static DIRECT_PLAYER_STATE: OnceLock<Mutex<HashMap<usize, DirectPlayerEntry>>> =
    OnceLock::new();

/// Memory pool for direct player ports
pub static DIRECT_PLAYER_POOL: OnceLock<Mutex<SendablePool>> = OnceLock::new();

/// Queue a PJSUA operation to be executed by the audio thread
pub fn queue_pjsua_op(op: PendingPjsuaOp) {
    PENDING_PJSUA_OPS.push(op);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_call_id_invalid() {
        assert_eq!(CallId::INVALID.get(), -1);
        assert!(!CallId::INVALID.is_valid());
    }

    #[test]
    fn test_call_id_valid() {
        assert!(CallId::new(0).is_valid());
        assert!(CallId::new(5).is_valid());
    }

    #[test]
    fn test_call_id_deref() {
        let id = CallId::new(42);
        let val: &i32 = &id;
        assert_eq!(*val, 42);
    }

    #[test]
    fn test_call_id_from_into() {
        let id: CallId = 7.into();
        assert_eq!(id.get(), 7);
        let raw: i32 = id.into();
        assert_eq!(raw, 7);
    }

    #[test]
    fn test_call_id_display_debug() {
        let id = CallId::new(3);
        assert_eq!(format!("{}", id), "3");
        assert_eq!(format!("{:?}", id), "CallId(3)");
    }

    #[test]
    fn test_conf_port_invalid() {
        assert_eq!(ConfPort::INVALID.get(), -1);
        assert!(!ConfPort::INVALID.is_valid());
    }

    #[test]
    fn test_conf_port_valid() {
        assert!(ConfPort::new(0).is_valid());
        assert!(ConfPort::new(5).is_valid());
    }

    #[test]
    fn test_conf_port_deref() {
        let port = ConfPort::new(10);
        let val: &i32 = &port;
        assert_eq!(*val, 10);
    }

    #[test]
    fn test_conf_port_from_into() {
        let port: ConfPort = 9.into();
        assert_eq!(port.get(), 9);
        let raw: i32 = port.into();
        assert_eq!(raw, 9);
    }

    #[test]
    fn test_conf_port_display_debug() {
        let port = ConfPort::new(4);
        assert_eq!(format!("{}", port), "4");
        assert_eq!(format!("{:?}", port), "ConfPort(4)");
    }

    #[test]
    fn test_digest_auth_params_default() {
        let params = DigestAuthParams::default();
        assert!(params.username.is_empty());
        assert!(params.realm.is_empty());
        assert!(params.nonce.is_empty());
        assert!(params.uri.is_empty());
        assert!(params.response.is_empty());
        assert!(params.method.is_empty());
        assert!(params.qop.is_none());
        assert!(params.nc.is_none());
        assert!(params.cnonce.is_none());
    }
}
