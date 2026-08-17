use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

/// Errors that can occur loading and validating bridge configuration.
#[derive(thiserror::Error, Debug)]
pub enum ConfigError {
    #[error("failed to read config file {path:?}: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to parse config file {path:?}: {source}")]
    TomlParse {
        path: PathBuf,
        #[source]
        source: toml::de::Error,
    },

    #[error("failed to parse environment variables: {0}")]
    Envy(#[from] envy::Error),

    #[error("global EnvConfig has already been initialised")]
    EnvAlreadyInitialised,

    #[error("required environment variable {0} is not set")]
    MissingEnvVar(&'static str),
}

/// Global application config (loaded from config.toml)
pub static APP_CONFIG: OnceLock<AppConfig> = OnceLock::new();

/// Global environment config (parsed once at startup via `envy`)
static ENV_CONFIG: OnceLock<EnvConfig> = OnceLock::new();

fn default_data_dir() -> String {
    "/var/lib/sipcord".to_string()
}
fn default_config_path() -> String {
    "./config.toml".to_string()
}
fn default_bridge_id() -> String {
    "br_unknown".to_string()
}
fn default_sounds_dir() -> String {
    "./wav".to_string()
}
fn default_sip_port() -> u16 {
    5060
}
fn default_rtp_port_start() -> u16 {
    10000
}
fn default_rtp_port_end() -> u16 {
    15000
}
fn default_tls_port() -> u16 {
    5061
}
fn default_tls_refresh() -> u64 {
    3600
}
fn default_dialplan_path() -> String {
    "./dialplan.toml".to_string()
}

/// All environment variables consumed by the bridge, deserialized once at startup.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct EnvConfig {
    // Paths & Identity
    #[serde(default = "default_data_dir")]
    pub data_dir: String,
    #[serde(default = "default_config_path")]
    pub config_path: String,
    #[serde(default = "default_bridge_id")]
    pub bridge_id: String,
    #[serde(default = "default_sounds_dir")]
    pub sounds_dir: String,

    // Mode
    #[serde(default)]
    pub dev_mode: bool,

    // SIP
    pub sip_public_host: Option<String>,
    #[serde(default = "default_sip_port")]
    pub sip_port: u16,
    #[serde(default = "default_rtp_port_start")]
    pub rtp_port_start: u16,
    #[serde(default = "default_rtp_port_end")]
    pub rtp_port_end: u16,
    pub rtp_public_ip: Option<String>,
    pub sip_local_host: Option<String>,
    pub sip_local_cidr: Option<String>,

    // TLS
    pub tls_cert_dir: Option<String>,
    #[serde(default = "default_tls_port")]
    pub tls_port: u16,
    #[serde(default = "default_tls_refresh")]
    pub tls_refresh_interval: u64,

    // Static router
    pub discord_bot_token: Option<String>,
    #[serde(default = "default_dialplan_path")]
    pub dialplan_path: String,
}

impl EnvConfig {
    /// Parse environment variables (via `envy`) and store in the global `OnceLock`.
    /// Call once at the top of `main()`.
    pub fn init() -> Result<(), ConfigError> {
        dotenvy::dotenv().ok();
        let cfg: EnvConfig = envy::from_env()?;
        ENV_CONFIG
            .set(cfg)
            .map_err(|_| ConfigError::EnvAlreadyInitialised)?;
        Ok(())
    }

    /// Access the global `EnvConfig`. Panics if `init()` was not called.
    pub fn global() -> &'static EnvConfig {
        ENV_CONFIG.get().unwrap_or_else(|| {
            panic!("EnvConfig not initialized — call EnvConfig::init() first")
        })
    }

    /// Build a `SipConfig` from the parsed environment.
    pub fn to_sip_config(&self) -> Result<SipConfig, ConfigError> {
        let public_host = self
            .sip_public_host
            .clone()
            .ok_or(ConfigError::MissingEnvVar("SIP_PUBLIC_HOST"))?;

        let local_net = match (&self.sip_local_host, &self.sip_local_cidr) {
            (Some(host), Some(cidr)) => Some(LocalNetConfig {
                host: host.clone(),
                cidr: cidr.clone(),
            }),
            _ => None,
        };

        Ok(SipConfig {
            public_host,
            port: self.sip_port,
            rtp_port_start: self.rtp_port_start,
            rtp_port_end: self.rtp_port_end,
            rtp_public_ip: self.rtp_public_ip.clone(),
            local_net,
        })
    }

    /// Build a `TlsConfig` from the parsed environment.
    pub fn to_tls_config(&self) -> TlsConfig {
        let cert_dir = self
            .tls_cert_dir
            .as_ref()
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(&self.data_dir).join("certs"));

        TlsConfig {
            cert_dir,
            port: self.tls_port,
            refresh_interval_secs: self.tls_refresh_interval,
        }
    }

    /// Return the SIP public host, falling back to `"0.0.0.0"` when unset.
    pub fn sip_public_host_or_default(&self) -> &str {
        self.sip_public_host.as_deref().unwrap_or("0.0.0.0")
    }

    /// Return the resolved DATA_DIR path, applying the smart fallback:
    /// if the default `/var/lib/sipcord` doesn't exist on disk, fall back to `.`.
    pub fn resolved_data_dir(&self) -> String {
        if self.data_dir == "/var/lib/sipcord" && !Path::new(&self.data_dir).exists() {
            ".".to_string()
        } else {
            self.data_dir.clone()
        }
    }
}

/// Application-level configuration from config.toml
#[derive(Debug, Clone, serde::Deserialize)]
pub struct AppConfig {
    pub sounds: SoundsConfig,
    #[serde(default)]
    pub bridge: BridgeConfig,
    #[serde(default)]
    pub audio: AudioConfig,
    #[serde(default)]
    pub fax: FaxConfig,
}

/// Bridge operational settings
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(default)]
pub struct BridgeConfig {
    /// Seconds without RTP before a call is considered dead
    pub rtp_inactivity_timeout_secs: u64,
    /// Seconds to wait for the first RTP packet before declaring no audio
    /// (faster than rtp_inactivity_timeout for calls that never receive any audio)
    pub no_audio_timeout_secs: u64,
    /// Seconds before destroying a bridge with no SIP calls
    pub empty_bridge_grace_period_secs: u64,
    /// Maximum samples buffered per channel (Discord->SIP direction)
    pub max_channel_buffer_samples: usize,
    /// API request timeout in seconds
    pub api_timeout_secs: u64,
    /// Health check interval in seconds
    pub health_check_interval_secs: u64,
    /// Maximum voice join retry attempts
    pub voice_join_max_retries: u32,
    /// Delay between voice join retries in seconds
    pub voice_join_retry_delay_secs: u64,
    /// Maximum time allowed for one Discord voice join attempt
    pub voice_join_timeout_secs: u64,
    /// Maximum time allowed for Discord voice teardown
    pub voice_disconnect_timeout_secs: u64,
    /// PJSIP internal log level (0-6, filtered via tracing)
    pub pjsip_log_level: u32,
    /// Maximum reconnection attempts before tearing down the bridge
    pub reconnect_max_attempts: u32,
    /// Base delay (seconds) for exponential backoff between reconnections
    pub reconnect_base_delay_secs: u64,
    /// Maximum backoff delay cap (seconds)
    pub reconnect_max_delay_secs: u64,
    /// Minimum bridge age (seconds) before it can be reconnected (cooldown)
    pub reconnect_min_age_secs: u64,
    /// Maximum reconnections allowed per health check cycle
    pub reconnect_max_per_cycle: usize,
}

impl Default for BridgeConfig {
    fn default() -> Self {
        Self {
            rtp_inactivity_timeout_secs: 60,
            no_audio_timeout_secs: 10,
            empty_bridge_grace_period_secs: 30,
            max_channel_buffer_samples: 32000,
            api_timeout_secs: 10,
            health_check_interval_secs: 5,
            voice_join_max_retries: 2,
            voice_join_retry_delay_secs: 5,
            voice_join_timeout_secs: 15,
            voice_disconnect_timeout_secs: 5,
            pjsip_log_level: 4,
            reconnect_max_attempts: 5,
            reconnect_base_delay_secs: 5,
            reconnect_max_delay_secs: 300,
            reconnect_min_age_secs: 30,
            reconnect_max_per_cycle: 3,
        }
    }
}

/// Audio pipeline settings
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(default)]
pub struct AudioConfig {
    /// Ring buffer size in samples for Discord audio streaming
    pub ring_buffer_samples: usize,
    /// Pre-buffer samples before starting Discord audio playback
    pub pre_buffer_samples: usize,
    /// Amplitude threshold above which audio is considered speech
    pub vad_silence_threshold: i16,
    /// Amplitude threshold below which audio is considered muted
    pub vad_mute_threshold: i16,
    /// Consecutive silence frames before stopping speaking state
    pub vad_silence_frames_before_stop: u32,
}

impl Default for AudioConfig {
    fn default() -> Self {
        Self {
            ring_buffer_samples: 96000,
            pre_buffer_samples: 14400,
            vad_silence_threshold: 200,
            vad_mute_threshold: 50,
            vad_silence_frames_before_stop: 15,
        }
    }
}

/// Fax reception settings
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(default)]
pub struct FaxConfig {
    /// Directory for temporary fax files. Defaults to system temp dir.
    pub tmp_folder: Option<PathBuf>,
    /// Filename prefix for fax TIFF/output files (e.g. "fax_")
    pub prefix: String,
    /// Output image format: "png" or "jpg"
    pub output_format: String,
}

impl Default for FaxConfig {
    fn default() -> Self {
        Self {
            tmp_folder: None,
            prefix: "fax_".to_string(),
            output_format: "png".to_string(),
        }
    }
}

/// Sound configuration section
#[derive(Debug, Clone, serde::Deserialize)]
pub struct SoundsConfig {
    #[serde(flatten)]
    pub entries: HashMap<String, SoundEntry>,
}

/// Individual sound entry configuration
#[derive(Debug, Clone, serde::Deserialize)]
pub struct SoundEntry {
    /// Source file path (relative to sounds directory). None for generated tones.
    pub src: Option<String>,
    /// Whether to preload into memory (true) or stream from disk (false)
    #[serde(default)]
    pub preload: bool,
    /// Optional extension that triggers this sound (for easter eggs)
    #[serde(default)]
    pub extension: Option<u32>,
}

impl AppConfig {
    /// Load configuration from a TOML file
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let contents = std::fs::read_to_string(path).map_err(|source| ConfigError::Read {
            path: path.to_path_buf(),
            source,
        })?;
        toml::from_str(&contents).map_err(|source| ConfigError::TomlParse {
            path: path.to_path_buf(),
            source,
        })
    }

    /// Get the global application config. Panics if `AppConfig::load(...)` was not called.
    pub fn global() -> &'static AppConfig {
        APP_CONFIG.get().unwrap_or_else(|| {
            panic!("AppConfig not initialized — call AppConfig::load() first")
        })
    }

    /// Get bridge config (with defaults if not loaded yet)
    pub fn bridge() -> &'static BridgeConfig {
        APP_CONFIG.get().map(|c| &c.bridge).unwrap_or_else(|| {
            static DEFAULT: OnceLock<BridgeConfig> = OnceLock::new();
            DEFAULT.get_or_init(BridgeConfig::default)
        })
    }

    /// Get audio config (with defaults if not loaded yet)
    pub fn audio() -> &'static AudioConfig {
        APP_CONFIG.get().map(|c| &c.audio).unwrap_or_else(|| {
            static DEFAULT: OnceLock<AudioConfig> = OnceLock::new();
            DEFAULT.get_or_init(AudioConfig::default)
        })
    }

    /// Get fax config (with defaults if not loaded yet)
    pub fn fax() -> &'static FaxConfig {
        APP_CONFIG.get().map(|c| &c.fax).unwrap_or_else(|| {
            static DEFAULT: OnceLock<FaxConfig> = OnceLock::new();
            DEFAULT.get_or_init(FaxConfig::default)
        })
    }
}

#[derive(Debug, Clone)]
pub struct TlsConfig {
    pub cert_dir: PathBuf,
    pub port: u16,
    pub refresh_interval_secs: u64,
}

#[derive(Debug, Clone)]
pub struct SipConfig {
    pub public_host: String,
    pub port: u16,
    pub rtp_port_start: u16,
    pub rtp_port_end: u16,
    /// Public IP address to advertise in SDP for RTP media (c= line)
    /// If not set, pjsua will use the local interface IP which won't work for NAT
    pub rtp_public_ip: Option<String>,
    /// Local network support: rewrite Contact headers for clients in local_network to use local_host
    /// This allows the bridge to serve both public and local clients simultaneously
    pub local_net: Option<LocalNetConfig>,
}

#[derive(Debug, Clone)]
pub struct LocalNetConfig {
    /// Local host IP to use in Contact headers for local clients (e.g., 192.168.10.1)
    pub host: String,
    /// Local network CIDR - clients in this range get local_host in Contact (e.g., 192.168.10.0/24)
    pub cidr: String,
}

impl SipConfig {
    /// Load SIP configuration from environment variables.
    /// Standalone method for backends that don't need the full Config.
    pub fn from_env() -> Result<Self, ConfigError> {
        EnvConfig::global().to_sip_config()
    }
}

impl TlsConfig {
    pub fn cert_path(&self) -> PathBuf {
        self.cert_dir.join("bridge.crt")
    }

    pub fn key_path(&self) -> PathBuf {
        self.cert_dir.join("bridge.key")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bridge_config_default() {
        let c = BridgeConfig::default();
        assert_eq!(c.rtp_inactivity_timeout_secs, 60);
        assert_eq!(c.no_audio_timeout_secs, 10);
        assert_eq!(c.empty_bridge_grace_period_secs, 30);
        assert_eq!(c.max_channel_buffer_samples, 32000);
        assert_eq!(c.api_timeout_secs, 10);
        assert_eq!(c.voice_join_timeout_secs, 15);
        assert_eq!(c.voice_disconnect_timeout_secs, 5);
        assert_eq!(c.pjsip_log_level, 4);
    }

    #[test]
    fn test_audio_config_default() {
        let c = AudioConfig::default();
        assert_eq!(c.ring_buffer_samples, 96000);
        assert_eq!(c.pre_buffer_samples, 14400);
        assert_eq!(c.vad_silence_threshold, 200);
        assert_eq!(c.vad_mute_threshold, 50);
        assert_eq!(c.vad_silence_frames_before_stop, 15);
    }

    #[test]
    fn test_fax_config_default() {
        let c = FaxConfig::default();
        assert!(c.tmp_folder.is_none());
        assert_eq!(c.prefix, "fax_");
        assert_eq!(c.output_format, "png");
    }

    #[test]
    fn test_resolved_data_dir_default_missing() {
        let env = EnvConfig {
            data_dir: "/var/lib/sipcord".to_string(),
            config_path: "./config.toml".to_string(),
            bridge_id: "br_test".to_string(),
            sounds_dir: "./wav".to_string(),
            dev_mode: false,
            sip_public_host: None,
            sip_port: 5060,
            rtp_port_start: 10000,
            rtp_port_end: 15000,
            rtp_public_ip: None,
            sip_local_host: None,
            sip_local_cidr: None,
            tls_cert_dir: None,
            tls_port: 5061,
            tls_refresh_interval: 3600,
            discord_bot_token: None,
            dialplan_path: "./dialplan.toml".to_string(),
        };
        assert_eq!(env.resolved_data_dir(), ".");
    }

    #[test]
    fn test_resolved_data_dir_custom() {
        let env = EnvConfig {
            data_dir: "/tmp".to_string(),
            config_path: "./config.toml".to_string(),
            bridge_id: "br_test".to_string(),
            sounds_dir: "./wav".to_string(),
            dev_mode: false,
            sip_public_host: None,
            sip_port: 5060,
            rtp_port_start: 10000,
            rtp_port_end: 15000,
            rtp_public_ip: None,
            sip_local_host: None,
            sip_local_cidr: None,
            tls_cert_dir: None,
            tls_port: 5061,
            tls_refresh_interval: 3600,
            discord_bot_token: None,
            dialplan_path: "./dialplan.toml".to_string(),
        };
        assert_eq!(env.resolved_data_dir(), "/tmp");
    }

    #[test]
    fn test_to_tls_config_cert_dir_fallback() {
        let env = EnvConfig {
            data_dir: "/data".to_string(),
            config_path: "./config.toml".to_string(),
            bridge_id: "br_test".to_string(),
            sounds_dir: "./wav".to_string(),
            dev_mode: false,
            sip_public_host: None,
            sip_port: 5060,
            rtp_port_start: 10000,
            rtp_port_end: 15000,
            rtp_public_ip: None,
            sip_local_host: None,
            sip_local_cidr: None,
            tls_cert_dir: None,
            tls_port: 5061,
            tls_refresh_interval: 3600,
            discord_bot_token: None,
            dialplan_path: "./dialplan.toml".to_string(),
        };
        let tls = env.to_tls_config();
        assert_eq!(tls.cert_dir, PathBuf::from("/data/certs"));
        assert_eq!(tls.port, 5061);
    }

    #[test]
    fn test_tls_config_paths() {
        let tls = TlsConfig {
            cert_dir: PathBuf::from("/etc/ssl/sipcord"),
            port: 5061,
            refresh_interval_secs: 3600,
        };
        assert_eq!(
            tls.cert_path(),
            PathBuf::from("/etc/ssl/sipcord/bridge.crt")
        );
        assert_eq!(tls.key_path(), PathBuf::from("/etc/ssl/sipcord/bridge.key"));
    }

    #[test]
    fn test_app_config_load_valid_toml() {
        let toml_content = r#"
[sounds]
join = { src = "join.wav", preload = true }

[bridge]
rtp_inactivity_timeout_secs = 120

[audio]
ring_buffer_samples = 48000

[fax]
prefix = "test_"
"#;
        let dir = std::env::temp_dir().join("sipcord_test_config");
        std::fs::create_dir_all(&dir).ok();
        let path = dir.join("test_config.toml");
        std::fs::write(&path, toml_content).unwrap();

        let config = AppConfig::load(&path).unwrap();
        assert_eq!(config.bridge.rtp_inactivity_timeout_secs, 120);
        assert_eq!(config.audio.ring_buffer_samples, 48000);
        assert_eq!(config.fax.prefix, "test_");
        assert!(config.sounds.entries.contains_key("join"));
    }
}
