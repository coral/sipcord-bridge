mod voice;

use crate::audio::simd;
use crate::services::snowflake::Snowflake;
use anyhow::Result;
use audioadapter::Adapter;
use audioadapter_buffers::direct::SequentialSliceOfVecs;
use crossbeam_channel::Sender;
use dashmap::DashMap;
use parking_lot::Mutex;
use rtrb::Producer;
use rubato::{
    Async, FixedAsync, Resampler, SincInterpolationParameters, SincInterpolationType,
    WindowFunction,
};
use serenity::all::{ChannelId, Client, Context, EventHandler, FullEvent, GatewayIntents, GuildId};
use serenity::async_trait;
use serenity::secrets::Token;
use songbird::driver::DecodeMode;
use songbird::tracks::PlayMode;
use songbird::{
    Config, CoreEvent, Event, EventContext, EventHandler as VoiceEventHandler, Songbird, TrackEvent,
};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::oneshot;
use tracing::{debug, error, info, trace, warn};

// Direct audio path: SIP audio thread → Discord
// Uses lock-free ring buffer for real-time audio streaming

/// Global registry of channel_id → audio sender for direct SIP→Discord audio path.
/// This allows the pjsua audio thread to send directly to Discord without going through tokio.
static DISCORD_AUDIO_SENDERS: OnceLock<DashMap<Snowflake, DirectAudioSender>> = OnceLock::new();

// Discord→SIP direct path: Discord VoiceTick → ring buffer → SIP audio thread
// Uses lock-free ring buffer to bypass tokio/crossbeam async round-trip

/// Per-channel ring buffer producers for Discord→SIP audio.
/// VoiceReceiver writes resampled i16 mono @ 16kHz here.
/// channel_port_get_frame reads from the consumer side (in transport/sip/channel_audio.rs).
static DISCORD_TO_SIP_PRODUCERS: OnceLock<DashMap<Snowflake, Mutex<rtrb::Producer<i16>>>> =
    OnceLock::new();

fn get_discord_to_sip_producers() -> &'static DashMap<Snowflake, Mutex<rtrb::Producer<i16>>> {
    DISCORD_TO_SIP_PRODUCERS.get_or_init(DashMap::new)
}

/// Register a ring buffer producer for Discord→SIP audio on a channel.
pub fn register_discord_to_sip_producer(channel_id: Snowflake, producer: rtrb::Producer<i16>) {
    debug!(
        "Registering Discord→SIP ring buffer producer for channel {}",
        channel_id
    );
    get_discord_to_sip_producers().insert(channel_id, Mutex::new(producer));
}

/// Unregister the ring buffer producer for a channel.
pub fn unregister_discord_to_sip_producer(channel_id: Snowflake) {
    debug!(
        "Unregistering Discord→SIP ring buffer producer for channel {}",
        channel_id
    );
    get_discord_to_sip_producers().remove(&channel_id);
}

/// Write resampled audio directly to the Discord→SIP ring buffer.
/// Called from VoiceReceiver on the Songbird event loop.
/// Returns true if audio was written, false if no producer registered or buffer full.
fn write_discord_to_sip(channel_id: Snowflake, samples_16k: &[i16]) -> bool {
    let Some(producer_entry) = get_discord_to_sip_producers().get(&channel_id) else {
        return false;
    };
    let Some(mut producer) = producer_entry.try_lock() else {
        return false;
    };
    let slots = producer.slots();
    if slots >= samples_16k.len() {
        if let Ok(mut chunk) = producer.write_chunk(samples_16k.len()) {
            let (first, second) = chunk.as_mut_slices();
            let first_len = first.len();
            first.copy_from_slice(&samples_16k[..first_len]);
            if !second.is_empty() {
                second.copy_from_slice(&samples_16k[first_len..]);
            }
            chunk.commit_all();
        }
        true
    } else {
        // Ring buffer full - drop this frame
        trace!(
            "Discord→SIP ring buffer full for channel {} (need {}, have {})",
            channel_id,
            samples_16k.len(),
            slots
        );
        false
    }
}

fn get_audio_senders() -> &'static DashMap<Snowflake, DirectAudioSender> {
    DISCORD_AUDIO_SENDERS.get_or_init(DashMap::new)
}

/// Combined resampler + ring buffer producer, locked together (always accessed together)
struct AudioPipeline {
    resampler: ResamplerState,
    producer: Producer<f32>,
}

/// Cached VAD config values (read once at creation, never change at runtime)
struct CachedVadConfig {
    silence_threshold: i16,
    mute_threshold: i16,
    silence_frames_before_stop: u32,
}

/// Wrapper for the audio sender with resampler state and ring buffer producer
struct DirectAudioSender {
    /// Resampler + ring buffer producer locked together (one lock instead of two per frame)
    pipeline: Mutex<AudioPipeline>,
    /// Cached VAD config (avoids AppConfig::audio() call every 20ms frame)
    vad_config: CachedVadConfig,
    /// VAD: Counter for consecutive silent frames
    silence_frame_count: AtomicU32,
    /// VAD: Whether we're currently sending speech
    is_speaking: AtomicBool,
    /// Health tracking: consecutive overflow errors
    consecutive_overflows: AtomicU64,
}

/// Consolidated resampler state with pre-allocated buffers
struct ResamplerState {
    resampler: Async<f64>,
    /// Pre-allocated buffer for i16→f64 conversion (capacity: 320)
    input_f64: Vec<f64>,
    /// Pre-allocated buffer for mono→stereo f32 output (capacity: 1920)
    stereo_f32: Vec<f32>,
}

impl ResamplerState {
    fn new() -> Self {
        Self {
            resampler: create_resampler(),
            input_f64: Vec::with_capacity(320),
            stereo_f32: Vec::with_capacity(1920),
        }
    }
}

/// Create a high-quality sinc resampler for 16kHz → 48kHz
fn create_resampler() -> Async<f64> {
    let params = SincInterpolationParameters {
        sinc_len: 256,
        f_cutoff: 0.95,
        interpolation: SincInterpolationType::Linear,
        oversampling_factor: 256,
        window: WindowFunction::BlackmanHarris2,
    };

    // 16kHz to 48kHz = ratio of 3.0, mono input, 320 samples per chunk (20ms at 16kHz)
    Async::new_sinc(
        48000.0 / 16000.0, // resample ratio (3.0x)
        1.1,               // max relative ratio (allow slight variation)
        &params,
        320,               // chunk size (samples per frame at 16kHz)
        1,                 // mono channel
        FixedAsync::Input, // fixed input size
    )
    .expect("Failed to create resampler")
}

/// RAII guard for a registered Discord audio sender.
/// Automatically unregisters the sender when dropped.
pub struct RegisteredAudioSender {
    channel_id: Snowflake,
}

impl RegisteredAudioSender {
    /// Register a Discord audio sender for direct SIP→Discord audio path.
    pub fn new(channel_id: Snowflake, producer: Producer<f32>) -> Self {
        debug!("Registering direct audio sender for channel {}", channel_id);
        let audio_cfg = crate::config::AppConfig::audio();
        get_audio_senders().insert(
            channel_id,
            DirectAudioSender {
                pipeline: Mutex::new(AudioPipeline {
                    resampler: ResamplerState::new(),
                    producer,
                }),
                vad_config: CachedVadConfig {
                    silence_threshold: audio_cfg.vad_silence_threshold,
                    mute_threshold: audio_cfg.vad_mute_threshold,
                    silence_frames_before_stop: audio_cfg.vad_silence_frames_before_stop,
                },
                silence_frame_count: AtomicU32::new(0),
                is_speaking: AtomicBool::new(false),
                consecutive_overflows: AtomicU64::new(0),
            },
        );
        Self { channel_id }
    }
}

impl Drop for RegisteredAudioSender {
    fn drop(&mut self) {
        debug!(
            "Unregistering direct audio sender for channel {}",
            self.channel_id
        );
        get_audio_senders().remove(&self.channel_id);
    }
}

/// Send audio directly from SIP to Discord, bypassing tokio.
/// This is called from the pjsua audio thread.
///
/// samples: PCM i16 mono at sample_rate (typically 16kHz from pjsua)
/// Returns true if audio was sent, false if no sender registered for this channel.
pub fn send_audio_to_discord_direct(
    channel_id: Snowflake,
    samples: &[i16],
    sample_rate: u32,
) -> bool {
    use std::sync::atomic::AtomicU64;
    static SEND_COUNT: AtomicU64 = AtomicU64::new(0);
    let count = SEND_COUNT.fetch_add(1, Ordering::Relaxed);

    let Some(sender) = get_audio_senders().get(&channel_id) else {
        return false;
    };

    // VAD constants from cached config (no per-frame AppConfig lookup)
    let silence_threshold = sender.vad_config.silence_threshold;
    let mute_threshold = sender.vad_config.mute_threshold;
    let silence_frames_before_stop = sender.vad_config.silence_frames_before_stop;

    // SIMD-accelerated amplitude detection for VAD
    let input_max_amp = simd::max_abs_i16(samples);

    // Check for muted audio
    let is_muted = input_max_amp < mute_threshold;
    let has_speech = input_max_amp > silence_threshold;
    let was_speaking = sender.is_speaking.load(Ordering::Relaxed);
    let prev_silence_count = sender.silence_frame_count.load(Ordering::Relaxed);

    // Update VAD state (for diagnostics)
    if is_muted {
        sender
            .silence_frame_count
            .store(silence_frames_before_stop, Ordering::Relaxed);
        sender.is_speaking.store(false, Ordering::Relaxed);
    } else if has_speech {
        sender.silence_frame_count.store(0, Ordering::Relaxed);
        sender.is_speaking.store(true, Ordering::Relaxed);
    } else {
        let new_count = prev_silence_count.saturating_add(1);
        sender
            .silence_frame_count
            .store(new_count, Ordering::Relaxed);
        if new_count >= silence_frames_before_stop || !was_speaking {
            sender.is_speaking.store(false, Ordering::Relaxed);
        }
    }

    // Lock the audio pipeline once for both resampling and ring buffer push
    // (previously two separate Mutex acquisitions per frame)
    let mut pipeline = sender.pipeline.lock();
    // Destructure to allow simultaneous borrows of resampler and producer
    let AudioPipeline {
        ref mut resampler,
        ref mut producer,
    } = *pipeline;
    let rs = resampler;

    let f32_samples_len;

    if sample_rate != DISCORD_SAMPLE_RATE {
        // Convert i16 to f64 for rubato, reusing pre-allocated buffer
        rs.input_f64.clear();
        rs.input_f64
            .extend(samples.iter().map(|&s| s as f64 / 32768.0));

        let input_len = rs.input_f64.len();

        // Process through sinc resampler (maintains state across calls)
        // rubato 1.0 uses audioadapter traits - wrap our mono Vec in a sequential slice of vecs
        let input_channels = vec![std::mem::take(&mut rs.input_f64)];
        let input_adapter = match SequentialSliceOfVecs::new(&input_channels, 1, input_len) {
            Ok(a) => a,
            Err(e) => {
                warn!(
                    "Failed to create input adapter for channel {}: {:?}",
                    channel_id, e
                );
                let resampled_i16 = resample_audio(samples, sample_rate, DISCORD_SAMPLE_RATE);
                rs.stereo_f32.clear();
                for &s in &resampled_i16 {
                    let f = s as f32 / 32768.0;
                    rs.stereo_f32.push(f);
                    rs.stereo_f32.push(f);
                }
                f32_samples_len = rs.stereo_f32.len();
                let ring_slots = producer.slots();
                if ring_slots >= f32_samples_len {
                    if let Ok(mut chunk) = producer.write_chunk(f32_samples_len) {
                        let (first, second) = chunk.as_mut_slices();
                        let first_len = first.len();
                        first.copy_from_slice(&rs.stereo_f32[..first_len]);
                        if !second.is_empty() {
                            second.copy_from_slice(&rs.stereo_f32[first_len..]);
                        }
                        chunk.commit_all();
                    }
                    sender.consecutive_overflows.store(0, Ordering::Relaxed);
                }
                return !rs.stereo_f32.is_empty();
            }
        };
        match rs.resampler.process(&input_adapter, 0, None) {
            Ok(output_buffer) => {
                let out_frames = output_buffer.frames();
                let out_channels = output_buffer.channels();
                if out_frames == 0 {
                    // Resampler buffering - send silence to keep timing
                    if count.is_multiple_of(50) {
                        warn!(
                            "Resampler returned empty output (buffering?) input={}",
                            input_len
                        );
                    }
                    rs.stereo_f32.clear();
                    rs.stereo_f32.resize(1920, 0.0f32); // 20ms of stereo silence at 48kHz
                } else {
                    // Extract the mono channel data from the interleaved buffer
                    let data = output_buffer.take_data();
                    let output_mono_len;
                    // Convert mono f64 to stereo f32, reusing pre-allocated buffer
                    rs.stereo_f32.clear();
                    if out_channels == 1 {
                        output_mono_len = data.len();
                        for sample in &data {
                            let s = *sample as f32;
                            rs.stereo_f32.push(s);
                            rs.stereo_f32.push(s);
                        }
                    } else {
                        // Extract first channel from interleaved data
                        output_mono_len = data.len() / out_channels;
                        for sample in data.iter().step_by(out_channels) {
                            let s = *sample as f32;
                            rs.stereo_f32.push(s);
                            rs.stereo_f32.push(s);
                        }
                    }
                    // Log resampler input/output ratio
                    if count.is_multiple_of(50) {
                        debug!(
                            "Resampler: input={} samples, output={} samples (ratio={:.2}, expected=3.0)",
                            input_len,
                            output_mono_len,
                            output_mono_len as f64 / input_len as f64
                        );
                        debug!(
                            "SIP→Discord #{}: mono_out={}, stereo_out={} samples ({} bytes as f32)",
                            count,
                            output_mono_len,
                            rs.stereo_f32.len(),
                            rs.stereo_f32.len() * 4
                        );
                    }
                }
            }
            Err(e) => {
                warn!(
                    "Resampler error for channel {}: {:?} (falling back to linear)",
                    channel_id, e
                );
                // Fallback to simple linear interpolation, reusing buffer
                let resampled_i16 = resample_audio(samples, sample_rate, DISCORD_SAMPLE_RATE);
                rs.stereo_f32.clear();
                for &s in &resampled_i16 {
                    let f = s as f32 / 32768.0;
                    rs.stereo_f32.push(f);
                    rs.stereo_f32.push(f);
                }
            }
        }
    } else {
        // Already at 48kHz - just convert to stereo f32, reusing buffer
        rs.stereo_f32.clear();
        for &sample in samples {
            let s = sample as f32 / 32768.0;
            rs.stereo_f32.push(s);
            rs.stereo_f32.push(s);
        }
    }

    f32_samples_len = rs.stereo_f32.len();

    // Push samples to the ring buffer (same lock, no second acquisition)
    let ring_slots = producer.slots();
    let samples_to_push = f32_samples_len;

    // Log every 50 packets (1 second at 20ms/packet)
    if count.is_multiple_of(50) {
        let ring_total = voice::ring_buffer_samples();
        let buffer_fill = ring_total - ring_slots;
        let fill_ms = buffer_fill as f64 / 48000.0 / 2.0 * 1000.0;
        debug!(
            "SIP→Discord direct #{}: channel={}, pushing {} samples, ring buffer: {}/{} ({:.0}ms), input_amp={}",
            count, channel_id, samples_to_push, buffer_fill, ring_total, fill_ms, input_max_amp
        );
    }

    if ring_slots >= samples_to_push {
        // Enough space - push all samples
        if let Ok(mut chunk) = producer.write_chunk(samples_to_push) {
            let (first, second) = chunk.as_mut_slices();
            let first_len = first.len();
            first.copy_from_slice(&rs.stereo_f32[..first_len]);
            if !second.is_empty() {
                second.copy_from_slice(&rs.stereo_f32[first_len..]);
            }
            chunk.commit_all();
        }
        sender.consecutive_overflows.store(0, Ordering::Relaxed);
    } else {
        // Ring buffer full - drop samples (overflow)
        let consecutive = sender.consecutive_overflows.fetch_add(1, Ordering::Relaxed) + 1;
        if consecutive <= 10 || consecutive % 50 == 0 {
            warn!(
                "Ring buffer overflow for channel {} (consecutive: {}, need {} slots, have {})",
                channel_id, consecutive, samples_to_push, ring_slots
            );
        }
    }

    true
}

fn silence_threshold() -> i16 {
    use std::sync::OnceLock;
    static CACHED: OnceLock<i16> = OnceLock::new();
    *CACHED.get_or_init(|| crate::config::AppConfig::audio().vad_silence_threshold)
}

pub use voice::{DISCORD_SAMPLE_RATE, StreamingAudioSource, resample_audio, resample_audio_into};

/// Events emitted by the Discord module
#[derive(Debug, Clone)]
pub enum DiscordEvent {
    /// Successfully connected to a voice channel
    VoiceConnected {
        bridge_id: String,
        guild_id: Snowflake,
        channel_id: Snowflake,
    },
    /// Disconnected from voice channel
    VoiceDisconnected { bridge_id: String },
}

/// Shared Discord client that maintains a single gateway connection.
///
/// Instead of creating a new Serenity Client per SIP call (which opens a new
/// gateway WebSocket each time), we create ONE client at startup and reuse its
/// Songbird manager to join/leave voice channels. This reduces gateway connections
/// from N-per-call to exactly 1.
pub struct SharedDiscordClient {
    songbird: Arc<Songbird>,
    bot_user_id: AtomicU64,
    _client_handle: tokio::task::JoinHandle<()>,
}

impl SharedDiscordClient {
    /// Create the shared Discord client. Call once at bridge startup.
    ///
    /// This opens a single gateway WebSocket connection that stays alive for
    /// the bridge's lifetime. The returned Songbird manager is used by all
    /// voice connections to join/leave channels.
    pub async fn new(bot_token: &str) -> Result<Arc<Self>> {
        info!("Creating shared Discord client (single gateway connection)");

        let intents = GatewayIntents::GUILDS | GatewayIntents::GUILD_VOICE_STATES;

        let songbird_config = Config::default().decode_mode(DecodeMode::Decode(Default::default()));
        let songbird = Songbird::serenity_from_config(songbird_config);

        let (ready_tx, ready_rx) = oneshot::channel::<u64>();
        let ready_tx = Arc::new(tokio::sync::Mutex::new(Some(ready_tx)));

        let token: Token = bot_token
            .parse()
            .map_err(|e| anyhow::anyhow!("Invalid bot token: {}", e))?;

        let mut client = Client::builder(token, intents)
            .event_handler(Arc::new(SharedClientEventHandler { ready_tx }))
            .voice_manager(songbird.clone())
            .await?;

        let client_handle = tokio::spawn(async move {
            if let Err(e) = client.start().await {
                error!("Shared Discord client error: {}", e);
            }
        });

        // Wait for gateway Ready event to get the bot's user ID
        let bot_user_id = match tokio::time::timeout(std::time::Duration::from_secs(15), ready_rx)
            .await
        {
            Ok(Ok(id)) => {
                info!("Shared Discord client ready, bot user ID: {}", id);
                id
            }
            _ => {
                error!(
                    "Failed to get bot user ID from shared client, feedback filtering may not work"
                );
                0
            }
        };

        // Let gateway stabilize
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;

        Ok(Arc::new(Self {
            songbird,
            bot_user_id: AtomicU64::new(bot_user_id),
            _client_handle: client_handle,
        }))
    }

    /// Get the shared Songbird manager for joining/leaving voice channels.
    pub fn songbird(&self) -> &Arc<Songbird> {
        &self.songbird
    }

    /// Get the bot's user ID (for filtering own audio in VoiceTick).
    pub fn bot_user_id(&self) -> Snowflake {
        Snowflake::new(self.bot_user_id.load(Ordering::Relaxed))
    }
}

/// Serenity event handler for the shared client
struct SharedClientEventHandler {
    ready_tx: Arc<tokio::sync::Mutex<Option<oneshot::Sender<u64>>>>,
}

#[async_trait]
impl EventHandler for SharedClientEventHandler {
    async fn dispatch(&self, _ctx: &Context, event: &FullEvent) {
        if let FullEvent::Ready { data_about_bot, .. } = event {
            info!(
                "Shared Discord bot connected as {} (ID: {})",
                data_about_bot.user.name, data_about_bot.user.id
            );
            if let Some(tx) = self.ready_tx.lock().await.take() {
                let _ = tx.send(data_about_bot.user.id.get());
            }
        }
    }
}

/// Inner state for Discord voice connection
struct DiscordVoiceConnectionInner {
    bridge_id: String,
    guild_id: Snowflake,
    channel_id: Snowflake,
    songbird: Arc<Songbird>,
    event_tx: Sender<DiscordEvent>,
    /// Health tracking: timestamp (ms since epoch) of last audio received from Discord (VoiceTick)
    last_audio_received: Arc<AtomicU64>,
    /// RAII guard: auto-unregisters the audio sender on drop
    _audio_sender: RegisteredAudioSender,
    /// Shared flag to deactivate VoiceReceiver handlers on disconnect
    voice_receiver_active: Arc<AtomicBool>,
    /// Set by VoiceReceiver when an unexpected DriverDisconnect event fires.
    /// Checked by is_healthy() so the health check can react immediately.
    driver_disconnected: Arc<AtomicBool>,
}

/// A voice connection to a single Discord voice channel.
///
/// Uses the shared Discord client's Songbird manager to join/leave channels
/// without creating new gateway connections. Each connection manages its own
/// audio pipeline (ring buffer, resampler, event handlers).
///
/// This type is Clone-able (uses Arc internally) to allow sharing across async tasks.
#[derive(Clone)]
pub struct DiscordVoiceConnection {
    inner: Arc<DiscordVoiceConnectionInner>,
}

impl DiscordVoiceConnection {
    /// Join a Discord voice channel using the shared client's Songbird manager.
    ///
    /// This does NOT create a new gateway connection — it reuses the single
    /// shared client established at startup. Only the voice channel join/leave
    /// is per-call.
    pub async fn connect(
        bridge_id: String,
        shared_client: &Arc<SharedDiscordClient>,
        guild_id: Snowflake,
        channel_id: Snowflake,
        event_tx: Sender<DiscordEvent>,
        health_check_notify: Arc<tokio::sync::Notify>,
    ) -> Result<Self> {
        info!(
            "Joining voice channel {} in guild {} for bridge {} (using shared client)",
            channel_id, guild_id, bridge_id
        );

        let songbird = shared_client.songbird().clone();
        let bot_user_id = shared_client.bot_user_id();

        // Join the voice channel with retry logic
        let guild = GuildId::new(*guild_id);
        let channel = ChannelId::new(*channel_id);

        let bridge_cfg = crate::config::AppConfig::bridge();
        let max_retries = bridge_cfg.voice_join_max_retries;
        let retry_delay_secs = bridge_cfg.voice_join_retry_delay_secs;

        let mut last_error = None;
        for attempt in 1..=max_retries {
            if attempt > 1 {
                info!(
                    "Retry attempt {} for joining voice channel {} (bridge {})",
                    attempt, channel_id, bridge_id
                );
            }

            match songbird.join(guild, channel).await {
                Ok(handler_lock) => {
                    info!(
                        "Joined voice channel {} in guild {} for bridge {}{}",
                        channel_id,
                        guild_id,
                        bridge_id,
                        if attempt > 1 {
                            format!(" (attempt {})", attempt)
                        } else {
                            String::new()
                        }
                    );

                    // Create the streaming audio source with ring buffer for sending audio to Discord
                    let (streaming_source, producer) = StreamingAudioSource::new();

                    // Register the ring buffer producer for direct SIP→Discord audio path
                    // This allows the pjsua audio thread to bypass tokio entirely
                    let audio_sender = RegisteredAudioSender::new(channel_id, producer);

                    // Create shared timestamp for health tracking
                    let now_ms = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_millis() as u64;
                    let last_audio_received = Arc::new(AtomicU64::new(now_ms));

                    // Set up audio receiver for incoming Discord voice
                    // and start the streaming audio source for outgoing audio
                    let voice_receiver_active = Arc::new(AtomicBool::new(true));
                    let driver_disconnected = Arc::new(AtomicBool::new(false));
                    {
                        let mut handler = handler_lock.lock().await;

                        // CRITICAL: Clear any stale event handlers from previous bridges
                        // that may have accumulated on this guild's Call handler.
                        // Without this, each connect() adds 5 more handlers that never
                        // get removed, causing N duplicate audio processing per VoiceTick.
                        handler.remove_all_global_events();

                        // Register for VoiceTick events (decoded audio every 20ms)
                        // Also register for SpeakingStateUpdate to track SSRC-to-user mappings
                        // And driver events to monitor connection health
                        let receiver = VoiceReceiver::new(
                            bridge_id.clone(),
                            channel_id,
                            bot_user_id,
                            last_audio_received.clone(),
                            voice_receiver_active.clone(),
                            driver_disconnected.clone(),
                            health_check_notify,
                        );
                        handler.add_global_event(
                            Event::Core(CoreEvent::SpeakingStateUpdate),
                            receiver.clone(),
                        );
                        handler
                            .add_global_event(Event::Core(CoreEvent::VoiceTick), receiver.clone());
                        handler.add_global_event(
                            Event::Core(CoreEvent::DriverConnect),
                            receiver.clone(),
                        );
                        handler.add_global_event(
                            Event::Core(CoreEvent::DriverDisconnect),
                            receiver.clone(),
                        );
                        handler.add_global_event(Event::Core(CoreEvent::DriverReconnect), receiver);

                        // Start playing the streaming audio source immediately
                        // Track stays playing so Songbird always reads from the queue,
                        // preventing overflow. VAD filters which frames we push to the queue.
                        let input = streaming_source.into_input();
                        let track_handle = handler.play_input(input);

                        // Register track event handlers to monitor playback state
                        // This helps diagnose why Songbird might stop consuming audio
                        let track_handler = TrackEventHandler {
                            bridge_id: bridge_id.clone(),
                        };
                        // Listen for track state changes (only End and Error are concerning)
                        track_handle
                            .add_event(Event::Track(TrackEvent::Play), track_handler.clone())
                            .ok();
                        track_handle
                            .add_event(Event::Track(TrackEvent::Pause), track_handler.clone())
                            .ok();
                        track_handle
                            .add_event(Event::Track(TrackEvent::End), track_handler.clone())
                            .ok();
                        track_handle
                            .add_event(Event::Track(TrackEvent::Error), track_handler)
                            .ok();

                        // Track stays playing - never pause it to avoid buffer underruns.
                        // Songbird needs to continuously read from the queue.
                        info!("Started streaming audio source for bridge {}", bridge_id);

                        let _ = event_tx.send(DiscordEvent::VoiceConnected {
                            bridge_id: bridge_id.clone(),
                            guild_id,
                            channel_id,
                        });

                        // We don't need the track_handle anymore - track always plays
                        drop(track_handle);

                        return Ok(Self {
                            inner: Arc::new(DiscordVoiceConnectionInner {
                                bridge_id,
                                guild_id,
                                channel_id,
                                songbird,
                                event_tx,
                                last_audio_received,
                                _audio_sender: audio_sender,
                                voice_receiver_active,
                                driver_disconnected,
                            }),
                        });
                    }
                }
                Err(e) => {
                    error!(
                        "Failed to join voice channel (attempt {}/{}): {:?}",
                        attempt, max_retries, e
                    );
                    last_error = Some(e);

                    if attempt < max_retries {
                        info!(
                            "Waiting {} seconds before retry for bridge {}",
                            retry_delay_secs, bridge_id
                        );
                        tokio::time::sleep(std::time::Duration::from_secs(retry_delay_secs)).await;
                    }
                }
            }
        }

        // All retries failed
        anyhow::bail!(
            "Failed to join voice channel after {} attempts: {:?}",
            max_retries,
            last_error
        )
    }

    /// Send audio to the Discord voice channel
    ///
    /// The samples should be PCM i16 at the given sample_rate (mono).
    /// This function handles resampling to Discord's 48kHz stereo format.
    /// Implements VAD (Voice Activity Detection) to only send audio when speech is detected.
    /// Note: This is synchronous to minimize latency - no async overhead.
    /// Check if the Discord connection is healthy.
    ///
    /// Returns true if VoiceTick events have been received within the last 5 seconds.
    /// This indicates that Songbird is actively processing audio from Discord.
    pub fn is_healthy(&self) -> bool {
        // Immediate fail if the Songbird driver disconnected unexpectedly
        if self.inner.driver_disconnected.load(Ordering::Relaxed) {
            return false;
        }

        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        let last_recv = self.inner.last_audio_received.load(Ordering::Relaxed);
        let recv_age_ms = now_ms.saturating_sub(last_recv);

        // Consider unhealthy if no VoiceTick for 5 seconds
        recv_age_ms < 5000
    }

    /// Get the current audio ring buffer fill percentage (0-100).
    ///
    /// High values (>80%) indicate backpressure - Discord consumer is falling behind.
    pub fn queue_fill_percent(&self) -> u8 {
        // Read from the direct audio sender registry
        get_audio_senders()
            .get(&self.inner.channel_id)
            .map(|s| {
                let pipeline = s.pipeline.lock();
                let slots_free = pipeline.producer.slots();
                let total = voice::ring_buffer_samples();
                let filled = total.saturating_sub(slots_free);
                ((filled * 100) / total).min(100) as u8
            })
            .unwrap_or(0)
    }

    /// Get the number of consecutive overflow errors.
    ///
    /// High values indicate the Discord audio consumer has stopped reading.
    pub fn consecutive_overflows(&self) -> u64 {
        // Read from the direct audio sender registry
        get_audio_senders()
            .get(&self.inner.channel_id)
            .map(|s| s.consecutive_overflows.load(Ordering::Relaxed))
            .unwrap_or(0)
    }

    /// Get the bridge ID for this connection.
    pub fn bridge_id(&self) -> &str {
        &self.inner.bridge_id
    }

    /// Leave the voice channel and disconnect.
    ///
    /// This only leaves the voice channel — it does NOT shut down the shared
    /// Discord client, which stays alive for other connections.
    pub async fn disconnect(self) {
        info!("Disconnecting bridge {} from Discord", self.inner.bridge_id);

        // Deactivate the VoiceReceiver to prevent stale event processing.
        // This is a safety net: even if remove_all_global_events misses something
        // (e.g. race with reconnect), the old handler becomes a no-op.
        self.inner
            .voice_receiver_active
            .store(false, Ordering::Relaxed);

        // Audio sender is auto-unregistered when DiscordVoiceConnectionInner is dropped

        let guild = GuildId::new(*self.inner.guild_id);

        // Stop all tracks and clear event handlers before leaving.
        // This ensures old StreamingAudioSource instances stop being polled
        // and no stale VoiceReceiver handlers survive on the Call handler.
        if let Some(handler_lock) = self.inner.songbird.get(guild) {
            let mut handler = handler_lock.lock().await;
            handler.remove_all_global_events();
            handler.stop();
        }

        let _ = self.inner.songbird.leave(guild).await;

        // Small delay to let Songbird fully release resources before any reconnection
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        let _ = self.inner.event_tx.send(DiscordEvent::VoiceDisconnected {
            bridge_id: self.inner.bridge_id.clone(),
        });
    }
}

/// Track event handler to monitor audio playback state
/// This helps diagnose why Songbird might stop consuming audio
#[derive(Clone)]
struct TrackEventHandler {
    bridge_id: String,
}

#[async_trait]
impl VoiceEventHandler for TrackEventHandler {
    async fn act(&self, ctx: &EventContext<'_>) -> Option<Event> {
        if let EventContext::Track(track_list) = ctx {
            for (state, _handle) in track_list.iter() {
                // Only log concerning states at warn/error level
                match state.playing {
                    PlayMode::Stop => {
                        error!(
                            "TRACK STOPPED for bridge {} - this will cause queue overflow!",
                            self.bridge_id
                        );
                    }
                    PlayMode::End => {
                        error!(
                            "TRACK ENDED for bridge {} - this will cause queue overflow!",
                            self.bridge_id
                        );
                    }
                    PlayMode::Play | PlayMode::Pause => {
                        // Normal state changes - log at trace level
                        trace!(
                            "Track event for bridge {}: mode={:?}, position={:?}",
                            self.bridge_id, state.playing, state.position,
                        );
                    }
                    _ => {
                        trace!(
                            "Track event for bridge {}: mode={:?}",
                            self.bridge_id, state.playing,
                        );
                    }
                }
            }
        }
        None
    }
}

/// Pre-allocated buffers for audio mixing to avoid per-tick allocations
struct MixingBuffer {
    /// Mixed audio in i32 for headroom (1920 samples = 20ms @ 48kHz stereo)
    mixed: Vec<i32>,
    /// Stereo output after clamping to i16 (1920 samples)
    stereo_out: Vec<i16>,
    /// Mono output for SIP (960 samples = 20ms @ 48kHz mono)
    mono_out: Vec<i16>,
    /// Pre-allocated buffer for 48kHz→16kHz resampled output (avoids per-tick Vec allocation)
    resample_buf: Vec<i16>,
}

impl MixingBuffer {
    fn new() -> Self {
        Self {
            mixed: vec![0i32; 1920],
            stereo_out: vec![0i16; 1920],
            mono_out: vec![0i16; 960],
            // 960 mono samples at 48kHz → ~320 at 16kHz (ratio 3:1)
            resample_buf: Vec::with_capacity(960),
        }
    }
}

/// Voice event receiver for capturing audio
#[derive(Clone)]
struct VoiceReceiver {
    bridge_id: String,
    /// Discord channel ID for direct ring buffer writes
    channel_id: Snowflake,
    /// The bot's own user ID - used to filter out our own audio from VoiceTick
    bot_user_id: Snowflake,
    /// Map from SSRC to user ID - populated from SpeakingStateUpdate events
    ssrc_to_user: Arc<Mutex<HashMap<u32, Snowflake>>>,
    /// Shared timestamp for health tracking - updated when audio is received
    last_audio_received: Arc<AtomicU64>,
    /// Pre-allocated mixing buffers to avoid allocations in hot path
    mixing_buffer: Arc<Mutex<MixingBuffer>>,
    /// Safety flag: set to false on disconnect to make stale handlers no-op.
    /// Prevents accumulated handlers from processing audio after their bridge disconnects.
    active: Arc<AtomicBool>,
    /// Set when an unexpected DriverDisconnect fires, so is_healthy() returns false immediately.
    driver_disconnected: Arc<AtomicBool>,
    /// Notify the health check loop to wake up immediately on driver disconnect.
    health_check_notify: Arc<tokio::sync::Notify>,
}

impl VoiceReceiver {
    fn new(
        bridge_id: String,
        channel_id: Snowflake,
        bot_user_id: Snowflake,
        last_audio_received: Arc<AtomicU64>,
        active: Arc<AtomicBool>,
        driver_disconnected: Arc<AtomicBool>,
        health_check_notify: Arc<tokio::sync::Notify>,
    ) -> Self {
        Self {
            bridge_id,
            channel_id,
            bot_user_id,
            ssrc_to_user: Arc::new(Mutex::new(HashMap::new())),
            last_audio_received,
            mixing_buffer: Arc::new(Mutex::new(MixingBuffer::new())),
            active,
            driver_disconnected,
            health_check_notify,
        }
    }
}

#[async_trait]
impl VoiceEventHandler for VoiceReceiver {
    async fn act(&self, ctx: &EventContext<'_>) -> Option<Event> {
        // Safety net: if this receiver has been deactivated (bridge disconnected),
        // skip all processing to prevent stale handlers from corrupting audio.
        if !self.active.load(Ordering::Relaxed) {
            return None;
        }

        match ctx {
            EventContext::SpeakingStateUpdate(speaking) => {
                // Track SSRC-to-user mappings for filtering out bot's own audio
                if let Some(user_id) = speaking.user_id {
                    let user_id_snowflake = Snowflake::new(user_id.0);
                    let mut map = self.ssrc_to_user.lock();
                    map.insert(speaking.ssrc, user_id_snowflake);
                    if user_id_snowflake == self.bot_user_id {
                        debug!(
                            "Recorded bot's own SSRC {} for bridge {}",
                            speaking.ssrc, self.bridge_id
                        );
                    } else {
                        trace!(
                            "Recorded SSRC {} -> user {} for bridge {}",
                            speaking.ssrc, user_id_snowflake, self.bridge_id
                        );
                    }
                }
                debug!("Speaking state update: {:?}", speaking);
            }
            EventContext::DriverConnect(info) => {
                info!(
                    "Songbird DRIVER CONNECTED for bridge {}: channel={:?}, ssrc={:?}, session_id={:?}",
                    self.bridge_id, info.channel_id, info.ssrc, info.session_id
                );
            }
            EventContext::DriverDisconnect(info) => {
                // Check if this was a requested disconnect (normal) or unexpected
                let is_requested = info
                    .reason
                    .as_ref()
                    .map(|r| format!("{:?}", r).contains("Requested"))
                    .unwrap_or(false);
                if is_requested {
                    debug!(
                        "Songbird driver disconnected (requested) for bridge {}: channel={:?}",
                        self.bridge_id, info.channel_id
                    );
                } else {
                    // Unexpected disconnect - this is a problem!
                    error!(
                        "Songbird DRIVER DISCONNECTED unexpectedly for bridge {}: channel={:?}, reason={:?}",
                        self.bridge_id, info.channel_id, info.reason
                    );
                    // Signal unhealthy immediately so the health check can react
                    // within ~1s instead of waiting for the next 5s tick.
                    self.driver_disconnected.store(true, Ordering::Relaxed);
                    self.health_check_notify.notify_one();
                }
            }
            EventContext::DriverReconnect(info) => {
                warn!(
                    "Songbird DRIVER RECONNECTING for bridge {}: channel={:?}, ssrc={:?}",
                    self.bridge_id, info.channel_id, info.ssrc
                );
            }
            EventContext::VoiceTick(tick) => {
                static TICK_COUNT: AtomicU64 = AtomicU64::new(0);
                let count = TICK_COUNT.fetch_add(1, Ordering::Relaxed);

                // Update health tracking timestamp - VoiceTick arriving means Discord is alive
                let now_ms = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_millis() as u64;
                self.last_audio_received.store(now_ms, Ordering::Relaxed);

                // Log every 250 ticks (5 seconds at 20ms per tick)
                let should_log = count.is_multiple_of(250);

                // Use try_lock to avoid blocking on the event loop - skip tick if contended
                let ssrc_map = self.ssrc_to_user.try_lock();

                // Try to get mixing buffer - skip tick if contended (shouldn't happen normally)
                let mut mixing_buf = match self.mixing_buffer.try_lock() {
                    Some(buf) => buf,
                    None => {
                        if should_log {
                            trace!("VoiceTick: Skipping tick due to mixing buffer contention");
                        }
                        return None;
                    }
                };

                let speaker_count = tick.speaking.len();
                let silent_count = tick.silent.len();
                let mut skipped_self = false;
                let mut has_audio = false;
                let mut max_len: usize = 0;

                if should_log {
                    trace!(
                        "VoiceTick #{}: {} speaking, {} silent users",
                        count, speaker_count, silent_count
                    );
                }

                // Reset the mixing buffer for this tick
                // Only clear as much as we'll use (optimization for fewer speakers)
                let buffer_capacity = mixing_buf.mixed.len();

                for (ssrc, voice_data) in tick.speaking.iter() {
                    // CRITICAL: Skip our own SSRC to prevent feedback loop
                    // When we send audio to Discord, it comes back in VoiceTick.
                    // If we don't filter it out, we get: SIP -> Discord -> SIP -> Discord -> ...
                    if let Some(ref map) = ssrc_map
                        && let Some(&user_id) = map.get(ssrc)
                        && user_id == self.bot_user_id
                    {
                        skipped_self = true;
                        if should_log {
                            trace!(
                                "VoiceTick: Skipping bot's own SSRC {} to prevent feedback",
                                ssrc
                            );
                        }
                        continue;
                    }

                    if let Some(ref decoded) = voice_data.decoded_voice {
                        if decoded.is_empty() {
                            if should_log {
                                trace!("VoiceTick: SSRC {} has empty decoded_voice", ssrc);
                            }
                            continue;
                        }

                        if should_log || count < 10 {
                            trace!(
                                "VoiceTick: SSRC {} has {} decoded samples",
                                ssrc,
                                decoded.len()
                            );
                        }

                        let len = decoded.len().min(buffer_capacity);

                        if !has_audio {
                            // First speaker - widen i16 to i32 using SIMD
                            simd::widen_i16_to_i32(&decoded[..len], &mut mixing_buf.mixed[..len]);
                            max_len = len;
                            has_audio = true;
                        } else {
                            // Mix in additional speakers using SIMD accumulate
                            let mix_len = len.min(max_len);
                            simd::accumulate_i16_to_i32(
                                &decoded[..mix_len],
                                &mut mixing_buf.mixed[..mix_len],
                            );
                            // Handle case where this speaker has more samples
                            if len > max_len {
                                simd::widen_i16_to_i32(
                                    &decoded[max_len..len],
                                    &mut mixing_buf.mixed[max_len..len],
                                );
                                max_len = len;
                            }
                        }
                    } else if should_log {
                        trace!(
                            "VoiceTick: SSRC {} has no decoded_voice (decode mode not enabled?)",
                            ssrc
                        );
                    }
                }

                // Log when we filtered out our own audio
                if skipped_self && should_log {
                    trace!("VoiceTick: Filtered out bot's own audio to prevent feedback loop");
                }

                // Diagnostic: Log when there are speakers but no decoded audio
                // This helps identify when Discord is sending data but decode isn't working
                let other_speaker_count = if skipped_self {
                    speaker_count.saturating_sub(1)
                } else {
                    speaker_count
                };
                if !has_audio && other_speaker_count > 0 {
                    // Count speakers without decoded audio
                    static NO_DECODE_COUNT: AtomicU64 = AtomicU64::new(0);
                    let no_decode = NO_DECODE_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
                    if no_decode <= 10 || no_decode.is_multiple_of(50) {
                        warn!(
                            "VoiceTick #{}: {} speakers but no decoded audio! (no_decode_count={})",
                            count, other_speaker_count, no_decode
                        );
                    }
                }

                // If we have audio, convert and send it using pre-allocated buffers
                if has_audio && max_len > 0 {
                    // Destructure to allow simultaneous borrows of different fields
                    let MixingBuffer {
                        ref mixed,
                        ref mut stereo_out,
                        ref mut mono_out,
                        ref mut resample_buf,
                    } = *mixing_buf;

                    // Convert i32 -> i16 with saturation using SIMD
                    let stereo_len = max_len.min(stereo_out.len());
                    simd::clamp_i32_to_i16(&mixed[..stereo_len], &mut stereo_out[..stereo_len]);

                    // Convert stereo to mono for SIP using SIMD
                    let mono_len = (stereo_len / 2).min(mono_out.len());
                    simd::stereo_to_mono_i16(&stereo_out[..stereo_len], &mut mono_out[..mono_len]);

                    // Check max amplitude for VAD using SIMD
                    let max_amp = simd::max_abs_i16(&mono_out[..mono_len]);

                    // VAD: Only send audio if it's above the silence threshold
                    // This prevents feedback loops and reduces unnecessary traffic
                    // Use same threshold as SIP→Discord for consistency
                    if max_amp < silence_threshold() {
                        if should_log {
                            trace!(
                                "VoiceTick: VAD filtering silence (max_amp={} < threshold={})",
                                max_amp,
                                silence_threshold()
                            );
                        }
                    } else if mono_len > 0 {
                        trace!(
                            "VoiceTick: {} speakers, {} mono samples, max amp: {}",
                            speaker_count, mono_len, max_amp
                        );

                        // Direct ring buffer path: resample 48kHz→16kHz and write to ring buffer
                        // This bypasses the entire tokio async round-trip through call/mod.rs
                        // Uses pre-allocated resample_buf to avoid per-tick Vec allocation
                        resample_audio_into(
                            &mono_out[..mono_len],
                            DISCORD_SAMPLE_RATE,
                            16000, // CONF_SAMPLE_RATE
                            resample_buf,
                        );
                        if !resample_buf.is_empty() {
                            write_discord_to_sip(self.channel_id, resample_buf);
                        }
                    }
                }
            }
            _ => {}
        }
        None
    }
}
