//! FaxSession state machine — manages a single incoming fax reception.
//!
//! Lifecycle:
//! 1. Created when a fax call is answered (ConnectFax route decision)
//! 2. Audio frames are fed via `feed_audio()`
//! 3. SpanDSP demodulates the fax tones into a TIFF file
//! 4. On completion, TIFF is converted to PNG and posted to Discord
//! 5. On failure or timeout, an error message is posted to Discord

use crate::fax::FaxError;
use crate::fax::discord_poster::DiscordPoster;
use crate::fax::spandsp::{FaxReceiver, FaxRxStatus, FaxT38Receiver};
use crate::fax::tiff_decoder;
use crate::services::snowflake::Snowflake;
use crate::transport::sip::CallId;
use std::io::Cursor;
use std::path::PathBuf;
use std::time::{Duration, Instant};
use tracing::{debug, error, info, warn};

/// Maximum time without observable T.30 progress. A completed page, negotiation
/// start, or advancing decoded row count refreshes this deadline.
const FAX_INACTIVITY_TIMEOUT_SECS: u64 = 300;

/// Absolute safety limit for a fax session, even while it continues to make
/// progress. This keeps pathological sessions bounded while allowing normal
/// multi-page faxes to run well beyond five minutes.
const FAX_SESSION_LIMIT_SECS: u64 = 30 * 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FaxTimeoutReason {
    Inactive,
    SessionLimit,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct FaxProgress {
    negotiation_started: bool,
    pages_received: u32,
    image_length: u32,
}

impl FaxProgress {
    fn has_advanced_from(self, previous: Self) -> bool {
        (self.negotiation_started && !previous.negotiation_started)
            || self.pages_received > previous.pages_received
            || (self.pages_received == previous.pages_received
                && self.image_length != previous.image_length)
    }
}

fn timeout_reason_at(
    created_at: Instant,
    last_progress_at: Instant,
    now: Instant,
) -> Option<FaxTimeoutReason> {
    if now.saturating_duration_since(created_at) >= Duration::from_secs(FAX_SESSION_LIMIT_SECS) {
        Some(FaxTimeoutReason::SessionLimit)
    } else if now.saturating_duration_since(last_progress_at)
        >= Duration::from_secs(FAX_INACTIVITY_TIMEOUT_SECS)
    {
        Some(FaxTimeoutReason::Inactive)
    } else {
        None
    }
}

/// How the fax audio is being received
pub enum FaxSource {
    /// G.711 audio passthrough
    G711Audio,
    /// T.38 UDPTL
    T38Udptl,
}

/// The active receiver — either audio-based or T.38 IFP-based.
enum FaxReceiverKind {
    /// G.711 audio passthrough (demodulates fax tones from audio samples)
    Audio(FaxReceiver),
    /// T.38 UDPTL (receives IFP packets directly)
    T38(FaxT38Receiver),
}

/// Current state of the fax reception
pub enum FaxState {
    /// Answered, feeding audio to SpanDSP, waiting for fax negotiation
    WaitingForData,
    /// SpanDSP confirmed fax negotiation started
    Receiving {
        /// Number of pages received so far
        pages_received: u32,
    },
    /// SpanDSP signaled fax complete, awaiting conversion and Discord posting
    Received,
    /// Fax posted to Discord successfully
    Complete,
    /// Fax reception failed
    Failed(String),
}

/// A single fax reception session
pub struct FaxSession {
    /// SIP call ID for this fax
    pub call_id: CallId,
    /// Discord text channel to post the fax to
    pub text_channel_id: Snowflake,
    /// Guild ID (for logging)
    pub guild_id: Snowflake,
    /// User ID who owns this mapping
    pub user_id: String,
    /// Current state
    pub state: FaxState,
    /// How we're receiving the fax
    pub source: FaxSource,
    /// When this session was created
    pub created_at: Instant,
    /// Most recent time SpanDSP reported observable fax progress.
    last_progress_at: Instant,
    /// Last observed progress marker, used to avoid extending the timeout for
    /// duplicate packets or timer ticks that do not advance the fax.
    last_progress: FaxProgress,
    /// Discord poster for this session
    pub poster: DiscordPoster,
    /// SpanDSP fax receiver (audio or T.38 mode)
    receiver: FaxReceiverKind,
    /// Temp directory for this fax session's TIFF output
    pub tiff_dir: PathBuf,
    /// Discord message ID for the "Receiving fax..." status message.
    /// Stored separately so it survives state transitions to Complete/Failed.
    receiving_message_id: Option<u64>,
}

impl FaxSession {
    /// Create a new fax session. Initializes SpanDSP in receive mode.
    pub fn new(
        call_id: CallId,
        text_channel_id: Snowflake,
        guild_id: Snowflake,
        user_id: String,
        bot_token: String,
    ) -> Result<Self, FaxError> {
        let fax_config = crate::config::AppConfig::fax();

        // Use configured tmp_folder or system temp dir
        let base_dir = fax_config
            .tmp_folder
            .clone()
            .unwrap_or_else(std::env::temp_dir);

        // Generate a unique session ID for the filename
        let session_id = format!("{:016x}", {
            use std::time::{SystemTime, UNIX_EPOCH};
            let t = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default();
            // Mix timestamp with call_id using a prime constant for a unique session ID
            t.as_nanos() as u64 ^ (*call_id as u64).wrapping_mul(0x517cc1b727220a95)
        });

        let tiff_dir = base_dir.join(format!("{}{}", fax_config.prefix, session_id));
        std::fs::create_dir_all(&tiff_dir).map_err(|source| FaxError::Io {
            context: format!("create tiff dir {}", tiff_dir.display()),
            source,
        })?;
        let tiff_path = tiff_dir.join(format!("{}{}.tiff", fax_config.prefix, session_id));

        let receiver = FaxReceiver::new_audio_receiver(&tiff_path)?;

        let poster = DiscordPoster::new(bot_token, text_channel_id, user_id.clone())?;

        let now = Instant::now();

        Ok(Self {
            call_id,
            text_channel_id,
            guild_id,
            user_id,
            state: FaxState::WaitingForData,
            source: FaxSource::G711Audio,
            created_at: now,
            last_progress_at: now,
            last_progress: FaxProgress::default(),
            poster,
            receiver: FaxReceiverKind::Audio(receiver),
            tiff_dir,
            receiving_message_id: None,
        })
    }

    /// Feed audio samples from the SIP call (16kHz mono i16).
    /// Downsamples to 8kHz and feeds to SpanDSP's fax_rx().
    /// Returns true if the fax is complete and ready for post-processing.
    /// Only works in Audio mode — logs a warning and returns false if called in T.38 mode.
    pub fn feed_audio(&mut self, samples: &[i16]) -> bool {
        if self.is_finished() {
            return matches!(self.state, FaxState::Received | FaxState::Complete);
        }

        let receiver = match &mut self.receiver {
            FaxReceiverKind::Audio(r) => r,
            FaxReceiverKind::T38(_) => {
                warn!("feed_audio called on T.38 session {}", self.call_id);
                return false;
            }
        };

        let status = receiver.feed_samples_16k(samples);
        self.handle_rx_status(status)
    }

    /// Feed a T.38 IFP packet from the UDPTL socket to SpanDSP.
    /// Returns true if the fax is complete and ready for post-processing.
    /// Only works in T.38 mode.
    pub fn feed_t38_ifp(&mut self, data: &[u8], seq: u16) -> bool {
        if self.is_finished() {
            return matches!(self.state, FaxState::Received | FaxState::Complete);
        }

        let receiver = match &mut self.receiver {
            FaxReceiverKind::T38(r) => r,
            FaxReceiverKind::Audio(_) => {
                warn!("feed_t38_ifp called on audio session {}", self.call_id);
                return false;
            }
        };

        let status = receiver.feed_ifp_packet(data, seq);
        self.handle_rx_status(status)
    }

    /// Drive the T.38 terminal timer (call every 20ms).
    /// Returns true if the fax is complete and ready for post-processing.
    pub fn drive_t38_timer(&mut self) -> bool {
        if self.is_finished() {
            return matches!(self.state, FaxState::Received | FaxState::Complete);
        }

        let receiver = match &mut self.receiver {
            FaxReceiverKind::T38(r) => r,
            FaxReceiverKind::Audio(_) => return false,
        };

        let status = receiver.drive_timer();
        self.handle_rx_status(status)
    }

    /// Common handler for FaxRxStatus from either audio or T.38 receiver.
    fn handle_rx_status(&mut self, status: FaxRxStatus) -> bool {
        // Log stats on completion/error before delegating to pure state transition
        match &status {
            FaxRxStatus::Complete => {
                if let Some(stats) = self.get_stats() {
                    info!(
                        "Fax {} complete: {} pages, {}bps, {}x{}, ECM={}, bad_rows={}",
                        self.call_id,
                        stats.pages_rx,
                        stats.bit_rate,
                        stats.image_width,
                        stats.image_length,
                        stats.ecm,
                        stats.bad_rows
                    );
                }
            }
            FaxRxStatus::Error(msg) => {
                if let Some(stats) = self.get_stats() {
                    warn!(
                        "Fax {} failed: {} ({}bps, {}x{}, ECM={}, pages_rx={}, bad_rows={}, audio={:.1}s)",
                        self.call_id,
                        msg,
                        stats.bit_rate,
                        stats.image_width,
                        stats.image_length,
                        stats.ecm,
                        stats.pages_rx,
                        stats.bad_rows,
                        self.audio_duration_secs()
                    );
                } else {
                    warn!(
                        "Fax {} failed: {} (no stats, audio={:.1}s)",
                        self.call_id,
                        msg,
                        self.audio_duration_secs()
                    );
                }
            }
            FaxRxStatus::InProgress => {}
        }

        let page_count = self.pages_received();
        let progress = FaxProgress {
            negotiation_started: self.negotiation_started(),
            pages_received: page_count,
            image_length: self
                .get_stats()
                .map(|stats| stats.image_length.max(0) as u32)
                .unwrap_or(0),
        };
        self.observe_progress(progress);
        apply_rx_status(&mut self.state, status, page_count)
    }

    fn negotiation_started(&self) -> bool {
        match &self.receiver {
            FaxReceiverKind::Audio(r) => r.negotiation_started(),
            FaxReceiverKind::T38(r) => r.negotiation_started(),
        }
    }

    fn observe_progress(&mut self, progress: FaxProgress) {
        if progress.has_advanced_from(self.last_progress) {
            let log_milestone = progress.negotiation_started
                != self.last_progress.negotiation_started
                || progress.pages_received != self.last_progress.pages_received;
            self.last_progress = progress;
            self.last_progress_at = Instant::now();
            if log_milestone {
                debug!(
                    "Fax {} progress: negotiation={}, pages={}, rows={}",
                    self.call_id,
                    progress.negotiation_started,
                    progress.pages_received,
                    progress.image_length
                );
            }
        }
    }

    /// Number of pages received so far.
    pub fn pages_received(&self) -> u32 {
        match &self.receiver {
            FaxReceiverKind::Audio(r) => r.pages_received(),
            FaxReceiverKind::T38(r) => r.pages_received(),
        }
    }

    /// Get transfer statistics from SpanDSP.
    fn get_stats(&self) -> Option<crate::fax::spandsp::FaxStats> {
        match &self.receiver {
            FaxReceiverKind::Audio(r) => r.get_stats(),
            FaxReceiverKind::T38(r) => r.get_stats(),
        }
    }

    /// Check if this session has timed out
    pub fn is_timed_out(&self) -> bool {
        timeout_reason_at(self.created_at, self.last_progress_at, Instant::now()).is_some()
    }

    /// Check if the session is in a terminal state
    pub fn is_finished(&self) -> bool {
        matches!(
            self.state,
            FaxState::Received | FaxState::Complete | FaxState::Failed(_)
        )
    }

    /// Post the initial "Receiving fax..." message to Discord.
    /// Called when fax negotiation is detected.
    pub async fn post_receiving_message(&mut self) -> Result<(), FaxError> {
        match self.poster.post_fax_receiving().await {
            Ok(msg_id) => {
                debug!(
                    "Posted 'Receiving fax...' message {} to channel {} (call {})",
                    msg_id, self.text_channel_id, self.call_id
                );
                self.receiving_message_id = Some(msg_id);
                self.state = FaxState::Receiving { pages_received: 0 };
                Ok(())
            }
            Err(e) => {
                error!(
                    "Failed to post receiving message to channel {}: {}",
                    self.text_channel_id, e
                );
                self.state = FaxState::Failed(format!("Discord error: {}", e));
                Err(e)
            }
        }
    }

    /// Post a failure message to Discord
    pub async fn post_failure(&mut self, reason: &str) {
        if let Some(discord_msg_id) = self.receiving_message_id {
            if let Err(e) = self.poster.edit_fax_failed(discord_msg_id, reason).await {
                error!("Failed to edit fax failure message: {}", e);
            }
        } else {
            // No receiving message was posted — post a standalone failure
            if let Err(e) = self.poster.post_fax_failed(reason).await {
                error!("Failed to post fax failure message: {}", e);
            }
        }
        self.state = FaxState::Failed(reason.to_string());
    }

    /// Convert the received TIFF to images and post to Discord.
    /// Called after fax reception is complete.
    pub async fn convert_and_post(&mut self) -> Result<(), FaxError> {
        // Guard against double-processing: if we've already posted (Complete) or failed,
        // another caller (e.g., CallEnded racing with T.38 completion) already handled it.
        // Note: FaxState::Received is NOT skipped — that's the normal entry state.
        if matches!(self.state, FaxState::Complete | FaxState::Failed(_)) {
            debug!(
                "convert_and_post called on already-finished session {} — skipping",
                self.call_id
            );
            return Ok(());
        }

        let (tiff_path, pages) = match &self.receiver {
            FaxReceiverKind::Audio(r) => (
                r.tiff_output_path().to_path_buf(),
                r.pages_received().max(1),
            ),
            FaxReceiverKind::T38(r) => (
                r.tiff_output_path().to_path_buf(),
                r.pages_received().max(1),
            ),
        };
        let tiff_path = &tiff_path;

        let fax_config = crate::config::AppConfig::fax();
        let (output_format, file_ext) = match fax_config.output_format.as_str() {
            "jpg" | "jpeg" => (OutputFormat::Jpeg, "jpg"),
            _ => (OutputFormat::Png, "png"),
        };

        debug!(
            "Converting TIFF to {} for call {}: {} ({} pages)",
            output_format.label(),
            self.call_id,
            tiff_path.display(),
            pages
        );

        let gray_images = match tiff_decoder::decode_fax_tiff(tiff_path) {
            Ok(images) => images,
            Err(error @ FaxError::CorruptPageData(_)) => {
                warn!(
                    call_id = %self.call_id,
                    error = ?error,
                    "Rejecting corrupt/incomplete fax page data"
                );
                let user_message = error.to_string();
                self.post_failure(&user_message).await;

                // The failure has been reported. Returning Ok prevents the
                // caller from replacing the specific message with its generic
                // conversion-failure fallback.
                return Ok(());
            }
            Err(error) => return Err(error),
        };
        let image_pages: Vec<Vec<u8>> = gray_images
            .into_iter()
            .map(|img| {
                let mut buf = Vec::new();
                image::DynamicImage::ImageLuma8(img)
                    .write_to(&mut Cursor::new(&mut buf), output_format.image_format())
                    .map(|_| buf)
            })
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| FaxError::Tiff(format!("image encode: {e}")))?;

        if image_pages.is_empty() {
            self.post_failure("No pages in received fax").await;
            return Err(FaxError::NoPages);
        }

        let page_count = image_pages.len() as u32;

        if let Some(discord_msg_id) = self.receiving_message_id {
            match self
                .poster
                .edit_fax_complete(discord_msg_id, image_pages, page_count, file_ext)
                .await
            {
                Ok(()) => {
                    info!(
                        "Fax complete: {} pages posted to channel {} (call {})",
                        page_count, self.text_channel_id, self.call_id
                    );
                    self.state = FaxState::Complete;
                }
                Err(e) => {
                    error!("Failed to post completed fax: {}", e);
                    self.state = FaxState::Failed(format!("Discord upload error: {}", e));
                    return Err(e);
                }
            }
        } else {
            // If we never posted a "receiving" message (e.g., fast fax), post directly
            // This shouldn't normally happen since we post receiving message early
            warn!("Fax completed without a receiving message — posting directly");
            match self.poster.post_fax_receiving().await {
                Ok(msg_id) => {
                    self.receiving_message_id = Some(msg_id);
                    self.poster
                        .edit_fax_complete(msg_id, image_pages, page_count, file_ext)
                        .await?;
                    self.state = FaxState::Complete;
                }
                Err(e) => {
                    error!("Failed to post fax: {}", e);
                    self.state = FaxState::Failed(format!("Discord error: {}", e));
                    return Err(e);
                }
            }
        }

        Ok(())
    }

    /// Switch from G.711 audio mode to T.38 UDPTL mode.
    ///
    /// Replaces the audio receiver with a T.38 receiver. The caller must:
    /// 1. Stop feeding audio samples (remove fax audio port)
    /// 2. Start the UDPTL processing tasks (rx, tx, timer)
    pub fn switch_to_t38(&mut self, t38_receiver: FaxT38Receiver) {
        debug!("Fax session {} switching from G.711 to T.38", self.call_id);
        self.source = FaxSource::T38Udptl;
        self.receiver = FaxReceiverKind::T38(t38_receiver);
        self.last_progress = FaxProgress::default();
        self.last_progress_at = Instant::now();
    }

    /// Generate transmit audio from SpanDSP (CED tones, T.30 signaling).
    ///
    /// Only works in Audio mode — T.38 uses IFP packets, not audio.
    /// `out_buf` should be 320 samples (20ms at 16kHz).
    /// Returns the number of 16kHz samples written.
    pub fn generate_tx_16k(&mut self, out_buf: &mut [i16]) -> usize {
        match &mut self.receiver {
            FaxReceiverKind::Audio(r) => r.generate_tx_16k(out_buf),
            FaxReceiverKind::T38(_) => 0,
        }
    }

    /// Get the total audio duration received so far (for debugging).
    /// Returns 0 in T.38 mode (no audio samples).
    pub fn audio_duration_secs(&self) -> f64 {
        match &self.receiver {
            FaxReceiverKind::Audio(r) => r.audio_duration_secs(),
            FaxReceiverKind::T38(_) => 0.0,
        }
    }
}

impl Drop for FaxSession {
    fn drop(&mut self) {
        let status = match &self.state {
            FaxState::WaitingForData => "waiting_for_data",
            FaxState::Receiving { .. } => "receiving",
            FaxState::Received => "received",
            FaxState::Complete => "complete",
            FaxState::Failed(reason) => {
                debug!("Fax failure reason: {}", reason);
                "failed"
            }
        };
        debug!(
            "FaxSession dropped: call={}, channel={}, guild={}, user={}, status={}, duration={:.1}s, audio={:.1}s",
            self.call_id,
            self.text_channel_id,
            self.guild_id,
            self.user_id,
            status,
            self.created_at.elapsed().as_secs_f64(),
            self.audio_duration_secs()
        );
        if let Err(e) = std::fs::remove_dir_all(&self.tiff_dir) {
            debug!(
                "Failed to clean up fax temp dir {}: {}",
                self.tiff_dir.display(),
                e
            );
        } else {
            debug!("Cleaned up fax temp dir: {}", self.tiff_dir.display());
        }
    }
}

// Pure state transition logic (extracted for testability)

/// Apply a FaxRxStatus to a FaxState, returning whether the fax is complete.
/// This is the core state transition logic used by `FaxSession::handle_rx_status`.
fn apply_rx_status(state: &mut FaxState, status: FaxRxStatus, page_count: u32) -> bool {
    match status {
        FaxRxStatus::InProgress => {
            if let FaxState::Receiving { pages_received, .. } = state {
                *pages_received = page_count;
            }
            false
        }
        FaxRxStatus::Complete => {
            *state = FaxState::Received;
            true
        }
        FaxRxStatus::Error(msg) => {
            *state = FaxState::Failed(msg);
            false
        }
    }
}

// Output format

#[derive(Debug, Clone, Copy)]
enum OutputFormat {
    Png,
    Jpeg,
}

impl OutputFormat {
    fn image_format(self) -> image::ImageFormat {
        match self {
            OutputFormat::Png => image::ImageFormat::Png,
            OutputFormat::Jpeg => image::ImageFormat::Jpeg,
        }
    }

    fn label(self) -> &'static str {
        match self {
            OutputFormat::Png => "PNG",
            OutputFormat::Jpeg => "JPEG",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Helper: check if a FaxState is_finished (mirrors FaxSession::is_finished logic)
    fn state_is_finished(state: &FaxState) -> bool {
        matches!(
            state,
            FaxState::Received | FaxState::Complete | FaxState::Failed(_)
        )
    }

    // is_finished tests

    #[test]
    fn is_finished_waiting_for_data() {
        assert!(!state_is_finished(&FaxState::WaitingForData));
    }

    #[test]
    fn is_finished_receiving() {
        assert!(!state_is_finished(&FaxState::Receiving {
            pages_received: 0
        }));
    }

    #[test]
    fn is_finished_received() {
        assert!(state_is_finished(&FaxState::Received));
    }

    #[test]
    fn is_finished_complete() {
        assert!(state_is_finished(&FaxState::Complete));
    }

    #[test]
    fn is_finished_failed() {
        assert!(state_is_finished(&FaxState::Failed("err".to_string())));
    }

    // Timeout policy tests

    #[test]
    fn fresh_session_is_not_timed_out() {
        let now = Instant::now();
        assert_eq!(timeout_reason_at(now, now, now), None);
    }

    #[test]
    fn inactivity_timeout_fires_at_deadline() {
        let created_at = Instant::now();
        let now = created_at + Duration::from_secs(FAX_INACTIVITY_TIMEOUT_SECS);
        assert_eq!(
            timeout_reason_at(created_at, created_at, now),
            Some(FaxTimeoutReason::Inactive)
        );
    }

    #[test]
    fn progress_extends_session_past_old_five_minute_limit() {
        let created_at = Instant::now();
        let last_progress_at = created_at + Duration::from_secs(280);
        let now = created_at + Duration::from_secs(360);

        assert_eq!(timeout_reason_at(created_at, last_progress_at, now), None);
    }

    #[test]
    fn progress_does_not_extend_hard_session_limit() {
        let created_at = Instant::now();
        let last_progress_at = created_at + Duration::from_secs(FAX_SESSION_LIMIT_SECS - 1);
        let now = created_at + Duration::from_secs(FAX_SESSION_LIMIT_SECS);

        assert_eq!(
            timeout_reason_at(created_at, last_progress_at, now),
            Some(FaxTimeoutReason::SessionLimit)
        );
    }

    #[test]
    fn completed_page_is_progress() {
        let previous = FaxProgress {
            negotiation_started: true,
            pages_received: 1,
            image_length: 2200,
        };
        let current = FaxProgress {
            negotiation_started: true,
            pages_received: 2,
            image_length: 0,
        };

        assert!(current.has_advanced_from(previous));
    }

    #[test]
    fn duplicate_progress_marker_does_not_extend_timeout() {
        let progress = FaxProgress {
            negotiation_started: true,
            pages_received: 1,
            image_length: 2200,
        };

        assert!(!progress.has_advanced_from(progress));
    }

    #[test]
    fn advancing_rows_is_progress_before_page_completion() {
        let previous = FaxProgress {
            negotiation_started: true,
            pages_received: 0,
            image_length: 100,
        };
        let current = FaxProgress {
            image_length: 101,
            ..previous
        };

        assert!(current.has_advanced_from(previous));
    }

    #[test]
    fn row_count_reset_at_page_boundary_is_progress() {
        let previous = FaxProgress {
            negotiation_started: true,
            pages_received: 1,
            image_length: 2200,
        };
        let current = FaxProgress {
            image_length: 0,
            ..previous
        };

        assert!(current.has_advanced_from(previous));
    }

    // apply_rx_status tests

    #[test]
    fn apply_rx_status_in_progress_on_waiting() {
        let mut state = FaxState::WaitingForData;
        let result = apply_rx_status(&mut state, FaxRxStatus::InProgress, 0);
        assert!(!result);
        assert!(matches!(state, FaxState::WaitingForData));
    }

    #[test]
    fn apply_rx_status_in_progress_on_receiving_updates_pages() {
        let mut state = FaxState::Receiving { pages_received: 0 };
        let result = apply_rx_status(&mut state, FaxRxStatus::InProgress, 3);
        assert!(!result);
        match state {
            FaxState::Receiving { pages_received } => assert_eq!(pages_received, 3),
            _ => panic!("Expected Receiving state"),
        }
    }

    #[test]
    fn apply_rx_status_complete_transitions_to_received() {
        let mut state = FaxState::Receiving { pages_received: 1 };
        let result = apply_rx_status(&mut state, FaxRxStatus::Complete, 1);
        assert!(result);
        assert!(matches!(state, FaxState::Received));
    }

    #[test]
    fn apply_rx_status_error_transitions_to_failed() {
        let mut state = FaxState::WaitingForData;
        let result = apply_rx_status(&mut state, FaxRxStatus::Error("timeout".to_string()), 0);
        assert!(!result);
        match state {
            FaxState::Failed(msg) => assert_eq!(msg, "timeout"),
            _ => panic!("Expected Failed state"),
        }
    }

    #[test]
    fn apply_rx_status_idempotent_on_terminal_complete() {
        // Once in Received, InProgress should not change the state
        let mut state = FaxState::Received;
        let result = apply_rx_status(&mut state, FaxRxStatus::InProgress, 0);
        assert!(!result);
        assert!(matches!(state, FaxState::Received));
    }

    #[test]
    fn apply_rx_status_idempotent_on_terminal_failed() {
        let mut state = FaxState::Failed("original".to_string());
        let result = apply_rx_status(&mut state, FaxRxStatus::InProgress, 0);
        assert!(!result);
        match state {
            FaxState::Failed(msg) => assert_eq!(msg, "original"),
            _ => panic!("Expected Failed state"),
        }
    }
}
