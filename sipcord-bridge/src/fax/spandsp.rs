//! SpanDSP wrapper for fax demodulation.
//!
//! Uses the `spandsp` safe wrapper crate to decode G.711 audio into TIFF images.
//! Audio arrives at 16kHz from PJSUA conference bridge; we downsample to 8kHz for SpanDSP.

use anyhow::{Context, Result};
use spandsp::fax::FaxState;
use spandsp::logging::{LogLevel, LogShowFlags};
use spandsp::spandsp_sys;
use spandsp::t30::T30ModemSupport;
use spandsp::t38_terminal::T38Terminal;
use std::path::{Path, PathBuf};
use tokio::sync::mpsc;
use tracing::{debug, error, info, trace, warn};

// T.4 image compression types (bitmask for t30_set_supported_compressions)
const T4_COMPRESSION_T4_1D: i32 = spandsp_sys::t4_image_compression_t_T4_COMPRESSION_T4_1D as i32;
const T4_COMPRESSION_T4_2D: i32 = spandsp_sys::t4_image_compression_t_T4_COMPRESSION_T4_2D as i32;
const T4_COMPRESSION_T6: i32 = spandsp_sys::t4_image_compression_t_T4_COMPRESSION_T6 as i32;

// T.4 supported image widths (bitmask for t30_set_supported_image_sizes)
// These are #defines in the C header that bindgen doesn't capture as constants.
// Values from spandsp/t4_rx.h: T4_SUPPORT_WIDTH_215MM=0x01, 255MM=0x02, 303MM=0x04
const T4_SUPPORT_WIDTH_215MM: i32 = 0x01;
const T4_SUPPORT_WIDTH_255MM: i32 = 0x02;
const T4_SUPPORT_WIDTH_303MM: i32 = 0x04;

// T.4 supported resolutions (bitmask, OR'd into the same sizes parameter)
// Values from spandsp/t4_rx.h
const T4_RESOLUTION_R8_STANDARD: i32 = 0x01; // 204×98 DPI
const T4_RESOLUTION_R8_FINE: i32 = 0x02; // 204×196 DPI
const T4_RESOLUTION_R8_SUPERFINE: i32 = 0x04; // 204×391 DPI
const T4_RESOLUTION_200_200: i32 = 0x40; // 200×200 DPI

/// Status returned after processing audio
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FaxRxStatus {
    /// Still processing, no state change
    InProgress,
    /// Fax reception completed successfully
    Complete,
    /// Error during reception
    Error(String),
}

/// Callbacks from SpanDSP via the T.30 phase handlers.
/// These track progress but don't drive control flow — FaxSession checks
/// the receiver's state after each feed_samples() call.
struct FaxCallbackState {
    /// Whether phase B (negotiation) has been entered
    negotiation_started: bool,
    /// Number of pages received (phase D count)
    pages_received: u32,
    /// Final completion code from phase E (-1 = not yet completed)
    completion_code: i32,
    /// Whether phase E (completion) has fired
    completed: bool,
}

/// Summary statistics from a fax reception.
#[derive(Debug)]
pub struct FaxStats {
    pub bit_rate: i32,
    pub pages_rx: i32,
    pub image_width: i32,
    pub image_length: i32,
    pub bad_rows: i32,
    pub ecm: bool,
}

// Shared helpers

/// Configure T.30 session parameters, set output TIFF, and register phase handlers.
fn configure_t30(
    t30: &spandsp::t30::T30State,
    tiff_path: &str,
    callback_state: &mut FaxCallbackState,
) -> Result<()> {
    t30.set_rx_file(tiff_path, -1)
        .map_err(|e| anyhow::anyhow!("Failed to set rx file: {}", e))?;

    t30.set_supported_modems(T30ModemSupport::default())
        .map_err(|e| anyhow::anyhow!("Failed to set supported modems: {}", e))?;

    t30.set_ecm_capability(true)
        .map_err(|e| anyhow::anyhow!("Failed to set ECM: {}", e))?;

    let compressions = T4_COMPRESSION_T4_1D | T4_COMPRESSION_T4_2D | T4_COMPRESSION_T6;
    t30.set_supported_compressions(compressions)
        .map_err(|e| anyhow::anyhow!("Failed to set compressions: {}", e))?;

    let sizes = T4_SUPPORT_WIDTH_215MM
        | T4_SUPPORT_WIDTH_255MM
        | T4_SUPPORT_WIDTH_303MM
        | T4_RESOLUTION_R8_STANDARD
        | T4_RESOLUTION_R8_FINE
        | T4_RESOLUTION_R8_SUPERFINE
        | T4_RESOLUTION_200_200;
    t30.set_supported_image_sizes(sizes)
        .map_err(|e| anyhow::anyhow!("Failed to set image sizes: {}", e))?;

    let user_data = callback_state as *mut FaxCallbackState as *mut std::ffi::c_void;
    unsafe {
        t30.set_phase_b_handler_raw(Some(phase_b_handler), user_data);
        t30.set_phase_d_handler_raw(Some(phase_d_handler), user_data);
        t30.set_phase_e_handler_raw(Some(phase_e_handler), user_data);
    }

    Ok(())
}

/// Configure a SpanDSP logging state to route messages to tracing.
unsafe fn configure_log_state(log_state: *mut spandsp_sys::logging_state_t) {
    if log_state.is_null() {
        return;
    }
    let log_level = LogLevel::Flow as i32 | LogShowFlags::TAG.bits();
    unsafe {
        spandsp_sys::span_log_set_level(log_state, log_level);
        spandsp_sys::span_log_set_message_handler(
            log_state,
            Some(spandsp_log_handler),
            std::ptr::null_mut(),
        );
    }
}

/// Check fax reception completion status from callback state.
fn check_completion(state: &FaxCallbackState) -> FaxRxStatus {
    if state.completed {
        match spandsp::t30::T30State::completion_code(state.completion_code) {
            Some(err) if err.is_ok() => FaxRxStatus::Complete,
            Some(err) => FaxRxStatus::Error(format!("Fax failed: {}", err)),
            None => FaxRxStatus::Error(format!(
                "Fax failed with unknown T.30 error code {}",
                state.completion_code
            )),
        }
    } else {
        FaxRxStatus::InProgress
    }
}

/// Extract transfer statistics from a T.30 state.
fn get_fax_stats(t30: &spandsp::t30::T30State) -> FaxStats {
    let stats = t30.get_transfer_statistics();
    FaxStats {
        bit_rate: stats.bit_rate,
        pages_rx: stats.pages_rx,
        image_width: stats.image_width,
        image_length: stats.image_length,
        bad_rows: stats.bad_rows,
        ecm: stats.error_correcting_mode != 0,
    }
}

// Pure resampling helpers (extracted for testability)

/// Downsample 16kHz→8kHz by averaging consecutive pairs.
/// Appends `samples` to `buf` (accumulator), drains pairs, returns 8kHz samples.
/// Leftover odd samples remain in `buf` for the next call.
fn downsample_16k_to_8k(buf: &mut Vec<i16>, samples: &[i16]) -> Vec<i16> {
    buf.extend_from_slice(samples);
    let pairs = buf.len() / 2;
    if pairs == 0 {
        return Vec::new();
    }
    let mut out = Vec::with_capacity(pairs);
    for i in 0..pairs {
        let a = buf[i * 2] as i32;
        let b = buf[i * 2 + 1] as i32;
        out.push(((a + b) / 2) as i16);
    }
    let consumed = pairs * 2;
    buf.drain(..consumed);
    out
}

/// Upsample 8kHz→16kHz by duplicating each sample.
/// Writes to `out`, returns number of 16kHz samples written (= input_len * 2).
fn upsample_8k_to_16k(samples_8k: &[i16], out: &mut [i16]) -> usize {
    for (i, &s) in samples_8k.iter().enumerate() {
        out[i * 2] = s;
        out[i * 2 + 1] = s;
    }
    samples_8k.len() * 2
}

// Audio-based fax receiver

/// SpanDSP fax receiver — wraps `FaxState` for receiving faxes from audio.
pub struct FaxReceiver {
    fax: FaxState,
    tiff_path: PathBuf,
    callback_state: Box<FaxCallbackState>,
    /// Downsampling buffer: accumulates 16kHz samples, emits 8kHz
    downsample_buf: Vec<i16>,
    /// Total 8kHz samples fed to SpanDSP
    samples_fed: usize,
}

// FaxState is Send (via unsafe impl in the spandsp crate).
// Box<FaxCallbackState> and Vec<i16> are Send.
// We ensure exclusive access via tokio::sync::Mutex in FaxSession.
unsafe impl Send for FaxReceiver {}

impl FaxReceiver {
    /// Create a new fax receiver in audio mode.
    ///
    /// Initializes SpanDSP in receive mode and sets the output TIFF path.
    pub fn new_audio_receiver(tiff_path: &Path) -> Result<Self> {
        let tiff_path_str = tiff_path.to_str().context("Invalid TIFF path")?;

        let fax = FaxState::new(false)
            .map_err(|e| anyhow::anyhow!("Failed to initialize SpanDSP fax state: {}", e))?;

        let t30 = fax
            .get_t30_state()
            .map_err(|e| anyhow::anyhow!("Failed to get T.30 state: {}", e))?;

        let mut callback_state = Box::new(FaxCallbackState {
            negotiation_started: false,
            pages_received: 0,
            completion_code: -1,
            completed: false,
        });

        configure_t30(&t30, tiff_path_str, &mut callback_state)?;

        // Route SpanDSP log messages to tracing.
        // We use raw spandsp_sys functions since LoggingState doesn't
        // support borrowed pointers from parent objects safely yet.
        unsafe {
            configure_log_state(spandsp_sys::fax_get_logging_state(fax.as_ptr()));
            configure_log_state(spandsp_sys::t30_get_logging_state(t30.as_ptr()));
        }

        debug!(
            "SpanDSP fax receiver initialized, output: {}",
            tiff_path.display()
        );

        Ok(Self {
            fax,
            tiff_path: tiff_path.to_path_buf(),
            callback_state,
            downsample_buf: Vec::with_capacity(640), // 2 frames worth
            samples_fed: 0,
        })
    }

    /// Feed 16kHz mono i16 audio samples (from PJSUA conference bridge).
    ///
    /// Downsamples to 8kHz and passes to SpanDSP's `fax_rx()`.
    /// Returns the current reception status.
    pub fn feed_samples_16k(&mut self, samples: &[i16]) -> FaxRxStatus {
        let mut downsampled = downsample_16k_to_8k(&mut self.downsample_buf, samples);
        if downsampled.is_empty() {
            return self.current_status();
        }
        self.feed_samples_8k(&mut downsampled)
    }

    /// Feed 8kHz mono i16 audio samples directly to SpanDSP.
    fn feed_samples_8k(&mut self, samples: &mut [i16]) -> FaxRxStatus {
        if samples.is_empty() {
            return self.current_status();
        }

        let _result = self.fax.rx(samples);
        self.samples_fed += samples.len();

        if self.samples_fed.is_multiple_of(80000) {
            // Log every 10 seconds of audio
            trace!("SpanDSP fed {}s of audio", self.samples_fed as f64 / 8000.0,);
        }

        self.current_status()
    }

    /// Check the current status based on callback state.
    fn current_status(&self) -> FaxRxStatus {
        check_completion(&self.callback_state)
    }

    /// Number of pages received so far.
    pub fn pages_received(&self) -> u32 {
        self.callback_state.pages_received
    }

    /// Get the output TIFF file path.
    pub fn tiff_output_path(&self) -> &Path {
        &self.tiff_path
    }

    /// Generate transmit audio from SpanDSP (CED tones, T.30 signaling).
    ///
    /// SpanDSP generates at 8kHz; we upsample to 16kHz for the conference bridge.
    /// `out_buf` must be large enough for 16kHz samples (e.g., 320 for 20ms).
    /// Returns the number of 16kHz samples written.
    pub fn generate_tx_16k(&mut self, out_buf: &mut [i16]) -> usize {
        let max_8k_samples = out_buf.len() / 2;
        let mut buf_8k = vec![0i16; max_8k_samples];
        let generated = self.fax.tx(&mut buf_8k);
        if generated == 0 {
            return 0;
        }
        upsample_8k_to_16k(&buf_8k[..generated], out_buf)
    }

    /// Total seconds of audio fed (at 8kHz).
    pub fn audio_duration_secs(&self) -> f64 {
        self.samples_fed as f64 / 8000.0
    }

    /// Get transfer statistics from SpanDSP (for logging).
    pub fn get_stats(&self) -> Option<FaxStats> {
        let t30 = self.fax.get_t30_state().ok()?;
        Some(get_fax_stats(&t30))
    }
}

// T.38 IFP-based receiver (UDPTL mode)

/// State passed to the T.38 TX packet handler callback.
/// When SpanDSP wants to send an IFP packet, we push it into the mpsc channel.
struct TxCallbackState {
    sender: mpsc::UnboundedSender<Vec<u8>>,
}

/// SpanDSP fax receiver using T.38 IFP packets (via T38Terminal).
///
/// Instead of demodulating audio, this receives IFP packets from the UDPTL
/// socket and feeds them to SpanDSP's T38Terminal, which handles the T.30
/// protocol directly over T.38.
pub struct FaxT38Receiver {
    terminal: T38Terminal,
    tiff_path: PathBuf,
    callback_state: Box<FaxCallbackState>,
    _tx_callback_state: Box<TxCallbackState>,
}

// T38Terminal is Send (via unsafe impl in spandsp-rs crate).
// Box<FaxCallbackState> and Box<TxCallbackState> are Send.
// We ensure exclusive access via tokio::sync::Mutex in FaxSession.
unsafe impl Send for FaxT38Receiver {}

impl FaxT38Receiver {
    /// Create a new T.38 fax receiver.
    ///
    /// `tiff_path`: Where to write the received fax TIFF file.
    /// `tx_ifp_sender`: Channel for outgoing IFP packets (sent to UDPTL socket).
    pub fn new(tiff_path: &Path, tx_ifp_sender: mpsc::UnboundedSender<Vec<u8>>) -> Result<Self> {
        let tiff_path_str = tiff_path.to_str().context("Invalid TIFF path")?;

        let tx_callback_state = Box::new(TxCallbackState {
            sender: tx_ifp_sender,
        });
        let tx_user_data = &*tx_callback_state as *const TxCallbackState as *mut std::ffi::c_void;

        let terminal = unsafe {
            T38Terminal::new_raw(false, Some(tx_packet_handler), tx_user_data)
                .map_err(|e| anyhow::anyhow!("Failed to initialize T38Terminal: {}", e))?
        };

        let t30 = terminal
            .get_t30_state()
            .map_err(|e| anyhow::anyhow!("Failed to get T.30 state from T38Terminal: {}", e))?;

        let mut callback_state = Box::new(FaxCallbackState {
            negotiation_started: false,
            pages_received: 0,
            completion_code: -1,
            completed: false,
        });

        configure_t30(&t30, tiff_path_str, &mut callback_state)?;

        unsafe {
            configure_log_state(spandsp_sys::t38_terminal_get_logging_state(
                terminal.as_ptr(),
            ));
            configure_log_state(spandsp_sys::t30_get_logging_state(t30.as_ptr()));

            let t38_core = terminal
                .get_t38_core_state()
                .map_err(|e| anyhow::anyhow!("Failed to get T38Core: {}", e))?;
            configure_log_state(spandsp_sys::t38_core_get_logging_state(t38_core.as_ptr()));
        }

        debug!(
            "T.38 fax receiver initialized, output: {}",
            tiff_path.display()
        );

        Ok(Self {
            terminal,
            tiff_path: tiff_path.to_path_buf(),
            callback_state,
            _tx_callback_state: tx_callback_state,
        })
    }

    /// Feed a received IFP packet from the UDPTL socket to SpanDSP.
    pub fn feed_ifp_packet(&self, data: &[u8], seq: u16) -> FaxRxStatus {
        let t38_core = match self.terminal.get_t38_core_state() {
            Ok(core) => core,
            Err(e) => {
                error!("Failed to get T38Core for rx: {}", e);
                return FaxRxStatus::Error(format!("T38Core error: {}", e));
            }
        };

        if let Err(e) = t38_core.rx_ifp_packet(data, seq) {
            warn!("T38Core rx_ifp_packet error: {} (seq={})", e, seq);
            // Don't return error — packet loss is expected in UDPTL
        }

        self.current_status()
    }

    /// Drive the T.38 terminal's timer. Call every 20ms (160 samples at 8kHz).
    ///
    /// This advances the T.30 state machine. Returns the current reception status.
    pub fn drive_timer(&self) -> FaxRxStatus {
        // 160 samples = 20ms at 8kHz
        let _result = self.terminal.send_timeout(160);
        self.current_status()
    }

    /// Check current status based on T.30 callback state.
    fn current_status(&self) -> FaxRxStatus {
        check_completion(&self.callback_state)
    }

    /// Number of pages received so far.
    pub fn pages_received(&self) -> u32 {
        self.callback_state.pages_received
    }

    /// Get the output TIFF file path.
    pub fn tiff_output_path(&self) -> &Path {
        &self.tiff_path
    }

    /// Get transfer statistics from SpanDSP.
    pub fn get_stats(&self) -> Option<FaxStats> {
        let t30 = self.terminal.get_t30_state().ok()?;
        Some(get_fax_stats(&t30))
    }
}

// SpanDSP C callbacks

/// T.38 TX packet handler callback.
///
/// Called by SpanDSP when it wants to send an IFP packet to the remote endpoint.
/// We push the packet into an mpsc channel, which the UDPTL socket task reads from.
///
/// Signature matches `t38_tx_packet_handler_t`:
///   `fn(s: *mut t38_core_state_t, user_data: *mut c_void, buf: *const u8, len: i32, count: i32) -> i32`
unsafe extern "C" fn tx_packet_handler(
    _s: *mut spandsp_sys::t38_core_state_t,
    user_data: *mut std::ffi::c_void,
    buf: *const u8,
    len: i32,
    count: i32,
) -> i32 {
    if user_data.is_null() || buf.is_null() || len <= 0 {
        return -1;
    }
    let (state, data) = unsafe {
        let state = &*(user_data as *const TxCallbackState);
        let data = std::slice::from_raw_parts(buf, len as usize);
        (state, data)
    };
    debug!("SpanDSP TX IFP: {}B (count={})", len, count);
    // Send the packet `count` times as SpanDSP requests.
    // For indicator packets (CNG, CED, DIS), count is typically 3 — these
    // must be sent multiple times because early packets have no UDPTL
    // redundancy history for error recovery.
    let send_count = count.max(1) as usize;
    for _ in 0..send_count {
        match state.sender.send(data.to_vec()) {
            Ok(()) => {}
            Err(_) => {
                // Channel closed — UDPTL socket task has ended
                warn!("SpanDSP TX IFP channel closed");
                return -1;
            }
        }
    }
    0
}

/// Phase B handler: called when T.30 negotiation starts.
unsafe extern "C" fn phase_b_handler(user_data: *mut std::ffi::c_void, result: i32) -> i32 {
    if !user_data.is_null() {
        let state = unsafe { &mut *(user_data as *mut FaxCallbackState) };
        state.negotiation_started = true;
        info!(
            "SpanDSP phase B: fax negotiation started (result={})",
            result
        );
    }
    0 // T30_ERR_OK
}

/// Phase D handler: called when a page is received.
unsafe extern "C" fn phase_d_handler(user_data: *mut std::ffi::c_void, result: i32) -> i32 {
    if !user_data.is_null() {
        let state = unsafe { &mut *(user_data as *mut FaxCallbackState) };
        state.pages_received += 1;
        info!(
            "SpanDSP phase D: page {} received (result={})",
            state.pages_received, result
        );
    }
    0 // T30_ERR_OK
}

/// Phase E handler: called when fax reception completes (success or failure).
unsafe extern "C" fn phase_e_handler(user_data: *mut std::ffi::c_void, completion_code: i32) {
    if !user_data.is_null() {
        let state = unsafe { &mut *(user_data as *mut FaxCallbackState) };
        state.completion_code = completion_code;
        state.completed = true;

        let reason = match spandsp::t30::T30State::completion_code(completion_code) {
            Some(err) if err.is_ok() => "OK".to_string(),
            Some(err) => format!("{}", err),
            None => format!("unknown code {}", completion_code),
        };

        if completion_code == 0 {
            info!(
                "SpanDSP phase E: fax complete, {} pages received",
                state.pages_received
            );
        } else {
            warn!(
                "SpanDSP phase E: fax failed after {} pages — T.30 error {}: {}",
                state.pages_received, completion_code, reason
            );
        }
    }
}

/// SpanDSP log handler: routes SpanDSP log messages to tracing.
unsafe extern "C" fn spandsp_log_handler(
    _user_data: *mut std::ffi::c_void,
    level: i32,
    text: *const std::ffi::c_char,
) {
    if text.is_null() {
        return;
    }
    let msg = unsafe { std::ffi::CStr::from_ptr(text) }.to_string_lossy();
    let msg = msg.trim_end(); // SpanDSP messages often have trailing newlines

    match level {
        l if l <= LogLevel::Error as i32 => error!(target: "spandsp", "{}", msg),
        l if l <= LogLevel::Warning as i32 => warn!(target: "spandsp", "{}", msg),
        l if l <= LogLevel::Flow as i32 => debug!(target: "spandsp", "{}", msg),
        _ => trace!(target: "spandsp", "{}", msg),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // check_completion tests

    #[test]
    fn check_completion_not_completed_returns_in_progress() {
        let state = FaxCallbackState {
            negotiation_started: false,
            pages_received: 0,
            completion_code: -1,
            completed: false,
        };
        assert_eq!(check_completion(&state), FaxRxStatus::InProgress);
    }

    #[test]
    fn check_completion_completed_code_0_returns_complete() {
        let state = FaxCallbackState {
            negotiation_started: true,
            pages_received: 1,
            completion_code: 0,
            completed: true,
        };
        assert_eq!(check_completion(&state), FaxRxStatus::Complete);
    }

    #[test]
    fn check_completion_completed_bad_code_returns_error() {
        let state = FaxCallbackState {
            negotiation_started: true,
            pages_received: 0,
            completion_code: 42,
            completed: true,
        };
        match check_completion(&state) {
            FaxRxStatus::Error(msg) => assert!(
                msg.contains("42") || msg.contains("failed") || msg.contains("Fax"),
                "Error message should reference the code: {}",
                msg
            ),
            other => panic!("Expected Error, got {:?}", other),
        }
    }

    // downsample_16k_to_8k tests

    #[test]
    fn downsample_even_count() {
        let mut buf = Vec::new();
        let samples: Vec<i16> = vec![100, 200, 300, 400, 500, 600, 700, 800, 900, 1000];
        let out = downsample_16k_to_8k(&mut buf, &samples);
        assert_eq!(out.len(), 5);
        assert_eq!(out[0], 150); // (100+200)/2
        assert_eq!(out[1], 350); // (300+400)/2
        assert_eq!(out[2], 550);
        assert_eq!(out[3], 750);
        assert_eq!(out[4], 950);
        assert!(buf.is_empty());
    }

    #[test]
    fn downsample_odd_count_preserves_leftover() {
        let mut buf = Vec::new();
        let samples: Vec<i16> = vec![100, 200, 300];
        let out = downsample_16k_to_8k(&mut buf, &samples);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0], 150);
        assert_eq!(buf.len(), 1);
        assert_eq!(buf[0], 300);
    }

    #[test]
    fn downsample_sequential_calls_bridge_accumulator() {
        let mut buf = Vec::new();
        // First call: 3 samples → 1 output, 1 leftover
        let out1 = downsample_16k_to_8k(&mut buf, &[10, 20, 30]);
        assert_eq!(out1, vec![15]);
        assert_eq!(buf, vec![30]);

        // Second call: leftover 30 + new [40, 50] = [30, 40, 50] → 1 output, 1 leftover
        let out2 = downsample_16k_to_8k(&mut buf, &[40, 50]);
        assert_eq!(out2, vec![35]); // (30+40)/2
        assert_eq!(buf, vec![50]);
    }

    #[test]
    fn downsample_single_sample_returns_empty() {
        let mut buf = Vec::new();
        let out = downsample_16k_to_8k(&mut buf, &[42]);
        assert!(out.is_empty());
        assert_eq!(buf, vec![42]);
    }

    // upsample_8k_to_16k tests

    #[test]
    fn upsample_basic() {
        let input: Vec<i16> = vec![100, 200, 300, 400];
        let mut out = vec![0i16; 8];
        let written = upsample_8k_to_16k(&input, &mut out);
        assert_eq!(written, 8);
        assert_eq!(out, vec![100, 100, 200, 200, 300, 300, 400, 400]);
    }

    #[test]
    fn upsample_empty_input() {
        let mut out = vec![0i16; 8];
        let written = upsample_8k_to_16k(&[], &mut out);
        assert_eq!(written, 0);
    }
}
