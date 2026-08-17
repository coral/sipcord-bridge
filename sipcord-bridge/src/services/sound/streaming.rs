//! Streaming audio player for large files.

use crate::transport::sip::CONF_SAMPLE_RATE;
use std::collections::VecDeque;
use std::fs::File;
use std::path::{Path, PathBuf};
use symphonia::core::audio::{AudioBufferRef, Signal};
use symphonia::core::codecs::{CODEC_TYPE_NULL, DecoderOptions};
use symphonia::core::formats::FormatOptions;
use symphonia::core::io::MediaSourceStream;
use symphonia::core::meta::MetadataOptions;
use symphonia::core::probe::Hint;

#[derive(thiserror::Error, Debug)]
pub enum StreamingError {
    #[error("failed to open streaming file {path:?}: {source}")]
    Open {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to probe streaming format {path:?}: {source}")]
    Probe {
        path: PathBuf,
        #[source]
        source: symphonia::core::errors::Error,
    },

    #[error("streaming file {path:?} has no audio track")]
    NoTrack { path: PathBuf },

    #[error("streaming file {path:?} has no sample rate")]
    NoSampleRate { path: PathBuf },

    #[error("streaming file {path:?} has wrong sample rate: {got} Hz (expected {expected} Hz)")]
    WrongSampleRate {
        path: PathBuf,
        got: u32,
        expected: u32,
    },

    #[error("failed to create streaming decoder: {0}")]
    Decoder(#[source] symphonia::core::errors::Error),
}

/// Streaming player for large audio files; reads FLAC frames on-demand.
pub struct StreamingPlayer {
    format: Box<dyn symphonia::core::formats::FormatReader>,
    decoder: Box<dyn symphonia::core::codecs::Decoder>,
    track_id: u32,
    samples_buffer: VecDeque<i16>,
    eof: bool,
    total_samples_read: u64,
    total_samples_delivered: u64,
}

impl StreamingPlayer {
    pub fn new(path: &Path) -> Result<Self, StreamingError> {
        let file = File::open(path).map_err(|source| StreamingError::Open {
            path: path.to_path_buf(),
            source,
        })?;

        let mss = MediaSourceStream::new(Box::new(file), Default::default());

        let mut hint = Hint::new();
        if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
            hint.with_extension(ext);
        }

        let probed = symphonia::default::get_probe()
            .format(
                &hint,
                mss,
                &FormatOptions::default(),
                &MetadataOptions::default(),
            )
            .map_err(|source| StreamingError::Probe {
                path: path.to_path_buf(),
                source,
            })?;

        let format = probed.format;

        let track = format
            .tracks()
            .iter()
            .find(|t| t.codec_params.codec != CODEC_TYPE_NULL)
            .ok_or_else(|| StreamingError::NoTrack {
                path: path.to_path_buf(),
            })?;

        let track_id = track.id;

        let sample_rate = track
            .codec_params
            .sample_rate
            .ok_or_else(|| StreamingError::NoSampleRate {
                path: path.to_path_buf(),
            })?;

        if sample_rate != CONF_SAMPLE_RATE {
            return Err(StreamingError::WrongSampleRate {
                path: path.to_path_buf(),
                got: sample_rate,
                expected: CONF_SAMPLE_RATE,
            });
        }

        let channels = track.codec_params.channels.map(|c| c.count()).unwrap_or(1);
        let n_frames = track.codec_params.n_frames;

        tracing::info!(
            "Created Symphonia streaming player for {}: {}Hz, {} channels, n_frames={:?}",
            path.display(),
            sample_rate,
            channels,
            n_frames
        );

        let decoder = symphonia::default::get_codecs()
            .make(&track.codec_params, &DecoderOptions::default())
            .map_err(StreamingError::Decoder)?;

        Ok(Self {
            format,
            decoder,
            track_id,
            samples_buffer: VecDeque::with_capacity(4096),
            eof: false,
            total_samples_read: 0,
            total_samples_delivered: 0,
        })
    }

    /// Get the next frame of samples. Returns None when the file is finished.
    pub fn get_frame(&mut self, frame_size: usize) -> Option<Vec<i16>> {
        while self.samples_buffer.len() < frame_size && !self.eof {
            if !self.read_more_samples() {
                self.eof = true;
            }
        }

        if self.samples_buffer.is_empty() {
            return None;
        }

        let count = frame_size.min(self.samples_buffer.len());
        let samples: Vec<i16> = self.samples_buffer.drain(..count).collect();
        self.total_samples_delivered += samples.len() as u64;

        if samples.len() < frame_size {
            let mut padded = samples;
            padded.resize(frame_size, 0);
            return Some(padded);
        }

        Some(samples)
    }

    pub fn is_finished(&self) -> bool {
        let finished = self.eof && self.samples_buffer.is_empty();
        if finished {
            tracing::info!(
                "StreamingPlayer finished: read {} samples, delivered {} samples",
                self.total_samples_read,
                self.total_samples_delivered,
            );
        }
        finished
    }

    /// Returns false when EOF is reached.
    fn read_more_samples(&mut self) -> bool {
        loop {
            let packet = match self.format.next_packet() {
                Ok(packet) => packet,
                Err(symphonia::core::errors::Error::IoError(e))
                    if e.kind() == std::io::ErrorKind::UnexpectedEof =>
                {
                    return false;
                }
                Err(e) => {
                    tracing::debug!("Error reading packet: {}", e);
                    return false;
                }
            };

            if packet.track_id() != self.track_id {
                continue;
            }

            match self.decoder.decode(&packet) {
                Ok(decoded) => {
                    let samples_added = convert_audio_buffer(&decoded, &mut self.samples_buffer);
                    self.total_samples_read += samples_added as u64;
                    return true;
                }
                Err(symphonia::core::errors::Error::DecodeError(e)) => {
                    tracing::debug!("Decode error: {}", e);
                    continue;
                }
                Err(e) => {
                    tracing::debug!("Fatal decode error: {}", e);
                    return false;
                }
            }
        }
    }
}

fn convert_audio_buffer(audio: &AudioBufferRef, samples_buffer: &mut VecDeque<i16>) -> usize {
    let mut count = 0;

    match audio {
        AudioBufferRef::S16(buf) => {
            let channels = buf.spec().channels.count();
            let frames = buf.frames();
            for frame_idx in 0..frames {
                if channels == 1 {
                    samples_buffer.push_back(buf.chan(0)[frame_idx]);
                    count += 1;
                } else {
                    let mut sum: i32 = 0;
                    for ch in 0..channels {
                        sum += buf.chan(ch)[frame_idx] as i32;
                    }
                    samples_buffer.push_back((sum / channels as i32) as i16);
                    count += 1;
                }
            }
        }
        AudioBufferRef::S32(buf) => {
            let channels = buf.spec().channels.count();
            let frames = buf.frames();
            for frame_idx in 0..frames {
                if channels == 1 {
                    samples_buffer.push_back((buf.chan(0)[frame_idx] >> 16) as i16);
                    count += 1;
                } else {
                    let mut sum: i64 = 0;
                    for ch in 0..channels {
                        sum += buf.chan(ch)[frame_idx] as i64;
                    }
                    samples_buffer.push_back(((sum / channels as i64) >> 16) as i16);
                    count += 1;
                }
            }
        }
        AudioBufferRef::F32(buf) => {
            let channels = buf.spec().channels.count();
            let frames = buf.frames();
            for frame_idx in 0..frames {
                if channels == 1 {
                    samples_buffer.push_back((buf.chan(0)[frame_idx] * 32767.0) as i16);
                    count += 1;
                } else {
                    let mut sum: f32 = 0.0;
                    for ch in 0..channels {
                        sum += buf.chan(ch)[frame_idx];
                    }
                    samples_buffer.push_back(((sum / channels as f32) * 32767.0) as i16);
                    count += 1;
                }
            }
        }
        _ => {
            tracing::warn!("Unsupported audio buffer format");
        }
    }

    count
}
