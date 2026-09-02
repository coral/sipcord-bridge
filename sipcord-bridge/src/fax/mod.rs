//! Incoming fax support — receives faxes over SIP and posts images to Discord.
//!
//! Supports two transport modes:
//! - **G.711 passthrough**: Demodulates fax tones from audio samples (SpanDSP FaxState)
//! - **T.38 native**: Receives IFP packets via UDPTL (SpanDSP T38Terminal)
//!
//! Architecture:
//! - FaxSession: State machine managing a single fax reception (audio or T.38)
//! - DiscordPoster: Posts/edits messages in Discord text channels with fax images
//! - SpanDSP wrapper: FFI to SpanDSP for fax demodulation (FaxReceiver + FaxT38Receiver)
//! - audio_port: Conference bridge port for capturing SIP audio (G.711 mode)
//! - UDPTL: UDP transport for T.38 IFP packets

pub mod audio_port;
pub mod discord_poster;
pub mod session;
pub mod spandsp;
pub mod tiff_decoder;

#[derive(thiserror::Error, Debug)]
pub enum FaxPageDataError {
    #[error("TIFF page {page_number} decoded only {decoded_rows} rows (minimum {minimum_rows})")]
    TooShort {
        page_number: usize,
        decoded_rows: u32,
        minimum_rows: u32,
    },

    #[error(
        "TIFF page {page_number} decoded {decoded_rows} rows, but TIFF declares {declared_rows} \
         (difference {difference}, allowed {allowed_difference})"
    )]
    RowCountMismatch {
        page_number: usize,
        decoded_rows: u32,
        declared_rows: u32,
        difference: u32,
        allowed_difference: u32,
    },
}

#[derive(thiserror::Error, Debug)]
pub enum FaxError {
    #[error("Discord post failed: {0}")]
    Discord(#[from] serenity::Error),

    #[error("invalid Discord bot token: {0}")]
    InvalidToken(String),

    #[error("fax I/O ({context}): {source}")]
    Io {
        context: String,
        #[source]
        source: std::io::Error,
    },

    #[error("path is not valid UTF-8: {0}")]
    NonUtf8Path(String),

    #[error("SpanDSP ({operation}): {detail}")]
    SpanDsp {
        operation: &'static str,
        detail: String,
    },

    #[error("TIFF decode: {0}")]
    Tiff(String),

    #[error("Fax received with corrupt/incomplete page data")]
    CorruptPageData(#[source] FaxPageDataError),

    #[error("no pages in received fax")]
    NoPages,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn corrupt_page_error_has_stable_user_message_and_diagnostic_detail() {
        let error = FaxError::CorruptPageData(FaxPageDataError::TooShort {
            page_number: 2,
            decoded_rows: 4,
            minimum_rows: 64,
        });

        assert_eq!(
            error.to_string(),
            "Fax received with corrupt/incomplete page data"
        );
        let FaxError::CorruptPageData(source) = error else {
            panic!("expected corrupt page data error");
        };
        assert_eq!(
            source.to_string(),
            "TIFF page 2 decoded only 4 rows (minimum 64)"
        );
    }
}
