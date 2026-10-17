//! The one public error type.
//!
//! The pipelines keep the crate-private internal error (`AsxError` with an
//! `ErrorCode`); [`Error::from_internal`] is the single function that maps it
//! to an [`ErrorKind`] at the API boundary.

use crate::audit::AuditRecord;
use crate::core::{AsxError, ErrorCode};
use std::fmt;

/// A boxed, `Send` future — the return type of every trait method an embedder
/// implements.
pub type BoxFuture<'a, T> = std::pin::Pin<Box<dyn std::future::Future<Output = T> + Send + 'a>>;

/// The error type an embedder's trait implementation returns.
pub(crate) type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// `Result` with [`Error`] as the default error.
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// The one error type. Opaque; ask it questions.
///
/// - [`kind`](Error::kind) says what happened, in the terms a caller acts on.
/// - [`is_retryable`](Error::is_retryable) says whether sending the *same*
///   message again (same message id and timestamp) is safe and may succeed.
/// - [`ebms_code`](Error::ebms_code) and [`mdn_disposition`](Error::mdn_disposition)
///   name the partner's or our own fault.
/// - [`evidence`](Error::evidence) returns the audit record that exists
///   despite the error.
#[derive(Debug)]
pub struct Error {
    kind: ErrorKind,
    message: String,
    retryable: bool,
    ebms: Option<String>,
    mdn: Option<String>,
    evidence: Option<Box<AuditRecord>>,
    source: Option<BoxError>,
}

/// What happened, in the terms a caller acts on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ErrorKind {
    /// Invalid configuration or message. Nothing was sent.
    Config,
    /// This side refused an inbound message, receipt or MDN.
    Rejected,
    /// The partner refused our message (`eb:Error`, or MDN `processed/error` /
    /// `failed`).
    PartnerError,
    /// Definitely not delivered (connect, DNS, TLS, or request not written).
    /// Resend the same message.
    Transport,
    /// Possibly delivered: timeout after writing, no or unparseable signal, or
    /// a receipt/MDN that failed verification. Resend the same message, with
    /// the same message id and timestamp (AS4 Profile 1.0 §3.2).
    Indeterminate,
    /// An embedder backend failed: `DedupStore`, `AuditSink`, `Signer`,
    /// `Decrypter`.
    Backend,
}

impl ErrorKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Config => "configuration error",
            Self::Rejected => "rejected",
            Self::PartnerError => "partner error",
            Self::Transport => "transport error",
            Self::Indeterminate => "indeterminate",
            Self::Backend => "backend error",
        }
    }
}

/// Where an internal failure happened; selects the row of the mapping table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(any(feature = "as2", feature = "as4")), allow(dead_code))]
pub(crate) enum Stage {
    /// `build()`, send-time validation, certificate and key parsing.
    Config,
    /// The request was not written (connect, DNS, TLS, address pin).
    HttpNotWritten,
    /// The request may have been written (timeout, reset, custom client).
    HttpAfterWrite,
    /// The partner's receipt or MDN failed verification.
    ResponseVerify,
    /// `verify_async_mdn`: the request is not an MDN for this `PendingMdn`.
    AsyncMdnMatch,
    /// `Smp::lookup`.
    SmpLookup,
    /// An inbound message we refused.
    Inbound,
}

impl Error {
    /// What happened, in the terms a caller acts on.
    pub fn kind(&self) -> ErrorKind {
        self.kind
    }

    /// Whether sending the *same* `Message` again (same message id and
    /// timestamp) is safe and may succeed. True for `Transport`,
    /// `Indeterminate`, `PartnerError` with EBMS:0202 or
    /// `unexpected-processing-error`, and `Backend` unless the evidence shows
    /// delivery.
    pub fn is_retryable(&self) -> bool {
        self.retryable
    }

    /// The ebMS3 error code of a `Rejected`/`PartnerError` AS4 fault, e.g.
    /// `"EBMS:0202"`.
    pub fn ebms_code(&self) -> Option<&str> {
        self.ebms.as_deref()
    }

    /// The AS2 disposition of a `Rejected`/`PartnerError` AS2 fault, e.g.
    /// `"processed/error: decryption-failed"`.
    pub fn mdn_disposition(&self) -> Option<&str> {
        self.mdn.as_deref()
    }

    /// Evidence that exists despite the error: the unverifiable receipt bytes
    /// (`Indeterminate`), the partner's `eb:Error`/negative MDN
    /// (`PartnerError`), or the verified receipt when only the audit record
    /// failed (`Backend`, delivered).
    pub fn evidence(&self) -> Option<&AuditRecord> {
        self.evidence.as_deref()
    }

    // ── crate-private construction ──────────────────────────────────────────

    pub(crate) fn new(kind: ErrorKind, message: impl Into<String>) -> Self {
        let retryable = matches!(
            kind,
            ErrorKind::Transport | ErrorKind::Indeterminate | ErrorKind::Backend
        );
        Self {
            kind,
            message: message.into(),
            retryable,
            ebms: None,
            mdn: None,
            evidence: None,
            source: None,
        }
    }

    pub(crate) fn config(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::Config, message)
    }

    /// A failure of an embedder's backend (`Signer`, `Decrypter`,
    /// `DedupStore`, `AuditSink`).
    pub(crate) fn backend(message: impl Into<String>, source: BoxError) -> Self {
        Self::new(ErrorKind::Backend, message).with_source(source)
    }

    /// The partner refused our message with an ebMS3 error.
    pub(crate) fn partner_ebms(code: impl Into<String>, message: impl Into<String>) -> Self {
        let code = code.into();
        let mut err = Self::new(ErrorKind::PartnerError, message);
        err.retryable = code == "EBMS:0202";
        err.ebms = Some(code);
        err
    }

    /// The partner refused our message with a negative MDN.
    #[cfg_attr(not(feature = "as2"), allow(dead_code))]
    pub(crate) fn partner_mdn(disposition: impl Into<String>, message: impl Into<String>) -> Self {
        let disposition = disposition.into();
        let mut err = Self::new(ErrorKind::PartnerError, message);
        err.retryable = disposition.contains("unexpected-processing-error");
        err.mdn = Some(disposition);
        err
    }

    /// A partner error answered with an HTTP 5xx status is the receiver's
    /// transient failure (its store or sink), so resending may succeed.
    #[cfg_attr(not(any(feature = "as2", feature = "as4")), allow(dead_code))]
    pub(crate) fn retryable_if(mut self, condition: bool) -> Self {
        self.retryable |= condition;
        self
    }

    pub(crate) fn with_source(mut self, source: BoxError) -> Self {
        self.source = Some(source);
        self
    }

    pub(crate) fn with_evidence(mut self, record: Option<AuditRecord>) -> Self {
        self.evidence = record.map(Box::new);
        self
    }

    /// The audit record could not be written after a verified receipt: the
    /// message was delivered, so resending is not what the caller should do.
    pub(crate) fn delivered_but_unrecorded(source: Self, record: AuditRecord) -> Self {
        let mut err = Self::new(
            ErrorKind::Backend,
            format!("the message was delivered but its audit record was not written: {source}"),
        );
        err.retryable = false;
        err.evidence = Some(Box::new(record));
        err.source = Some(Box::new(source));
        err
    }

    /// An internal error with no better stage information: classified by its
    /// code alone (a configuration problem only where the code says so).
    pub(crate) fn internal(err: AsxError) -> Self {
        Self::from_internal(Stage::Config, err)
    }

    /// The one mapping from the internal error to a public kind.
    pub(crate) fn from_internal(stage: Stage, err: AsxError) -> Self {
        let kind = match (stage, err.code) {
            (_, ErrorCode::CapacityExhausted) => ErrorKind::Transport,
            (_, ErrorCode::StorageBackendFailure | ErrorCode::ReliabilityFailure) => {
                ErrorKind::Backend
            }
            (Stage::Config, _) => ErrorKind::Config,
            (Stage::HttpNotWritten, ErrorCode::TransportFailure) => ErrorKind::Transport,
            // The address pin and the HTTPS rule refuse before
            // anything is written: not delivered, and not worth a retry.
            (
                Stage::HttpNotWritten,
                ErrorCode::InvalidInput | ErrorCode::PolicyViolation | ErrorCode::NotFound,
            ) => ErrorKind::Transport,
            (Stage::HttpNotWritten | Stage::HttpAfterWrite, _) => ErrorKind::Indeterminate,
            (Stage::ResponseVerify, _) => ErrorKind::Indeterminate,
            (Stage::AsyncMdnMatch, _) => ErrorKind::Rejected,
            (Stage::SmpLookup, ErrorCode::TransportFailure | ErrorCode::Timeout) => {
                ErrorKind::Transport
            }
            (Stage::SmpLookup, ErrorCode::NotFound | ErrorCode::InvalidInput) => ErrorKind::Config,
            (Stage::SmpLookup, _) => ErrorKind::Rejected,
            (Stage::Inbound, _) => ErrorKind::Rejected,
        };
        let mut out = Self::new(kind, err.message.clone());
        let address_pin_refusal = stage == Stage::HttpNotWritten
            && matches!(
                err.code,
                ErrorCode::InvalidInput | ErrorCode::PolicyViolation | ErrorCode::NotFound
            );
        out.retryable = match kind {
            ErrorKind::Transport => !address_pin_refusal,
            ErrorKind::Indeterminate | ErrorKind::Backend => true,
            _ => false,
        };
        out.source = Some(Box::new(err));
        out
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.kind.as_str(), self.message)?;
        if let Some(code) = &self.ebms {
            write!(f, " ({code})")?;
        }
        if let Some(disposition) = &self.mdn {
            write!(f, " ({disposition})")?;
        }
        Ok(())
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source
            .as_deref()
            .map(|s| s as &(dyn std::error::Error + 'static))
    }
}

/// Test hooks for `tests/error_mapping.rs`: drive the mapping table without a
/// pipeline. Not part of the public API.
#[doc(hidden)]
pub mod __mapping {
    use super::*;
    use crate::core::ErrorContext;

    /// The stages the table distinguishes, by name.
    #[doc(hidden)]
    pub fn map(stage: &str, code: ErrorCode) -> Option<Error> {
        let stage = match stage {
            "config" => Stage::Config,
            "http_not_written" => Stage::HttpNotWritten,
            "http_after_write" => Stage::HttpAfterWrite,
            "response_verify" => Stage::ResponseVerify,
            "async_mdn_match" => Stage::AsyncMdnMatch,
            "smp_lookup" => Stage::SmpLookup,
            "inbound" => Stage::Inbound,
            _ => return None,
        };
        Some(Error::from_internal(
            stage,
            AsxError::new(code, "mapped", ErrorContext::new("error_mapping")),
        ))
    }

    /// A partner `eb:Error` with `code`.
    #[doc(hidden)]
    pub fn partner_ebms(code: &str) -> Error {
        Error::partner_ebms(code, "partner refused")
    }

    /// A negative MDN with `disposition`.
    #[doc(hidden)]
    pub fn partner_mdn(disposition: &str) -> Error {
        Error::partner_mdn(disposition, "partner refused")
    }

    /// A backend failure (signer, decrypter, store, sink).
    #[doc(hidden)]
    pub fn backend() -> Error {
        Error::backend("backend failed", "down".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::ErrorContext;

    fn assert_send_sync_static<T: Send + Sync + 'static>() {}

    #[test]
    fn error_is_send_sync_static() {
        assert_send_sync_static::<Error>();
        assert_send_sync_static::<ErrorKind>();
    }

    #[test]
    fn display_has_no_trailing_period() {
        let err = Error::config("partner endpoint must be https");
        let text = err.to_string();
        assert!(!text.ends_with('.'), "{text}");
        assert!(text.starts_with("configuration error: "), "{text}");
    }

    #[test]
    fn source_is_preserved() {
        let internal = AsxError::new(
            ErrorCode::TransportFailure,
            "connection refused",
            ErrorContext::new("unit"),
        );
        let err = Error::from_internal(Stage::HttpNotWritten, internal);
        assert_eq!(err.kind(), ErrorKind::Transport);
        let source = std::error::Error::source(&err).expect("source kept");
        assert!(source.to_string().contains("connection refused"));
    }

    #[test]
    fn partner_retry_rule() {
        assert!(Error::partner_ebms("EBMS:0202", "x").is_retryable());
        assert!(!Error::partner_ebms("EBMS:0004", "x").is_retryable());
        assert!(
            Error::partner_mdn("processed/error: unexpected-processing-error", "x").is_retryable()
        );
        assert!(!Error::partner_mdn("processed/error: decryption-failed", "x").is_retryable());
    }
}
