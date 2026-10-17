//! `AsxError`, `ErrorCode`, `ErrorContext` and the crate `Result` alias.

use super::*;

pub type Result<T> = std::result::Result<T, AsxError>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErrorContext {
    pub stage: &'static str,
    pub message_id: Option<String>,
    pub partner_id: Option<String>,
    pub session_id: Option<String>,
}

impl ErrorContext {
    #[must_use]
    pub fn new(stage: &'static str) -> Self {
        Self {
            stage,
            message_id: None,
            partner_id: None,
            session_id: None,
        }
    }

    /// Create an `ErrorContext` pre-populated with session and partner IDs from a `SessionContext`.
    /// Prefer this over chaining `with_session_id` + `with_partner_id` to avoid redundant clones.
    #[must_use]
    pub fn for_session(stage: &'static str, session: &SessionContext) -> Self {
        Self::new(stage).with_session_and_partner(session.session_id(), session.partner_id())
    }

    /// Create an `ErrorContext` pre-populated with session, partner, and message IDs.
    /// Prefer this over chaining three separate `with_*` calls.
    #[must_use]
    pub fn for_session_with_message(
        stage: &'static str,
        session: &SessionContext,
        message_id: impl Into<String>,
    ) -> Self {
        Self::new(stage)
            .with_session_and_partner(session.session_id(), session.partner_id())
            .with_message_id(message_id)
    }

    #[must_use]
    pub fn with_session_and_partner(
        mut self,
        session_id: impl Into<String>,
        partner_id: impl Into<String>,
    ) -> Self {
        self.session_id = Some(session_id.into());
        self.partner_id = Some(partner_id.into());
        self
    }

    #[must_use]
    pub fn with_message_id(mut self, message_id: impl Into<String>) -> Self {
        self.message_id = Some(message_id.into());
        self
    }

    #[must_use]
    pub fn with_partner_id(mut self, partner_id: impl Into<String>) -> Self {
        self.partner_id = Some(partner_id.into());
        self
    }

    #[must_use]
    pub fn with_session_id(mut self, session_id: impl Into<String>) -> Self {
        self.session_id = Some(session_id.into());
        self
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ErrorCode {
    InvalidInput,
    ParseFailed,
    SecurityVerificationFailed,
    DecryptionFailed,
    PolicyViolation,
    TransportFailure,
    InteropViolation,
    ReliabilityFailure,
    /// A requested resource (e.g. SMP endpoint, profile) does not exist.
    NotFound,
    /// A bounded resource (e.g. a connection pool) has no
    /// remaining capacity.  Callers should shed load or retry after a delay.
    CapacityExhausted,
    /// The inbound request body exceeds the configured size limit.
    ///
    /// HTTP semantics: respond with 413 Content Too Large.
    PayloadTooLarge,
    /// A storage or infrastructure backend (dedup store,
    /// audit sink) failed with an I/O or connectivity error.
    ///
    /// This is distinct from [`ReliabilityFailure`](Self::ReliabilityFailure)
    /// (protocol-level duplicate/ordering failure) and from
    /// [`TransportFailure`](Self::TransportFailure) (network/HTTP failure).
    ///
    /// HTTP semantics: respond with 503 Service Unavailable — the server is
    /// temporarily unable to handle the request due to a backend outage.
    StorageBackendFailure,
    /// The partner's certificate has been revoked by its issuing CA.
    ///
    /// Distinct from [`SecurityVerificationFailed`](Self::SecurityVerificationFailed)
    /// (which covers signature/chain errors) so that monitoring can page on revocation
    /// separately from transient verification failures.
    ///
    /// HTTP semantics: 403 Forbidden — the certificate is permanently invalid.
    CertificateRevoked,
    /// The partner's certificate has passed its `notAfter` validity date.
    ///
    /// Distinct from [`SecurityVerificationFailed`](Self::SecurityVerificationFailed)
    /// so that operations teams receive a targeted remediation hint (rotate the
    /// partner cert) rather than a generic security failure alert.
    ///
    /// HTTP semantics: 403 Forbidden.
    CertificateExpired,
    /// A network or I/O operation timed out before completing.
    ///
    /// Distinct from [`TransportFailure`](Self::TransportFailure) (which covers
    /// protocol/TLS errors) so that callers can apply timeout-specific retry
    /// policies (e.g., exponential back-off with jitter rather than immediate retry).
    ///
    /// HTTP semantics: 504 Gateway Timeout when acting as a proxy/client.
    Timeout,
}

impl ErrorCode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidInput => "invalid_input",
            Self::ParseFailed => "parse_failed",
            Self::SecurityVerificationFailed => "security_verification_failed",
            Self::DecryptionFailed => "decryption_failed",
            Self::PolicyViolation => "policy_violation",
            Self::TransportFailure => "transport_failure",
            Self::InteropViolation => "interop_violation",
            Self::ReliabilityFailure => "reliability_failure",
            Self::NotFound => "not_found",
            Self::CapacityExhausted => "capacity_exhausted",
            Self::PayloadTooLarge => "payload_too_large",
            Self::StorageBackendFailure => "storage_backend_failure",
            Self::CertificateRevoked => "certificate_revoked",
            Self::CertificateExpired => "certificate_expired",
            Self::Timeout => "timeout",
        }
    }

    /// Returns the canonical HTTP status code for this error.
    ///
    /// Embedders can use this in transport adapters to map `AsxError` to HTTP
    /// responses without writing a custom match.  For errors that represent
    /// an external failure (e.g., `TransportFailure`), the code is 5xx; for
    /// caller-induced errors it is 4xx.
    ///
    /// | Variant                       | HTTP status |
    /// |-------------------------------|-------------|
    /// | `InvalidInput`                | 400         |
    /// | `ParseFailed`                 | 400         |
    /// | `SecurityVerificationFailed`  | 401         |
    /// | `DecryptionFailed`            | 400         |
    /// | `PolicyViolation`             | 422         |
    /// | `TransportFailure`            | 502         |
    /// | `InteropViolation`            | 400         |
    /// | `ReliabilityFailure`          | 503         |
    /// | `NotFound`                    | 404         |
    /// | `CapacityExhausted`           | 429         |
    /// | `PayloadTooLarge`             | 413         |
    /// | `StorageBackendFailure`        | 503         |
    /// | `CertificateRevoked`          | 403         |
    /// | `CertificateExpired`          | 403         |
    /// | `Timeout`                     | 504         |
    pub fn to_http_status(self) -> u16 {
        match self {
            Self::InvalidInput => 400,
            Self::ParseFailed => 400,
            Self::SecurityVerificationFailed => 401,
            Self::DecryptionFailed => 400,
            Self::PolicyViolation => 422,
            Self::TransportFailure => 502,
            Self::InteropViolation => 400,
            Self::ReliabilityFailure => 503,
            Self::NotFound => 404,
            Self::CapacityExhausted => 429,
            Self::PayloadTooLarge => 413,
            Self::StorageBackendFailure => 503,
            Self::CertificateRevoked => 403,
            Self::CertificateExpired => 403,
            Self::Timeout => 504,
        }
    }
}

/// The crate-private internal error; `Error::from_internal` maps it to the
/// public error at the API boundary.
///
/// `code` is the machine-readable part and is load-bearing: ingress handlers map
/// it to an HTTP status and `Error::from_internal` classifies on it.
/// `message` is for operators, never for matching.
///
/// The context is boxed. Every fallible function in this crate returns
/// `Result<T, AsxError>`, so the error variant's size is paid on the success
/// path too: inline, [`ErrorContext`] would make every `Result` in the crate
/// 120 bytes wide, including `Result<()>`; boxed it is 40, and
/// `err.context.session_id` still works through `Deref`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AsxError {
    /// Machine-readable classification. Match on this, not on `message`.
    pub code: ErrorCode,
    /// Operator-facing description of what went wrong.
    pub message: String,
    /// Correlation context: stage, and optionally session, partner and message id.
    pub context: Box<ErrorContext>,
}

impl AsxError {
    /// Construct an error.
    pub fn new(code: ErrorCode, message: impl Into<String>, context: ErrorContext) -> Self {
        Self {
            code,
            message: message.into(),
            context: Box::new(context),
        }
    }

    /// Enrich the error context with the partner ID for easier correlation in embedder logs.
    ///
    /// Delegates to [`ErrorContext::with_partner_id`]. Designed for use in `map_err` closures
    /// where the full `ErrorContext` is not directly accessible:
    ///
    /// ```text
    /// some_op().map_err(|e| e.with_partner_id(session.partner_id()))?;
    /// ```
    #[must_use]
    pub fn with_partner_id(mut self, partner_id: impl Into<String>) -> Self {
        self.context = Box::new(self.context.with_partner_id(partner_id));
        self
    }

    /// Enrich the error context with the session ID for easier correlation in embedder logs.
    ///
    /// Delegates to [`ErrorContext::with_session_id`].
    #[must_use]
    pub fn with_session_id(mut self, session_id: impl Into<String>) -> Self {
        self.context = Box::new(self.context.with_session_id(session_id));
        self
    }

    /// Enrich the error context with both session and partner IDs in one call.
    ///
    /// Delegates to [`ErrorContext::with_session_and_partner`].
    #[must_use]
    pub fn with_session_and_partner(
        mut self,
        session_id: impl Into<String>,
        partner_id: impl Into<String>,
    ) -> Self {
        self.context = Box::new(
            self.context
                .with_session_and_partner(session_id, partner_id),
        );
        self
    }

    /// Enrich the error context with the message ID for easier correlation in embedder logs.
    ///
    /// Delegates to [`ErrorContext::with_message_id`].
    #[must_use]
    pub fn with_message_id(mut self, message_id: impl Into<String>) -> Self {
        self.context = Box::new(self.context.with_message_id(message_id));
        self
    }

    /// Returns `true` if this error represents a replay-protection rejection
    /// (the message was already seen by the dedup store): a
    /// `ReliabilityFailure` whose message mentions "replay".
    #[inline]
    pub fn is_duplicate(&self) -> bool {
        self.code == ErrorCode::ReliabilityFailure && self.message.contains("replay")
    }

    /// Returns `true` if this error represents a transient storage or infrastructure failure.
    #[inline]
    pub fn is_storage_failure(&self) -> bool {
        self.code == ErrorCode::StorageBackendFailure
    }
}

impl fmt::Display for AsxError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} [{}|stage={}]",
            self.message,
            self.code.as_str(),
            self.context.stage
        )?;
        if let Some(pid) = &self.context.partner_id {
            write!(f, "[partner={pid}]")?;
        }
        if let Some(mid) = &self.context.message_id {
            write!(f, "[msg={mid}]")?;
        }
        if let Some(sid) = &self.context.session_id {
            write!(f, "[session={sid}]")?;
        }
        Ok(())
    }
}

impl std::error::Error for AsxError {}
