use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

pub type Result<T> = std::result::Result<T, AsxError>;

/// Escapes the five canonical XML special characters (`&`, `<`, `>`, `"`, `'`)
/// and strips XML 1.0 §2.2 forbidden control characters (including NUL bytes)
/// to prevent injection into SOAP/SBDH envelopes.
///
/// # ⚠ Forbidden-character stripping
///
/// Bytes in the ranges `U+0000–U+0008`, `U+000B–U+000C`, `U+000E–U+001F`, and
/// `U+007F` are **stripped** (not replaced) from the output.  If the input
/// contains such bytes, the output will differ from the input — which can
/// cause integrity failures that are hard to diagnose.  A `tracing::warn!`
/// event is emitted (when the `trace` feature is enabled) so that callers
/// can detect this condition via their observability pipeline.
///
/// If you need to **reject** inputs containing forbidden characters rather
/// than silently strip them, validate `s` before calling this function.
pub fn escape_xml(s: &str) -> String {
    let mut out = String::new();
    let mut last = 0usize;
    let mut modified = false;
    let mut stripped_count: usize = 0;
    for (i, b) in s.bytes().enumerate() {
        let escaped = match b {
            // Forbidden XML 1.0 §2.2 characters — strip and warn.
            0x00..=0x08 | 0x0B..=0x0C | 0x0E..=0x1F | 0x7F => {
                if !modified {
                    out.reserve(s.len());
                    modified = true;
                }
                out.push_str(&s[last..i]);
                last = i + 1;
                stripped_count += 1;
                continue;
            }
            b'&' => "&amp;",
            b'<' => "&lt;",
            b'>' => "&gt;",
            b'"' => "&quot;",
            b'\'' => "&apos;",
            _ => continue,
        };
        if !modified {
            out.reserve(s.len() + 16);
            modified = true;
        }
        out.push_str(&s[last..i]);
        out.push_str(escaped);
        last = i + 1;
    }
    if !modified {
        return s.to_owned();
    }
    out.push_str(&s[last..]);
    if stripped_count > 0 {
        // Emit a warning observable via the tracing subscriber so that
        // embedders can detect and alert on truncated XML field values.
        tracing::warn!(
            stripped_bytes = stripped_count,
            "escape_xml stripped {} forbidden XML 1.0 control character(s) from input; \
             output differs from input — check the source field for binary/control data",
            stripped_count,
        );
    }
    out
}

fn default_blocking_crypto_concurrency() -> usize {
    // Slightly above core-count keeps throughput stable while bounding queueing.
    std::thread::available_parallelism()
        .map(|n| n.get().saturating_mul(2))
        .unwrap_or(8)
        .clamp(4, 128)
}

const BLOCKING_CRYPTO_CONCURRENCY_ENV: &str = "ASX_BLOCKING_CRYPTO_CONCURRENCY";

fn configured_blocking_crypto_concurrency() -> usize {
    std::env::var(BLOCKING_CRYPTO_CONCURRENCY_ENV)
        .ok()
        .and_then(|raw| raw.trim().parse::<usize>().ok())
        .filter(|value| *value > 0)
        .map(|value| value.clamp(1, 4096))
        .unwrap_or_else(default_blocking_crypto_concurrency)
}

fn blocking_crypto_semaphore() -> Arc<Semaphore> {
    static SEM: OnceLock<Arc<Semaphore>> = OnceLock::new();
    Arc::clone(
        SEM.get_or_init(|| Arc::new(Semaphore::new(configured_blocking_crypto_concurrency()))),
    )
}

// ---------------------------------------------------------------------------
// CryptoAdmissionControl — instance-scoped or process-global semaphore
// ---------------------------------------------------------------------------

/// Default inbound payload ceiling (256 MiB).
///
/// Production EDI batch files routinely exceed 50–100 MB; this default
/// accommodates X12, EDIFACT, and Peppol BIS payloads without operator
/// intervention.  Override via `StreamLimits` for resource-constrained
/// deployments.
pub const DEFAULT_MAX_BODY_BYTES: usize = 256 * 1024 * 1024;

/// Controls how many concurrent CPU-heavy crypto/protocol tasks are admitted.
///
/// The default ([`CryptoAdmissionControl::process_global()`]) shares a
/// process-wide semaphore across all sessions.  For multi-tenant embeddings,
/// create a **per-tenant** instance so that one tenant's burst traffic cannot
/// starve another's:
///
/// ```rust,ignore
/// let control = Arc::new(CryptoAdmissionControl::new(32));
/// // Store in your tenant context and call:
/// // control.acquire(stage, session).await?
/// ```
///
/// ## Choosing a concurrency limit
///
/// A value of `num_cpus * 2` (the default) is appropriate for workloads where
/// crypto dominates.  For mixed workloads, set it to the number of Tokio
/// blocking threads you are willing to dedicate to crypto work.
#[derive(Clone, Debug)]
pub struct CryptoAdmissionControl {
    semaphore: Arc<Semaphore>,
    /// Human-readable label used in error messages.
    label: &'static str,
}

impl CryptoAdmissionControl {
    /// Create a new **instance-scoped** admission controller with `concurrency`
    /// permits.
    ///
    /// Use this for per-tenant or per-connection isolation.
    pub fn new(concurrency: usize) -> Self {
        let cap = concurrency.clamp(1, 4096);
        Self {
            semaphore: Arc::new(Semaphore::new(cap)),
            label: "instance-scoped crypto semaphore",
        }
    }

    /// Return the **process-global** admission controller.
    ///
    /// Concurrency is configured by the `ASX_BLOCKING_CRYPTO_CONCURRENCY` env var
    /// or defaults to `num_cpus × 2`.
    pub fn process_global() -> Self {
        Self {
            semaphore: blocking_crypto_semaphore(),
            label: "process-global crypto semaphore",
        }
    }

    /// Acquire one permit, waiting if all permits are currently held.
    pub async fn acquire(
        &self,
        stage: &'static str,
        session: &SessionContext,
    ) -> Result<OwnedSemaphorePermit> {
        Arc::clone(&self.semaphore)
            .acquire_owned()
            .await
            .map_err(|_| {
                AsxError::new(
                    ErrorCode::TransportFailure,
                    format!("{} is closed", self.label),
                    ErrorContext::for_session(stage, session),
                )
            })
    }
}

/// Interpret a byte slice as UTF-8, returning a contextual error on failure.
/// Avoids repeating the 4-line `from_utf8(...).map_err(|_| AsxError::new(...))` pattern.
#[cfg(feature = "as4")]
pub(crate) fn bytes_to_utf8_str<'a>(
    bytes: &'a [u8],
    stage: &'static str,
    session: &SessionContext,
) -> Result<&'a str> {
    std::str::from_utf8(bytes).map_err(|_| {
        AsxError::new(
            ErrorCode::ParseFailed,
            format!("{stage}: payload is not valid UTF-8"),
            ErrorContext::for_session(stage, session),
        )
    })
}

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
    /// A bounded resource (e.g. conversation gate, connection pool) has no
    /// remaining capacity.  Callers should shed load or retry after a delay.
    CapacityExhausted,
    /// The inbound request body exceeds the configured size limit.
    ///
    /// HTTP semantics: respond with 413 Content Too Large.
    PayloadTooLarge,
    /// A storage or infrastructure backend (dedup store, reconciliation queue,
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

    /// A short operator-facing remediation hint for the most common failure
    /// codes, or `None` for failures that require caller-specific diagnosis.
    ///
    /// Intended for structured logging and monitoring dashboards; not a
    /// substitute for full error context.
    pub fn remediation_hint(self) -> Option<&'static str> {
        match self {
            Self::DecryptionFailed => Some(
                "Verify that the recipient certificate PEM and its private key PEM match. \
                 Ensure the sender is encrypting to the correct public certificate. \
                 Re-key the key pair if the certificate has been re-issued.",
            ),
            Self::SecurityVerificationFailed => Some(
                "Confirm the trust anchor PEM includes the full CA chain of the signer. \
                 Check certificate validity period. \
                 Ensure CRL distribution points or OCSP responders are reachable.",
            ),
            Self::TransportFailure => Some(
                "Check network connectivity and DNS resolution for the remote endpoint. \
                 Verify TLS certificate chain and mutual-TLS configuration. \
                 Ensure the spool directory exists and is writable.",
            ),
            Self::ReliabilityFailure => Some(
                "Ensure an EventBus broadcast subscriber is active before message sends. \
                 Check dedup and reconciliation backend availability and capacity.",
            ),
            Self::PolicyViolation => Some(
                "Review the PMode and profile configuration against the partner specification. \
                 Verify the interop mode matches the partner's published requirements.",
            ),
            Self::CapacityExhausted => Some(
                "Shed load or retry after a backoff delay. \
                 Consider increasing channel capacity or conversation gate limits.",
            ),
            Self::StorageBackendFailure => Some(
                "Check dedup/reconciliation/audit backend connectivity and disk space. \
                 Inspect backend logs for I/O errors. \
                 Consider a circuit-breaker or fallback backend for resilience.",
            ),
            Self::CertificateRevoked => Some(
                "The partner's signing certificate has been revoked by its issuing CA. \
                 Contact the trading partner to obtain a replacement certificate. \
                 Update the trust anchor and retry.",
            ),
            Self::CertificateExpired => Some(
                "The partner's signing certificate has passed its notAfter validity date. \
                 Request a renewed certificate from the trading partner. \
                 Do not extend trust to expired certificates.",
            ),
            Self::Timeout => Some(
                "The remote endpoint did not respond within the configured timeout. \
                 Verify network connectivity and DNS resolution. \
                 Apply exponential back-off before retrying.",
            ),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AsxError {
    pub code: ErrorCode,
    pub message: String,
    pub context: ErrorContext,
}

impl AsxError {
    pub fn new(code: ErrorCode, message: impl Into<String>, context: ErrorContext) -> Self {
        Self {
            code,
            message: message.into(),
            context,
        }
    }

    /// Short operator-facing remediation hint, delegated from [`ErrorCode::remediation_hint`].
    ///
    /// Returns `None` for error codes that do not have a generic hint.
    pub fn remediation_hint(&self) -> Option<&'static str> {
        self.code.remediation_hint()
    }

    /// Enrich the error context with the partner ID for easier correlation in embedder logs.
    ///
    /// Delegates to [`ErrorContext::with_partner_id`]. Designed for use in `map_err` closures
    /// where the full `ErrorContext` is not directly accessible:
    ///
    /// ```ignore
    /// some_op().map_err(|e| e.with_partner_id(session.partner_id()))?;
    /// ```
    #[must_use]
    pub fn with_partner_id(mut self, partner_id: impl Into<String>) -> Self {
        self.context = self.context.with_partner_id(partner_id);
        self
    }

    /// Enrich the error context with the session ID for easier correlation in embedder logs.
    ///
    /// Delegates to [`ErrorContext::with_session_id`].
    #[must_use]
    pub fn with_session_id(mut self, session_id: impl Into<String>) -> Self {
        self.context = self.context.with_session_id(session_id);
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
        self.context = self
            .context
            .with_session_and_partner(session_id, partner_id);
        self
    }

    /// Enrich the error context with the message ID for easier correlation in embedder logs.
    ///
    /// Delegates to [`ErrorContext::with_message_id`].
    #[must_use]
    pub fn with_message_id(mut self, message_id: impl Into<String>) -> Self {
        self.context = self.context.with_message_id(message_id);
        self
    }

    /// Returns `true` if this error represents a replay-protection rejection
    /// (the message was already seen by the dedup store).
    ///
    /// Equivalent to `err.code == ErrorCode::ReliabilityFailure && err.message contains "replay"`,
    /// but stable across message-text changes.  Use this instead of matching on error text.
    ///
    /// # Example
    /// ```rust,ignore
    /// if let Err(e) = receive_push_with_dedup_async(...).await {
    ///     if e.is_duplicate() {
    ///         // idempotent: send receipt without re-processing
    ///     }
    /// }
    /// ```
    ///
    /// **Prefer [`asx_rs::as4::As4ReceiveOutcome`] over this method** — the discriminated
    /// outcome enum is the primary API for duplicate detection on the receive path.
    /// This method is provided for error-path scenarios (e.g., when a storage backend
    /// fails-closed and propagates a duplicate as an error rather than an outcome).
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[non_exhaustive]
pub enum InteropMode {
    #[default]
    Strict,
    /// Relaxed interoperability mode — permits deviations from strict AS2/AS4
    /// profile requirements to accommodate legacy or non-conformant partners.
    ///
    /// # Feature gate
    ///
    /// This variant is only available when the **`interop-relaxed`** Cargo
    /// feature is enabled:
    ///
    /// ```toml
    /// [dependencies]
    /// asx = { version = "0.5", features = ["interop-relaxed"] }
    /// ```
    #[cfg(feature = "interop-relaxed")]
    Relaxed,
}

/// Per-partner session context — identity, trust configuration, and correlation
/// metadata required by every send/receive operation in `asx`.
///
/// # Cardinality and Lifetime
///
/// `SessionContext` is scoped to **one trading-partner relationship** and
/// represents a reusable, long-lived object — not a per-message allocation.
/// Typical lifecycle patterns:
///
/// | Deployment style | Recommended granularity |
/// |---|---|
/// | Single fixed partner (e.g. one supplier) | One `SessionContext` per process; share via `Arc`. |
/// | Multiple partners (hub/spoke) | One `SessionContext` per partner; keyed by `partner_id`. |
/// | Short-lived CLI / batch | One `SessionContext` per batch run; `Clone` is O(1). |
///
/// Using a *new* `SessionContext` for every outbound message is valid but
/// wasteful — it pays session-ID generation and cert-validation costs on every
/// call.  Prefer reusing and, when certificates rotate, call
/// [`rotate_cert_handle`] in place rather than rebuilding.
///
/// # Observability Impact
///
/// The `session_id` is emitted on every span, metric label, and error context
/// produced during message processing.  Using inconsistent or randomly
/// generated `session_id` values per message will fragment observability data
/// in your monitoring backend and make per-partner dashboards unusable.
/// Choose a stable, human-readable ID such as `"partner-acme-prod"`.
///
/// # Cloning
///
/// `Clone` is O(1) — all heavy data (certificates, trust anchors) is behind
/// `Arc` and is not deep-copied.  Clones share the same `CertHandle` lineage
/// until [`rotate_cert_handle`] is called on one of them.
///
/// # Construction
///
/// Prefer [`SessionContext::builder`] for incremental construction, or
/// [`SessionContext::new`] for the minimal three-field shorthand.
///
/// [`rotate_cert_handle`]: SessionContext::rotate_cert_handle
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionContext {
    session_id: String,
    partner_id: String,
    profile_name: String,
    metadata: SessionMetadata,
    /// The certificate/trust configuration for this session.
    ///
    /// Stored behind an `Arc` so that:
    /// - `SessionContext::clone()` is O(1) — increments a refcount rather than
    ///   deep-copying all PEM strings and DER blobs.
    /// - In-flight verifications continue using the cert snapshot they started
    ///   with even after a rotation (Arc keeps the old handle alive).
    /// - [`rotate_cert_handle`] can swap the handle without rebuilding the session,
    ///   preserving `session_id`, `partner_id`, reliability queues, and event
    ///   subscriptions.
    ///
    /// Access via [`SessionContext::cert_handle`].
    ///
    /// [`rotate_cert_handle`]: SessionContext::rotate_cert_handle
    cert_handle: Arc<CertHandle>,
    correlation_scope: CorrelationScope,
    /// Lazy-parsed trust-anchor cache.  Invalidated whenever `cert_handle` is
    /// replaced via [`with_cert_handle`] or [`rotate_cert_handle`].
    ///
    /// [`with_cert_handle`]: SessionContext::with_cert_handle
    /// [`rotate_cert_handle`]: SessionContext::rotate_cert_handle
    #[cfg(any(feature = "as2", feature = "as4"))]
    trust_anchors_cache: TrustAnchorCache,
    /// Lazy-built X.509 store derived from `trust_anchor_pems`.
    /// Invalidated whenever `cert_handle` is replaced.
    #[cfg(any(feature = "as2", feature = "as4"))]
    x509_store_cache: X509StoreCache,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SessionMetadata {
    pub effective_policy_snapshot_json: Option<String>,
    pub strict_runtime_bootstrap_validated: bool,
}

/// Builder for ergonomic incremental construction of [`SessionContext`].
#[derive(Debug, Clone)]
pub struct SessionContextBuilder {
    session_id: String,
    partner_id: String,
    profile_name: String,
    cert_handle: Option<CertHandle>,
    effective_policy_snapshot_json: Option<String>,
    correlation_scope: Option<CorrelationScope>,
}

impl SessionContextBuilder {
    /// Create a new builder with required identity fields.
    ///
    /// `profile_name` defaults to `"strict"` and can be overridden with
    /// [`profile_name`][Self::profile_name].
    pub fn new(session_id: impl Into<String>, partner_id: impl Into<String>) -> Self {
        Self {
            session_id: session_id.into(),
            partner_id: partner_id.into(),
            profile_name: "strict".to_string(),
            cert_handle: None,
            effective_policy_snapshot_json: None,
            correlation_scope: None,
        }
    }

    /// Override the profile name (defaults to `"strict"`).
    pub fn profile_name(mut self, profile_name: impl Into<String>) -> Self {
        self.profile_name = profile_name.into();
        self
    }

    /// Set explicit certificate/trust material for the session.
    pub fn cert_handle(mut self, cert_handle: CertHandle) -> Self {
        self.cert_handle = Some(cert_handle);
        self
    }

    /// Return a key_id string derived from the partner_id, matching the
    /// pattern used by [`SessionContext::new`] for the default `CertHandle`.
    fn default_cert_handle_key_id(&self) -> String {
        format!("cert:{}", self.partner_id)
    }

    /// Get or lazily create the builder's CertHandle with a sensible key_id.
    fn cert_handle_or_init(&mut self) -> &mut CertHandle {
        let key_id = self.default_cert_handle_key_id();
        self.cert_handle
            .get_or_insert_with(|| CertHandle::new(key_id))
    }

    /// Append a single PEM-encoded trust anchor to the session's certificate store.
    ///
    /// This is a convenience alternative to constructing a [`CertHandle`] manually.
    /// Can be called multiple times to build up a set of trusted root/intermediate CAs.
    ///
    /// # Example
    /// ```rust,ignore
    /// let session = SessionContextBuilder::new("s1", "partner-a")
    ///     .with_trust_anchor_pem(root_ca_pem)
    ///     .build()?;
    /// ```
    pub fn with_trust_anchor_pem(mut self, pem: impl Into<String>) -> Self {
        self.cert_handle_or_init()
            .trust_anchor_pems
            .push(pem.into());
        self
    }

    /// Append multiple PEM-encoded trust anchors to the session's certificate store.
    ///
    /// Equivalent to calling [`with_trust_anchor_pem`][Self::with_trust_anchor_pem]
    /// in a loop.
    pub fn with_trust_anchor_pems(
        mut self,
        pems: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        self.cert_handle_or_init()
            .trust_anchor_pems
            .extend(pems.into_iter().map(|p| p.into()));
        self
    }

    /// Set the OCSP revocation-check mode for the session.
    ///
    /// Defaults to [`OcspMode::default()`] when not specified.
    pub fn with_ocsp_mode(mut self, mode: OcspMode) -> Self {
        self.cert_handle_or_init().ocsp_mode = mode;
        self
    }

    /// Set the PEM-encoded X.509 certificate used to sign **outbound** messages.
    ///
    /// Must be called together with [`with_signing_key_pem`](Self::with_signing_key_pem).
    /// [`build`](Self::build) will return an error when only one of the signing
    /// pair is provided, or when the key does not match the certificate.
    ///
    /// Once set, `send_sync` / `send_async` use this certificate for every
    /// message sent on this session — no per-request `As4SendCredentials` /
    /// `As2SendCredentials` is required.  Per-request credentials remain
    /// available as an explicit override via `Some(creds)` on the send request.
    ///
    /// # Example
    /// ```rust,ignore
    /// let session = SessionContextBuilder::new("s1", "partner-a")
    ///     .with_signing_cert_pem(our_cert_pem)
    ///     .with_signing_key_pem(our_key_pem)
    ///     .with_trust_anchor_pem(partner_root_ca_pem)
    ///     .build()?;
    /// // All sends on this session are signed automatically.
    /// asx_rs::as4::send_sync(&session, &bus, As4SendRequest {
    ///     message_id,
    ///     payload,
    ///     policy,
    ///     credentials: None,  // ← session certificate used
    ///     payload_filename: None,
    /// })?;
    /// ```
    pub fn with_signing_cert_pem(mut self, pem: impl Into<String>) -> Self {
        self.cert_handle_or_init().signing_cert_pem = Some(pem.into());
        self
    }

    /// Set the PEM-encoded private key used to sign **outbound** messages.
    ///
    /// Must match the certificate supplied via
    /// [`with_signing_cert_pem`](Self::with_signing_cert_pem).  The raw key
    /// bytes are **zeroized on drop** via the `CertHandle` destructor.
    pub fn with_signing_key_pem(mut self, pem: impl Into<String>) -> Self {
        self.cert_handle_or_init().signing_key_pem = Some(zeroize::Zeroizing::new(pem.into()));
        self
    }

    /// Set the PEM-encoded X.509 certificate belonging to **this partner**,
    /// used to encrypt outbound messages when the send policy has
    /// `encrypt = true`.
    ///
    /// When set, sends with `encrypt = true` do not require a per-request
    /// `recipient_cert_pem` in `As4SendCredentials` / `As2SendCredentials`.
    pub fn with_recipient_cert_pem(mut self, pem: impl Into<String>) -> Self {
        self.cert_handle_or_init().recipient_cert_pem = Some(pem.into());
        self
    }

    /// Set both signing certificate and key in one call.
    ///
    /// Equivalent to chaining [`with_signing_cert_pem`](Self::with_signing_cert_pem)
    /// and [`with_signing_key_pem`](Self::with_signing_key_pem), but eliminates the
    /// intermediate half-configured state where one of the pair is set and the other
    /// is not.  [`build`](Self::build) validates that the cert and key match.
    pub fn with_signing_material(
        mut self,
        cert_pem: impl Into<String>,
        key_pem: impl Into<String>,
    ) -> Self {
        let ch = self.cert_handle_or_init();
        ch.signing_cert_pem = Some(cert_pem.into());
        ch.signing_key_pem = Some(zeroize::Zeroizing::new(key_pem.into()));
        self
    }

    /// Pin the expected SHA-256 fingerprint (lower-case hex, no separators) of
    /// the partner's signing certificate.
    ///
    /// When set, the WS-Security / S/MIME verifier rejects any message whose
    /// signing certificate does not match this fingerprint, even when the
    /// signature is cryptographically valid and the cert chains to a trust anchor.
    ///
    /// Useful for high-assurance deployments where the exact partner certificate
    /// is known in advance (e.g. BDEW regulated partners, Peppol cornernodes).
    pub fn with_fingerprint_sha256(mut self, fingerprint: impl Into<String>) -> Self {
        self.cert_handle_or_init().fingerprint_sha256 = fingerprint.into();
        self
    }

    /// Attach a serialized effective policy snapshot JSON string.
    pub fn effective_policy_snapshot_json(mut self, snapshot_json: impl Into<String>) -> Self {
        self.effective_policy_snapshot_json = Some(snapshot_json.into());
        self
    }

    /// Override the default correlation scope.
    pub fn correlation_scope(
        mut self,
        root_id: impl Into<String>,
        parent_message_id: Option<String>,
    ) -> Self {
        self.correlation_scope = Some(CorrelationScope {
            root_id: root_id.into(),
            parent_message_id,
            traceparent: None,
        });
        self
    }

    /// Build a validated [`SessionContext`].
    pub fn build(self) -> Result<SessionContext> {
        let mut session = SessionContext::new(self.session_id, self.partner_id, self.profile_name)?;

        if let Some(cert_handle) = self.cert_handle {
            // Validate that signing_key_pem and signing_cert_pem are both
            // present or both absent.
            match (&cert_handle.signing_key_pem, &cert_handle.signing_cert_pem) {
                (Some(_), None) | (None, Some(_)) => {
                    return Err(AsxError::new(
                        ErrorCode::InvalidInput,
                        "signing_key_pem and signing_cert_pem must both be set or both absent",
                        ErrorContext::new("session_context_builder"),
                    ));
                }
                _ => {}
            }
            // Eagerly parse and validate PEM material when crypto features are
            // available.  This surfaces key/cert mismatches at session
            // construction time rather than deep inside the send pipeline.
            #[cfg(any(feature = "as2", feature = "as4"))]
            validate_cert_handle_outbound_pem(&cert_handle)?;
            session = session.with_cert_handle(cert_handle)?;
        }

        if let Some(correlation_scope) = self.correlation_scope {
            if correlation_scope.root_id.trim().is_empty() {
                return Err(AsxError::new(
                    ErrorCode::InvalidInput,
                    "correlation root_id must not be empty",
                    ErrorContext::for_session("session_context_builder", &session),
                ));
            }
            session.correlation_scope = correlation_scope;
        }

        if let Some(snapshot_json) = self.effective_policy_snapshot_json {
            session = session.with_effective_policy_snapshot_json(snapshot_json)?;
        }

        Ok(session)
    }
}

/// Validate PEM-encoded outbound signing material stored in a `CertHandle`.
///
/// Called from `SessionContextBuilder::build` when `as2` or `as4` features
/// are active.  Parses the signing cert + key, verifies the key matches the
/// cert, and optionally parses the recipient cert if present.  All errors are
/// surfaced at session construction time rather than deep in the send pipeline.
#[cfg(any(feature = "as2", feature = "as4"))]
fn validate_cert_handle_outbound_pem(cert_handle: &CertHandle) -> Result<()> {
    if let (Some(key_pem), Some(cert_pem)) =
        (&cert_handle.signing_key_pem, &cert_handle.signing_cert_pem)
    {
        let cert = openssl::x509::X509::from_pem(cert_pem.as_bytes()).map_err(|_| {
            AsxError::new(
                ErrorCode::InvalidInput,
                "signing_cert_pem is not a valid PEM X.509 certificate",
                ErrorContext::new("session_context_builder_validate"),
            )
        })?;

        let key = openssl::pkey::PKey::private_key_from_pem(key_pem.as_bytes()).map_err(|_| {
            AsxError::new(
                ErrorCode::InvalidInput,
                "signing_key_pem is not a valid PEM private key",
                ErrorContext::new("session_context_builder_validate"),
            )
        })?;

        let cert_pub = cert.public_key().map_err(|_| {
            AsxError::new(
                ErrorCode::InvalidInput,
                "signing_cert_pem does not contain a usable public key",
                ErrorContext::new("session_context_builder_validate"),
            )
        })?;

        if !key.public_eq(&cert_pub) {
            return Err(AsxError::new(
                ErrorCode::InvalidInput,
                "signing_key_pem does not match signing_cert_pem",
                ErrorContext::new("session_context_builder_validate"),
            ));
        }
    }

    if let Some(pem) = &cert_handle.recipient_cert_pem {
        openssl::x509::X509::from_pem(pem.as_bytes()).map_err(|_| {
            AsxError::new(
                ErrorCode::InvalidInput,
                "recipient_cert_pem is not a valid PEM X.509 certificate",
                ErrorContext::new("session_context_builder_validate"),
            )
        })?;
    }

    Ok(())
}

/// Lazy cache of trust-anchor X.509 certificates parsed from
/// [`CertHandle::trust_anchor_pems`].  Shared across clones of the same
/// [`CertHandle`] via an `Arc` so that clones see the same populated cache
/// rather than re-parsing independently.
///
/// Equality is always `true` — the cache is an implementation detail derived
/// from the authoritative `trust_anchor_pems` field; it does not contribute to
/// the identity of a [`CertHandle`].
#[derive(Debug, Default, Clone)]
#[cfg(any(feature = "as2", feature = "as4"))]
pub(crate) struct TrustAnchorCache(Arc<OnceLock<Vec<openssl::x509::X509>>>);

#[cfg(any(feature = "as2", feature = "as4"))]
impl PartialEq for TrustAnchorCache {
    fn eq(&self, _: &Self) -> bool {
        true // cache state is not part of CertHandle identity
    }
}
#[cfg(any(feature = "as2", feature = "as4"))]
impl Eq for TrustAnchorCache {}

/// Lazy cache of the `X509Store` built from [`CertHandle::trust_anchor_pems`].
///
/// Caching avoids rebuilding an `X509Store` (O(n_anchors) OpenSSL allocations)
/// on every inbound message verification.  Shared across clones via `Arc`;
/// the store is built at most once per `CertHandle` lineage regardless of how
/// many clones exist.  Equality is always `true` (derived from `trust_anchor_pems`).
#[derive(Default, Clone)]
#[cfg(any(feature = "as2", feature = "as4"))]
pub(crate) struct X509StoreCache(Arc<OnceLock<Arc<openssl::x509::store::X509Store>>>);

#[cfg(any(feature = "as2", feature = "as4"))]
impl std::fmt::Debug for X509StoreCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("X509StoreCache")
            .field(&self.0.get().is_some())
            .finish()
    }
}

#[cfg(any(feature = "as2", feature = "as4"))]
impl PartialEq for X509StoreCache {
    fn eq(&self, _: &Self) -> bool {
        true
    }
}
#[cfg(any(feature = "as2", feature = "as4"))]
impl Eq for X509StoreCache {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertHandle {
    pub key_id: String,
    pub fingerprint_sha256: String,
    pub trust_anchor_pems: Vec<String>,
    /// Intermediate CA certificates (PEM) used for chain building during
    /// signature verification.  Supply any CAs that issued the partner's
    /// signing certificate when those intermediates are not embedded in
    /// the signed payload and are not already in `trust_anchor_pems`.
    pub intermediate_ca_pems: Vec<String>,
    pub revocation_crl_pems: Vec<String>,
    pub ocsp_mode: OcspMode,
    pub ocsp_failure_mode: OcspFailureMode,
    pub stapled_ocsp_responses_der: Vec<Vec<u8>>,
    pub responder_ocsp_responses_der: Vec<Vec<u8>>,
    /// PEM-encoded X.509 certificate used to sign **outbound** messages to
    /// this partner.  When set via
    /// [`SessionContextBuilder::with_signing_cert_pem`], `send_sync` /
    /// `send_async` use this certificate automatically; no per-request
    /// `As4SendCredentials` / `As2SendCredentials` is required.
    ///
    /// Must be paired with [`signing_key_pem`](Self::signing_key_pem).
    /// [`SessionContextBuilder::build`] validates the pair and checks that
    /// the key matches the certificate.
    pub signing_cert_pem: Option<String>,
    /// PEM-encoded private key matching
    /// [`signing_cert_pem`](Self::signing_cert_pem).
    ///
    /// # Security
    ///
    /// The key bytes are **zeroized on drop** via the `Zeroizing` wrapper.
    /// Do not log or persist a `CertHandle` that contains live key material.
    pub signing_key_pem: Option<zeroize::Zeroizing<String>>,
    /// PEM-encoded X.509 certificate belonging to this partner, used to
    /// encrypt outbound AS4 / AS2 messages when the send policy has
    /// `encrypt = true` and no per-request credential is provided.
    pub recipient_cert_pem: Option<String>,
}

impl CertHandle {
    /// Construct a `CertHandle` with sensible defaults for the given key ID.
    ///
    /// All PEM/DER fields default to empty (`Vec::new()`), with OCSP mode
    /// `ResponderOnly` and `HardFail`.  Override any field with struct update
    /// syntax before passing to [`SessionContext::with_cert_handle`] or
    /// [`SessionContext::rotate_cert_handle`]:
    ///
    /// ```rust,ignore
    /// let handle = CertHandle {
    ///     trust_anchor_pems: vec![root_pem],
    ///     ocsp_mode: OcspMode::Disabled,
    ///     ..CertHandle::new("partner-cert")
    /// };
    /// ```
    pub fn new(key_id: impl Into<String>) -> Self {
        Self {
            key_id: key_id.into(),
            fingerprint_sha256: String::new(),
            trust_anchor_pems: Vec::new(),
            intermediate_ca_pems: Vec::new(),
            revocation_crl_pems: Vec::new(),
            ocsp_mode: OcspMode::default(),
            ocsp_failure_mode: OcspFailureMode::HardFail,
            stapled_ocsp_responses_der: Vec::new(),
            responder_ocsp_responses_der: Vec::new(),
            signing_cert_pem: None,
            signing_key_pem: None,
            recipient_cert_pem: None,
        }
    }

    /// Set the PEM-encoded private key for outbound signing without requiring
    /// callers to depend on the `zeroize` crate directly.
    ///
    /// The key bytes are automatically wrapped in [`zeroize::Zeroizing`] and
    /// will be zeroized on drop.
    pub fn set_signing_key_pem(&mut self, key_pem: impl Into<String>) {
        self.signing_key_pem = Some(zeroize::Zeroizing::new(key_pem.into()));
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum OcspMode {
    Disabled,
    StapledOnly,
    #[default]
    ResponderOnly,
    StapledThenResponder,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum OcspFailureMode {
    #[default]
    HardFail,
    SoftFail,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CorrelationScope {
    pub root_id: String,
    pub parent_message_id: Option<String>,
    /// Inbound W3C Trace Context `traceparent` header value, if present and valid.
    ///
    /// Populated by the transport ingress layer for inbound messages and
    /// propagated into every [`ScopedAsxEvent`] emitted during the
    /// corresponding processing session, enabling distributed-trace correlation
    /// with upstream callers.
    ///
    /// [`ScopedAsxEvent`]: crate::observability::ScopedAsxEvent
    pub traceparent: Option<Arc<str>>,
}

/// Payload bytes supplied to AS2/AS4 send/receive operations.
///
/// Consolidates the previously separate `As2PayloadInput` and `PushPayloadInput` types.
/// `Shared` avoids a copy when the caller already holds an `Arc<[u8]>`.
#[non_exhaustive]
pub enum PayloadInput<'a> {
    Owned(Vec<u8>),
    Shared(Arc<[u8]>),
    Borrowed(&'a [u8]),
}

impl<'a> PayloadInput<'a> {
    pub fn as_slice(&self) -> &[u8] {
        match self {
            Self::Owned(payload) => payload,
            Self::Shared(payload) => payload,
            Self::Borrowed(payload) => payload,
        }
    }

    pub fn into_arc(self) -> Arc<[u8]> {
        match self {
            Self::Owned(payload) => Arc::from(payload),
            Self::Shared(payload) => payload,
            Self::Borrowed(payload) => Arc::from(payload),
        }
    }
}

/// Receive-body abstraction used by verifier contracts.
///
/// In-memory handles avoid extra copies, while spooled handles keep large
/// messages out of RSS and make materialization an explicit decision point.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SpoolEncryption {
    Plaintext,
    Aes256Gcm { key: Arc<[u8; 32]> },
}

pub(crate) const SPOOLED_AES256_GCM_MAGIC: [u8; 8] = *b"ASXSPG01";
pub(crate) const SPOOLED_AES256_GCM_NONCE_LEN: usize = 12;
pub(crate) const SPOOLED_AES256_GCM_TAG_LEN: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpoolLifecyclePolicy {
    pub delete_on_materialize: bool,
    pub secure_delete_on_materialize: bool,
}

impl Default for SpoolLifecyclePolicy {
    fn default() -> Self {
        Self {
            delete_on_materialize: true,
            secure_delete_on_materialize: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ReceivedBodyHandle {
    InMemory(Arc<[u8]>),
    Spooled {
        path: PathBuf,
        encryption: SpoolEncryption,
        lifecycle: SpoolLifecyclePolicy,
    },
}

impl ReceivedBodyHandle {
    #[must_use]
    pub fn from_payload_input(input: PayloadInput<'_>) -> Self {
        Self::InMemory(input.into_arc())
    }

    pub fn payload_len(&self, stage: &'static str, session: &SessionContext) -> Result<usize> {
        match self {
            Self::InMemory(bytes) => Ok(bytes.len()),
            Self::Spooled { path, .. } => {
                let metadata = std::fs::metadata(path).map_err(|err| {
                    AsxError::new(
                        ErrorCode::TransportFailure,
                        format!("failed to stat spooled body {}: {err}", path.display()),
                        ErrorContext::for_session(stage, session),
                    )
                })?;
                usize::try_from(metadata.len()).map_err(|_| {
                    AsxError::new(
                        ErrorCode::PolicyViolation,
                        format!(
                            "spooled body {} exceeds platform addressable size",
                            path.display()
                        ),
                        ErrorContext::for_session(stage, session),
                    )
                })
            }
        }
    }

    pub fn materialize_contiguous(
        &self,
        stage: &'static str,
        session: &SessionContext,
    ) -> Result<Arc<[u8]>> {
        match self {
            Self::InMemory(bytes) => Ok(Arc::clone(bytes)),
            Self::Spooled {
                path, encryption, ..
            } => Ok(Arc::from(read_spooled_bytes(
                path, encryption, stage, session,
            )?)),
        }
    }

    pub fn into_arc(self, stage: &'static str, session: &SessionContext) -> Result<Arc<[u8]>> {
        match self {
            Self::InMemory(bytes) => Ok(bytes),
            Self::Spooled {
                path,
                encryption,
                lifecycle,
            } => {
                let bytes = read_spooled_bytes(&path, &encryption, stage, session)?;
                if lifecycle.delete_on_materialize {
                    delete_spooled_file(
                        &path,
                        lifecycle.secure_delete_on_materialize,
                        stage,
                        session,
                    )?;
                }
                Ok(Arc::from(bytes))
            }
        }
    }

    pub fn dispose(self, stage: &'static str, session: &SessionContext) -> Result<()> {
        match self {
            Self::InMemory(_) => Ok(()),
            Self::Spooled {
                path, lifecycle, ..
            } => {
                if lifecycle.delete_on_materialize {
                    delete_spooled_file(
                        &path,
                        lifecycle.secure_delete_on_materialize,
                        stage,
                        session,
                    )?;
                }
                Ok(())
            }
        }
    }
}

fn read_spooled_bytes(
    path: &Path,
    encryption: &SpoolEncryption,
    stage: &'static str,
    session: &SessionContext,
) -> Result<Vec<u8>> {
    let bytes = std::fs::read(path).map_err(|err| {
        AsxError::new(
            ErrorCode::TransportFailure,
            format!("failed to read spooled body {}: {err}", path.display()),
            ErrorContext::for_session(stage, session),
        )
    })?;

    match encryption {
        SpoolEncryption::Plaintext => Ok(bytes),
        SpoolEncryption::Aes256Gcm { key } => {
            let min_len = SPOOLED_AES256_GCM_MAGIC.len()
                + SPOOLED_AES256_GCM_NONCE_LEN
                + SPOOLED_AES256_GCM_TAG_LEN;
            if bytes.len() < min_len {
                return Err(AsxError::new(
                    ErrorCode::DecryptionFailed,
                    format!(
                        "spooled encrypted body {} is too short for AES-GCM envelope",
                        path.display()
                    ),
                    ErrorContext::for_session(stage, session),
                ));
            }

            let magic = &bytes[..SPOOLED_AES256_GCM_MAGIC.len()];
            if magic != SPOOLED_AES256_GCM_MAGIC {
                return Err(AsxError::new(
                    ErrorCode::DecryptionFailed,
                    format!(
                        "spooled encrypted body {} has invalid envelope magic",
                        path.display()
                    ),
                    ErrorContext::for_session(stage, session),
                ));
            }

            let nonce_start = SPOOLED_AES256_GCM_MAGIC.len();
            let nonce_end = nonce_start + SPOOLED_AES256_GCM_NONCE_LEN;
            let tag_start = bytes.len() - SPOOLED_AES256_GCM_TAG_LEN;
            let nonce = &bytes[nonce_start..nonce_end];
            let ciphertext = &bytes[nonce_end..tag_start];
            let tag = &bytes[tag_start..];

            decrypt_spooled_aes256_gcm(path, key.as_ref(), nonce, ciphertext, tag, stage, session)
        }
    }
}

#[cfg(any(feature = "as2", feature = "as4", feature = "async-ocsp"))]
fn decrypt_spooled_aes256_gcm(
    path: &Path,
    key: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
    tag: &[u8],
    stage: &'static str,
    session: &SessionContext,
) -> Result<Vec<u8>> {
    openssl::symm::decrypt_aead(
        openssl::symm::Cipher::aes_256_gcm(),
        key,
        Some(nonce),
        &[],
        ciphertext,
        tag,
    )
    .map_err(|err| {
        AsxError::new(
            ErrorCode::DecryptionFailed,
            format!(
                "failed to decrypt spooled encrypted body {}: {err}",
                path.display()
            ),
            ErrorContext::for_session(stage, session),
        )
    })
}

#[cfg(not(any(feature = "as2", feature = "as4", feature = "async-ocsp")))]
fn decrypt_spooled_aes256_gcm(
    path: &Path,
    _key: &[u8],
    _nonce: &[u8],
    _ciphertext: &[u8],
    _tag: &[u8],
    stage: &'static str,
    session: &SessionContext,
) -> Result<Vec<u8>> {
    Err(AsxError::new(
        ErrorCode::PolicyViolation,
        format!(
            "spool AES-256-GCM decryption unavailable for {} without crypto protocol features",
            path.display()
        ),
        ErrorContext::for_session(stage, session),
    ))
}

fn delete_spooled_file(
    path: &Path,
    secure_delete: bool,
    stage: &'static str,
    session: &SessionContext,
) -> Result<()> {
    if secure_delete {
        use std::io::{Seek, SeekFrom, Write};

        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .map_err(|err| {
                AsxError::new(
                    ErrorCode::TransportFailure,
                    format!(
                        "failed to open spooled file {} for secure delete: {err}",
                        path.display()
                    ),
                    ErrorContext::for_session(stage, session),
                )
            })?;
        let file_len = file
            .metadata()
            .map_err(|err| {
                AsxError::new(
                    ErrorCode::TransportFailure,
                    format!(
                        "failed to stat spooled file {} for secure delete: {err}",
                        path.display()
                    ),
                    ErrorContext::for_session(stage, session),
                )
            })?
            .len();

        file.seek(SeekFrom::Start(0)).map_err(|err| {
            AsxError::new(
                ErrorCode::TransportFailure,
                format!(
                    "failed to seek spooled file {} for secure delete: {err}",
                    path.display()
                ),
                ErrorContext::for_session(stage, session),
            )
        })?;

        let zeroes = vec![0u8; 8192];
        let mut remaining = file_len;
        while remaining > 0 {
            let write_len =
                usize::try_from(remaining.min(zeroes.len() as u64)).unwrap_or(zeroes.len());
            file.write_all(&zeroes[..write_len]).map_err(|err| {
                AsxError::new(
                    ErrorCode::TransportFailure,
                    format!(
                        "failed to overwrite spooled file {} for secure delete: {err}",
                        path.display()
                    ),
                    ErrorContext::for_session(stage, session),
                )
            })?;
            remaining -= write_len as u64;
        }
        file.flush().map_err(|err| {
            AsxError::new(
                ErrorCode::TransportFailure,
                format!(
                    "failed to flush overwritten spooled file {}: {err}",
                    path.display()
                ),
                ErrorContext::for_session(stage, session),
            )
        })?;
        file.sync_all().map_err(|err| {
            AsxError::new(
                ErrorCode::TransportFailure,
                format!(
                    "failed to sync overwritten spooled file {}: {err}",
                    path.display()
                ),
                ErrorContext::for_session(stage, session),
            )
        })?;
    }

    std::fs::remove_file(path).map_err(|err| {
        AsxError::new(
            ErrorCode::TransportFailure,
            format!("failed to remove spooled file {}: {err}", path.display()),
            ErrorContext::for_session(stage, session),
        )
    })
}

impl SessionContext {
    /// Start building a [`SessionContext`] incrementally.
    pub fn builder(
        session_id: impl Into<String>,
        partner_id: impl Into<String>,
    ) -> SessionContextBuilder {
        SessionContextBuilder::new(session_id, partner_id)
    }

    pub fn new(
        session_id: impl Into<String>,
        partner_id: impl Into<String>,
        profile_name: impl Into<String>,
    ) -> Result<Self> {
        let session_id = session_id.into();
        let partner_id = partner_id.into();
        let profile_name = profile_name.into();

        if session_id.trim().is_empty() {
            return Err(AsxError::new(
                ErrorCode::InvalidInput,
                "session_id must not be empty",
                ErrorContext::new("session_context_init"),
            ));
        }
        if partner_id.trim().is_empty() {
            return Err(AsxError::new(
                ErrorCode::InvalidInput,
                "partner_id must not be empty",
                ErrorContext::new("session_context_init").with_session_id(&session_id),
            ));
        }
        if profile_name.trim().is_empty() {
            return Err(AsxError::new(
                ErrorCode::InvalidInput,
                "profile_name must not be empty",
                ErrorContext::new("session_context_init")
                    .with_session_and_partner(&session_id, &partner_id),
            ));
        }

        Ok(Self {
            metadata: SessionMetadata::default(),
            cert_handle: Arc::new(CertHandle::new(format!("cert:{partner_id}"))),
            correlation_scope: CorrelationScope {
                root_id: format!("corr:{session_id}"),
                parent_message_id: None,
                traceparent: None,
            },
            session_id,
            partner_id,
            profile_name,
            #[cfg(any(feature = "as2", feature = "as4"))]
            trust_anchors_cache: TrustAnchorCache::default(),
            #[cfg(any(feature = "as2", feature = "as4"))]
            x509_store_cache: X509StoreCache::default(),
        })
    }

    /// Validate and set the session's certificate/trust configuration (builder method).
    ///
    /// This is the primary way to attach certificate material when constructing a
    /// session.  For rotation on an already-live session, prefer
    /// [`rotate_cert_handle`] which takes `&mut self`.
    ///
    /// Both the trust-anchor parse cache and the X.509 store cache are reset so
    /// that the new handle's anchors are parsed fresh on first use.
    ///
    /// [`rotate_cert_handle`]: Self::rotate_cert_handle
    pub fn with_cert_handle(mut self, cert_handle: CertHandle) -> Result<Self> {
        Self::validate_cert_handle_fields(&cert_handle, "session_context_cert_update", &self)?;
        self.cert_handle = Arc::new(cert_handle);
        #[cfg(any(feature = "as2", feature = "as4"))]
        {
            self.trust_anchors_cache = TrustAnchorCache::default();
            self.x509_store_cache = X509StoreCache::default();
        }
        Ok(self)
    }

    /// Atomically rotate the certificate/trust configuration on a live session.
    ///
    /// Unlike [`with_cert_handle`], this takes `&mut self` and therefore works
    /// on an already-constructed session without rebuilding it.  The `session_id`,
    /// `partner_id`, profile, reliability queues, and event subscriptions are
    /// preserved.
    ///
    /// Any in-flight verification calls that were already dispatched continue
    /// using the previous `Arc<CertHandle>` snapshot until they complete; newly
    /// accepted messages see the updated configuration immediately.
    ///
    /// # Errors
    ///
    /// Returns `InvalidInput` if `cert_handle` fails the same validation as
    /// [`with_cert_handle`].
    ///
    /// [`with_cert_handle`]: Self::with_cert_handle
    pub fn rotate_cert_handle(&mut self, cert_handle: CertHandle) -> Result<()> {
        Self::validate_cert_handle_fields(&cert_handle, "session_context_cert_rotate", self)?;
        self.cert_handle = Arc::new(cert_handle);
        #[cfg(any(feature = "as2", feature = "as4"))]
        {
            self.trust_anchors_cache = TrustAnchorCache::default();
            self.x509_store_cache = X509StoreCache::default();
        }
        Ok(())
    }

    fn validate_cert_handle_fields(
        cert_handle: &CertHandle,
        stage: &'static str,
        session: &SessionContext,
    ) -> Result<()> {
        if cert_handle.key_id.trim().is_empty() {
            return Err(AsxError::new(
                ErrorCode::InvalidInput,
                "cert handle key_id must not be empty",
                ErrorContext::for_session(stage, session),
            ));
        }
        if cert_handle
            .trust_anchor_pems
            .iter()
            .any(|pem| pem.trim().is_empty())
            || cert_handle
                .revocation_crl_pems
                .iter()
                .any(|pem| pem.trim().is_empty())
            || cert_handle
                .stapled_ocsp_responses_der
                .iter()
                .any(Vec::is_empty)
            || cert_handle
                .responder_ocsp_responses_der
                .iter()
                .any(Vec::is_empty)
        {
            return Err(AsxError::new(
                ErrorCode::InvalidInput,
                "cert handle PKIX/OCSP material must not contain empty entries",
                ErrorContext::for_session(stage, session),
            ));
        }
        Ok(())
    }

    pub fn with_effective_policy_snapshot_json(
        mut self,
        snapshot_json: impl Into<String>,
    ) -> Result<Self> {
        let snapshot_json = snapshot_json.into();
        if snapshot_json.trim().is_empty() {
            return Err(AsxError::new(
                ErrorCode::InvalidInput,
                "effective policy snapshot JSON must not be empty",
                ErrorContext::for_session("session_context_metadata_update", &self),
            ));
        }
        self.metadata.effective_policy_snapshot_json = Some(snapshot_json);
        Ok(self)
    }

    pub fn effective_policy_snapshot_json(&self) -> Option<&str> {
        self.metadata.effective_policy_snapshot_json.as_deref()
    }

    /// Return whether this session is explicitly marked as startup-validated
    /// for strict-runtime protocol entry point enforcement.
    pub fn strict_runtime_bootstrap_validated(&self) -> bool {
        self.metadata.strict_runtime_bootstrap_validated
    }

    /// Return a cloned session marked with strict-runtime bootstrap validation state.
    pub fn with_strict_runtime_bootstrap_validated(mut self, validated: bool) -> Self {
        self.metadata.strict_runtime_bootstrap_validated = validated;
        self
    }

    /// Set strict-runtime bootstrap validation state on an existing session.
    pub fn set_strict_runtime_bootstrap_validated(&mut self, validated: bool) {
        self.metadata.strict_runtime_bootstrap_validated = validated;
    }

    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    pub fn partner_id(&self) -> &str {
        &self.partner_id
    }

    pub fn profile_name(&self) -> &str {
        &self.profile_name
    }

    pub fn cert_handle(&self) -> &CertHandle {
        self.cert_handle.as_ref()
    }

    /// Return the parsed trust-anchor X.509 certificates, parsing from
    /// `cert_handle.trust_anchor_pems` on first call and caching the result.
    ///
    /// Thread-safe: multiple concurrent callers share one parse via `OnceLock`.
    /// The cache is invalidated automatically when `with_cert_handle` or
    /// `rotate_cert_handle` is called on this session.
    #[cfg(any(feature = "as2", feature = "as4"))]
    pub(crate) fn trust_anchors_x509(&self) -> Result<Vec<openssl::x509::X509>> {
        if let Some(anchors) = self.trust_anchors_cache.0.get() {
            return Ok(anchors.clone());
        }
        let mut anchors = Vec::new();
        for pem in &self.cert_handle.trust_anchor_pems {
            let certs = openssl::x509::X509::stack_from_pem(pem.as_bytes()).map_err(|e| {
                AsxError::new(
                    ErrorCode::InvalidInput,
                    format!("invalid trust-anchor PEM in CertHandle: {e}"),
                    ErrorContext::new("session_parse_trust_anchors"),
                )
            })?;
            anchors.extend(certs);
        }
        let _ = self.trust_anchors_cache.0.set(anchors.clone());
        Ok(anchors)
    }

    /// Return an `Arc`-wrapped `X509Store` built from the trust-anchor PEMs.
    ///
    /// Built at most once per `(session, cert_handle)` pair and shared across
    /// clones.  The cache is invalidated automatically when `with_cert_handle`
    /// or `rotate_cert_handle` is called.
    #[cfg(any(feature = "as2", feature = "as4"))]
    pub(crate) fn trust_anchor_x509_store(&self) -> Result<Arc<openssl::x509::store::X509Store>> {
        if let Some(store) = self.x509_store_cache.0.get() {
            return Ok(Arc::clone(store));
        }
        let anchors = self.trust_anchors_x509()?;
        let mut builder = openssl::x509::store::X509StoreBuilder::new().map_err(|e| {
            AsxError::new(
                ErrorCode::InvalidInput,
                format!("failed to build X.509 trust store: {e}"),
                ErrorContext::new("session_build_x509_store"),
            )
        })?;
        for cert in &anchors {
            builder.add_cert(cert.clone()).map_err(|e| {
                AsxError::new(
                    ErrorCode::InvalidInput,
                    format!("failed to add trust anchor to X.509 store: {e}"),
                    ErrorContext::new("session_build_x509_store"),
                )
            })?;
        }
        let store = Arc::new(builder.build());
        let _ = self.x509_store_cache.0.set(Arc::clone(&store));
        Ok(store)
    }

    pub fn correlation_scope(&self) -> &CorrelationScope {
        &self.correlation_scope
    }

    /// Attach an inbound W3C Trace Context `traceparent` header value to this
    /// session so that every [`ScopedAsxEvent`] emitted during processing
    /// carries the upstream trace identifier.
    ///
    /// Typically called by the embedder's HTTP handler after parsing the
    /// inbound request with [`parse_as2_ingress_request`] or
    /// [`parse_as4_ingress_request`]:
    ///
    /// ```rust,ignore
    /// let ingress = parse_as4_ingress_request(&http_request)?;
    /// let session = SessionContext::new("s1", "partner", "strict")?
    ///     .with_incoming_traceparent(ingress.traceparent.as_deref());
    /// ```
    ///
    /// Passing `None` is a no-op (leaves any previously set value unchanged
    /// because inbound absence of the header should not clear a manually set
    /// value).
    ///
    /// [`ScopedAsxEvent`]: crate::observability::ScopedAsxEvent
    /// [`parse_as2_ingress_request`]: crate::transport::ingress::parse_as2_ingress_request
    /// [`parse_as4_ingress_request`]: crate::transport::ingress::parse_as4_ingress_request
    pub fn with_incoming_traceparent(mut self, traceparent: Option<&str>) -> Self {
        if let Some(tp) = traceparent {
            self.correlation_scope.traceparent = Some(Arc::from(tp));
        }
        self
    }

    /// Construct a minimal `SessionContext` for unit tests.
    ///
    /// Uses `OcspMode::Disabled` and soft-fail to avoid network I/O in tests.
    /// Prefer this over manually building `SessionContext` with `new()` in test code.
    #[cfg(any(test, feature = "testing"))]
    pub fn for_testing(session_id: impl Into<String>, partner_id: impl Into<String>) -> Self {
        let session_id = session_id.into();
        let partner_id = partner_id.into();
        Self {
            metadata: SessionMetadata::default(),
            cert_handle: Arc::new(CertHandle {
                ocsp_mode: OcspMode::Disabled,
                ocsp_failure_mode: OcspFailureMode::SoftFail,
                ..CertHandle::new(format!("cert:{partner_id}"))
            }),
            correlation_scope: CorrelationScope {
                root_id: format!("corr:{session_id}"),
                parent_message_id: None,
                traceparent: None,
            },
            session_id,
            partner_id,
            profile_name: "test".into(),
            #[cfg(any(feature = "as2", feature = "as4"))]
            trust_anchors_cache: TrustAnchorCache::default(),
            #[cfg(any(feature = "as2", feature = "as4"))]
            x509_store_cache: X509StoreCache::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escape_xml_prevents_injection() {
        // Test ampersand
        assert_eq!(escape_xml("A&B"), "A&amp;B");
        // Test less-than
        assert_eq!(escape_xml("A<B"), "A&lt;B");
        // Test greater-than
        assert_eq!(escape_xml("A>B"), "A&gt;B");
        // Test double quote
        assert_eq!(escape_xml("A\"B"), "A&quot;B");
        // Test combined injection attempt
        assert_eq!(
            escape_xml("msg<inject>B&C\"D"),
            "msg&lt;inject&gt;B&amp;C&quot;D"
        );
        // Test empty string
        assert_eq!(escape_xml(""), "");
        // Test string with no special chars
        assert_eq!(escape_xml("hello-world"), "hello-world");
        // XML 1.0 §2.2: NUL and other forbidden control chars must be stripped.
        assert_eq!(escape_xml("ab\x00cd"), "abcd");
        assert_eq!(escape_xml("\x01\x08\x0B\x0C\x0E\x1F\x7F"), "");
        // NUL inside markup-requiring content
        assert_eq!(escape_xml("a\x00<b\x00>"), "a&lt;b&gt;");
    }

    #[test]
    fn error_code_strings_are_stable() {
        assert_eq!(ErrorCode::TransportFailure.as_str(), "transport_failure");
        assert_eq!(ErrorCode::InteropViolation.as_str(), "interop_violation");
    }

    #[test]
    fn session_context_validation_rejects_empty_values() {
        assert!(SessionContext::new("", "p", "strict").is_err());
        assert!(SessionContext::new("s", "", "strict").is_err());
        assert!(SessionContext::new("s", "p", "").is_err());
    }

    #[test]
    fn session_context_has_deterministic_default_handles() {
        let session = SessionContext::new("s1", "partner-a", "strict").expect("session");
        assert_eq!(session.cert_handle().key_id, "cert:partner-a");
        assert_eq!(session.correlation_scope().root_id, "corr:s1");
        assert!(session.effective_policy_snapshot_json().is_none());
    }

    #[test]
    fn session_context_builder_supports_incremental_configuration() {
        let cert = CertHandle {
            trust_anchor_pems: vec!["anchor-pem".into()],
            ..CertHandle::new("partner-key")
        };

        let session = SessionContext::builder("s-builder", "partner-z")
            .profile_name("peppol")
            .cert_handle(cert)
            .effective_policy_snapshot_json("{\"mode\":\"Strict\"}")
            .correlation_scope("corr-custom", Some("parent-1".into()))
            .build()
            .expect("builder session");

        assert_eq!(session.session_id(), "s-builder");
        assert_eq!(session.partner_id(), "partner-z");
        assert_eq!(session.profile_name(), "peppol");
        assert_eq!(session.cert_handle().key_id, "partner-key");
        assert_eq!(session.correlation_scope().root_id, "corr-custom");
        assert_eq!(
            session.correlation_scope().parent_message_id.as_deref(),
            Some("parent-1")
        );
        assert_eq!(
            session.effective_policy_snapshot_json(),
            Some("{\"mode\":\"Strict\"}")
        );
    }

    #[test]
    fn session_context_builder_rejects_blank_correlation_root() {
        let err = SessionContext::builder("s-builder", "partner-z")
            .correlation_scope("  ", None)
            .build()
            .expect_err("must reject blank correlation root");
        assert_eq!(err.code, ErrorCode::InvalidInput);
    }

    #[test]
    fn session_context_metadata_attaches_snapshot_json() {
        let session = SessionContext::new("s1", "partner-a", "strict")
            .expect("session")
            .with_effective_policy_snapshot_json("{\"resolved_mode\":\"Strict\"}")
            .expect("snapshot json");

        assert_eq!(
            session.effective_policy_snapshot_json(),
            Some("{\"resolved_mode\":\"Strict\"}")
        );
    }

    #[test]
    fn session_context_metadata_rejects_empty_snapshot_json() {
        let err = SessionContext::new("s1", "partner-a", "strict")
            .expect("session")
            .with_effective_policy_snapshot_json("   ")
            .expect_err("must reject blank snapshot");
        assert_eq!(err.code, ErrorCode::InvalidInput);
    }

    #[test]
    fn cert_handle_new_has_expected_defaults() {
        let h = CertHandle::new("my-key");
        assert_eq!(h.key_id, "my-key");
        assert!(h.trust_anchor_pems.is_empty());
        assert_eq!(h.ocsp_mode, OcspMode::ResponderOnly);
        assert_eq!(h.ocsp_failure_mode, OcspFailureMode::HardFail);
    }

    #[test]
    fn cert_handle_struct_update_syntax_works() {
        let base = CertHandle::new("base-key");
        let updated = CertHandle {
            trust_anchor_pems: vec!["fake-pem".into()],
            ocsp_mode: OcspMode::Disabled,
            ..base
        };
        assert_eq!(updated.key_id, "base-key");
        assert_eq!(updated.trust_anchor_pems, vec!["fake-pem".to_string()]);
        assert_eq!(updated.ocsp_mode, OcspMode::Disabled);
    }

    #[test]
    fn rotate_cert_handle_preserves_session_identity() {
        let mut session =
            SessionContext::new("rotate-session", "partner-b", "strict").expect("session");
        let original_session_id = session.session_id().to_string();
        let original_partner_id = session.partner_id().to_string();
        let original_root_id = session.correlation_scope().root_id.clone();

        let new_cert = CertHandle {
            trust_anchor_pems: vec!["new-anchor-pem".into()],
            ..CertHandle::new("new-key")
        };
        session.rotate_cert_handle(new_cert).expect("rotate");

        assert_eq!(session.session_id(), original_session_id);
        assert_eq!(session.partner_id(), original_partner_id);
        assert_eq!(session.correlation_scope().root_id, original_root_id);
        assert_eq!(session.cert_handle().key_id, "new-key");
        assert_eq!(
            session.cert_handle().trust_anchor_pems,
            vec!["new-anchor-pem".to_string()]
        );
    }

    #[test]
    fn rotate_cert_handle_rejects_empty_key_id() {
        let mut session = SessionContext::new("s1", "p1", "strict").expect("session");
        let bad_cert = CertHandle::new("");
        assert!(session.rotate_cert_handle(bad_cert).is_err());
    }

    #[test]
    fn arc_cert_handle_clone_shares_same_pointer() {
        let session = SessionContext::new("s1", "p1", "strict").expect("session");
        let clone = session.clone();
        // Both sessions share the same Arc<CertHandle> pointer — O(1) clone.
        assert!(Arc::ptr_eq(&session.cert_handle, &clone.cert_handle));
    }

    #[test]
    #[cfg(any(feature = "as2", feature = "as4"))]
    fn with_cert_handle_resets_trust_anchor_cache() {
        // Verify that replacing cert_handle on a session resets the caches so
        // the new anchor PEMs are parsed fresh on next access.
        let session = SessionContext::new("s-cache", "partner-cache", "strict").expect("session");
        // The initial session has empty trust_anchor_pems — caches default.
        assert!(session.trust_anchors_cache.0.get().is_none());

        let new_handle = CertHandle::new("partner-cache-cert");
        // with_cert_handle always installs a fresh default cache, irrespective
        // of what was in the provided CertHandle.
        let session = session.with_cert_handle(new_handle).expect("set handle");
        assert!(session.trust_anchors_cache.0.get().is_none());

        // Struct update syntax now works from external callers too since
        // CertHandle has no pub(crate) fields.
        let handle2 = CertHandle {
            trust_anchor_pems: vec!["some-pem".into()],
            ..CertHandle::new("partner-cache-cert-2")
        };
        let _ = session.with_cert_handle(handle2);
    }

    // ── BUG-1 regression: builder convenience setters must derive key_id ──────

    #[test]
    fn builder_with_trust_anchor_pem_does_not_leave_empty_key_id() {
        // Any convenience builder setter should auto-derive key_id from partner_id,
        // so build() must not fail with "cert handle key_id must not be empty".
        let result = SessionContextBuilder::new("s1", "partner-xyz")
            .with_trust_anchor_pem("fake-pem")
            .build();
        assert!(result.is_ok(), "build() must not fail: {:?}", result);
        let session = result.unwrap();
        assert_eq!(
            session.cert_handle().key_id,
            "cert:partner-xyz",
            "key_id should be auto-derived from partner_id"
        );
    }

    #[test]
    fn builder_with_signing_cert_and_key_pem_do_not_leave_empty_key_id() {
        // Regression for BUG-1: with_signing_cert_pem / with_signing_key_pem
        // previously initialised CertHandle with key_id="" which caused build() to fail.
        // We cannot use real PEM material here, so just verify that the cert_handle
        // key_id is derived from partner_id.
        let builder =
            SessionContextBuilder::new("s1", "partner-abc").with_signing_cert_pem("not-real-pem");
        assert_eq!(
            builder.cert_handle.as_ref().expect("handle").key_id,
            "cert:partner-abc",
        );
    }

    #[test]
    fn builder_with_fingerprint_sha256_sets_field() {
        let builder =
            SessionContextBuilder::new("s1", "partner-fp").with_fingerprint_sha256("aabbcc");
        assert_eq!(
            builder
                .cert_handle
                .as_ref()
                .expect("handle")
                .fingerprint_sha256,
            "aabbcc",
        );
    }

    #[test]
    fn builder_with_signing_material_sets_both_fields() {
        let builder = SessionContextBuilder::new("s1", "partner-mat")
            .with_signing_material("cert-pem-value", "key-pem-value");
        let ch = builder.cert_handle.as_ref().expect("handle");
        assert_eq!(ch.signing_cert_pem.as_deref(), Some("cert-pem-value"));
        assert!(ch.signing_key_pem.is_some());
        assert_eq!(
            ch.signing_key_pem.as_ref().map(|s| s.as_str()),
            Some("key-pem-value")
        );
    }

    #[test]
    fn cert_handle_set_signing_key_pem_avoids_zeroize_dep() {
        let mut ch = CertHandle::new("key");
        ch.set_signing_key_pem("my-private-key");
        assert!(ch.signing_key_pem.is_some());
        assert_eq!(
            ch.signing_key_pem.as_ref().map(|s| s.as_str()),
            Some("my-private-key")
        );
    }
}
