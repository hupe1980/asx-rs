use std::sync::Arc;

/// Protocol identifier used in [`AsxEvent::OutboundPrepared`].
///
/// Using a typed enum rather than a raw `&'static str` prevents typos and
/// enables exhaustive matching in monitoring dashboards that pattern-match on
/// protocol names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize)]
#[non_exhaustive]
pub enum AsxProtocol {
    /// EDIINT AS2 (RFC 4130).
    As2,
    /// OASIS AS4 / ebMS3.
    As4,
}

impl AsxProtocol {
    /// Return the canonical lowercase string representation.
    ///
    /// Suitable for use as a metric label or log field.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::As2 => "as2",
            Self::As4 => "as4",
        }
    }
}

impl std::fmt::Display for AsxProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Ingress stage identifier used in [`AsxEvent::DuplicateDetected`].
///
/// Identifies which receive path detected the duplicate, enabling monitoring
/// dashboards to partition dedup counters by inbound channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize)]
#[non_exhaustive]
pub enum AsxIngressStage {
    /// AS2 `receive_with_mdn` path (MDN correlation dedup).
    As2ReceiveWithMdn,
    /// AS4 push receive path.
    As4ReceivePush,
    /// AS4 pull receive path.
    As4ReceivePull,
}

impl AsxIngressStage {
    /// Return the canonical snake_case string representation.
    ///
    /// The returned value is stable across releases and may be stored as part
    /// of dedup event logs or metrics labels.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::As2ReceiveWithMdn => "as2_receive_with_mdn",
            Self::As4ReceivePush => "as4_receive_push",
            Self::As4ReceivePull => "as4_receive_pull",
        }
    }
}

impl std::fmt::Display for AsxIngressStage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Protocol-level event emitted by AS2/AS4 send and receive pipelines.
///
/// Each variant carries only the fields that are *unique to that event type*.
/// Fields common to all events — `session_id`, `partner_id`, and `timestamp_ms` —
/// are hoisted to [`ScopedAsxEvent`] to eliminate redundant allocations.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[non_exhaustive]
pub enum AsxEvent {
    OutboundPrepared {
        message_id: Arc<str>,
        /// The AS2 or AS4 protocol that produced this message.
        protocol: AsxProtocol,
    },
    MicComputed {
        message_id: Arc<str>,
        digest_alg: &'static str,
        mic_base64: String,
    },
    MessageSigned {
        message_id: Arc<str>,
    },
    MessageEncrypted {
        message_id: Arc<str>,
    },
    MdnReceived {
        message_id: Arc<str>,
        disposition: String,
    },
    ReceiptReceived {
        message_id: Arc<str>,
        signal: &'static str,
    },
    ReceiptTaxonomyOutcome {
        message_id: Arc<str>,
        signal: &'static str,
        outcome: &'static str,
        detail: &'static str,
    },
    ReceiptTaxonomyAlertRaised {
        signal: &'static str,
        severity: &'static str,
        category: &'static str,
        observed_rate_ppm: u64,
        sample_size: u64,
    },
    RetryScheduled {
        message_id: Arc<str>,
        attempt: u32,
        reason: &'static str,
    },
    ReconciliationQueued {
        message_id: Arc<str>,
        reason: &'static str,
    },
    DuplicateDetected {
        message_id: Arc<str>,
        key: String,
        /// The receive path that detected the duplicate.
        ingress: AsxIngressStage,
    },
    InteropRelaxationApplied {
        message_id: Arc<str>,
        rule: &'static str,
        detail: &'static str,
    },
    InteropGuardrailEvaluated {
        message_id: Arc<str>,
        code: &'static str,
        outcome: &'static str,
        detail: &'static str,
    },
    MaterializationApplied {
        message_id: Arc<str>,
        stage: &'static str,
        reason: &'static str,
        bytes: usize,
        source: &'static str,
    },
    SpoolKeyProviderHealthChecked {
        provider: &'static str,
        backend: &'static str,
        auth_mode: &'static str,
        auth_fingerprint_label: Arc<str>,
        auth_rotation_hint: &'static str,
        health_state: &'static str,
        startup_self_test_ms: u64,
        resolve_key_ms: u64,
    },
    SpoolKeyProviderHealthCheckFailed {
        provider: &'static str,
        backend: &'static str,
        auth_mode: &'static str,
        auth_fingerprint_label: Arc<str>,
        auth_rotation_hint: &'static str,
        health_state: &'static str,
        phase: &'static str,
        error_code: &'static str,
    },
    SpoolKeyProviderHealthStateChanged {
        provider: &'static str,
        backend: &'static str,
        previous_state: &'static str,
        current_state: &'static str,
        reason: &'static str,
    },
    SpoolProviderHealthAlertRaised {
        severity: &'static str,
        category: &'static str,
        observed_rate_ppm: u64,
        sample_size: u64,
    },
    SpoolHeadroomChecked {
        stage: &'static str,
        free_bytes: u64,
        min_required_bytes: u64,
    },
    PullQueueOverflow {
        message_id: Arc<str>,
        action: &'static str,
        policy: &'static str,
    },
    /// OCSP response confirmed the signer certificate is **revoked**.
    ///
    /// This event is emitted whenever OCSP validation returns
    /// `OcspCertStatus::REVOKED` for the leaf (signer) certificate.
    /// The verification pipeline will fail with `SecurityVerificationFailed`,
    /// but this event allows monitoring systems to alert on revocation
    /// independently of the error return value.
    CertOcspRevoked {
        /// Message being verified when revocation was detected.
        message_id: Arc<str>,
        /// Subject CN from the revoked certificate (best-effort, empty string if unavailable).
        subject_cn: Arc<str>,
        /// Hex-encoded serial number of the revoked certificate.
        serial_hex: Arc<str>,
    },
    /// OCSP response returned an **unknown** status for the signer certificate.
    ///
    /// `Unknown` means the OCSP responder does not have revocation data for
    /// this certificate. Combined with `OcspFailureMode::HardFail`, the
    /// verification pipeline will fail; with `SoftFail` it will succeed.
    CertOcspUnknown {
        /// Message being verified when the unknown status was returned.
        message_id: Arc<str>,
        /// Subject CN from the certificate (best-effort, empty string if unavailable).
        subject_cn: Arc<str>,
    },
    /// Signer certificate is approaching expiry (within the warning window).
    ///
    /// Emitted after a successful verification pass when `not_after` is within
    /// `days_remaining_threshold` days. Allows pre-emptive certificate rotation
    /// before the partner's certificate expires and causes message rejections.
    CertNearExpiry {
        /// Message being verified during which expiry proximity was detected.
        message_id: Arc<str>,
        /// Subject CN from the certificate (best-effort, empty string if unavailable).
        subject_cn: Arc<str>,
        /// Days until `not_after` (rounded down).
        days_remaining: i64,
    },
    /// An AS2 inbound message requested asynchronous MDN delivery via a
    /// `mailto:` address in the `Disposition-Notification-To` header
    /// (RFC 4130 §7.3).
    ///
    /// The library **does not dispatch SMTP email** — that is the embedder's
    /// responsibility.  This event is emitted so that observability backends
    /// can alert when async MDN dispatch is expected but may not have been
    /// implemented by the host application.
    ///
    /// The `mailto_address` field contains the raw value extracted from the
    /// `Disposition-Notification-To` header after the `mailto:` prefix is
    /// stripped.
    As2AsyncMdnRequested {
        message_id: Arc<str>,
        /// The `mailto:` address extracted from `Disposition-Notification-To`.
        mailto_address: Arc<str>,
    },
    // ── Outbound delivery result events ────────────────────────────────────────
    //
    // These events complete the outbound observability story.  Monitoring systems
    // can subscribe to `MessageSent` / `MessageSendFailed` to build end-to-end
    // delivery dashboards without adding custom instrumentation in every embedder.
    /// Outbound message was sent successfully and the receipt/MDN was acknowledged.
    ///
    /// Emitted after the HTTP response with a positive receipt signal is received.
    MessageSent {
        message_id: Arc<str>,
        /// Endpoint URL the message was delivered to.
        endpoint_url: Arc<str>,
        /// Total round-trip time in milliseconds (send + receipt processing).
        duration_ms: u64,
    },
    /// All retry attempts exhausted — outbound delivery failed permanently.
    ///
    /// Emitted when the retry scheduler gives up after exhausting the configured
    /// retry budget.  The `total_attempts` count includes the initial attempt.
    MessageSendFailed {
        message_id: Arc<str>,
        /// Human-readable reason for the final failure.
        reason: &'static str,
        /// Total number of delivery attempts made (initial + retries).
        total_attempts: u32,
    },
    // ── Large-message fragment progress events ─────────────────────────────────
    //
    // These events allow monitoring systems to track reassembly progress and
    // detect stuck or abandoned large-message transfers without requiring
    // embedder-side instrumentation.
    /// A fragment was successfully ingested into the joiner.
    ///
    /// Emitted by `As4FragmentJoiner::ingest_fragment` for every accepted
    /// fragment.  `expected_total` is `None` until a fragment carrying the
    /// fragment count is received.
    FragmentIngested {
        /// AS4 large-message `GroupId` (sender-scope-qualified).
        group_id: Arc<str>,
        /// Zero-based fragment number of the ingested fragment.
        fragment_num: usize,
        /// Number of distinct fragments received so far (including this one).
        received_so_far: usize,
        /// Expected total fragment count, if known.
        expected_total: Option<usize>,
    },
    /// All fragments received — reassembly is complete.
    ///
    /// Emitted by `As4FragmentJoiner::ingest_fragment` when the last expected
    /// fragment arrives and the full message has been reconstructed.
    FragmentGroupComplete {
        /// AS4 large-message `GroupId`.
        group_id: Arc<str>,
        /// Total number of fragments that made up the message.
        total_fragments: usize,
        /// Total reconstructed payload size in bytes.
        total_bytes: usize,
    },
    /// A fragment group was evicted before all fragments arrived.
    ///
    /// Emitted by `As4FragmentJoiner` when a group is evicted due to:
    /// - Count limit (`max_concurrent_groups`) exhausted.
    /// - Byte limit (`max_bytes_per_group`) exceeded.
    /// - Age limit (`max_group_age`) exceeded via `prune_stale_groups`.
    /// - Protocol violation (duplicate fragment, count mismatch, etc.).
    ///
    /// The `reason` field distinguishes between limit types and protocol errors.
    FragmentGroupEvicted {
        /// AS4 large-message `GroupId`.
        group_id: Arc<str>,
        /// Machine-readable eviction reason.
        ///
        /// Stable values: `"count_limit"`, `"byte_limit"`, `"age_limit"`,
        /// `"duplicate_fragment"`, `"count_mismatch"`, `"protocol_violation"`.
        reason: &'static str,
    },
}

impl AsxEvent {
    pub fn kind(&self) -> &'static str {
        match self {
            Self::OutboundPrepared { .. } => "outbound_prepared",
            Self::MicComputed { .. } => "mic_computed",
            Self::MessageSigned { .. } => "message_signed",
            Self::MessageEncrypted { .. } => "message_encrypted",
            Self::MdnReceived { .. } => "mdn_received",
            Self::ReceiptReceived { .. } => "receipt_received",
            Self::ReceiptTaxonomyOutcome { .. } => "receipt_taxonomy_outcome",
            Self::ReceiptTaxonomyAlertRaised { .. } => "receipt_taxonomy_alert_raised",
            Self::RetryScheduled { .. } => "retry_scheduled",
            Self::ReconciliationQueued { .. } => "reconciliation_queued",
            Self::DuplicateDetected { .. } => "duplicate_detected",
            Self::InteropRelaxationApplied { .. } => "interop_relaxation_applied",
            Self::InteropGuardrailEvaluated { .. } => "interop_guardrail_evaluated",
            Self::MaterializationApplied { .. } => "materialization_applied",
            Self::SpoolKeyProviderHealthChecked { .. } => "spool_key_provider_health_checked",
            Self::SpoolKeyProviderHealthCheckFailed { .. } => {
                "spool_key_provider_health_check_failed"
            }
            Self::SpoolKeyProviderHealthStateChanged { .. } => {
                "spool_key_provider_health_state_changed"
            }
            Self::SpoolProviderHealthAlertRaised { .. } => "spool_provider_health_alert_raised",
            Self::SpoolHeadroomChecked { .. } => "spool_headroom_checked",
            Self::PullQueueOverflow { .. } => "pull_queue_overflow",
            Self::CertOcspRevoked { .. } => "cert_ocsp_revoked",
            Self::CertOcspUnknown { .. } => "cert_ocsp_unknown",
            Self::CertNearExpiry { .. } => "cert_near_expiry",
            Self::As2AsyncMdnRequested { .. } => "as2_async_mdn_requested",
            Self::MessageSent { .. } => "message_sent",
            Self::MessageSendFailed { .. } => "message_send_failed",
            Self::FragmentIngested { .. } => "fragment_ingested",
            Self::FragmentGroupComplete { .. } => "fragment_group_complete",
            Self::FragmentGroupEvicted { .. } => "fragment_group_evicted",
        }
    }
}

pub type SharedAsxEvent = Arc<AsxEvent>;

/// An [`AsxEvent`] annotated with session-scoped context.
///
/// The `session_id`, `partner_id`, and `timestamp_ms` fields are common across
/// all events and are stored here once rather than in every [`AsxEvent`] variant.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ScopedAsxEvent {
    pub session_id: String,
    /// AS2/AS4 partner identifier, always equal to `session.partner_id()`.
    pub partner_id: String,
    /// Event emission timestamp (milliseconds since Unix epoch).
    pub timestamp_ms: u64,
    /// W3C Trace Context `traceparent` value propagated from the inbound
    /// transport header (if present).
    ///
    /// Enables distributed-trace correlation between the emitting session and
    /// upstream callers without requiring a full OpenTelemetry SDK.  Set from
    /// [`CorrelationScope::traceparent`][crate::core::CorrelationScope::traceparent];
    /// `None` for outbound-initiated sessions that carry no inbound header.
    pub traceparent: Option<Arc<str>>,
    pub event: SharedAsxEvent,
}
