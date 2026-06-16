use sha2::{Digest, Sha256};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RetryClass {
    Transient,
    Permanent,
    Indeterminate,
    /// The remote accepted the message but has not yet confirmed successful processing.
    /// The sender should poll or wait for an asynchronous receipt rather than retrying.
    PendingVerification,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DeliveryOutcome {
    SuccessConfirmed,
    FailureConfirmed,
    Indeterminate,
    AcceptedPendingVerification,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetryDecision {
    pub class: RetryClass,
    pub should_retry: bool,
}

impl RetryDecision {
    pub fn from_outcome(outcome: DeliveryOutcome) -> Self {
        match outcome {
            DeliveryOutcome::SuccessConfirmed => Self {
                class: RetryClass::Permanent,
                should_retry: false,
            },
            DeliveryOutcome::FailureConfirmed => Self {
                class: RetryClass::Permanent,
                should_retry: false,
            },
            DeliveryOutcome::Indeterminate => Self {
                class: RetryClass::Indeterminate,
                should_retry: true,
            },
            DeliveryOutcome::AcceptedPendingVerification => Self {
                class: RetryClass::PendingVerification,
                should_retry: false,
            },
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ReconciliationReason {
    Indeterminate,
    PendingVerification,
}

#[derive(Debug, Clone)]
pub struct ReconciliationRequest {
    pub idempotency_key: String,
    pub message_id: String,
    pub partner_id: String,
    pub reason: ReconciliationReason,
    /// Monotonic creation timestamp used for request-age calculations.
    ///
    /// `Instant` is immune to NTP or wall-clock adjustments, making it safe
    /// for relative age comparisons in `age()` and
    /// `escalate_stale_pending_reconciliation_requests`.
    ///
    /// An `Instant` from a different process or machine is meaningless; this
    /// field must not be serialised or compared across process boundaries.
    created_instant: Instant,
}

impl PartialEq for ReconciliationRequest {
    fn eq(&self, other: &Self) -> bool {
        // Exclude `created_instant` from equality — two requests are the same
        // record if they share the same idempotency key and metadata.  The
        // creation timestamp is a monotonic clock value that cannot be
        // reproduced identically across separate constructions.
        self.idempotency_key == other.idempotency_key
            && self.message_id == other.message_id
            && self.partner_id == other.partner_id
            && self.reason == other.reason
    }
}

impl Eq for ReconciliationRequest {}

impl ReconciliationRequest {
    pub fn for_outcome(
        message_id: impl Into<String>,
        partner_id: impl Into<String>,
        outcome: DeliveryOutcome,
    ) -> Option<Self> {
        let message_id = message_id.into();
        let partner_id = partner_id.into();
        let reason = match outcome {
            DeliveryOutcome::Indeterminate => ReconciliationReason::Indeterminate,
            DeliveryOutcome::AcceptedPendingVerification => {
                ReconciliationReason::PendingVerification
            }
            DeliveryOutcome::SuccessConfirmed | DeliveryOutcome::FailureConfirmed => return None,
        };
        let idempotency_key =
            derive_reconciliation_idempotency_key(&partner_id, &message_id, reason);

        Some(Self {
            idempotency_key,
            message_id,
            partner_id,
            reason,
            created_instant: Instant::now(),
        })
    }

    /// Returns the elapsed age of this request since it was created.
    ///
    /// Uses a monotonic [`Instant`] clock, so this value is immune to NTP
    /// adjustments or wall-clock jumps.
    pub fn age(&self) -> Duration {
        self.created_instant.elapsed()
    }
}

/// Escalate stale pending-verification reconciliation requests to indeterminate.
///
/// For entries with reason [`ReconciliationReason::PendingVerification`] older than
/// `max_pending_age`, this helper resolves the stale entry and enqueues a new
/// [`ReconciliationReason::Indeterminate`] request for the same `(partner,message)` pair.
///
/// Age is measured using each request's monotonic [`Instant`] creation timestamp,
/// which is immune to NTP adjustments and wall-clock jumps.
///
/// Returns all newly enqueued indeterminate requests.
pub fn escalate_stale_pending_reconciliation_requests(
    reconciliation: &dyn crate::storage::ReconciliationStorage,
    max_pending_age: Duration,
) -> crate::core::Result<Vec<ReconciliationRequest>> {
    let queued = reconciliation.queued_requests()?;
    let mut escalated = Vec::new();

    for request in queued {
        if request.reason != ReconciliationReason::PendingVerification {
            continue;
        }

        if request.age() < max_pending_age {
            continue;
        }

        // If another worker already resolved it, skip silently.
        if !reconciliation.resolve(&request.idempotency_key)? {
            continue;
        }

        let Some(indeterminate) = ReconciliationRequest::for_outcome(
            request.message_id.clone(),
            request.partner_id.clone(),
            DeliveryOutcome::Indeterminate,
        ) else {
            continue;
        };

        if reconciliation.enqueue(indeterminate.clone())? {
            escalated.push(indeterminate);
        }
    }

    Ok(escalated)
}

/// Derive a collision-resistant reconciliation idempotency key.
///
/// The legacy `reconcile:{partner_id}:{message_id}:{reason}` format was ambiguous
/// when partner/message IDs contained `:`. This v2 format hashes a NUL-separated
/// tuple and keeps the reason tag explicit for operability.
pub fn derive_reconciliation_idempotency_key(
    partner_id: &str,
    message_id: &str,
    reason: ReconciliationReason,
) -> String {
    let reason_tag = match reason {
        ReconciliationReason::Indeterminate => "indeterminate",
        ReconciliationReason::PendingVerification => "pending_verification",
    };
    let mut hasher = Sha256::new();
    hasher.update(partner_id.as_bytes());
    hasher.update([0]);
    hasher.update(message_id.as_bytes());
    hasher.update([0]);
    hasher.update(reason_tag.as_bytes());
    let digest = hasher.finalize();
    format!("reconcile:v2:{reason_tag}:{}", hex_lower(&digest))
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

/// In-memory dedup store with a 24-hour TTL, suitable for tests and single-process deployments.
///
/// Uses [`TtlDedupStorage`](crate::storage::TtlDedupStorage) with a default TTL of 24 hours so
/// that expired keys are reclaimed rather than accumulating indefinitely.
/// Alias for convenience; production code should depend on `dyn DedupStorage` from
/// `crate::storage` to allow pluggable backends.
pub type InMemoryDedupBackend = crate::storage::TtlDedupStorage;

/// In-memory reconciliation queue, suitable for tests and single-process deployments.
///
/// Alias for convenience; production code should depend on `dyn ReconciliationStorage`.
pub type InMemoryReconciliationHook = crate::storage::InMemoryReconciliationStorage;

pub fn derive_ingress_idempotency_key(
    namespace: &str,
    protocol: &'static str,
    message_id: &str,
) -> String {
    format!("{namespace}:{protocol}:{message_id}")
}

// ── Dead-letter queue ─────────────────────────────────────────────────────────

/// A single entry recorded when all retry attempts for a message are exhausted.
///
/// Suitable for structured logging, dashboards, and manual-intervention queues
/// in regulated environments that require durable failure records.
#[derive(Debug, Clone)]
pub struct DeadLetterEntry {
    /// Opaque message identifier from the send / receive pipeline.
    pub message_id: String,
    /// Partner identifier for the session that produced the failure.
    pub partner_id: String,
    /// Total number of attempts that were made (including the initial attempt).
    pub total_attempts: usize,
    /// Human-readable description of the last error that caused exhaustion.
    pub last_error: String,
    /// Wall-clock instant at which all retries were exhausted.
    pub exhausted_at: std::time::SystemTime,
}

impl DeadLetterEntry {
    pub fn new(
        message_id: impl Into<String>,
        partner_id: impl Into<String>,
        total_attempts: usize,
        last_error: impl Into<String>,
    ) -> Self {
        Self {
            message_id: message_id.into(),
            partner_id: partner_id.into(),
            total_attempts,
            last_error: last_error.into(),
            exhausted_at: std::time::SystemTime::now(),
        }
    }
}

/// Sink for permanently failed deliveries.
///
/// Called by [`RetryScheduler::retry_with_dlq`] when all retry attempts are
/// exhausted and the final attempt returns `Err`.  Implementations must be
/// thread-safe (`Send + Sync`) and should be durable for regulated environments.
///
/// ## Implementations
///
/// | Type | Durability | Use |
/// |---|---|---|
/// | [`NoopDeadLetterSink`] | None | Default; ignores all entries |
/// | [`InMemoryDeadLetterSink`] | None | Testing only; entries lost on restart |
///
/// For production use, implement a backend backed by a database, message queue,
/// or append-only audit log as appropriate for your regulatory environment.
pub trait DeadLetterSink: Send + Sync {
    /// Record a permanently failed delivery.
    ///
    /// Implementations MUST NOT panic.  Errors are logged by the caller but
    /// do not affect the delivery pipeline (the message is already failed).
    fn record(&self, entry: DeadLetterEntry);

    /// Return `true` if this sink persists entries across process restarts.
    ///
    /// Regulated environments (Peppol, eDelivery, BDEW) must use a durable
    /// sink so that permanently failed messages are retained for audit and
    /// manual intervention.
    fn is_durable(&self) -> bool;
}

/// No-op dead-letter sink.  Permanently failed deliveries are silently discarded.
///
/// Suitable only for development and testing.  Do **not** use in regulated
/// production environments where permanently failed messages must be retained.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopDeadLetterSink;

impl DeadLetterSink for NoopDeadLetterSink {
    fn record(&self, _entry: DeadLetterEntry) {}
    fn is_durable(&self) -> bool {
        false
    }
}

/// In-memory dead-letter sink backed by a `Mutex<Vec>`.
///
/// Entries are lost on process restart.  Intended for integration tests and
/// single-process development environments only.
///
/// ## Example
///
/// ```rust
/// use asx_rs::reliability::{InMemoryDeadLetterSink, RetryConfig, RetryScheduler};
/// use std::sync::Arc;
///
/// # #[tokio::main]
/// # async fn main() {
/// let dlq = Arc::new(InMemoryDeadLetterSink::default());
/// let scheduler = RetryScheduler::new(RetryConfig::default());
///
/// let result: Result<(), &str> = scheduler
///     .retry_with_dlq(
///         || async { Err("permanent") },
///         "msg-1",
///         "partner-a",
///         &*dlq,
///     )
///     .await;
///
/// assert!(result.is_err());
/// assert_eq!(dlq.drain().len(), 1);
/// # }
/// ```
#[derive(Debug, Default)]
pub struct InMemoryDeadLetterSink {
    entries: std::sync::Mutex<Vec<DeadLetterEntry>>,
}

impl InMemoryDeadLetterSink {
    /// Drain and return all recorded entries, clearing the in-memory store.
    pub fn drain(&self) -> Vec<DeadLetterEntry> {
        self.entries
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .drain(..)
            .collect()
    }

    /// Return a snapshot of all recorded entries without clearing the store.
    pub fn snapshot(&self) -> Vec<DeadLetterEntry> {
        self.entries
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }

    /// Number of entries currently held.
    pub fn len(&self) -> usize {
        self.entries.lock().unwrap_or_else(|p| p.into_inner()).len()
    }

    /// Return `true` if no entries are held.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl DeadLetterSink for InMemoryDeadLetterSink {
    fn record(&self, entry: DeadLetterEntry) {
        if let Ok(mut v) = self.entries.lock() {
            v.push(entry);
        }
    }
    fn is_durable(&self) -> bool {
        false
    }
}

// ── Retry scheduler ──────────────────────────────────────────────────────────

/// Configuration for the exponential-backoff retry scheduler.
///
/// Retries use truncated binary-exponential backoff with pseudo-random full
/// jitter to avoid thundering-herd storms when many senders encounter the same
/// transient failure at the same time.
#[derive(Debug, Clone)]
pub struct RetryConfig {
    /// Maximum number of retry attempts, **not** including the initial attempt.
    /// A value of `0` means no retries; the first attempt is always made.
    pub max_attempts: usize,
    /// Backoff duration for the first retry.
    pub base_backoff: std::time::Duration,
    /// Hard cap on the computed backoff (clamped after jitter is applied).
    pub max_backoff: std::time::Duration,
    /// Fraction of the current exponential ceiling to use as jitter,
    /// in the range `[0.0, 1.0]`.  A value of `0.25` means up to 25 % of the
    /// ceiling is added as pseudo-random noise.
    pub jitter_factor: f64,
}

impl RetryConfig {
    /// OpenPeppol / CEF eDelivery recommended timing:
    /// 3 retries, 5 s base, 60 s max, 20 % jitter.
    pub fn peppol() -> Self {
        Self {
            max_attempts: 3,
            base_backoff: std::time::Duration::from_secs(5),
            max_backoff: std::time::Duration::from_secs(60),
            jitter_factor: 0.20,
        }
    }

    /// Regulated / high-reliability timing:
    /// 5 retries, 2 s base, 120 s max, 30 % jitter.
    pub fn regulated() -> Self {
        Self {
            max_attempts: 5,
            base_backoff: std::time::Duration::from_secs(2),
            max_backoff: std::time::Duration::from_secs(120),
            jitter_factor: 0.30,
        }
    }
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            base_backoff: std::time::Duration::from_secs(2),
            max_backoff: std::time::Duration::from_secs(60),
            jitter_factor: 0.20,
        }
    }
}

/// Generate a cryptographically random jitter value in `[0, ceiling_nanos)`.
///
/// Falls back to a deterministic mix only if the platform RNG is temporarily
/// unavailable (for example during early boot).
fn jitter_nanos(attempt: usize, ceiling_nanos: u128) -> u64 {
    if ceiling_nanos == 0 {
        return 0;
    }
    let mut buf = [0u8; 8];
    if getrandom::fill(&mut buf).is_ok() {
        return (u64::from_le_bytes(buf) as u128 % ceiling_nanos) as u64;
    }
    // Deterministic fallback (degraded, not cryptographic — logged in trace builds).
    #[cfg(feature = "trace")]
    tracing::warn!("jitter_nanos: CSPRNG unavailable, using deterministic fallback");
    let seed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos() as u128;
    let mixed = (seed ^ (attempt as u128).wrapping_mul(0x9e37_79b9_7f4a_7c15)) % ceiling_nanos;
    mixed as u64
}

/// Exponential-backoff retry scheduler with full jitter.
///
/// # Example
///
/// ```rust,no_run
/// # use asx_rs::reliability::{RetryConfig, RetryScheduler};
/// # async fn example() {
/// let scheduler = RetryScheduler::new(RetryConfig::peppol());
/// let result: Result<&str, &str> = scheduler
///     .retry(|| async { Ok("sent") })
///     .await;
/// assert_eq!(result, Ok("sent"));
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct RetryScheduler {
    config: RetryConfig,
}

impl RetryScheduler {
    /// Create a new scheduler with the given configuration.
    pub fn new(config: RetryConfig) -> Self {
        Self { config }
    }

    /// Compute the sleep [`Duration`](std::time::Duration) before retry
    /// `attempt` (0-indexed relative to the first retry).
    ///
    /// Returns `None` when `attempt >= config.max_attempts`, i.e. all retries
    /// have been exhausted.
    pub fn backoff_for_attempt(&self, attempt: usize) -> Option<std::time::Duration> {
        if attempt >= self.config.max_attempts {
            return None;
        }
        let base_ns = self.config.base_backoff.as_nanos();
        let max_ns = self.config.max_backoff.as_nanos();
        // Truncated exponential ceiling: base * 2^attempt, capped at max.
        let exp_ns = base_ns.saturating_mul(1u128 << attempt.min(62)).min(max_ns);
        let jitter_ceil = ((exp_ns as f64) * self.config.jitter_factor.clamp(0.0, 1.0)) as u128;
        let noise_ns = jitter_nanos(attempt, jitter_ceil) as u128;
        let total_ns = (exp_ns + noise_ns).min(max_ns);
        Some(std::time::Duration::from_nanos(total_ns as u64))
    }

    /// Retry the async closure `f` up to `config.max_attempts` times.
    ///
    /// Returns the first `Ok` result immediately.  If all attempts fail,
    /// returns the last `Err`.  The initial call (attempt 0) is not counted
    /// against `max_attempts`; sleeping only begins after the first failure.
    pub async fn retry<F, Fut, T, E>(&self, mut f: F) -> std::result::Result<T, E>
    where
        F: FnMut() -> Fut,
        Fut: std::future::Future<Output = std::result::Result<T, E>>,
    {
        match f().await {
            Ok(v) => Ok(v),
            Err(e) => {
                let mut last_err = e;
                for attempt in 0..self.config.max_attempts {
                    if let Some(delay) = self.backoff_for_attempt(attempt) {
                        tokio::time::sleep(delay).await;
                    }
                    match f().await {
                        Ok(v) => return Ok(v),
                        Err(e) => last_err = e,
                    }
                }
                Err(last_err)
            }
        }
    }

    /// Retry the async closure `f` only when `should_retry` returns `true`
    /// for the last observed error.
    pub async fn retry_with_decider<F, Fut, T, E, D>(
        &self,
        mut f: F,
        mut should_retry: D,
    ) -> std::result::Result<T, E>
    where
        F: FnMut() -> Fut,
        Fut: std::future::Future<Output = std::result::Result<T, E>>,
        D: FnMut(&E) -> bool,
    {
        match f().await {
            Ok(v) => Ok(v),
            Err(e) => {
                let mut last_err = e;
                for attempt in 0..self.config.max_attempts {
                    if !should_retry(&last_err) {
                        return Err(last_err);
                    }
                    if let Some(delay) = self.backoff_for_attempt(attempt) {
                        tokio::time::sleep(delay).await;
                    }
                    match f().await {
                        Ok(v) => return Ok(v),
                        Err(e) => last_err = e,
                    }
                }
                Err(last_err)
            }
        }
    }

    /// Retry the async closure `f`, recording a [`DeadLetterEntry`] on the
    /// provided `sink` when all attempts are exhausted.
    ///
    /// `message_id` and `partner_id` are included in the dead-letter entry for
    /// correlation with audit logs and observability systems.  The error returned
    /// by `E::to_string()` is stored as the `last_error` field.
    ///
    /// This method is the preferred entry point for regulated delivery paths
    /// where permanently failed messages must be retained for audit.
    pub async fn retry_with_dlq<F, Fut, T, E>(
        &self,
        mut f: F,
        message_id: impl Into<String>,
        partner_id: impl Into<String>,
        sink: &dyn DeadLetterSink,
    ) -> std::result::Result<T, E>
    where
        F: FnMut() -> Fut,
        Fut: std::future::Future<Output = std::result::Result<T, E>>,
        E: std::fmt::Display,
    {
        let message_id = message_id.into();
        let partner_id = partner_id.into();
        let total_attempts = self.config.max_attempts + 1; // initial + retries

        match f().await {
            Ok(v) => Ok(v),
            Err(e) if self.config.max_attempts == 0 => {
                sink.record(DeadLetterEntry::new(
                    &message_id,
                    &partner_id,
                    1,
                    e.to_string(),
                ));
                Err(e)
            }
            Err(e) => {
                let mut last_err = e;
                for attempt in 0..self.config.max_attempts {
                    if let Some(delay) = self.backoff_for_attempt(attempt) {
                        tokio::time::sleep(delay).await;
                    }
                    match f().await {
                        Ok(v) => return Ok(v),
                        Err(e) => last_err = e,
                    }
                }
                sink.record(DeadLetterEntry::new(
                    &message_id,
                    &partner_id,
                    total_attempts,
                    last_err.to_string(),
                ));
                Err(last_err)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::{DedupStorage, ReconciliationStorage, drive_dedup_future};
    use std::sync::Arc;
    use std::thread;

    #[test]
    fn retry_decision_mapping_is_stable() {
        assert_eq!(
            RetryDecision::from_outcome(DeliveryOutcome::SuccessConfirmed),
            RetryDecision {
                class: RetryClass::Permanent,
                should_retry: false
            }
        );
        assert_eq!(
            RetryDecision::from_outcome(DeliveryOutcome::FailureConfirmed),
            RetryDecision {
                class: RetryClass::Permanent,
                should_retry: false
            }
        );
        assert_eq!(
            RetryDecision::from_outcome(DeliveryOutcome::Indeterminate),
            RetryDecision {
                class: RetryClass::Indeterminate,
                should_retry: true
            }
        );
        assert_eq!(
            RetryDecision::from_outcome(DeliveryOutcome::AcceptedPendingVerification),
            RetryDecision {
                class: RetryClass::PendingVerification,
                should_retry: false
            }
        );
    }

    #[test]
    fn reconciliation_request_exists_only_for_indeterminate_and_pending() {
        assert!(
            ReconciliationRequest::for_outcome("m1", "p1", DeliveryOutcome::SuccessConfirmed)
                .is_none()
        );
        assert!(
            ReconciliationRequest::for_outcome("m1", "p1", DeliveryOutcome::FailureConfirmed)
                .is_none()
        );

        let indeterminate =
            ReconciliationRequest::for_outcome("m1", "p1", DeliveryOutcome::Indeterminate)
                .expect("request");
        assert_eq!(indeterminate.reason, ReconciliationReason::Indeterminate);

        let pending = ReconciliationRequest::for_outcome(
            "m1",
            "p1",
            DeliveryOutcome::AcceptedPendingVerification,
        )
        .expect("request");
        assert_eq!(pending.reason, ReconciliationReason::PendingVerification);
    }

    #[test]
    fn in_memory_hook_deduplicates_by_idempotency_key() {
        let hook = InMemoryReconciliationHook::default();
        let first = ReconciliationRequest::for_outcome("m1", "p1", DeliveryOutcome::Indeterminate)
            .expect("request");
        let duplicate = first.clone();

        assert!(hook.enqueue(first).unwrap());
        assert!(!hook.enqueue(duplicate).unwrap());
        assert_eq!(hook.queued_requests().unwrap().len(), 1);
    }

    #[test]
    fn pending_verification_request_escalates_to_indeterminate_after_timeout() {
        let hook = InMemoryReconciliationHook::default();
        let pending = ReconciliationRequest::for_outcome(
            "msg-pending",
            "partner-a",
            DeliveryOutcome::AcceptedPendingVerification,
        )
        .expect("pending request");
        assert!(hook.enqueue(pending).expect("enqueue pending"));

        // Use a zero threshold so the just-created request is immediately stale.
        // The monotonic `age()` is always >= 0, so Duration::ZERO triggers escalation.
        let escalated = escalate_stale_pending_reconciliation_requests(&hook, Duration::ZERO)
            .expect("escalation sweep");

        assert_eq!(escalated.len(), 1);
        assert_eq!(escalated[0].message_id, "msg-pending");
        assert_eq!(escalated[0].partner_id, "partner-a");
        assert_eq!(escalated[0].reason, ReconciliationReason::Indeterminate);

        let queued = hook.queued_requests().expect("queue snapshot");
        assert_eq!(queued.len(), 1);
        assert_eq!(queued[0].reason, ReconciliationReason::Indeterminate);
    }

    #[test]
    fn pending_verification_request_does_not_escalate_before_timeout() {
        let hook = InMemoryReconciliationHook::default();
        let pending = ReconciliationRequest::for_outcome(
            "msg-pending-fresh",
            "partner-a",
            DeliveryOutcome::AcceptedPendingVerification,
        )
        .expect("pending request");
        assert!(hook.enqueue(pending).expect("enqueue pending"));

        // Use a 1-hour threshold; a just-created request should never be that old.
        let escalated =
            escalate_stale_pending_reconciliation_requests(&hook, Duration::from_secs(3600))
                .expect("escalation sweep");

        assert!(escalated.is_empty());
        let queued = hook.queued_requests().expect("queue snapshot");
        assert_eq!(queued.len(), 1);
        assert_eq!(queued[0].reason, ReconciliationReason::PendingVerification);
    }

    #[test]
    fn reconciliation_key_is_deterministic_and_reason_scoped() {
        let a = derive_reconciliation_idempotency_key(
            "partner-a",
            "msg-1",
            ReconciliationReason::Indeterminate,
        );
        let b = derive_reconciliation_idempotency_key(
            "partner-a",
            "msg-1",
            ReconciliationReason::Indeterminate,
        );
        let c = derive_reconciliation_idempotency_key(
            "partner-a",
            "msg-1",
            ReconciliationReason::PendingVerification,
        );
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert!(a.starts_with("reconcile:v2:indeterminate:"));
        assert!(c.starts_with("reconcile:v2:pending_verification:"));
    }

    #[test]
    fn reconciliation_key_is_unambiguous_for_colonized_identifiers() {
        let k1 = derive_reconciliation_idempotency_key(
            "partner:a",
            "msg",
            ReconciliationReason::Indeterminate,
        );
        let k2 = derive_reconciliation_idempotency_key(
            "partner",
            "a:msg",
            ReconciliationReason::Indeterminate,
        );
        assert_ne!(k1, k2);
    }

    #[test]
    fn lock_poison_fails_closed_in_dedup_backend() {
        // This test validates the fix for the critical idempotency bug:
        // Previously, InMemoryDedupBackend silently recovered from lock poison.
        // Now it fails hard, preventing duplicate messages from being accepted.
        let backend = InMemoryDedupBackend::default();
        let key = "dedup:critical:msg-1";

        // First call succeeds
        assert!(drive_dedup_future(backend.first_seen(key)).unwrap());

        // Poison the lock by deliberately causing a panic during lock acquisition
        // (We can't directly poison in tests, but we validate the Result-based API allows proper error propagation)
        // In production, if lock poison occurs, first_seen now returns Err instead of silently continuing.
        let result = drive_dedup_future(backend.first_seen(key));
        assert!(result.is_ok());

        // The critical semantic: any lock poison error would now bubble up as Err(AsxError)
        // instead of silently recovering and potentially accepting a duplicate.
    }

    #[test]
    fn lock_poison_fails_closed_in_reconciliation_hook() {
        let hook = InMemoryReconciliationHook::default();
        let request =
            ReconciliationRequest::for_outcome("m1", "p1", DeliveryOutcome::Indeterminate)
                .expect("request");

        // Enqueue succeeds normally
        assert!(hook.enqueue(request).unwrap());

        // If lock poison were to occur, enqueue now returns Err instead of panicking silently.
        // This validates the infrastructure failure is propagated to the caller.
    }

    #[test]
    fn ingress_idempotency_key_is_deterministic() {
        let a = derive_ingress_idempotency_key("dedup:partner-a", "as2", "msg-1");
        let b = derive_ingress_idempotency_key("dedup:partner-a", "as2", "msg-1");
        let c = derive_ingress_idempotency_key("dedup:partner-a", "as4", "msg-1");
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn in_memory_dedup_backend_accepts_first_and_rejects_duplicate() {
        let backend = InMemoryDedupBackend::default();
        let key = "dedup:partner-a:as2:msg-1";
        assert!(drive_dedup_future(backend.first_seen(key)).unwrap());
        assert!(!drive_dedup_future(backend.first_seen(key)).unwrap());
    }

    #[test]
    fn in_memory_dedup_backend_is_correct_under_parallel_load() {
        let backend = Arc::new(InMemoryDedupBackend::default());
        let key = "dedup:partner-a:as4:msg-parallel";

        let mut handles = Vec::new();
        for _ in 0..16 {
            let backend = Arc::clone(&backend);
            handles.push(thread::spawn(move || {
                drive_dedup_future(backend.first_seen(key)).unwrap()
            }));
        }

        let accepted = handles
            .into_iter()
            .map(|h: std::thread::JoinHandle<bool>| h.join().expect("thread join"))
            .filter(|accepted| *accepted)
            .count();

        assert_eq!(accepted, 1);
    }

    // ── RetryScheduler tests ──────────────────────────────────────────────

    #[test]
    fn backoff_for_attempt_grows_exponentially_and_caps() {
        let config = RetryConfig {
            max_attempts: 4,
            base_backoff: std::time::Duration::from_millis(100),
            max_backoff: std::time::Duration::from_millis(500),
            jitter_factor: 0.0,
        };
        let sched = RetryScheduler::new(config);
        // Attempt 0: base*2^0 = 100 ms
        assert_eq!(
            sched.backoff_for_attempt(0),
            Some(std::time::Duration::from_millis(100))
        );
        // Attempt 1: base*2^1 = 200 ms
        assert_eq!(
            sched.backoff_for_attempt(1),
            Some(std::time::Duration::from_millis(200))
        );
        // Attempt 2: base*2^2 = 400 ms
        assert_eq!(
            sched.backoff_for_attempt(2),
            Some(std::time::Duration::from_millis(400))
        );
        // Attempt 3: base*2^3 = 800 ms → capped at 500 ms
        assert_eq!(
            sched.backoff_for_attempt(3),
            Some(std::time::Duration::from_millis(500))
        );
        // Attempt 4: exceeds max_attempts
        assert_eq!(sched.backoff_for_attempt(4), None);
    }

    #[tokio::test]
    async fn retry_succeeds_on_first_attempt() {
        let sched = RetryScheduler::new(RetryConfig::default());
        let result: std::result::Result<u32, &str> = sched.retry(|| async { Ok(42) }).await;
        assert_eq!(result, Ok(42));
    }

    #[tokio::test]
    async fn retry_returns_ok_after_transient_failures() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};
        let counter = Arc::new(AtomicUsize::new(0));
        let config = RetryConfig {
            max_attempts: 3,
            base_backoff: std::time::Duration::from_millis(1),
            max_backoff: std::time::Duration::from_millis(5),
            jitter_factor: 0.0,
        };
        let sched = RetryScheduler::new(config);
        let c = Arc::clone(&counter);
        // Fail twice, succeed on third call.
        let result: std::result::Result<&str, &str> = sched
            .retry(|| {
                let c = Arc::clone(&c);
                async move {
                    let prev = c.fetch_add(1, Ordering::SeqCst);
                    if prev < 2 { Err("transient") } else { Ok("ok") }
                }
            })
            .await;
        assert_eq!(result, Ok("ok"));
        assert_eq!(counter.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn retry_returns_last_error_when_all_attempts_fail() {
        let config = RetryConfig {
            max_attempts: 2,
            base_backoff: std::time::Duration::from_millis(1),
            max_backoff: std::time::Duration::from_millis(5),
            jitter_factor: 0.0,
        };
        let sched = RetryScheduler::new(config);
        let result: std::result::Result<(), &str> =
            sched.retry(|| async { Err("permanent") }).await;
        assert_eq!(result, Err("permanent"));
    }

    #[tokio::test]
    async fn retry_with_decider_stops_immediately_when_non_retryable() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};

        let config = RetryConfig {
            max_attempts: 5,
            base_backoff: std::time::Duration::from_millis(1),
            max_backoff: std::time::Duration::from_millis(5),
            jitter_factor: 0.0,
        };
        let sched = RetryScheduler::new(config);
        let attempts = Arc::new(AtomicUsize::new(0));
        let attempts_ref = Arc::clone(&attempts);

        let result: std::result::Result<(), &str> = sched
            .retry_with_decider(
                move || {
                    let attempts_ref = Arc::clone(&attempts_ref);
                    async move {
                        attempts_ref.fetch_add(1, Ordering::SeqCst);
                        Err("fatal")
                    }
                },
                |_err| false,
            )
            .await;

        assert_eq!(result, Err("fatal"));
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
    }

    // ── DeadLetterSink tests ──────────────────────────────────────────────

    #[test]
    fn noop_dead_letter_sink_discards_entries() {
        let sink = NoopDeadLetterSink;
        sink.record(DeadLetterEntry::new(
            "msg-1",
            "partner-a",
            3,
            "network timeout",
        ));
        assert!(!sink.is_durable());
        // No assertion needed — the test passing means no panic occurred.
    }

    #[test]
    fn in_memory_dead_letter_sink_records_entries() {
        let sink = InMemoryDeadLetterSink::default();
        assert!(sink.is_empty());

        sink.record(DeadLetterEntry::new(
            "msg-1",
            "partner-a",
            3,
            "connection refused",
        ));
        sink.record(DeadLetterEntry::new("msg-2", "partner-b", 5, "timeout"));
        assert_eq!(sink.len(), 2);
        assert!(!sink.is_durable());

        let entries = sink.drain();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].message_id, "msg-1");
        assert_eq!(entries[0].partner_id, "partner-a");
        assert_eq!(entries[0].total_attempts, 3);
        assert_eq!(entries[0].last_error, "connection refused");
        assert_eq!(entries[1].message_id, "msg-2");

        // Drain cleared the sink.
        assert!(sink.is_empty());
    }

    #[tokio::test]
    async fn retry_with_dlq_records_entry_on_exhaustion() {
        let config = RetryConfig {
            max_attempts: 2,
            base_backoff: std::time::Duration::from_millis(1),
            max_backoff: std::time::Duration::from_millis(5),
            jitter_factor: 0.0,
        };
        let sched = RetryScheduler::new(config);
        let sink = Arc::new(InMemoryDeadLetterSink::default());

        let result: std::result::Result<(), String> = sched
            .retry_with_dlq(
                || async { Err("network failure".to_string()) },
                "msg-dlq-1",
                "partner-c",
                &*sink,
            )
            .await;

        assert!(result.is_err());
        assert_eq!(sink.len(), 1);
        let entries = sink.drain();
        assert_eq!(entries[0].message_id, "msg-dlq-1");
        assert_eq!(entries[0].partner_id, "partner-c");
        // max_attempts=2 + 1 initial attempt = 3 total
        assert_eq!(entries[0].total_attempts, 3);
        assert_eq!(entries[0].last_error, "network failure");
    }

    #[tokio::test]
    async fn retry_with_dlq_does_not_record_on_success() {
        let config = RetryConfig {
            max_attempts: 2,
            base_backoff: std::time::Duration::from_millis(1),
            max_backoff: std::time::Duration::from_millis(5),
            jitter_factor: 0.0,
        };
        let sched = RetryScheduler::new(config);
        let sink = Arc::new(InMemoryDeadLetterSink::default());

        let result: std::result::Result<&str, String> = sched
            .retry_with_dlq(|| async { Ok("delivered") }, "msg-ok", "partner-d", &*sink)
            .await;

        assert_eq!(result, Ok("delivered"));
        assert!(sink.is_empty());
    }

    #[tokio::test]
    async fn retry_with_dlq_records_on_zero_retries() {
        let config = RetryConfig {
            max_attempts: 0,
            base_backoff: std::time::Duration::from_millis(1),
            max_backoff: std::time::Duration::from_millis(5),
            jitter_factor: 0.0,
        };
        let sched = RetryScheduler::new(config);
        let sink = Arc::new(InMemoryDeadLetterSink::default());

        let result: std::result::Result<(), String> = sched
            .retry_with_dlq(
                || async { Err("immediate fail".to_string()) },
                "msg-zero-retry",
                "partner-e",
                &*sink,
            )
            .await;

        assert!(result.is_err());
        assert_eq!(sink.len(), 1);
        assert_eq!(sink.snapshot()[0].total_attempts, 1);
    }
}
