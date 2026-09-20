//! In-memory storage implementations for dedup and reconciliation.
//!
//! These implementations are suitable for single-node development and testing.
//! For multi-node deployments requiring exactly-once delivery guarantees,
//! implement custom backends using Redis, PostgreSQL, DynamoDB, etc.

use super::BoxFuture;
use parking_lot::Mutex;
use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use super::{DedupStorage, DedupVerdict, ReconciliationStorage};
use crate::reliability::ReconciliationRequest;

/// Default lease on an unsettled claim for the in-memory backends.
///
/// Long enough to outlast any plausible receive-and-persist, short enough that
/// a process that died mid-handling does not block the retransmission for long.
pub const DEFAULT_CLAIM_LEASE: Duration = Duration::from_secs(300);

/// State of one idempotency key in an in-memory backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KeyState {
    /// Claimed but not settled; the lease expires at this instant.
    InFlight(Instant),
    /// Settled as accepted; the replay window expires at this instant.
    Accepted(Instant),
}

impl KeyState {
    /// The instant this state stops being meaningful.
    fn expires_at(&self) -> Instant {
        match self {
            Self::InFlight(at) | Self::Accepted(at) => *at,
        }
    }

    fn is_live(&self, now: Instant) -> bool {
        now < self.expires_at()
    }
}

/// The verdict for `now` given the key's current state, shared by every
/// in-memory backend so they cannot drift apart.
///
/// `None` means "take the key": absent, or a lease/TTL that has run out.
fn verdict_for(existing: Option<&KeyState>, now: Instant) -> Option<DedupVerdict> {
    match existing {
        Some(state) if state.is_live(now) => Some(match state {
            KeyState::Accepted(_) => DedupVerdict::Duplicate,
            KeyState::InFlight(_) => DedupVerdict::InFlight,
        }),
        _ => None,
    }
}

/// In-memory reconciliation storage using HashSet (dedup) + Vec (queue).
/// Fail-closed semantics: any infrastructure failure (lock poison) fails the operation.
///
/// `max_queued` caps the number of pending requests (default: `usize::MAX`).
/// When at capacity, new `enqueue` calls return `Err(CapacityExceeded)`.
/// Use [`InMemoryReconciliationStorage::with_capacity`] to set a limit.
#[derive(Debug)]
pub struct InMemoryReconciliationStorage {
    seen: Mutex<HashSet<String>>,
    queued: Mutex<Vec<ReconciliationRequest>>,
    max_queued: usize,
}

impl Default for InMemoryReconciliationStorage {
    fn default() -> Self {
        Self {
            seen: Mutex::new(HashSet::new()),
            queued: Mutex::new(Vec::new()),
            max_queued: usize::MAX,
        }
    }
}

impl InMemoryReconciliationStorage {
    /// Create a bounded reconciliation queue. `max_queued` is the maximum number of
    /// pending (unresolved) requests. When exceeded, `enqueue` returns `Err`.
    pub fn with_capacity(max_queued: usize) -> Self {
        Self {
            seen: Mutex::new(HashSet::new()),
            queued: Mutex::new(Vec::new()),
            max_queued,
        }
    }
}

impl ReconciliationStorage for InMemoryReconciliationStorage {
    fn is_durable(&self) -> bool {
        false
    }

    fn enqueue<'a>(
        &'a self,
        request: ReconciliationRequest,
    ) -> super::BoxFuture<'a, crate::core::Result<bool>> {
        Box::pin(async move {
            // Hold the `seen` lock while acquiring `queued` to eliminate the TOCTOU window
            // where seen.insert succeeds but queued acquisition fails, leaving the key
            // permanently stuck in `seen` without a corresponding queued entry.
            let mut seen = self.seen.lock();
            if seen.contains(&request.idempotency_key) {
                return Ok(false);
            }
            let mut queued = self.queued.lock();
            if queued.len() >= self.max_queued {
                return Err(crate::core::AsxError::new(
                    crate::core::ErrorCode::PolicyViolation,
                    format!(
                        "reconciliation queue at capacity ({} entries); resolve pending requests before enqueuing more",
                        self.max_queued
                    ),
                    crate::core::ErrorContext::new("reconciliation_storage_enqueue"),
                ));
            }
            seen.insert(request.idempotency_key.clone());
            queued.push(request);
            Ok(true)
        })
    }

    fn queued_requests(
        &self,
    ) -> super::BoxFuture<'_, crate::core::Result<Vec<ReconciliationRequest>>> {
        Box::pin(async move {
            let queued = self.queued.lock();
            Ok(queued.clone())
        })
    }

    fn resolve<'a>(
        &'a self,
        idempotency_key: &'a str,
    ) -> super::BoxFuture<'a, crate::core::Result<bool>> {
        Box::pin(async move {
            // Acquire in the same `seen → queued` order used by `enqueue` to prevent
            // lock-order inversion deadlocks when both locks are held simultaneously.
            let mut seen = self.seen.lock();
            let mut queued = self.queued.lock();
            let before = queued.len();
            queued.retain(|r| r.idempotency_key != idempotency_key);
            let removed = queued.len() < before;
            if removed {
                // Remove from `seen` so the key can be re-enqueued after resolution.
                // Without this, a resolved key would remain permanently stuck in `seen`
                // for the lifetime of the process, preventing re-delivery on retry.
                seen.remove(idempotency_key);
            }
            Ok(removed)
        })
    }
}

/// Capacity-bounded FIFO dedup storage.
///
/// Maintains a sliding window of the most recent `capacity` idempotency keys.
/// When the store is full, the **oldest** key is silently evicted before the new
/// key is inserted (FIFO / LRU-by-insertion-order).
///
/// This prevents unbounded memory growth in long-running services while
/// preserving duplicate-rejection for all keys within the window.
///
/// # ⚠ A peer controls when your window slides
///
/// Eviction is driven by *insertion*, and inbound message IDs come from the
/// counterparty. An attacker who can push `capacity` distinct messages flushes
/// the window and can then replay a message older than that — bounded dedup
/// trades replay coverage for a memory bound, and the peer chooses where the
/// boundary falls.
///
/// Size `capacity` against the volume an adversary could push within your
/// replay-protection window, not against normal throughput. Where that is not
/// tractable, prefer [`TtlDedupStorage`] (time-bounded, so a flood cannot
/// shorten the window) or a durable backend.
///
/// `10_000` suits a deployment processing tens of thousands of messages per
/// hour from *trusted* peers.
/// TTL-aware in-memory dedup storage.
///
/// TTL-based deduplication store backed by a `HashMap<String, Instant>`.
///
/// Each key is tracked with a state and an expiry timestamp. On `claim`:
/// - **Settled fast path**: an unexpired `accepted` key returns
///   [`DedupVerdict::Duplicate`] in O(1); an unexpired claim returns
///   [`DedupVerdict::InFlight`].
/// - **New key, or an expired one**: inserts a claim leased for
///   `claim_lease` and returns [`DedupVerdict::Claimed`]. `accept` then
///   restamps it for `ttl`, which is the replay window.
/// - **Sweep**: expired entries are swept lazily at most once per `sweep_interval`
///   (default: `min(ttl / 10, 60s)`), rather than on every insert, keeping the
///   amortised cost sub-linear for large windows.
///
/// Memory is bounded by the replay window rather than by a key count
/// and matches real AS4 replay-window semantics (typically 1–24 hours).
///
/// # ⚠ Single-process scope
///
/// `TtlDedupStorage` uses [`std::time::Instant`] as its clock source. `Instant`
/// is monotonic and NOT calendar-aligned:
///
/// - **No persistence across restarts**: all entries are in-process memory.
///   After a process restart, previously seen message IDs are unknown and will
///   be accepted again. Use a durable backend (e.g., Redis with `SETNX` or a
///   SQL table) when cross-restart replay protection is required.
/// - **No cross-replica protection**: in horizontally-scaled deployments,
///   different replicas maintain independent dedup windows. A message replayed
///   to a different replica will pass the dedup check. Use a shared durable
///   backend or an external dedup proxy for multi-replica deployments.
/// - **`is_durable()` returns `false`**: the runtime startup guards in strict
///   mode detect non-durable backends and require explicit opt-in.
///
/// # TTL alignment with `timestamp_freshness_window`
///
/// `As4PushPolicy::timestamp_freshness_window` (default: 5 minutes) and this
/// store's TTL form a layered replay-defence:
///
/// | Condition | Replay risk |
/// |---|---|
/// | `ttl ≥ freshness_window` | No gap: dedup window outlasts freshness rejection. Best. |
/// | `ttl < freshness_window` | Gap: messages evicted from dedup store but still inside freshness window will be accepted once re-played. Avoid. |
/// | `freshness_window = None` | Only the dedup window provides protection. Acceptable when TTL >> expected replay window; risky after restarts. |
///
/// The default TTL of 24 hours greatly exceeds the default 5-minute freshness
/// window, providing defence-in-depth for the common case.
#[derive(Debug)]
pub struct TtlDedupStorage {
    inner: Mutex<TtlDedupInner>,
    ttl: Duration,
    sweep_interval: Duration,
    claim_lease: Duration,
}

#[derive(Debug)]
struct TtlDedupInner {
    entries: HashMap<String, KeyState>,
    last_sweep: Instant,
}

impl TtlDedupStorage {
    /// Create a new TTL dedup store. `ttl` is the replay-protection window.
    ///
    /// The sweep interval defaults to `min(ttl / 10, 60s)`.  Use
    /// [`TtlDedupStorage::with_sweep_interval`] to override it.
    pub fn new(ttl: Duration) -> Self {
        let sweep_interval = ttl / 10;
        let sweep_interval = if sweep_interval > Duration::from_secs(60) {
            Duration::from_secs(60)
        } else {
            sweep_interval
        };
        Self::with_sweep_interval(ttl, sweep_interval)
    }

    /// Create a new TTL dedup store with an explicit sweep interval.
    ///
    /// The sweep is the **only** eviction path: an expired entry still occupies
    /// memory until a sweep removes it. Smaller intervals cost CPU; larger ones
    /// let expired entries accumulate.
    ///
    /// `Duration::MAX` disables sweeping, which means memory grows without
    /// bound for the lifetime of the store. That is only sensible for a
    /// short-lived instance in a test.
    pub fn with_sweep_interval(ttl: Duration, sweep_interval: Duration) -> Self {
        Self {
            inner: Mutex::new(TtlDedupInner {
                entries: HashMap::new(),
                last_sweep: Instant::now(),
            }),
            ttl,
            sweep_interval,
            claim_lease: DEFAULT_CLAIM_LEASE,
        }
    }

    /// Override the lease on an unsettled claim (default:
    /// [`DEFAULT_CLAIM_LEASE`]).
    ///
    /// Size it above the longest plausible receive-and-persist and below the
    /// sender's retransmission interval: too short and two retransmissions
    /// process concurrently, too long and a crashed handover blocks redelivery.
    pub fn with_claim_lease(mut self, claim_lease: Duration) -> Self {
        self.claim_lease = claim_lease;
        self
    }

    /// The configured replay-protection window for accepted keys.
    pub fn ttl(&self) -> Duration {
        self.ttl
    }

    /// The configured lease on an unsettled claim.
    pub fn claim_lease(&self) -> Duration {
        self.claim_lease
    }
}

impl Default for TtlDedupStorage {
    /// Default TTL is 24 hours — sufficient for AS2/AS4 replay-protection windows.
    fn default() -> Self {
        Self::new(Duration::from_secs(86_400))
    }
}

impl DedupStorage for TtlDedupStorage {
    fn is_durable(&self) -> bool {
        false
    }

    fn claim<'a>(
        &'a self,
        idempotency_key: &'a str,
    ) -> BoxFuture<'a, crate::core::Result<DedupVerdict>> {
        Box::pin(async move {
            let mut inner = self.inner.lock();
            let now = Instant::now();
            if let Some(verdict) = verdict_for(inner.entries.get(idempotency_key), now) {
                return Ok(verdict);
            }
            if now.duration_since(inner.last_sweep) >= self.sweep_interval {
                inner.entries.retain(|_, state| state.is_live(now));
                inner.last_sweep = now;
            }
            inner.entries.insert(
                idempotency_key.to_string(),
                KeyState::InFlight(now + self.claim_lease),
            );
            Ok(DedupVerdict::Claimed)
        })
    }

    fn accept<'a>(&'a self, idempotency_key: &'a str) -> BoxFuture<'a, crate::core::Result<()>> {
        Box::pin(async move {
            // The replay window starts at settlement, not at claim: `ttl` is
            // "how long after handling a message is a replay of it rejected".
            let expiry = Instant::now() + self.ttl;
            self.inner
                .lock()
                .entries
                .insert(idempotency_key.to_string(), KeyState::Accepted(expiry));
            Ok(())
        })
    }

    fn abandon<'a>(&'a self, idempotency_key: &'a str) -> BoxFuture<'a, crate::core::Result<()>> {
        Box::pin(async move {
            let mut inner = self.inner.lock();
            if matches!(
                inner.entries.get(idempotency_key),
                Some(KeyState::InFlight(_))
            ) {
                inner.entries.remove(idempotency_key);
            }
            Ok(())
        })
    }
}

/// Test-only wrapper that marks an [`TtlDedupStorage`] as durable.
///
/// In production, dedup backends must implement `is_durable() -> true` only
/// when backed by a persistent store.  This wrapper is intentionally available
/// only under the `testing` feature so it cannot accidentally be used in
/// production code.
///
/// Use this in integration tests that need to exercise the receive pipeline
/// without configuring a real durable backend:
///
/// ```rust,ignore
/// # #[cfg(feature = "testing")]
/// let dedup = DurableInMemoryDedupBackend::default();
/// ```
#[cfg(feature = "testing")]
#[derive(Debug, Default)]
pub struct DurableInMemoryDedupBackend(TtlDedupStorage);

#[cfg(feature = "testing")]
impl DurableInMemoryDedupBackend {
    /// Create a new durable-flagged in-memory dedup store with the given TTL.
    pub fn new(ttl: std::time::Duration) -> Self {
        Self(TtlDedupStorage::new(ttl))
    }
}

#[cfg(feature = "testing")]
impl DedupStorage for DurableInMemoryDedupBackend {
    /// Returns `true` — this wrapper claims durability for test use only.
    ///
    /// **Never use in production.** Entries are lost on process restart.
    fn is_durable(&self) -> bool {
        true
    }

    fn claim<'a>(
        &'a self,
        idempotency_key: &'a str,
    ) -> BoxFuture<'a, crate::core::Result<DedupVerdict>> {
        self.0.claim(idempotency_key)
    }

    fn accept<'a>(&'a self, idempotency_key: &'a str) -> BoxFuture<'a, crate::core::Result<()>> {
        self.0.accept(idempotency_key)
    }

    fn abandon<'a>(&'a self, idempotency_key: &'a str) -> BoxFuture<'a, crate::core::Result<()>> {
        self.0.abandon(idempotency_key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reliability::DeliveryOutcome;
    use crate::storage::drive_dedup_future;
    use std::sync::Arc;
    use std::thread;

    /// Claim, settle as accepted, and expect a replay to be rejected.
    fn claim_and_accept(storage: &dyn DedupStorage, key: &str) -> DedupVerdict {
        let verdict = drive_dedup_future(storage.claim(key)).unwrap();
        if verdict == DedupVerdict::Claimed {
            drive_dedup_future(storage.accept(key)).unwrap();
        }
        verdict
    }

    #[test]
    fn ttl_dedup_accepts_first_and_rejects_duplicate() {
        let storage = TtlDedupStorage::default();
        let key = "dedup:test:msg-1";
        assert_eq!(claim_and_accept(&storage, key), DedupVerdict::Claimed);
        assert_eq!(claim_and_accept(&storage, key), DedupVerdict::Duplicate);
    }

    #[test]
    fn ttl_dedup_reports_unsettled_claim_as_in_flight() {
        let storage = TtlDedupStorage::default();
        let key = "dedup:test:msg-unsettled";
        assert_eq!(
            drive_dedup_future(storage.claim(key)).unwrap(),
            DedupVerdict::Claimed
        );
        // Not Duplicate: nothing has taken responsibility for this message yet.
        assert_eq!(
            drive_dedup_future(storage.claim(key)).unwrap(),
            DedupVerdict::InFlight
        );
    }

    #[test]
    fn ttl_dedup_abandon_releases_but_accept_is_final() {
        let storage = TtlDedupStorage::default();
        let key = "dedup:test:msg-abandon";
        drive_dedup_future(storage.claim(key)).unwrap();
        drive_dedup_future(storage.abandon(key)).unwrap();
        assert_eq!(
            drive_dedup_future(storage.claim(key)).unwrap(),
            DedupVerdict::Claimed
        );
        drive_dedup_future(storage.accept(key)).unwrap();
        // A late abandon must not reopen a message that was really processed.
        drive_dedup_future(storage.abandon(key)).unwrap();
        assert_eq!(
            drive_dedup_future(storage.claim(key)).unwrap(),
            DedupVerdict::Duplicate
        );
    }

    #[test]
    fn ttl_dedup_is_correct_under_parallel_load() {
        let storage = Arc::new(TtlDedupStorage::default());
        let key = "dedup:test:parallel-msg";

        let mut handles = Vec::new();
        for _ in 0..16 {
            let storage = Arc::clone(&storage);
            handles.push(thread::spawn(move || {
                drive_dedup_future(storage.claim(key)).unwrap()
            }));
        }

        let accepted = handles
            .into_iter()
            .map(|h| h.join().expect("thread join"))
            .filter(|verdict| *verdict == DedupVerdict::Claimed)
            .count();

        assert_eq!(accepted, 1);
    }

    #[test]
    fn in_memory_reconciliation_deduplicates_by_key() {
        let storage = InMemoryReconciliationStorage::default();
        let first = ReconciliationRequest::for_outcome("m1", "p1", DeliveryOutcome::Indeterminate)
            .expect("request");
        let duplicate = first.clone();

        assert!(drive_dedup_future(storage.enqueue(first)).unwrap());
        assert!(!drive_dedup_future(storage.enqueue(duplicate)).unwrap());
        assert_eq!(
            drive_dedup_future(storage.queued_requests()).unwrap().len(),
            1
        );
    }

    #[test]
    fn in_memory_reconciliation_resolve_removes_from_queue() {
        let storage = InMemoryReconciliationStorage::default();
        let req =
            ReconciliationRequest::for_outcome("msg-resolve", "p1", DeliveryOutcome::Indeterminate)
                .expect("request");
        let key = req.idempotency_key.clone();
        assert!(drive_dedup_future(storage.enqueue(req)).unwrap());
        assert_eq!(
            drive_dedup_future(storage.queued_requests()).unwrap().len(),
            1
        );

        assert!(
            drive_dedup_future(storage.resolve(&key)).unwrap(),
            "resolve should return true when found"
        );
        assert_eq!(
            drive_dedup_future(storage.queued_requests()).unwrap().len(),
            0
        );

        // resolving again returns false (already removed)
        assert!(!drive_dedup_future(storage.resolve(&key)).unwrap());
    }

    #[test]
    fn ttl_dedup_rejects_duplicates_just_before_expiry() {
        let storage =
            TtlDedupStorage::with_sweep_interval(Duration::from_secs(2), Duration::from_secs(60));
        let key = "dedup:ttl:edge-before-expiry";

        assert_eq!(claim_and_accept(&storage, key), DedupVerdict::Claimed);
        thread::sleep(Duration::from_millis(1900));
        assert_eq!(
            drive_dedup_future(storage.claim(key)).unwrap(),
            DedupVerdict::Duplicate,
            "duplicate must be rejected inside TTL window"
        );
    }

    #[test]
    fn ttl_dedup_accepts_replay_after_expiry_with_buffer() {
        let storage =
            TtlDedupStorage::with_sweep_interval(Duration::from_secs(2), Duration::from_secs(60));
        let key = "dedup:ttl:edge-after-expiry";

        assert_eq!(claim_and_accept(&storage, key), DedupVerdict::Claimed);
        thread::sleep(Duration::from_millis(2300));
        assert_eq!(
            drive_dedup_future(storage.claim(key)).unwrap(),
            DedupVerdict::Claimed,
            "key must be claimable again after TTL expiry"
        );
    }

    #[test]
    fn ttl_dedup_expired_claim_lease_is_reclaimable() {
        // A process that died between claim and accept must not wedge the
        // message: the lease expires and the retransmission takes the key.
        let storage = TtlDedupStorage::with_sweep_interval(
            Duration::from_secs(3600),
            Duration::from_secs(3600),
        )
        .with_claim_lease(Duration::from_millis(200));
        let key = "dedup:ttl:lease-expiry";

        assert_eq!(
            drive_dedup_future(storage.claim(key)).unwrap(),
            DedupVerdict::Claimed
        );
        assert_eq!(
            drive_dedup_future(storage.claim(key)).unwrap(),
            DedupVerdict::InFlight
        );
        thread::sleep(Duration::from_millis(350));
        assert_eq!(
            drive_dedup_future(storage.claim(key)).unwrap(),
            DedupVerdict::Claimed,
            "an expired claim lease must be reclaimable"
        );
    }

    #[test]
    fn in_memory_reconciliation_bounded_capacity_rejects_overflow() {
        let storage = InMemoryReconciliationStorage::with_capacity(2);
        let r1 =
            ReconciliationRequest::for_outcome("msg-cap-1", "p1", DeliveryOutcome::Indeterminate)
                .unwrap();
        let r2 =
            ReconciliationRequest::for_outcome("msg-cap-2", "p1", DeliveryOutcome::Indeterminate)
                .unwrap();
        let r3 =
            ReconciliationRequest::for_outcome("msg-cap-3", "p1", DeliveryOutcome::Indeterminate)
                .unwrap();

        assert!(drive_dedup_future(storage.enqueue(r1)).unwrap());
        assert!(drive_dedup_future(storage.enqueue(r2)).unwrap());
        assert!(
            drive_dedup_future(storage.enqueue(r3)).is_err(),
            "should fail at capacity"
        );
    }

    #[test]
    fn in_memory_reconciliation_resolve_makes_room_after_capacity_hit() {
        let storage = InMemoryReconciliationStorage::with_capacity(1);
        let r1 =
            ReconciliationRequest::for_outcome("msg-room-1", "p1", DeliveryOutcome::Indeterminate)
                .unwrap();
        let r2 =
            ReconciliationRequest::for_outcome("msg-room-2", "p1", DeliveryOutcome::Indeterminate)
                .unwrap();
        let key1 = r1.idempotency_key.clone();

        assert!(drive_dedup_future(storage.enqueue(r1)).unwrap());
        assert!(
            drive_dedup_future(storage.enqueue(r2)).is_err(),
            "should fail at capacity"
        );

        // After resolving, the dedup key is also removed from `seen`, so the
        // same idempotency key can be re-enqueued for a retry.
        assert!(drive_dedup_future(storage.resolve(&key1)).unwrap());
        let r3 =
            ReconciliationRequest::for_outcome("msg-room-3", "p1", DeliveryOutcome::Indeterminate)
                .unwrap();
        assert!(
            drive_dedup_future(storage.enqueue(r3)).unwrap(),
            "new request should be accepted after resolve"
        );
    }

    #[test]
    fn in_memory_reconciliation_resolve_allows_reenqueue_of_same_key() {
        let storage = InMemoryReconciliationStorage::default();
        let r1 =
            ReconciliationRequest::for_outcome("msg-retry", "p1", DeliveryOutcome::Indeterminate)
                .unwrap();
        let key = r1.idempotency_key.clone();
        // Enqueue, then resolve; the same key must be re-enqueueable (retry scenario).
        assert!(
            drive_dedup_future(storage.enqueue(r1)).unwrap(),
            "initial enqueue"
        );
        assert!(
            !drive_dedup_future(
                storage.enqueue(
                    ReconciliationRequest::for_outcome(
                        "msg-retry",
                        "p1",
                        DeliveryOutcome::Indeterminate
                    )
                    .unwrap()
                )
            )
            .unwrap(),
            "duplicate enqueue before resolve must be rejected"
        );
        assert!(
            drive_dedup_future(storage.resolve(&key)).unwrap(),
            "resolve returns true"
        );
        // Re-enqueue the same idempotency key — must succeed after resolution.
        let r2 =
            ReconciliationRequest::for_outcome("msg-retry", "p1", DeliveryOutcome::Indeterminate)
                .unwrap();
        assert!(
            drive_dedup_future(storage.enqueue(r2)).unwrap(),
            "re-enqueue after resolve must succeed (retry path)"
        );
    }

    #[test]
    fn queued_requests_returns_all_items() {
        let storage = InMemoryReconciliationStorage::default();
        let r1 =
            ReconciliationRequest::for_outcome("m-each-1", "p1", DeliveryOutcome::Indeterminate)
                .unwrap();
        let r2 =
            ReconciliationRequest::for_outcome("m-each-2", "p1", DeliveryOutcome::Indeterminate)
                .unwrap();
        drive_dedup_future(storage.enqueue(r1)).unwrap();
        drive_dedup_future(storage.enqueue(r2)).unwrap();

        let mut collected: Vec<String> = drive_dedup_future(storage.queued_requests())
            .unwrap()
            .into_iter()
            .map(|r| r.message_id)
            .collect();
        collected.sort();
        assert_eq!(collected, ["m-each-1", "m-each-2"]);
    }

    #[test]
    fn ttl_dedup_accepts_after_expiry() {
        // Use a 1-nanosecond TTL so entries expire immediately.
        let storage = TtlDedupStorage::new(Duration::from_nanos(1));
        assert_eq!(claim_and_accept(&storage, "msg-2"), DedupVerdict::Claimed);
        // Sleep long enough for the TTL to expire (even nanosecond TTLs need
        // at least one syscall round-trip to observe the expiry reliably).
        std::thread::sleep(Duration::from_millis(10));
        // After expiry, the same key should be claimable again.
        assert_eq!(
            drive_dedup_future(storage.claim("msg-2")).unwrap(),
            DedupVerdict::Claimed,
            "key should be claimable after TTL expiry"
        );
    }

    #[test]
    fn ttl_dedup_distinct_keys_are_independent() {
        let storage = TtlDedupStorage::new(Duration::from_secs(60));
        assert_eq!(claim_and_accept(&storage, "key-a"), DedupVerdict::Claimed);
        assert_eq!(claim_and_accept(&storage, "key-b"), DedupVerdict::Claimed);
        assert_eq!(claim_and_accept(&storage, "key-a"), DedupVerdict::Duplicate);
        assert_eq!(claim_and_accept(&storage, "key-b"), DedupVerdict::Duplicate);
    }

    /// With sweeping disabled, an expired key is still re-accepted — the
    /// expiry *check* is per-key, so correctness does not depend on the sweep.
    /// Only reclamation does: re-inserting overwrites one entry, but a key that
    /// is never seen again is never removed.
    #[test]
    fn ttl_dedup_expiry_check_is_independent_of_sweeping() {
        let storage = TtlDedupStorage::with_sweep_interval(Duration::from_nanos(1), Duration::MAX)
            .with_claim_lease(Duration::from_nanos(1));
        assert_eq!(
            claim_and_accept(&storage, "msg-nosweep"),
            DedupVerdict::Claimed
        );
        std::thread::sleep(Duration::from_millis(10));
        assert_eq!(
            drive_dedup_future(storage.claim("msg-nosweep")).unwrap(),
            DedupVerdict::Claimed,
            "an expired key must be re-claimable even when the sweep never fires"
        );
    }

    /// The sweep is the only path that releases memory. Disabling it means
    /// entries for keys that are never seen again accumulate forever — worth
    /// pinning so the behaviour is not mistaken for an eviction policy.
    #[test]
    fn ttl_dedup_without_sweeping_never_releases_distinct_keys() {
        let storage = TtlDedupStorage::with_sweep_interval(Duration::from_nanos(1), Duration::MAX)
            .with_claim_lease(Duration::from_nanos(1));
        for i in 0..64 {
            let key = format!("k{i}");
            assert_eq!(claim_and_accept(&storage, &key), DedupVerdict::Claimed);
        }
        assert_eq!(
            storage.inner.lock().entries.len(),
            64,
            "every distinct key is retained when sweeping is disabled"
        );

        // A sweeping store reclaims them instead.
        let sweeping =
            TtlDedupStorage::with_sweep_interval(Duration::from_nanos(1), Duration::ZERO)
                .with_claim_lease(Duration::from_nanos(1));
        for i in 0..64 {
            let key = format!("k{i}");
            assert_eq!(claim_and_accept(&sweeping, &key), DedupVerdict::Claimed);
        }
        assert!(
            sweeping.inner.lock().entries.len() < 64,
            "a sweeping store reclaims expired entries"
        );
    }

    #[test]
    fn ttl_dedup_sweep_interval_constructor_respects_max_60s() {
        // ttl / 10 > 60s → sweep_interval capped at 60s
        let storage = TtlDedupStorage::new(Duration::from_secs(700));
        // Can't directly inspect sweep_interval, but construction must not panic.
        assert_eq!(claim_and_accept(&storage, "probe"), DedupVerdict::Claimed);
    }
}
