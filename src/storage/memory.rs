//! In-memory storage implementations for dedup and reconciliation.
//!
//! These implementations are suitable for single-node development and testing.
//! For multi-node deployments requiring exactly-once delivery guarantees,
//! implement custom backends using Redis, PostgreSQL, DynamoDB, etc.

use super::BoxFuture;
use parking_lot::Mutex;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::{DedupStorage, ReconciliationStorage};
use crate::reliability::ReconciliationRequest;

/// In-memory dedup storage using a HashSet.
/// Fail-closed semantics: any infrastructure failure (lock poison) fails the dedup check.
///
/// # ⚠ Unbounded memory growth
///
/// Every unique idempotency key is retained **indefinitely** — there is no
/// eviction, no TTL, and no capacity limit. Over days or weeks of operation
/// with UUID-based message IDs, memory consumption grows monotonically.
///
/// **For development and short-lived tests**: `InMemoryDedupStorage` is
/// convenient and accurate.
///
/// **For production deployments**: use one of the bounded alternatives:
/// - [`TtlDedupStorage`] — retains keys only for a configurable TTL window
///   (matches the replay-attack window; typically 5–60 minutes).
/// - [`BoundedFifoDedupStorage`] — FIFO eviction when a fixed capacity is
///   reached (predictable memory footprint, weaker anti-replay guarantee).
/// - A durable distributed backend (Redis, PostgreSQL, etc.) that implements
///   [`DedupStorage`] for clustered deployments.
#[derive(Debug, Default)]
pub struct InMemoryDedupStorage {
    seen: Mutex<HashSet<String>>,
}

impl DedupStorage for InMemoryDedupStorage {
    fn is_durable(&self) -> bool {
        false
    }

    fn first_seen<'a>(
        &'a self,
        idempotency_key: &'a str,
    ) -> BoxFuture<'a, crate::core::Result<bool>> {
        Box::pin(async move {
            let mut seen = self.seen.lock();
            if seen.contains(idempotency_key) {
                return Ok(false);
            }
            seen.insert(idempotency_key.to_owned());
            Ok(true)
        })
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
/// **Choose `capacity` based on your replay-protection window**: a value
/// of `10_000` is appropriate for most AS2/AS4 deployments that process
/// up to tens of thousands of messages per hour.
/// Internal dedup state: queue of seen keys + set of current keys.
type DedupState = (VecDeque<Arc<str>>, HashSet<Arc<str>>);

#[derive(Debug)]
pub struct BoundedFifoDedupStorage {
    /// Combined state protected by a single lock to eliminate TOCTOU races.
    /// Uses `Arc<str>` so both the queue and the set share one heap allocation
    /// per key — the `Arc::clone()` is a single reference-count increment with
    /// no additional heap allocation.
    state: Mutex<DedupState>,
    capacity: usize,
}

impl BoundedFifoDedupStorage {
    /// Create a new bounded FIFO store. `capacity` must be at least 1.
    ///
    /// # Panics
    /// Panics if `capacity` is 0.
    pub fn new(capacity: usize) -> Self {
        assert!(capacity > 0, "BoundedFifoDedupStorage capacity must be > 0");
        Self {
            state: Mutex::new((
                VecDeque::with_capacity(capacity),
                HashSet::with_capacity(capacity),
            )),
            capacity,
        }
    }

    /// Returns the configured maximum capacity.
    pub fn capacity(&self) -> usize {
        self.capacity
    }
}

impl DedupStorage for BoundedFifoDedupStorage {
    fn is_durable(&self) -> bool {
        false
    }

    fn first_seen<'a>(
        &'a self,
        idempotency_key: &'a str,
    ) -> BoxFuture<'a, crate::core::Result<bool>> {
        Box::pin(async move {
            let mut state = self.state.lock();
            let (queue, set) = &mut *state;
            if set.contains(idempotency_key) {
                return Ok(false);
            }
            if queue.len() >= self.capacity
                && let Some(oldest) = queue.pop_front()
            {
                set.remove(&*oldest);
            }
            let owned: Arc<str> = Arc::from(idempotency_key);
            queue.push_back(Arc::clone(&owned));
            set.insert(owned);
            Ok(true)
        })
    }
}

/// TTL-aware in-memory dedup storage.
///
/// TTL-based deduplication store backed by a `HashMap<String, Instant>`.
///
/// Each key is tracked with an expiry timestamp. On `first_seen`:
/// - **Duplicate fast path**: if the key exists and is unexpired, returns `false` in O(1).
/// - **New key**: inserts with `now + ttl` and returns `true`.
/// - **Sweep**: expired entries are swept lazily at most once per `sweep_interval`
///   (default: `min(ttl / 10, 60s)`), rather than on every insert, keeping the
///   amortised cost sub-linear for large windows.
///
/// This prevents the unbounded memory growth of `InMemoryDedupStorage`
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
}

#[derive(Debug)]
struct TtlDedupInner {
    entries: HashMap<String, Instant>,
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
    /// Smaller intervals use more CPU; larger intervals allow stale entries to
    /// accumulate until the next sweep fires.  A value of `Duration::MAX`
    /// disables background sweeps entirely (only the fast-path eviction runs).
    pub fn with_sweep_interval(ttl: Duration, sweep_interval: Duration) -> Self {
        Self {
            inner: Mutex::new(TtlDedupInner {
                entries: HashMap::new(),
                last_sweep: Instant::now(),
            }),
            ttl,
            sweep_interval,
        }
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

    fn first_seen<'a>(
        &'a self,
        idempotency_key: &'a str,
    ) -> BoxFuture<'a, crate::core::Result<bool>> {
        Box::pin(async move {
            let mut inner = self.inner.lock();
            let now = Instant::now();
            if inner
                .entries
                .get(idempotency_key)
                .is_some_and(|exp| now < *exp)
            {
                return Ok(false);
            }
            if now.duration_since(inner.last_sweep) >= self.sweep_interval {
                inner.entries.retain(|_, exp| now < *exp);
                inner.last_sweep = now;
            }
            inner
                .entries
                .insert(idempotency_key.to_string(), now + self.ttl);
            Ok(true)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reliability::DeliveryOutcome;
    use crate::storage::drive_dedup_future;
    use std::sync::Arc;
    use std::thread;

    #[test]
    fn in_memory_dedup_accepts_first_and_rejects_duplicate() {
        let storage = InMemoryDedupStorage::default();
        let key = "dedup:test:msg-1";
        assert!(drive_dedup_future(storage.first_seen(key)).unwrap());
        assert!(!drive_dedup_future(storage.first_seen(key)).unwrap());
    }

    #[test]
    fn in_memory_dedup_is_correct_under_parallel_load() {
        let storage = Arc::new(InMemoryDedupStorage::default());
        let key = "dedup:test:parallel-msg";

        let mut handles = Vec::new();
        for _ in 0..16 {
            let storage = Arc::clone(&storage);
            handles.push(thread::spawn(move || {
                drive_dedup_future(storage.first_seen(key)).unwrap()
            }));
        }

        let accepted = handles
            .into_iter()
            .map(|h| h.join().expect("thread join"))
            .filter(|accepted| *accepted)
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

        assert!(drive_dedup_future(storage.first_seen(key)).unwrap());
        thread::sleep(Duration::from_millis(1900));
        assert!(
            !drive_dedup_future(storage.first_seen(key)).unwrap(),
            "duplicate must be rejected inside TTL window"
        );
    }

    #[test]
    fn ttl_dedup_accepts_replay_after_expiry_with_buffer() {
        let storage =
            TtlDedupStorage::with_sweep_interval(Duration::from_secs(2), Duration::from_secs(60));
        let key = "dedup:ttl:edge-after-expiry";

        assert!(drive_dedup_future(storage.first_seen(key)).unwrap());
        thread::sleep(Duration::from_millis(2300));
        assert!(
            drive_dedup_future(storage.first_seen(key)).unwrap(),
            "key must be accepted after TTL expiry"
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
    fn bounded_fifo_accepts_first_and_rejects_duplicate() {
        let storage = BoundedFifoDedupStorage::new(10);
        assert!(drive_dedup_future(storage.first_seen("msg-a")).unwrap());
        assert!(!drive_dedup_future(storage.first_seen("msg-a")).unwrap());
        assert!(drive_dedup_future(storage.first_seen("msg-b")).unwrap());
    }

    #[test]
    fn bounded_fifo_evicts_oldest_at_capacity() {
        let storage = BoundedFifoDedupStorage::new(3);
        assert!(drive_dedup_future(storage.first_seen("k1")).unwrap());
        assert!(drive_dedup_future(storage.first_seen("k2")).unwrap());
        assert!(drive_dedup_future(storage.first_seen("k3")).unwrap());
        // k1 should now be evicted; re-inserting it succeeds.
        assert!(
            drive_dedup_future(storage.first_seen("k4")).unwrap(),
            "k1 evicted, k4 should insert"
        );
        assert!(
            drive_dedup_future(storage.first_seen("k1")).unwrap(),
            "k1 was evicted, should be accepted again"
        );
        // k2 is next oldest (after k1 was evicted and k4+k1 filled the queue)
        assert!(
            !drive_dedup_future(storage.first_seen("k4")).unwrap(),
            "k4 is still in window"
        );
    }

    #[test]
    fn bounded_fifo_capacity_one_always_evicts_previous() {
        let storage = BoundedFifoDedupStorage::new(1);
        assert!(drive_dedup_future(storage.first_seen("only-key")).unwrap());
        assert!(
            !drive_dedup_future(storage.first_seen("only-key")).unwrap(),
            "duplicate in window"
        );
        assert!(
            drive_dedup_future(storage.first_seen("new-key")).unwrap(),
            "evicts old, inserts new"
        );
        assert!(
            drive_dedup_future(storage.first_seen("only-key")).unwrap(),
            "evicted, accepted again"
        );
    }

    #[test]
    fn bounded_fifo_is_correct_under_parallel_load() {
        let storage = Arc::new(BoundedFifoDedupStorage::new(128));
        let key = "dedup:fifo:parallel-msg";
        let mut handles = Vec::new();
        for _ in 0..16 {
            let storage = Arc::clone(&storage);
            handles.push(thread::spawn(move || {
                drive_dedup_future(storage.first_seen(key)).unwrap()
            }));
        }
        let accepted = handles
            .into_iter()
            .map(|h| h.join().expect("thread join"))
            .filter(|a| *a)
            .count();
        assert_eq!(accepted, 1);
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
    fn ttl_dedup_accepts_first_and_rejects_duplicate() {
        let storage = TtlDedupStorage::new(Duration::from_secs(60));
        assert!(drive_dedup_future(storage.first_seen("msg-1")).unwrap());
        assert!(!drive_dedup_future(storage.first_seen("msg-1")).unwrap());
    }

    #[test]
    fn ttl_dedup_accepts_after_expiry() {
        // Use a 1-nanosecond TTL so entries expire immediately.
        let storage = TtlDedupStorage::new(Duration::from_nanos(1));
        assert!(drive_dedup_future(storage.first_seen("msg-2")).unwrap());
        // Sleep long enough for the TTL to expire (even nanosecond TTLs need
        // at least one syscall round-trip to observe the expiry reliably).
        std::thread::sleep(Duration::from_millis(10));
        // After expiry, the same key should be accepted again.
        assert!(
            drive_dedup_future(storage.first_seen("msg-2")).unwrap(),
            "key should be accepted after TTL expiry"
        );
    }

    #[test]
    fn ttl_dedup_distinct_keys_are_independent() {
        let storage = TtlDedupStorage::new(Duration::from_secs(60));
        assert!(drive_dedup_future(storage.first_seen("key-a")).unwrap());
        assert!(drive_dedup_future(storage.first_seen("key-b")).unwrap());
        assert!(!drive_dedup_future(storage.first_seen("key-a")).unwrap());
        assert!(!drive_dedup_future(storage.first_seen("key-b")).unwrap());
    }

    #[test]
    fn ttl_dedup_with_sweep_interval_max_never_sweeps() {
        // With sweep_interval = MAX, the throttled sweep never fires.
        // Entries accumulate until the fast-path eviction handles them on re-insert.
        let storage = TtlDedupStorage::with_sweep_interval(Duration::from_nanos(1), Duration::MAX);
        assert!(drive_dedup_future(storage.first_seen("msg-nosweep")).unwrap());
        std::thread::sleep(Duration::from_millis(10));
        // Expired key, but sweep is suppressed — fast-path still allows re-insert.
        assert!(
            drive_dedup_future(storage.first_seen("msg-nosweep")).unwrap(),
            "expired key re-accepted even without sweep"
        );
    }

    #[test]
    fn ttl_dedup_sweep_interval_constructor_respects_max_60s() {
        // ttl / 10 > 60s → sweep_interval capped at 60s
        let storage = TtlDedupStorage::new(Duration::from_secs(700));
        // Can't directly inspect sweep_interval, but construction must not panic.
        assert!(drive_dedup_future(storage.first_seen("probe")).unwrap());
    }
}
