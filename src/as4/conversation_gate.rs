//! Per-conversation serialization gate for ordered AS4 MEP configurations.
//!
//! ebMS3 §5.1.5 defines ordered delivery semantics: messages that belong to the
//! same `<eb:ConversationId>` SHOULD be delivered to the application in arrival
//! order when the P-Mode requires it.  This module provides
//! [`As4ConversationOrderGate`], a lightweight concurrent-safe registry of
//! per-conversation mutexes that serializes concurrent receives for the **same**
//! conversation while allowing **distinct** conversations to proceed in parallel.
//!
//! ## Slot lifecycle
//!
//! Each slot is stored as a [`Weak<ConversationTurnSlot>`].  The backing [`Arc`] lives only
//! as long as at least one [`ConversationGuard`] (or a task waiting to acquire
//! one) holds a strong reference.  When the last guard is dropped the `Arc`
//! strong-count reaches zero, the slot becomes *dead* (`Weak::upgrade` returns
//! `None`), and the next insertion at that key replaces it with a fresh
//! allocation.
//!
//! The `capacity` parameter therefore bounds the number of *simultaneously
//! active* conversations, not the total number of historical ones.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Weak};
use tokio::sync::{Mutex, Notify};

use crate::as4::As4TopologyCoordination;
use crate::as4::coordination::{ConversationGuardHandle, ConversationOrderGate};
use crate::core::{AsxError, ErrorCode, ErrorContext, Result};

// ── Public types ─────────────────────────────────────────────────────────────

/// Per-conversation serialization gate for ordered AS4 MEP configurations.
///
/// When two concurrent calls to [`acquire`](Self::acquire) share the same
/// `conversation_id`, the second caller suspends until the first releases its
/// [`ConversationGuard`].  Calls with *different* conversation IDs proceed in
/// parallel without contention.
///
/// ## ⚠ Single-process limitation
///
/// `As4ConversationOrderGate` is an **in-process, in-memory** gate.  It
/// provides no ordering guarantees across multiple process replicas.  If your
/// deployment runs more than one instance behind a load balancer (horizontal
/// scaling), sticky routing — pinning all messages for a given
/// `ConversationId` to the same replica — is required to preserve ordered
/// delivery semantics.  Without sticky routing, interleaved deliveries from
/// different replicas can violate ebMS3 §5.1.5 ordering even though each
/// individual replica serialises correctly.
///
/// For multi-process deployments consider replacing this gate with a
/// distributed coordination primitive (e.g. a Redis `SETNX` lock, a
/// database advisory lock) that spans all replicas.
///
/// ## Example
///
/// ```rust
/// # use asx_rs::as4::{
/// #     receive_push_ordered, As4ConversationOrderGate, As4ReceivePushOrderedRequest,
/// #     As4ReceivePushRequest,
/// # };
/// # async fn example(
/// #     session: &asx_rs::core::SessionContext,
/// #     bus: &asx_rs::observability::EventBus,
/// #     request: As4ReceivePushRequest,
/// #     dedup: std::sync::Arc<dyn asx_rs::storage::DedupStorage>,
/// # ) -> asx_rs::core::Result<()> {
/// let gate = As4ConversationOrderGate::new(256);
///
/// // Serializes all messages for the same ConversationId, lets distinct
/// // conversations through without contention.
/// let output = receive_push_ordered(
///     session,
///     bus,
///     As4ReceivePushOrderedRequest {
///         request,
///         dedup_backend: dedup,
///         gate: &gate,
///     },
/// )
/// .await?;
/// # Ok(())
/// # }
/// ```
pub struct As4ConversationOrderGate {
    /// Map from `conversation_id` → `Weak<ConversationTurnSlot>`.
    /// The outer `Mutex` is held only for brief slot look-up/create.
    slots: Mutex<HashMap<Arc<str>, Weak<ConversationTurnSlot>>>,
    completed_messages: Mutex<HashMap<Arc<str>, CompletedMessageTracker>>,
    capacity: usize,
}

impl std::fmt::Debug for As4ConversationOrderGate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("As4ConversationOrderGate")
            .field("capacity", &self.capacity)
            .finish_non_exhaustive()
    }
}

/// RAII guard returned by [`As4ConversationOrderGate::acquire`].
///
/// Holding this guard ensures exclusive access for the acquired `conversation_id`.
/// Dropping it allows the next waiting caller for the same conversation to proceed.
pub struct ConversationGuard {
    _turn: ConversationTurnGuard,
}

/// Ticket reservation used to preserve per-conversation arrival ordering while
/// allowing heavy work to happen before waiting for turn.
pub struct ConversationTurnReservation {
    slot: Arc<ConversationTurnSlot>,
    ticket: u64,
    advance_on_drop: bool,
}

/// Guard for a currently active ticket turn.
///
/// Dropping advances the conversation to the next ticket and wakes one waiter.
pub struct ConversationTurnGuard {
    slot: Arc<ConversationTurnSlot>,
}

struct ConversationTurnState {
    waiters: HashMap<u64, Arc<Notify>>,
    abandoned: HashSet<u64>,
}

#[derive(Default)]
struct CompletedMessageTracker {
    ids: HashSet<Arc<str>>,
    order: VecDeque<Arc<str>>,
}

struct ConversationTurnSlot {
    next_ticket: AtomicU64,
    serving_ticket: AtomicU64,
    /// `std::sync::Mutex` is correct here: the critical section is a single
    /// `HashMap::insert/remove` with no `.await` points, so a blocking mutex
    /// is both sufficient and avoids the `blocking_lock()` / async-context
    /// deadlock that arises when `tokio::sync::Mutex` is dropped from `Drop`.
    state: std::sync::Mutex<ConversationTurnState>,
}

impl Default for ConversationTurnSlot {
    fn default() -> Self {
        Self {
            next_ticket: AtomicU64::new(0),
            serving_ticket: AtomicU64::new(0),
            state: std::sync::Mutex::new(ConversationTurnState {
                waiters: HashMap::new(),
                abandoned: HashSet::new(),
            }),
        }
    }
}

const MAX_TRACKED_COMPLETED_MESSAGE_IDS_PER_CONVERSATION: usize = 4096;
// NOTE: Replay-window interaction with `DedupStorage` TTL
//
// `CompletedMessageTracker` guards against duplicate delivery *within a single
// gate instance* (i.e. a single process and its in-memory lifetime).  When the
// 4 096-ID ring is full for a given conversation, the oldest IDs are evicted;
// a later replay of an evicted ID will not be caught by this gate.
//
// The backing `DedupStorage` (typically `TtlDedupStorage`) provides a second,
// time-bounded deduplication layer.  To avoid a replay window you MUST ensure:
//
//   `DedupStorage::TTL`  ≥  max in-flight message rate × gate eviction time
//
// Concretely: if a conversation produces messages faster than
// (4 096 / TTL-seconds) messages per second the gate will evict IDs before the
// dedup TTL expires, creating a window where a replayed message-ID passes both
// checks.  Align your dedup TTL to cover the expected burst rate, or configure
// a larger `DedupStorage` capacity.
//
// In single-process deployments the gate and `DedupStorage` together form a
// defense-in-depth pair.  In multi-replica deployments the gate provides no
// cross-process protection; rely on `DedupStorage` (backed by a shared store
// such as Redis or a database) as the primary dedup mechanism.

impl std::fmt::Debug for ConversationGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConversationGuard").finish_non_exhaustive()
    }
}

impl std::fmt::Debug for ConversationTurnReservation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConversationTurnReservation")
            .field("ticket", &self.ticket)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for ConversationTurnGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConversationTurnGuard")
            .finish_non_exhaustive()
    }
}

// ── Implementation ────────────────────────────────────────────────────────────

impl As4ConversationOrderGate {
    /// Create a gate that can track up to `capacity` simultaneously active
    /// conversations (those with at least one caller holding or waiting for a
    /// [`ConversationGuard`]).
    ///
    /// A sensible default for most deployments is `256`–`4096`.
    ///
    /// # Panics
    ///
    /// Panics if `capacity == 0`.
    pub fn new(capacity: usize) -> Self {
        assert!(
            capacity > 0,
            "As4ConversationOrderGate capacity must be > 0"
        );
        Self {
            slots: Mutex::new(HashMap::with_capacity(capacity.min(512))),
            completed_messages: Mutex::new(HashMap::with_capacity(capacity.min(512))),
            capacity,
        }
    }

    /// Whether this ordering gate implementation is safe for clustered deployments.
    ///
    /// `As4ConversationOrderGate` is process-local and therefore not cluster-safe.
    #[inline]
    pub fn cluster_safe(&self) -> bool {
        false
    }

    pub(crate) async fn enforce_reply_predecessor_and_record(
        &self,
        conversation_id: &str,
        message_id: &str,
        ref_to_message_id: Option<&str>,
    ) -> Result<()> {
        let mut completed = self.completed_messages.lock().await;
        let tracker = completed.entry(Arc::from(conversation_id)).or_default();

        if let Some(ref_to) = ref_to_message_id
            && !tracker.ids.contains(ref_to)
        {
            return Err(AsxError::new(
                ErrorCode::ReliabilityFailure,
                format!(
                    "ordered AS4 Two-Way response references unknown predecessor MessageId '{}'; expected predecessor completion on this replica before response processing",
                    ref_to
                ),
                ErrorContext::new("as4_receive_push_ordered"),
            ));
        }

        let message_id: Arc<str> = Arc::from(message_id);
        if tracker.ids.insert(Arc::clone(&message_id)) {
            tracker.order.push_back(message_id);
            while tracker.order.len() > MAX_TRACKED_COMPLETED_MESSAGE_IDS_PER_CONVERSATION {
                if let Some(expired) = tracker.order.pop_front() {
                    tracker.ids.remove(&expired);
                }
            }
        }

        Ok(())
    }

    /// Acquire exclusive access for `conversation_id`.
    ///
    /// If another caller already holds the guard for this conversation, this
    /// call suspends until that guard is dropped.  Calls for *different*
    /// conversation IDs return immediately, independent of each other.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorCode::CapacityExhausted`] if the gate has reached
    /// `capacity` *active* (guard-held) conversations and no idle slots could
    /// be reclaimed.  Callers should shed load or retry after a brief delay.
    pub async fn acquire(&self, conversation_id: &str) -> Result<ConversationGuard> {
        let turn = self.reserve_turn(conversation_id).await?;
        let turn_guard = turn.wait_turn().await?;
        Ok(ConversationGuard { _turn: turn_guard })
    }

    /// Reserve an arrival-order ticket for `conversation_id`.
    ///
    /// The returned ticket preserves ordering among callers that reserved for
    /// the same conversation. Callers can do expensive work first, then await
    /// their turn by calling `wait_turn()` on the returned reservation.
    pub async fn reserve_turn(&self, conversation_id: &str) -> Result<ConversationTurnReservation> {
        let slot = self.lookup_or_create_turn_slot(conversation_id).await?;
        let ticket = slot.next_ticket.fetch_add(1, Ordering::AcqRel);
        if ticket == u64::MAX {
            return Err(AsxError::new(
                ErrorCode::PolicyViolation,
                "as4 conversation order gate ticket counter overflow",
                ErrorContext::new("as4_conversation_order_gate"),
            ));
        }

        Ok(ConversationTurnReservation {
            slot,
            ticket,
            advance_on_drop: true,
        })
    }

    async fn lookup_or_create_turn_slot(
        &self,
        conversation_id: &str,
    ) -> Result<Arc<ConversationTurnSlot>> {
        let mut map = self.slots.lock().await;

        if let Some(slot_ref) = map.get_mut(conversation_id) {
            if let Some(slot) = slot_ref.upgrade() {
                return Ok(slot);
            }
            let new_slot = Arc::new(ConversationTurnSlot::default());
            *slot_ref = Arc::downgrade(&new_slot);
            return Ok(new_slot);
        }

        // Capacity check and insertion happen while holding the same map lock,
        // so there is no admission race between count and insert.
        if map.len() >= self.capacity {
            map.retain(|_, w| w.strong_count() > 0);
            let active_keys: HashSet<Arc<str>> = map.keys().cloned().collect();
            let mut completed = self.completed_messages.lock().await;
            completed.retain(|k, _| active_keys.contains(k));

            if map.len() >= self.capacity {
                return Err(AsxError::new(
                    ErrorCode::CapacityExhausted,
                    format!(
                        "as4 conversation order gate capacity exhausted \
                                 ({} active conversations)",
                        self.capacity
                    ),
                    ErrorContext::new("as4_conversation_order_gate"),
                ));
            }
        }

        let new_slot = Arc::new(ConversationTurnSlot::default());
        map.insert(Arc::from(conversation_id), Arc::downgrade(&new_slot));
        Ok(new_slot)
    }

    /// Returns the configured maximum capacity.
    #[inline]
    pub fn capacity(&self) -> usize {
        self.capacity
    }
}

impl As4TopologyCoordination for As4ConversationOrderGate {
    fn cluster_safe(&self) -> bool {
        self.cluster_safe()
    }

    fn topology_component(&self) -> &'static str {
        "conversation-order-gate"
    }
}

// ---------------------------------------------------------------------------
// ConversationOrderGate + ConversationGuardHandle for As4ConversationOrderGate
// ---------------------------------------------------------------------------

/// Wraps a [`ConversationTurnGuard`] as a boxable [`ConversationGuardHandle`].
struct InProcessConversationGuardHandle(Option<ConversationTurnGuard>);

impl ConversationGuardHandle for InProcessConversationGuardHandle {
    fn release(mut self: Box<Self>) {
        // Drop the inner guard, which advances the ticket counter.
        drop(self.0.take());
    }
}

impl Drop for InProcessConversationGuardHandle {
    fn drop(&mut self) {
        // Guard releases on drop too — nothing to do here because dropping
        // `ConversationTurnGuard` already advances the counter.
        let _ = self.0.take();
    }
}

#[allow(clippy::manual_async_fn)]
impl ConversationOrderGate for As4ConversationOrderGate {
    /// Acquire the ordered turn for `conversation_id`.
    ///
    /// Combines the internal `reserve_turn` + `wait_turn` two-phase operation
    /// into a single future.  For the in-process gate the optimization of early
    /// reservation (before full parse) is available via the lower-level
    /// `reserve_turn` / `wait_turn` methods; this combined path is provided for
    /// trait-object callers that cannot use the concrete type.
    fn acquire_ordered_turn<'a>(
        &'a self,
        conversation_id: &'a str,
        _session: &'a crate::core::SessionContext,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = crate::core::Result<Box<dyn ConversationGuardHandle>>>
                + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            let turn = self.reserve_turn(conversation_id).await?;
            let guard = turn.wait_turn().await?;
            Ok(Box::new(InProcessConversationGuardHandle(Some(guard)))
                as Box<dyn ConversationGuardHandle>)
        })
    }

    fn record_message_ordering<'a>(
        &'a self,
        conversation_id: &'a str,
        message_id: &'a str,
        ref_to_message_id: Option<&'a str>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = crate::core::Result<()>> + Send + 'a>>
    {
        Box::pin(async move {
            self.enforce_reply_predecessor_and_record(
                conversation_id,
                message_id,
                ref_to_message_id,
            )
            .await
        })
    }
}

impl ConversationTurnReservation {
    /// Wait until this reservation reaches the head of the per-conversation
    /// queue and return a guard that advances the queue when dropped.
    pub async fn wait_turn(mut self) -> Result<ConversationTurnGuard> {
        loop {
            if self.ticket == self.slot.serving_ticket.load(Ordering::Acquire) {
                self.advance_on_drop = false;
                return Ok(ConversationTurnGuard {
                    slot: self.slot.clone(),
                });
            }

            let maybe_waiter = {
                let mut state = self
                    .slot
                    .state
                    .lock()
                    .expect("conversation gate state lock");
                if self.ticket == self.slot.serving_ticket.load(Ordering::Acquire) {
                    continue;
                }
                state
                    .waiters
                    .entry(self.ticket)
                    .or_insert_with(|| Arc::new(Notify::new()))
                    .clone()
            };
            maybe_waiter.notified().await;
        }
    }
}

impl Drop for ConversationTurnReservation {
    fn drop(&mut self) {
        if !self.advance_on_drop {
            return;
        }

        {
            let mut state = self
                .slot
                .state
                .lock()
                .expect("conversation gate state lock");
            state.waiters.remove(&self.ticket);
            state.abandoned.insert(self.ticket);
        }

        self.slot.drain_abandoned_head();
    }
}

impl Drop for ConversationTurnGuard {
    fn drop(&mut self) {
        let next_ticket = self.slot.serving_ticket.fetch_add(1, Ordering::AcqRel) + 1;
        let maybe_waiter = {
            let mut state = self
                .slot
                .state
                .lock()
                .expect("conversation gate state lock");
            state.waiters.remove(&next_ticket)
        };
        if let Some(waiter) = maybe_waiter {
            waiter.notify_one();
        }
        self.slot.drain_abandoned_head();
    }
}

impl ConversationTurnSlot {
    /// Advance past any abandoned tickets at the head of the queue.
    ///
    /// Called from [`ConversationTurnGuard::drop`] after the current turn
    /// completes so the next waiter can proceed.
    ///
    /// The loop is **capped** at `MAX_DRAIN_ITERS` to bound the work done
    /// in a single drop.  Any remaining abandoned-head tickets will be drained
    /// by the next dropper, keeping tail latency predictable under adversarial
    /// or burst-cancellation workloads.
    fn drain_abandoned_head(&self) {
        /// Maximum consecutive abandoned tickets drained in a single call.
        const MAX_DRAIN_ITERS: u32 = 64;

        for _ in 0..MAX_DRAIN_ITERS {
            let serving = self.serving_ticket.load(Ordering::Acquire);
            let is_abandoned = {
                let state = self.state.lock().expect("conversation gate state lock");
                state.abandoned.contains(&serving)
            };

            if !is_abandoned {
                break;
            }

            if self
                .serving_ticket
                .compare_exchange(serving, serving + 1, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
            {
                // Another thread advanced the counter concurrently; re-check
                // the new head on the next iteration.
                continue;
            }

            let maybe_waiter = {
                let mut state = self.state.lock().expect("conversation gate state lock");
                state.abandoned.remove(&serving);
                state.waiters.remove(&(serving + 1))
            };

            if let Some(waiter) = maybe_waiter {
                waiter.notify_one();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::As4ConversationOrderGate;
    use crate::core::ErrorCode;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::sync::oneshot;
    use tokio::sync::{Barrier, Notify};
    use tokio::time::{Duration, timeout};

    #[tokio::test]
    async fn same_conversation_is_serialized() {
        let gate = Arc::new(As4ConversationOrderGate::new(8));
        let guard = gate.acquire("conv-1").await.expect("first acquire");

        let (acquired_tx, acquired_rx) = oneshot::channel::<()>();
        let gate_ref = Arc::clone(&gate);
        let waiter = tokio::spawn(async move {
            let _g = gate_ref.acquire("conv-1").await.expect("second acquire");
            let _ = acquired_tx.send(());
        });

        // The second acquire must remain blocked while the first guard is held.
        assert!(
            timeout(Duration::from_millis(30), acquired_rx)
                .await
                .is_err()
        );

        drop(guard);
        waiter.await.expect("waiter task join");
    }

    #[tokio::test]
    async fn different_conversations_proceed_in_parallel() {
        let gate = As4ConversationOrderGate::new(8);
        let _guard_a = gate.acquire("conv-a").await.expect("acquire conv-a");

        // Different conversation key should not block behind conv-a.
        let guard_b = timeout(Duration::from_millis(50), gate.acquire("conv-b"))
            .await
            .expect("conv-b acquire timeout")
            .expect("acquire conv-b");
        drop(guard_b);
    }

    #[tokio::test]
    async fn capacity_is_never_overshot_under_contention() {
        const CAPACITY: usize = 8;
        const CONTENDERS: usize = 64;

        let gate = Arc::new(As4ConversationOrderGate::new(CAPACITY));
        let start = Arc::new(Barrier::new(CONTENDERS + 1));
        let release = Arc::new(Notify::new());

        let success = Arc::new(AtomicUsize::new(0));
        let capacity_exhausted = Arc::new(AtomicUsize::new(0));

        let mut tasks = Vec::with_capacity(CONTENDERS);
        for idx in 0..CONTENDERS {
            let gate_ref = Arc::clone(&gate);
            let start_ref = Arc::clone(&start);
            let release_ref = Arc::clone(&release);
            let success_ref = Arc::clone(&success);
            let exhausted_ref = Arc::clone(&capacity_exhausted);

            tasks.push(tokio::spawn(async move {
                start_ref.wait().await;

                match gate_ref.acquire(&format!("conv-{idx}")).await {
                    Ok(_guard) => {
                        success_ref.fetch_add(1, Ordering::SeqCst);
                        release_ref.notified().await;
                    }
                    Err(err) if err.code == ErrorCode::CapacityExhausted => {
                        exhausted_ref.fetch_add(1, Ordering::SeqCst);
                    }
                    Err(err) => panic!("unexpected error: {err}"),
                }
            }));
        }

        start.wait().await;
        tokio::time::sleep(Duration::from_millis(40)).await;

        assert_eq!(success.load(Ordering::SeqCst), CAPACITY);
        assert_eq!(
            capacity_exhausted.load(Ordering::SeqCst),
            CONTENDERS - CAPACITY
        );

        release.notify_waiters();
        for task in tasks {
            task.await.expect("join contender");
        }
    }

    #[tokio::test]
    async fn dropping_reserved_turn_skips_ticket_for_following_waiters() {
        let gate = As4ConversationOrderGate::new(8);

        let first = gate.reserve_turn("conv-drop").await.expect("reserve first");
        let dropped = gate
            .reserve_turn("conv-drop")
            .await
            .expect("reserve dropped");
        let third = gate.reserve_turn("conv-drop").await.expect("reserve third");

        let first_guard = first.wait_turn().await.expect("first guard");
        drop(dropped);

        drop(first_guard);
        let third_guard = timeout(Duration::from_millis(100), third.wait_turn())
            .await
            .expect("third wait timeout")
            .expect("third guard");
        drop(third_guard);
    }

    #[tokio::test]
    async fn cancelled_wait_turn_does_not_deadlock_later_ticket() {
        let gate = Arc::new(As4ConversationOrderGate::new(8));

        let first = gate
            .reserve_turn("conv-cancel")
            .await
            .expect("reserve first");
        let cancelled = gate
            .reserve_turn("conv-cancel")
            .await
            .expect("reserve cancelled");
        let third = gate
            .reserve_turn("conv-cancel")
            .await
            .expect("reserve third");

        let first_guard = first.wait_turn().await.expect("first guard");

        let cancelled_task = tokio::spawn(async move {
            let _ = cancelled.wait_turn().await;
        });

        tokio::time::sleep(Duration::from_millis(10)).await;
        cancelled_task.abort();
        let _ = cancelled_task.await;

        drop(first_guard);
        let third_guard = timeout(Duration::from_millis(100), third.wait_turn())
            .await
            .expect("third wait timeout")
            .expect("third guard");
        drop(third_guard);
    }
}
