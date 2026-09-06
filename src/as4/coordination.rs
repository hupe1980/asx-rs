//! Shared coordination-capability contract for AS4 topology validation.

use crate::core::{Result, SessionContext};

/// Boxed future yielding a held turn.
type TurnFuture<'a> = std::pin::Pin<
    Box<dyn std::future::Future<Output = Result<Box<dyn ConversationGuardHandle>>> + Send + 'a>,
>;

/// Boxed future returned by [`ConversationOrderGate::reserve_ordered_turn`].
type ReserveTurnFuture<'a> = std::pin::Pin<
    Box<dyn std::future::Future<Output = Result<Box<dyn ConversationTurnHandle>>> + Send + 'a>,
>;

/// Capability surface for AS4 ordered-delivery and pull-queue coordination backends.
///
/// Strict-production startup validation uses this trait so clustered deployments
/// must pass concrete coordination handles instead of raw booleans.
pub trait As4TopologyCoordination: Send + Sync {
    /// Whether this backend is safe for multi-node clustered deployments.
    fn cluster_safe(&self) -> bool;

    /// Human-readable component label used in startup-validation diagnostics.
    fn topology_component(&self) -> &'static str;
}

// ---------------------------------------------------------------------------
// ConversationOrderGate — distributed / pluggable gate abstraction
// ---------------------------------------------------------------------------

/// RAII guard for a conversation's active turn.
///
/// The guard holds the ordered turn for a single AS4 conversation.  All
/// subsequent waiters for the same conversation are suspended until this guard
/// is released.
///
/// Implementations must also release the turn on `drop` so that panics or task
/// cancellation never leave a conversation permanently blocked.
pub trait ConversationGuardHandle: Send {
    /// Explicitly release this turn and advance to the next waiter.
    ///
    /// Calling `release` is optional — the guard also releases on `drop`.
    /// Prefer explicit `release` so that the turn boundary is visible at the
    /// call site.
    fn release(self: Box<Self>);
}

/// A reserved place in a conversation's **arrival** order.
///
/// This is the half of the gate that makes ordering mean anything. The
/// reservation is taken as soon as a message arrives — before it is parsed,
/// verified or decrypted — so the queue reflects the order messages showed up
/// in. [`wait_for_turn`](Self::wait_for_turn) is then awaited *after* that work,
/// and yields only once every earlier arrival has finished.
///
/// Reserving after the work instead orders by processing time: a small message
/// that arrived second overtakes a large one that arrived first (D54).
///
/// Dropping a reservation without waiting releases the place, so a failed
/// receive does not block the conversation.
pub trait ConversationTurnHandle: Send {
    /// Wait until every earlier reservation for this conversation has been
    /// released, then take the turn.
    ///
    /// # Errors
    ///
    /// Backend-specific; a distributed gate typically fails on lock timeout.
    fn wait_for_turn(self: Box<Self>) -> TurnFuture<'static>;
}

/// Conversation-level ordering gate for AS4 ordered-delivery MEPs.
///
/// The `As4ConversationOrderGate` is an **in-process** implementation.  For
/// multi-replica deployments, supply a custom implementation backed by:
/// - A Redis `SET NX PX` lock (redlock-style)
/// - A database advisory lock (`pg_try_advisory_lock`)
/// - A ZooKeeper ephemeral node
///
/// ## ⚠ Sticky routing requirement
///
/// Even with a distributed `ConversationOrderGate`, replicas that receive
/// messages out of order cannot guarantee the *application-visible* delivery
/// sequence unless all messages for a given `ConversationId` are routed to the
/// same replica **or** the coordination primitive enforces strict global ordering.
/// A Redis-based gate provides mutual exclusion but NOT sequencing across replicas
/// unless combined with a sequence counter.  Document your deployment topology's
/// ordering guarantees clearly.
///
/// ## Example — plugging in a custom gate
///
/// ```rust,ignore
/// struct RedisOrderGate { client: redis::Client }
///
/// impl ConversationOrderGate for RedisOrderGate {
///     fn reserve_ordered_turn<'a>(
///         &'a self, conversation_id: &'a str, _session: &'a SessionContext,
///     ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Box<dyn ConversationTurnHandle>>> + Send + 'a>> {
///         Box::pin(async move {
///             // Take a sequence number now; wait for it in `wait_for_turn`.
///             let ticket = self.next_ticket(conversation_id).await?;
///             Ok(Box::new(ticket) as Box<dyn ConversationTurnHandle>)
///         })
///     }
///     fn record_message_ordering<'a>(
///         &'a self, _: &'a str, _: &'a str, _: Option<&'a str>,
///     ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'a>> {
///         Box::pin(async move { Ok(()) })
///     }
/// }
///
/// impl As4TopologyCoordination for RedisOrderGate {
///     fn cluster_safe(&self) -> bool { true }
///     fn topology_component(&self) -> &'static str { "redis-conversation-gate" }
/// }
/// ```
pub trait ConversationOrderGate: As4TopologyCoordination + std::fmt::Debug {
    /// Take this message's place in `conversation_id`'s arrival order.
    ///
    /// Returns immediately with a [`ConversationTurnHandle`]; it does **not**
    /// wait for the turn. Call this before parsing, verification or decryption,
    /// so the queue records arrival order rather than completion order.
    ///
    /// # Errors
    ///
    /// Returns `ErrorCode::CapacityExhausted` if the gate cannot accept new
    /// conversations (capacity limit reached, lock timeout, and so on).
    fn reserve_ordered_turn<'a>(
        &'a self,
        conversation_id: &'a str,
        session: &'a SessionContext,
    ) -> ReserveTurnFuture<'a>;

    /// Reserve and immediately wait — the whole turn in one call.
    ///
    /// Only correct where there is no work to overlap with the wait. The
    /// ordered receive path does not use it, because everything expensive
    /// belongs *between* the two halves.
    fn acquire_ordered_turn<'a>(
        &'a self,
        conversation_id: &'a str,
        session: &'a SessionContext,
    ) -> TurnFuture<'a> {
        Box::pin(async move {
            self.reserve_ordered_turn(conversation_id, session)
                .await?
                .wait_for_turn()
                .await
        })
    }

    /// Validate and record the reply-predecessor relationship for ordered
    /// Two-Way MEPs.
    ///
    /// Must be called **while holding** the guard from
    /// [`ConversationTurnHandle::wait_for_turn`], before releasing it.  Implementations that do not enforce predecessor
    /// semantics should return `Ok(())`.
    ///
    /// # Parameters
    ///
    /// - `conversation_id`: the conversation being processed.
    /// - `message_id`: the `MessageId` of the message just processed.
    /// - `ref_to_message_id`: the `RefToMessageId` from the inbound message, if any.
    fn record_message_ordering<'a>(
        &'a self,
        conversation_id: &'a str,
        message_id: &'a str,
        ref_to_message_id: Option<&'a str>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'a>>;
}
