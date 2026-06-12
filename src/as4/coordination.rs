//! Shared coordination-capability contract for AS4 topology validation.

use crate::core::{Result, SessionContext};

/// Boxed future returned by [`ConversationOrderGate::acquire_ordered_turn`].
type AcquireOrderedTurnFuture<'a> = std::pin::Pin<
    Box<dyn std::future::Future<Output = Result<Box<dyn ConversationGuardHandle>>> + Send + 'a>,
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

/// RAII guard returned by [`ConversationOrderGate::acquire_ordered_turn`].
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
///     fn acquire_ordered_turn<'a>(
///         &'a self, conversation_id: &'a str, _session: &'a SessionContext,
///     ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Box<dyn ConversationGuardHandle>>> + Send + 'a>> {
///         Box::pin(async move {
///             let guard = self.acquire_redis_lock(conversation_id).await?;
///             Ok(Box::new(guard) as Box<dyn ConversationGuardHandle>)
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
pub trait ConversationOrderGate: As4TopologyCoordination {
    /// Acquire and hold the ordered turn for `conversation_id`.
    ///
    /// Suspends until all previously-acquired turns for the same conversation
    /// have been released.  Returns a [`ConversationGuardHandle`] that releases
    /// the turn when dropped or when [`ConversationGuardHandle::release`] is
    /// called.
    ///
    /// # Errors
    ///
    /// Returns `ErrorCode::CapacityExhausted` if the gate cannot accept new
    /// conversations (e.g., capacity limit reached, lock timeout, etc.).
    fn acquire_ordered_turn<'a>(
        &'a self,
        conversation_id: &'a str,
        session: &'a SessionContext,
    ) -> AcquireOrderedTurnFuture<'a>;

    /// Validate and record the reply-predecessor relationship for ordered
    /// Two-Way MEPs.
    ///
    /// Must be called **while holding** the guard from `acquire_ordered_turn`,
    /// before releasing it.  Implementations that do not enforce predecessor
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
