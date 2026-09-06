use super::super::coordination::ConversationOrderGate;
use super::super::large_message::As4FragmentJoiner;
use super::super::types::{As4ReceiveOutcome, As4ReceivePushProgress, As4ReceivePushRequest};
use super::ordered::As4Ordered;
use super::ordered_async;
use super::{As4WsSecVerifier, EventBus, SessionContext, sync_core};
use crate::core::Result;
use crate::storage::DedupStorage;
use std::sync::Arc;

#[derive(Debug)]
pub struct As4ReceivePushOrderedRequest<'a> {
    pub request: As4ReceivePushRequest,
    pub dedup_backend: Arc<dyn crate::storage::DedupStorage>,
    /// Conversation ordering gate.
    ///
    /// Accepts any [`ConversationOrderGate`] implementation — use
    /// `&gate` where `gate: As4ConversationOrderGate` for the default
    /// in-process gate, or pass a custom distributed implementation for
    /// multi-replica deployments.
    pub gate: &'a dyn ConversationOrderGate,
}

#[derive(Debug)]
pub struct As4ReceivePushOrderedFragmentAwareRequest<'a> {
    pub request: As4ReceivePushRequest,
    pub dedup_backend: Arc<dyn crate::storage::DedupStorage>,
    /// Conversation ordering gate (see [`As4ReceivePushOrderedRequest::gate`]).
    pub gate: &'a dyn ConversationOrderGate,
    pub fragment_joiner: Arc<std::sync::Mutex<As4FragmentJoiner>>,
}

#[derive(Debug)]
pub struct As4ReceivePushAsyncFragmentAwareRequest {
    pub request: As4ReceivePushRequest,
    pub dedup_backend: Arc<dyn DedupStorage>,
    pub fragment_joiner: Arc<std::sync::Mutex<As4FragmentJoiner>>,
}

#[derive(Debug)]
pub struct As4ReceivePushSyncRequest<'a> {
    pub request: As4ReceivePushRequest,
    pub dedup_backend: &'a dyn DedupStorage,
}

#[derive(Debug)]
pub struct As4ReceivePushSyncFragmentAwareRequest<'a> {
    pub request: As4ReceivePushRequest,
    pub dedup_backend: &'a dyn DedupStorage,
    pub fragment_joiner: &'a mut As4FragmentJoiner,
}

// Public receive wrappers are isolated here so receive.rs remains focused
// on guard enforcement and protocol orchestration internals.

pub fn receive_push_with_dedup_sync(
    session: &SessionContext,
    event_bus: &EventBus,
    request: As4ReceivePushSyncRequest<'_>,
) -> Result<As4ReceiveOutcome> {
    let As4ReceivePushSyncRequest {
        request,
        dedup_backend,
    } = request;

    super::receive_push_with_dedup_sync_with_verifier(
        session,
        event_bus,
        request,
        dedup_backend,
        &As4WsSecVerifier,
    )
}

pub fn receive_push_with_dedup_sync_fragment_aware(
    session: &SessionContext,
    event_bus: &EventBus,
    request: As4ReceivePushSyncFragmentAwareRequest<'_>,
) -> Result<As4ReceivePushProgress> {
    let As4ReceivePushSyncFragmentAwareRequest {
        request,
        dedup_backend,
        fragment_joiner,
    } = request;

    sync_core::receive_push_with_dedup_sync_fragment_aware_with_verifier(
        session,
        event_bus,
        request,
        dedup_backend,
        &As4WsSecVerifier,
        Some(fragment_joiner),
    )
}

/// Async-safe receive entrypoint that isolates
/// synchronous parse/verify/decrypt work onto Tokio's blocking thread pool.
pub async fn receive_push_with_dedup_async(
    session: &SessionContext,
    event_bus: &EventBus,
    request: As4ReceivePushRequest,
    dedup_backend: Arc<dyn DedupStorage>,
) -> Result<As4ReceiveOutcome> {
    super::receive_push_with_dedup_async_with_verifier(
        session,
        event_bus,
        request,
        dedup_backend,
        As4WsSecVerifier,
    )
    .await
}

pub async fn receive_push_with_dedup_async_fragment_aware(
    session: &SessionContext,
    event_bus: &EventBus,
    request: As4ReceivePushAsyncFragmentAwareRequest,
) -> Result<As4ReceivePushProgress> {
    let As4ReceivePushAsyncFragmentAwareRequest {
        request,
        dedup_backend,
        fragment_joiner,
    } = request;

    super::async_bridge::receive_push_with_dedup_async_fragment_aware_with_shared_verifier(
        session,
        event_bus,
        request,
        dedup_backend,
        Arc::new(As4WsSecVerifier),
        fragment_joiner,
    )
    .await
}

/// Receive an inbound AS4 push message, preserving per-conversation arrival
/// order (ebMS3 §5.1.5).
///
/// The conversation's place in the queue is reserved from the raw bytes on
/// arrival, *before* parsing, verification and decryption — which run in
/// parallel with other messages — and the returned [`As4Ordered`] **holds the
/// turn** until it is dropped. Deliver the message to the application first;
/// dropping the value is what lets the next message in the conversation
/// through.
///
/// Both halves are load-bearing: reserving after the work orders by processing
/// time rather than arrival, and releasing before returning leaves delivery
/// unserialized (D54).
#[cfg_attr(feature = "trace", tracing::instrument(skip_all, fields(partner_id = %session.partner_id())))]
pub async fn receive_push_ordered(
    session: &SessionContext,
    event_bus: &EventBus,
    request: As4ReceivePushOrderedRequest<'_>,
) -> crate::core::Result<As4Ordered<As4ReceiveOutcome>> {
    let As4ReceivePushOrderedRequest {
        request,
        dedup_backend,
        gate,
    } = request;

    ordered_async::receive_push_ordered_with_verifier(
        session,
        event_bus,
        request,
        dedup_backend,
        gate,
        Arc::new(As4WsSecVerifier),
    )
    .await
}

#[cfg_attr(feature = "trace", tracing::instrument(skip_all, fields(partner_id = %session.partner_id())))]
/// Ordered receive that also reassembles ebMS3 Part 2 message fragments.
///
/// Only a *completed* message takes a turn: an incomplete fragment group and a
/// duplicate are never delivered, so neither holds the conversation open.
pub async fn receive_push_ordered_fragment_aware(
    session: &SessionContext,
    event_bus: &EventBus,
    request: As4ReceivePushOrderedFragmentAwareRequest<'_>,
) -> crate::core::Result<As4Ordered<As4ReceivePushProgress>> {
    let As4ReceivePushOrderedFragmentAwareRequest {
        request,
        dedup_backend,
        gate,
        fragment_joiner,
    } = request;

    ordered_async::receive_push_ordered_fragment_aware_with_verifier(
        session,
        event_bus,
        request,
        dedup_backend,
        gate,
        Arc::new(As4WsSecVerifier),
        fragment_joiner,
    )
    .await
}

/// Synchronous receive with a caller-supplied verifier — available under the
/// `testing` feature only.
///
/// Allows integration tests and [`crate::as4::mock_endpoint::MockAs4Endpoint`]
/// to inject a custom [`super::As4Verifier`] (e.g.
/// [`super::verifier::InsecureBypassAs4Verifier`]) without real PKI material.
///
/// # ⚠ Security
///
/// Never enable the `testing` feature in production builds.  The custom-verifier
/// entrypoint bypasses the production-hardened default verifier path.
#[cfg(feature = "testing")]
pub fn receive_push_with_dedup_sync_with_custom_verifier(
    session: &SessionContext,
    event_bus: &EventBus,
    request: As4ReceivePushSyncRequest<'_>,
    verifier: &(dyn super::As4Verifier + Send + Sync),
) -> Result<As4ReceiveOutcome> {
    super::receive_push_with_dedup_sync_with_verifier(
        session,
        event_bus,
        request.request,
        request.dedup_backend,
        verifier,
    )
}

/// Async receive with a caller-supplied verifier — available under the
/// `testing` feature only.
///
/// See [`receive_push_with_dedup_sync_with_custom_verifier`] for the sync
/// equivalent and a security note on this family of entrypoints.
#[cfg(feature = "testing")]
pub async fn receive_push_with_dedup_async_with_custom_verifier<V>(
    session: &SessionContext,
    event_bus: &EventBus,
    request: As4ReceivePushRequest,
    dedup_backend: Arc<dyn DedupStorage>,
    verifier: V,
) -> Result<As4ReceiveOutcome>
where
    V: super::As4Verifier + Send + Sync + 'static,
{
    super::receive_push_with_dedup_async_with_verifier(
        session,
        event_bus,
        request,
        dedup_backend,
        verifier,
    )
    .await
}
