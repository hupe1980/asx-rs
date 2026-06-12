use super::super::coordination::ConversationOrderGate;
use super::super::large_message::As4FragmentJoiner;
use super::super::types::{As4ReceivePushOutput, As4ReceivePushProgress, As4ReceivePushRequest};
use super::ordered_async;
use super::{As4WsSecVerifier, EventBus, SessionContext, sync_core};
use crate::core::Result;
use crate::storage::DedupStorage;
use std::sync::Arc;

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

pub struct As4ReceivePushOrderedFragmentAwareRequest<'a> {
    pub request: As4ReceivePushRequest,
    pub dedup_backend: Arc<dyn crate::storage::DedupStorage>,
    /// Conversation ordering gate (see [`As4ReceivePushOrderedRequest::gate`]).
    pub gate: &'a dyn ConversationOrderGate,
    pub fragment_joiner: Arc<std::sync::Mutex<As4FragmentJoiner>>,
}

pub struct As4ReceivePushAsyncFragmentAwareRequest {
    pub request: As4ReceivePushRequest,
    pub dedup_backend: Arc<dyn DedupStorage>,
    pub fragment_joiner: Arc<std::sync::Mutex<As4FragmentJoiner>>,
}

pub struct As4ReceivePushSyncRequest<'a> {
    pub request: As4ReceivePushRequest,
    pub dedup_backend: &'a dyn DedupStorage,
}

pub struct As4ReceivePushSyncFragmentAwareRequest<'a> {
    pub request: As4ReceivePushRequest,
    pub dedup_backend: &'a dyn DedupStorage,
    pub fragment_joiner: &'a mut As4FragmentJoiner,
}

// Public receive wrappers are isolated here so receive.rs remains focused
// on guard enforcement and protocol orchestration internals.

#[cfg_attr(feature = "trace", tracing::instrument(skip_all, fields(partner_id = %session.partner_id())))]
pub fn receive_push_with_dedup_sync(
    session: &SessionContext,
    event_bus: &EventBus,
    request: As4ReceivePushSyncRequest<'_>,
) -> Result<As4ReceivePushOutput> {
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
) -> Result<As4ReceivePushOutput> {
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

/// Receive an inbound AS4 push message, serializing concurrent calls that
/// share the same <eb:ConversationId> through the provided gate.
///
/// This is the high-level entry point for deployments that require
/// per-conversation ordered delivery as defined by ebMS3 section 5.1.5.
#[cfg_attr(feature = "trace", tracing::instrument(skip_all, fields(partner_id = %session.partner_id())))]
pub async fn receive_push_ordered(
    session: &SessionContext,
    event_bus: &EventBus,
    request: As4ReceivePushOrderedRequest<'_>,
) -> crate::core::Result<As4ReceivePushOutput> {
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
pub async fn receive_push_ordered_fragment_aware(
    session: &SessionContext,
    event_bus: &EventBus,
    request: As4ReceivePushOrderedFragmentAwareRequest<'_>,
) -> crate::core::Result<As4ReceivePushProgress> {
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
