use super::super::coordination::ConversationOrderGate;
use super::super::large_message::As4FragmentJoiner;
use super::super::types::{As4ReceiveOutcome, As4ReceivePushProgress, As4ReceivePushRequest};
use super::{As4Verifier, EventBus, SessionContext, ordered};
use std::sync::Arc;

pub(super) async fn receive_push_ordered_with_verifier(
    session: &SessionContext,
    event_bus: &EventBus,
    request: As4ReceivePushRequest,
    dedup_backend: Arc<dyn crate::storage::DedupStorage>,
    gate: &dyn ConversationOrderGate,
    verifier: Arc<dyn As4Verifier + Send + Sync>,
) -> crate::core::Result<As4ReceiveOutcome> {
    let outcome = super::async_completion::receive_push_with_dedup_async_with_shared_verifier(
        session,
        event_bus,
        request,
        dedup_backend,
        verifier,
    )
    .await?;

    ordered::finalize_ordered_outcome_with_gate_trait(session, gate, outcome).await
}

pub(super) async fn receive_push_ordered_fragment_aware_with_verifier(
    session: &SessionContext,
    event_bus: &EventBus,
    request: As4ReceivePushRequest,
    dedup_backend: Arc<dyn crate::storage::DedupStorage>,
    gate: &dyn ConversationOrderGate,
    verifier: Arc<dyn As4Verifier + Send + Sync>,
    fragment_joiner: Arc<std::sync::Mutex<As4FragmentJoiner>>,
) -> crate::core::Result<As4ReceivePushProgress> {
    let progress =
        super::async_bridge::receive_push_with_dedup_async_fragment_aware_with_shared_verifier(
            session,
            event_bus,
            request,
            dedup_backend,
            verifier,
            fragment_joiner,
        )
        .await?;
    ordered::finalize_fragment_aware_ordered_progress(session, gate, progress).await
}
