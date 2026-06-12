use super::super::coordination::ConversationOrderGate;
use super::super::large_message::As4FragmentJoiner;
use super::super::types::{As4ReceivePushOutput, As4ReceivePushProgress, As4ReceivePushRequest};
use super::{As4Verifier, EventBus, SessionContext, ordered};
use std::sync::Arc;

pub(super) async fn receive_push_ordered_with_verifier(
    session: &SessionContext,
    event_bus: &EventBus,
    request: As4ReceivePushRequest,
    dedup_backend: Arc<dyn crate::storage::DedupStorage>,
    gate: &dyn ConversationOrderGate,
    verifier: Arc<dyn As4Verifier + Send + Sync>,
) -> crate::core::Result<As4ReceivePushOutput> {
    // Phase 3: full receive pipeline runs before acquiring the ordered turn.
    // For the in-process gate the conversation-id is pre-extracted to
    // reduce hold time; for custom gates the combined acquire path is used.
    let output = super::async_completion::receive_push_with_dedup_async_with_shared_verifier(
        session,
        event_bus,
        request,
        dedup_backend,
        verifier,
    )
    .await?;

    // Phase 4: serialize completion through the ordered gate.
    ordered::finalize_ordered_output_with_gate_trait(session, gate, output).await
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
