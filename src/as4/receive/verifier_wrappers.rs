use super::super::types::{As4ReceivePushOutput, As4ReceivePushProgress, As4ReceivePushRequest};
use super::{As4Verifier, EventBus, SessionContext, async_completion, sync_core};
use crate::core::{AsxError, ErrorCode, ErrorContext, Result};
use crate::storage::DedupStorage;
use std::sync::Arc;

pub(super) fn receive_push_with_dedup_sync_with_verifier(
    session: &SessionContext,
    event_bus: &EventBus,
    request: As4ReceivePushRequest,
    dedup_backend: &dyn DedupStorage,
    verifier: &(dyn As4Verifier + Send + Sync),
) -> Result<As4ReceivePushOutput> {
    match sync_core::receive_push_with_dedup_sync_fragment_aware_with_verifier(
        session,
        event_bus,
        request,
        dedup_backend,
        verifier,
        None,
    )? {
        As4ReceivePushProgress::Complete(output) => Ok(*output),
        As4ReceivePushProgress::PendingFragment { .. } => Err(AsxError::new(
            ErrorCode::PolicyViolation,
            "AS4 message contains mf:MessageFragment; use receive_push_with_dedup_sync_fragment_aware",
            ErrorContext::for_session("as4_receive_push", session),
        )),
    }
}

pub(super) async fn receive_push_with_dedup_async_with_verifier<V>(
    session: &SessionContext,
    event_bus: &EventBus,
    request: As4ReceivePushRequest,
    dedup_backend: Arc<dyn DedupStorage>,
    verifier: V,
) -> Result<As4ReceivePushOutput>
where
    V: As4Verifier + Send + Sync + 'static,
{
    async_completion::receive_push_with_dedup_async_with_shared_verifier(
        session,
        event_bus,
        request,
        dedup_backend,
        Arc::new(verifier),
    )
    .await
}
