use super::super::types::{As4ReceivePushOutput, As4ReceivePushProgress, As4ReceivePushRequest};
use super::{As4Verifier, EventBus, SessionContext, async_bridge};
use crate::core::{AsxError, ErrorCode, ErrorContext, Result};
use crate::storage::DedupStorage;
use std::sync::Arc;

pub(super) async fn receive_push_with_dedup_async_with_shared_verifier(
    session: &SessionContext,
    event_bus: &EventBus,
    request: As4ReceivePushRequest,
    dedup_backend: Arc<dyn DedupStorage>,
    verifier: Arc<dyn As4Verifier + Send + Sync>,
) -> Result<As4ReceivePushOutput> {
    match async_bridge::receive_push_with_dedup_async_fragment_aware_with_shared_verifier(
        session,
        event_bus,
        request,
        dedup_backend,
        verifier,
        Arc::new(std::sync::Mutex::new(
            super::super::large_message::As4FragmentJoiner::new(),
        )),
    )
    .await?
    {
        As4ReceivePushProgress::Complete(output) => Ok(*output),
        As4ReceivePushProgress::PendingFragment { .. } => Err(AsxError::new(
            ErrorCode::PolicyViolation,
            "AS4 message contains mf:MessageFragment; use receive_push_with_dedup_async_fragment_aware",
            ErrorContext::for_session("as4_receive_push", session),
        )),
    }
}
