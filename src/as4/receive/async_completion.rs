use super::super::types::{As4ReceiveOutcome, As4ReceivePushProgress, As4ReceivePushRequest};
use super::{As4Verifier, EventBus, SessionContext, async_bridge};
use crate::core::{AsxError, ErrorCode, ErrorContext, Result};
use crate::storage::DedupStorage;
use std::sync::Arc;

pub(super) async fn receive_push_with_shared_verifier(
    session: &SessionContext,
    event_bus: &EventBus,
    request: As4ReceivePushRequest,
    dedup_backend: Arc<dyn DedupStorage>,
    verifier: Arc<dyn As4Verifier + Send + Sync>,
    signer_pins: Option<Arc<dyn crate::as4::As4SignerPins>>,
) -> Result<As4ReceiveOutcome> {
    match async_bridge::receive_push_fragment_aware_with_shared_verifier(
        session,
        event_bus,
        request,
        dedup_backend,
        verifier,
        signer_pins,
        Arc::new(std::sync::Mutex::new(
            super::super::large_message::As4FragmentJoiner::new(),
        )),
    )
    .await?
    {
        As4ReceivePushProgress::Complete { output, claim } => {
            Ok(As4ReceiveOutcome::FirstSeen { output, claim })
        }
        As4ReceivePushProgress::Duplicate { message_id } => {
            Ok(As4ReceiveOutcome::Duplicate { message_id })
        }
        As4ReceivePushProgress::InFlight { message_id } => {
            Ok(As4ReceiveOutcome::InFlight { message_id })
        }
        As4ReceivePushProgress::PendingFragment { .. } => Err(AsxError::new(
            ErrorCode::PolicyViolation,
            "AS4 message contains mf:MessageFragment; use receive_push_fragment_aware",
            ErrorContext::for_session("as4_receive_push", session),
        )),
    }
}
