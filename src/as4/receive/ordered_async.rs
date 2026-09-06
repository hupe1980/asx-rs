use super::super::coordination::ConversationOrderGate;
use super::super::large_message::As4FragmentJoiner;
use super::super::types::{As4ReceiveOutcome, As4ReceivePushProgress, As4ReceivePushRequest};
use super::ordered::{self, As4Ordered};
use super::{As4Verifier, EventBus, SessionContext};
use crate::core::Result;
use std::sync::Arc;

/// Reserve the conversation's turn from the raw bytes, before any work.
///
/// The key is read with a bounded byte scan rather than a parse, because the
/// point is to record *arrival* order: anything that waits for parsing,
/// verification or decryption records completion order instead, and a small
/// message that arrived second overtakes a large one that arrived first.
///
/// The value is unauthenticated; [`ordered::confirm_and_record_turn`] compares
/// it against the verified `eb:ConversationId` once the message is parsed.
async fn reserve_turn_for_payload(
    session: &SessionContext,
    gate: &dyn ConversationOrderGate,
    payload: &[u8],
) -> Result<(
    String,
    Box<dyn super::super::coordination::ConversationTurnHandle>,
)> {
    let conversation_id = super::super::parser::extract_conversation_id_for_gate(payload)
        .ok_or_else(|| ordered::ordered_missing_conversation_id_error(session))?;
    let reservation = gate.reserve_ordered_turn(&conversation_id, session).await?;
    Ok((conversation_id, reservation))
}

pub(super) async fn receive_push_ordered_with_verifier(
    session: &SessionContext,
    event_bus: &EventBus,
    request: As4ReceivePushRequest,
    dedup_backend: Arc<dyn crate::storage::DedupStorage>,
    gate: &dyn ConversationOrderGate,
    verifier: Arc<dyn As4Verifier + Send + Sync>,
) -> Result<As4Ordered<As4ReceiveOutcome>> {
    let (conversation_id, reservation) =
        reserve_turn_for_payload(session, gate, &request.payload).await?;

    // Everything expensive happens here, holding only a ticket: messages in
    // different conversations never block each other, and messages in the same
    // conversation still verify and decrypt in parallel.
    //
    // A failure returns early and drops the reservation, which releases the
    // place rather than stalling the conversation behind a message that will
    // never be delivered.
    let outcome = super::async_completion::receive_push_with_dedup_async_with_shared_verifier(
        session,
        event_bus,
        request,
        dedup_backend,
        verifier,
    )
    .await?;

    match outcome {
        As4ReceiveOutcome::FirstSeen(output) => {
            let turn = reservation.wait_for_turn().await?;
            ordered::confirm_and_record_turn(session, gate, &conversation_id, &output).await?;
            Ok(As4Ordered::held(As4ReceiveOutcome::FirstSeen(output), turn))
        }
        // A duplicate is not delivered, so it takes no place in the order and
        // must not make the next arrival wait for one.
        duplicate @ As4ReceiveOutcome::Duplicate { .. } => Ok(As4Ordered::untimed(duplicate)),
    }
}

pub(super) async fn receive_push_ordered_fragment_aware_with_verifier(
    session: &SessionContext,
    event_bus: &EventBus,
    request: As4ReceivePushRequest,
    dedup_backend: Arc<dyn crate::storage::DedupStorage>,
    gate: &dyn ConversationOrderGate,
    verifier: Arc<dyn As4Verifier + Send + Sync>,
    fragment_joiner: Arc<std::sync::Mutex<As4FragmentJoiner>>,
) -> Result<As4Ordered<As4ReceivePushProgress>> {
    let (conversation_id, reservation) =
        reserve_turn_for_payload(session, gate, &request.payload).await?;

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

    match progress {
        As4ReceivePushProgress::Complete(output) => {
            let turn = reservation.wait_for_turn().await?;
            ordered::confirm_and_record_turn(session, gate, &conversation_id, &output).await?;
            Ok(As4Ordered::held(
                As4ReceivePushProgress::Complete(output),
                turn,
            ))
        }
        // Neither a pending fragment nor a duplicate reaches the application,
        // so neither holds the conversation open.
        other => Ok(As4Ordered::untimed(other)),
    }
}
