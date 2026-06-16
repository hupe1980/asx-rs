use super::super::coordination::ConversationOrderGate;
use super::super::types::{As4ReceiveOutcome, As4ReceivePushOutput, As4ReceivePushProgress};
use crate::core::{AsxError, ErrorCode, ErrorContext, Result, SessionContext};

fn ordered_missing_conversation_id_error(session: &SessionContext) -> AsxError {
    AsxError::new(
        ErrorCode::PolicyViolation,
        "ordered AS4 receive requires eb:ConversationId",
        ErrorContext::for_session("as4_receive_push_ordered", session),
    )
}

fn ordered_gate_key_from_output(
    session: &SessionContext,
    output: &As4ReceivePushOutput,
) -> Result<String> {
    output
        .user_message
        .conversation_id
        .clone()
        .ok_or_else(|| ordered_missing_conversation_id_error(session))
}

/// Finalize ordered output using the `ConversationOrderGate` trait interface.
///
/// For duplicates, no gate acquisition is needed — the message was already
/// serialized on its first pass.
pub(super) async fn finalize_ordered_outcome_with_gate_trait(
    session: &SessionContext,
    gate: &dyn ConversationOrderGate,
    outcome: As4ReceiveOutcome,
) -> Result<As4ReceiveOutcome> {
    match outcome {
        As4ReceiveOutcome::FirstSeen(output) => {
            let gate_key = ordered_gate_key_from_output(session, &output)?;
            let guard = gate.acquire_ordered_turn(&gate_key, session).await?;
            gate.record_message_ordering(
                &gate_key,
                &output.user_message.message_id,
                output.user_message.ref_to_message_id.as_deref(),
            )
            .await?;
            guard.release();
            Ok(As4ReceiveOutcome::FirstSeen(output))
        }
        duplicate @ As4ReceiveOutcome::Duplicate { .. } => Ok(duplicate),
    }
}

pub(super) async fn finalize_fragment_aware_ordered_progress(
    session: &SessionContext,
    gate: &dyn ConversationOrderGate,
    progress: As4ReceivePushProgress,
) -> Result<As4ReceivePushProgress> {
    match progress {
        As4ReceivePushProgress::Complete(output) => {
            let gate_key = ordered_gate_key_from_output(session, &output)?;
            let guard = gate.acquire_ordered_turn(&gate_key, session).await?;
            gate.record_message_ordering(
                &gate_key,
                &output.user_message.message_id,
                output.user_message.ref_to_message_id.as_deref(),
            )
            .await?;
            guard.release();
            Ok(As4ReceivePushProgress::Complete(output))
        }
        pending @ As4ReceivePushProgress::PendingFragment { .. } => Ok(pending),
        duplicate @ As4ReceivePushProgress::Duplicate { .. } => Ok(duplicate),
    }
}
