use super::super::coordination::ConversationOrderGate;
use super::super::types::{As4ReceivePushOutput, As4ReceivePushProgress};
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
/// Used by pipeline paths that accept `&dyn ConversationOrderGate` (i.e., when
/// a custom distributed gate is supplied).
pub(super) async fn finalize_ordered_output_with_gate_trait(
    session: &SessionContext,
    gate: &dyn ConversationOrderGate,
    output: As4ReceivePushOutput,
) -> Result<As4ReceivePushOutput> {
    let gate_key = ordered_gate_key_from_output(session, &output)?;
    let guard = gate.acquire_ordered_turn(&gate_key, session).await?;
    gate.record_message_ordering(
        &gate_key,
        &output.user_message.message_id,
        output.user_message.ref_to_message_id.as_deref(),
    )
    .await?;
    guard.release();
    Ok(output)
}

pub(super) async fn finalize_fragment_aware_ordered_progress(
    session: &SessionContext,
    gate: &dyn ConversationOrderGate,
    progress: As4ReceivePushProgress,
) -> Result<As4ReceivePushProgress> {
    match progress {
        As4ReceivePushProgress::Complete(output) => {
            let output = finalize_ordered_output_with_gate_trait(session, gate, *output).await?;
            Ok(As4ReceivePushProgress::Complete(Box::new(output)))
        }
        pending @ As4ReceivePushProgress::PendingFragment { .. } => Ok(pending),
    }
}
