use super::super::coordination::{ConversationGuardHandle, ConversationOrderGate};
use super::super::types::As4ReceivePushOutput;
use crate::core::{AsxError, ErrorCode, ErrorContext, Result, SessionContext};

pub(super) fn ordered_missing_conversation_id_error(session: &SessionContext) -> AsxError {
    AsxError::new(
        ErrorCode::PolicyViolation,
        "ordered AS4 receive requires eb:ConversationId",
        ErrorContext::for_session("as4_receive_push", session),
    )
}

/// The conversation key read off the wire disagreed with the verified one.
///
/// The gate key is taken from unauthenticated bytes so the arrival order can be
/// recorded before any work happens. This check is what keeps that safe: a peer
/// whose envelope says one thing to the byte-scanner and another to the parser
/// has its message rejected, so the worst it can do is mis-order or reject its
/// own traffic.
pub(super) fn ordered_conversation_id_mismatch_error(
    session: &SessionContext,
    reserved: &str,
    verified: &str,
) -> AsxError {
    AsxError::new(
        ErrorCode::SecurityVerificationFailed,
        format!(
            "AS4 ordered receive reserved the turn for conversation '{reserved}' but the \
             verified eb:ConversationId is '{verified}'"
        ),
        ErrorContext::for_session("as4_receive_push", session),
    )
}

/// Confirm the verified conversation matches the one the turn was reserved for,
/// and record the message's place in it.
///
/// The caller keeps the guard: releasing it here would end the turn before the
/// application has seen the message, which is the whole thing ordered delivery
/// is for.
pub(super) async fn confirm_and_record_turn(
    session: &SessionContext,
    gate: &dyn ConversationOrderGate,
    reserved_conversation_id: &str,
    output: &As4ReceivePushOutput,
) -> Result<()> {
    let verified = output
        .user_message
        .conversation_id
        .as_deref()
        .ok_or_else(|| ordered_missing_conversation_id_error(session))?;

    if verified != reserved_conversation_id {
        return Err(ordered_conversation_id_mismatch_error(
            session,
            reserved_conversation_id,
            verified,
        ));
    }

    gate.record_message_ordering(
        verified,
        &output.user_message.message_id,
        output.user_message.ref_to_message_id.as_deref(),
    )
    .await
}

/// A received message together with the conversation turn that orders it.
///
/// The turn is held for as long as this value lives. Hand the message to the
/// application **before** dropping it: a turn released at the end of the
/// receive call orders nothing, because the application delivers after that
/// (D54).
///
/// ```rust,no_run
/// # async fn example(
/// #     ordered: asx_rs::as4::As4Ordered<asx_rs::as4::As4ReceiveOutcome>,
/// # ) {
/// // The turn is held here …
/// if let asx_rs::as4::As4ReceiveOutcome::FirstSeen { output, .. } = ordered.get() {
///     deliver_to_application(output).await;
/// }
/// // … and released here, when `ordered` goes out of scope.
/// # }
/// # async fn deliver_to_application(_: &asx_rs::as4::As4ReceivePushOutput) {}
/// ```
pub struct As4Ordered<T> {
    value: T,
    turn: Option<Box<dyn ConversationGuardHandle>>,
}

impl<T> As4Ordered<T> {
    pub(super) fn held(value: T, turn: Box<dyn ConversationGuardHandle>) -> Self {
        Self {
            value,
            turn: Some(turn),
        }
    }

    /// A result that took no turn — a duplicate, or a fragment that did not
    /// complete a message.
    pub(super) fn untimed(value: T) -> Self {
        Self { value, turn: None }
    }

    /// Borrow the received message while the turn is still held.
    pub fn get(&self) -> &T {
        &self.value
    }

    /// Whether a conversation turn is being held.
    ///
    /// `false` for a duplicate or an incomplete fragment group: neither is
    /// delivered, so neither occupies a place in the conversation.
    pub fn holds_turn(&self) -> bool {
        self.turn.is_some()
    }

    /// Take the message out, **ending the turn**.
    ///
    /// Only correct once the message has been delivered, or where ordering
    /// does not matter to the caller.
    pub fn into_inner(mut self) -> T {
        if let Some(turn) = self.turn.take() {
            turn.release();
        }
        self.value
    }
}

impl<T: std::fmt::Debug> std::fmt::Debug for As4Ordered<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("As4Ordered")
            .field("value", &self.value)
            .field("holds_turn", &self.turn.is_some())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The gate key comes off the wire before anything is verified. The
    /// mismatch check is what keeps that safe: reserving under one
    /// conversation and being delivered under another would let a peer insert
    /// itself into someone else's ordering.
    #[test]
    fn mismatch_is_a_security_failure_and_names_both_conversations() {
        let session = SessionContext::new("s", "p", "strict").expect("session");
        let err =
            ordered_conversation_id_mismatch_error(&session, "reserved-conv", "verified-conv");
        assert_eq!(err.code, ErrorCode::SecurityVerificationFailed);
        assert!(err.message.contains("reserved-conv"), "{}", err.message);
        assert!(err.message.contains("verified-conv"), "{}", err.message);
    }

    #[test]
    fn a_result_without_a_turn_reports_that_it_holds_none() {
        let ordered = As4Ordered::untimed(7u8);
        assert!(!ordered.holds_turn());
        assert_eq!(*ordered.get(), 7);
        assert_eq!(ordered.into_inner(), 7);
    }
}
