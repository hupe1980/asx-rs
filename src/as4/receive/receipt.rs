use super::super::parser::{parse_as4_receipt, precheck_as4_receipt_structure_bytes};
use super::super::services::{
    emit_receive_push_receipt_received, emit_receive_push_receipt_taxonomy_outcome,
    expected_fingerprint_from_session, wssec_revocation_policy_from_session,
};
use super::super::types::As4PushPolicy;
use crate::core::{AsxError, ErrorCode, ErrorContext, Result, SessionContext};
use crate::crypto::wssec::WsSecVerifyOptions;
use crate::observability::EventBus;
use crate::wire::enforce_payload_limit;
use std::sync::Arc;

const MAX_AS4_RECEIPT_BYTES: usize = 256 * 1024;

pub(super) fn parse_and_verify_receipt_if_present(
    session: &SessionContext,
    event_bus: &EventBus,
    receipt_payload: Option<&[u8]>,
    policy: &As4PushPolicy,
    message_id: &str,
) -> Result<Option<super::super::ParsedAs4Receipt>> {
    let Some(raw) = receipt_payload else {
        return Ok(None);
    };
    let message_id = Arc::<str>::from(message_id);

    enforce_payload_limit("as4_receive_receipt", raw.len(), MAX_AS4_RECEIPT_BYTES)?;
    precheck_as4_receipt_structure_bytes(raw, session, "as4_receive_receipt")?;
    let receipt_xml = crate::core::bytes_to_utf8_str(raw, "as4_receive_receipt", session)?;

    let parsed_receipt = parse_as4_receipt(
        session,
        event_bus,
        receipt_xml,
        policy.interop,
        policy.fail_closed_audit_events,
    )?;

    if parsed_receipt.is_signed {
        let expected_fingerprint = expected_fingerprint_from_session(session);
        if expected_fingerprint.is_none() {
            emit_receive_push_receipt_taxonomy_outcome(
                session,
                event_bus,
                &message_id,
                "security_verification_failed",
                "receipt_signer_fingerprint_missing",
                policy.fail_closed_audit_events,
            )?;
            return Err(AsxError::new(
                ErrorCode::PolicyViolation,
                "AS4 signed receipt verification requires cert_handle.fingerprint_sha256",
                ErrorContext::for_session_with_message(
                    "as4_receive_receipt",
                    session,
                    message_id.as_ref(),
                ),
            ));
        }
        let revocation_policy = wssec_revocation_policy_from_session(session)?;
        match crate::crypto::wssec::verify_enveloped_signature(
            receipt_xml,
            WsSecVerifyOptions::new()
                .with_expected_fingerprint(expected_fingerprint)
                .with_revocation(revocation_policy),
        ) {
            Ok(()) => (),
            Err(err) => {
                emit_receive_push_receipt_taxonomy_outcome(
                    session,
                    event_bus,
                    &message_id,
                    "security_verification_failed",
                    "receipt_signature_verification_failed",
                    policy.fail_closed_audit_events,
                )?;
                return Err(normalize_receipt_signature_verification_error(
                    session,
                    message_id.as_ref(),
                    err,
                ));
            }
        }
    } else if policy.require_signed_receipt {
        emit_receive_push_receipt_taxonomy_outcome(
            session,
            event_bus,
            &message_id,
            "security_verification_failed",
            "receipt_signature_required_but_missing",
            policy.fail_closed_audit_events,
        )?;
        return Err(AsxError::new(
            ErrorCode::SecurityVerificationFailed,
            "AS4 receipt signature is required but not present",
            ErrorContext::for_session_with_message(
                "as4_receive_receipt",
                session,
                message_id.as_ref(),
            ),
        ));
    }

    if parsed_receipt.ref_to_message_id != message_id.as_ref() {
        emit_receive_push_receipt_taxonomy_outcome(
            session,
            event_bus,
            &message_id,
            "semantic_interop_failure",
            "receipt_ref_to_message_id_mismatch",
            policy.fail_closed_audit_events,
        )?;
        return Err(AsxError::new(
            ErrorCode::InteropViolation,
            "receipt RefToMessageId does not match AS4 user message id",
            ErrorContext::for_session_with_message(
                "as4_receive_receipt",
                session,
                message_id.as_ref(),
            ),
        ));
    }

    emit_receive_push_receipt_received(session, event_bus, &message_id)?;
    Ok(Some(parsed_receipt))
}

fn normalize_receipt_signature_verification_error(
    session: &SessionContext,
    message_id: &str,
    err: AsxError,
) -> AsxError {
    AsxError::new(
        ErrorCode::SecurityVerificationFailed,
        format!("AS4 receipt signature verification failed: {}", err.message),
        ErrorContext::for_session_with_message("as4_receive_receipt", session, message_id),
    )
}
