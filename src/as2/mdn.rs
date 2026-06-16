use super::{
    As2MdnMode, As2ReceivePolicy, As2TrustVerifier, AsxError, ErrorCode, EventBus, InteropDecision,
    InteropExceptionCode, InteropMode, MAX_AS2_MDN_BYTES, ParsedMdn, ReceivedBodyHandle, Result,
    SessionContext, emit_audit_event, enforce_exception, enforce_payload_limit,
    evaluate_exception_guardrail,
};
use crate::interop::InteropGuardrailOutcome;

const AS2_MISSING_FINAL_RECIPIENT_REASON_CODE: &str = "as2_missing_final_recipient";
use base64::{Engine as _, engine::general_purpose::STANDARD};
use mailparse::{ParsedMail, parse_mail};
use std::collections::HashSet;
use std::sync::Arc;

/// Parsed AS2 MDN fields: (final_recipient, original_message_id, disposition, received_content_mic).
type MdnFields = (
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
);

fn parse_mdn_fields_from_bytes(raw: &[u8]) -> Result<MdnFields> {
    let text = std::str::from_utf8(raw).map_err(|_| {
        AsxError::new(
            ErrorCode::ParseFailed,
            "MDN notification body contains invalid UTF-8; cannot parse disposition fields",
            super::ErrorContext::new("as2_receive_mdn_parse"),
        )
    })?;
    parse_mdn_fields(text)
}

/// Extract the `original_message_id` from raw MDN bytes (walks the MIME parts
/// looking for `message/disposition-notification`).
///
/// Used by [`crate::as2::correlate_async_mdn`].
pub(super) fn extract_original_message_id(raw: &[u8]) -> Option<String> {
    let parsed_mail = mailparse::parse_mail(raw).ok()?;
    // Find the disposition-notification part and decode its body.
    let body = find_disposition_notification_body_bytes(&parsed_mail)?;
    let (_, original_message_id, _, _) = parse_mdn_fields_from_bytes(&body).ok()?;
    original_message_id
}

/// Walk a parsed MIME tree looking for a `message/disposition-notification` part.
/// Returns the decoded body bytes of the first matching part.
fn find_disposition_notification_body_bytes(mail: &mailparse::ParsedMail<'_>) -> Option<Vec<u8>> {
    let ct = mail.ctype.mimetype.to_ascii_lowercase();
    if ct == "message/disposition-notification" {
        return mail.get_body_raw().ok();
    }
    for sub in &mail.subparts {
        if let Some(b) = find_disposition_notification_body_bytes(sub) {
            return Some(b);
        }
    }
    None
}

fn normalize_received_mic_value(value: &str) -> (&str, Option<&str>) {
    // RFC 4130 §7.4.3: Received-Content-MIC = base64-value *WSP "," *WSP micalg
    let mut parts = value.splitn(2, ',');
    let digest = parts.next().unwrap_or(value).trim().trim_matches('"');
    let alg = parts.next().map(|s| s.trim().trim_matches('"'));
    (digest, alg)
}

/// Compare two `Received-Content-MIC` values for equality.
///
/// Both the base64-encoded digest bytes and — when present in **both** sides —
/// the algorithm name are validated.  This prevents a MITM from substituting
/// a MIC computed with a weaker algorithm while leaving the digest field
/// unchanged (RFC 4130 §7.4.3).
fn mic_values_match(actual: &str, expected: &str) -> bool {
    let (actual_digest, actual_alg) = normalize_received_mic_value(actual);
    let (expected_digest, expected_alg) = normalize_received_mic_value(expected);

    // Compare digest bytes (base64-decoded when both sides decode successfully).
    let digests_match = match (
        STANDARD.decode(actual_digest),
        STANDARD.decode(expected_digest),
    ) {
        (Ok(a), Ok(b)) => a == b,
        _ => actual_digest == expected_digest,
    };

    if !digests_match {
        return false;
    }

    // Cross-validate algorithm name when both sides supply one.
    match (actual_alg, expected_alg) {
        (Some(a), Some(e)) => a.eq_ignore_ascii_case(e),
        _ => true,
    }
}

pub(super) fn parse_mdn(
    raw: &[u8],
    policy: As2ReceivePolicy,
    session: &SessionContext,
    event_bus: &EventBus,
    verifier: &dyn As2TrustVerifier,
) -> Result<(ParsedMdn, Vec<&'static str>)> {
    enforce_payload_limit("as2_receive_mdn_parse", raw.len(), MAX_AS2_MDN_BYTES)?;
    if raw.is_empty() {
        return Err(AsxError::new(
            ErrorCode::ParseFailed,
            "mdn payload is empty",
            super::ErrorContext::new("as2_receive_mdn_parse")
                .with_session_and_partner(session.session_id(), session.partner_id()),
        ));
    }

    let parsed_mail = parse_mail(raw).map_err(|_| {
        AsxError::new(
            ErrorCode::ParseFailed,
            "failed to parse mdn MIME envelope",
            super::ErrorContext::new("as2_receive_mdn_parse")
                .with_session_and_partner(session.session_id(), session.partner_id()),
        )
    })?;

    let mut interop_reasons: Vec<&'static str> = Vec::new();

    let boundary = parsed_mail.ctype.params.get("boundary");
    let has_signed_content_type = is_signed_mdn(&parsed_mail);

    if has_signed_content_type {
        let mdn_body = ReceivedBodyHandle::InMemory(Arc::from(raw));
        let verify_result = verifier.verify_and_decrypt(session, &mdn_body);
        match policy.interop_mode {
            InteropMode::Strict => {
                verify_result.map_err(|err| {
                    AsxError::new(
                        ErrorCode::SecurityVerificationFailed,
                        format!("signed MDN signature verification failed: {err}"),
                        super::ErrorContext::for_session("as2_receive_mdn_verify", session),
                    )
                })?;
            }
            #[cfg(feature = "interop-relaxed")]
            InteropMode::Relaxed => {
                if verify_result.is_err() {
                    interop_reasons.push("mdn_signature_verification_failed");
                }
            }
        }
    }
    let notification_part = resolve_mdn_notification_part(&parsed_mail, &policy, session)?;
    if policy.interop_mode == InteropMode::Strict
        && notification_part.is_none()
        && !has_signed_content_type
        && !is_report_mdn(&parsed_mail)
    {
        return Err(AsxError::new(
            ErrorCode::InteropViolation,
            "strict AS2 policy requires MDN multipart/report or multipart/signed content-type",
            super::ErrorContext::for_session("as2_receive_mdn_parse", session),
        ));
    }

    let top_level_multipart = parsed_mail.ctype.mimetype.starts_with("multipart/");
    if top_level_multipart && boundary.is_none() {
        let outcome = evaluate_exception_guardrail(
            session,
            policy.interop_mode,
            &policy.interop_exceptions,
            InteropExceptionCode::As2AllowMissingMdnBoundary,
        );
        emit_audit_event(
            event_bus,
            session,
            super::AsxEvent::InteropGuardrailEvaluated {
                message_id: Arc::from("unknown"),
                code: InteropExceptionCode::As2AllowMissingMdnBoundary.reason_code(),
                outcome: outcome.as_str(),
                detail: "missing_mdn_boundary",
            },
            policy.fail_closed_audit_events,
            "as2_receive_mdn_parse",
        )?;
        match enforce_exception(
            session,
            policy.interop_mode,
            &policy.interop_exceptions,
            InteropExceptionCode::As2AllowMissingMdnBoundary,
            "as2_receive_mdn_boundary",
            "mdn multipart content-type is missing boundary parameter",
        )? {
            InteropDecision::RelaxedException { reason_code } => interop_reasons.push(reason_code),
        }
    }

    let (final_recipient, original_message_id, disposition, received_content_mic) =
        if let Some(part) = notification_part {
            let body = part.get_body_raw().map_err(|_| {
                AsxError::new(
                    ErrorCode::ParseFailed,
                    "failed to decode mdn notification body",
                    super::ErrorContext::for_session("as2_receive_mdn_parse", session),
                )
            })?;
            parse_mdn_fields_from_bytes(&body)?
        } else {
            parse_mdn_fields_from_bytes(raw)?
        };

    let Some(disposition) = disposition else {
        return Err(AsxError::new(
            ErrorCode::ParseFailed,
            "mdn is missing disposition field",
            super::ErrorContext::for_session("as2_receive_mdn_parse", session),
        ));
    };

    if policy.interop_mode == InteropMode::Strict
        && !disposition
            .to_ascii_lowercase()
            .contains("automatic-action/")
    {
        return Err(AsxError::new(
            ErrorCode::InteropViolation,
            "strict AS2 policy requires disposition with automatic-action",
            super::ErrorContext::for_session("as2_receive_mdn_parse", session),
        ));
    }

    if final_recipient.is_none() {
        emit_audit_event(
            event_bus,
            session,
            super::AsxEvent::InteropGuardrailEvaluated {
                message_id: original_message_id
                    .as_deref()
                    .unwrap_or("unknown")
                    .to_string()
                    .into(),
                code: AS2_MISSING_FINAL_RECIPIENT_REASON_CODE,
                outcome: InteropGuardrailOutcome::Denied.as_str(),
                detail: "missing_final_recipient",
            },
            policy.fail_closed_audit_events,
            "as2_receive_mdn_parse",
        )?;
        return Err(AsxError::new(
            ErrorCode::InteropViolation,
            "AS2 MDN missing final-recipient is not allowed",
            super::ErrorContext::for_session("as2_receive_mdn_parse", session),
        ));
    }

    Ok((
        ParsedMdn {
            final_recipient,
            original_message_id,
            disposition,
            received_content_mic,
            is_signed: has_signed_content_type,
        },
        interop_reasons,
    ))
}

pub(super) fn extract_content_type_header(mime_bytes: &[u8]) -> Option<String> {
    let header_section = std::str::from_utf8(mime_bytes).ok()?;
    let headers = header_section
        .split("\r\n\r\n")
        .next()
        .or_else(|| header_section.split("\n\n").next())?;

    let mut content_type = String::new();
    let mut in_ct = false;
    for line in headers.lines() {
        if line.to_ascii_lowercase().starts_with("content-type:") {
            content_type = line["content-type:".len()..].trim().to_string();
            in_ct = true;
        } else if in_ct && (line.starts_with('\t') || line.starts_with(' ')) {
            content_type.push(' ');
            content_type.push_str(line.trim());
        } else if in_ct {
            break;
        }
    }
    if content_type.is_empty() {
        None
    } else {
        Some(content_type)
    }
}

pub(super) fn classify_mdn_outcome(
    mdn: &ParsedMdn,
    mdn_mode: As2MdnMode,
    expected_mic: Option<&str>,
) -> super::DeliveryOutcome {
    if mdn_mode == As2MdnMode::None {
        return super::DeliveryOutcome::SuccessConfirmed;
    }

    let parsed = parse_disposition(&mdn.disposition);

    if parsed.disposition_type.eq_ignore_ascii_case("failed") {
        return super::DeliveryOutcome::FailureConfirmed;
    }

    if parsed.disposition_type.eq_ignore_ascii_case("processed")
        && parsed
            .modifier
            .is_some_and(|modifier| modifier.eq_ignore_ascii_case("error"))
    {
        return super::DeliveryOutcome::FailureConfirmed;
    }

    if parsed.disposition_type.eq_ignore_ascii_case("processed")
        && parsed
            .modifier
            .is_some_and(|modifier| modifier.eq_ignore_ascii_case("warning"))
    {
        return super::DeliveryOutcome::AcceptedPendingVerification;
    }

    if parsed.disposition_type.eq_ignore_ascii_case("processed") {
        match expected_mic {
            Some(expected) => match &mdn.received_content_mic {
                Some(actual) => {
                    if mic_values_match(actual, expected) {
                        super::DeliveryOutcome::SuccessConfirmed
                    } else {
                        super::DeliveryOutcome::FailureConfirmed
                    }
                }
                None => {
                    if mdn_mode == As2MdnMode::Asynchronous {
                        super::DeliveryOutcome::AcceptedPendingVerification
                    } else {
                        super::DeliveryOutcome::Indeterminate
                    }
                }
            },
            None => super::DeliveryOutcome::SuccessConfirmed,
        }
    } else {
        super::DeliveryOutcome::Indeterminate
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ParsedDisposition<'a> {
    disposition_type: &'a str,
    modifier: Option<&'a str>,
}

fn parse_disposition(disposition: &str) -> ParsedDisposition<'_> {
    let action_part = disposition
        .split_once(';')
        .map(|(_, action)| action.trim())
        .unwrap_or("");

    if action_part.is_empty() {
        return ParsedDisposition {
            disposition_type: "",
            modifier: None,
        };
    }

    let mut parts = action_part.split('/');
    let disposition_type = parts.next().unwrap_or("").trim();
    let modifier = parts
        .next()
        .and_then(|m| m.split(',').next())
        .map(|m| m.trim())
        .filter(|m| !m.is_empty());

    ParsedDisposition {
        disposition_type,
        modifier,
    }
}

fn parse_mdn_fields(text: &str) -> Result<MdnFields> {
    let mut final_recipient = None;
    let mut original_message_id = None;
    let mut disposition = None;
    let mut received_content_mic = None;
    let mut current_key: Option<String> = None;
    let mut current_value = String::new();
    let mut seen_keys: HashSet<String> = HashSet::new();

    let commit_field = |key: Option<String>,
                        value: &mut String,
                        final_recipient: &mut Option<String>,
                        original_message_id: &mut Option<String>,
                        disposition: &mut Option<String>,
                        received_content_mic: &mut Option<String>|
     -> Result<()> {
        let Some(key) = key else {
            value.clear();
            return Ok(());
        };

        let value = value.trim().to_string();
        match key.as_str() {
            "final-recipient" if final_recipient.is_none() => {
                *final_recipient = Some(value);
            }
            "original-message-id" if original_message_id.is_none() => {
                *original_message_id = Some(value);
            }
            "disposition" if disposition.is_none() => *disposition = Some(value),
            "received-content-mic" if received_content_mic.is_none() => {
                *received_content_mic = Some(value);
            }
            _ => {}
        }

        Ok(())
    };

    for raw_line in text.lines() {
        let line = raw_line.trim_end_matches('\r');
        if line.is_empty() {
            continue;
        }

        if line.starts_with(' ') || line.starts_with('\t') {
            if !current_value.is_empty() {
                current_value.push(' ');
            }
            current_value.push_str(line.trim());
            continue;
        }

        commit_field(
            current_key.take(),
            &mut current_value,
            &mut final_recipient,
            &mut original_message_id,
            &mut disposition,
            &mut received_content_mic,
        )?;

        let Some((key, value)) = line.split_once(':') else {
            current_key = None;
            current_value.clear();
            continue;
        };

        let key = key.trim();
        let normalized_key = key.to_ascii_lowercase();
        if !seen_keys.insert(normalized_key.clone()) {
            return Err(AsxError::new(
                ErrorCode::InteropViolation,
                format!("mdn contains duplicate {key} field"),
                super::ErrorContext::new("as2_receive_mdn_parse"),
            ));
        }

        current_key = Some(normalized_key);
        current_value.clear();
        current_value.push_str(value.trim());
    }

    commit_field(
        current_key.take(),
        &mut current_value,
        &mut final_recipient,
        &mut original_message_id,
        &mut disposition,
        &mut received_content_mic,
    )?;

    Ok((
        final_recipient,
        original_message_id,
        disposition,
        received_content_mic,
    ))
}

fn is_report_mdn(parsed_mail: &ParsedMail<'_>) -> bool {
    parsed_mail
        .ctype
        .mimetype
        .eq_ignore_ascii_case("multipart/report")
        && parsed_mail
            .ctype
            .params
            .get("report-type")
            .is_some_and(|report_type| report_type.eq_ignore_ascii_case("disposition-notification"))
}

fn is_signed_mdn(parsed_mail: &ParsedMail<'_>) -> bool {
    parsed_mail
        .ctype
        .mimetype
        .eq_ignore_ascii_case("multipart/signed")
}

fn resolve_mdn_notification_part<'a>(
    parsed_mail: &'a ParsedMail<'a>,
    policy: &As2ReceivePolicy,
    session: &SessionContext,
) -> Result<Option<&'a ParsedMail<'a>>> {
    if is_report_mdn(parsed_mail) {
        if parsed_mail.subparts.is_empty() {
            return Ok(None);
        }

        if policy.interop_mode == InteropMode::Strict && parsed_mail.subparts.len() > 3 {
            return Err(AsxError::new(
                ErrorCode::InteropViolation,
                "strict AS2 policy requires multipart/report to contain only the human-readable part, machine-readable part, and optional returned content",
                super::ErrorContext::for_session("as2_receive_mdn_parse", session),
            ));
        }

        if policy.interop_mode == InteropMode::Strict && parsed_mail.subparts.len() < 2 {
            return Err(AsxError::new(
                ErrorCode::InteropViolation,
                "strict AS2 policy requires multipart/report body part 2 to be message/disposition-notification",
                super::ErrorContext::for_session("as2_receive_mdn_parse", session),
            ));
        }

        let notification_part = parsed_mail.subparts.get(1).filter(|part| {
            part.ctype
                .mimetype
                .eq_ignore_ascii_case("message/disposition-notification")
        });

        if notification_part.is_none() && policy.interop_mode == InteropMode::Strict {
            return Err(AsxError::new(
                ErrorCode::InteropViolation,
                "strict AS2 policy requires multipart/report body part 2 to be message/disposition-notification",
                super::ErrorContext::for_session("as2_receive_mdn_parse", session),
            ));
        }

        return Ok(notification_part.or_else(|| {
            parsed_mail.subparts.iter().find(|part| {
                part.ctype
                    .mimetype
                    .eq_ignore_ascii_case("message/disposition-notification")
            })
        }));
    }

    if is_signed_mdn(parsed_mail) {
        let first = parsed_mail.subparts.first();
        if let Some(first) = first {
            if first
                .ctype
                .mimetype
                .eq_ignore_ascii_case("message/disposition-notification")
            {
                return Ok(Some(first));
            }

            if first
                .ctype
                .mimetype
                .eq_ignore_ascii_case("multipart/report")
            {
                return Ok(first
                    .subparts
                    .iter()
                    .find(|part| {
                        part.ctype
                            .mimetype
                            .eq_ignore_ascii_case("message/disposition-notification")
                    })
                    .or_else(|| first.subparts.get(1)));
            }

            return Ok(Some(first));
        }
    }

    Ok(None)
}
