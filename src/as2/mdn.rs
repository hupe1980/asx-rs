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

    // Strip whitespace before decoding. A `Received-Content-MIC` travels in a
    // MIME header, and RFC 5322 §2.2.3 lets a header fold across lines — so a
    // conformant partner's digest can arrive with a CRLF and a space inside it.
    // Decoding that with the strict engine fails, which used to drop the
    // comparison to raw string equality and report a MIC mismatch: a delivered
    // message declared undelivered. Same defect class as the XML base64 path.
    let unfold = |v: &str| -> String { v.chars().filter(|c| !c.is_ascii_whitespace()).collect() };
    let actual_compact = unfold(actual_digest);
    let expected_compact = unfold(expected_digest);

    // Compare digest bytes (base64-decoded when both sides decode successfully),
    // in constant time.
    let digests_match = match (
        STANDARD.decode(&actual_compact),
        STANDARD.decode(&expected_compact),
    ) {
        (Ok(a), Ok(b)) => crate::core::constant_time_eq(&a, &b),
        _ => crate::core::constant_time_eq(actual_compact.as_bytes(), expected_compact.as_bytes()),
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
    require_signed_mdn: bool,
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

    // RFC 4130 §7.3: if a signed receipt was requested, an unsigned MDN is a
    // non-repudiation downgrade and must not be silently accepted.
    if require_signed_mdn && !has_signed_content_type {
        match policy.interop_mode {
            InteropMode::Strict => {
                return Err(AsxError::new(
                    ErrorCode::SecurityVerificationFailed,
                    "a signed MDN was requested but the received MDN is not multipart/signed",
                    super::ErrorContext::for_session("as2_receive_mdn_verify", session),
                ));
            }
            #[cfg(feature = "interop-relaxed")]
            InteropMode::Relaxed => {
                interop_reasons.push("mdn_signature_required_but_absent");
            }
        }
    }

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

/// The `message/disposition-notification` parts of a `multipart/report`.
///
/// Selected by media type. RFC 3798 §3 puts the machine-readable part second,
/// but the type is what identifies it — picking by position means parsing
/// whatever happens to sit there as the delivery verdict.
fn disposition_notification_parts<'a>(report: &'a ParsedMail<'a>) -> Vec<&'a ParsedMail<'a>> {
    report
        .subparts
        .iter()
        .filter(|part| {
            part.ctype
                .mimetype
                .eq_ignore_ascii_case("message/disposition-notification")
        })
        .collect()
}

/// Resolve the machine-readable part of a `multipart/report` MDN.
///
/// Two reports carrying two disposition notifications are ambiguous about the
/// delivery outcome, so the ambiguity is refused rather than resolved by
/// document order (D5).
fn report_notification_part<'a>(
    report: &'a ParsedMail<'a>,
    policy: &As2ReceivePolicy,
    session: &SessionContext,
) -> Result<Option<&'a ParsedMail<'a>>> {
    if report.subparts.is_empty() {
        return Ok(None);
    }

    let strict = policy.interop_mode == InteropMode::Strict;

    if strict && report.subparts.len() > 3 {
        return Err(AsxError::new(
            ErrorCode::InteropViolation,
            "strict AS2 policy requires multipart/report to contain only the human-readable part, machine-readable part, and optional returned content",
            super::ErrorContext::for_session("as2_receive_mdn_parse", session),
        ));
    }

    let candidates = disposition_notification_parts(report);
    if candidates.len() > 1 {
        return Err(AsxError::new(
            ErrorCode::InteropViolation,
            "AS2 MDN multipart/report carries more than one message/disposition-notification \
             part; refusing to choose one — the delivery outcome would be decided by document \
             order",
            super::ErrorContext::for_session("as2_receive_mdn_parse", session),
        ));
    }

    match candidates.first().copied() {
        // RFC 3798 §3 places the machine-readable part second.
        Some(part) if strict && report.subparts.get(1).map(std::ptr::from_ref) != Some(part) => {
            Err(AsxError::new(
                ErrorCode::InteropViolation,
                "strict AS2 policy requires multipart/report body part 2 to be message/disposition-notification",
                super::ErrorContext::for_session("as2_receive_mdn_parse", session),
            ))
        }
        Some(part) => Ok(Some(part)),
        None if strict => Err(AsxError::new(
            ErrorCode::InteropViolation,
            "strict AS2 policy requires multipart/report body part 2 to be message/disposition-notification",
            super::ErrorContext::for_session("as2_receive_mdn_parse", session),
        )),
        // Relaxed widens the *absent* case only: no machine-readable part means
        // no verdict, never a verdict read out of another part (D12).
        None => Ok(None),
    }
}

/// Locate the part carrying the MDN's machine-readable fields.
///
/// A signed MDN gets the same treatment as an unsigned one. The signed content
/// must itself be a disposition notification or a report; anything else is not
/// an MDN, and reading a `Disposition:` line out of it would let a counterparty
/// choose the delivery outcome by putting the header in a human-readable part.
fn resolve_mdn_notification_part<'a>(
    parsed_mail: &'a ParsedMail<'a>,
    policy: &As2ReceivePolicy,
    session: &SessionContext,
) -> Result<Option<&'a ParsedMail<'a>>> {
    if is_report_mdn(parsed_mail) {
        return report_notification_part(parsed_mail, policy, session);
    }

    if is_signed_mdn(parsed_mail) {
        let Some(signed) = parsed_mail.subparts.first() else {
            return Ok(None);
        };

        if signed
            .ctype
            .mimetype
            .eq_ignore_ascii_case("message/disposition-notification")
        {
            return Ok(Some(signed));
        }

        if is_report_mdn(signed) {
            return report_notification_part(signed, policy, session);
        }

        if policy.interop_mode == InteropMode::Strict {
            return Err(AsxError::new(
                ErrorCode::InteropViolation,
                format!(
                    "AS2 signed MDN content is '{}'; a disposition notification must be \
                     message/disposition-notification or multipart/report",
                    signed.ctype.mimetype
                ),
                super::ErrorContext::for_session("as2_receive_mdn_parse", session),
            ));
        }
        return Ok(None);
    }

    Ok(None)
}

#[cfg(test)]
mod mic_match_tests {
    use super::mic_values_match;

    /// RFC 5322 §2.2.3 lets a MIME header fold across lines, so a conformant
    /// partner's `Received-Content-MIC` can arrive with a CRLF and a space
    /// inside the base64. Strict decoding failed on that and the comparison
    /// fell back to raw string equality — reporting a MIC mismatch, i.e. a
    /// delivered message declared undelivered.
    #[test]
    fn folded_received_content_mic_header_still_matches() {
        let digest = "hvfkN/qlp/zhXR3cuerq6jd2Z7g+/Z9nDkNbLmXcU0k=";
        let unfolded = format!("{digest}, sha-256");
        let folded = "hvfkN/qlp/zhXR3cuerq\r\n 6jd2Z7g+/Z9nDkNbLmXcU0k=, sha-256";

        assert!(
            mic_values_match(folded, &unfolded),
            "a folded header carries the same digest"
        );
    }

    #[test]
    fn a_different_digest_still_fails() {
        let a = "hvfkN/qlp/zhXR3cuerq6jd2Z7g+/Z9nDkNbLmXcU0k=, sha-256";
        let b = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=, sha-256";
        assert!(!mic_values_match(a, b));
    }

    /// A weaker algorithm with the same digest field must not pass.
    #[test]
    fn algorithm_mismatch_fails() {
        let digest = "hvfkN/qlp/zhXR3cuerq6jd2Z7g+/Z9nDkNbLmXcU0k=";
        assert!(!mic_values_match(
            &format!("{digest}, sha-256"),
            &format!("{digest}, md5")
        ));
    }
}

#[cfg(test)]
mod notification_part_tests {
    use super::*;

    fn policy(mode: InteropMode) -> As2ReceivePolicy {
        As2ReceivePolicy {
            interop_mode: mode,
            ..As2ReceivePolicy::default()
        }
    }

    fn session() -> SessionContext {
        SessionContext::new("s", "p", "strict").expect("session")
    }

    /// The interop modes this build compiles. `Relaxed` exists only under the
    /// `interop-relaxed` feature.
    fn modes() -> Vec<InteropMode> {
        #[cfg(feature = "interop-relaxed")]
        {
            vec![InteropMode::Strict, InteropMode::Relaxed]
        }
        #[cfg(not(feature = "interop-relaxed"))]
        {
            vec![InteropMode::Strict]
        }
    }

    fn signed_mdn(inner: &str) -> String {
        format!(
            "Content-Type: multipart/signed; protocol=\"application/pkcs7-signature\"; \
             micalg=sha-256; boundary=SIG\r\n\r\n\
             --SIG\r\n{inner}\r\n\
             --SIG\r\n\
             Content-Type: application/pkcs7-signature\r\n\r\n\
             signature-bytes\r\n\
             --SIG--\r\n"
        )
    }

    /// A report with no `message/disposition-notification` part yields no
    /// verdict. Falling back to the part at index 1 lets a counterparty put a
    /// forged `Disposition:` line in a human-readable part and have it read as
    /// the delivery outcome.
    #[test]
    fn signed_report_without_a_machine_readable_part_yields_no_verdict() {
        let raw = signed_mdn(concat!(
            "Content-Type: multipart/report; report-type=disposition-notification; ",
            "boundary=REP\r\n\r\n",
            "--REP\r\n",
            "Content-Type: text/plain\r\n\r\n",
            "The message was rejected.\r\n",
            "--REP\r\n",
            "Content-Type: text/plain\r\n\r\n",
            "Disposition: automatic-action/MDN-sent-automatically; processed\r\n",
            "--REP--"
        ));
        let parsed = mailparse::parse_mail(raw.as_bytes()).expect("parse");

        let err = resolve_mdn_notification_part(&parsed, &policy(InteropMode::Strict), &session())
            .expect_err("strict must refuse a report with no machine-readable part");
        assert_eq!(err.code, ErrorCode::InteropViolation);

        // Relaxed widens the absent case only — no verdict, not a wrong one.
        #[cfg(feature = "interop-relaxed")]
        {
            let relaxed =
                resolve_mdn_notification_part(&parsed, &policy(InteropMode::Relaxed), &session())
                    .expect("relaxed tolerates the absence");
            assert!(
                relaxed.is_none(),
                "a forged Disposition in a text/plain part must never become the verdict"
            );
        }
    }

    /// Signed content that is not an MDN at all is not an MDN.
    #[test]
    fn signed_content_that_is_not_an_mdn_is_refused() {
        let raw = signed_mdn(concat!(
            "Content-Type: text/html\r\n\r\n",
            "<p>Disposition: automatic-action/MDN-sent-automatically; processed</p>"
        ));
        let parsed = mailparse::parse_mail(raw.as_bytes()).expect("parse");

        let err = resolve_mdn_notification_part(&parsed, &policy(InteropMode::Strict), &session())
            .expect_err("strict must refuse non-MDN signed content");
        assert!(err.message.contains("text/html"), "{}", err.message);
        #[cfg(feature = "interop-relaxed")]
        assert!(
            resolve_mdn_notification_part(&parsed, &policy(InteropMode::Relaxed), &session())
                .expect("relaxed does not error")
                .is_none()
        );
    }

    /// The well-formed shape still resolves, signed and unsigned alike.
    #[test]
    fn a_conformant_signed_report_resolves_its_machine_readable_part() {
        let raw = signed_mdn(concat!(
            "Content-Type: multipart/report; report-type=disposition-notification; ",
            "boundary=REP\r\n\r\n",
            "--REP\r\n",
            "Content-Type: text/plain\r\n\r\n",
            "The message was processed.\r\n",
            "--REP\r\n",
            "Content-Type: message/disposition-notification\r\n\r\n",
            "Disposition: automatic-action/MDN-sent-automatically; processed\r\n",
            "--REP--"
        ));
        let parsed = mailparse::parse_mail(raw.as_bytes()).expect("parse");
        for mode in modes() {
            let part = resolve_mdn_notification_part(&parsed, &policy(mode), &session())
                .expect("conformant MDN resolves")
                .expect("machine-readable part present");
            assert_eq!(part.ctype.mimetype, "message/disposition-notification");
        }
    }

    /// Signed content that is *directly* a disposition notification is the
    /// other conformant shape.
    #[test]
    fn signed_bare_disposition_notification_resolves() {
        let raw = signed_mdn(concat!(
            "Content-Type: message/disposition-notification\r\n\r\n",
            "Disposition: automatic-action/MDN-sent-automatically; processed"
        ));
        let parsed = mailparse::parse_mail(raw.as_bytes()).expect("parse");
        let part = resolve_mdn_notification_part(&parsed, &policy(InteropMode::Strict), &session())
            .expect("resolves")
            .expect("part present");
        assert_eq!(part.ctype.mimetype, "message/disposition-notification");
    }

    /// Two machine-readable parts are two verdicts. Refuse rather than let
    /// document order pick (D5).
    #[test]
    fn two_disposition_notification_parts_are_refused() {
        let raw = concat!(
            "Content-Type: multipart/report; report-type=disposition-notification; ",
            "boundary=REP\r\n\r\n",
            "--REP\r\n",
            "Content-Type: message/disposition-notification\r\n\r\n",
            "Disposition: automatic-action/MDN-sent-automatically; processed\r\n",
            "--REP\r\n",
            "Content-Type: message/disposition-notification\r\n\r\n",
            "Disposition: automatic-action/MDN-sent-automatically; failed\r\n",
            "--REP--\r\n"
        );
        let parsed = mailparse::parse_mail(raw.as_bytes()).expect("parse");
        for mode in modes() {
            let err = resolve_mdn_notification_part(&parsed, &policy(mode), &session())
                .expect_err("two verdicts are ambiguous in every mode");
            assert_eq!(err.code, ErrorCode::InteropViolation);
            assert!(err.message.contains("more than one"), "{}", err.message);
        }
    }
}
