use super::{
    As2MdnSigningCredentials, As2TrustVerifier, AsxError, ErrorCode, ErrorContext,
    MAX_AS2_MDN_BYTES, ParsedMdn, Result, SessionContext, enforce_payload_limit,
};

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
pub(super) fn mic_values_match(actual: &str, expected: &str) -> bool {
    let (actual_digest, actual_alg) = normalize_received_mic_value(actual);
    let (expected_digest, expected_alg) = normalize_received_mic_value(expected);

    // Strip whitespace before decoding. A `Received-Content-MIC` travels in a
    // MIME header, and RFC 5322 §2.2.3 lets a header fold across lines — so a
    // conformant partner's digest can arrive with a CRLF and a space inside it,
    // and the strict engine refuses that: a delivered message would read as a
    // MIC mismatch.
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

/// [`parse_mdn`], also returning the certificate (DER) whose signature
/// verified, for a signed MDN.
pub(super) fn parse_mdn_with_signer(
    raw: &[u8],
    require_signed_mdn: bool,
    session: &SessionContext,
    verifier: &dyn As2TrustVerifier,
) -> Result<(ParsedMdn, Option<Vec<u8>>, Vec<openssl::x509::X509>)> {
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

    let boundary = parsed_mail.ctype.params.get("boundary");
    let has_signed_content_type = is_signed_mdn(&parsed_mail);

    // RFC 4130 §7.3: if a signed receipt was requested, an unsigned MDN is a
    // non-repudiation downgrade and must not be silently accepted.
    if require_signed_mdn && !has_signed_content_type {
        return Err(AsxError::new(
            ErrorCode::SecurityVerificationFailed,
            "a signed MDN was requested but the received MDN is not multipart/signed",
            super::ErrorContext::for_session("as2_receive_mdn_verify", session),
        ));
    }

    // A present signature that fails is fatal.
    let verified_entity = if has_signed_content_type {
        let mdn_body: Arc<[u8]> = Arc::from(raw);
        let trust = verifier
            .verify_and_decrypt(session, &mdn_body)
            .map_err(|err| {
                AsxError::new(
                    ErrorCode::SecurityVerificationFailed,
                    format!("signed MDN signature verification failed: {err}"),
                    super::ErrorContext::for_session("as2_receive_mdn_verify", session),
                )
            })?;
        trust.protected_entity
    } else {
        None
    };

    // For a verified signed MDN, read every field from the verified entity —
    // never from a second, independent parse of the raw bytes, which may
    // split the MIME differently from the verifier.
    let verified_mail = verified_entity
        .as_ref()
        .map(|entity| {
            parse_mail(entity.entity()).map_err(|_| {
                AsxError::new(
                    ErrorCode::ParseFailed,
                    "failed to parse verified mdn entity",
                    super::ErrorContext::for_session("as2_receive_mdn_parse", session),
                )
            })
        })
        .transpose()?;
    // The boundary rule below reads the outer entity; for a signed MDN the
    // report is the signed content, and the same rule applies to it.
    if let Some(entity_mail) = verified_mail.as_ref()
        && entity_mail.ctype.mimetype.starts_with("multipart/")
        && !entity_mail.ctype.params.contains_key("boundary")
    {
        return Err(AsxError::new(
            ErrorCode::InteropViolation,
            "signed mdn multipart content-type is missing boundary parameter",
            super::ErrorContext::for_session("as2_receive_mdn_boundary", session),
        ));
    }
    let notification_part = match verified_mail.as_ref() {
        Some(entity_mail) => resolve_signed_content_notification_part(entity_mail, session)?,
        None => resolve_mdn_notification_part(&parsed_mail, session)?,
    };
    if notification_part.is_none() && !has_signed_content_type && !is_report_mdn(&parsed_mail) {
        return Err(AsxError::new(
            ErrorCode::InteropViolation,
            "strict AS2 policy requires MDN multipart/report or multipart/signed content-type",
            super::ErrorContext::for_session("as2_receive_mdn_parse", session),
        ));
    }

    let top_level_multipart = parsed_mail.ctype.mimetype.starts_with("multipart/");
    if top_level_multipart && boundary.is_none() {
        return Err(AsxError::new(
            ErrorCode::InteropViolation,
            "mdn multipart content-type is missing boundary parameter",
            super::ErrorContext::for_session("as2_receive_mdn_boundary", session),
        ));
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
        } else if let Some(entity) = verified_entity.as_ref() {
            parse_mdn_fields_from_bytes(entity.entity())?
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

    if !disposition
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
        tracing::debug!(
            target: "asx",
            message_id = original_message_id.as_deref().unwrap_or("unknown"),
            code = AS2_MISSING_FINAL_RECIPIENT_REASON_CODE,
            "interop guardrail denied: MDN missing Final-Recipient"
        );
        return Err(AsxError::new(
            ErrorCode::InteropViolation,
            "AS2 MDN missing final-recipient is not allowed",
            super::ErrorContext::for_session("as2_receive_mdn_parse", session),
        ));
    }

    let signer_der = verified_entity
        .as_ref()
        .and_then(|entity| entity.signer_der().map(<[u8]>::to_vec));
    let signer_path = verified_entity
        .as_ref()
        .map(|entity| entity.signer_path().to_vec())
        .unwrap_or_default();
    Ok((
        ParsedMdn {
            final_recipient,
            original_message_id,
            disposition,
            received_content_mic,
            is_signed: has_signed_content_type,
        },
        signer_der,
        signer_path,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct ParsedDisposition<'a> {
    pub(super) disposition_type: &'a str,
    pub(super) modifier: Option<&'a str>,
}

pub(super) fn parse_disposition(disposition: &str) -> ParsedDisposition<'_> {
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
/// document order.
fn report_notification_part<'a>(
    report: &'a ParsedMail<'a>,
    session: &SessionContext,
) -> Result<Option<&'a ParsedMail<'a>>> {
    if report.subparts.is_empty() {
        return Ok(None);
    }

    if report.subparts.len() > 3 {
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
        Some(part) if report.subparts.get(1).map(std::ptr::from_ref) != Some(part) => {
            Err(AsxError::new(
                ErrorCode::InteropViolation,
                "strict AS2 policy requires multipart/report body part 2 to be message/disposition-notification",
                super::ErrorContext::for_session("as2_receive_mdn_parse", session),
            ))
        }
        Some(part) => Ok(Some(part)),
        None => Err(AsxError::new(
            ErrorCode::InteropViolation,
            "strict AS2 policy requires multipart/report body part 2 to be message/disposition-notification",
            super::ErrorContext::for_session("as2_receive_mdn_parse", session),
        )),
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
    session: &SessionContext,
) -> Result<Option<&'a ParsedMail<'a>>> {
    if is_report_mdn(parsed_mail) {
        return report_notification_part(parsed_mail, session);
    }

    if is_signed_mdn(parsed_mail) {
        let Some(signed) = parsed_mail.subparts.first() else {
            return Ok(None);
        };
        return resolve_signed_content_notification_part(signed, session);
    }

    Ok(None)
}

/// Locate the notification inside the signed content of a `multipart/signed`
/// MDN — either the first MIME subpart or the verifier's protected entity.
fn resolve_signed_content_notification_part<'a>(
    signed: &'a ParsedMail<'a>,
    session: &SessionContext,
) -> Result<Option<&'a ParsedMail<'a>>> {
    if signed
        .ctype
        .mimetype
        .eq_ignore_ascii_case("message/disposition-notification")
    {
        return Ok(Some(signed));
    }

    if is_report_mdn(signed) {
        return report_notification_part(signed, session);
    }

    Err(AsxError::new(
        ErrorCode::InteropViolation,
        format!(
            "AS2 signed MDN content is '{}'; a disposition notification must be \
             message/disposition-notification or multipart/report",
            signed.ctype.mimetype
        ),
        super::ErrorContext::for_session("as2_receive_mdn_parse", session),
    ))
}

#[cfg(test)]
mod mic_match_tests {
    use super::mic_values_match;

    /// RFC 5322 §2.2.3 lets a MIME header fold across lines, so a conformant
    /// partner's `Received-Content-MIC` can arrive with a CRLF and a space
    /// inside the base64; it must still compare equal.
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

    fn session() -> SessionContext {
        SessionContext::new("s", "p", "strict").expect("session")
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
    /// verdict. Falling back to the part at index 1 would let a counterparty put a
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

        let err = resolve_mdn_notification_part(&parsed, &session())
            .expect_err("strict must refuse a report with no machine-readable part");
        assert_eq!(err.code, ErrorCode::InteropViolation);
    }

    /// Signed content that is not an MDN at all is not an MDN.
    #[test]
    fn signed_content_that_is_not_an_mdn_is_refused() {
        let raw = signed_mdn(concat!(
            "Content-Type: text/html\r\n\r\n",
            "<p>Disposition: automatic-action/MDN-sent-automatically; processed</p>"
        ));
        let parsed = mailparse::parse_mail(raw.as_bytes()).expect("parse");

        let err = resolve_mdn_notification_part(&parsed, &session())
            .expect_err("strict must refuse non-MDN signed content");
        assert!(err.message.contains("text/html"), "{}", err.message);
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
        {
            let part = resolve_mdn_notification_part(&parsed, &session())
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
        let part = resolve_mdn_notification_part(&parsed, &session())
            .expect("resolves")
            .expect("part present");
        assert_eq!(part.ctype.mimetype, "message/disposition-notification");
    }

    /// Two machine-readable parts are two verdicts. Refuse rather than let
    /// document order pick.
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
        {
            let err = resolve_mdn_notification_part(&parsed, &session())
                .expect_err("two verdicts are ambiguous");
            assert_eq!(err.code, ErrorCode::InteropViolation);
            assert!(err.message.contains("more than one"), "{}", err.message);
        }
    }
}

use crate::crypto::as2_smime::sign_smime_message;

pub fn generate_signed_mdn(
    session: &SessionContext,
    original_message_id: &str,
    disposition: &str,
    received_content_mic: Option<&str>,
    signing: &As2MdnSigningCredentials,
) -> Result<Vec<u8>> {
    let report = generate_mdn(
        session,
        original_message_id,
        disposition,
        received_content_mic,
    )?;

    sign_smime_message(
        &report,
        signing.signing_key_pem.as_slice(),
        signing.signing_cert_pem.as_slice(),
    )
}

pub fn generate_mdn(
    session: &SessionContext,
    original_message_id: &str,
    disposition: &str,
    received_content_mic: Option<&str>,
) -> Result<Vec<u8>> {
    if original_message_id.trim().is_empty() {
        return Err(AsxError::new(
            ErrorCode::InvalidInput,
            "original_message_id must not be empty",
            ErrorContext::for_session("as2_generate_mdn", session),
        ));
    }
    if disposition.trim().is_empty() {
        return Err(AsxError::new(
            ErrorCode::InvalidInput,
            "disposition must not be empty",
            ErrorContext::for_session("as2_generate_mdn", session),
        ));
    }
    // Every value below is placed in a header or notification line: a CR, LF
    // or NUL would end the line and inject another field.
    for (field, value) in [
        ("original_message_id", original_message_id),
        ("disposition", disposition),
        ("received_content_mic", received_content_mic.unwrap_or("")),
        ("partner_id", session.partner_id()),
    ] {
        if value.bytes().any(|b| matches!(b, b'\r' | b'\n' | 0)) {
            return Err(AsxError::new(
                ErrorCode::InvalidInput,
                format!("{field} must not contain CR, LF or NUL"),
                ErrorContext::for_session("as2_generate_mdn", session),
            ));
        }
    }

    Ok(mdn_report(
        session.partner_id(),
        original_message_id,
        disposition,
        received_content_mic,
        "The message has been received and processed by ASX.",
    ))
}

/// The RFC 3798 `multipart/report` of an MDN. The caller has checked every
/// value for CR, LF and NUL.
pub(crate) fn mdn_report(
    final_recipient: &str,
    original_message_id: &str,
    disposition: &str,
    received_content_mic: Option<&str>,
    text: &str,
) -> Vec<u8> {
    let boundary = mdn_boundary_from_message_id(original_message_id);

    let mut notification_part = format!(
        "Final-Recipient: rfc822; {}\r\nOriginal-Message-ID: {}\r\nDisposition: {}\r\n",
        final_recipient, original_message_id, disposition
    );
    if let Some(mic) = received_content_mic {
        notification_part.push_str(&format!("Received-Content-MIC: {}\r\n", mic.trim()));
    }

    // RFC 3798 MDN wire shape: multipart/report with human-readable + machine-readable parts.
    let mdn = format!(
        "Content-Type: multipart/report; report-type=disposition-notification; boundary=\"{boundary}\"\r\n\
MIME-Version: 1.0\r\n\
\r\n\
--{boundary}\r\n\
Content-Type: text/plain; charset=us-ascii\r\n\
\r\n\
{text}\r\n\
\r\n\
--{boundary}\r\n\
Content-Type: message/disposition-notification\r\n\
\r\n\
{notification_part}\
\r\n\
--{boundary}--\r\n"
    );

    mdn.into_bytes()
}

fn mdn_boundary_from_message_id(original_message_id: &str) -> String {
    // FNV-1a: fast non-cryptographic hash sufficient for MIME boundary uniqueness.
    const OFFSET: u64 = 14_695_981_039_346_656_037;
    const PRIME: u64 = 1_099_511_628_211;
    let mut h: u64 = OFFSET;
    for &b in original_message_id.as_bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(PRIME);
    }
    format!("asx-mdn-{h:016x}")
}
