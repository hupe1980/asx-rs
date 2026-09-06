use roxmltree::Document;

use super::super::services::{
    expected_fingerprint_from_session, wssec_revocation_policy_from_session,
};
use super::super::types::As4PushPolicy;
use crate::core::{AsxError, ErrorCode, ErrorContext, Result, SessionContext};
use crate::crypto::wssec::WsSecVerifyOptions;

/// Sealing module — prevents external crates from implementing
/// As4Verifier without going through the testing escape hatch.
#[cfg(not(feature = "testing"))]
pub(crate) mod private {
    pub trait Sealed {}
}

/// Under the `testing` feature, the sealing module is made public so that
/// downstream crates can implement [`As4Verifier`] for their own custom verifier
/// types (e.g., a recording verifier that also captures the parsed envelope).
/// This is intentionally restricted to `testing` builds so the sealed trait
/// cannot be bypassed in production code.
///
/// Re-exported from `asx_rs::as4` as [`as4::verifier_seal`](crate::as4::verifier_seal).
#[cfg(feature = "testing")]
pub mod private {
    pub trait Sealed {}
}

/// Security-verification hook for the AS4 push receive pipeline.
///
/// This trait is sealed — external crates cannot implement it unless the
/// testing feature is enabled. This mirrors the sealing approach used on
/// AS2 trust-verifier surfaces and prevents silent trust bypasses on AS4.
pub trait As4Verifier: private::Sealed {
    fn verify_security(
        &self,
        session: &SessionContext,
        policy: &As4PushPolicy,
        soap_xml: &str,
        soap_doc: &Document<'_>,
        message_id: &str,
        // Every payload attachment as `(content_id, bytes)`, for `cid:`
        // reference resolution. Empty when the message has no attachments.
        external_references: &[(&str, &[u8])],
    ) -> Result<()>;
}

#[derive(Debug, Default, Clone, Copy)]
pub struct As4WsSecVerifier;

impl private::Sealed for As4WsSecVerifier {}

impl As4Verifier for As4WsSecVerifier {
    fn verify_security(
        &self,
        session: &SessionContext,
        policy: &As4PushPolicy,
        soap_xml: &str,
        soap_doc: &Document<'_>,
        message_id: &str,
        external_references: &[(&str, &[u8])],
    ) -> Result<()> {
        let expected_fingerprint = expected_fingerprint_from_session(session);
        let revocation_policy = wssec_revocation_policy_from_session(session)?;
        let opts = WsSecVerifyOptions::new()
            .with_expected_fingerprint(expected_fingerprint)
            .with_revocation(revocation_policy);

        let coverage = crate::crypto::wssec::verify::verify_enveloped_signature_optional_with_doc(
            soap_doc,
            soap_xml,
            opts.with_external_references(external_references),
        )?;

        let signature_present = coverage.is_some();

        if policy.require_signed_push && !signature_present {
            return Err(AsxError::new(
                ErrorCode::SecurityVerificationFailed,
                "AS4 push message signature is required but not present",
                ErrorContext::for_session_with_message("as4_receive_push", session, message_id),
            ));
        }

        if signature_present && expected_fingerprint.is_none() {
            return Err(AsxError::new(
                ErrorCode::PolicyViolation,
                "AS4 receive requires cert_handle.fingerprint_sha256 when verifying signed messages",
                ErrorContext::for_session_with_message("as4_receive_push", session, message_id),
            ));
        }

        // XML Signature Wrapping defence: when a signature is present, the
        // eb:Messaging block the pipeline routes on MUST be the one the
        // signature actually covered. Otherwise an attacker could relocate the
        // signed block (still resolvable by wsu:Id) and inject an unsigned
        // replacement that the parser consumes.
        if let Some(coverage) = coverage {
            enforce_messaging_signature_coverage(session, soap_doc, message_id, &coverage)?;
            enforce_attachment_signature_coverage(
                session,
                message_id,
                external_references,
                &coverage,
            )?;
        }

        Ok(())
    }
}

/// Require that the payload attachment the pipeline is about to surface was
/// covered by a verified `cid:` reference.
///
/// Signing `eb:Messaging` and the SOAP Body proves nothing about the payload —
/// the actual business document travels as a detached MIME part. Without this
/// check, a signature covering only the header and body verifies happily while
/// an intermediary swaps the attachment, and the receive pipeline hands the
/// substituted bytes to the application as `DomainReady`.
fn enforce_attachment_signature_coverage(
    session: &SessionContext,
    message_id: &str,
    attachments: &[(&str, &[u8])],
    coverage: &crate::crypto::wssec::verify::VerifiedSignatureCoverage,
) -> Result<()> {
    // Every attachment must be covered, not just the first: a multi-payload
    // message whose signature references only payload 1 leaves payloads 2..n
    // swappable.
    for (cid, _) in attachments {
        let cid = normalize_cid(cid);
        if coverage
            .signed_cid_references
            .iter()
            .any(|signed| normalize_cid(signed) == cid)
        {
            continue;
        }

        return Err(AsxError::new(
            ErrorCode::SecurityVerificationFailed,
            format!(
                "AS4 payload attachment cid:{cid} is not covered by the WS-Security \
                 signature; the signature must include a ds:Reference URI=\"cid:{cid}\" \
                 so the payload is integrity-protected alongside the eb:Messaging header"
            ),
            ErrorContext::for_session_with_message("as4_receive_push", session, message_id),
        ));
    }

    Ok(())
}

/// Strip an optional `cid:` scheme prefix and angle brackets, so a reference
/// written `cid:x@y`, `<x@y>` or `x@y` all compare equal.
fn normalize_cid(value: &str) -> &str {
    let value = value.trim();
    let value = value.strip_prefix('<').unwrap_or(value);
    let value = value.strip_suffix('>').unwrap_or(value);
    value
        .get(..4)
        .filter(|prefix| prefix.eq_ignore_ascii_case("cid:"))
        .map_or(value, |_| &value[4..])
}

/// ebMS3 core namespace.
const EBMS3_NS: &str = "http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/";
const WSU_NS: &str =
    "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd";

/// Require that the single `eb:Messaging` header block is covered by a verified
/// signature reference (matched by its `wsu:Id`).
fn enforce_messaging_signature_coverage(
    session: &SessionContext,
    soap_doc: &Document<'_>,
    message_id: &str,
    coverage: &crate::crypto::wssec::verify::VerifiedSignatureCoverage,
) -> Result<()> {
    let messaging_nodes: Vec<_> = soap_doc
        .descendants()
        .filter(|n| {
            n.is_element()
                && n.tag_name().name() == "Messaging"
                && n.tag_name().namespace() == Some(EBMS3_NS)
        })
        .collect();

    // Exactly one eb:Messaging block is expected; 0 or >1 is a wrapping attempt
    // or a malformed envelope.
    if messaging_nodes.len() != 1 {
        return Err(AsxError::new(
            ErrorCode::SecurityVerificationFailed,
            format!(
                "AS4 envelope must contain exactly one eb:Messaging header block (found {})",
                messaging_nodes.len()
            ),
            ErrorContext::for_session_with_message("as4_receive_push", session, message_id),
        ));
    }

    let messaging = messaging_nodes[0];
    let messaging_id = messaging
        .attribute((WSU_NS, "Id"))
        .or_else(|| messaging.attribute("Id"));

    let covered =
        messaging_id.is_some_and(|id| coverage.signed_same_document_ids.iter().any(|s| s == id));

    if !covered {
        return Err(AsxError::new(
            ErrorCode::SecurityVerificationFailed,
            "AS4 eb:Messaging header block is not covered by the verified WS-Security signature \
             (possible XML signature wrapping)",
            ErrorContext::for_session_with_message("as4_receive_push", session, message_id),
        ));
    }

    Ok(())
}

/// Test-only bypass verifier — skips all WS-Security checks.
///
/// Available only under the `testing` feature.  **Never use in production.**
///
/// Useful for:
/// - Integration tests that exercise the full AS4 receive pipeline without
///   setting up a real X.509 PKI (no trust anchors, no certificate pinning).
/// - [`MockAs4Endpoint`] — the in-process mock AS4 server.
/// - Testing BDEW/PEPPOL message routing without WIRK/production certificates.
///
/// ```toml
/// [dev-dependencies]
/// asx-rs = { version = "0.14", features = ["as4", "testing"] }
/// ```
///
/// [`MockAs4Endpoint`]: crate::as4::mock_endpoint::MockAs4Endpoint
#[cfg(feature = "testing")]
#[derive(Debug, Default, Clone, Copy)]
pub struct InsecureBypassAs4Verifier;

#[cfg(feature = "testing")]
impl private::Sealed for InsecureBypassAs4Verifier {}

#[cfg(feature = "testing")]
impl As4Verifier for InsecureBypassAs4Verifier {
    fn verify_security(
        &self,
        session: &SessionContext,
        _policy: &As4PushPolicy,
        _soap_xml: &str,
        _soap_doc: &Document<'_>,
        message_id: &str,
        _external_references: &[(&str, &[u8])],
    ) -> Result<()> {
        // Intentional no-op — bypasses ALL WS-Security checks.
        // Emit a tracing event so test logs are auditable and production
        // log-scraping can detect accidental non-test usage.
        tracing::warn!(
            target: "asx_rs::as4::testing",
            session_id = %session.session_id(),
            message_id = %message_id,
            "InsecureBypassAs4Verifier: ALL SIGNATURE / TRUST CHECKS BYPASSED (testing only)"
        );
        Ok(())
    }
}

#[cfg(test)]
mod xsw_coverage_tests {
    use super::{
        EBMS3_NS, ErrorCode, enforce_attachment_signature_coverage,
        enforce_messaging_signature_coverage,
    };
    use crate::core::SessionContext;
    use crate::crypto::wssec::verify::VerifiedSignatureCoverage;
    use roxmltree::Document;

    fn session() -> SessionContext {
        SessionContext::new("s-xsw", "partner", "strict").expect("session")
    }

    fn coverage(ids: &[&str]) -> VerifiedSignatureCoverage {
        VerifiedSignatureCoverage {
            signed_same_document_ids: ids.iter().map(|s| s.to_string()).collect(),
            signed_cid_references: Vec::new(),
        }
    }

    fn cid_coverage(cids: &[&str]) -> VerifiedSignatureCoverage {
        VerifiedSignatureCoverage {
            signed_same_document_ids: Vec::new(),
            signed_cid_references: cids.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn attachment_covered_by_a_signed_cid_reference_is_accepted() {
        enforce_attachment_signature_coverage(
            &session(),
            "m1",
            &[("payload@example.com", b"bytes".as_slice())],
            &cid_coverage(&["payload@example.com"]),
        )
        .expect("covered attachment must verify");
    }

    #[test]
    fn cid_comparison_ignores_scheme_prefix_and_angle_brackets() {
        for (attachment, signed) in [
            ("cid:p@e.com", "p@e.com"),
            ("p@e.com", "cid:p@e.com"),
            ("<p@e.com>", "p@e.com"),
            ("CID:p@e.com", "p@e.com"),
        ] {
            enforce_attachment_signature_coverage(
                &session(),
                "m1",
                &[(attachment, b"bytes".as_slice())],
                &cid_coverage(&[signed]),
            )
            .unwrap_or_else(|err| panic!("{attachment} vs {signed} must match: {err}"));
        }
    }

    #[test]
    fn attachment_not_covered_by_any_signed_reference_is_rejected() {
        // The signature covers the eb:Messaging header but no attachment — the
        // payload could be swapped in transit without breaking it.
        let err = enforce_attachment_signature_coverage(
            &session(),
            "m1",
            &[("payload@example.com", b"bytes".as_slice())],
            &coverage(&["as4-messaging"]),
        )
        .expect_err("uncovered attachment must be rejected");
        assert_eq!(err.code, ErrorCode::SecurityVerificationFailed);
        assert!(err.message.contains("payload@example.com"));
    }

    #[test]
    fn attachment_covered_by_a_different_cid_is_rejected() {
        let err = enforce_attachment_signature_coverage(
            &session(),
            "m1",
            &[("payload@example.com", b"bytes".as_slice())],
            &cid_coverage(&["decoy@example.com"]),
        )
        .expect_err("a signed reference to a different part must not count");
        assert_eq!(err.code, ErrorCode::SecurityVerificationFailed);
    }

    #[test]
    fn no_attachment_needs_no_cid_coverage() {
        enforce_attachment_signature_coverage(&session(), "m1", &[], &coverage(&["as4-messaging"]))
            .expect("a message with no attachment has nothing to cover");
    }

    /// Every attachment must be covered — a signature referencing only the
    /// first payload leaves payloads 2..n swappable.
    #[test]
    fn every_attachment_must_be_covered_not_just_the_first() {
        let attachments: &[(&str, &[u8])] =
            &[("xmlpayload@gitb", b"one"), ("custompayload@gitb", b"two")];

        enforce_attachment_signature_coverage(
            &session(),
            "m1",
            attachments,
            &cid_coverage(&["xmlpayload@gitb", "custompayload@gitb"]),
        )
        .expect("both covered");

        let err = enforce_attachment_signature_coverage(
            &session(),
            "m1",
            attachments,
            &cid_coverage(&["xmlpayload@gitb"]),
        )
        .expect_err("the second attachment is not covered");
        assert_eq!(err.code, ErrorCode::SecurityVerificationFailed);
        assert!(
            err.message.contains("custompayload@gitb"),
            "{}",
            err.message
        );
    }

    fn envelope_with(messaging_blocks: &str) -> String {
        format!(
            r#"<S12:Envelope xmlns:S12="http://www.w3.org/2003/05/soap-envelope"
                xmlns:eb="{EBMS3_NS}"
                xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
              <S12:Header>{messaging_blocks}</S12:Header>
              <S12:Body/>
            </S12:Envelope>"#
        )
    }

    #[test]
    fn accepts_single_signed_messaging() {
        let xml = envelope_with(
            r#"<eb:Messaging wsu:Id="as4-messaging"><eb:UserMessage/></eb:Messaging>"#,
        );
        let doc = Document::parse(&xml).unwrap();
        enforce_messaging_signature_coverage(&session(), &doc, "m1", &coverage(&["as4-messaging"]))
            .expect("signed eb:Messaging must be accepted");
    }

    #[test]
    fn rejects_uncovered_messaging_id() {
        let xml =
            envelope_with(r#"<eb:Messaging wsu:Id="attacker-id"><eb:UserMessage/></eb:Messaging>"#);
        let doc = Document::parse(&xml).unwrap();
        let err = enforce_messaging_signature_coverage(
            &session(),
            &doc,
            "m1",
            &coverage(&["as4-messaging"]),
        )
        .expect_err("eb:Messaging id not in signed set must reject");
        assert_eq!(err.code, crate::core::ErrorCode::SecurityVerificationFailed);
    }

    #[test]
    fn rejects_injected_second_messaging_block() {
        // Signature covers the original block; attacker injected a second one.
        let xml = envelope_with(
            r#"<eb:Messaging wsu:Id="as4-messaging"><eb:UserMessage/></eb:Messaging>
               <eb:Messaging><eb:UserMessage/></eb:Messaging>"#,
        );
        let doc = Document::parse(&xml).unwrap();
        let err = enforce_messaging_signature_coverage(
            &session(),
            &doc,
            "m1",
            &coverage(&["as4-messaging"]),
        )
        .expect_err("two eb:Messaging blocks must reject");
        assert_eq!(err.code, crate::core::ErrorCode::SecurityVerificationFailed);
    }

    #[test]
    fn rejects_messaging_without_wsu_id() {
        let xml = envelope_with(r#"<eb:Messaging><eb:UserMessage/></eb:Messaging>"#);
        let doc = Document::parse(&xml).unwrap();
        let err = enforce_messaging_signature_coverage(
            &session(),
            &doc,
            "m1",
            &coverage(&["as4-messaging"]),
        )
        .expect_err("unsigned eb:Messaging must reject");
        assert_eq!(err.code, crate::core::ErrorCode::SecurityVerificationFailed);
    }
}
