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
/// Re-exported from `asx_rs::as4` as [`as4::verifier_seal`].
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
        external_reference: Option<(&str, &[u8])>,
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
        external_reference: Option<(&str, &[u8])>,
    ) -> Result<()> {
        let expected_fingerprint = expected_fingerprint_from_session(session);
        let revocation_policy = wssec_revocation_policy_from_session(session)?;
        let opts = WsSecVerifyOptions::new()
            .with_expected_fingerprint(expected_fingerprint)
            .with_revocation(revocation_policy);

        let coverage = if let Some(external_reference) = external_reference {
            let external_references = [external_reference];
            crate::crypto::wssec::verify::verify_enveloped_signature_optional_with_doc(
                soap_doc,
                soap_xml,
                opts.with_external_references(&external_references),
            )?
        } else {
            crate::crypto::wssec::verify::verify_enveloped_signature_optional_with_doc(
                soap_doc, soap_xml, opts,
            )?
        };

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
        }

        Ok(())
    }
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
/// asx-rs = { version = "0.9", features = ["as4", "testing"] }
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
        _external_reference: Option<(&str, &[u8])>,
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
    use super::{EBMS3_NS, enforce_messaging_signature_coverage};
    use crate::core::SessionContext;
    use crate::crypto::wssec::verify::VerifiedSignatureCoverage;
    use roxmltree::Document;

    fn session() -> SessionContext {
        SessionContext::new("s-xsw", "partner", "strict").expect("session")
    }

    fn coverage(ids: &[&str]) -> VerifiedSignatureCoverage {
        VerifiedSignatureCoverage {
            signed_same_document_ids: ids.iter().map(|s| s.to_string()).collect(),
        }
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
