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

        let signature_present = if let Some(external_reference) = external_reference {
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

        Ok(())
    }
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
/// asx-rs = { version = "0.6", features = ["as4", "testing"] }
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
