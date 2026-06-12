use roxmltree::Document;

use super::super::services::{
    expected_fingerprint_from_session, wssec_revocation_policy_from_session,
};
use super::super::types::As4PushPolicy;
use crate::core::{AsxError, ErrorCode, ErrorContext, Result, SessionContext};
use crate::crypto::wssec::WsSecVerifyOptions;

/// Sealing module — prevents external crates from implementing
/// As4Verifier without going through the testing escape hatch.
pub(crate) mod private {
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

        if policy.require_signed_push() && !signature_present {
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
