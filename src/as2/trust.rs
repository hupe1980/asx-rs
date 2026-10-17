//! AS2 trust-verification traits and implementations.
//!
//! Defines the sealed [`As2TrustVerifier`] trait and the production
//! [`CmsSmimeTrustVerifier`] backed by OpenSSL CMS / S/MIME.

use std::sync::Arc;
use zeroize::Zeroize;

use crate::core::{AsxError, ErrorCode, ErrorContext, Result, SessionContext};
use crate::crypto::as2_smime::VerifiedSmimeEntity;
#[cfg(feature = "as2")]
use crate::crypto::as2_smime::{
    As2SmimeVerificationOptions, SmimeFormat, decrypt_smime_enveloped_payload, detect_smime_format,
    verify_smime_signed_payload,
};

/// Sealing module — prevents external crates from implementing the trust
/// verifier traits.
pub(crate) mod private {
    pub(crate) trait Sealed {}
}

/// Result returned by [`As2TrustVerifier::verify_and_decrypt`].
///
/// Carries the cryptographic verdict together with the MIME entity that the
/// message-level security actually protected. That entity matters twice:
///
/// - it is the RFC 4130 §7.3.1 input for the `Received-Content-MIC` the MDN
///   echoes back, and
/// - its content — headers stripped — is the business document the application
///   receives.
///
/// Returning the whole S/MIME envelope instead would hand the application an
/// unparsed `multipart/signed` blob and produce a MIC no sender can reproduce.
#[derive(Debug)]
pub(crate) struct TrustResult {
    /// The protected MIME entity — exact signed/decrypted octets, headers
    /// included. `None` only when the message carried no message-level
    /// security, in which case the raw body is both content and MIC input.
    pub protected_entity: Option<VerifiedSmimeEntity>,
}

impl TrustResult {
    /// Verification passed over `entity`; no decryption was required.
    pub(crate) fn signed_only(entity: VerifiedSmimeEntity) -> Self {
        Self {
            protected_entity: Some(entity),
        }
    }

    /// Verification passed and decryption was applied, yielding `entity`.
    pub(crate) fn decrypted(entity: VerifiedSmimeEntity) -> Self {
        Self {
            protected_entity: Some(entity),
        }
    }
}

/// Sealed trust-verification contract for AS2 inbound messages.
///
/// ## Security note
///
/// This trait is **sealed**: it cannot be implemented outside this crate. The
/// only implementation is [`CmsSmimeTrustVerifier`]; tests run it against
/// generated test PKI (`asx-rs-testkit`), never against a bypass.
pub(crate) trait As2TrustVerifier: private::Sealed + std::fmt::Debug {
    fn verify_and_decrypt(&self, session: &SessionContext, body: &Arc<[u8]>)
    -> Result<TrustResult>;
}

/// Production AS2 trust verifier using OpenSSL CMS / S/MIME.
///
/// Handles three inbound AS2 content layouts:
///
/// 1. **Signed-only** (`multipart/signed` or `smime-type=signed-data`) —
///    the signature is verified with the configured trust anchors.
/// 2. **Encrypted-only** (`smime-type=enveloped-data`) — the `EnvelopedData`
///    layer is decrypted using [`Self::decryption_key_pem`] /
///    [`Self::decryption_cert_pem`].  An unsigned inner entity is
///    rejected: encryption alone authenticates nothing.
/// 3. **Signed-then-encrypted** (the AS2 interop recommendation per
///    RFC 4130 §7.5) — the outer `EnvelopedData` is decrypted first, then
///    the inner signed structure is verified.
///
/// If `decryption_key_pem` is `None` and an encrypted payload arrives, the
/// call returns [`crate::core::ErrorCode::DecryptionFailed`].
#[derive(Clone, Default)]
pub(crate) struct CmsSmimeTrustVerifier {
    /// PEM-encoded recipient private key for `EnvelopedData` decryption.
    /// Required when inbound AS2 messages are encrypted.
    pub decryption_key_pem: Option<Vec<u8>>,
    /// PEM-encoded X.509 recipient certificate matching `decryption_key_pem`.
    /// Required when inbound AS2 messages are encrypted.
    pub decryption_cert_pem: Option<Vec<u8>>,
}

impl std::fmt::Debug for CmsSmimeTrustVerifier {
    /// Never prints `decryption_key_pem`.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CmsSmimeTrustVerifier")
            .field(
                "decryption_key_pem",
                &crate::core::redact_present(self.decryption_key_pem.is_some()),
            )
            .field("decryption_cert_pem", &self.decryption_cert_pem)
            .finish()
    }
}

impl Drop for CmsSmimeTrustVerifier {
    fn drop(&mut self) {
        if let Some(key) = self.decryption_key_pem.as_mut() {
            key.zeroize();
        }
    }
}

impl CmsSmimeTrustVerifier {
    pub(super) fn build_chain_policy<'a>(
        session: &'a SessionContext,
    ) -> Result<crate::crypto::wssec::ChainPolicy<'a>> {
        if session.cert_handle().trust_anchor_pems.is_empty() {
            return Err(AsxError::new(
                ErrorCode::SecurityVerificationFailed,
                "PKIX chain validation requires at least one trust anchor PEM; \
                 call with_cert_handle() and provide trust_anchor_pems before verifying signed AS2 messages",
                ErrorContext::for_session("as2_smime_build_chain_policy", session),
            ));
        }
        Ok(crate::crypto::wssec::ChainPolicy {
            trust_anchor_pems: &session.cert_handle().trust_anchor_pems,
            require_chain_validation: true,
            pre_parsed_trust_anchors: Some(session.trust_anchors_x509()?),
            pre_built_x509_store: Some(session.trust_anchor_x509_store()?),
        })
    }
}

impl private::Sealed for CmsSmimeTrustVerifier {}

impl As2TrustVerifier for CmsSmimeTrustVerifier {
    fn verify_and_decrypt(
        &self,
        session: &SessionContext,
        body: &Arc<[u8]>,
    ) -> Result<TrustResult> {
        #[cfg(feature = "as2")]
        {
            let payload = body;
            let expected_fingerprint = match session.cert_handle().fingerprint_sha256.trim() {
                "" => None,
                value => Some(value),
            };
            let build_options = || -> Result<As2SmimeVerificationOptions<'_>> {
                Ok(As2SmimeVerificationOptions {
                    expected_signer_fingerprint_sha256: expected_fingerprint,
                    chain_policy: Self::build_chain_policy(session)?,
                    intermediate_ca_pems: &session.cert_handle().intermediate_ca_pems,
                })
            };

            match detect_smime_format(payload.as_ref()) {
                SmimeFormat::Enveloped => {
                    // ── Decrypt outer EnvelopedData ───────────────────────────────
                    let (key, cert) = match (&self.decryption_key_pem, &self.decryption_cert_pem) {
                        (Some(k), Some(c)) => (k.as_slice(), c.as_slice()),
                        _ => {
                            return Err(AsxError::new(
                                ErrorCode::DecryptionFailed,
                                "AS2 message is encrypted but no decryption key is configured \
                                 on CmsSmimeTrustVerifier; supply decryption_key_pem and \
                                 decryption_cert_pem",
                                ErrorContext::for_session("as2_smime_decrypt", session),
                            ));
                        }
                    };
                    let decrypted = decrypt_smime_enveloped_payload(payload.as_ref(), cert, key)?;
                    // ── Optionally verify inner signature (signed-then-encrypted) ─
                    let entity = match detect_smime_format(&decrypted) {
                        SmimeFormat::OpaqueSignedData | SmimeFormat::MultipartSigned => {
                            verify_smime_signed_payload(&decrypted, build_options()?).map_err(|err| {
                                AsxError::new(
                                    ErrorCode::SecurityVerificationFailed,
                                    format!(
                                        "AS2 inner signed message verification failed after decryption: {err}"
                                    ),
                                    ErrorContext::for_session("as2_smime_verify_inner", session),
                                )
                            })?
                        }
                        _ => {
                            // Unsigned encrypted payload — no inner signature to
                            // verify. The recipient encryption cert is semi-public,
                            // so this authenticates nothing about the sender.
                            return Err(AsxError::new(
                                ErrorCode::SecurityVerificationFailed,
                                "AS2 message is encrypted but not signed; encryption alone \
                                 does not authenticate the sender because the recipient \
                                 certificate is not secret",
                                ErrorContext::for_session("as2_smime_signature_policy", session),
                            ));
                        }
                    };
                    Ok(TrustResult::decrypted(entity))
                }
                // ── Signed-only path: opaque or detached signature ───────────────
                SmimeFormat::OpaqueSignedData | SmimeFormat::MultipartSigned => {
                    Ok(TrustResult::signed_only(verify_smime_signed_payload(
                        payload.as_ref(),
                        build_options()?,
                    )?))
                }
                // Not an S/MIME structure at all — a plain AS2 payload, which
                // RFC 4130 permits. Feeding it to the CMS parser would only
                // produce a misleading ASN.1 error, so decide on policy.
                SmimeFormat::Unknown => Err(AsxError::new(
                    ErrorCode::SecurityVerificationFailed,
                    "AS2 message carries no S/MIME signature or encryption layer; \
                         signatures are required",
                    ErrorContext::for_session("as2_smime_signature_policy", session),
                )),
                SmimeFormat::AuthenticatedData => Err(AsxError::new(
                    ErrorCode::InteropViolation,
                    "CMS AuthenticatedData (smime-type=authenticated-data) is not supported \
                         for AS2 message delivery; partner must use SignedData or EnvelopedData",
                    ErrorContext::for_session("as2_smime_verify", session),
                )),
                SmimeFormat::DigestedData => Err(AsxError::new(
                    ErrorCode::InteropViolation,
                    "CMS DigestedData (smime-type=digested-data) is not supported \
                         for AS2 message delivery; partner must use SignedData or EnvelopedData",
                    ErrorContext::for_session("as2_smime_verify", session),
                )),
            }
        }
        #[cfg(not(feature = "as2"))]
        {
            let _ = (session, body);
            Err(AsxError::new(
                ErrorCode::PolicyViolation,
                "CmsSmimeTrustVerifier requires the 'as2' feature",
                ErrorContext::new("as2_smime_feature_disabled"),
            ))
        }
    }
}
