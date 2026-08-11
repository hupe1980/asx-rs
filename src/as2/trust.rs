//! AS2 trust-verification traits and implementations.
//!
//! Defines the sealed [`As2TrustVerifier`] / [`AsyncAs2TrustVerifier`] trait
//! pair, the production [`CmsSmimeTrustVerifier`] backed by OpenSSL CMS /
//! S/MIME, and the [`SyncToAsyncTrustVerifier`] adapter.

use std::sync::Arc;
use zeroize::Zeroize;

use crate::core::{AsxError, ErrorCode, ErrorContext, ReceivedBodyHandle, Result, SessionContext};
use crate::crypto::as2_smime::VerifiedSmimeEntity;
#[cfg(feature = "as2")]
use crate::crypto::as2_smime::{
    As2SmimeVerificationOptions, SmimeFormat, decrypt_smime_enveloped_payload, detect_smime_format,
    verify_smime_signed_payload,
};
#[cfg(test)]
use crate::lifecycle::TrustEvidence;
use crate::lifecycle::{DecryptionMaterial, SignatureVerification};

/// Sealing module — prevents external crates from implementing the trust
/// verifier traits outside the `testing` feature escape hatch.
pub(crate) mod private {
    pub trait Sealed {}
}

/// Re-export the sealing marker under the `testing` feature so that
/// integration tests can implement [`As2TrustVerifier`] on their own stubs.
///
/// **Never use this in production code.**
#[cfg(feature = "testing")]
pub use private::Sealed as TrustVerifierSeal;

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
pub struct TrustResult {
    /// Whether S/MIME signature verification succeeded.
    pub signature: SignatureVerification,
    /// Whether decryption material was present and (if needed) applied.
    pub decryption: DecryptionMaterial,
    /// The protected MIME entity — exact signed/decrypted octets, headers
    /// included. `None` only when the message carried no message-level
    /// security, in which case the raw body is both content and MIC input.
    pub protected_entity: Option<VerifiedSmimeEntity>,
}

impl TrustResult {
    /// Verification passed over `entity`; no decryption was required.
    pub fn signed_only(entity: VerifiedSmimeEntity) -> Self {
        Self {
            signature: SignatureVerification::Verified,
            decryption: DecryptionMaterial::Available,
            protected_entity: Some(entity),
        }
    }

    /// Verification passed and decryption was applied, yielding `entity`.
    pub fn decrypted(entity: VerifiedSmimeEntity) -> Self {
        Self {
            signature: SignatureVerification::Verified,
            decryption: DecryptionMaterial::Available,
            protected_entity: Some(entity),
        }
    }

    /// The message carried no signature and policy allowed it. `entity` is the
    /// decrypted MIME entity for encrypted-but-unsigned messages.
    pub fn unsigned(entity: VerifiedSmimeEntity) -> Self {
        Self {
            signature: SignatureVerification::NotSigned,
            decryption: DecryptionMaterial::Available,
            protected_entity: Some(entity),
        }
    }
}

/// Sealed trust-verification contract for AS2 inbound messages.
///
/// ## Security note
///
/// This trait is **sealed**: it cannot be implemented outside this crate
/// except when the `testing` Cargo feature is enabled.  In production builds
/// the only valid implementation is [`CmsSmimeTrustVerifier`].
///
/// Unlike the AS4 side, there is **no downstream-visible bypass verifier for
/// AS2**: `InsecureBypassTrustVerifier` is `#[cfg(test)]`, so it exists only
/// inside this crate's own test builds and is not reachable from a dependent
/// crate even with `testing` enabled. Downstream integration tests should
/// implement [`As2TrustVerifier`] against a local fixture, which the `testing`
/// feature permits via [`TrustVerifierSeal`](crate::as2::TrustVerifierSeal).
/// Never enable the `testing` feature in production binaries.
pub trait As2TrustVerifier: private::Sealed {
    fn verify_and_decrypt(
        &self,
        session: &SessionContext,
        body: &ReceivedBodyHandle,
    ) -> Result<TrustResult>;
}

/// Async counterpart of [`As2TrustVerifier`].
///
/// Implement this trait when your verification backend requires async I/O —
/// for example, an HSM accessed over a network socket, or an OCSP responder
/// that is checked inline during signature verification.
///
/// For synchronous verifiers, use [`SyncToAsyncTrustVerifier`] to adapt an
/// existing [`As2TrustVerifier`] to this interface with blocking-pool
/// offloading.
///
/// ## Security note
///
/// This trait is **sealed**: see [`As2TrustVerifier`] for details.
pub trait AsyncAs2TrustVerifier: Send + Sync + private::Sealed {
    fn verify_and_decrypt<'a>(
        &'a self,
        session: &'a SessionContext,
        body: &'a ReceivedBodyHandle,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<TrustResult>> + Send + 'a>>;
}

/// Adapts any synchronous [`As2TrustVerifier`] to the async
/// [`AsyncAs2TrustVerifier`] interface.
///
/// Verification runs on Tokio's blocking pool via `spawn_blocking`, so
/// CPU-heavy crypto and chain validation do not execute on async workers.
///
/// The inner verifier is stored behind an `Arc`, so `SyncToAsyncTrustVerifier`
/// itself is `Clone` regardless of whether `V` is `Clone`.  This avoids
/// cloning non-trivial verifier state (parsed cert chains, OCSP caches) on
/// every call, reducing memory pressure under concurrent receive load.
///
/// # Migration from the old API
///
/// The previous signature required `V: Clone`.  Existing callsites that
/// already had `SyncToAsyncTrustVerifier(my_verifier)` now need:
///
/// ```rust,ignore
/// SyncToAsyncTrustVerifier::new(my_verifier)
/// // or equivalently
/// SyncToAsyncTrustVerifier(Arc::new(my_verifier))
/// ```
pub struct SyncToAsyncTrustVerifier<V: As2TrustVerifier + Send + Sync + 'static>(pub Arc<V>);

impl<V: As2TrustVerifier + Send + Sync + 'static> SyncToAsyncTrustVerifier<V> {
    /// Wrap `verifier` in an `Arc` and return an adapter.
    pub fn new(verifier: V) -> Self {
        Self(Arc::new(verifier))
    }
}

impl<V: As2TrustVerifier + Send + Sync + 'static> Clone for SyncToAsyncTrustVerifier<V> {
    fn clone(&self) -> Self {
        Self(Arc::clone(&self.0))
    }
}

impl<V: As2TrustVerifier + Send + Sync + 'static> private::Sealed for SyncToAsyncTrustVerifier<V> {}

impl<V: As2TrustVerifier + Send + Sync + 'static> AsyncAs2TrustVerifier
    for SyncToAsyncTrustVerifier<V>
{
    fn verify_and_decrypt<'a>(
        &'a self,
        session: &'a SessionContext,
        body: &'a ReceivedBodyHandle,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<TrustResult>> + Send + 'a>> {
        let verifier = Arc::clone(&self.0);
        let blocking_session = session.clone();
        let blocking_body = body.clone();
        let error_session = session.clone();
        Box::pin(async move {
            let permit = crate::core::CryptoAdmissionControl::process_global()
                .acquire("as2_trust_verify_async_admission", &blocking_session)
                .await?;
            tokio::task::spawn_blocking(move || {
                let _permit = permit;
                verifier.verify_and_decrypt(&blocking_session, &blocking_body)
            })
            .await
            .map_err(|err| {
                AsxError::new(
                    ErrorCode::TransportFailure,
                    format!("AS2 trust verification blocking task failed: {err}"),
                    ErrorContext::for_session("as2_trust_verify_async_join", &error_session),
                )
            })?
        })
    }
}

/// Test-only bypass verifier — skips all cryptographic checks.
///
/// Only available in `#[cfg(test)]` builds.  Never use in production.
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InsecureBypassTrustVerifier {
    trust: TrustEvidence,
}

#[cfg(test)]
impl InsecureBypassTrustVerifier {
    pub fn new(trust: TrustEvidence) -> Self {
        Self { trust }
    }
}

#[cfg(test)]
impl private::Sealed for InsecureBypassTrustVerifier {}

#[cfg(test)]
impl As2TrustVerifier for InsecureBypassTrustVerifier {
    fn verify_and_decrypt(
        &self,
        _session: &SessionContext,
        _body: &ReceivedBodyHandle,
    ) -> Result<TrustResult> {
        Ok(TrustResult {
            signature: self.trust.signature,
            decryption: self.trust.decryption,
            protected_entity: None,
        })
    }
}

/// Production AS2 trust verifier using OpenSSL CMS / S/MIME.
///
/// Handles three inbound AS2 content layouts:
///
/// 1. **Signed-only** (`multipart/signed` or `smime-type=signed-data`) —
///    the signature is verified with the configured trust anchors.
/// 2. **Encrypted-only** (`smime-type=enveloped-data`) — the `EnvelopedData`
///    layer is decrypted using [`Self::decryption_key_pem`] /
///    [`Self::decryption_cert_pem`].  No signature is required *unless*
///    [`Self::require_signed`] is set, in which case unsigned messages are
///    rejected.
/// 3. **Signed-then-encrypted** (the AS2 interop recommendation per
///    RFC 4130 §7.5) — the outer `EnvelopedData` is decrypted first, then
///    the inner signed structure is verified.
///
/// If `decryption_key_pem` is `None` and an encrypted payload arrives, the
/// call returns [`crate::core::ErrorCode::DecryptionFailed`].
#[derive(Debug, Clone, Default)]
pub struct CmsSmimeTrustVerifier {
    /// PEM-encoded recipient private key for `EnvelopedData` decryption.
    /// Required when inbound AS2 messages are encrypted.
    pub decryption_key_pem: Option<Vec<u8>>,
    /// PEM-encoded X.509 recipient certificate matching `decryption_key_pem`.
    /// Required when inbound AS2 messages are encrypted.
    pub decryption_cert_pem: Option<Vec<u8>>,
    /// Whether unsigned inbound messages are acceptable.
    ///
    /// Defaults to [`As2SignaturePolicy::Required`] — fail-closed.
    pub signature_policy: As2SignaturePolicy,
}

/// Whether inbound AS2 messages must carry a verifiable signature.
///
/// RFC 4130 permits unsigned messages, but an unsigned message authenticates
/// nothing about its sender: AS2 recipient encryption certificates are
/// exchanged with partners and are effectively semi-public, so even an
/// *encrypted* message proves only that someone had the recipient's public
/// certificate — which is not a secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum As2SignaturePolicy {
    /// Every inbound message must carry a signature that verifies against a
    /// configured trust anchor. Unsigned messages are rejected with
    /// [`ErrorCode::SecurityVerificationFailed`]. **Default.**
    #[default]
    Required,
    /// Accept unsigned messages, reporting them as
    /// [`SignatureVerification::NotSigned`]. Signed messages are still fully
    /// verified, and a *failed* signature is still fatal.
    ///
    /// Only appropriate when sender authenticity is established by other means
    /// (for example mutually-authenticated TLS on a closed network).
    Optional,
}

impl Drop for CmsSmimeTrustVerifier {
    fn drop(&mut self) {
        if let Some(key) = self.decryption_key_pem.as_mut() {
            key.zeroize();
        }
    }
}

impl CmsSmimeTrustVerifier {
    /// Create a new verifier with decryption credentials.
    ///
    /// Signatures are required by default; call
    /// [`allowing_unsigned`](Self::allowing_unsigned) to relax that.
    pub fn with_decryption_credentials(key_pem: Vec<u8>, cert_pem: Vec<u8>) -> Self {
        Self {
            decryption_key_pem: Some(key_pem),
            decryption_cert_pem: Some(cert_pem),
            signature_policy: As2SignaturePolicy::Required,
        }
    }

    /// Accept inbound messages that carry no signature.
    ///
    /// See [`As2SignaturePolicy::Optional`] for when this is defensible.
    /// Chainable:
    ///
    /// ```rust,ignore
    /// let verifier = CmsSmimeTrustVerifier::with_decryption_credentials(key, cert)
    ///     .allowing_unsigned();
    /// ```
    #[must_use]
    pub fn allowing_unsigned(mut self) -> Self {
        self.signature_policy = As2SignaturePolicy::Optional;
        self
    }

    fn build_revocation_policy<'a>(
        session: &'a SessionContext,
    ) -> Result<crate::crypto::wssec::RevocationPolicy<'a>> {
        if session.cert_handle().trust_anchor_pems.is_empty() {
            return Err(AsxError::new(
                ErrorCode::SecurityVerificationFailed,
                "PKIX chain validation requires at least one trust anchor PEM; \
                 call with_cert_handle() and provide trust_anchor_pems before verifying signed AS2 messages",
                ErrorContext::for_session("as2_smime_build_revocation_policy", session),
            ));
        }
        Ok(crate::crypto::wssec::RevocationPolicy {
            trust_anchor_pems: &session.cert_handle().trust_anchor_pems,
            revocation_crl_pems: &session.cert_handle().revocation_crl_pems,
            ocsp_mode: session.cert_handle().ocsp_mode,
            ocsp_failure_mode: session.cert_handle().ocsp_failure_mode,
            stapled_ocsp_responses_der: &session.cert_handle().stapled_ocsp_responses_der,
            responder_ocsp_responses_der: &session.cert_handle().responder_ocsp_responses_der,
            ocsp_cache_namespace: session.partner_id(),
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
        body: &ReceivedBodyHandle,
    ) -> Result<TrustResult> {
        #[cfg(feature = "as2")]
        {
            let payload = body.materialize_contiguous("as2_smime_verify", session)?;
            let expected_fingerprint = match session.cert_handle().fingerprint_sha256.trim() {
                "" => None,
                value => Some(value),
            };
            let build_options = || -> Result<As2SmimeVerificationOptions<'_>> {
                Ok(As2SmimeVerificationOptions {
                    expected_signer_fingerprint_sha256: expected_fingerprint,
                    revocation_policy: Self::build_revocation_policy(session)?,
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
                            if self.signature_policy == As2SignaturePolicy::Required {
                                return Err(AsxError::new(
                                    ErrorCode::SecurityVerificationFailed,
                                    "AS2 message is encrypted but not signed; encryption alone \
                                     does not authenticate the sender because the recipient \
                                     certificate is not secret. Sign the message, or set \
                                     As2SignaturePolicy::Optional to accept this",
                                    ErrorContext::for_session("as2_smime_signature_policy", session),
                                ));
                            }
                            // RFC 4130 §7.3.1: for an encrypted-but-unsigned
                            // message the MIC covers the *decrypted* MIME entity.
                            return Ok(TrustResult::unsigned(
                                VerifiedSmimeEntity::from_entity_bytes(decrypted),
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
                SmimeFormat::Unknown => {
                    if self.signature_policy == As2SignaturePolicy::Required {
                        return Err(AsxError::new(
                            ErrorCode::SecurityVerificationFailed,
                            "AS2 message carries no S/MIME signature or encryption layer; \
                             signatures are required. Ask the partner to sign, or set \
                             As2SignaturePolicy::Optional to accept unsigned payloads",
                            ErrorContext::for_session("as2_smime_signature_policy", session),
                        ));
                    }
                    // Unprotected: RFC 4130 §7.3.1 MICs the content with no MIME
                    // headers, which is what `protected_entity: None` selects.
                    Ok(TrustResult {
                        signature: SignatureVerification::NotSigned,
                        decryption: DecryptionMaterial::Available,
                        protected_entity: None,
                    })
                }
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
