//! Signing key abstraction for outbound XMLDSig and WS-Security operations.
//!
//! This module decouples signing from key storage, enabling HSM/PKCS#11
//! and cloud KMS integrations without touching library internals.
//!
//! ## Implementations
//!
//! | Type | Backing | Use case |
//! |------|---------|----------|
//! | [`PemSigningKeyProvider`](crate::crypto::signing::PemSigningKeyProvider) | In-memory PEM | Development, testing, simple deployments |
//! | `HsmSigningKeyProvider` *(user-supplied)* | PKCS#11 slot | PCI-DSS / HIPAA / eIDAS regulated |
//! | `KmsSigningKeyProvider` *(user-supplied)* | AWS/GCP/Azure KMS | Cloud-native deployments |
//!
//! ## Output encoding
//!
//! [`SigningKeyProvider::sign`](crate::crypto::signing::SigningKeyProvider::sign) returns what key stores return: RSA PKCS #1
//! v1.5 signature octets, ECDSA as an ASN.1 DER `ECDSA-Sig-Value`. The XMLDSig
//! layer converts ECDSA to the fixed-width `r ‖ s` that XMLDSig 1.1 §6.4.3
//! puts on the wire; any other encoding fails signing.

use openssl::pkey::{PKey, Private};
use openssl::sign::Signer;
use openssl::x509::X509;

use crate::core::{AsxError, ErrorCode, ErrorContext, Result};

// ---------------------------------------------------------------------------
// Algorithm enum (defined in the registry, `crypto::alg`)
// ---------------------------------------------------------------------------

pub use crate::crypto::alg::SignatureAlgorithm;

impl SignatureAlgorithm {
    /// Infer the preferred `SignatureAlgorithm` for a parsed `PKey`.
    pub(crate) fn from_pkey(key: &PKey<Private>) -> Option<Self> {
        match key.id() {
            openssl::pkey::Id::RSA | openssl::pkey::Id::RSA_PSS => Some(Self::RsaSha256),
            openssl::pkey::Id::EC => Some(Self::EcdsaSha256),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// SigningKeyProvider trait
// ---------------------------------------------------------------------------

/// Abstraction over private-key signing for outbound XMLDSig operations.
///
/// Implement this trait to integrate any key storage backend — HSM slot,
/// cloud KMS, or an in-memory PEM key — with the AS2/AS4 send pipelines.
///
/// # Contract
///
/// - `sign` must be **deterministic in algorithm** (for RSA, PKCS1-v1.5
///   padding; for ECDSA, the signature is necessarily non-deterministic).
/// - `certificate_der` must return a DER-encoded X.509 certificate whose
///   public key matches the private key used by `sign`.
/// - Implementations MUST NOT store the raw private key bytes in a form
///   that survives past the provider object's lifetime (zeroize on drop).
///
/// # Thread Safety
///
/// Implementations must be `Send + Sync` so they can be wrapped in `Arc`
/// and shared across Tokio tasks.  In-memory keys are trivially `Send + Sync`.
/// PKCS#11 session handles may require a per-thread or pooled session strategy.
pub trait SigningKeyProvider: Send + Sync + std::fmt::Debug {
    /// Sign `data` with this provider's private key using `algorithm`.
    ///
    /// The implementation is responsible for:
    /// 1. Hashing `data` with the digest appropriate for `algorithm`.
    /// 2. Performing the asymmetric signing operation (RSA PKCS1-v1.5 or ECDSA).
    /// 3. Returning, for RSA, the PKCS #1 v1.5 signature octets and, for
    ///    ECDSA, the ASN.1 DER `ECDSA-Sig-Value` (what OpenSSL, PKCS #11
    ///    wrappers and the cloud KMS APIs return). The XMLDSig layer converts
    ///    ECDSA to `r ‖ s` (XMLDSig 1.1 §6.4.3); any other encoding fails
    ///    signing.
    ///
    /// The caller (XMLDSig pipeline) passes the canonical `ds:SignedInfo` bytes
    /// as `data`.  No pre-hashing is performed by the caller.
    fn sign(&self, data: &[u8], algorithm: SignatureAlgorithm) -> Result<Vec<u8>>;

    /// DER-encoded X.509 certificate for the public key corresponding to this
    /// provider's private key.  Used to populate `<ds:X509Certificate>` and
    /// (for RSA keys) `<ds:RSAKeyValue>` in the generated `<ds:KeyInfo>`.
    fn certificate_der(&self) -> Result<Vec<u8>>;

    /// Preferred signing algorithm for this provider.
    ///
    /// The XMLDSig builder uses this to choose the `<ds:SignatureMethod>`
    /// algorithm URI. Reference digests are SHA-256 whatever this returns.
    fn preferred_algorithm(&self) -> SignatureAlgorithm;
}

// ---------------------------------------------------------------------------
// PemSigningKeyProvider — default in-memory implementation
// ---------------------------------------------------------------------------

/// In-memory PEM-backed signing key provider.
///
/// Parses RSA or EC private key PEM material once at construction time and
/// caches the `PKey<Private>` and `X509` objects for reuse across many
/// signing operations.  Private key bytes are zeroized on drop.
///
/// This is the default implementation for deployments that do not require HSM
/// integration.  For PCI-DSS / HIPAA / eIDAS regulated environments, replace
/// with a PKCS#11 or cloud-KMS backed implementation.
pub struct PemSigningKeyProvider {
    key: PKey<Private>,
    cert: X509,
    preferred: SignatureAlgorithm,
    /// Original PEM bytes kept for zeroize-on-drop.
    key_pem: Vec<u8>,
}

impl std::fmt::Debug for PemSigningKeyProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PemSigningKeyProvider")
            .field("algorithm", &self.preferred)
            .finish_non_exhaustive()
    }
}

impl Drop for PemSigningKeyProvider {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.key_pem.zeroize();
    }
}

impl PemSigningKeyProvider {
    /// Parse and validate an RSA or EC private key + X.509 certificate PEM pair.
    ///
    /// Validates that:
    /// - Both PEM blobs are well-formed.
    /// - The certificate's public key matches the private key.
    ///
    /// # Errors
    ///
    /// Returns `ErrorCode::SecurityVerificationFailed` if either PEM is
    /// malformed or if the public key of the certificate does not match the
    /// private key.
    pub fn from_pem(key_pem: &[u8], cert_pem: &[u8]) -> Result<Self> {
        let ctx = || ErrorContext::new("signing_key_provider_from_pem");

        let key = PKey::private_key_from_pem(key_pem).map_err(|_err| {
            AsxError::new(
                ErrorCode::SecurityVerificationFailed,
                "signing key PEM is not a valid private key (RSA or EC)",
                ctx(),
            )
        })?;

        let cert = X509::from_pem(cert_pem).map_err(|_err| {
            AsxError::new(
                ErrorCode::SecurityVerificationFailed,
                "signing certificate PEM is not a valid X.509 certificate",
                ctx(),
            )
        })?;

        // Validate public key match.
        let cert_pubkey = cert.public_key().map_err(|_err| {
            AsxError::new(
                ErrorCode::SecurityVerificationFailed,
                "signing certificate does not contain a usable public key",
                ctx(),
            )
        })?;
        if !key.public_eq(&cert_pubkey) {
            return Err(AsxError::new(
                ErrorCode::SecurityVerificationFailed,
                "signing certificate public key does not match the private key",
                ctx(),
            ));
        }

        let preferred = SignatureAlgorithm::from_pkey(&key).ok_or_else(|| {
            AsxError::new(
                ErrorCode::SecurityVerificationFailed,
                "signing key type is not supported (use RSA or EC P-256/P-384/P-521)",
                ctx(),
            )
        })?;

        Ok(Self {
            key,
            cert,
            preferred,
            key_pem: key_pem.to_vec(),
        })
    }

    /// A provider over an already-parsed key and certificate (the pre-parsed
    /// signing path). The certificate must carry the key's public half.
    #[cfg(feature = "as4")]
    pub(crate) fn from_parts(key: PKey<Private>, cert: X509) -> Result<Self> {
        let ctx = || ErrorContext::new("signing_key_provider_from_parts");
        let cert_pubkey = cert.public_key().map_err(|_err| {
            AsxError::new(
                ErrorCode::SecurityVerificationFailed,
                "signing certificate does not contain a usable public key",
                ctx(),
            )
        })?;
        if !key.public_eq(&cert_pubkey) {
            return Err(AsxError::new(
                ErrorCode::SecurityVerificationFailed,
                "signing certificate public key does not match the private key",
                ctx(),
            ));
        }
        let preferred = SignatureAlgorithm::from_pkey(&key).ok_or_else(|| {
            AsxError::new(
                ErrorCode::SecurityVerificationFailed,
                "XMLDSig signing key type is not supported; use an RSA or EC key \
                 (P-256, P-384, P-521, brainpoolP256r1, …)",
                ctx(),
            )
        })?;
        Ok(Self {
            key,
            cert,
            preferred,
            key_pem: Vec::new(),
        })
    }
}

impl SigningKeyProvider for PemSigningKeyProvider {
    fn sign(&self, data: &[u8], algorithm: SignatureAlgorithm) -> Result<Vec<u8>> {
        let mut signer = Signer::new(algorithm.message_digest(), &self.key).map_err(|_err| {
            AsxError::new(
                ErrorCode::SecurityVerificationFailed,
                "failed to initialize XMLDSig signer",
                ErrorContext::new("pem_signing_key_provider_sign"),
            )
        })?;
        signer.update(data).map_err(|_err| {
            AsxError::new(
                ErrorCode::SecurityVerificationFailed,
                "failed to feed data to XMLDSig signer",
                ErrorContext::new("pem_signing_key_provider_sign"),
            )
        })?;
        signer.sign_to_vec().map_err(|_err| {
            AsxError::new(
                ErrorCode::SecurityVerificationFailed,
                "XMLDSig signing operation failed",
                ErrorContext::new("pem_signing_key_provider_sign"),
            )
        })
    }

    fn certificate_der(&self) -> Result<Vec<u8>> {
        self.cert.to_der().map_err(|_err| {
            AsxError::new(
                ErrorCode::SecurityVerificationFailed,
                "failed to DER-encode signing certificate",
                ErrorContext::new("pem_signing_key_provider_cert_der"),
            )
        })
    }

    fn preferred_algorithm(&self) -> SignatureAlgorithm {
        self.preferred
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl::asn1::Asn1Time;
    use openssl::ec::{EcGroup, EcKey};
    use openssl::hash::MessageDigest;
    use openssl::nid::Nid;
    use openssl::pkey::PKey;
    use openssl::rsa::Rsa;
    use openssl::x509::{X509Builder, X509NameBuilder};

    fn gen_rsa_pem_pair() -> (Vec<u8>, Vec<u8>) {
        let rsa = Rsa::generate(2048).unwrap();
        let pkey = PKey::from_rsa(rsa).unwrap();
        let key_pem = pkey.private_key_to_pem_pkcs8().unwrap();

        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", "test").unwrap();
        let name = name.build();

        let mut builder = X509Builder::new().unwrap();
        builder.set_subject_name(&name).unwrap();
        builder.set_issuer_name(&name).unwrap();
        builder.set_pubkey(&pkey).unwrap();
        builder
            .set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        builder
            .set_not_after(&Asn1Time::days_from_now(365).unwrap())
            .unwrap();
        builder.sign(&pkey, MessageDigest::sha256()).unwrap();
        let cert_pem = builder.build().to_pem().unwrap();

        (key_pem, cert_pem)
    }

    fn gen_ec_pem_pair() -> (Vec<u8>, Vec<u8>) {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let ec = EcKey::generate(&group).unwrap();
        let pkey = PKey::from_ec_key(ec).unwrap();
        let key_pem = pkey.private_key_to_pem_pkcs8().unwrap();

        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", "test-ec").unwrap();
        let name = name.build();

        let mut builder = X509Builder::new().unwrap();
        builder.set_subject_name(&name).unwrap();
        builder.set_issuer_name(&name).unwrap();
        builder.set_pubkey(&pkey).unwrap();
        builder
            .set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        builder
            .set_not_after(&Asn1Time::days_from_now(365).unwrap())
            .unwrap();
        builder.sign(&pkey, MessageDigest::sha256()).unwrap();
        let cert_pem = builder.build().to_pem().unwrap();

        (key_pem, cert_pem)
    }

    #[test]
    fn rsa_pem_provider_round_trips() {
        let (key_pem, cert_pem) = gen_rsa_pem_pair();
        let provider = PemSigningKeyProvider::from_pem(&key_pem, &cert_pem).unwrap();
        assert_eq!(
            provider.preferred_algorithm(),
            SignatureAlgorithm::RsaSha256
        );
        let sig = provider
            .sign(b"hello world", SignatureAlgorithm::RsaSha256)
            .unwrap();
        assert!(!sig.is_empty());
        let der = provider.certificate_der().unwrap();
        assert!(!der.is_empty());
    }

    #[test]
    fn ec_pem_provider_round_trips() {
        let (key_pem, cert_pem) = gen_ec_pem_pair();
        let provider = PemSigningKeyProvider::from_pem(&key_pem, &cert_pem).unwrap();
        assert_eq!(
            provider.preferred_algorithm(),
            SignatureAlgorithm::EcdsaSha256
        );
        let sig = provider
            .sign(b"test data", SignatureAlgorithm::EcdsaSha256)
            .unwrap();
        assert!(!sig.is_empty());
    }

    #[test]
    fn mismatched_cert_key_is_rejected() {
        let (key_pem_a, _) = gen_rsa_pem_pair();
        let (_, cert_pem_b) = gen_rsa_pem_pair();
        let err = PemSigningKeyProvider::from_pem(&key_pem_a, &cert_pem_b).unwrap_err();
        assert_eq!(err.code, ErrorCode::SecurityVerificationFailed);
        assert!(err.message.contains("does not match"));
    }

    #[test]
    fn algorithm_uri_matches_the_rfc_9231_identifiers() {
        assert_eq!(
            SignatureAlgorithm::RsaSha256.algorithm_uri(),
            "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
        );
        assert_eq!(
            SignatureAlgorithm::EcdsaSha256.algorithm_uri(),
            "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"
        );
    }

    #[test]
    fn sign_produces_verifiable_signature() {
        let (key_pem, cert_pem) = gen_rsa_pem_pair();
        let provider = PemSigningKeyProvider::from_pem(&key_pem, &cert_pem).unwrap();
        let data = b"canonical signed info bytes";
        let sig = provider.sign(data, SignatureAlgorithm::RsaSha256).unwrap();

        // Verify using the provider's own certificate.
        let cert_der = provider.certificate_der().unwrap();
        let cert = openssl::x509::X509::from_der(&cert_der).unwrap();
        let pubkey = cert.public_key().unwrap();
        let mut verifier = openssl::sign::Verifier::new(MessageDigest::sha256(), &pubkey).unwrap();
        verifier.update(data).unwrap();
        assert!(verifier.verify(&sig).unwrap(), "signature must verify");
    }

    #[test]
    fn sign_with_sha384_produces_verifiable_signature() {
        let (key_pem, cert_pem) = gen_rsa_pem_pair();
        let provider = PemSigningKeyProvider::from_pem(&key_pem, &cert_pem).unwrap();
        let data = b"sha384 test payload";
        let sig = provider.sign(data, SignatureAlgorithm::RsaSha384).unwrap();

        let cert_der = provider.certificate_der().unwrap();
        let cert = openssl::x509::X509::from_der(&cert_der).unwrap();
        let pubkey = cert.public_key().unwrap();
        let mut verifier = openssl::sign::Verifier::new(MessageDigest::sha384(), &pubkey).unwrap();
        verifier.update(data).unwrap();
        assert!(verifier.verify(&sig).unwrap());
    }
}
