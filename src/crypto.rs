#[cfg(feature = "as2")]
pub mod as2_smime;
#[cfg(feature = "compression")]
pub mod compression;
#[cfg(any(feature = "as2", feature = "as4", feature = "async-ocsp"))]
pub mod ocsp_client;
#[cfg(any(feature = "as2", feature = "as4", feature = "async-ocsp"))]
pub mod ocsp_discovery;
/// Signing key abstraction — `SigningKeyProvider` trait + `PemSigningKeyProvider` default.
#[cfg(any(feature = "as2", feature = "as4"))]
pub mod signing;
#[cfg(feature = "as4")]
pub mod soap_builder;
#[cfg(any(feature = "as2", feature = "as4"))]
pub mod wssec;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CryptoPolicy {
    pub require_signing: bool,
    pub require_encryption: bool,
}

impl Default for CryptoPolicy {
    fn default() -> Self {
        Self {
            require_signing: true,
            require_encryption: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateRef {
    pub subject: String,
    pub fingerprint_sha256: String,
}

impl CertificateRef {
    pub fn new(subject: impl Into<String>, fingerprint_sha256: impl Into<String>) -> Self {
        Self {
            subject: subject.into(),
            fingerprint_sha256: fingerprint_sha256.into(),
        }
    }
}
