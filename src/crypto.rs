#[cfg(feature = "as2")]
pub mod as2_smime;
// Always available: a receiver must be able to *detect* a compressed payload and
// fail with a clear message even when the `compression` feature is off.
pub mod compression;
pub mod fingerprint;
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

pub use fingerprint::CertFingerprint;
