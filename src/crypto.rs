/// The algorithm registry: the one URI table.
#[cfg(any(feature = "as2", feature = "as4"))]
pub(crate) mod alg;
#[cfg(feature = "as2")]
pub mod as2_smime;
#[cfg(any(feature = "as2", feature = "as4"))]
pub mod compression;
pub mod fingerprint;
/// Signing key abstraction — `SigningKeyProvider` trait + `PemSigningKeyProvider` default.
#[cfg(any(feature = "as2", feature = "as4"))]
pub mod signing;
#[cfg(feature = "as4")]
pub mod soap_builder;
#[cfg(any(feature = "as2", feature = "as4"))]
pub mod wssec;

pub use fingerprint::CertFingerprint;
