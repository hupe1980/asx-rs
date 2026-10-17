//! Certificate fingerprints, as a type rather than a string.
//!
//! A pinned fingerprint is a security control whose failure mode is silent:
//! get the encoding wrong and every message from the partner is refused with
//! "signature does not match", which reads as the counterparty's fault. So the
//! value is computed here rather than by each integrator, and a malformed one
//! is rejected where it is configured instead of where it is used.

use crate::core::{AsxError, ErrorCode, ErrorContext, Result};
use sha2::{Digest, Sha256};
use std::fmt;

/// Number of hex characters in a SHA-256 fingerprint.
const SHA256_HEX_LEN: usize = 64;

/// The SHA-256 fingerprint of an X.509 certificate, over its **DER** encoding.
///
/// This is the value [`SessionContextBuilder::with_fingerprint_sha256`] pins
/// and the form `Partner::signing_cert` pins are kept in. Canonical form is
/// lower-case hex with no separators; [`parse`](Self::parse) accepts the
/// colon-separated upper-case form that `openssl x509 -fingerprint` prints and
/// normalizes it.
///
/// [`SessionContextBuilder::with_fingerprint_sha256`]: crate::core::SessionContextBuilder::with_fingerprint_sha256
///
/// # Computing one
///
/// ```text
/// use asx::crypto::CertFingerprint;
///
/// # fn example(partner_cert_pem: &[u8]) -> asx::Result<()> {
/// let pin = CertFingerprint::from_cert_pem(partner_cert_pem)?;
/// println!("{pin}"); // 64 lower-case hex characters
/// # Ok(())
/// # }
/// ```
///
/// Equivalent to `openssl x509 -in cert.pem -noout -fingerprint -sha256`, with
/// the colons removed and lower-cased.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CertFingerprint(String);

impl CertFingerprint {
    /// Compute the fingerprint of a PEM-encoded certificate.
    ///
    /// # Errors
    ///
    /// [`ErrorCode::InvalidInput`] when the input is not a parseable X.509
    /// certificate. A PEM **bundle** is not accepted: the fingerprint of "the
    /// first certificate in a file" is a guess, and pinning the wrong one of a
    /// chain is the mistake this type exists to prevent — pass the leaf.
    ///
    /// Requires the `crypto` feature, which supplies the X.509 parser. Without
    /// it, [`from_cert_der`](Self::from_cert_der) and [`parse`](Self::parse)
    /// are still available, since neither needs one.
    #[cfg(any(feature = "as2", feature = "as4"))]
    #[cfg_attr(docsrs, doc(cfg(any(feature = "as2", feature = "as4"))))]
    pub fn from_cert_pem(cert_pem: &[u8]) -> Result<Self> {
        let cert = openssl::x509::X509::from_pem(cert_pem).map_err(|err| {
            AsxError::new(
                ErrorCode::InvalidInput,
                format!("not a PEM X.509 certificate: {err}"),
                ErrorContext::new("cert_fingerprint_from_pem"),
            )
        })?;
        let der = cert.to_der().map_err(|err| {
            AsxError::new(
                ErrorCode::InvalidInput,
                format!("certificate could not be re-encoded as DER: {err}"),
                ErrorContext::new("cert_fingerprint_from_pem"),
            )
        })?;
        Ok(Self::from_cert_der(&der))
    }

    /// Compute the fingerprint of a DER-encoded certificate.
    ///
    /// The bytes are hashed as given; this is infallible because there is
    /// nothing to parse. Use [`from_cert_pem`](Self::from_cert_pem) when the
    /// input is PEM, so the certificate is validated first.
    pub fn from_cert_der(cert_der: &[u8]) -> Self {
        let digest = Sha256::digest(cert_der);
        let mut out = String::with_capacity(SHA256_HEX_LEN);
        for byte in digest {
            use fmt::Write as _;
            let _ = write!(out, "{byte:02x}");
        }
        Self(out)
    }

    /// Parse a fingerprint that was written down — from a partner's
    /// onboarding pack, a config file, or `openssl`'s output.
    ///
    /// Separators (`:`, spaces, `-`) are ignored and case is normalized, so
    /// all of these are the same value:
    ///
    /// ```text
    /// use asx::crypto::CertFingerprint;
    /// # fn main() -> asx::Result<()> {
    /// let a = CertFingerprint::parse(
    ///     "AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:\
    ///      AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89",
    /// )?;
    /// let b = CertFingerprint::parse(
    ///     "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
    /// )?;
    /// assert_eq!(a, b);
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`ErrorCode::InvalidInput`] when the value does not hold exactly 64 hex
    /// digits. **This length check is the point.** A truncated or mistyped pin
    /// is otherwise accepted at configuration time and fails at message time as
    /// "signer certificate fingerprint does not match expected fingerprint",
    /// which points the operator at the counterparty instead of at their own
    /// config.
    pub fn parse(value: &str) -> Result<Self> {
        let normalized: String = value
            .chars()
            .filter(char::is_ascii_hexdigit)
            .map(|c| c.to_ascii_lowercase())
            .collect();

        if normalized.len() != SHA256_HEX_LEN {
            return Err(AsxError::new(
                ErrorCode::InvalidInput,
                format!(
                    "a SHA-256 certificate fingerprint has {SHA256_HEX_LEN} hex digits, \
                     this one has {} — check for a truncated or SHA-1 value",
                    normalized.len()
                ),
                ErrorContext::new("cert_fingerprint_parse"),
            ));
        }

        Ok(Self(normalized))
    }

    /// The canonical lower-case hex form, no separators.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for CertFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for CertFingerprint {
    /// Prints the value, which is public information — it is a hash of a
    /// certificate, and the certificate is on the wire.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CertFingerprint({})", self.0)
    }
}

impl std::str::FromStr for CertFingerprint {
    type Err = AsxError;

    fn from_str(s: &str) -> Result<Self> {
        Self::parse(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HEX64: &str = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";

    #[test]
    fn parse_normalizes_separators_and_case() {
        let colons = "AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:\
                      AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89";
        assert_eq!(
            CertFingerprint::parse(colons).expect("parse"),
            CertFingerprint::parse(HEX64).expect("parse")
        );
    }

    /// The check that makes a bad pin a configuration error rather than a
    /// message-time rejection blamed on the counterparty.
    #[test]
    fn parse_rejects_a_truncated_value() {
        let err = CertFingerprint::parse(&HEX64[..40]).expect_err("must reject");
        assert_eq!(err.code, ErrorCode::InvalidInput);
        assert!(
            err.message.contains("64 hex digits"),
            "the error must name the expected length: {}",
            err.message
        );
    }

    #[test]
    fn parse_rejects_a_sha1_fingerprint() {
        // 40 hex digits — what `openssl x509 -fingerprint` prints by default.
        let sha1 = "AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01";
        assert!(CertFingerprint::parse(sha1).is_err());
    }

    #[test]
    fn parse_rejects_empty_and_non_hex() {
        assert!(CertFingerprint::parse("").is_err());
        assert!(CertFingerprint::parse("not-a-fingerprint").is_err());
    }

    #[test]
    fn der_digest_matches_a_known_vector() {
        // SHA-256 of the empty input, the one value that needs no fixture.
        assert_eq!(
            CertFingerprint::from_cert_der(b"").as_str(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn from_cert_pem_rejects_non_certificate_input() {
        let err = CertFingerprint::from_cert_pem(b"-----BEGIN CERTIFICATE-----\nnope\n")
            .expect_err("must reject");
        assert_eq!(err.code, ErrorCode::InvalidInput);
    }
}
