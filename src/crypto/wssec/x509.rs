// Functions below are used exclusively by wssec::verify (as4-only); suppress
// dead-code warnings when the as4 feature is not enabled.
#![cfg_attr(not(feature = "as4"), allow(dead_code))]

use openssl::bn::BigNum;
use openssl::pkey::PKey;
use openssl::rsa::Rsa;
use openssl::stack::Stack;
use openssl::x509::store::X509StoreBuilder;
use openssl::x509::{X509, X509StoreContext};
use sha2::{Digest, Sha256};
use x509_parser::prelude::{FromDer, X509Certificate};
use x509_parser::public_key::PublicKey;
use x509_parser::time::ASN1Time;

use super::ChainPolicy;
use crate::core::{AsxError, ErrorCode, ErrorContext, Result};

/// Validate `x509_certificates_der` (signer first, then intermediates)
/// offline against `policy` and return the certification path OpenSSL
/// built, signer first and trust anchor last (DER). No CRL or OCSP is
/// consulted: revocation is `crate::revocation`'s, after the signature.
pub fn validate_certificate_chain(
    x509_certificates_der: &[Vec<u8>],
    policy: &ChainPolicy<'_>,
) -> Result<Vec<Vec<u8>>> {
    let chain = validate_chain_offline(x509_certificates_der, policy)?;
    chain
        .path
        .iter()
        .map(|c| {
            c.to_der()
                .map_err(|e| pkix_error(format!("unencodable certificate: {e}")))
        })
        .collect()
}

/// A certification path that validated offline: signer first, trust anchor
/// last, as OpenSSL built it. The caller checks its revocation after the
/// signature and the sender rule.
#[derive(Clone)]
pub(crate) struct ValidatedChain {
    pub(crate) path: Vec<X509>,
}

impl std::fmt::Debug for ValidatedChain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ValidatedChain")
            .field("path", &self.path.len())
            .finish()
    }
}

fn pkix_error(message: String) -> AsxError {
    AsxError::new(
        ErrorCode::SecurityVerificationFailed,
        message,
        ErrorContext::new("wssec_verify_signature_value"),
    )
}

/// PKIX validation, offline: the signer (first certificate) must chain
/// through the supplied intermediates to a configured trust anchor. No CRL
/// or OCSP is consulted and nothing is fetched.
pub(crate) fn validate_chain_offline(
    x509_certificates_der: &[Vec<u8>],
    policy: &ChainPolicy<'_>,
) -> Result<ValidatedChain> {
    if policy.trust_anchor_pems.is_empty() {
        return Err(pkix_error(
            "PKIX validation requires at least one trust anchor".to_string(),
        ));
    }

    let leaf_der = x509_certificates_der.first().ok_or_else(|| {
        pkix_error("PKIX validation requires an X509 certificate in KeyInfo".to_string())
    })?;
    let leaf = X509::from_der(leaf_der).map_err(|err| {
        pkix_error(format!(
            "failed to parse signer certificate for PKIX validation: {err}"
        ))
    })?;

    let mut intermediates = Stack::new().map_err(|err| {
        pkix_error(format!(
            "failed to initialize intermediate certificate stack: {err}"
        ))
    })?;
    for cert_der in x509_certificates_der.iter().skip(1) {
        let cert = X509::from_der(cert_der).map_err(|err| {
            pkix_error(format!(
                "failed to parse intermediate certificate for PKIX validation: {err}"
            ))
        })?;
        intermediates.push(cert).map_err(|err| {
            pkix_error(format!(
                "failed to register intermediate certificate: {err}"
            ))
        })?;
    }

    // Use the pre-built X509Store from the CertHandle cache when available:
    // building a store is O(n_anchors) OpenSSL allocations, the single most
    // expensive per-message allocation on the hot receive path.
    let store = if let Some(ref pre) = policy.pre_built_x509_store {
        std::sync::Arc::clone(pre)
    } else {
        let trust_anchor_certs: Vec<X509> = if let Some(ref pre) = policy.pre_parsed_trust_anchors {
            pre.clone()
        } else {
            let mut certs = Vec::new();
            for pem in policy.trust_anchor_pems {
                certs.extend(X509::stack_from_pem(pem.as_bytes()).map_err(|err| {
                    pkix_error(format!("invalid trust-anchor certificate PEM: {err}"))
                })?);
            }
            certs
        };
        let mut builder = X509StoreBuilder::new()
            .map_err(|err| pkix_error(format!("failed to initialize PKIX trust store: {err}")))?;
        for cert in &trust_anchor_certs {
            builder.add_cert(cert.clone()).map_err(|err| {
                pkix_error(format!("failed to add trust-anchor certificate: {err}"))
            })?;
        }
        std::sync::Arc::new(builder.build())
    };

    let mut context = X509StoreContext::new().map_err(|err| {
        pkix_error(format!(
            "failed to initialize PKIX validation context: {err}"
        ))
    })?;
    let (valid, path) = context
        .init(&store, &leaf, &intermediates, |ctx| {
            let valid = ctx.verify_cert()?;
            let path: Vec<X509> = ctx
                .chain()
                .map(|chain| chain.iter().map(|c| c.to_owned()).collect())
                .unwrap_or_default();
            Ok((valid, path))
        })
        .map_err(|err| pkix_error(format!("PKIX certificate validation failed: {err}")))?;
    if !valid || path.is_empty() {
        return Err(pkix_error(
            "PKIX certificate validation did not produce a trusted chain".to_string(),
        ));
    }

    Ok(ValidatedChain { path })
}

/// Minimum accepted RSA modulus size in bits.
///
/// 2048 bits is the floor mandated by NIST SP 800-131A / BSI TR-02102-2 for
/// signatures valid beyond 2030; 1024-bit RSA is broken for long-lived B2B
/// non-repudiation and is rejected.
const MIN_RSA_MODULUS_BITS: usize = 2048;

/// Effective bit length of a big-endian unsigned modulus (leading zero bytes and
/// the high zero bits of the top non-zero byte do not count).
fn unsigned_bigint_bits(bytes: &[u8]) -> usize {
    let first_nonzero = bytes.iter().position(|&b| b != 0);
    match first_nonzero {
        None => 0,
        Some(idx) => {
            let remaining = &bytes[idx..];
            let top = remaining[0];
            (remaining.len() - 1) * 8 + (8 - top.leading_zeros() as usize)
        }
    }
}

/// Validate an end-entity certificate DER for validity period, CA flag, KeyUsage, and EKU.
pub(crate) fn validate_x509_certificate(cert_der: &[u8]) -> Result<()> {
    let cert = parse_x509_certificate(cert_der)?;

    if !cert.validity().is_valid_at(ASN1Time::now()) {
        return Err(AsxError::new(
            ErrorCode::SecurityVerificationFailed,
            "X509 certificate is outside validity period",
            ErrorContext::new("wssec_verify_signature_value"),
        ));
    }

    // Reject cryptographically weak signing keys. Only RSA has a realistic weak
    // variant in this profile (1024-bit); all supported EC curves are ≥ 256-bit.
    if let Ok(PublicKey::RSA(rsa)) = cert.public_key().parsed() {
        let bits = unsigned_bigint_bits(rsa.modulus);
        if bits < MIN_RSA_MODULUS_BITS {
            return Err(AsxError::new(
                ErrorCode::SecurityVerificationFailed,
                format!(
                    "X509 signing certificate RSA key is too weak: {bits}-bit modulus \
                     (minimum {MIN_RSA_MODULUS_BITS}-bit required)"
                ),
                ErrorContext::new("wssec_verify_signature_value"),
            ));
        }
    }

    if let Some(basic_constraints) = cert.basic_constraints().map_err(|err| {
        AsxError::new(
            ErrorCode::SecurityVerificationFailed,
            format!("failed to read certificate BasicConstraints: {err}"),
            ErrorContext::new("wssec_verify_signature_value"),
        )
    })? && basic_constraints.value.ca
    {
        return Err(AsxError::new(
            ErrorCode::SecurityVerificationFailed,
            "X509 certificate must be end-entity (CA=false) for WS-Security message signing",
            ErrorContext::new("wssec_verify_signature_value"),
        ));
    }

    if let Some(key_usage) = cert.key_usage().map_err(|err| {
        AsxError::new(
            ErrorCode::SecurityVerificationFailed,
            format!("failed to read certificate KeyUsage: {err}"),
            ErrorContext::new("wssec_verify_signature_value"),
        )
    })? {
        let usage = key_usage.value;
        if !usage.digital_signature() {
            return Err(AsxError::new(
                ErrorCode::SecurityVerificationFailed,
                "X509 certificate KeyUsage does not permit digitalSignature",
                ErrorContext::new("wssec_verify_signature_value"),
            ));
        }
        if usage.key_cert_sign() {
            return Err(AsxError::new(
                ErrorCode::SecurityVerificationFailed,
                "X509 certificate KeyUsage is CA-oriented (keyCertSign) and not valid for end-entity message signing",
                ErrorContext::new("wssec_verify_signature_value"),
            ));
        }
    }

    if let Some(eku) = cert.extended_key_usage().map_err(|err| {
        AsxError::new(
            ErrorCode::SecurityVerificationFailed,
            format!("failed to read certificate ExtendedKeyUsage: {err}"),
            ErrorContext::new("wssec_verify_signature_value"),
        )
    })? {
        let eku = eku.value;
        if !eku.any && !eku.email_protection && !eku.client_auth {
            return Err(AsxError::new(
                ErrorCode::SecurityVerificationFailed,
                "X509 certificate ExtendedKeyUsage does not permit signer use for WS-Security",
                ErrorContext::new("wssec_verify_signature_value"),
            ));
        }
        if eku.time_stamping || eku.ocsp_signing || eku.server_auth {
            return Err(AsxError::new(
                ErrorCode::SecurityVerificationFailed,
                "X509 certificate ExtendedKeyUsage is incompatible with WS-Security signer use",
                ErrorContext::new("wssec_verify_signature_value"),
            ));
        }
    }

    Ok(())
}

pub(crate) fn parse_x509_certificate(cert_der: &[u8]) -> Result<X509Certificate<'_>> {
    let (_, cert): (_, X509Certificate<'_>) =
        X509Certificate::from_der(cert_der).map_err(|err| {
            AsxError::new(
                ErrorCode::SecurityVerificationFailed,
                format!("failed to parse X509Certificate from KeyInfo: {err}"),
                ErrorContext::new("wssec_verify_signature_value"),
            )
        })?;
    Ok(cert)
}

pub(crate) fn validate_cert_public_key_matches_rsa_keyvalue(
    cert_der: &[u8],
    rsa_modulus: &[u8],
    rsa_exponent: &[u8],
) -> Result<()> {
    let cert = parse_x509_certificate(cert_der)?;
    let parsed_key = cert.public_key().parsed().map_err(|err| {
        AsxError::new(
            ErrorCode::SecurityVerificationFailed,
            format!("failed to parse certificate public key: {err}"),
            ErrorContext::new("wssec_verify_signature_value"),
        )
    })?;

    let (cert_modulus, cert_exponent) = match parsed_key {
        PublicKey::RSA(rsa) => (rsa.modulus, rsa.exponent),
        _ => {
            return Err(AsxError::new(
                ErrorCode::InteropViolation,
                "unsupported certificate public key type for RSA SignatureMethod",
                ErrorContext::new("wssec_verify_signature_value"),
            ));
        }
    };

    if !equal_unsigned_bigint(cert_modulus, rsa_modulus)
        || !equal_unsigned_bigint(cert_exponent, rsa_exponent)
    {
        return Err(AsxError::new(
            ErrorCode::SecurityVerificationFailed,
            "X509 certificate public key does not match ds:RSAKeyValue",
            ErrorContext::new("wssec_verify_signature_value"),
        ));
    }

    Ok(())
}

pub(crate) fn extract_rsa_keyvalue_from_cert(cert_der: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let cert = parse_x509_certificate(cert_der)?;
    let parsed_key = cert.public_key().parsed().map_err(|err| {
        AsxError::new(
            ErrorCode::SecurityVerificationFailed,
            format!("failed to parse certificate public key: {err}"),
            ErrorContext::new("wssec_verify_signature_value"),
        )
    })?;

    match parsed_key {
        PublicKey::RSA(rsa) => Ok((rsa.modulus.to_vec(), rsa.exponent.to_vec())),
        _ => Err(AsxError::new(
            ErrorCode::InteropViolation,
            "unsupported certificate public key type for RSA SignatureMethod",
            ErrorContext::new("wssec_verify_signature_value"),
        )),
    }
}

/// Build a PKey from raw RSA modulus and exponent bytes (big-endian, unsigned).
pub(crate) fn pkey_from_rsa_components(
    modulus: &[u8],
    exponent: &[u8],
) -> Result<PKey<openssl::pkey::Public>> {
    let n = BigNum::from_slice(modulus).map_err(|err| {
        AsxError::new(
            ErrorCode::ParseFailed,
            format!("invalid RSA modulus in KeyInfo: {err}"),
            ErrorContext::new("wssec_verify_signature_value"),
        )
    })?;
    let e = BigNum::from_slice(exponent).map_err(|err| {
        AsxError::new(
            ErrorCode::ParseFailed,
            format!("invalid RSA exponent in KeyInfo: {err}"),
            ErrorContext::new("wssec_verify_signature_value"),
        )
    })?;
    let rsa_pub = Rsa::from_public_components(n, e).map_err(|err| {
        AsxError::new(
            ErrorCode::ParseFailed,
            format!("invalid RSA KeyValue in KeyInfo: {err}"),
            ErrorContext::new("wssec_verify_signature_value"),
        )
    })?;
    PKey::from_rsa(rsa_pub).map_err(|err| {
        AsxError::new(
            ErrorCode::ParseFailed,
            format!("failed to build PKey from RSA modulus/exponent: {err}"),
            ErrorContext::new("wssec_verify_signature_value"),
        )
    })
}

pub(crate) fn equal_unsigned_bigint(a: &[u8], b: &[u8]) -> bool {
    let a = trim_leading_zeroes(a);
    let b = trim_leading_zeroes(b);
    secure_eq(a, b)
}

pub(crate) fn trim_leading_zeroes(bytes: &[u8]) -> &[u8] {
    if bytes.is_empty() {
        return bytes;
    }
    let mut idx = 0usize;
    while idx + 1 < bytes.len() && bytes[idx] == 0 {
        idx += 1;
    }
    &bytes[idx..]
}

pub(crate) fn sha256_hex_lower(input: &[u8]) -> String {
    let digest = Sha256::digest(input);
    let mut out = String::with_capacity(digest.len() * 2);
    for b in digest {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

pub(crate) use crate::core::constant_time_eq as secure_eq;

#[cfg(test)]
mod key_strength_tests {
    use super::{MIN_RSA_MODULUS_BITS, unsigned_bigint_bits};

    #[test]
    fn unsigned_bigint_bits_counts_effective_length() {
        assert_eq!(unsigned_bigint_bits(&[]), 0);
        assert_eq!(unsigned_bigint_bits(&[0x00, 0x00]), 0);
        assert_eq!(unsigned_bigint_bits(&[0x01]), 1);
        assert_eq!(unsigned_bigint_bits(&[0xFF]), 8);
        assert_eq!(unsigned_bigint_bits(&[0x00, 0x80]), 8);
        // 2048-bit modulus: 256 bytes with a high bit set in the top byte.
        let mut m2048 = vec![0u8; 256];
        m2048[0] = 0x80;
        assert_eq!(unsigned_bigint_bits(&m2048), 2048);
        // 1024-bit modulus is below the floor.
        let mut m1024 = vec![0u8; 128];
        m1024[0] = 0x80;
        assert!(unsigned_bigint_bits(&m1024) < MIN_RSA_MODULUS_BITS);
    }
}
