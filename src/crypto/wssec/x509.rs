use openssl::bn::BigNum;
use openssl::pkey::PKey;
use openssl::rsa::Rsa;
use openssl::stack::Stack;
use openssl::x509::store::X509StoreBuilder;
use openssl::x509::{X509, X509Crl, X509StoreContext, X509StoreContextRef};
use sha2::{Digest, Sha256};
use x509_parser::prelude::{FromDer, X509Certificate};
use x509_parser::public_key::PublicKey;
use x509_parser::time::ASN1Time;

use super::RevocationPolicy;
use super::ocsp::{CertOcspOutcome, is_revoked, validate_crls, validate_ocsp_status};
use crate::core::{AsxError, ErrorCode, ErrorContext, Result};

pub fn validate_certificate_chain(
    x509_certificates_der: &[Vec<u8>],
    revocation_policy: &RevocationPolicy<'_>,
) -> Result<CertOcspOutcome> {
    validate_pkix_chain_and_revocation(x509_certificates_der, revocation_policy)
}

pub(crate) fn validate_pkix_chain_and_revocation(
    x509_certificates_der: &[Vec<u8>],
    revocation_policy: &RevocationPolicy<'_>,
) -> Result<CertOcspOutcome> {
    if revocation_policy.trust_anchor_pems.is_empty() {
        return Err(AsxError::new(
            ErrorCode::SecurityVerificationFailed,
            "PKIX validation requires at least one trust anchor",
            ErrorContext::new("wssec_verify_signature_value"),
        ));
    }

    let leaf_der = x509_certificates_der.first().ok_or_else(|| {
        AsxError::new(
            ErrorCode::SecurityVerificationFailed,
            "PKIX validation requires an X509 certificate in KeyInfo",
            ErrorContext::new("wssec_verify_signature_value"),
        )
    })?;

    let leaf = X509::from_der(leaf_der).map_err(|err| {
        AsxError::new(
            ErrorCode::SecurityVerificationFailed,
            format!("failed to parse signer certificate for PKIX validation: {err}"),
            ErrorContext::new("wssec_verify_signature_value"),
        )
    })?;

    let mut intermediates = Stack::new().map_err(|err| {
        AsxError::new(
            ErrorCode::SecurityVerificationFailed,
            format!("failed to initialize intermediate certificate stack: {err}"),
            ErrorContext::new("wssec_verify_signature_value"),
        )
    })?;
    for cert_der in x509_certificates_der.iter().skip(1) {
        let cert = X509::from_der(cert_der).map_err(|err| {
            AsxError::new(
                ErrorCode::SecurityVerificationFailed,
                format!("failed to parse intermediate certificate for PKIX validation: {err}"),
                ErrorContext::new("wssec_verify_signature_value"),
            )
        })?;
        intermediates.push(cert).map_err(|err| {
            AsxError::new(
                ErrorCode::SecurityVerificationFailed,
                format!("failed to register intermediate certificate: {err}"),
                ErrorContext::new("wssec_verify_signature_value"),
            )
        })?;
    }

    // Collect trust-anchor certs for CRL validation (needed separately from the store).
    let mut trust_anchor_certs: Vec<X509>;
    if let Some(ref pre) = revocation_policy.pre_parsed_trust_anchors {
        trust_anchor_certs = pre.clone();
    } else {
        trust_anchor_certs = Vec::new();
        for pem in revocation_policy.trust_anchor_pems {
            let certs = X509::stack_from_pem(pem.as_bytes()).map_err(|err| {
                AsxError::new(
                    ErrorCode::SecurityVerificationFailed,
                    format!("invalid trust-anchor certificate PEM: {err}"),
                    ErrorContext::new("wssec_verify_signature_value"),
                )
            })?;
            trust_anchor_certs.extend(certs);
        }
    }

    // Use the pre-built X509Store from CertHandle cache when available.
    // Building a store is O(n_anchors) OpenSSL allocations; on the hot receive
    // path this is the single most expensive per-message allocation.
    let fresh_store: Option<openssl::x509::store::X509Store>;
    let store: &openssl::x509::store::X509StoreRef =
        if let Some(ref pre) = revocation_policy.pre_built_x509_store {
            &**pre
        } else {
            let mut builder = X509StoreBuilder::new().map_err(|err| {
                AsxError::new(
                    ErrorCode::SecurityVerificationFailed,
                    format!("failed to initialize PKIX trust store: {err}"),
                    ErrorContext::new("wssec_verify_signature_value"),
                )
            })?;
            for cert in &trust_anchor_certs {
                builder.add_cert(cert.clone()).map_err(|err| {
                    AsxError::new(
                        ErrorCode::SecurityVerificationFailed,
                        format!("failed to add trust-anchor certificate: {err}"),
                        ErrorContext::new("wssec_verify_signature_value"),
                    )
                })?;
            }
            fresh_store = Some(builder.build());
            fresh_store.as_ref().unwrap()
        };

    let mut crls = Vec::new();
    for pem in revocation_policy.revocation_crl_pems {
        let crl = X509Crl::from_pem(pem.as_bytes()).map_err(|err| {
            AsxError::new(
                ErrorCode::SecurityVerificationFailed,
                format!("invalid revocation CRL PEM: {err}"),
                ErrorContext::new("wssec_verify_signature_value"),
            )
        })?;
        crls.push(crl);
    }

    validate_crls(&crls, &intermediates, &trust_anchor_certs)?;

    let mut context = X509StoreContext::new().map_err(|err| {
        AsxError::new(
            ErrorCode::SecurityVerificationFailed,
            format!("failed to initialize PKIX validation context: {err}"),
            ErrorContext::new("wssec_verify_signature_value"),
        )
    })?;

    let valid = context
        .init(
            store,
            &leaf,
            &intermediates,
            X509StoreContextRef::verify_cert,
        )
        .map_err(|err| {
            AsxError::new(
                ErrorCode::SecurityVerificationFailed,
                format!("PKIX certificate validation failed: {err}"),
                ErrorContext::new("wssec_verify_signature_value"),
            )
        })?;

    if !valid {
        return Err(AsxError::new(
            ErrorCode::SecurityVerificationFailed,
            "PKIX certificate validation did not produce a trusted chain",
            ErrorContext::new("wssec_verify_signature_value"),
        ));
    }

    if !crls.is_empty() {
        if is_revoked(&leaf, &crls)? {
            return Err(AsxError::new(
                ErrorCode::SecurityVerificationFailed,
                "signer certificate is revoked by configured CRL",
                ErrorContext::new("wssec_verify_signature_value"),
            ));
        }

        for intermediate in intermediates.iter() {
            if is_revoked(intermediate, &crls)? {
                return Err(AsxError::new(
                    ErrorCode::SecurityVerificationFailed,
                    "intermediate certificate is revoked by configured CRL",
                    ErrorContext::new("wssec_verify_signature_value"),
                ));
            }
        }
    }

    let ocsp_outcome = validate_ocsp_status(
        &leaf,
        &intermediates,
        &trust_anchor_certs,
        store,
        revocation_policy,
    )?;

    // A Revoked outcome from OCSP is a hard security failure regardless of policy.
    if let CertOcspOutcome::Revoked { .. } = &ocsp_outcome {
        return Err(AsxError::new(
            ErrorCode::SecurityVerificationFailed,
            "OCSP response reports signer certificate revoked",
            ErrorContext::new("wssec_verify_signature_value"),
        ));
    }

    Ok(ocsp_outcome)
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

pub(crate) fn normalize_fingerprint(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }

    let normalized: String = trimmed
        .chars()
        .filter(char::is_ascii_hexdigit)
        .map(|c| c.to_ascii_lowercase())
        .collect();

    if normalized.is_empty() {
        None
    } else {
        Some(normalized)
    }
}

pub(crate) fn sha256_hex_lower(input: &[u8]) -> String {
    let digest = Sha256::digest(input);
    let mut out = String::with_capacity(digest.len() * 2);
    for b in digest {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

fn secure_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (lhs, rhs) in a.iter().zip(b.iter()) {
        diff |= lhs ^ rhs;
    }
    diff == 0
}
