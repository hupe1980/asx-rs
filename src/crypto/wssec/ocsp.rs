use openssl::asn1::Asn1Time;
use openssl::hash::MessageDigest;
use openssl::ocsp::{OcspCertId, OcspCertStatus, OcspFlag, OcspResponse, OcspResponseStatus};
use openssl::stack::Stack;
use openssl::x509::{X509, X509Crl, X509Ref};
use std::time::{SystemTime, UNIX_EPOCH};

use super::RevocationPolicy;
use crate::core::{AsxError, ErrorCode, ErrorContext, OcspFailureMode, OcspMode, Result};
use crate::crypto::ocsp_client;

/// Outcome of an OCSP revocation check.
///
/// `validate_ocsp_status` returns this alongside `Ok(())` so callers can emit
/// observability events (e.g., [`crate::observability::AsxEvent::CertOcspRevoked`])
/// without requiring an `EventBus` deep inside the crypto layer.
///
/// This type is `pub` so that `validate_certificate_chain` (a public API) can
/// include it in its return type while keeping the internal detail well-typed.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CertOcspOutcome {
    /// Certificate confirmed good by OCSP.
    Good,
    /// OCSP was disabled or no responses were provided; revocation not checked.
    Skipped,
    /// No usable OCSP response found; policy determines whether this is fatal.
    NoResponse,
    /// OCSP response returned `Unknown` status for the certificate.
    Unknown { subject_cn: String },
    /// OCSP response confirmed the certificate is revoked.
    Revoked {
        subject_cn: String,
        serial_hex: String,
    },
}

/// Extract a best-effort subject CN string from a certificate.
fn cert_subject_cn(cert: &X509Ref) -> String {
    cert.subject_name()
        .entries_by_nid(openssl::nid::Nid::COMMONNAME)
        .next()
        .and_then(|e| e.data().as_utf8().ok())
        .map(|s| s.to_string())
        .unwrap_or_default()
}

/// Hex-encode the serial number of a certificate.
fn cert_serial_hex(cert: &X509Ref) -> String {
    cert.serial_number()
        .to_bn()
        .ok()
        .and_then(|bn| bn.to_hex_str().ok())
        .map(|s| s.to_lowercase())
        .unwrap_or_default()
}

pub(crate) fn validate_crls(
    crls: &[X509Crl],
    intermediates: &Stack<X509>,
    trust_anchors: &[X509],
) -> Result<()> {
    if crls.is_empty() {
        return Ok(());
    }

    let now = Asn1Time::from_unix(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|err| {
                AsxError::new(
                    ErrorCode::SecurityVerificationFailed,
                    format!("failed to resolve current system time: {err}"),
                    ErrorContext::new("wssec_verify_signature_value"),
                )
            })?
            .as_secs() as i64,
    )
    .map_err(|err| {
        AsxError::new(
            ErrorCode::SecurityVerificationFailed,
            format!("failed to convert system time for CRL validation: {err}"),
            ErrorContext::new("wssec_verify_signature_value"),
        )
    })?;

    for crl in crls {
        if crl
            .last_update()
            .compare(now.as_ref())
            .map_err(|err| {
                AsxError::new(
                    ErrorCode::SecurityVerificationFailed,
                    format!("failed to compare CRL lastUpdate: {err}"),
                    ErrorContext::new("wssec_verify_signature_value"),
                )
            })?
            .is_gt()
        {
            return Err(AsxError::new(
                ErrorCode::SecurityVerificationFailed,
                "CRL lastUpdate is in the future",
                ErrorContext::new("wssec_verify_signature_value"),
            ));
        }

        if let Some(next_update) = crl.next_update()
            && next_update
                .compare(now.as_ref())
                .map_err(|err| {
                    AsxError::new(
                        ErrorCode::SecurityVerificationFailed,
                        format!("failed to compare CRL nextUpdate: {err}"),
                        ErrorContext::new("wssec_verify_signature_value"),
                    )
                })?
                .is_lt()
        {
            return Err(AsxError::new(
                ErrorCode::SecurityVerificationFailed,
                "CRL nextUpdate is in the past",
                ErrorContext::new("wssec_verify_signature_value"),
            ));
        }

        let crl_issuer = crl.issuer_name().to_der().map_err(|err| {
            AsxError::new(
                ErrorCode::SecurityVerificationFailed,
                format!("failed to read CRL issuer: {err}"),
                ErrorContext::new("wssec_verify_signature_value"),
            )
        })?;

        let mut issuer_cert = None;
        for candidate in intermediates.iter() {
            if candidate
                .subject_name()
                .to_der()
                .map(|der| der == crl_issuer)
                .unwrap_or(false)
            {
                issuer_cert = Some(candidate.to_owned());
                break;
            }
        }
        if issuer_cert.is_none() {
            issuer_cert = trust_anchors
                .iter()
                .find(|candidate| {
                    candidate
                        .subject_name()
                        .to_der()
                        .map(|der| der == crl_issuer)
                        .unwrap_or(false)
                })
                .cloned();
        }

        let issuer_cert = issuer_cert.ok_or_else(|| {
            AsxError::new(
                ErrorCode::SecurityVerificationFailed,
                "CRL issuer does not match certificate chain or trust anchors",
                ErrorContext::new("wssec_verify_signature_value"),
            )
        })?;

        let valid_signature = crl
            .verify(
                issuer_cert
                    .public_key()
                    .map_err(|err| {
                        AsxError::new(
                            ErrorCode::SecurityVerificationFailed,
                            format!("failed to extract CRL issuer public key: {err}"),
                            ErrorContext::new("wssec_verify_signature_value"),
                        )
                    })?
                    .as_ref(),
            )
            .map_err(|err| {
                AsxError::new(
                    ErrorCode::SecurityVerificationFailed,
                    format!("failed to verify CRL signature: {err}"),
                    ErrorContext::new("wssec_verify_signature_value"),
                )
            })?;

        if !valid_signature {
            return Err(AsxError::new(
                ErrorCode::SecurityVerificationFailed,
                "CRL signature verification failed",
                ErrorContext::new("wssec_verify_signature_value"),
            ));
        }
    }

    Ok(())
}

pub(crate) fn validate_ocsp_status(
    leaf: &X509Ref,
    intermediates: &Stack<X509>,
    trust_anchors: &[X509],
    store: &openssl::x509::store::X509StoreRef,
    revocation_policy: &RevocationPolicy<'_>,
) -> Result<CertOcspOutcome> {
    let disabled_with_supplied_responses = revocation_policy.ocsp_mode == OcspMode::Disabled
        && (!revocation_policy.stapled_ocsp_responses_der.is_empty()
            || !revocation_policy.responder_ocsp_responses_der.is_empty());

    if revocation_policy.ocsp_mode == OcspMode::Disabled && !disabled_with_supplied_responses {
        return Ok(CertOcspOutcome::Skipped);
    }

    // Guard: an empty namespace silently merges OCSP cache entries across all
    // tenants/partners — only acceptable with OCSP disabled.  Fail-closed here
    // so misconfigured callers see a clear error rather than a cache poisoning
    // window.  Use `RevocationPolicy { ocsp_cache_namespace: session.partner_id(), .. }`
    // (as supplied by `wssec_revocation_policy_from_session`) to isolate entries.
    let needs_responder = matches!(
        revocation_policy.ocsp_mode,
        OcspMode::ResponderOnly | OcspMode::StapledThenResponder
    );
    if needs_responder && revocation_policy.ocsp_cache_namespace.is_empty() {
        return Err(AsxError::new(
            ErrorCode::PolicyViolation,
            "OCSP responder fetching requires a non-empty ocsp_cache_namespace to prevent \
             cross-tenant cache poisoning; supply a session- or partner-scoped identifier",
            ErrorContext::new("wssec_validate_ocsp_status"),
        ));
    }

    let leaf_issuer_der = leaf.issuer_name().to_der().map_err(|err| {
        AsxError::new(
            ErrorCode::SecurityVerificationFailed,
            format!("failed to read signer issuer for OCSP: {err}"),
            ErrorContext::new("wssec_verify_signature_value"),
        )
    })?;

    let mut issuer: Option<X509> = None;
    for candidate in intermediates.iter() {
        if candidate
            .subject_name()
            .to_der()
            .map(|der| der == leaf_issuer_der)
            .unwrap_or(false)
        {
            issuer = Some(candidate.to_owned());
            break;
        }
    }
    if issuer.is_none() {
        issuer = trust_anchors
            .iter()
            .find(|candidate| {
                candidate
                    .subject_name()
                    .to_der()
                    .map(|der| der == leaf_issuer_der)
                    .unwrap_or(false)
            })
            .cloned();
    }

    let Some(issuer) = issuer else {
        return match revocation_policy.ocsp_failure_mode {
            OcspFailureMode::HardFail => Err(AsxError::new(
                ErrorCode::SecurityVerificationFailed,
                "OCSP verification could not resolve signer issuer",
                ErrorContext::new("wssec_verify_signature_value"),
            )),
            OcspFailureMode::SoftFail => Ok(CertOcspOutcome::NoResponse),
        };
    };

    let responder_responses = if needs_responder {
        effective_responder_ocsp_responses(
            leaf,
            issuer.as_ref(),
            revocation_policy.responder_ocsp_responses_der,
            revocation_policy.ocsp_cache_namespace,
        )?
    } else {
        revocation_policy.responder_ocsp_responses_der.to_vec()
    };

    let sources: Vec<&[Vec<u8>]> = match revocation_policy.ocsp_mode {
        OcspMode::StapledOnly => vec![revocation_policy.stapled_ocsp_responses_der],
        OcspMode::ResponderOnly => vec![responder_responses.as_slice()],
        OcspMode::StapledThenResponder => {
            vec![
                revocation_policy.stapled_ocsp_responses_der,
                responder_responses.as_slice(),
            ]
        }
        OcspMode::Disabled => vec![
            revocation_policy.stapled_ocsp_responses_der,
            responder_responses.as_slice(),
        ],
    };

    let mut cert_stack = Stack::new().map_err(|err| {
        AsxError::new(
            ErrorCode::SecurityVerificationFailed,
            format!("failed to initialize OCSP certificate stack: {err}"),
            ErrorContext::new("wssec_verify_signature_value"),
        )
    })?;
    for candidate in intermediates.iter() {
        cert_stack.push(candidate.to_owned()).map_err(|err| {
            AsxError::new(
                ErrorCode::SecurityVerificationFailed,
                format!("failed to push intermediate into OCSP stack: {err}"),
                ErrorContext::new("wssec_verify_signature_value"),
            )
        })?;
    }
    for anchor in trust_anchors {
        cert_stack.push(anchor.clone()).map_err(|err| {
            AsxError::new(
                ErrorCode::SecurityVerificationFailed,
                format!("failed to push trust anchor into OCSP stack: {err}"),
                ErrorContext::new("wssec_verify_signature_value"),
            )
        })?;
    }

    // RFC 8954 §2.1 recommends SHA-256 as the certID hash algorithm.
    // Build both so we can match responses from responders that still use SHA-1.
    let cert_id_sha256 = OcspCertId::from_cert(MessageDigest::sha256(), leaf, issuer.as_ref())
        .map_err(|err| {
            AsxError::new(
                ErrorCode::SecurityVerificationFailed,
                format!("failed to build OCSP certificate id (sha256): {err}"),
                ErrorContext::new("wssec_verify_signature_value"),
            )
        })?;
    let cert_id_sha1 = OcspCertId::from_cert(MessageDigest::sha1(), leaf, issuer.as_ref())
        .map_err(|err| {
            AsxError::new(
                ErrorCode::SecurityVerificationFailed,
                format!("failed to build OCSP certificate id (sha1): {err}"),
                ErrorContext::new("wssec_verify_signature_value"),
            )
        })?;

    let mut saw_usable = false;
    let mut unknown_outcome: Option<CertOcspOutcome> = None;

    for source in sources {
        for der in source {
            let Ok(response) = OcspResponse::from_der(der) else {
                continue;
            };
            if response.status() != OcspResponseStatus::SUCCESSFUL {
                continue;
            }
            let Ok(basic) = response.basic() else {
                continue;
            };
            if basic.verify(&cert_stack, store, OcspFlag::empty()).is_err() {
                continue;
            }
            // Try SHA-256 first (RFC 8954 preferred); fall back to SHA-1 for
            // legacy responders that embed SHA-1 certIDs in their responses.
            let Some(status) = basic
                .find_status(&cert_id_sha256)
                .or_else(|| basic.find_status(&cert_id_sha1))
            else {
                continue;
            };

            saw_usable = true;
            status.check_validity(300, Some(86400)).map_err(|err| {
                AsxError::new(
                    ErrorCode::SecurityVerificationFailed,
                    format!("OCSP response failed freshness validation: {err}"),
                    ErrorContext::new("wssec_verify_signature_value"),
                )
            })?;

            if status.status == OcspCertStatus::REVOKED {
                // Return the revocation outcome; callers should emit a
                // CertOcspRevoked event and then fail with SecurityVerificationFailed.
                return Ok(CertOcspOutcome::Revoked {
                    subject_cn: cert_subject_cn(leaf),
                    serial_hex: cert_serial_hex(leaf),
                });
            }
            if status.status == OcspCertStatus::GOOD {
                return Ok(CertOcspOutcome::Good);
            }
            // Unknown status — record it; policy decides leniency below
            unknown_outcome = Some(CertOcspOutcome::Unknown {
                subject_cn: cert_subject_cn(leaf),
            });
        }
    }

    match revocation_policy.ocsp_failure_mode {
        OcspFailureMode::HardFail => Err(AsxError::new(
            ErrorCode::SecurityVerificationFailed,
            if saw_usable {
                "OCSP status was not good"
            } else {
                "OCSP verification required but no usable response was found"
            },
            ErrorContext::new("wssec_verify_signature_value"),
        )),
        OcspFailureMode::SoftFail => Ok(unknown_outcome.unwrap_or(CertOcspOutcome::NoResponse)),
    }
}

pub(crate) fn effective_responder_ocsp_responses(
    cert: &X509Ref,
    issuer: &X509Ref,
    configured: &[Vec<u8>],
    ocsp_cache_namespace: &str,
) -> Result<Vec<Vec<u8>>> {
    if !configured.is_empty() {
        return Ok(configured.to_vec());
    }

    ocsp_client::fetch_ocsp_responses_with_cache_scoped(cert, issuer, ocsp_cache_namespace)
}

pub(crate) fn is_revoked(cert: &X509Ref, crls: &[X509Crl]) -> Result<bool> {
    let cert_issuer = cert.issuer_name().to_der().map_err(|err| {
        AsxError::new(
            ErrorCode::SecurityVerificationFailed,
            format!("failed to read certificate issuer: {err}"),
            ErrorContext::new("wssec_verify_signature_value"),
        )
    })?;
    let cert_serial = cert.serial_number().to_bn().map_err(|err| {
        AsxError::new(
            ErrorCode::SecurityVerificationFailed,
            format!("failed to read certificate serial number: {err}"),
            ErrorContext::new("wssec_verify_signature_value"),
        )
    })?;
    let cert_serial_bytes = cert_serial.to_vec();

    for crl in crls {
        let crl_issuer = crl.issuer_name().to_der().map_err(|err| {
            AsxError::new(
                ErrorCode::SecurityVerificationFailed,
                format!("failed to read CRL issuer: {err}"),
                ErrorContext::new("wssec_verify_signature_value"),
            )
        })?;
        if crl_issuer != cert_issuer {
            continue;
        }

        if let Some(revoked) = crl.get_revoked() {
            for entry in revoked {
                let serial = entry.serial_number().to_bn().map_err(|err| {
                    AsxError::new(
                        ErrorCode::SecurityVerificationFailed,
                        format!("failed to read revoked serial number from CRL: {err}"),
                        ErrorContext::new("wssec_verify_signature_value"),
                    )
                })?;
                if serial.to_vec() == cert_serial_bytes {
                    return Ok(true);
                }
            }
        }
    }

    Ok(false)
}
