use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use openssl::asn1::Asn1Time;
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::ocsp::{OcspCertId, OcspCertStatus, OcspFlag, OcspResponse, OcspResponseStatus};
use openssl::pkcs7::{Pkcs7, Pkcs7Flags};
use openssl::pkey::PKey;
use openssl::stack::Stack;
use openssl::x509::store::X509StoreBuilder;
use openssl::x509::{X509, X509Crl, X509Ref};
use std::borrow::Cow;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::core::{AsxError, ErrorCode, ErrorContext, OcspFailureMode, OcspMode, Result};
use crate::crypto::ocsp_client;
use crate::crypto::wssec;

#[derive(Debug, Clone)]
pub struct As2SmimeVerificationOptions<'a> {
    pub expected_signer_fingerprint_sha256: Option<&'a str>,
    pub revocation_policy: wssec::RevocationPolicy<'a>,
    /// Optional intermediate CA certificates (PEM) to supplement chain building.
    /// Use when the partner's CMS SignedData does not embed the full intermediate
    /// chain and the intermediate is not present in `trust_anchor_pems`.
    pub intermediate_ca_pems: &'a [String],
}

/// # Cancel Safety
///
/// This function is **synchronous** and not cancel-safe.  When invoked from a
/// `tokio::task::spawn_blocking` closure, cancelling the outer Tokio task does
/// **not** interrupt the blocking thread — OpenSSL operations run to completion
/// and all temporary allocations (parsed certificates, CRL/OCSP responses, etc.)
/// are released only when the thread finishes naturally.
///
/// Do not call this function directly from an async context; always dispatch via
/// `tokio::task::spawn_blocking` or an equivalent executor thread.
pub fn verify_smime_signed_payload(
    payload: &[u8],
    options: As2SmimeVerificationOptions<'_>,
) -> Result<VerifiedSmimeEntity> {
    if options.revocation_policy.trust_anchor_pems.is_empty() {
        return Err(AsxError::new(
            ErrorCode::SecurityVerificationFailed,
            "AS2 CMS verification requires at least one trust anchor",
            ErrorContext::new("as2_smime_verify"),
        ));
    }

    let (pkcs7, detached_content) = Pkcs7::from_smime(payload).map_err(|err| {
        // Produce a richer error for RFC 5652 CMS types that some legacy AS2
        // partners send but that the AS2 receive path does not support.
        // Header-based detection is cheap and runs before the OpenSSL parse.
        let cms_type_hint = match detect_smime_format(payload) {
            SmimeFormat::AuthenticatedData => Some(
                "CMS AuthenticatedData (smime-type=authenticated-data) is not supported \
                 for AS2 signed/encrypted message delivery; \
                 partner must use SignedData or EnvelopedData (RFC 5652 §5/§6)",
            ),
            SmimeFormat::DigestedData => Some(
                "CMS DigestedData (smime-type=digested-data) is not supported \
                 for AS2 signed/encrypted message delivery; \
                 partner must use SignedData or EnvelopedData (RFC 5652 §5/§6)",
            ),
            _ => None,
        };
        AsxError::new(
            if cms_type_hint.is_some() {
                ErrorCode::InteropViolation
            } else {
                ErrorCode::SecurityVerificationFailed
            },
            cms_type_hint.map_or_else(
                || format!("failed to parse S/MIME payload: {err}"),
                |hint| hint.to_string(),
            ),
            ErrorContext::new("as2_smime_verify"),
        )
    })?;

    // Parse trust-anchor PEMs once; reuse parsed certs for both the X509Store
    // and the CRL/OCSP issuer pool.  Use pre-parsed anchors from the cache
    // when available (zero PEM parse overhead on hot path).
    let mut trust_anchor_certs: Vec<X509>;
    if let Some(ref pre) = options.revocation_policy.pre_parsed_trust_anchors {
        trust_anchor_certs = pre.clone(); // O(n) refcount bumps — O(1) per cert
    } else {
        trust_anchor_certs = Vec::new();
        for pem in options.revocation_policy.trust_anchor_pems {
            let certs = X509::stack_from_pem(pem.as_bytes()).map_err(|err| {
                AsxError::new(
                    ErrorCode::SecurityVerificationFailed,
                    format!("invalid trust-anchor certificate PEM: {err}"),
                    ErrorContext::new("as2_smime_verify"),
                )
            })?;
            trust_anchor_certs.extend(certs);
        }
    }

    // Use the pre-built X509Store from CertHandle cache when available.
    // This avoids rebuilding the store (O(n_anchors) OpenSSL allocations) on
    // every inbound message — the most common hot-path for AS2 receive.
    let fresh_store: Option<openssl::x509::store::X509Store>;
    let store: &openssl::x509::store::X509StoreRef =
        if let Some(ref pre) = options.revocation_policy.pre_built_x509_store {
            pre
        } else {
            let mut builder = X509StoreBuilder::new().map_err(|err| {
                AsxError::new(
                    ErrorCode::SecurityVerificationFailed,
                    format!("failed to initialize X509 trust store: {err}"),
                    ErrorContext::new("as2_smime_verify"),
                )
            })?;
            for cert in &trust_anchor_certs {
                builder.add_cert(cert.clone()).map_err(|err| {
                    AsxError::new(
                        ErrorCode::SecurityVerificationFailed,
                        format!("failed to add trust-anchor certificate: {err}"),
                        ErrorContext::new("as2_smime_verify"),
                    )
                })?;
            }
            fresh_store = Some(builder.build());
            fresh_store.as_ref().unwrap()
        };

    let mut crls = Vec::new();
    for pem in options.revocation_policy.revocation_crl_pems {
        let crl = X509Crl::from_pem(pem.as_bytes()).map_err(|err| {
            AsxError::new(
                ErrorCode::SecurityVerificationFailed,
                format!("invalid revocation CRL PEM: {err}"),
                ErrorContext::new("as2_smime_verify"),
            )
        })?;
        crls.push(crl);
    }

    // Build the intermediate-certificate stack.  OpenSSL's PKCS7_verify already
    // searches certificates embedded in the CMS SignedData structure, but it
    // cannot find intermediates that are neither embedded nor in the trust store.
    // Providing them here (RFC 5280 §6 chain building) lets OpenSSL complete the
    // path for certificates issued by an intermediate CA not present in the store.
    let mut certs = Stack::new().map_err(|err| {
        AsxError::new(
            ErrorCode::SecurityVerificationFailed,
            format!("failed to initialize certificate stack: {err}"),
            ErrorContext::new("as2_smime_verify"),
        )
    })?;
    for pem in options.intermediate_ca_pems {
        let chain = X509::stack_from_pem(pem.as_bytes()).map_err(|err| {
            AsxError::new(
                ErrorCode::SecurityVerificationFailed,
                format!("invalid intermediate CA certificate PEM: {err}"),
                ErrorContext::new("as2_smime_verify"),
            )
        })?;
        for cert in chain {
            certs.push(cert).map_err(|err| {
                AsxError::new(
                    ErrorCode::SecurityVerificationFailed,
                    format!("failed to add intermediate CA certificate: {err}"),
                    ErrorContext::new("as2_smime_verify"),
                )
            })?;
        }
    }

    let mut verified_payload = Vec::new();
    // PKCS7_NOINTERN: prevent certificates embedded in the inbound CMS structure
    // from being used during chain building.  OpenSSL will only use the explicitly
    // supplied `certs` stack and the configured `store` to construct the path.
    // This closes the embedded-certificate-chain influence attack described in
    // the project changelog §5 (MEDIUM).  The explicit `certs` stack (built from
    // `intermediate_ca_pems`) must include any intermediate CAs required to
    // complete the path to a configured trust anchor.
    let verify_flags = Pkcs7Flags::NOINTERN;

    pkcs7
        .verify(
            &certs,
            store,
            detached_content.as_deref(),
            Some(&mut verified_payload),
            verify_flags,
        )
        .map_err(|err| {
            AsxError::new(
                ErrorCode::SecurityVerificationFailed,
                format!("CMS signature verification failed: {err}"),
                ErrorContext::new("as2_smime_verify"),
            )
        })?;

    // Use Pkcs7Flags::empty() for signers() so that the signer certificate can
    // be located from the message's embedded certificates even when PKCS7_NOINTERN
    // was used for chain-validation above.  Chain-building is already complete at
    // this point; we only need to identify the signer for fingerprint comparison.
    let signer_lookup_flags = Pkcs7Flags::empty();
    let signers = pkcs7.signers(&certs, signer_lookup_flags).map_err(|err| {
        AsxError::new(
            ErrorCode::SecurityVerificationFailed,
            format!("failed to inspect CMS signer certificates: {err}"),
            ErrorContext::new("as2_smime_verify"),
        )
    })?;

    let signer = signers.get(0).ok_or_else(|| {
        AsxError::new(
            ErrorCode::SecurityVerificationFailed,
            "CMS payload does not contain signer certificates",
            ErrorContext::new("as2_smime_verify"),
        )
    })?;

    if let Some(expected_fingerprint) =
        normalize_fingerprint(options.expected_signer_fingerprint_sha256)
            .filter(|value| !value.is_empty())
    {
        let digest = signer.digest(MessageDigest::sha256()).map_err(|err| {
            AsxError::new(
                ErrorCode::SecurityVerificationFailed,
                format!("failed to hash signer certificate: {err}"),
                ErrorContext::new("as2_smime_verify"),
            )
        })?;
        let actual = hex_lower(&digest);

        if actual != expected_fingerprint {
            return Err(AsxError::new(
                ErrorCode::SecurityVerificationFailed,
                "CMS signer certificate fingerprint mismatch",
                ErrorContext::new("as2_smime_verify"),
            ));
        }
    }

    if !crls.is_empty() {
        validate_crls(&crls, &trust_anchor_certs)?;

        if is_revoked(signer, &crls)? {
            return Err(AsxError::new(
                ErrorCode::SecurityVerificationFailed,
                "CMS signer certificate is revoked by configured CRL",
                ErrorContext::new("as2_smime_verify"),
            ));
        }
    }

    validate_ocsp_status(
        signer,
        &trust_anchor_certs,
        options.revocation_policy.ocsp_mode,
        options.revocation_policy.ocsp_failure_mode,
        options.revocation_policy.stapled_ocsp_responses_der,
        options.revocation_policy.responder_ocsp_responses_der,
        options.revocation_policy.ocsp_cache_namespace,
    )?;

    // For a detached (`multipart/signed`) signature OpenSSL hands back the exact
    // octets that were signed; for opaque `signed-data` it writes the
    // encapsulated content into `verified_payload`.  Either way this is the MIME
    // entity RFC 4130 §7.3.1 requires the MIC to be computed over — return it
    // instead of discarding it.
    let entity = detached_content.unwrap_or(verified_payload);
    Ok(VerifiedSmimeEntity::from_entity_bytes(entity))
}

/// The MIME entity a CMS `SignedData` actually covered.
///
/// AS2 signs a complete MIME entity — headers *and* content — so both halves
/// matter downstream:
///
/// - [`entity`](Self::entity) is the exact signed octet sequence and is the
///   input to the RFC 4130 §7.3.1 MIC. It must not be re-serialized or
///   normalized, or the MIC will not match the sender's.
/// - [`content`](Self::content) is the business document with the entity's MIME
///   headers stripped — what the application actually wants.
#[derive(Debug, Clone)]
pub struct VerifiedSmimeEntity {
    entity: Vec<u8>,
    content_start: usize,
}

impl VerifiedSmimeEntity {
    /// Split a signed MIME entity into its header block and content.
    ///
    /// A MIME entity separates headers from content with a blank line. If no
    /// separator is present the whole buffer is treated as content, matching
    /// how partners that sign bare payloads (no headers) behave.
    pub fn from_entity_bytes(entity: Vec<u8>) -> Self {
        let content_start = find_mime_header_break(&entity).unwrap_or(0);
        Self {
            entity,
            content_start,
        }
    }

    /// Exact signed octets (headers + content) — the RFC 4130 §7.3.1 MIC input.
    pub fn entity(&self) -> &[u8] {
        &self.entity
    }

    /// The entity content with MIME headers stripped, still transfer-encoded.
    ///
    /// Prefer [`decoded_content`](Self::decoded_content) unless you specifically
    /// need the wire form.
    pub fn content(&self) -> &[u8] {
        &self.entity[self.content_start..]
    }

    /// The entity content with its `Content-Transfer-Encoding` reversed.
    ///
    /// Signed entities carrying binary payloads are base64-encoded per RFC 5751
    /// §3.1.1; handing that back undecoded would give the application base64
    /// text where it expected its document.
    pub fn decoded_content(&self) -> Result<Cow<'_, [u8]>> {
        let encoding = header_value(self.headers(), "content-transfer-encoding")
            .unwrap_or_default()
            .to_ascii_lowercase();

        match encoding.trim() {
            "base64" => {
                // Line breaks are folding artefacts, not data.
                let compact: Vec<u8> = self
                    .content()
                    .iter()
                    .copied()
                    .filter(|b| !b.is_ascii_whitespace())
                    .collect();
                let decoded = BASE64_STANDARD.decode(&compact).map_err(|err| {
                    AsxError::new(
                        ErrorCode::ParseFailed,
                        format!("signed MIME entity has invalid base64 content: {err}"),
                        ErrorContext::new("as2_smime_entity_decode"),
                    )
                })?;
                Ok(Cow::Owned(decoded))
            }
            // `binary`, `8bit`, `7bit`, and an absent header all mean the
            // content is already the payload octets.
            _ => Ok(Cow::Borrowed(self.content())),
        }
    }

    /// The entity's MIME header block (empty when the entity carried no headers).
    pub fn headers(&self) -> &[u8] {
        &self.entity[..self.content_start]
    }

    /// Value of the entity's `Content-Type` header, if present.
    pub fn content_type(&self) -> Option<String> {
        header_value(self.headers(), "content-type")
    }

    /// Consume the entity, returning the signed octets and the content offset.
    pub fn into_parts(self) -> (Vec<u8>, usize) {
        (self.entity, self.content_start)
    }
}

/// Byte offset just past the `CRLF CRLF` (or `LF LF`) that ends a MIME header
/// block. Returns `None` when the buffer contains no header/body separator.
fn find_mime_header_break(bytes: &[u8]) -> Option<usize> {
    let crlf = memchr::memmem::find(bytes, b"\r\n\r\n").map(|i| i + 4);
    let lf = memchr::memmem::find(bytes, b"\n\n").map(|i| i + 2);
    match (crlf, lf) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (Some(a), None) => Some(a),
        (None, Some(b)) => Some(b),
        (None, None) => None,
    }
}

/// Read a header value out of a raw MIME header block, unfolding continuation
/// lines. Header names are matched case-insensitively per RFC 5322.
fn header_value(headers: &[u8], wanted_lower: &str) -> Option<String> {
    let text = String::from_utf8_lossy(headers);
    let mut lines: Vec<String> = Vec::new();
    for raw in text.split('\n') {
        let line = raw.strip_suffix('\r').unwrap_or(raw);
        if line.is_empty() {
            continue;
        }
        // A leading space or tab continues the previous header (RFC 5322 §2.2.3
        // folding); unfold it rather than treating it as a new header.
        if let Some(last) = lines.last_mut()
            && (line.starts_with(' ') || line.starts_with('\t'))
        {
            last.push(' ');
            last.push_str(line.trim());
            continue;
        }
        lines.push(line.to_string());
    }

    lines.iter().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.trim()
            .eq_ignore_ascii_case(wanted_lower)
            .then(|| value.trim().to_string())
    })
}

fn is_revoked(cert: &X509Ref, crls: &[X509Crl]) -> Result<bool> {
    let cert_issuer = cert.issuer_name().to_der().map_err(|err| {
        AsxError::new(
            ErrorCode::SecurityVerificationFailed,
            format!("failed to read signer certificate issuer: {err}"),
            ErrorContext::new("as2_smime_verify"),
        )
    })?;
    let cert_serial = cert.serial_number().to_bn().map_err(|err| {
        AsxError::new(
            ErrorCode::SecurityVerificationFailed,
            format!("failed to read signer certificate serial number: {err}"),
            ErrorContext::new("as2_smime_verify"),
        )
    })?;
    let cert_serial_bytes = cert_serial.to_vec();

    for crl in crls {
        let crl_issuer = crl.issuer_name().to_der().map_err(|err| {
            AsxError::new(
                ErrorCode::SecurityVerificationFailed,
                format!("failed to read CRL issuer: {err}"),
                ErrorContext::new("as2_smime_verify"),
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
                        ErrorContext::new("as2_smime_verify"),
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

fn validate_crls(crls: &[X509Crl], issuer_pool: &[X509]) -> Result<()> {
    let now = Asn1Time::from_unix(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|err| {
                AsxError::new(
                    ErrorCode::SecurityVerificationFailed,
                    format!("failed to resolve current system time: {err}"),
                    ErrorContext::new("as2_smime_verify"),
                )
            })?
            .as_secs() as i64,
    )
    .map_err(|err| {
        AsxError::new(
            ErrorCode::SecurityVerificationFailed,
            format!("failed to convert system time for CRL validation: {err}"),
            ErrorContext::new("as2_smime_verify"),
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
                    ErrorContext::new("as2_smime_verify"),
                )
            })?
            .is_gt()
        {
            return Err(AsxError::new(
                ErrorCode::SecurityVerificationFailed,
                "CRL lastUpdate is in the future",
                ErrorContext::new("as2_smime_verify"),
            ));
        }

        if let Some(next_update) = crl.next_update()
            && next_update
                .compare(now.as_ref())
                .map_err(|err| {
                    AsxError::new(
                        ErrorCode::SecurityVerificationFailed,
                        format!("failed to compare CRL nextUpdate: {err}"),
                        ErrorContext::new("as2_smime_verify"),
                    )
                })?
                .is_lt()
        {
            return Err(AsxError::new(
                ErrorCode::SecurityVerificationFailed,
                "CRL nextUpdate is in the past",
                ErrorContext::new("as2_smime_verify"),
            ));
        }

        let crl_issuer = crl.issuer_name().to_der().map_err(|err| {
            AsxError::new(
                ErrorCode::SecurityVerificationFailed,
                format!("failed to read CRL issuer: {err}"),
                ErrorContext::new("as2_smime_verify"),
            )
        })?;

        let issuer_cert = issuer_pool
            .iter()
            .find(|cert| {
                cert.subject_name()
                    .to_der()
                    .map(|der| der == crl_issuer)
                    .unwrap_or(false)
            })
            .ok_or_else(|| {
                AsxError::new(
                    ErrorCode::SecurityVerificationFailed,
                    "CRL issuer does not match configured trust anchors",
                    ErrorContext::new("as2_smime_verify"),
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
                            ErrorContext::new("as2_smime_verify"),
                        )
                    })?
                    .as_ref(),
            )
            .map_err(|err| {
                AsxError::new(
                    ErrorCode::SecurityVerificationFailed,
                    format!("failed to verify CRL signature: {err}"),
                    ErrorContext::new("as2_smime_verify"),
                )
            })?;
        if !valid_signature {
            return Err(AsxError::new(
                ErrorCode::SecurityVerificationFailed,
                "CRL signature verification failed",
                ErrorContext::new("as2_smime_verify"),
            ));
        }
    }

    Ok(())
}

fn validate_ocsp_status(
    cert: &X509Ref,
    issuer_pool: &[X509],
    mode: OcspMode,
    failure_mode: OcspFailureMode,
    stapled_responses_der: &[Vec<u8>],
    responder_responses_der: &[Vec<u8>],
    ocsp_cache_namespace: &str,
) -> Result<()> {
    let disabled_with_supplied_responses = mode == OcspMode::Disabled
        && (!stapled_responses_der.is_empty() || !responder_responses_der.is_empty());

    if mode == OcspMode::Disabled && !disabled_with_supplied_responses {
        return Ok(());
    }

    let issuer = issuer_pool.iter().find(|candidate| {
        match (
            candidate.subject_name().to_der(),
            cert.issuer_name().to_der(),
        ) {
            (Ok(subject), Ok(issuer_name)) => subject == issuer_name,
            _ => false,
        }
    });

    let Some(issuer) = issuer else {
        return match failure_mode {
            OcspFailureMode::HardFail => Err(AsxError::new(
                ErrorCode::SecurityVerificationFailed,
                "OCSP verification could not resolve certificate issuer",
                ErrorContext::new("as2_smime_verify"),
            )),
            OcspFailureMode::SoftFail => Ok(()),
        };
    };

    let needs_responder = matches!(
        mode,
        OcspMode::ResponderOnly | OcspMode::StapledThenResponder
    );
    let responder_responses = if needs_responder {
        effective_responder_ocsp_responses(
            cert,
            issuer.as_ref(),
            responder_responses_der,
            ocsp_cache_namespace,
        )?
    } else {
        responder_responses_der.to_vec()
    };

    let responses = match mode {
        OcspMode::StapledOnly => vec![stapled_responses_der],
        OcspMode::ResponderOnly => vec![responder_responses.as_slice()],
        OcspMode::StapledThenResponder => {
            vec![stapled_responses_der, responder_responses.as_slice()]
        }
        OcspMode::Disabled => vec![stapled_responses_der, responder_responses.as_slice()],
    };

    let mut saw_usable = false;
    let mut cert_stack = Stack::new().map_err(|err| {
        AsxError::new(
            ErrorCode::SecurityVerificationFailed,
            format!("failed to initialize OCSP certificate stack: {err}"),
            ErrorContext::new("as2_smime_verify"),
        )
    })?;
    for candidate in issuer_pool {
        cert_stack.push(candidate.clone()).map_err(|err| {
            AsxError::new(
                ErrorCode::SecurityVerificationFailed,
                format!("failed to build OCSP verification stack: {err}"),
                ErrorContext::new("as2_smime_verify"),
            )
        })?;
    }

    let mut store_builder = X509StoreBuilder::new().map_err(|err| {
        AsxError::new(
            ErrorCode::SecurityVerificationFailed,
            format!("failed to initialize OCSP trust store: {err}"),
            ErrorContext::new("as2_smime_verify"),
        )
    })?;
    for candidate in issuer_pool {
        store_builder.add_cert(candidate.clone()).map_err(|err| {
            AsxError::new(
                ErrorCode::SecurityVerificationFailed,
                format!("failed to add OCSP trust anchor: {err}"),
                ErrorContext::new("as2_smime_verify"),
            )
        })?;
    }
    let store = store_builder.build();

    for source in responses {
        for der in source {
            let response = match OcspResponse::from_der(der) {
                Ok(value) => value,
                Err(_) => continue,
            };
            if response.status() != OcspResponseStatus::SUCCESSFUL {
                continue;
            }
            let basic = match response.basic() {
                Ok(value) => value,
                Err(_) => continue,
            };
            if basic
                .verify(&cert_stack, &store, OcspFlag::empty())
                .is_err()
            {
                continue;
            }

            let cert_id = match OcspCertId::from_cert(MessageDigest::sha1(), cert, issuer.as_ref())
            {
                Ok(value) => value,
                Err(_) => continue,
            };

            let status = match basic.find_status(&cert_id) {
                Some(value) => value,
                None => continue,
            };

            saw_usable = true;
            status.check_validity(300, Some(86400)).map_err(|err| {
                AsxError::new(
                    ErrorCode::SecurityVerificationFailed,
                    format!("OCSP response failed freshness validation: {err}"),
                    ErrorContext::new("as2_smime_verify"),
                )
            })?;

            if status.status == OcspCertStatus::REVOKED {
                return Err(AsxError::new(
                    ErrorCode::SecurityVerificationFailed,
                    "OCSP response reports signer certificate revoked",
                    ErrorContext::new("as2_smime_verify"),
                ));
            }
            if status.status == OcspCertStatus::GOOD {
                return Ok(());
            }
        }
    }

    match failure_mode {
        OcspFailureMode::HardFail => Err(AsxError::new(
            ErrorCode::SecurityVerificationFailed,
            if saw_usable {
                "OCSP status was not good"
            } else {
                "OCSP verification required but no usable response was found"
            },
            ErrorContext::new("as2_smime_verify"),
        )),
        OcspFailureMode::SoftFail => Ok(()),
    }
}

fn effective_responder_ocsp_responses(
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

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn normalize_fingerprint(value: Option<&str>) -> Option<String> {
    value.and_then(|candidate| {
        let normalized: String = candidate
            .chars()
            .filter(|ch| ch.is_ascii_hexdigit())
            .map(|ch| ch.to_ascii_lowercase())
            .collect();

        if normalized.len() == 64 {
            Some(normalized)
        } else {
            None
        }
    })
}

/// Sign a prepared AS2 MIME entity with S/MIME (CMS).
///
/// `entity` must be the complete MIME entity to sign — headers, a blank line,
/// then content — because that is exactly what RFC 4130 §7.3.1 makes the MIC
/// input. Build it with the AS2 send path's MIME entity builder so the payload's real
/// `Content-Type` travels on the wire.
pub fn sign_smime_message(
    payload: &[u8],
    signing_key_pem: &[u8],
    signing_cert_pem: &[u8],
) -> Result<Vec<u8>> {
    let signing_key = PKey::private_key_from_pem(signing_key_pem).map_err(|err| {
        AsxError::new(
            ErrorCode::SecurityVerificationFailed,
            format!("failed to parse signing key PEM: {err}"),
            ErrorContext::new("as2_smime_sign"),
        )
    })?;
    let signing_cert = X509::from_pem(signing_cert_pem).map_err(|err| {
        AsxError::new(
            ErrorCode::SecurityVerificationFailed,
            format!("failed to parse signing certificate PEM: {err}"),
            ErrorContext::new("as2_smime_sign"),
        )
    })?;

    sign_smime_message_preparsed(payload, &signing_key, &signing_cert)
}

pub fn sign_smime_message_preparsed(
    payload: &[u8],
    signing_key: &openssl::pkey::PKeyRef<openssl::pkey::Private>,
    signing_cert: &X509Ref,
) -> Result<Vec<u8>> {
    let mut certs = Stack::new().map_err(|err| {
        AsxError::new(
            ErrorCode::SecurityVerificationFailed,
            format!("failed to create certificate stack: {err}"),
            ErrorContext::new("as2_smime_sign"),
        )
    })?;

    certs.push(signing_cert.to_owned()).map_err(|err| {
        AsxError::new(
            ErrorCode::SecurityVerificationFailed,
            format!("failed to add certificate to stack: {err}"),
            ErrorContext::new("as2_smime_sign"),
        )
    })?;

    // No `Pkcs7Flags::TEXT`: that flag makes OpenSSL prepend its own
    // `Content-Type: text/plain` to the signed content, which would overwrite
    // the payload's real media type (application/edi-x12, EDIFACT, XML, …) and
    // desynchronize the MIC from what the caller believes it sent. The caller
    // supplies a fully-formed MIME entity instead.
    let sign_flags = Pkcs7Flags::DETACHED | Pkcs7Flags::BINARY;

    let pkcs7 =
        Pkcs7::sign(signing_cert, signing_key, &certs, payload, sign_flags).map_err(|err| {
            AsxError::new(
                ErrorCode::SecurityVerificationFailed,
                format!("failed to create S/MIME signed message: {err}"),
                ErrorContext::new("as2_smime_sign"),
            )
        })?;

    let signed_data = pkcs7.to_smime(payload, sign_flags).map_err(|err| {
        AsxError::new(
            ErrorCode::SecurityVerificationFailed,
            format!("failed to encode S/MIME signed message: {err}"),
            ErrorContext::new("as2_smime_sign_encode"),
        )
    })?;

    Ok(signed_data)
}

// ── Envelope detection helpers ──────────────────────────────────────────────

/// Classifies the S/MIME wire format of an AS2 payload per RFC 5751.
///
/// Distinguishing the two signed formats is necessary for correct wire
/// handling: `multipart/signed` carries the signed content as a separate MIME
/// body part (detached signature), while `application/pkcs7-mime;
/// smime-type=signed-data` embeds the content inside the PKCS#7 structure.
///
/// Callers should use [`detect_smime_format`] rather than inspecting headers
/// manually.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SmimeFormat {
    /// `application/pkcs7-mime; smime-type=enveloped-data` — encrypted.
    Enveloped,
    /// `application/pkcs7-mime; smime-type=signed-data` — opaque signed.
    OpaqueSignedData,
    /// `multipart/signed; protocol="application/pkcs7-signature"` — detached
    /// signature.  The signed content is the first MIME part and the
    /// signature is the second.
    MultipartSigned,
    /// Could not be classified (unknown or missing Content-Type).
    Unknown,
    /// `application/pkcs7-mime; smime-type=authenticated-data` — RFC 5652
    /// `AuthenticatedData` CMS type. Not supported for AS2; rejected with an
    /// explicit `InteropViolation` error rather than a generic `ParseFailed`.
    AuthenticatedData,
    /// `application/pkcs7-mime; smime-type=digested-data` — RFC 5652
    /// `DigestedData` CMS type. Not supported for AS2; rejected with an
    /// explicit `InteropViolation` error rather than a generic `ParseFailed`.
    DigestedData,
}

/// Inspect the MIME headers (first 512 bytes) and classify the S/MIME format.
///
/// This allows the receive path to dispatch correctly before invoking
/// OpenSSL's parser, producing better error messages when the wire format
/// does not match what a policy expects.
pub fn detect_smime_format(payload: &[u8]) -> SmimeFormat {
    let header_region = &payload[..payload.len().min(512)];
    let Ok(header_str) = std::str::from_utf8(header_region) else {
        return detect_smime_format_from_pkcs7(payload).unwrap_or(SmimeFormat::Unknown);
    };
    let lower = header_str.to_ascii_lowercase();
    let header_hint = if lower.contains("multipart/signed") {
        SmimeFormat::MultipartSigned
    } else if lower.contains("smime-type=enveloped-data") {
        SmimeFormat::Enveloped
    } else if lower.contains("smime-type=signed-data") {
        SmimeFormat::OpaqueSignedData
    } else if lower.contains("smime-type=authenticated-data") {
        SmimeFormat::AuthenticatedData
    } else if lower.contains("smime-type=digested-data") {
        SmimeFormat::DigestedData
    } else {
        SmimeFormat::Unknown
    };

    if matches!(header_hint, SmimeFormat::MultipartSigned) {
        return header_hint;
    }

    // When the payload is a PKCS7 MIME container, prefer ASN.1-level type
    // detection over `smime-type=` header heuristics. Legacy partners may emit
    // incomplete or incorrect `smime-type` parameters.
    if (lower.contains("application/pkcs7-mime") || lower.contains("application/x-pkcs7-mime"))
        && let Some(parsed) = detect_smime_format_from_pkcs7(payload)
    {
        return parsed;
    }

    header_hint
}

fn detect_smime_format_from_pkcs7(payload: &[u8]) -> Option<SmimeFormat> {
    let (pkcs7, _) = Pkcs7::from_smime(payload).ok()?;
    match pkcs7.type_()?.nid() {
        Nid::PKCS7_ENVELOPED => Some(SmimeFormat::Enveloped),
        Nid::PKCS7_SIGNED => Some(SmimeFormat::OpaqueSignedData),
        _ => None,
    }
}

/// Returns `true` when the MIME payload's Content-Type indicates an S/MIME
/// `EnvelopedData` (encrypted) structure.
///
/// Inspects only the first 512 bytes (header region) to avoid scanning large
/// payloads.  This is deliberately a fast heuristic; the authoritative check
/// is performed by OpenSSL during the actual decrypt call.
pub fn is_smime_enveloped(payload: &[u8]) -> bool {
    matches!(detect_smime_format(payload), SmimeFormat::Enveloped)
}

/// Returns `true` when the MIME payload appears to be S/MIME signed content
/// (`multipart/signed` or `smime-type=signed-data`).
pub fn is_smime_signed(payload: &[u8]) -> bool {
    matches!(
        detect_smime_format(payload),
        SmimeFormat::OpaqueSignedData | SmimeFormat::MultipartSigned
    )
}

/// Decrypt an AS2 S/MIME `EnvelopedData` payload (RFC 5751 §3.3).
///
/// # Arguments
/// - `payload`            — Raw MIME bytes with `Content-Type: application/pkcs7-mime;
///                          smime-type=enveloped-data`.
/// - `recipient_cert_pem` — PEM-encoded X.509 certificate matching the decryption key.
/// - `recipient_key_pem`  — PEM-encoded PKCS#8 / PKCS#1 private key.
///
/// # Returns
/// The decrypted inner MIME message bytes.
///
/// # Errors
/// Returns [`crate::core::ErrorCode::DecryptionFailed`] on parse or decryption failure.
pub fn decrypt_smime_enveloped_payload(
    payload: &[u8],
    recipient_cert_pem: &[u8],
    recipient_key_pem: &[u8],
) -> Result<Vec<u8>> {
    use openssl::pkey::PKey;

    let (pkcs7, _) = Pkcs7::from_smime(payload).map_err(|err| {
        AsxError::new(
            ErrorCode::DecryptionFailed,
            format!("failed to parse S/MIME EnvelopedData structure: {err}"),
            ErrorContext::new("as2_smime_decrypt"),
        )
    })?;

    let pkey = PKey::private_key_from_pem(recipient_key_pem).map_err(|err| {
        AsxError::new(
            ErrorCode::DecryptionFailed,
            format!("failed to parse AS2 decryption private key: {err}"),
            ErrorContext::new("as2_smime_decrypt"),
        )
    })?;

    let cert = X509::from_pem(recipient_cert_pem).map_err(|err| {
        AsxError::new(
            ErrorCode::DecryptionFailed,
            format!("failed to parse AS2 decryption certificate: {err}"),
            ErrorContext::new("as2_smime_decrypt"),
        )
    })?;

    pkcs7
        .decrypt(&pkey, &cert, Pkcs7Flags::empty())
        .map_err(|err| {
            AsxError::new(
                ErrorCode::DecryptionFailed,
                format!("AS2 S/MIME EnvelopedData decryption failed: {err}"),
                ErrorContext::new("as2_smime_decrypt"),
            )
        })
}

// ── Encryption ──────────────────────────────────────────────────────────────

/// Symmetric cipher used for S/MIME (CMS EnvelopedData) encryption.
///
/// The cipher is negotiated per partner via [`crate::as2::As2SendPolicy::encryption_cipher`].
/// `Aes256Cbc` is the default and is required in strict interop mode.
///
/// **Security guidance:**
/// - Prefer `Aes256Cbc` (default) or `Aes192Cbc` for all new deployments.
/// - `Aes128Cbc` is acceptable but offers reduced key material.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum SmimeCipher {
    /// AES-128-CBC. Acceptable for interoperability but weaker key material.
    Aes128Cbc,
    /// AES-192-CBC.
    Aes192Cbc,
    /// AES-256-CBC (default). Required in strict mode.
    #[default]
    Aes256Cbc,
}

/// Encrypt an AS2 payload with S/MIME (CMS) using the recipient certificate.
///
/// The `cipher` parameter controls which symmetric algorithm is used to wrap
/// the content-encryption key.  Pass [`SmimeCipher::default()`] (`Aes256Cbc`)
/// for all new deployments.
pub fn encrypt_smime_message(
    payload: &[u8],
    recipient_cert_pem: &[u8],
    cipher: SmimeCipher,
) -> Result<Vec<u8>> {
    let recipient_cert = X509::from_pem(recipient_cert_pem).map_err(|err| {
        AsxError::new(
            ErrorCode::SecurityVerificationFailed,
            format!("failed to parse recipient certificate PEM: {err}"),
            ErrorContext::new("as2_smime_encrypt"),
        )
    })?;

    encrypt_smime_message_preparsed(payload, &recipient_cert, cipher)
}

pub fn encrypt_smime_message_preparsed(
    payload: &[u8],
    recipient_cert: &X509Ref,
    cipher: SmimeCipher,
) -> Result<Vec<u8>> {
    use openssl::symm::Cipher;

    let openssl_cipher = match cipher {
        SmimeCipher::Aes128Cbc => Cipher::aes_128_cbc(),
        SmimeCipher::Aes192Cbc => Cipher::aes_192_cbc(),
        SmimeCipher::Aes256Cbc => Cipher::aes_256_cbc(),
    };

    let mut recipients = Stack::new().map_err(|err| {
        AsxError::new(
            ErrorCode::SecurityVerificationFailed,
            format!("failed to create recipient certificate stack: {err}"),
            ErrorContext::new("as2_smime_encrypt"),
        )
    })?;

    recipients.push(recipient_cert.to_owned()).map_err(|err| {
        AsxError::new(
            ErrorCode::SecurityVerificationFailed,
            format!("failed to add recipient certificate to stack: {err}"),
            ErrorContext::new("as2_smime_encrypt"),
        )
    })?;

    let pkcs7 = Pkcs7::encrypt(&recipients, payload, openssl_cipher, Pkcs7Flags::BINARY).map_err(
        |err| {
            AsxError::new(
                ErrorCode::SecurityVerificationFailed,
                format!("failed to create S/MIME encrypted message: {err}"),
                ErrorContext::new("as2_smime_encrypt"),
            )
        },
    )?;

    pkcs7.to_smime(payload, Pkcs7Flags::BINARY).map_err(|err| {
        AsxError::new(
            ErrorCode::SecurityVerificationFailed,
            format!("failed to encode S/MIME encrypted message: {err}"),
            ErrorContext::new("as2_smime_encrypt_encode"),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_smime_format_enveloped() {
        let payload = b"Content-Type: application/pkcs7-mime; smime-type=enveloped-data\r\n\r\n";
        assert_eq!(detect_smime_format(payload), SmimeFormat::Enveloped);
        assert!(is_smime_enveloped(payload));
        assert!(!is_smime_signed(payload));
    }

    #[test]
    fn detect_smime_format_opaque_signed() {
        let payload = b"Content-Type: application/pkcs7-mime; smime-type=signed-data\r\n\r\n";
        assert_eq!(detect_smime_format(payload), SmimeFormat::OpaqueSignedData);
        assert!(!is_smime_enveloped(payload));
        assert!(is_smime_signed(payload));
    }

    #[test]
    fn detect_smime_format_multipart_signed() {
        let payload =
            b"Content-Type: multipart/signed; protocol=\"application/pkcs7-signature\"\r\n\r\n";
        assert_eq!(detect_smime_format(payload), SmimeFormat::MultipartSigned);
        assert!(!is_smime_enveloped(payload));
        assert!(is_smime_signed(payload));
    }

    #[test]
    fn detect_smime_format_unknown() {
        assert_eq!(
            detect_smime_format(b"Content-Type: text/plain\r\n\r\n"),
            SmimeFormat::Unknown
        );
        assert_eq!(detect_smime_format(b""), SmimeFormat::Unknown);
    }

    #[test]
    fn detect_smime_format_is_case_insensitive() {
        let payload = b"Content-Type: Application/PKCS7-Mime; SMIME-Type=Enveloped-Data\r\n\r\n";
        assert_eq!(detect_smime_format(payload), SmimeFormat::Enveloped);
    }

    #[test]
    fn detect_smime_format_only_inspects_first_512_bytes() {
        // Build a payload whose content-type header is beyond byte 512.
        let padding = vec![b'X'; 512];
        let mut payload = padding;
        payload.extend_from_slice(
            b"\r\nContent-Type: application/pkcs7-mime; smime-type=enveloped-data\r\n",
        );
        // The format cannot be detected from the header region — returns Unknown.
        assert_eq!(detect_smime_format(&payload), SmimeFormat::Unknown);
    }

    #[test]
    fn detect_smime_format_uses_pkcs7_type_when_signed_smime_type_missing() {
        let payload = b"content";
        let key_pem = include_bytes!("../../tests/fixtures/pki/receipt_signing.key.pem");
        let cert_pem = include_bytes!("../../tests/fixtures/pki/receipt_signing.cert.pem");

        let signing_key = PKey::private_key_from_pem(key_pem).expect("private key");
        let signing_cert = X509::from_pem(cert_pem).expect("signing cert");
        let mut certs = Stack::new().expect("stack");
        certs.push(signing_cert.clone()).expect("push signing cert");

        let pkcs7 = Pkcs7::sign(
            &signing_cert,
            &signing_key,
            &certs,
            payload,
            Pkcs7Flags::BINARY,
        )
        .expect("opaque signed pkcs7");
        let mut signed = pkcs7
            .to_smime(payload, Pkcs7Flags::BINARY)
            .expect("opaque signed smime");
        let text = String::from_utf8(signed.clone()).expect("smime utf8 envelope");
        let rewritten = text.replace("; smime-type=signed-data", "");
        signed = rewritten.into_bytes();

        assert_eq!(detect_smime_format(&signed), SmimeFormat::OpaqueSignedData);
    }

    #[test]
    fn detect_smime_format_uses_pkcs7_type_when_enveloped_smime_type_missing() {
        let payload = b"content";
        let cert_pem = include_bytes!("../../tests/fixtures/pki/receipt_signing.cert.pem");

        let mut enveloped = encrypt_smime_message(payload, cert_pem, SmimeCipher::Aes256Cbc)
            .expect("enveloped smime");
        let text = String::from_utf8(enveloped.clone()).expect("smime utf8 envelope");
        let rewritten = text.replace("; smime-type=enveloped-data", "");
        enveloped = rewritten.into_bytes();

        assert_eq!(detect_smime_format(&enveloped), SmimeFormat::Enveloped);
    }
}
