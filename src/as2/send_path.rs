use super::{
    As2SendPolicy, AsxError, ErrorCode, ErrorContext, MimeEnvelope, Result, SessionContext,
    extract_content_type_header,
    mic::{build_outbound_entity, compute_mic},
    pipeline,
};

/// Validate an AS2 identifier value against RFC 4130 §4 grammar.
///
/// RFC 4130 §4 defines `as2-id` as a printable-string or quoted-string of
/// 1..=128 US-ASCII printable characters:
///
/// - **printable-string**: visible US-ASCII only (0x21..=0x7E, no space).
/// - **quoted-string**: `"` + (0x20..=0x7E)* + `"` — space allowed inside
///   the quotes.
///
/// The function also rejects control characters and non-US-ASCII bytes so the
/// identifier is always safe to embed in HTTP headers.
fn validate_as2_from_identifier(
    stage: &'static str,
    session: &SessionContext,
    value: &str,
) -> Result<()> {
    // RFC 4130 §4: max length is 128 characters.
    const AS2_ID_MAX_LEN: usize = 128;

    // Determine whether this is a quoted-string and find the inner content
    // that must meet the printable-ASCII constraint.
    let (inner, allow_space) = if value.starts_with('"') && value.ends_with('"') && value.len() >= 2
    {
        (&value[1..value.len() - 1], true)
    } else {
        (value, false)
    };

    if inner.is_empty() {
        return Err(AsxError::new(
            ErrorCode::PolicyViolation,
            "AS2-From identifier must not be empty",
            ErrorContext::for_session(stage, session),
        ));
    }

    if inner.len() > AS2_ID_MAX_LEN {
        return Err(AsxError::new(
            ErrorCode::PolicyViolation,
            format!(
                "AS2-From identifier exceeds maximum length \
                 ({} bytes, limit is {AS2_ID_MAX_LEN})",
                inner.len()
            ),
            ErrorContext::for_session(stage, session),
        ));
    }

    let min_char: u8 = if allow_space { 0x20 } else { 0x21 };
    if let Some(bad) = inner.bytes().find(|&b| !(min_char..=0x7E).contains(&b)) {
        return Err(AsxError::new(
            ErrorCode::PolicyViolation,
            format!(
                "AS2-From identifier contains character 0x{bad:02X} \
                 not allowed by RFC 4130 §4 (US-ASCII printable only)"
            ),
            ErrorContext::for_session(stage, session),
        ));
    }

    Ok(())
}

/// The signed (or, unprotected, sent) MIME entity of an outbound message and
/// its MIC (RFC 4130 §7.3.1).
pub(crate) struct OutboundEntity {
    pub(crate) entity: Vec<u8>,
    pub(crate) mic_base64: String,
    pub(crate) digest_alg: &'static str,
}

/// Validate the send inputs and build the entity the signature and the MIC
/// cover. The private-key step follows in [`super::cms_keys`].
pub(crate) fn outbound_entity(
    session: &SessionContext,
    message_id: &str,
    payload: &[u8],
    policy: &As2SendPolicy,
    content_type: Option<&str>,
) -> Result<OutboundEntity> {
    pipeline::validate_message_id(message_id, "as2_send_validate", session)?;
    tracing::debug!(
        target: "asx",
        session_id = %session.session_id(),
        partner_id = %session.partner_id(),
        message_id = %message_id,
        sign = policy.sign,
        encrypt = policy.encrypt,
        "AS2 send: building outbound message",
    );
    if payload.is_empty() {
        return Err(AsxError::new(
            ErrorCode::PolicyViolation,
            "strict interop mode rejects empty AS2 payload",
            ErrorContext::for_session("as2_send_strict_policy", session),
        ));
    }
    if !policy.as2_from_id.trim().is_empty() {
        validate_as2_from_identifier("as2_send_validate", session, policy.as2_from_id.as_str())?;
    }

    // RFC 4130 §7.3.1 fixes the MIC input, and it depends on what protection is
    // applied. Build the MIME entity *after* compression, because the entity
    // that gets signed is the compressed one — MIC'ing the uncompressed payload
    // would produce a value the receiver can never reproduce.
    let compressed;
    let payload = if policy.compress {
        compressed = compress_payload(payload)?;
        compressed.as_slice()
    } else {
        payload
    };
    let entity_content_type = payload_entity_content_type(policy, content_type);
    // Signed/encrypted: the MIC covers the MIME entity — headers included.
    // Unsigned and unencrypted: content only, no MIME headers at all. Either
    // way it is what is signed, encrypted or sent, so the receiver recovers
    // the payload's real media type and digests the same octets.
    let entity: Vec<u8> = if policy.sign || policy.encrypt {
        build_outbound_entity(entity_content_type, payload)
    } else {
        payload.to_vec()
    };
    let (mic_base64, digest_alg) = compute_mic(&entity, policy.mic_algorithm);
    Ok(OutboundEntity {
        entity,
        mic_base64,
        digest_alg,
    })
}

/// Encrypt the signed entity to `recipient` (when the policy encrypts) and
/// wrap the result for HTTP.
pub(crate) fn envelope(
    signed: Vec<u8>,
    recipient: Option<&openssl::x509::X509Ref>,
    policy: &As2SendPolicy,
    content_type: Option<&str>,
) -> Result<MimeEnvelope> {
    let body = match (policy.encrypt, recipient) {
        (true, Some(recipient)) => encrypt_payload(&signed, recipient, policy)?,
        (true, None) => {
            return Err(AsxError::new(
                ErrorCode::PolicyViolation,
                "AS2 recipient certificate is missing",
                ErrorContext::new("as2_send_encrypt"),
            ));
        }
        (false, _) => signed,
    };
    Ok(build_mime_envelope(body, policy, content_type))
}

/// The crafting hook behind `asx::__fuzz::as2_raw_message`: an AS2 entity
/// carrying `payload`, signed by `signer` (`(cert PEM, key PEM)`) and
/// encrypted to `recipient_cert_pem` only when given. Returns
/// `(Content-Type, body)`.
///
/// The clients always sign and encrypt; the receive suites use this to present
/// an `Inbound` with what a client never sends (an unsigned or unencrypted
/// message, a signer that is not the pinned one). The signature is made by
/// the same CMS assembly as the client's (`super::cms_keys`).
pub fn raw_message(
    payload: &[u8],
    content_type: &str,
    as2_from: &str,
    signer: Option<(&[u8], &[u8])>,
    recipient_cert_pem: Option<&[u8]>,
) -> Result<(String, Vec<u8>)> {
    let refuse = |detail: String| {
        AsxError::new(
            ErrorCode::PolicyViolation,
            detail,
            ErrorContext::new("as2_raw_message"),
        )
    };
    let partner = crate::party::Partner::new(as2_from);
    let resolved = crate::profile::resolve(
        &crate::profile::Profile::as2(),
        &partner,
        &crate::clock::system(),
    );
    let mut policy = super::client::send_view(&resolved, as2_from);
    policy.sign = signer.is_some();
    policy.encrypt = recipient_cert_pem.is_some();
    let recipient = recipient_cert_pem
        .map(openssl::x509::X509::from_pem)
        .transpose()
        .map_err(|_| {
            refuse("AS2 recipient certificate is not a valid PEM X.509 certificate".into())
        })?;
    let session = SessionContext::new("raw", as2_from, "strict")?;
    let entity = outbound_entity(&session, "raw", payload, &policy, Some(content_type))?;
    let signed = match signer {
        Some((cert, key)) => {
            let pair =
                crate::keys::KeyPair::from_pem(cert, key).map_err(|e| refuse(e.to_string()))?;
            super::cms_keys::sign_detached_ready(&pair, &entity.entity, session.clock().now())
                .map_err(|e| refuse(e.to_string()))?
        }
        None => entity.entity,
    };
    let mime = envelope(signed, recipient.as_deref(), &policy, Some(content_type))?;
    Ok((mime.content_type, mime.body.to_vec()))
}

/// Media type stamped on the outbound MIME entity.
///
/// When compression is applied the entity carries the compressed octets, so it
/// is labelled as such rather than as the original business media type.
fn payload_entity_content_type<'a>(
    policy: &As2SendPolicy,
    content_type: Option<&'a str>,
) -> &'a str {
    if policy.compress {
        return crate::crypto::compression::AS2_COMPRESSED_CONTENT_TYPE;
    }
    content_type
        .or(policy.payload_content_type)
        .unwrap_or("application/octet-stream")
}

fn build_mime_envelope(
    payload_to_send: Vec<u8>,
    policy: &As2SendPolicy,
    content_type: Option<&str>,
) -> MimeEnvelope {
    if policy.encrypt {
        return MimeEnvelope {
            content_type: "application/pkcs7-mime; smime-type=enveloped-data; name=\"smime.p7m\""
                .to_string(),
            body: payload_to_send.into(),
        };
    }

    if policy.sign {
        let content_type = extract_content_type_header(&payload_to_send)
            .unwrap_or_else(|| "multipart/signed".to_string());
        return MimeEnvelope {
            content_type,
            body: payload_to_send.into(),
        };
    }

    // RFC 4130 §5: an unprotected AS2 message carries the payload directly as
    // the HTTP entity body under its own media type. There is no multipart
    // wrapper — inventing one would change the octets the receiver MICs.
    MimeEnvelope {
        content_type: payload_entity_content_type(policy, content_type).to_string(),
        body: payload_to_send.into(),
    }
}

fn encrypt_payload(
    payload: &[u8],
    recipient_cert: &openssl::x509::X509Ref,
    policy: &As2SendPolicy,
) -> Result<Vec<u8>> {
    crate::crypto::as2_smime::encrypt_smime_message_preparsed(
        payload,
        recipient_cert,
        policy.encryption_cipher,
    )
}

/// RFC 5402 AS2 compression: CMS `CompressedData` (ZLIB), not a bare gzip
/// stream — see [`crate::crypto::compression`].
fn compress_payload(payload: &[u8]) -> Result<Vec<u8>> {
    crate::crypto::compression::compress_cms_zlib(payload, 6)
}
