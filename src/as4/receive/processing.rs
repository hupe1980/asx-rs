use super::super::types::As4PushPolicy;
use super::{metadata, payload};
use crate::core::{AsxError, ErrorCode, ErrorContext, Result, SessionContext};

fn enforce_non_fragment_timestamp_freshness(
    session: &SessionContext,
    policy: &As4PushPolicy,
    parsed: &super::super::ParsedAs4UserMessage,
) -> Result<()> {
    // eb:Timestamp: at most the clock skew ahead (eDelivery AS4 1.15
    // §5.1.3), at most the dedup retention behind — a secondary replay
    // defence for message ids the dedup store has evicted; a retry within
    // the retention is a duplicate, not a replay.
    if let Some(window) = policy.timestamp_window {
        parsed
            .check_timestamp_freshness(window, session.clock().now())
            .inspect_err(|_err| {
                tracing::debug!(
                    target: "asx",
                    message_id = %parsed.message_id,
                    partner = %session.partner_id(),
                    "eb:Timestamp outside the freshness window"
                );
            })?;
    }

    Ok(())
}

// ── The inbound path ────────────────────────────────────────────────────────

/// What `Inbound` needs of one verified, decrypted message. No dedup claim
/// has been taken: the caller claims after this returns.
pub(crate) struct VerifiedInbound {
    pub(crate) parsed: super::super::ParsedAs4UserMessage,
    /// `(content id, decrypted and decompressed bytes, declared MimeType)`,
    /// primary first; a part without a `MimeType` is `application/octet-stream`.
    pub(crate) payloads: Vec<(String, Vec<u8>, String)>,
    /// The verified signer (DER).
    pub(crate) signer_der: Vec<u8>,
    /// The verified references, for the record.
    pub(crate) references: Vec<(String, String, String)>,
    /// The references a receipt echoes as NonRepudiationInformation.
    pub(crate) nri: Vec<super::super::types::As4NriReference>,
}

/// The stage name of an `eb:To` refusal (mapped to EBMS:0004).
pub(crate) const TO_PARTY_STAGE: &str = "as4_inbound_to_party";

/// An inbound push whose signature, signer authorization, same-document
/// digests and `eb:To` verified: what the revocation check (async and
/// outside the crypto pool) and then [`open_inbound`] need. Owned, so it crosses the `await`.
pub(crate) struct AuthenticatedInbound {
    pub(crate) parsed: super::super::ParsedAs4UserMessage,
    declared: Vec<String>,
    part_properties: super::payload::PartProperties,
    deferred: std::sync::Arc<crate::crypto::wssec::verify::Deferred>,
    signer_der: Vec<u8>,
    references: Vec<(String, String, String)>,
    nri: Vec<super::super::types::As4NriReference>,
    /// The validated signer path, signer first, anchor last.
    pub(crate) signer_path: Vec<openssl::x509::X509>,
}

/// Inbound verification up to the revocation check: bounded parse →
/// signer authorization, `SignatureValue` and same-document digests →
/// `eb:To` = `local`. No key is used and nothing is fetched.
pub(crate) fn authenticate_inbound(
    session: &SessionContext,
    policy: &As4PushPolicy,
    body: &[u8],
    content_type: &str,
    authorizer: &dyn super::SenderAuthorizer,
    local: (&str, Option<&str>),
) -> Result<AuthenticatedInbound> {
    let metadata::VerifiedHeader {
        soap_xml,
        parsed,
        declared,
        part_properties,
        signature,
        ..
    } = metadata::parse_and_verify_receive_push_metadata(
        session,
        body,
        content_type,
        policy,
        &super::As4WsSecVerifier,
        Some(authorizer),
    )?;
    let message_id = parsed.message_id.clone();
    let refused = |code: ErrorCode, detail: String| {
        AsxError::new(
            code,
            detail,
            ErrorContext::for_session_with_message("as4_receive_push", session, &message_id),
        )
    };
    let Some(signature) = signature else {
        return Err(refused(
            ErrorCode::SecurityVerificationFailed,
            "AS4 push message signature is required but not present".to_string(),
        ));
    };
    let (local_id, local_type) = local;
    let type_mismatch = matches!(
        (parsed.to_party_type.as_deref(), local_type),
        (Some(theirs), Some(ours)) if theirs != ours
    );
    if parsed.to_party_id() != local_id || type_mismatch {
        return Err(AsxError::new(
            ErrorCode::InteropViolation,
            format!(
                "eb:To/eb:PartyId {:?} is not this party ({local_id:?})",
                parsed.to_party_id()
            ),
            ErrorContext::for_session_with_message(TO_PARTY_STAGE, session, &parsed.message_id),
        ));
    }
    let deferred = signature.deferred.clone().ok_or_else(|| {
        refused(
            ErrorCode::SecurityVerificationFailed,
            "the attachment references were not deferred".to_string(),
        )
    })?;
    let nri = crate::crypto::wssec::parse_signature_references(soap_xml)?
        .into_iter()
        .map(super::super::types::As4NriReference::from)
        .collect();
    let signer_der = signature.signer_certificate_der.clone().ok_or_else(|| {
        refused(
            ErrorCode::SecurityVerificationFailed,
            "the verified signature names no signer certificate".to_string(),
        )
    })?;
    Ok(AuthenticatedInbound {
        parsed,
        declared,
        part_properties,
        deferred,
        signer_der,
        references: signature.references.clone(),
        nri,
        signer_path: signature.signer_path,
    })
}

/// Inbound verification after the revocation check: freshness → (test
/// service answered here) → payload set = `eb:PartInfo` → envelope structure
/// and restored types → algorithm suite → encryption coverage → decryption (`keys`) → `cid:` digests over the decrypted bytes →
/// decompression. The envelope is parsed again from the same bytes (no
/// signature is verified twice); no key is used before the envelope is
/// resolved; no claim is taken here.
pub(crate) fn open_inbound(
    session: &SessionContext,
    policy: &As4PushPolicy,
    body: &[u8],
    content_type: &str,
    authenticated: &AuthenticatedInbound,
    keys: &dyn crate::crypto::wssec::xmlenc::RecipientKeys,
    suite: &crate::crypto::wssec::xmlenc::Suite,
) -> Result<VerifiedInbound> {
    let AuthenticatedInbound {
        parsed,
        declared,
        part_properties,
        deferred,
        signer_der,
        references,
        nri,
        ..
    } = authenticated;
    let (parsed, signer_der, references, nri) = (
        parsed.clone(),
        signer_der.clone(),
        references.clone(),
        nri.clone(),
    );
    let message_id = parsed.message_id.clone();
    let refused = |code: ErrorCode, detail: String| {
        AsxError::new(
            code,
            detail,
            ErrorContext::for_session_with_message("as4_receive_push", session, &message_id),
        )
    };
    enforce_non_fragment_timestamp_freshness(session, policy, &parsed)?;
    let multipart = super::super::stream::extract_multipart_related_payload_if_present(
        body,
        content_type,
        session,
        "as4_receive_push",
    )?;
    let soap_bytes = multipart.as_ref().map(|m| m.soap_xml).unwrap_or(body);
    let xml = crate::core::bytes_to_utf8_str(soap_bytes, "as4_receive_push", session)?;
    let doc = super::super::parser::parse_as4_user_message_document(xml, session)?;

    // The test service is answered here; its parts are never opened.
    if parsed.service.as_deref() == Some(crate::profile::TEST_SERVICE)
        && parsed.action == crate::profile::TEST_ACTION
    {
        return Ok(VerifiedInbound {
            parsed,
            payloads: Vec::new(),
            signer_der,
            references,
            nri,
        });
    }

    // A payload-less BDEW path-switch message (B §2.2.8, §2.3.7),
    // classified from the verified header after signer authorization, eb:To,
    // revocation and freshness. Every other payload-less message falls
    // through to the part match and is refused there.
    if declared.is_empty()
        && policy.accept_path_switch
        && crate::as4::classify_path_switch(
            parsed.service.as_deref().unwrap_or_default(),
            &parsed.action,
        )
        .is_some()
    {
        payload::check_payload_less(session, &message_id, &doc, multipart.as_ref())?;
        return Ok(VerifiedInbound {
            parsed,
            payloads: Vec::new(),
            signer_der,
            references,
            nri,
        });
    }

    // The MIME parts are exactly the declared parts.
    let parts = payload::match_parts(session, &message_id, declared, multipart.as_ref())?;

    // Envelope structure and algorithm suite, without a key.
    let security = doc
        .descendants()
        .find(|n| {
            n.is_element()
                && n.tag_name().namespace() == Some(crate::xml::ns::DS)
                && n.tag_name().name() == "Signature"
        })
        .and_then(|n| n.parent())
        .ok_or_else(|| {
            refused(
                ErrorCode::SecurityVerificationFailed,
                "the verified signature has no wsse:Security header".to_string(),
            )
        })?;
    let envelope = crate::crypto::wssec::xmlenc::resolve_envelope(
        &doc,
        security,
        declared,
        Some(suite),
        super::super::stream::MAX_INBOUND_PAYLOADS,
    )
    .map_err(|err| err.with_message_id(message_id.clone()))?;
    // Every declared part is encrypted (every AS4 preset).
    let Some(envelope) = envelope.filter(|_| policy.require_encrypted_inbound) else {
        return Err(refused(
            ErrorCode::PolicyViolation,
            format!(
                "inbound AS4 payload cid:{} is not encrypted; the profile requires every \
                 payload part to be encrypted",
                declared.first().map(String::as_str).unwrap_or_default()
            ),
        ));
    };
    if let Some(plain) = declared
        .iter()
        .find(|cid| !envelope.data.iter().any(|d| &d.cid == *cid))
    {
        return Err(refused(
            ErrorCode::PolicyViolation,
            format!(
                "inbound AS4 payload cid:{plain} is not encrypted; the profile requires every \
                 payload part to be encrypted"
            ),
        ));
    }
    // Restored part types, before any key is used.
    let mut restored = Vec::with_capacity(envelope.data.len());
    for data in &envelope.data {
        restored.push(payload::restored_type(
            session,
            &message_id,
            &data.cid,
            data.mime_type.as_deref(),
            part_properties.compression.contains_key(&data.cid),
        )?);
    }

    // Select the decrypter, one key operation, decrypt every part.
    let bodies: Vec<&[u8]> = envelope
        .data
        .iter()
        .map(|d| {
            parts
                .iter()
                .find(|p| p.content_id == d.cid)
                .map(|p| p.bytes)
                .unwrap_or_default()
        })
        .collect();
    let plaintexts = crate::crypto::wssec::xmlenc::decrypt_attachments(&envelope, &bodies, keys)
        .map_err(|err| err.with_message_id(message_id.clone()))?;

    // The `cid:` digests over the decrypted bytes, input by restored type.
    let inputs = plaintexts
        .iter()
        .zip(&restored)
        .map(|(bytes, kind)| {
            crate::crypto::wssec::swa_attachment_digest_input(kind.as_deref(), bytes)
        })
        .collect::<Result<Vec<_>>>()?;
    let digest_parts: Vec<(&str, &[u8])> = envelope
        .data
        .iter()
        .zip(&inputs)
        .map(|(d, input)| (d.cid.as_str(), input.as_ref()))
        .collect();
    crate::crypto::wssec::verify::verify_cid_references(&deferred.cid_references, &digest_parts)
        .map_err(|err| err.with_message_id(message_id.clone()))?;
    drop(inputs);

    // Decompress, in declared order.
    let mut by_cid: Vec<(String, Vec<u8>)> = envelope
        .data
        .iter()
        .map(|d| d.cid.clone())
        .zip(plaintexts)
        .collect();
    let mut payloads = Vec::with_capacity(declared.len());
    for cid in declared {
        let at = by_cid
            .iter()
            .position(|(c, _)| c == cid)
            .expect("coverage checked above");
        let (cid, bytes) = by_cid.swap_remove(at);
        let bytes = payload::decompress_payload_if_declared(
            session,
            &cid,
            &part_properties.compression,
            bytes,
        )?;
        let mime_type = part_properties
            .mime_types
            .get(&cid)
            .cloned()
            .unwrap_or_else(|| "application/octet-stream".to_string());
        payloads.push((cid, bytes, mime_type));
    }

    Ok(VerifiedInbound {
        parsed,
        payloads,
        signer_der,
        references,
        nri,
    })
}
