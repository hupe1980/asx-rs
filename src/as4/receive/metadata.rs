use super::super::parser::{parse_as4_user_message_document, parse_as4_user_message_from_doc};
use super::super::stream::extract_multipart_related_payload_if_present;
use super::super::types::As4PushPolicy;
use super::{As4Verifier, payload};
use crate::core::{Result, SessionContext};

/// A parsed envelope whose signature value, signer and same-document
/// references verified. The `cid:` references are still open
/// (`signature.deferred`), and so is the revocation of
/// `signature.signer_path`.
pub(super) struct VerifiedHeader<'a> {
    pub(super) soap_xml: &'a str,
    pub(super) parsed: super::super::ParsedAs4UserMessage,
    /// `eb:PartInfo/@href` of the bound `eb:Messaging`, normalized, in order.
    pub(super) declared: Vec<String>,
    pub(super) part_properties: payload::PartProperties,
    pub(super) signature: Option<crate::crypto::wssec::verify::VerifiedSignatureCoverage>,
}

/// Parse the envelope and verify its WS-Security up to the attachments, up
/// to but not including the dedup claim.
///
/// The claim is taken by the caller, after the remaining steps: it must come
/// *after* signature verification, so an unauthenticated peer cannot burn a
/// partner's `eb:MessageId`, and it must be visible to the code that owns the
/// remaining fallible steps, so a failure can release it again.
pub(super) fn parse_and_verify_receive_push_metadata<'a>(
    session: &SessionContext,
    payload_bytes: &'a [u8],
    http_content_type: &str,
    policy: &As4PushPolicy,
    verifier: &(dyn As4Verifier + Send + Sync),
    authorizer: Option<&dyn super::SenderAuthorizer>,
) -> Result<VerifiedHeader<'a>> {
    let multipart = extract_multipart_related_payload_if_present(
        payload_bytes,
        http_content_type,
        session,
        "as4_receive_push",
    )?;
    let soap_bytes = multipart
        .as_ref()
        .map(|m| m.soap_xml)
        .unwrap_or(payload_bytes);

    let xml = crate::core::bytes_to_utf8_str(soap_bytes, "as4_receive_push", session)?;
    let doc = parse_as4_user_message_document(xml, session)?;

    let parsed = parse_as4_user_message_from_doc(session, &doc)?;
    // Resolved from the *claimed* sender, then checked against the *verified*
    // signer — which is what turns a valid signature into proof of identity.
    //
    // An empty result is not refused here: an *unsigned* message has no signer
    // to attribute, and whether one is present is only known after parsing the
    // security header. The verifier makes that call.
    let authorization = match authorizer {
        Some(authorizer) => Some(authorizer.authorize(&parsed)?),
        None => None,
    };
    let permitted_signers = match &authorization {
        Some(auth) => auth.pins.clone(),
        None => super::super::services::session_signer_pins(session)?,
    };
    let signer_check = authorization.as_ref().and_then(|a| a.check.as_deref());

    let evidence = std::sync::OnceLock::new();
    verifier.verify_security(super::verifier::As4SecurityVerification {
        session,
        policy,
        soap_xml: xml,
        soap_doc: &doc,
        message_id: &parsed.message_id,
        external_references: &[],
        from_party_id: parsed.sender_party_id(),
        permitted_signers: &permitted_signers,
        signer_check,
        evidence: &evidence,
    })?;

    // The payload set is what the signed header declares;
    // each declared part must be covered by a signed `cid:` reference, whose
    // digest waits for the decrypted bytes.
    let declared = payload::declared_parts(session, &doc, &parsed.message_id)?;
    if let Some(signature) = evidence.get() {
        let coverage: Vec<(&str, &[u8])> = declared.iter().map(|c| (c.as_str(), &[][..])).collect();
        super::verifier::enforce_attachment_signature_coverage(
            session,
            &parsed.message_id,
            &coverage,
            signature,
        )?;
    }

    // Part properties are read from the verified DOM — the one eb:Messaging
    // the signature covers — not from a re-parse of the bytes.
    let part_properties = payload::part_properties(session, &doc, &parsed.message_id)?;

    Ok(VerifiedHeader {
        soap_xml: xml,
        parsed,
        declared,
        part_properties,
        signature: evidence.into_inner(),
    })
}
