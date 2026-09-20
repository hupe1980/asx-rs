use super::super::parser::{
    parse_as4_user_message_document, parse_as4_user_message_from_doc,
    precheck_as4_user_message_structure_bytes,
};
use super::super::stream::{MultipartAs4Payload, extract_multipart_related_payload_if_present};
use super::super::types::As4PushPolicy;
use super::{As4Verifier, payload};
use crate::core::{Result, SessionContext};
use crate::observability::EventBus;
use roxmltree::Document;

#[allow(clippy::too_many_arguments)]
fn verify_wssec_gate(
    session: &SessionContext,
    xml: &str,
    soap_doc: &Document<'_>,
    policy: &As4PushPolicy,
    message_id: &str,
    external_references: &[(&str, &[u8])],
    verifier: &(dyn As4Verifier + Send + Sync),
    from_party_id: &str,
    permitted_signers: &[crate::crypto::CertFingerprint],
) -> Result<payload::WsSecVerifiedGate> {
    verifier.verify_security(super::verifier::As4SecurityVerification {
        session,
        policy,
        soap_xml: xml,
        soap_doc,
        message_id,
        external_references,
        from_party_id,
        permitted_signers,
    })?;
    Ok(payload::WsSecVerifiedGate)
}

/// The signing certificates the **claimed** `eb:From` party may use.
///
/// Resolution order: the caller's resolver, then the session's single-partner
/// pin. An empty result refuses the message, because a signature that verifies
/// against the network's anchors proves membership of the network, not the
/// identity of the sender — every access point shares those anchors.
fn permitted_signers_for(
    session: &SessionContext,
    signer_pins: Option<&std::sync::Arc<dyn super::super::As4SignerPins>>,
    from_party_id: &str,
) -> Vec<crate::crypto::CertFingerprint> {
    if let Some(pins) = signer_pins {
        let resolved = pins.pins_for(from_party_id);
        if !resolved.is_empty() {
            return resolved.to_vec();
        }
        // A resolver that was supplied and answered "nothing" is a decision,
        // not a gap: do not silently widen it with the session pin.
        return Vec::new();
    }
    super::super::services::session_signer_pins(session)
}

/// `cid:` reference material for WS-Security verification: **every** payload
/// attachment, so each one's digest can be checked and each one can be proven
/// signature-covered.
///
/// Each attachment's bytes are pre-transformed per the WSS SwA
/// `Attachment-Content-Signature-Transform`, selected by the MIME part's
/// `Content-Type` — XML-typed parts are digested over their Exclusive C14N
/// form, `text/*` parts over CRLF-normalized octets (what WSS4J-based signers
/// compute).
type SwaExternalReference<'a> = (&'a str, std::borrow::Cow<'a, [u8]>);

fn wssec_external_references<'a>(
    multipart: &'a Option<MultipartAs4Payload<'a>>,
) -> Result<Vec<SwaExternalReference<'a>>> {
    let Some(multipart) = multipart.as_ref() else {
        return Ok(Vec::new());
    };
    multipart
        .external_references()
        .into_iter()
        .map(|(cid, content_type, bytes)| {
            crate::crypto::wssec::swa_attachment_digest_input(content_type, bytes)
                .map(|input| (cid, input))
        })
        .collect()
}

/// Parse the envelope and verify its WS-Security, up to but not including the
/// dedup claim.
///
/// The claim is taken by the caller, immediately after this returns: it must
/// come *after* signature verification, so an unauthenticated peer cannot burn
/// a partner's `eb:MessageId`, and it must be visible to the code that owns the
/// remaining fallible steps, so a failure can release it again.
#[allow(clippy::type_complexity)]
pub(super) fn parse_and_verify_receive_push_metadata<'a>(
    session: &SessionContext,
    event_bus: &EventBus,
    payload_bytes: &'a [u8],
    http_content_type: &str,
    policy: &As4PushPolicy,
    verifier: &(dyn As4Verifier + Send + Sync),
    signer_pins: Option<&std::sync::Arc<dyn super::super::As4SignerPins>>,
) -> Result<(
    Option<MultipartAs4Payload<'a>>,
    &'a [u8],
    super::super::ParsedAs4UserMessage,
    payload::WsSecVerifiedGate,
)> {
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

    precheck_as4_user_message_structure_bytes(soap_bytes, session, "as4_receive_push")?;

    let xml = crate::core::bytes_to_utf8_str(soap_bytes, "as4_receive_push", session)?;
    let doc = parse_as4_user_message_document(xml, session)?;
    let wssec_external_references = wssec_external_references(&multipart)?;
    let wssec_external_references: Vec<(&str, &[u8])> = wssec_external_references
        .iter()
        .map(|(cid, input)| (*cid, input.as_ref()))
        .collect();

    let parsed = parse_as4_user_message_from_doc(
        session,
        event_bus,
        &doc,
        policy.interop,
        policy.fail_closed_audit_events,
    )?;
    // Resolved from the *claimed* sender, then checked against the *verified*
    // signer — which is what turns a valid signature into proof of identity.
    //
    // An empty result is not refused here: an *unsigned* message has no signer
    // to attribute, and whether one is present is only known after parsing the
    // security header. The verifier makes that call.
    let permitted_signers = permitted_signers_for(session, signer_pins, parsed.from_party_id());

    let gate = verify_wssec_gate(
        session,
        xml,
        &doc,
        policy,
        &parsed.message_id,
        &wssec_external_references,
        verifier,
        parsed.from_party_id(),
        &permitted_signers,
    )?;

    Ok((multipart, soap_bytes, parsed, gate))
}
