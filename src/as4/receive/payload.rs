//! The payload parts of a verified inbound message: the declared set
//! (`eb:PartInfo/@href` of the signed `eb:Messaging`), its match against the
//! MIME parts, type restoration and decompression.

use super::super::stream::{InboundAttachment, MAX_INBOUND_PAYLOADS, MultipartAs4Payload};
use crate::core::{AsxError, ErrorCode, ErrorContext, Result, SessionContext};
use crate::crypto::wssec::xmlenc::normalize_cid;
use crate::xml::ns::EBMS3;

fn is_eb(n: &roxmltree::Node<'_, '_>, local: &str) -> bool {
    n.is_element() && n.tag_name().namespace() == Some(EBMS3) && n.tag_name().name() == local
}

/// The one `eb:Messaging` of the envelope (the verifier bound it to the
/// signature: `enforce_messaging_signature_coverage`).
fn messaging<'a, 'i>(
    session: &SessionContext,
    doc: &'a roxmltree::Document<'i>,
    message_id: &str,
) -> Result<roxmltree::Node<'a, 'i>> {
    let mut all = doc.descendants().filter(|n| is_eb(n, "Messaging"));
    match (all.next(), all.next()) {
        (Some(one), None) => Ok(one),
        _ => Err(AsxError::new(
            ErrorCode::InteropViolation,
            "AS4 envelope must contain exactly one eb:Messaging header block",
            ErrorContext::for_session_with_message("as4_receive_push", session, message_id),
        )),
    }
}

/// The payload parts the signed header declares: every
/// `eb:UserMessage/eb:PayloadInfo/eb:PartInfo/@href`, normalized, in order.
/// Only SwA attachments are accepted: a `PartInfo` without a `cid:` href
/// names the Body and is refused.
pub(super) fn declared_parts(
    session: &SessionContext,
    doc: &roxmltree::Document<'_>,
    message_id: &str,
) -> Result<Vec<String>> {
    let refuse = |detail: String| {
        AsxError::new(
            ErrorCode::InteropViolation,
            detail,
            ErrorContext::for_session_with_message("as4_receive_push", session, message_id),
        )
    };
    let messaging = messaging(session, doc, message_id)?;
    let mut declared: Vec<String> = Vec::new();
    for part_info in messaging
        .descendants()
        .filter(|n| is_eb(n, "PartInfo"))
        .filter(|n| n.parent().is_some_and(|p| is_eb(&p, "PayloadInfo")))
    {
        let href = part_info.attribute("href").unwrap_or_default();
        if !href
            .trim()
            .get(..4)
            .is_some_and(|p| p.eq_ignore_ascii_case("cid:"))
        {
            return Err(refuse(format!(
                "eb:PartInfo href {href:?} does not name a MIME attachment: inline SOAP body \
                 payloads are not supported (PEPPOL/CEF/BDEW require SwA attachment packaging)"
            )));
        }
        let cid = normalize_cid(href).to_string();
        if cid.is_empty() || declared.contains(&cid) {
            return Err(refuse(format!(
                "eb:PartInfo href {href:?} is empty or declared twice"
            )));
        }
        declared.push(cid);
    }
    if declared.len() > MAX_INBOUND_PAYLOADS {
        return Err(AsxError::new(
            ErrorCode::PayloadTooLarge,
            format!("AS4 message declares more than {MAX_INBOUND_PAYLOADS} payload parts"),
            ErrorContext::for_session_with_message("as4_receive_push", session, message_id),
        ));
    }
    Ok(declared)
}

/// The shape of an accepted payload-less message:
/// no XML Encryption structure anywhere — there is nothing the profile lets
/// be encrypted (AS4 Profile 1.0 §5.1.6; B P-Mode `Encrypt.Element[]` is
/// empty), so any `xenc:*` is refused with EBMS:0103 before a key could be
/// used — an empty SOAP Body, and no MIME part besides the SOAP root.
pub(super) fn check_payload_less(
    session: &SessionContext,
    message_id: &str,
    doc: &roxmltree::Document<'_>,
    multipart: Option<&MultipartAs4Payload<'_>>,
) -> Result<()> {
    use crate::xml::ns::{SOAP12, XENC, XENC11};
    let context =
        || ErrorContext::for_session_with_message("as4_receive_push", session, message_id);
    if let Some(xenc) = doc
        .descendants()
        .find(|n| n.is_element() && matches!(n.tag_name().namespace(), Some(XENC | XENC11)))
    {
        return Err(AsxError::new(
            ErrorCode::PolicyViolation,
            format!(
                "a payload-less path-switch message carries xenc:{}; it has nothing to \
                 encrypt (AS4 Profile 1.0 §5.1.6, BDEW AS4-Profil 1.2 §2.3.7)",
                xenc.tag_name().name()
            ),
            context(),
        ));
    }
    if let Some(part) = multipart.and_then(|m| m.payloads.first()) {
        return Err(AsxError::new(
            ErrorCode::InteropViolation,
            format!(
                "MIME part cid:{} is not declared by eb:PartInfo",
                part.content_id
            ),
            context(),
        ));
    }
    let body_is_empty = doc
        .root_element()
        .children()
        .find(|n| {
            n.is_element()
                && n.tag_name().namespace() == Some(SOAP12)
                && n.tag_name().name() == "Body"
        })
        .is_some_and(|body| {
            body.children().all(|c| {
                c.is_comment() || (c.is_text() && c.text().unwrap_or("").trim().is_empty())
            })
        });
    if !body_is_empty {
        return Err(AsxError::new(
            ErrorCode::InteropViolation,
            "a message without eb:PartInfo must have an empty SOAP Body",
            context(),
        ));
    }
    Ok(())
}

/// The MIME parts after the root are exactly the declared parts. The
/// result is in declared order.
pub(super) fn match_parts<'a>(
    session: &SessionContext,
    message_id: &str,
    declared: &[String],
    multipart: Option<&MultipartAs4Payload<'a>>,
) -> Result<Vec<InboundAttachment<'a>>> {
    let refuse = |detail: String| {
        AsxError::new(
            ErrorCode::InteropViolation,
            detail,
            ErrorContext::for_session_with_message("as4_receive_push", session, message_id),
        )
    };
    let Some(multipart) = multipart else {
        return Err(AsxError::new(
            ErrorCode::PolicyViolation,
            "AS4 inbound payload must be multipart/related with a detached payload attachment",
            ErrorContext::for_session_with_message("as4_receive_push", session, message_id),
        ));
    };
    if declared.is_empty() {
        return Err(refuse(
            "AS4 message declares no payload part: inline SOAP body payloads are not \
             supported. PEPPOL/CEF require MIME multipart/related attachment packaging. If \
             the sending partner uses inline body mode, reconfigure their AS4 gateway to use \
             SwA MIME attachment packaging."
                .to_string(),
        ));
    }
    for (i, part) in multipart.payloads.iter().enumerate() {
        if !declared.iter().any(|d| d == part.content_id) {
            return Err(refuse(format!(
                "MIME part cid:{} is not declared by eb:PartInfo",
                part.content_id
            )));
        }
        if multipart.payloads[..i]
            .iter()
            .any(|p| p.content_id == part.content_id)
        {
            return Err(refuse(format!(
                "two MIME parts carry Content-ID cid:{}",
                part.content_id
            )));
        }
    }
    declared
        .iter()
        .map(|cid| {
            multipart
                .payloads
                .iter()
                .find(|p| p.content_id == cid)
                .copied()
                .ok_or_else(|| {
                    refuse(format!(
                        "eb:PartInfo declares cid:{cid} but no MIME part carries it"
                    ))
                })
        })
        .collect()
}

/// The `CompressionType` and `MimeType` part properties of the verified
/// `eb:Messaging` header, each keyed by the referenced payload Content-ID.
#[derive(Debug, Default)]
pub(super) struct PartProperties {
    pub(super) compression: std::collections::HashMap<String, String>,
    pub(super) mime_types: std::collections::HashMap<String, String>,
}

/// Read [`PartProperties`] from the one `eb:Messaging` the signature covers.
///
/// `CompressionType` is the only conformant signal that a payload is
/// compressed (AS4 profile §3.1): sniffing the gzip magic number would expand
/// a business document that merely is a gzip file. `MimeType` is the business
/// type the handler sees. A property named twice in one `eb:PartInfo` is
/// ambiguous and refused.
pub(super) fn part_properties(
    session: &crate::core::SessionContext,
    doc: &roxmltree::Document<'_>,
    message_id: &str,
) -> Result<PartProperties> {
    let reject = |detail: String| {
        AsxError::new(
            ErrorCode::InteropViolation,
            detail,
            crate::core::ErrorContext::for_session_with_message(
                "as4_receive_push",
                session,
                message_id,
            ),
        )
    };
    let messaging = messaging(session, doc, message_id)?;

    let mut out = PartProperties::default();
    for part_info in messaging.descendants().filter(|n| is_eb(n, "PartInfo")) {
        let Some(href) = part_info.attribute("href") else {
            continue;
        };
        let cid = normalize_cid(href);
        let (mut compression, mut mime_type) = (None, None);
        for property in part_info.descendants().filter(|n| is_eb(n, "Property")) {
            if !property
                .parent()
                .is_some_and(|p| is_eb(&p, "PartProperties"))
            {
                return Err(reject(
                    "eb:PartInfo carries an eb:Property outside eb:PartProperties (ebMS3 \
                     header schema)"
                        .to_string(),
                ));
            }
            let name = property.attribute("name");
            let slot = match name {
                Some("CompressionType") => &mut compression,
                Some("MimeType") => &mut mime_type,
                _ => continue,
            };
            let value = crate::as4::parser::property_value_from_node(
                property,
                session,
                "as4_receive_push",
            )?;
            if slot.is_some() {
                return Err(reject(format!(
                    "eb:PartInfo cid:{cid} declares the {} property more than once",
                    name.unwrap_or_default()
                )));
            }
            *slot = Some(value);
        }
        if let Some(Some(value)) = compression {
            out.compression.insert(cid.to_string(), value);
        }
        if let Some(Some(value)) = mime_type {
            out.mime_types.insert(cid.to_string(), value);
        }
    }
    Ok(out)
}

/// The part's type after decryption:
/// `EncryptedData/@MimeType`; when absent `application/gzip` for a part
/// whose `CompressionType` is declared, else the MIME type `eb:PartInfo`
/// declares (`None`: raw octets). `application/gzip` without a declared
/// `CompressionType`, or the reverse, is refused.
pub(super) fn restored_type(
    session: &SessionContext,
    message_id: &str,
    cid: &str,
    mime_type: Option<&str>,
    compressed: bool,
) -> Result<Option<String>> {
    let gzip = crate::crypto::compression::AS4_COMPRESSION_TYPE;
    match mime_type {
        Some(declared) => {
            let media = declared.split(';').next().unwrap_or("").trim();
            if media.eq_ignore_ascii_case(gzip) != compressed {
                return Err(AsxError::new(
                    ErrorCode::InteropViolation,
                    format!(
                        "xenc:EncryptedData for cid:{cid} declares MimeType {declared:?} but \
                         eb:PartInfo {} a CompressionType",
                        if compressed {
                            "declares"
                        } else {
                            "declares no"
                        }
                    ),
                    ErrorContext::for_session_with_message("as4_receive_push", session, message_id),
                ));
            }
            Ok(Some(declared.to_string()))
        }
        None if compressed => Ok(Some(gzip.to_string())),
        None => Ok(None),
    }
}

/// Reverse AS4 payload compression when the signed `eb:PartInfo` declares it.
pub(super) fn decompress_payload_if_declared(
    session: &SessionContext,
    content_id: &str,
    compression_types: &std::collections::HashMap<String, String>,
    payload: Vec<u8>,
) -> Result<Vec<u8>> {
    let Some(compression_type) = compression_types.get(normalize_cid(content_id)) else {
        return Ok(payload);
    };

    if !compression_type.eq_ignore_ascii_case(crate::crypto::compression::AS4_COMPRESSION_TYPE) {
        return Err(AsxError::new(
            ErrorCode::InteropViolation,
            format!(
                "AS4 payload declares unsupported CompressionType \"{compression_type}\"; \
                 the AS4 profile defines only \"{}\"",
                crate::crypto::compression::AS4_COMPRESSION_TYPE
            ),
            ErrorContext::for_session("as4_receive_decompress", session),
        ));
    }

    crate::crypto::compression::decompress_gzip(&payload).map_err(|err| {
        AsxError::new(
            err.code,
            format!(
                "failed to decompress AS4 payload attachment: {}",
                err.message
            ),
            ErrorContext::for_session("as4_receive_decompress", session),
        )
    })
}
