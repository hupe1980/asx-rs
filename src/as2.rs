use crate::core::{AsxError, ErrorCode, ErrorContext, Result, SessionContext};
#[cfg(feature = "as2")]
pub(crate) use crate::crypto::as2_smime::SmimeCipher;
use crate::send_pipeline as pipeline;
use crate::wire::enforce_payload_limit;
use std::sync::Arc;

pub(crate) mod client;
pub(crate) mod cms_keys;
#[cfg(test)]
pub(crate) use client::send_view;
pub use client::{As2, Message, PendingMdn, Received};
mod inbound;
mod ingress;
pub(crate) mod mdn;
mod mic;
mod send_client;
pub(crate) mod send_path;
mod trust;
pub(crate) mod types;

pub(crate) use trust::{As2TrustVerifier, CmsSmimeTrustVerifier};
pub(crate) use types::{
    As2MdnSigningCredentials, As2MicAlgorithm, As2SendPolicy, MimeEnvelope, ParsedMdn,
};

use mdn::extract_content_type_header;
pub(crate) use mdn::mdn_report;

const MAX_AS2_MDN_BYTES: usize = 256 * 1024;

/// Whether the body's first line is a plausible MIME header field
/// (`token ":" …`). Distinguishes bodies that repeat the outer MIME headers
/// (OpenSSL `SMIME_write_*` output, asx's own emission) from bodies that start
/// directly with content — a `multipart/signed` preamble or boundary, raw
/// PKCS#7 DER under a binary content-transfer-encoding, or a bare payload.
fn body_starts_with_mime_header(bytes: &[u8]) -> bool {
    let line_end = bytes
        .iter()
        .position(|&b| b == b'\n')
        .unwrap_or(bytes.len())
        .min(998);
    let line = &bytes[..line_end];
    let line = line.strip_suffix(b"\r").unwrap_or(line);
    let Some(colon) = line.iter().position(|&b| b == b':') else {
        return false;
    };
    let name = &line[..colon];
    !name.is_empty()
        && name.iter().all(|&b| {
            b.is_ascii_alphanumeric()
                || matches!(b, b'!' | b'#'..=b'\'' | b'-' | b'^'..=b'`' | b'|' | b'~' | b'+' | b'.')
        })
}

/// RFC 4130 partners differ in whether the HTTP entity body repeats the outer
/// MIME headers. S/MIME processing needs the self-describing form, so when the
/// body starts directly with content, synthesize the headers from the
/// transport `Content-Type`. Without this, a conformant partner that sends
/// `multipart/signed` content (or raw PKCS#7 DER under a binary
/// content-transfer-encoding) with the media type only in the HTTP header is
/// misdetected as carrying no S/MIME layer at all.
fn body_with_mime_headers(
    _session: &SessionContext,
    bytes: &Arc<[u8]>,
    body_content_type: Option<&str>,
) -> Arc<[u8]> {
    let Some(content_type) = body_content_type else {
        return Arc::clone(bytes);
    };
    if body_starts_with_mime_header(bytes) {
        return Arc::clone(bytes);
    }
    // Raw DER (a PKCS#7 ContentInfo starts with SEQUENCE, 0x30) travels under
    // a binary content-transfer-encoding; everything else is already
    // line-oriented MIME content.
    let cte: &str = if bytes.first() == Some(&0x30) {
        "Content-Transfer-Encoding: binary\r\n"
    } else {
        ""
    };
    let mut synthesized =
        format!("MIME-Version: 1.0\r\nContent-Type: {content_type}\r\n{cte}\r\n").into_bytes();
    synthesized.extend_from_slice(bytes);
    synthesized.into()
}

/// Recover the business document from a verified MIME entity, reversing RFC
/// 5402 compression when the entity advertises it.
fn decode_entity_content(
    session: &SessionContext,
    entity: &crate::crypto::as2_smime::VerifiedSmimeEntity,
) -> Result<Arc<[u8]>> {
    let content_type = entity.content_type().unwrap_or_default();
    let decoded = entity.decoded_content()?;
    if crate::crypto::compression::is_as2_compressed_content_type(&content_type) {
        return decompress_as2_entity(session, &decoded);
    }
    Ok(Arc::from(decoded.as_ref()))
}

/// Unwrap an RFC 5402 CMS `CompressedData` body.
fn decompress_as2_entity(session: &SessionContext, compressed: &[u8]) -> Result<Arc<[u8]>> {
    {
        let plain = crate::crypto::compression::decompress_cms_zlib(compressed).map_err(|err| {
            AsxError::new(
                err.code,
                format!(
                    "failed to decompress AS2 payload (RFC 5402): {}",
                    err.message
                ),
                ErrorContext::for_session("as2_receive_decompress", session),
            )
        })?;
        Ok(Arc::from(plain))
    }
}

/// An RFC 5322 msg-id without surrounding whitespace and angle brackets.
/// Comparison stays case-sensitive.
fn normalize_message_id(id: &str) -> &str {
    let id = id.trim();
    let id = id.strip_prefix('<').unwrap_or(id);
    id.strip_suffix('>').unwrap_or(id).trim()
}

/// `"base64-digest, algorithm"` (RFC 4130 §7.4.3) → `(algorithm, digest)`.
fn split_mic(value: &str) -> Option<(&str, Vec<u8>)> {
    use base64::Engine as _;
    let (digest, algorithm) = value.split_once(',').unwrap_or((value, ""));
    let digest = base64::engine::general_purpose::STANDARD
        .decode(digest.trim().trim_matches('"'))
        .ok()?;
    Some((algorithm.trim().trim_matches('"'), digest))
}

#[cfg(test)]
mod tests;
