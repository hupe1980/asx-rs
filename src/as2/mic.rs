//! RFC 4130 §7.3.1 Message-Integrity-Check (MIC) computation.
//!
//! The MIC is the value a receiver echoes back in the MDN's
//! `Received-Content-MIC` header so the sender can prove the bytes that arrived
//! are the bytes it sent. Sender and receiver therefore have to digest *exactly*
//! the same octets, and RFC 4130 §7.3.1 defines which ones:
//!
//! | Message | MIC input |
//! |---|---|
//! | Signed (with or without encryption) | the signed MIME entity — **headers, blank line, content** |
//! | Encrypted but unsigned | the decrypted MIME entity — headers and content |
//! | Neither signed nor encrypted | the content **only**, with no MIME headers at all |
//!
//! The last row is not an oversight in the RFC: unprotected messages travel
//! through intermediaries that reorder and rewrite headers, so including them
//! would make the MIC unreproducible.
//!
//! Everything here works on exact octets. Nothing re-serializes, re-folds, or
//! normalizes a header — doing so is the classic way to produce a MIC that is
//! self-consistent but matches no partner on earth.

use base64::{Engine as _, engine::general_purpose::STANDARD};

use super::As2MicAlgorithm;

/// Digest an exact byte sequence and return `(base64-digest, algorithm-name)`.
///
/// The algorithm name is the RFC 4130 §7.3 spelling (`sha-256`, …) used in the
/// `Received-Content-MIC` header and in `Disposition-Notification-Options`.
///
/// Callers pass the precise MIC input; selecting it (entity vs. bare content)
/// happens on the send and receive paths, which know what protection applied.
pub(crate) fn compute_mic(bytes: &[u8], algorithm: As2MicAlgorithm) -> (String, &'static str) {
    use sha2::Digest;
    match algorithm {
        As2MicAlgorithm::Sha256 => (STANDARD.encode(sha2::Sha256::digest(bytes)), "sha-256"),
        As2MicAlgorithm::Sha384 => (STANDARD.encode(sha2::Sha384::digest(bytes)), "sha-384"),
        As2MicAlgorithm::Sha512 => (STANDARD.encode(sha2::Sha512::digest(bytes)), "sha-512"),
    }
}

/// Build a MIME entity: headers, blank line, then content.
///
/// This is what AS2 signs and what the MIC is computed over, so the exact bytes
/// produced here are load-bearing. Headers use CRLF line endings per RFC 2045.
///
/// `content_transfer_encoding` is emitted when supplied. AS2 payloads are sent
/// with `binary` transfer encoding over HTTP (RFC 4130 §5) — HTTP is 8-bit
/// clean, so there is no reason to base64-inflate an EDI document by a third.
pub fn build_mime_entity(
    content_type: &str,
    content_transfer_encoding: Option<&str>,
    content: &[u8],
) -> Vec<u8> {
    let mut entity = Vec::with_capacity(content.len() + 96);
    entity.extend_from_slice(b"Content-Type: ");
    entity.extend_from_slice(content_type.as_bytes());
    entity.extend_from_slice(b"\r\n");
    if let Some(cte) = content_transfer_encoding {
        entity.extend_from_slice(b"Content-Transfer-Encoding: ");
        entity.extend_from_slice(cte.as_bytes());
        entity.extend_from_slice(b"\r\n");
    }
    entity.extend_from_slice(b"\r\n");
    entity.extend_from_slice(content);
    entity
}

/// Build the outbound entity, picking a transfer encoding that survives
/// `multipart/signed`.
///
/// RFC 5751 §3.1.1 requires binary content to be transfer-encoded before
/// signing. MIME line-ending canonicalization would otherwise rewrite bytes
/// inside a compressed or encrypted blob and break the signature — the digest
/// covers the entity *as transmitted*, so the encoding has to be settled before
/// the MIC is taken.
///
/// Text-shaped payloads (EDI, XML, CSV) keep `binary` transfer encoding, which
/// is what AS2 partners expect and avoids inflating them by a third.
pub fn build_outbound_entity(content_type: &str, content: &[u8]) -> Vec<u8> {
    if content_requires_base64(content) {
        let encoded = wrap_base64_lines(&STANDARD.encode(content));
        build_mime_entity(content_type, Some("base64"), encoded.as_bytes())
    } else {
        build_mime_entity(content_type, Some("binary"), content)
    }
}

/// Whether `content` contains octets that MIME processing would not preserve.
///
/// Control characters outside tab/CR/LF, NUL bytes, and 8-bit octets all mark
/// content as binary.
fn content_requires_base64(content: &[u8]) -> bool {
    content
        .iter()
        .any(|&b| b >= 0x80 || (b < 0x20 && !matches!(b, b'\t' | b'\r' | b'\n')))
}

/// Fold base64 into 76-character lines (RFC 2045 §6.8).
fn wrap_base64_lines(encoded: &str) -> String {
    let mut out = String::with_capacity(encoded.len() + encoded.len() / 76 * 2);
    for (i, chunk) in encoded.as_bytes().chunks(76).enumerate() {
        if i > 0 {
            out.push_str("\r\n");
        }
        out.push_str(std::str::from_utf8(chunk).expect("base64 is ASCII"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entity_layout_is_crlf_delimited() {
        let entity = build_mime_entity("application/edi-x12", Some("binary"), b"ISA*00~");
        assert_eq!(
            entity,
            b"Content-Type: application/edi-x12\r\nContent-Transfer-Encoding: binary\r\n\r\nISA*00~"
                .to_vec()
        );
    }

    #[test]
    fn entity_omits_transfer_encoding_when_absent() {
        let entity = build_mime_entity("application/xml", None, b"<x/>");
        assert_eq!(
            entity,
            b"Content-Type: application/xml\r\n\r\n<x/>".to_vec()
        );
    }

    #[test]
    fn mic_matches_a_hand_computed_digest_over_the_entity() {
        use sha2::Digest;
        let entity = build_mime_entity("application/edi-x12", Some("binary"), b"ISA*00~");
        let (mic, alg) = compute_mic(&entity, As2MicAlgorithm::Sha256);

        assert_eq!(alg, "sha-256");
        assert_eq!(mic, STANDARD.encode(sha2::Sha256::digest(&entity)));
    }

    #[test]
    fn mic_is_sensitive_to_content_type_octets() {
        let a = build_mime_entity("application/xml", None, b"p");
        let b = build_mime_entity("application/xml ", None, b"p");
        assert_ne!(
            compute_mic(&a, As2MicAlgorithm::Sha256).0,
            compute_mic(&b, As2MicAlgorithm::Sha256).0,
            "MIC must change when Content-Type octets differ"
        );
    }

    #[test]
    fn each_algorithm_reports_its_rfc4130_name() {
        for (alg, name) in [
            (As2MicAlgorithm::Sha256, "sha-256"),
            (As2MicAlgorithm::Sha384, "sha-384"),
            (As2MicAlgorithm::Sha512, "sha-512"),
        ] {
            assert_eq!(compute_mic(b"x", alg).1, name);
        }
    }
}
