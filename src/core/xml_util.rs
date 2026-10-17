//! XML text decoding helpers.

use super::*;

/// Interpret a byte slice as UTF-8, returning a contextual error on failure.
/// Avoids repeating the 4-line `from_utf8(...).map_err(|_| AsxError::new(...))` pattern.
pub(crate) fn bytes_to_utf8_str<'a>(
    bytes: &'a [u8],
    stage: &'static str,
    session: &SessionContext,
) -> Result<&'a str> {
    std::str::from_utf8(bytes).map_err(|_| {
        AsxError::new(
            ErrorCode::ParseFailed,
            format!("{stage}: payload is not valid UTF-8"),
            ErrorContext::for_session(stage, session),
        )
    })
}

/// Decode base64 that came out of an XML text node.
///
/// XML Signature §6.1 and XML Encryption both define their base64 content by
/// reference to RFC 2045, which **line-wraps**, and any XML pretty-printer will
/// happily fold a long `ds:DigestValue` or `ds:SignatureValue` anyway. The
/// `base64` crate's standard engine rejects embedded whitespace, so decoding
/// such a value directly turns a conformant counterparty into a parse failure —
/// or, worse, into a digest "mismatch" reported as a security incident.
///
/// Strip ASCII whitespace first, then decode. Every base64 value that arrives
/// inside an XML document goes through here.
// XML-carried base64 only: the AS2 side unfolds and decodes inline, because a
// folded MIME header is a different shape from a wrapped `ds:DigestValue`.
pub(crate) fn decode_xml_base64(value: &str, label: &str, stage: &'static str) -> Result<Vec<u8>> {
    use base64::Engine as _;
    let normalized: String = value.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    base64::engine::general_purpose::STANDARD
        .decode(normalized)
        .map_err(|err| {
            AsxError::new(
                ErrorCode::ParseFailed,
                format!("failed to decode base64 {label}: {err}"),
                ErrorContext::new(stage),
            )
        })
}
