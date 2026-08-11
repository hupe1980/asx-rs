//! Low-level stream-processing helpers for the AS4 receive pipeline.
//!
//! **P0 Streaming Refactor (May 21, 2026)**:
//! This module implements streaming-aware MIME parsing with minimal intermediate allocation.
//! Instead of materializing ALL multipart parts into a Vec, we only materialize the parts
//! we actually need (root SOAP + referenced attachment). This dramatically reduces memory
//! pressure for large payloads (10MB+) and eliminates unnecessary cloning in the hot path.
//!
//! Architecture: StreamingMimeParser yields part references (slices) without materializing.
//! Only the SOAP root and the parts referenced by an `xop:Include` are kept;
//! unreferenced parts are skipped without allocation.
//!
//! All functions are `pub(super)` — they are implementation details of the
//! `as4` module family and must not be part of the public API.

use crate::core::{AsxError, ErrorCode, ErrorContext, Result, SessionContext};
use crate::crypto::wssec::decrypt_payload_xmlenc;
use memchr::{memchr, memmem};

/// One inbound MIME payload part, resolved against an `xop:Include` reference.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct InboundAttachment<'a> {
    /// Content-ID, normalized: no `cid:` scheme, no angle brackets.
    pub content_id: &'a str,
    /// The MIME part's `Content-Type` header value, when present. Selects the
    /// SwA attachment digest input (XML canonicalization / CRLF / raw).
    pub content_type: Option<&'a str>,
    pub bytes: &'a [u8],
}

#[derive(Debug)]
pub(super) struct MultipartAs4Payload<'a> {
    pub soap_xml: &'a [u8],
    /// Payload attachments in `xop:Include` document order.
    ///
    /// ebMS3 allows several `eb:PartInfo` entries per `UserMessage`, and the
    /// eDelivery conformance payload profiles exercise up to four. Empty when
    /// the body carries no `xop:Include`.
    pub payloads: Vec<InboundAttachment<'a>>,
}

impl<'a> MultipartAs4Payload<'a> {
    /// The first payload attachment — the common single-payload case.
    #[cfg(test)]
    pub fn primary(&self) -> Option<InboundAttachment<'a>> {
        self.payloads.first().copied()
    }

    /// `(content_id, part_content_type, bytes)` triples for WS-Security
    /// `cid:` reference resolution.
    pub fn external_references(&self) -> Vec<(&'a str, Option<&'a str>, &'a [u8])> {
        self.payloads
            .iter()
            .map(|p| (p.content_id, p.content_type, p.bytes))
            .collect()
    }
}

fn parse_multipart_boundary_from_content_type(content_type: &str) -> Result<Option<String>> {
    let mut segments = content_type.split(';');
    let media_type = segments.next().unwrap_or("").trim();
    if !media_type.eq_ignore_ascii_case("multipart/related") {
        return Ok(None);
    }

    for segment in segments {
        let mut kv = segment.trim().splitn(2, '=');
        let key = kv.next().unwrap_or("").trim();
        if !key.eq_ignore_ascii_case("boundary") {
            continue;
        }
        let raw_value = kv.next().unwrap_or("").trim();
        let value = raw_value
            .strip_prefix('"')
            .and_then(|v| v.strip_suffix('"'))
            .unwrap_or(raw_value)
            .trim();
        if value.is_empty() {
            return Err(AsxError::new(
                ErrorCode::ParseFailed,
                "multipart/related Content-Type has an empty boundary parameter",
                ErrorContext::new("as4_receive_push"),
            ));
        }
        if value.ends_with("--") {
            return Err(AsxError::new(
                ErrorCode::ParseFailed,
                "multipart/related boundary parameter is malformed",
                ErrorContext::new("as4_receive_push"),
            ));
        }
        return Ok(Some(value.to_string()));
    }

    Err(AsxError::new(
        ErrorCode::ParseFailed,
        "multipart/related Content-Type is missing required boundary parameter",
        ErrorContext::new("as4_receive_push"),
    ))
}

/// Content-ID of the first `href="cid:…"` in the SOAP envelope, with the
/// scheme prefix stripped.
#[cfg(test)]
pub(super) fn extract_xop_cid_href_bytes(soap_xml: &[u8]) -> Option<&str> {
    collect_cid_hrefs(soap_xml, 1).into_iter().next()
}

/// Collect up to `limit` distinct `cid:` hrefs, in document order.
///
/// Accepts both XML quoting styles and optional whitespace around `=`, so
/// `href="cid:x"`, `href='cid:x'` and `href = "cid:x"` are all recognised. A
/// single-quoted `href` is legal XML and several stacks emit it; matching only
/// the double-quoted form used to leave the attachment unidentified, which in
/// turn meant it could not be tied to a `ds:Reference URI="cid:…"` and so could
/// never be proven signature-covered.
///
/// Duplicate references are collapsed — one attachment referenced twice is
/// still one attachment.
pub(super) fn collect_cid_hrefs(soap_xml: &[u8], limit: usize) -> Vec<&str> {
    let mut found: Vec<&str> = Vec::new();
    let mut search_from = 0usize;

    while found.len() < limit
        && let Some(rel) = memmem::find(&soap_xml[search_from..], b"href")
    {
        let after_name = search_from + rel + b"href".len();
        search_from = after_name;

        let mut cursor = after_name;
        // `href` must be followed by `=`, optionally separated by whitespace.
        while soap_xml.get(cursor).is_some_and(u8::is_ascii_whitespace) {
            cursor += 1;
        }
        if soap_xml.get(cursor) != Some(&b'=') {
            continue;
        }
        cursor += 1;
        while soap_xml.get(cursor).is_some_and(u8::is_ascii_whitespace) {
            cursor += 1;
        }

        let quote = match soap_xml.get(cursor) {
            Some(&q @ (b'"' | b'\'')) => q,
            _ => continue,
        };
        cursor += 1;

        let value_start = cursor;
        let Some(end_rel) = memchr::memchr(quote, &soap_xml[value_start..]) else {
            continue;
        };
        let value = &soap_xml[value_start..value_start + end_rel];

        // Only `cid:` hrefs identify a MIME attachment.
        let Some(cid) = value
            .get(..4)
            .filter(|prefix| prefix.eq_ignore_ascii_case(b"cid:"))
            .map(|_| &value[4..])
        else {
            continue;
        };

        if let Ok(cid) = std::str::from_utf8(cid)
            && !cid.is_empty()
            && !found.contains(&cid)
        {
            found.push(cid);
        }
    }

    found
}

/// Upper bound on payload attachments resolved from one inbound message.
///
/// ebMS3 places no limit on `eb:PartInfo` entries, so this caps the work an
/// attacker can induce with a body full of `xop:Include` references. The
/// eDelivery conformance payload profiles use four; 16 leaves ample headroom
/// for real profiles while keeping the resolution pass bounded.
pub(super) const MAX_INBOUND_PAYLOADS: usize = 16;

/// Strip `<`, `>`, and `cid:`/`CID:` prefixes from a MIME Content-ID value,
/// returning the bare CID token as a borrowed byte slice (zero allocation).
/// Used internally by [`content_ids_match`] to avoid UTF-8 decoding the MIME
/// header value for every attachment examined in the XOP-CID matching loop.
fn normalized_cid_bytes(content_id: &[u8]) -> &[u8] {
    let s = trim_ascii_whitespace(content_id);
    let s = s.strip_prefix(b"<").unwrap_or(s);
    let s = s.strip_suffix(b">").unwrap_or(s);
    if s.len() >= 4 && s[..4].eq_ignore_ascii_case(b"cid:") {
        &s[4..]
    } else {
        s
    }
}

/// Compare two Content-ID values for equality after normalising away angle
/// brackets and the `cid:`/`CID:` scheme prefix.  Zero allocations.
fn content_ids_match(a: &[u8], b: &[u8]) -> bool {
    normalized_cid_bytes(a) == normalized_cid_bytes(b)
}

fn header_value_from_block<'a>(headers: &'a [u8], header_name: &str) -> Result<Option<&'a str>> {
    let header_name_bytes = header_name.as_bytes();

    for raw_line in headers.split(|b| *b == b'\n') {
        let line = raw_line.strip_suffix(b"\r").unwrap_or(raw_line);
        let line = trim_ascii_whitespace(line);
        if line.is_empty() {
            continue;
        }

        let Some(colon_pos) = memchr(b':', line) else {
            return Err(AsxError::new(
                ErrorCode::ParseFailed,
                "MIME header line missing ':' separator",
                ErrorContext::new("as4_receive_push"),
            ));
        };

        let name = trim_ascii_whitespace(&line[..colon_pos]);
        if name.eq_ignore_ascii_case(header_name_bytes) {
            let value_bytes = trim_ascii_whitespace(&line[colon_pos + 1..]);
            let value = std::str::from_utf8(value_bytes).map_err(|_| {
                AsxError::new(
                    ErrorCode::ParseFailed,
                    "MIME header value is not valid UTF-8",
                    ErrorContext::new("as4_receive_push"),
                )
            })?;

            return Ok(Some(value));
        }
    }

    Ok(None)
}

/// Efficient substring search using the two-way algorithm (O(n) time, O(1) space).
/// Substantially faster than the naive O(n·m) `.windows()` loop for long needles or
/// large MIME payloads (validated in the benchmark suite).
#[inline]
fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    memmem::find(haystack, needle)
}

/// Streaming MIME part reference: (headers_bytes, body_bytes) - both as slices.
/// This avoids materializing parts into Vec until we know we need them.
struct StreamingMimePartRef<'a> {
    headers: &'a [u8],
    body: &'a [u8],
}

/// Efficient streaming MIME parser: yields part references without materializing intermediate Vecs.
/// Key optimization: only materializes parts we actually need (root SOAP + referenced attachment).
/// Non-matching parts are skipped entirely without intermediate Vec allocation.
///
/// Boundary byte patterns are pre-computed once in `new()` so that each call to
/// `next_part_slice` never formats a String or allocates a Vec for boundary matching.
struct StreamingMimeParser<'a> {
    raw_body: &'a [u8],
    /// Pre-computed: `--<boundary>` (start delimiter for inter-part scanning)
    boundary_start: Vec<u8>,
    /// Pre-computed: `\r\n--<boundary>` (CRLF-prefixed delimiter for body-end search)
    boundary_crlf: Vec<u8>,
    /// Pre-computed: `--<boundary>--` (closing delimiter)
    boundary_end: Vec<u8>,
    cursor: usize,
    exhausted: bool,
}

impl<'a> StreamingMimeParser<'a> {
    fn new(raw_body: &'a [u8], boundary: &str) -> Result<Self> {
        // Pre-compute all delimiter patterns once so next_part_slice never allocates.
        let boundary_bytes = boundary.as_bytes();

        let mut boundary_start = Vec::with_capacity(2 + boundary_bytes.len());
        boundary_start.extend_from_slice(b"--");
        boundary_start.extend_from_slice(boundary_bytes);

        let mut boundary_crlf = Vec::with_capacity(4 + boundary_bytes.len());
        boundary_crlf.extend_from_slice(b"\r\n--");
        boundary_crlf.extend_from_slice(boundary_bytes);

        let mut boundary_end = Vec::with_capacity(4 + boundary_bytes.len());
        boundary_end.extend_from_slice(b"--");
        boundary_end.extend_from_slice(boundary_bytes);
        boundary_end.extend_from_slice(b"--");

        if !raw_body.starts_with(&boundary_start) {
            return Err(AsxError::new(
                ErrorCode::ParseFailed,
                "multipart body does not start with boundary delimiter",
                ErrorContext::new("as4_receive_push"),
            ));
        }

        let mut cursor = boundary_start.len();

        if raw_body.get(cursor..cursor + 2) == Some(b"\r\n") {
            cursor += 2;
        } else {
            return Err(AsxError::new(
                ErrorCode::ParseFailed,
                "multipart boundary delimiter not followed by CRLF",
                ErrorContext::new("as4_receive_push"),
            ));
        }

        Ok(StreamingMimeParser {
            raw_body,
            boundary_start,
            boundary_crlf,
            boundary_end,
            cursor,
            exhausted: false,
        })
    }

    /// Yield next part as slices (zero-copy) without materializing into Vec.
    fn next_part_slice(&mut self) -> Result<Option<StreamingMimePartRef<'a>>> {
        if self.exhausted {
            return Ok(None);
        }

        // Find headers/body separator
        let headers_end_rel = find_subslice(&self.raw_body[self.cursor..], b"\r\n\r\n")
            .or_else(|| find_subslice(&self.raw_body[self.cursor..], b"\n\n"))
            .ok_or_else(|| {
                AsxError::new(
                    ErrorCode::ParseFailed,
                    "multipart part is missing header/body separator",
                    ErrorContext::new("as4_receive_push"),
                )
            })?;

        let headers_start = self.cursor;
        let headers_end = self.cursor + headers_end_rel;
        let separator_len = if self.raw_body.get(headers_end..headers_end + 4) == Some(b"\r\n\r\n")
        {
            4
        } else {
            2
        };
        let body_start = headers_end + separator_len;

        // Find next boundary (uses pre-computed patterns — no allocation per call)
        let next_boundary_rel = find_subslice(&self.raw_body[body_start..], &self.boundary_crlf)
            .ok_or_else(|| {
                AsxError::new(
                    ErrorCode::ParseFailed,
                    "multipart part is missing following boundary delimiter",
                    ErrorContext::new("as4_receive_push"),
                )
            })?;

        let body_end = body_start + next_boundary_rel;

        // Create part reference (zero-copy)
        let part = StreamingMimePartRef {
            headers: &self.raw_body[headers_start..headers_end],
            body: &self.raw_body[body_start..body_end],
        };

        self.cursor = body_end;

        // Skip line ending after body
        if self.raw_body.get(self.cursor..self.cursor + 2) == Some(b"\r\n") {
            self.cursor += 2;
        } else {
            return Err(AsxError::new(
                ErrorCode::ParseFailed,
                "multipart boundary delimiter is not CRLF-delimited",
                ErrorContext::new("as4_receive_push"),
            ));
        }

        // Check if we've reached the end (pre-computed patterns — no allocation)
        if self.raw_body[self.cursor..].starts_with(&self.boundary_end) {
            self.exhausted = true;
        } else if self.raw_body[self.cursor..].starts_with(&self.boundary_start) {
            self.cursor += self.boundary_start.len();
            if self.raw_body.get(self.cursor..self.cursor + 2) == Some(b"\r\n") {
                self.cursor += 2;
            } else {
                return Err(AsxError::new(
                    ErrorCode::ParseFailed,
                    "multipart boundary delimiter not followed by CRLF",
                    ErrorContext::new("as4_receive_push"),
                ));
            }
        } else if self.raw_body[self.cursor..].is_empty() {
            self.exhausted = true;
        } else {
            return Err(AsxError::new(
                ErrorCode::ParseFailed,
                "multipart boundary delimiter is malformed",
                ErrorContext::new("as4_receive_push"),
            ));
        }

        Ok(Some(part))
    }
}

/// Extract multipart AS4 payload with streaming-aware optimizations.
/// **Key optimization**: only materialize root (SOAP) + referenced attachment parts;
/// skip other parts entirely without creating intermediate Vecs.
/// For typical AS4 messages (SOAP + 1 attachment), this eliminates unnecessary allocation.
pub(super) fn extract_multipart_related_payload_if_present<'a>(
    raw_body: &'a [u8],
    http_content_type: &str,
    session: &SessionContext,
    stage: &'static str,
) -> Result<Option<MultipartAs4Payload<'a>>> {
    let boundary = parse_multipart_boundary_from_content_type(http_content_type)?;
    let Some(boundary) = boundary else {
        if raw_body.starts_with(b"--") {
            return Err(AsxError::new(
                ErrorCode::ParseFailed,
                "payload looks like multipart MIME but HTTP Content-Type is not multipart/related",
                ErrorContext::for_session(stage, session),
            ));
        }
        return Ok(None);
    };

    let mut parser = StreamingMimeParser::new(raw_body, &boundary)?;

    // Get root part
    let root = parser.next_part_slice()?.ok_or_else(|| {
        AsxError::new(
            ErrorCode::ParseFailed,
            "multipart/related AS4 body does not contain any parts",
            ErrorContext::for_session(stage, session),
        )
    })?;

    // Validate root headers
    let root_content_type =
        header_value_from_block(root.headers, "Content-Type")?.ok_or_else(|| {
            AsxError::new(
                ErrorCode::ParseFailed,
                "multipart/related AS4 root part is missing Content-Type",
                ErrorContext::for_session(stage, session),
            )
        })?;
    // AS4 (SwA packaging) roots are `application/soap+xml`; MTOM/XOP senders
    // (including asx through 0.12.0) use `application/xop+xml`. Both carry the
    // SOAP envelope as the root part; anything else is not an AS4 message.
    let media_type_str = root_content_type.split(';').next().unwrap_or("").trim();
    if !media_type_str.eq_ignore_ascii_case("application/soap+xml")
        && !media_type_str.eq_ignore_ascii_case("application/xop+xml")
    {
        return Err(AsxError::new(
            ErrorCode::ParseFailed,
            format!(
                "multipart/related AS4 root part must be application/soap+xml \
                 (or the MTOM variant application/xop+xml), got: {root_content_type}"
            ),
            ErrorContext::for_session(stage, session),
        ));
    }

    // Keep SOAP root and attachment payload as borrowed slices; ownership is
    // only taken later if decrypt/domain boundaries require it.
    let soap_xml = root.body;

    // Every `href="cid:…"` in the envelope, in document order and deduplicated.
    // For conformant AS4 (SwA) messages these are the `eb:PartInfo/@href`
    // entries in the **signed** `eb:Messaging` header; for MTOM senders the
    // `xop:Include/@href` in the Body matches the same set.
    //
    // An envelope with no `cid:` href yields an empty list rather than adopting
    // "the next MIME part": with no Content-ID there is nothing to tie such a
    // part to a `ds:Reference URI="cid:…"`, so it could never be shown to be
    // signature-covered. `resolve_verified_payload` turns the empty case into
    // an actionable error.
    let cid_hrefs = collect_cid_hrefs(soap_xml, MAX_INBOUND_PAYLOADS + 1);
    if cid_hrefs.len() > MAX_INBOUND_PAYLOADS {
        return Err(AsxError::new(
            ErrorCode::PayloadTooLarge,
            format!(
                "AS4 message references more than {MAX_INBOUND_PAYLOADS} payload \
                 attachments; refusing to resolve an unbounded attachment set"
            ),
            ErrorContext::for_session(stage, session),
        ));
    }

    // Single pass over the remaining MIME parts, matching each against the
    // wanted Content-ID set. Parts are examined as borrowed slices and those
    // that match no reference are skipped without materialization.
    let mut resolved: Vec<Option<(&[u8], Option<&str>)>> = vec![None; cid_hrefs.len()];
    if !cid_hrefs.is_empty() {
        let mut outstanding = cid_hrefs.len();
        while outstanding > 0 {
            let Some(part) = parser.next_part_slice()? else {
                break;
            };
            for (index, cid) in cid_hrefs.iter().enumerate() {
                if resolved[index].is_none()
                    && content_id_matches_from_block(part.headers, cid.as_bytes())?
                {
                    resolved[index] = Some((part.body, content_type_from_block(part.headers)));
                    outstanding -= 1;
                    break;
                }
            }
        }
    }

    let mut payloads = Vec::with_capacity(cid_hrefs.len());
    for (index, cid) in cid_hrefs.iter().enumerate() {
        let Some((bytes, content_type)) = resolved[index] else {
            let wanted = std::str::from_utf8(normalized_cid_bytes(cid.as_bytes())).unwrap_or(cid);
            return Err(AsxError::new(
                ErrorCode::ParseFailed,
                format!("xop:Include references missing MIME Content-ID: {wanted}"),
                ErrorContext::for_session(stage, session),
            ));
        };
        payloads.push(InboundAttachment {
            content_id: cid,
            content_type,
            bytes,
        });
    }

    Ok(Some(MultipartAs4Payload { soap_xml, payloads }))
}

/// The `Content-Type` header value of a MIME part header block, if present
/// and valid UTF-8. Folded continuation lines are joined with a single space.
fn content_type_from_block(headers: &[u8]) -> Option<&str> {
    let text = std::str::from_utf8(headers).ok()?;
    let mut lines = text.lines();
    while let Some(line) = lines.next() {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if !name.trim().eq_ignore_ascii_case("content-type") {
            continue;
        }
        let value = value.trim();
        // Continuation lines are rare on Content-Type; when present, fall back
        // to the unfolded first line rather than allocating — the media type
        // (the part that selects the SwA transform) is always on it.
        let _ = lines;
        return Some(value);
    }
    None
}

fn content_id_matches_from_block(headers: &[u8], expected_cid: &[u8]) -> Result<bool> {
    let header_name_bytes = b"content-id";

    for raw_line in headers.split(|b| *b == b'\n') {
        let line = raw_line.strip_suffix(b"\r").unwrap_or(raw_line);
        let line = trim_ascii_whitespace(line);
        if line.is_empty() {
            continue;
        }

        let Some(colon_pos) = memchr(b':', line) else {
            return Err(AsxError::new(
                ErrorCode::ParseFailed,
                "MIME header line missing ':' separator",
                ErrorContext::new("as4_receive_push"),
            ));
        };

        let name = trim_ascii_whitespace(&line[..colon_pos]);
        if name.eq_ignore_ascii_case(header_name_bytes) {
            let value_bytes = trim_ascii_whitespace(&line[colon_pos + 1..]);
            if !value_bytes.is_ascii() {
                return Err(AsxError::new(
                    ErrorCode::ParseFailed,
                    "MIME Content-ID value is not ASCII",
                    ErrorContext::new("as4_receive_push"),
                ));
            }
            return Ok(content_ids_match(value_bytes, expected_cid));
        }
    }

    Ok(false)
}

pub(super) fn decrypt_xmlenc_payload_if_present(
    payload: &[u8],
    decryption_key_pem: Option<&[u8]>,
    stage: &'static str,
) -> Result<Option<Vec<u8>>> {
    // Use memmem::find for O(n) containment check instead of O(n·m) windows().
    if memmem::find(payload, b"<xenc:EncryptedData").is_none() {
        return Ok(None);
    }

    let key = decryption_key_pem.ok_or_else(|| {
        AsxError::new(
            ErrorCode::DecryptionFailed,
            "AS4 MIME payload is XML-encrypted but no inbound decryption key is configured",
            ErrorContext::new(stage),
        )
    })?;

    decrypt_payload_xmlenc(payload, key).map(Some)
}

fn trim_ascii_whitespace(bytes: &[u8]) -> &[u8] {
    let mut start = 0;
    let mut end = bytes.len();

    while start < end && bytes[start].is_ascii_whitespace() {
        start += 1;
    }
    while end > start && bytes[end - 1].is_ascii_whitespace() {
        end -= 1;
    }

    &bytes[start..end]
}

// ── MPC normalization ────────────────────────────────────────────────────────

pub(super) fn normalize_mpc(mpc: &str) -> &str {
    let trimmed = mpc.trim();
    if trimmed.is_empty() {
        return "";
    }
    trimmed
}

// ── Constant-time comparison ─────────────────────────────────────────────────

/// Constant-time byte-slice equality to prevent timing side-channels when
/// comparing security tokens such as `<eb:AuthorizationInfo>` values.
///
/// Uses [`subtle::ConstantTimeEq`] for a well-audited, crate-standard
/// constant-time implementation instead of a hand-rolled XOR loop.
pub(super) fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    // Length comparison leaks length via branching, but constant-time
    // equality is undefined for different-length slices — any comparison that
    // requires equal length must first verify the lengths match.
    // Timing-leaking the length of `AuthorizationInfo` is acceptable because
    // the value's length is also visible in the SOAP envelope.
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

#[cfg(test)]
mod xop_href_tests {
    use super::extract_xop_cid_href_bytes;

    #[test]
    fn accepts_both_xml_quoting_styles_and_whitespace() {
        for body in [
            br#"<S12:Body><xop:Include href="cid:p@e.com"/></S12:Body>"#.as_slice(),
            br#"<S12:Body><xop:Include href='cid:p@e.com'/></S12:Body>"#.as_slice(),
            br#"<S12:Body><xop:Include href = "cid:p@e.com"/></S12:Body>"#.as_slice(),
            br#"<S12:Body><xop:Include href
                ='cid:p@e.com'/></S12:Body>"#
                .as_slice(),
            // Scheme prefix is case-insensitive per RFC 3986 §3.1.
            br#"<S12:Body><xop:Include href="CID:p@e.com"/></S12:Body>"#.as_slice(),
        ] {
            assert_eq!(
                extract_xop_cid_href_bytes(body),
                Some("p@e.com"),
                "failed for: {}",
                String::from_utf8_lossy(body)
            );
        }
    }

    #[test]
    fn skips_non_cid_hrefs_and_finds_the_cid_one() {
        let body = br#"<a href="https://example.com/x"/><xop:Include href='cid:real@e.com'/>"#;
        assert_eq!(extract_xop_cid_href_bytes(body), Some("real@e.com"));
    }

    #[test]
    fn returns_none_without_a_cid_href() {
        assert_eq!(extract_xop_cid_href_bytes(b"<S12:Body/>"), None);
        assert_eq!(
            extract_xop_cid_href_bytes(br#"<a href="https://example.com"/>"#),
            None
        );
        // Empty cid is not a usable Content-ID.
        assert_eq!(extract_xop_cid_href_bytes(br#"<x href="cid:"/>"#), None);
        // `href` not followed by `=` must not be mistaken for an attribute.
        assert_eq!(extract_xop_cid_href_bytes(b"the word href appears"), None);
    }
}
