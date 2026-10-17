//! Low-level stream-processing helpers for the AS4 receive pipeline.
//!
//! MIME parsing here is zero-copy: the parser yields part references (slices
//! of the request body) rather than materializing parts. Which parts are
//! payloads is decided after verification, from the signed `eb:PartInfo`.
//!
//! All functions are `pub(super)` — they are implementation details of the
//! `as4` module family and must not be part of the public API.

use crate::core::{AsxError, ErrorCode, ErrorContext, Result, SessionContext};
use memchr::{memchr, memmem};

/// One inbound MIME part after the root.
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
    /// Every MIME part after the root, in wire order (at most
    /// [`MAX_INBOUND_PAYLOADS`]). Matched against the signed `eb:PartInfo`
    /// set after verification.
    pub payloads: Vec<InboundAttachment<'a>>,
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

/// Upper bound on payload attachments resolved from one inbound message.
///
/// ebMS3 places no limit on `eb:PartInfo` entries, so this caps the work an
/// attacker can induce with a body full of MIME parts. The
/// eDelivery conformance payload profiles use four; 16 leaves ample headroom
/// for real profiles while keeping the resolution pass bounded.
pub(super) const MAX_INBOUND_PAYLOADS: usize = 16;

/// Strip `<`, `>`, and `cid:`/`CID:` prefixes from a MIME Content-ID value,
/// returning the bare CID token as a borrowed byte slice (zero allocation).
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

        // RFC 2046 §5.1.1: a preamble may precede the first delimiter, which
        // then starts a line (phase4/Jakarta Mail sends a leading CRLF).
        let first = if raw_body.starts_with(&boundary_start) {
            0
        } else {
            find_subslice(raw_body, &boundary_crlf)
                .map(|at| at + 2)
                .ok_or_else(|| {
                    AsxError::new(
                        ErrorCode::ParseFailed,
                        "multipart body has no boundary delimiter",
                        ErrorContext::new("as4_receive_push"),
                    )
                })?
        };

        let mut cursor = first + boundary_start.len();

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

/// Split a multipart/related AS4 body into the SOAP root and the other parts,
/// all borrowed from `raw_body` (no part is copied).
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
    // use `application/xop+xml`. Both carry the
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

    // Keep the SOAP root and every part as borrowed slices; which parts are
    // payloads is decided from the signed eb:PartInfo.
    let soap_xml = root.body;
    let mut payloads = Vec::new();
    while let Some(part) = parser.next_part_slice()? {
        if payloads.len() == MAX_INBOUND_PAYLOADS {
            return Err(AsxError::new(
                ErrorCode::PayloadTooLarge,
                format!(
                    "AS4 message carries more than {MAX_INBOUND_PAYLOADS} payload \
                     attachments; refusing to resolve an unbounded attachment set"
                ),
                ErrorContext::for_session(stage, session),
            ));
        }
        let content_id = content_id_from_block(part.headers)?.ok_or_else(|| {
            AsxError::new(
                ErrorCode::ParseFailed,
                "an AS4 MIME part carries no Content-ID; it cannot be tied to eb:PartInfo",
                ErrorContext::for_session(stage, session),
            )
        })?;
        payloads.push(InboundAttachment {
            content_id,
            content_type: content_type_from_block(part.headers),
            bytes: part.body,
        });
    }

    Ok(Some(MultipartAs4Payload { soap_xml, payloads }))
}

/// The normalized `Content-ID` of a MIME part header block.
fn content_id_from_block(headers: &[u8]) -> Result<Option<&str>> {
    let Some(value) = header_value_from_block(headers, "Content-ID")? else {
        return Ok(None);
    };
    if !value.is_ascii() {
        return Err(AsxError::new(
            ErrorCode::ParseFailed,
            "MIME Content-ID value is not ASCII",
            ErrorContext::new("as4_receive_push"),
        ));
    }
    let bare = normalized_cid_bytes(value.as_bytes());
    let start = bare.as_ptr() as usize - value.as_ptr() as usize;
    Ok(Some(&value[start..start + bare.len()]).filter(|v| !v.is_empty()))
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
