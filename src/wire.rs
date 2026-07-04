use crate::core::{
    AsxError, ErrorCode, ErrorContext, ReceivedBodyHandle, Result, SpoolEncryption,
    SpoolLifecyclePolicy,
};
use crate::http::{HttpHeaders, HttpRequest, PartnerEndpointGovernance, ValidatedHttpRequest};
use sha2::{Digest, Sha256};
use std::path::PathBuf;

mod spooling;

// Re-exported from `core` so callers that only depend on `wire` still compile.
pub use crate::core::DEFAULT_MAX_BODY_BYTES;
pub use crate::core::escape_xml;
pub const DEFAULT_STREAM_CHUNK_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamLimits {
    pub max_body_bytes: usize,
    pub chunk_bytes: usize,
}

impl Default for StreamLimits {
    fn default() -> Self {
        Self {
            max_body_bytes: DEFAULT_MAX_BODY_BYTES,
            chunk_bytes: DEFAULT_STREAM_CHUNK_BYTES,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct StreamReadMetrics {
    pub total_bytes: usize,
    pub chunks: usize,
    pub max_chunk_seen: usize,
    pub used_spool: bool,
    pub materialized_from_spool: bool,
    pub startup_hygiene_checked: bool,
    pub spool_free_bytes: Option<u64>,
    pub spool_min_free_bytes: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamBodyPolicy {
    pub spool_threshold_bytes: usize,
    pub spool_dir: Option<PathBuf>,
    pub spool_encryption: SpoolEncryption,
    pub spool_lifecycle: SpoolLifecyclePolicy,
    pub spool_retention_ttl_secs: Option<u64>,
    pub spool_min_free_bytes: Option<u64>,
    pub startup_hygiene_checks: bool,
}

impl StreamBodyPolicy {
    #[must_use]
    pub fn memory_only() -> Self {
        Self {
            spool_threshold_bytes: usize::MAX,
            spool_dir: None,
            spool_encryption: SpoolEncryption::Plaintext,
            spool_lifecycle: SpoolLifecyclePolicy::default(),
            spool_retention_ttl_secs: None,
            spool_min_free_bytes: None,
            startup_hygiene_checks: false,
        }
    }
}

impl Default for StreamBodyPolicy {
    fn default() -> Self {
        Self::memory_only()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContentType {
    Mime,
    SoapXml,
    OctetStream,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireEnvelope {
    pub content_type: ContentType,
    pub normalized_headers: HttpHeaders,
    pub body: std::sync::Arc<[u8]>,
}

impl WireEnvelope {
    pub fn from_http_request(request: ValidatedHttpRequest) -> Result<Self> {
        Self::from_http_request_with_limits(request, StreamLimits::default())
    }

    pub fn try_from_http_request(
        request: HttpRequest,
        partner_id: &str,
        governance: &PartnerEndpointGovernance,
    ) -> Result<Self> {
        Self::from_http_request(request.into_validated_for_partner(partner_id, governance)?)
    }

    pub fn from_http_request_with_limits(
        request: ValidatedHttpRequest,
        limits: StreamLimits,
    ) -> Result<Self> {
        let request = request.into_inner();
        let normalized_headers = normalize_headers_strict(&request.headers)?;
        let raw_content_type = require_header(&normalized_headers, "content-type")?;
        let content_type = parse_content_type(raw_content_type)?;
        enforce_payload_limit(
            "wire_from_http_request",
            request.body.len(),
            limits.max_body_bytes,
        )?;

        Ok(Self {
            content_type,
            normalized_headers,
            body: request.body,
        })
    }

    pub fn try_from_http_request_with_limits(
        request: HttpRequest,
        limits: StreamLimits,
        partner_id: &str,
        governance: &PartnerEndpointGovernance,
    ) -> Result<Self> {
        Self::from_http_request_with_limits(
            request.into_validated_for_partner(partner_id, governance)?,
            limits,
        )
    }
}

pub fn enforce_payload_limit(
    stage: &'static str,
    payload_len: usize,
    max_body_bytes: usize,
) -> Result<()> {
    if payload_len > max_body_bytes {
        return Err(AsxError::new(
            ErrorCode::PolicyViolation,
            format!(
                "payload exceeds configured max bytes: {} > {}",
                payload_len, max_body_bytes
            ),
            ErrorContext::new(stage),
        ));
    }
    Ok(())
}

fn bounded_stream_take_limit(max_body_bytes: usize, stage: &'static str) -> Result<u64> {
    (max_body_bytes as u64).checked_add(1).ok_or_else(|| {
        AsxError::new(
            ErrorCode::InvalidInput,
            format!("stream limit exceeds supported cap for bounded reader: {max_body_bytes}"),
            ErrorContext::new(stage),
        )
    })
}

fn bounded_stream_reader<R: tokio::io::AsyncRead + Unpin>(
    reader: R,
    limits: StreamLimits,
    stage: &'static str,
) -> Result<tokio::io::Take<R>> {
    use tokio::io::AsyncReadExt;

    if limits.max_body_bytes == 0 || limits.chunk_bytes == 0 {
        return Err(AsxError::new(
            ErrorCode::InvalidInput,
            "stream limits must be non-zero",
            ErrorContext::new(stage),
        ));
    }

    Ok(reader.take(bounded_stream_take_limit(limits.max_body_bytes, stage)?))
}

/// Read a bounded async stream into memory.
///
/// The reader is capped at `max_body_bytes + 1` so over-limit payloads are
/// detected and rejected without a separate overflow probe read.
/// Non-blocking and safe to call on a Tokio async runtime without starving
/// other tasks.
pub async fn read_bounded_stream_into_memory_async<R: tokio::io::AsyncRead + Unpin>(
    reader: R,
    limits: StreamLimits,
    stage: &'static str,
) -> Result<(std::sync::Arc<[u8]>, StreamReadMetrics)> {
    use tokio::io::AsyncReadExt;

    let mut reader = bounded_stream_reader(reader, limits, stage)?;
    let mut buf = Vec::with_capacity(limits.chunk_bytes.min(limits.max_body_bytes));
    let mut chunk = vec![0u8; limits.chunk_bytes];
    let mut metrics = StreamReadMetrics::default();

    loop {
        let n = reader.read(&mut chunk).await.map_err(|e| {
            AsxError::new(
                ErrorCode::TransportFailure,
                format!("async stream read failed: {e}"),
                ErrorContext::new(stage),
            )
        })?;
        if n == 0 {
            break;
        }
        metrics.total_bytes += n;
        metrics.chunks += 1;
        metrics.max_chunk_seen = metrics.max_chunk_seen.max(n);
        enforce_payload_limit(stage, metrics.total_bytes, limits.max_body_bytes)?;
        buf.extend_from_slice(&chunk[..n]);
    }

    Ok((std::sync::Arc::from(buf.into_boxed_slice()), metrics))
}

pub async fn read_bounded_stream_into_handle_async<R: tokio::io::AsyncRead + Unpin>(
    reader: R,
    limits: StreamLimits,
    body_policy: &StreamBodyPolicy,
    stage: &'static str,
) -> Result<(ReceivedBodyHandle, StreamReadMetrics)> {
    spooling::read_bounded_stream_into_handle_async_impl(reader, limits, body_policy, stage).await
}

/// Read a bounded async stream and forward bytes to an async writer.
///
/// This variant avoids accumulating the full payload in memory and is better
/// suited for large payload ingestion pipelines.
pub async fn copy_bounded_stream_async<
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
>(
    reader: R,
    mut writer: W,
    limits: StreamLimits,
    stage: &'static str,
) -> Result<StreamReadMetrics> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut reader = bounded_stream_reader(reader, limits, stage)?;
    let mut metrics = StreamReadMetrics::default();
    let mut chunk = vec![0u8; limits.chunk_bytes];

    loop {
        let n = reader.read(&mut chunk).await.map_err(|e| {
            AsxError::new(
                ErrorCode::TransportFailure,
                format!("async stream read failed: {e}"),
                ErrorContext::new(stage),
            )
        })?;
        if n == 0 {
            break;
        }

        metrics.total_bytes += n;
        metrics.chunks += 1;
        metrics.max_chunk_seen = metrics.max_chunk_seen.max(n);
        enforce_payload_limit(stage, metrics.total_bytes, limits.max_body_bytes)?;

        writer.write_all(&chunk[..n]).await.map_err(|e| {
            AsxError::new(
                ErrorCode::TransportFailure,
                format!("async stream write failed: {e}"),
                ErrorContext::new(stage),
            )
        })?;
    }

    writer.flush().await.map_err(|e| {
        AsxError::new(
            ErrorCode::TransportFailure,
            format!("async stream flush failed: {e}"),
            ErrorContext::new(stage),
        )
    })?;

    Ok(metrics)
}

pub fn canonical_transfer_fingerprint(request: &HttpRequest) -> Result<String> {
    let normalized_headers = normalize_headers_strict(&request.headers)?;
    let mut hasher = Sha256::new();

    hasher.update(request.method.as_bytes());
    hasher.update(b"\n");
    hasher.update(request.uri.as_bytes());
    hasher.update(b"\n");

    for (k, v) in normalized_headers {
        hasher.update(k.as_bytes());
        hasher.update(b":");
        hasher.update(v.as_bytes());
        hasher.update(b"\n");
    }

    hasher.update(&request.body);
    let digest = hasher.finalize();
    let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
    Ok(hex)
}

pub(crate) fn parse_content_type(raw: &str) -> Result<ContentType> {
    let media = parse_media_type(raw)?;

    if media.type_ == "multipart" {
        let has_boundary = media
            .params
            .iter()
            .any(|(k, v)| k == "boundary" && !v.trim().is_empty());
        if !has_boundary {
            return Err(AsxError::new(
                ErrorCode::ParseFailed,
                "multipart content-type requires non-empty boundary parameter",
                ErrorContext::new("wire_parse_content_type"),
            ));
        }
        return Ok(ContentType::Mime);
    }

    if media.type_ == "application" && media.subtype == "pkcs7-mime" {
        return Ok(ContentType::Mime);
    }

    if (media.type_ == "application" && (media.subtype == "soap+xml" || media.subtype == "xml"))
        || (media.type_ == "text" && media.subtype == "xml")
    {
        return Ok(ContentType::SoapXml);
    }

    if media.type_ == "application" && media.subtype == "octet-stream" {
        return Ok(ContentType::OctetStream);
    }

    Err(AsxError::new(
        ErrorCode::ParseFailed,
        format!("unsupported content-type: {raw}"),
        ErrorContext::new("wire_parse_content_type"),
    ))
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedMediaType {
    type_: String,
    subtype: String,
    params: Vec<(String, String)>,
}

fn parse_media_type(raw: &str) -> Result<ParsedMediaType> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(AsxError::new(
            ErrorCode::ParseFailed,
            "content-type header is empty",
            ErrorContext::new("wire_parse_content_type"),
        ));
    }

    let mut parts = trimmed.split(';');
    let essence = parts.next().unwrap_or_default().trim();
    let mut type_parts = essence.split('/');
    let raw_type = type_parts.next().unwrap_or_default().trim();
    let raw_subtype = type_parts.next().unwrap_or_default().trim();

    if raw_type.is_empty() || raw_subtype.is_empty() || type_parts.next().is_some() {
        return Err(AsxError::new(
            ErrorCode::ParseFailed,
            format!("invalid content-type media type: {raw}"),
            ErrorContext::new("wire_parse_content_type"),
        ));
    }

    if !is_token(raw_type) || !is_token(raw_subtype) {
        return Err(AsxError::new(
            ErrorCode::ParseFailed,
            format!("invalid token in content-type media type: {raw}"),
            ErrorContext::new("wire_parse_content_type"),
        ));
    }

    let mut params = Vec::new();
    for part in parts {
        let candidate = part.trim();
        if candidate.is_empty() {
            continue;
        }
        let (name, value) = candidate.split_once('=').ok_or_else(|| {
            AsxError::new(
                ErrorCode::ParseFailed,
                format!("invalid content-type parameter: {candidate}"),
                ErrorContext::new("wire_parse_content_type"),
            )
        })?;
        let name = name.trim().to_ascii_lowercase();
        if !is_token(&name) {
            return Err(AsxError::new(
                ErrorCode::ParseFailed,
                format!("invalid content-type parameter name: {name}"),
                ErrorContext::new("wire_parse_content_type"),
            ));
        }
        let value = strip_quoted_value(value.trim())?;
        params.push((name, value));
    }

    Ok(ParsedMediaType {
        type_: raw_type.to_ascii_lowercase(),
        subtype: raw_subtype.to_ascii_lowercase(),
        params,
    })
}

fn strip_quoted_value(value: &str) -> Result<String> {
    if value.starts_with('"') {
        if !value.ends_with('"') || value.len() < 2 {
            return Err(AsxError::new(
                ErrorCode::ParseFailed,
                "unterminated quoted content-type parameter",
                ErrorContext::new("wire_parse_content_type"),
            ));
        }
        Ok(value[1..value.len() - 1].to_string())
    } else {
        Ok(value.to_string())
    }
}

fn is_token(value: &str) -> bool {
    !value.is_empty()
        && value
            .as_bytes()
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(b))
}

impl ContentType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Mime => "multipart/signed",
            Self::SoapXml => "application/soap+xml",
            Self::OctetStream => "application/octet-stream",
        }
    }
}

pub(crate) fn normalize_headers(headers: &[(String, String)]) -> HttpHeaders {
    let mut normalized: HttpHeaders = headers
        .iter()
        .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_string()))
        .collect();

    normalized.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));
    normalized
}

pub(crate) fn normalize_headers_strict(headers: &[(String, String)]) -> Result<HttpHeaders> {
    let normalized = normalize_headers(headers);
    let singleton_keys = ["content-type"];

    for key in singleton_keys {
        let values: Vec<&str> = normalized
            .iter()
            .filter(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
            .collect();

        if values.len() > 1 {
            let first = values[0];
            if values.iter().any(|v| *v != first) {
                return Err(AsxError::new(
                    ErrorCode::ParseFailed,
                    format!("ambiguous singleton header: {key}"),
                    ErrorContext::new("wire_header_ambiguity"),
                ));
            }
        }
    }

    Ok(normalized)
}

pub(crate) fn require_header<'a>(headers: &'a [(String, String)], key: &str) -> Result<&'a str> {
    let target = key.to_ascii_lowercase();
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(&target))
        .map(|(_, v)| v.as_str())
        .ok_or_else(|| {
            AsxError::new(
                ErrorCode::ParseFailed,
                format!("missing required header: {key}"),
                ErrorContext::new("wire_require_header"),
            )
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::SessionContext;
    use crate::http::{HttpHeaders, HttpRequest, PartnerEndpointGovernance};
    use proptest::prelude::*;

    #[test]
    fn normalize_headers_is_deterministic() {
        let input = vec![
            ("X-B".to_string(), " 2 ".to_string()),
            ("x-a".to_string(), "1".to_string()),
        ];
        let expected =
            HttpHeaders::from_vec(vec![("x-a".into(), "1".into()), ("x-b".into(), "2".into())]);
        assert_eq!(normalize_headers(&input), expected);
    }

    #[test]
    fn from_http_request_parses_as2_mime() {
        let request = HttpRequest {
            method: "POST".into(),
            uri: "/as2".into(),
            headers: HttpHeaders::from_vec(vec![(
                "Content-Type".into(),
                "multipart/signed; protocol=application/pkcs7-signature; boundary=as2-boundary"
                    .into(),
            )]),
            body: vec![1, 2, 3].into(),
        };

        let governance = PartnerEndpointGovernance::ingress_strict();

        let envelope = WireEnvelope::try_from_http_request(request, "partner-a", &governance)
            .expect("wire envelope");
        assert_eq!(envelope.content_type, ContentType::Mime);
    }

    #[test]
    fn from_http_request_parses_as4_soap() {
        let request = HttpRequest {
            method: "POST".into(),
            uri: "/as4".into(),
            headers: HttpHeaders::from_vec(vec![(
                "Content-Type".into(),
                "application/soap+xml".into(),
            )]),
            body: vec![b'<', b'x', b'm', b'l', b'>'].into(),
        };

        let governance = PartnerEndpointGovernance::ingress_strict();

        let envelope = WireEnvelope::try_from_http_request(request, "partner-a", &governance)
            .expect("wire envelope");
        assert_eq!(envelope.content_type, ContentType::SoapXml);
    }

    #[test]
    fn unsupported_content_type_is_rejected() {
        let request = HttpRequest {
            method: "POST".into(),
            uri: "/as4/unsupported".into(),
            headers: HttpHeaders::from_vec(vec![(
                "Content-Type".into(),
                "application/json".into(),
            )]),
            body: vec![].into(),
        };

        let governance = PartnerEndpointGovernance::ingress_strict();

        let err = WireEnvelope::try_from_http_request(request, "partner-a", &governance)
            .expect_err("unsupported type");
        assert_eq!(err.code, ErrorCode::ParseFailed);
    }

    #[test]
    fn multipart_without_boundary_is_rejected() {
        let request = HttpRequest {
            method: "POST".into(),
            uri: "/as2".into(),
            headers: HttpHeaders::from_vec(vec![(
                "Content-Type".into(),
                "multipart/signed".into(),
            )]),
            body: vec![1].into(),
        };

        let governance = PartnerEndpointGovernance::ingress_strict();

        let err = WireEnvelope::try_from_http_request(request, "partner-a", &governance)
            .expect_err("must require boundary");
        assert_eq!(err.code, ErrorCode::ParseFailed);
    }

    #[test]
    fn pkcs7_mime_is_classified_as_mime() {
        let request = HttpRequest {
            method: "POST".into(),
            uri: "/as2".into(),
            headers: HttpHeaders::from_vec(vec![(
                "Content-Type".into(),
                "application/pkcs7-mime; smime-type=enveloped-data".into(),
            )]),
            body: vec![1, 2].into(),
        };

        let governance = PartnerEndpointGovernance::ingress_strict();

        let envelope = WireEnvelope::try_from_http_request(request, "partner-a", &governance)
            .expect("wire envelope");
        assert_eq!(envelope.content_type, ContentType::Mime);
    }

    #[test]
    fn from_http_request_with_limits_rejects_oversized_body() {
        let request = HttpRequest {
            method: "POST".into(),
            uri: "/as2".into(),
            headers: HttpHeaders::from_vec(vec![(
                "Content-Type".into(),
                "multipart/signed; boundary=abc".into(),
            )]),
            body: vec![0u8; 16].into(),
        };

        let governance = PartnerEndpointGovernance::ingress_strict();

        let err = WireEnvelope::try_from_http_request_with_limits(
            request,
            StreamLimits {
                max_body_bytes: 8,
                chunk_bytes: 4,
            },
            "partner-a",
            &governance,
        )
        .expect_err("oversized request body must fail");
        assert_eq!(err.code, ErrorCode::PolicyViolation);
    }

    #[test]
    fn canonical_transfer_is_stable_for_reordered_headers() {
        let req_a = HttpRequest {
            method: "POST".into(),
            uri: "/as2".into(),
            headers: HttpHeaders::from_vec(vec![
                ("X-Trace".into(), " abc ".into()),
                ("Content-Type".into(), "multipart/signed".into()),
            ]),
            body: vec![1, 2, 3].into(),
        };

        let req_b = HttpRequest {
            method: "POST".into(),
            uri: "/as2".into(),
            headers: HttpHeaders::from_vec(vec![
                ("content-type".into(), "multipart/signed".into()),
                ("x-trace".into(), "abc".into()),
            ]),
            body: vec![1, 2, 3].into(),
        };

        let fp_a = canonical_transfer_fingerprint(&req_a).expect("fingerprint a");
        let fp_b = canonical_transfer_fingerprint(&req_b).expect("fingerprint b");
        assert_eq!(fp_a, fp_b);
    }

    #[test]
    fn conflicting_singleton_headers_are_rejected() {
        let req = HttpRequest {
            method: "POST".into(),
            uri: "/as2".into(),
            headers: HttpHeaders::from_vec(vec![
                ("Content-Type".into(), "multipart/signed".into()),
                ("content-type".into(), "application/soap+xml".into()),
            ]),
            body: vec![].into(),
        };

        let err = canonical_transfer_fingerprint(&req).expect_err("must reject ambiguous header");
        assert_eq!(err.code, ErrorCode::ParseFailed);
    }

    #[test]
    fn from_http_request_applies_partner_governance() {
        let request = HttpRequest {
            method: "POST".into(),
            uri: "https://partner-a.example/as2".into(),
            headers: HttpHeaders::from_vec(vec![(
                "Content-Type".into(),
                "multipart/signed; boundary=as2-boundary".into(),
            )]),
            body: vec![1, 2, 3].into(),
        };

        let governance = PartnerEndpointGovernance::ingress_strict().with_partner_policy(
            "partner-a",
            crate::http::HttpEndpointPolicy::ingress_strict()
                .with_allowed_authority("partner-a.example"),
        );

        let envelope =
            WireEnvelope::try_from_http_request(request.clone(), "partner-a", &governance)
                .expect("partner-specific governance should allow request");
        assert_eq!(envelope.content_type, ContentType::Mime);

        let err = WireEnvelope::try_from_http_request(request, "partner-b", &governance)
            .expect_err("default policy should reject non-allowlisted authority");
        assert_eq!(err.code, ErrorCode::PolicyViolation);
    }

    proptest! {
        #[test]
        fn normalize_headers_is_idempotent(
            pairs in proptest::collection::vec(("[A-Za-z-]{1,12}", "[ -~]{0,20}"), 0..32)
        ) {
            let input: Vec<(String, String)> = pairs;

            let once = normalize_headers(&input);
            let twice = normalize_headers(&once);
            prop_assert_eq!(once, twice);
        }
    }

    #[tokio::test]
    async fn read_bounded_stream_async_collects_metrics() {
        let data = vec![7u8; 12];
        let (buf, metrics) = read_bounded_stream_into_memory_async(
            data.as_slice(),
            StreamLimits {
                max_body_bytes: 64,
                chunk_bytes: 4,
            },
            "wire_async_test",
        )
        .await
        .expect("async stream read");

        assert_eq!(buf.as_ref(), data.as_slice());
        assert_eq!(metrics.total_bytes, 12);
        assert!(metrics.chunks >= 3);
    }

    #[tokio::test]
    async fn read_bounded_stream_async_rejects_oversized_payload() {
        let data = vec![1u8; 10];
        let err = read_bounded_stream_into_memory_async(
            data.as_slice(),
            StreamLimits {
                max_body_bytes: 8,
                chunk_bytes: 4,
            },
            "wire_async_test",
        )
        .await
        .expect_err("oversized async stream must fail");
        assert_eq!(err.code, ErrorCode::PolicyViolation);
    }

    #[tokio::test]
    async fn read_bounded_stream_into_handle_keeps_small_payload_in_memory() {
        let data = vec![5u8; 12];
        let (handle, metrics) = read_bounded_stream_into_handle_async(
            data.as_slice(),
            StreamLimits {
                max_body_bytes: 64,
                chunk_bytes: 4,
            },
            &StreamBodyPolicy {
                spool_threshold_bytes: 64,
                spool_dir: None,
                spool_encryption: SpoolEncryption::Plaintext,
                spool_lifecycle: SpoolLifecyclePolicy::default(),
                spool_retention_ttl_secs: None,
                spool_min_free_bytes: None,
                startup_hygiene_checks: false,
            },
            "wire_handle_test",
        )
        .await
        .expect("small payload should stay in memory");

        assert!(!metrics.used_spool);
        match handle {
            ReceivedBodyHandle::InMemory(bytes) => assert_eq!(bytes.as_ref(), data.as_slice()),
            ReceivedBodyHandle::Spooled { path, .. } => {
                panic!(
                    "expected in-memory handle, got spooled path {}",
                    path.display()
                )
            }
        }
    }

    #[tokio::test]
    async fn read_bounded_stream_into_handle_spools_when_threshold_is_exceeded() {
        let data = vec![8u8; 18];
        let (handle, metrics) = read_bounded_stream_into_handle_async(
            data.as_slice(),
            StreamLimits {
                max_body_bytes: 64,
                chunk_bytes: 4,
            },
            &StreamBodyPolicy {
                spool_threshold_bytes: 8,
                spool_dir: None,
                spool_encryption: SpoolEncryption::Plaintext,
                spool_lifecycle: SpoolLifecyclePolicy::default(),
                spool_retention_ttl_secs: None,
                spool_min_free_bytes: None,
                startup_hygiene_checks: false,
            },
            "wire_handle_test",
        )
        .await
        .expect("large payload should spool");

        assert!(metrics.used_spool);
        match handle {
            ReceivedBodyHandle::InMemory(_) => panic!("expected spooled handle"),
            ReceivedBodyHandle::Spooled { path, .. } => {
                let spooled = std::fs::read(&path).expect("spooled payload must be readable");
                assert_eq!(spooled, data);
                let _ = std::fs::remove_file(path);
            }
        }
    }

    #[tokio::test]
    async fn read_bounded_stream_into_handle_spools_encrypted_and_materializes_plaintext() {
        let data = vec![0xABu8; 48 * 1024];
        let key = std::sync::Arc::new([0x11u8; 32]);
        let (handle, metrics) = read_bounded_stream_into_handle_async(
            data.as_slice(),
            StreamLimits {
                max_body_bytes: 64 * 1024,
                chunk_bytes: 8 * 1024,
            },
            &StreamBodyPolicy {
                spool_threshold_bytes: 8 * 1024,
                spool_dir: None,
                spool_encryption: SpoolEncryption::Aes256Gcm { key },
                spool_lifecycle: SpoolLifecyclePolicy::default(),
                spool_retention_ttl_secs: None,
                spool_min_free_bytes: None,
                startup_hygiene_checks: false,
            },
            "wire_handle_encrypted_test",
        )
        .await
        .expect("encrypted spooling should succeed");

        assert!(metrics.used_spool);
        let session = SessionContext::new("s-wire", "p-wire", "strict").expect("session");
        let path = match &handle {
            ReceivedBodyHandle::Spooled { path, .. } => Some(path.clone()),
            _ => None,
        };
        let plaintext = handle
            .into_arc("wire_handle_encrypted_test", &session)
            .expect("materialization should decrypt")
            .to_vec();
        assert_eq!(plaintext, data);

        if let Some(path) = path {
            assert!(
                !path.exists(),
                "spooled encrypted file should be deleted on materialization"
            );
        }
    }

    #[tokio::test]
    async fn copy_bounded_stream_async_collects_metrics_without_buffering() {
        let data = vec![9u8; 12];
        let metrics = copy_bounded_stream_async(
            data.as_slice(),
            tokio::io::sink(),
            StreamLimits {
                max_body_bytes: 64,
                chunk_bytes: 4,
            },
            "wire_async_copy_test",
        )
        .await
        .expect("async stream copy");

        assert_eq!(metrics.total_bytes, 12);
        assert!(metrics.chunks >= 3);
        assert_eq!(metrics.max_chunk_seen, 4);
    }

    #[tokio::test]
    async fn read_bounded_stream_into_handle_fails_when_headroom_is_below_threshold() {
        let data = vec![9u8; 12];
        let spool_dir = std::env::temp_dir().join(format!(
            "asx-wire-headroom-fail-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        let err = read_bounded_stream_into_handle_async(
            data.as_slice(),
            StreamLimits {
                max_body_bytes: 64,
                chunk_bytes: 4,
            },
            &StreamBodyPolicy {
                spool_threshold_bytes: 8,
                spool_dir: Some(spool_dir),
                spool_encryption: SpoolEncryption::Plaintext,
                spool_lifecycle: SpoolLifecyclePolicy::default(),
                spool_retention_ttl_secs: None,
                spool_min_free_bytes: Some(u64::MAX),
                startup_hygiene_checks: true,
            },
            "wire_headroom_test",
        )
        .await
        .expect_err("insufficient free-space headroom must fail closed");

        assert_eq!(err.code, ErrorCode::PolicyViolation);
        assert!(err.message.contains("headroom"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn read_bounded_stream_into_handle_reports_headroom_metrics_when_hygiene_runs() {
        let data = vec![0xAAu8; 32];
        let spool_dir = std::env::temp_dir().join(format!(
            "asx-wire-headroom-metrics-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));

        let (_handle, metrics) = read_bounded_stream_into_handle_async(
            data.as_slice(),
            StreamLimits {
                max_body_bytes: 128,
                chunk_bytes: 8,
            },
            &StreamBodyPolicy {
                spool_threshold_bytes: usize::MAX,
                spool_dir: Some(spool_dir.clone()),
                spool_encryption: SpoolEncryption::Plaintext,
                spool_lifecycle: SpoolLifecyclePolicy::default(),
                spool_retention_ttl_secs: None,
                spool_min_free_bytes: Some(1),
                startup_hygiene_checks: true,
            },
            "wire_headroom_metrics_test",
        )
        .await
        .expect("headroom check should pass");

        let _ = std::fs::remove_dir_all(&spool_dir);

        assert!(metrics.startup_hygiene_checked);
        assert_eq!(metrics.spool_min_free_bytes, Some(1));
        assert!(
            metrics.spool_free_bytes.unwrap_or(0) >= 1,
            "free space observation should be recorded"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn startup_hygiene_checks_run_once_per_spool_dir() {
        use std::os::unix::fs::PermissionsExt;

        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let spool_dir = std::env::temp_dir().join(format!(
            "asx-wire-hygiene-once-{}-{nanos}",
            std::process::id()
        ));
        std::fs::create_dir_all(&spool_dir).expect("create spool dir");

        let policy = StreamBodyPolicy {
            spool_threshold_bytes: usize::MAX,
            spool_dir: Some(spool_dir.clone()),
            spool_encryption: SpoolEncryption::Plaintext,
            spool_lifecycle: SpoolLifecyclePolicy::default(),
            spool_retention_ttl_secs: None,
            spool_min_free_bytes: None,
            startup_hygiene_checks: true,
        };

        let limits = StreamLimits {
            max_body_bytes: 64,
            chunk_bytes: 4,
        };

        let (_first_handle, first_metrics) = read_bounded_stream_into_handle_async(
            b"first".as_slice(),
            limits,
            &policy,
            "wire_hygiene_once_test",
        )
        .await
        .expect("first startup hygiene check should pass");
        assert!(first_metrics.startup_hygiene_checked);

        let mut perms = std::fs::metadata(&spool_dir)
            .expect("spool dir metadata")
            .permissions();
        perms.set_mode(0o000);
        std::fs::set_permissions(&spool_dir, perms).expect("chmod deny");

        let (_second_handle, second_metrics) = read_bounded_stream_into_handle_async(
            b"second".as_slice(),
            limits,
            &policy,
            "wire_hygiene_once_test",
        )
        .await
        .expect("second read should skip repeated startup checks");

        let mut restore = std::fs::metadata(&spool_dir)
            .expect("spool dir metadata")
            .permissions();
        restore.set_mode(0o700);
        let _ = std::fs::set_permissions(&spool_dir, restore);
        let _ = std::fs::remove_dir_all(&spool_dir);

        assert!(
            !second_metrics.startup_hygiene_checked,
            "startup hygiene checks should be skipped after first successful run"
        );
    }

    #[tokio::test]
    async fn startup_hygiene_ttl_cleanup_is_bounded_and_converges_across_runs() {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let spool_dir = std::env::temp_dir().join(format!(
            "asx-wire-hygiene-bounded-{}-{nanos}",
            std::process::id()
        ));
        std::fs::create_dir_all(&spool_dir).expect("create spool dir");

        for idx in 0..(spooling::STARTUP_HYGIENE_MAX_TTL_SCAN_ENTRIES + 8) {
            let path = spool_dir.join(format!("expired-{idx}.spool"));
            std::fs::write(&path, b"expired").expect("seed expired spool file");
        }

        std::thread::sleep(std::time::Duration::from_millis(5));

        let policy = StreamBodyPolicy {
            spool_threshold_bytes: usize::MAX,
            spool_dir: Some(spool_dir.clone()),
            spool_encryption: SpoolEncryption::Plaintext,
            spool_lifecycle: SpoolLifecyclePolicy::default(),
            spool_retention_ttl_secs: Some(0),
            spool_min_free_bytes: None,
            startup_hygiene_checks: true,
        };

        let limits = StreamLimits {
            max_body_bytes: 64,
            chunk_bytes: 4,
        };

        let first = read_bounded_stream_into_handle_async(
            b"probe".as_slice(),
            limits,
            &policy,
            "wire_hygiene_bounded_test",
        )
        .await
        .expect("first bounded hygiene run");
        assert!(first.1.startup_hygiene_checked);

        let remaining_after_first = std::fs::read_dir(&spool_dir)
            .expect("read spool dir")
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.path())
            .filter(|path| path.extension().and_then(|v| v.to_str()) == Some("spool"))
            .count();
        assert!(
            remaining_after_first > 0,
            "bounded hygiene should not require full-directory sweep in one run"
        );

        for _ in 0..4 {
            let _ = read_bounded_stream_into_handle_async(
                b"probe".as_slice(),
                limits,
                &policy,
                "wire_hygiene_bounded_test",
            )
            .await
            .expect("subsequent bounded hygiene run");
        }

        let remaining_after_retries = std::fs::read_dir(&spool_dir)
            .expect("read spool dir")
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.path())
            .filter(|path| path.extension().and_then(|v| v.to_str()) == Some("spool"))
            .count();

        let _ = std::fs::remove_dir_all(&spool_dir);

        assert_eq!(
            remaining_after_retries, 0,
            "repeated bounded hygiene runs should converge and delete expired spool files"
        );
    }

    #[tokio::test]
    async fn copy_bounded_stream_async_rejects_oversized_payload() {
        let data = vec![1u8; 10];
        let err = copy_bounded_stream_async(
            data.as_slice(),
            tokio::io::sink(),
            StreamLimits {
                max_body_bytes: 8,
                chunk_bytes: 4,
            },
            "wire_async_copy_test",
        )
        .await
        .expect_err("oversized async copy stream must fail");
        assert_eq!(err.code, ErrorCode::PolicyViolation);
    }

    #[tokio::test]
    async fn bounded_stream_helpers_reject_unsupported_limit_ceiling() {
        let data = [1u8; 1];
        let limits = StreamLimits {
            max_body_bytes: usize::MAX,
            chunk_bytes: 1,
        };

        let read_err =
            read_bounded_stream_into_memory_async(data.as_slice(), limits, "wire_async_test")
                .await
                .expect_err("unsupported reader cap must fail");
        assert_eq!(read_err.code, ErrorCode::InvalidInput);

        let copy_err = copy_bounded_stream_async(
            data.as_slice(),
            tokio::io::sink(),
            limits,
            "wire_async_copy_test",
        )
        .await
        .expect_err("unsupported copy cap must fail");
        assert_eq!(copy_err.code, ErrorCode::InvalidInput);
    }
}
