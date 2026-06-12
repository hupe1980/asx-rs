//! Async HTTP egress transport for AS2 and AS4.
//!
//! Requires the `client` feature flag.
//!
//! # Example — AS2
//! ```ignore
//! use asx::transport::egress::{As2HttpTransport, TransportConfig};
//! use asx::as2::{send_sync, As2SendPolicy, As2SendCredentials, As2SendRequest};
//!
//! let transport = As2HttpTransport::new(TransportConfig::default())?;
//! let output = send_sync(
//!     &session,
//!     &bus,
//!     As2SendRequest {
//!         message_id: msg_id,
//!         payload,
//!         policy,
//!         credentials: creds,
//!     },
//! )?;
//! let outcome = transport.send("https://partner.example/as2", &output).await?;
//! ```
//!
//! # Example — AS4
//! ```ignore
//! let transport = As4HttpTransport::new(TransportConfig::default())?;
//! let output = asx::as4::send_sync(
//!     &session,
//!     &bus,
//!     asx::as4::As4SendRequest {
//!         message_id: msg_id,
//!         payload,
//!         policy,
//!         credentials: creds,
//!     },
//! )?;
//! let outcome = transport.send("https://partner.example/as4", &output).await?;
//! ```

use std::net::SocketAddr;
use std::time::Duration;

use crate::core::{AsxError, ErrorCode, ErrorContext, Result};
use crate::http::HttpHeaders;

#[cfg(feature = "as2")]
use crate::as2::As2SendOutput;
#[cfg(feature = "as4")]
use crate::as4::As4SendOutput;

// ── SSRF protection ─────────────────────────────────────────────────────────

/// Validate an outbound URL before sending.
///
/// Rejects:
/// - Non-HTTP(S) schemes.
/// - All plain-HTTP URLs.
/// - Private / loopback / link-local IP ranges (RFC 1918, RFC 4291 §2.5.3,
///   RFC 3927) to prevent Server-Side Request Forgery (SSRF).
/// - Hostnames that DNS-resolve to any private / loopback address (DNS-rebinding
///   defence).
///
/// # Errors
/// Returns [`ErrorCode::InvalidInput`] for malformed URLs, disallowed schemes,
/// or private-range IP hosts. Returns [`ErrorCode::PolicyViolation`] when
/// plain HTTP is attempted.
#[cfg_attr(not(feature = "as4"), allow(dead_code))]
pub(crate) async fn validate_egress_url(url: &str, context: &'static str) -> Result<()> {
    let target = validate_egress_target_with_policy(url, context).await?;
    // In client-only builds without AS2/AS4 transport features enabled, this
    // keeps the validated target fields live so warning hygiene stays clean.
    let _ = (&target.url, &target.resolved_host, &target.resolved_addrs);
    Ok(())
}

#[derive(Debug, Clone)]
struct ValidatedEgressTarget {
    url: reqwest::Url,
    /// Hostname used in URL authority, if the target was DNS-resolved.
    resolved_host: Option<String>,
    /// Concrete destination addresses selected during validation.
    resolved_addrs: Vec<SocketAddr>,
}

async fn validate_egress_target_with_policy(
    url: &str,
    context: &'static str,
) -> Result<ValidatedEgressTarget> {
    let parsed = reqwest::Url::parse(url).map_err(|_| {
        AsxError::new(
            ErrorCode::InvalidInput,
            format!("malformed egress URL: {url}"),
            ErrorContext::new(context),
        )
    })?;

    match parsed.scheme() {
        "https" => {}
        "http" => {
            return Err(AsxError::new(
                ErrorCode::PolicyViolation,
                "plain HTTP egress is not permitted; use HTTPS for all outbound transport",
                ErrorContext::new(context),
            ));
        }
        scheme => {
            return Err(AsxError::new(
                ErrorCode::InvalidInput,
                format!(
                    "egress URL scheme '{scheme}' is not allowed; \
                     only http and https are permitted"
                ),
                ErrorContext::new(context),
            ));
        }
    }

    // Block private/loopback hosts to prevent SSRF.
    let mut resolved_host = None;
    let mut resolved_addrs = Vec::new();

    if let Some(host) = parsed.host_str() {
        // First check the literal value (fast path for IP addresses).
        if is_private_host(host) {
            return Err(AsxError::new(
                ErrorCode::InvalidInput,
                format!(
                    "egress URL host '{host}' is a private or loopback address; \
                     outbound requests to internal networks are not permitted"
                ),
                ErrorContext::new(context),
            ));
        }

        // For hostnames (not bare IPs), resolve and check every returned address
        // to defend against DNS-rebinding attacks.
        if host.parse::<std::net::IpAddr>().is_err() {
            let port = parsed.port_or_known_default().unwrap_or(443);
            let lookup_target = format!("{host}:{port}");
            let addrs = tokio::net::lookup_host(&lookup_target).await.map_err(|e| {
                AsxError::new(
                    ErrorCode::InvalidInput,
                    format!("egress URL host '{host}' could not be resolved: {e}"),
                    ErrorContext::new(context),
                )
            })?;
            for addr in addrs {
                if is_private_ip(addr.ip()) {
                    return Err(AsxError::new(
                        ErrorCode::InvalidInput,
                        format!(
                            "egress URL host '{host}' resolves to a private or loopback address \
                             ({ip}); outbound requests to internal networks are not permitted",
                            ip = addr.ip()
                        ),
                        ErrorContext::new(context),
                    ));
                }
                resolved_addrs.push(addr);
            }

            if resolved_addrs.is_empty() {
                return Err(AsxError::new(
                    ErrorCode::InvalidInput,
                    format!("egress URL host '{host}' resolved to no usable addresses"),
                    ErrorContext::new(context),
                ));
            }

            resolved_host = Some(host.to_string());
        }
    }

    Ok(ValidatedEgressTarget {
        url: parsed,
        resolved_host,
        resolved_addrs,
    })
}

#[cfg(any(feature = "as2", feature = "as4"))]
fn build_http_client(
    config: &TransportConfig,
    context: &'static str,
    pinned_resolution: Option<(&str, &[SocketAddr])>,
) -> Result<reqwest::Client> {
    let mut builder = reqwest::Client::builder()
        .use_rustls_tls()
        .https_only(true)
        .connect_timeout(config.connect_timeout)
        .timeout(config.request_timeout)
        .user_agent(&config.user_agent)
        .pool_max_idle_per_host(config.pool_max_idle_per_host)
        .pool_idle_timeout(Some(config.pool_idle_timeout));

    if let Some((host, addrs)) = pinned_resolution {
        builder = builder.resolve_to_addrs(host, addrs);
    }

    builder.build().map_err(|err| {
        AsxError::new(
            ErrorCode::TransportFailure,
            format!("failed to build HTTP client: {err}"),
            ErrorContext::new(context),
        )
    })
}

/// Returns `true` when `addr` is a private/loopback/link-local address.
pub(crate) fn is_private_ip(addr: std::net::IpAddr) -> bool {
    match addr {
        std::net::IpAddr::V4(ip) => {
            let [a, b, ..] = ip.octets();
            matches!(
                (a, b),
                (127, _) | (10, _) | (172, 16..=31) | (192, 168) | (169, 254)
            )
        }
        std::net::IpAddr::V6(ip) => {
            ip.is_loopback()
                || ip.is_unspecified()
                // unique-local fc00::/7
                || (ip.segments()[0] & 0xfe00) == 0xfc00
                // link-local fe80::/10
                || (ip.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

/// Returns `true` when `host` is a private/loopback/link-local address or
/// hostname that should not be contacted from an egress transport.
pub(crate) fn is_private_host(host: &str) -> bool {
    // Named loopback hostnames.
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }

    // Try to parse as an IP address (bare or bracket-wrapped).
    let h_lower = host.to_ascii_lowercase();
    let h_bare = h_lower.trim_start_matches('[').trim_end_matches(']');
    if let Ok(ip) = h_bare.parse::<std::net::IpAddr>() {
        return is_private_ip(ip);
    }

    false
}

// ── Transport configuration ─────────────────────────────────────────────────

/// Configuration for the async HTTP transport client.
///
/// Use [`TransportConfig::default`] for sensible production defaults, or
/// build a custom config with the builder methods.
#[derive(Debug, Clone)]
pub struct TransportConfig {
    /// Timeout for establishing a TCP+TLS connection. Default: 10 s.
    pub connect_timeout: Duration,
    /// Timeout for the full request round-trip (from send to last byte of
    /// response body). Default: 60 s.
    pub request_timeout: Duration,
    /// `User-Agent` header value. Default: `"asx/0.1"`.
    pub user_agent: String,
    /// Maximum idle connections per host kept in the pool. Default: 4.
    pub pool_max_idle_per_host: usize,
    /// Idle keep-alive timeout. Default: 90 s.
    pub pool_idle_timeout: Duration,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(10),
            request_timeout: Duration::from_secs(60),
            user_agent: "asx/0.1".to_string(),
            pool_max_idle_per_host: 4,
            pool_idle_timeout: Duration::from_secs(90),
        }
    }
}

impl TransportConfig {
    /// Override the connection timeout.
    pub fn with_connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = timeout;
        self
    }

    /// Override the request timeout.
    pub fn with_request_timeout(mut self, timeout: Duration) -> Self {
        self.request_timeout = timeout;
        self
    }

    /// Override the `User-Agent` header value.
    pub fn with_user_agent(mut self, user_agent: impl Into<String>) -> Self {
        self.user_agent = user_agent.into();
        self
    }
}

// ── Shared response type ────────────────────────────────────────────────────

/// The outcome of an HTTP transport send operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpSendOutcome {
    /// HTTP status code returned by the partner.
    pub status: u16,
    /// Response headers as case-preserved key/value pairs.
    pub headers: HttpHeaders,
    /// Response body bytes.
    pub body: std::sync::Arc<[u8]>,
}

impl HttpSendOutcome {
    /// Returns `true` when the partner responded with a 2xx status code.
    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }

    /// Returns the value of the first response header matching `name`
    /// (case-insensitive).
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// Returns `true` when the response body appears to be a synchronous AS2
    /// MDN (a `multipart/report` body returned immediately on the AS2 receive
    /// endpoint's HTTP response).
    pub fn is_sync_mdn(&self) -> bool {
        self.header("Content-Type")
            .map(|ct| ct.to_ascii_lowercase().contains("multipart/report"))
            .unwrap_or(false)
    }
}

// ── Error mapping ───────────────────────────────────────────────────────────

#[cfg(any(feature = "as2", feature = "as4"))]
fn reqwest_to_asx(err: reqwest::Error, context: &'static str) -> AsxError {
    AsxError::new(
        ErrorCode::TransportFailure,
        format!("HTTP transport error: {err}"),
        ErrorContext::new(context),
    )
}

// ── AS2 HTTP transport ──────────────────────────────────────────────────────

#[cfg(feature = "as2")]
/// Async HTTP transport for AS2 messages, implementing the RFC 4130 §6
/// HTTP binding.
///
/// The `http_headers` from [`As2SendOutput`] are forwarded verbatim.
/// `Content-Length` is added automatically.
///
/// Use [`As2HttpTransport::new`] with a [`TransportConfig`] (or
/// `TransportConfig::default()`) to construct an instance.
pub struct As2HttpTransport {
    client: reqwest::Client,
    runtime_config: TransportConfig,
}

#[cfg(feature = "as2")]
impl As2HttpTransport {
    /// Create a new AS2 transport client from the given configuration.
    ///
    /// # Errors
    /// Returns an error if the underlying `reqwest::Client` cannot be built
    /// (typically a TLS initialisation failure).
    pub fn new(config: TransportConfig) -> Result<Self> {
        let client = build_http_client(&config, "as2_transport_init", None)?;
        Ok(Self {
            client,
            runtime_config: config,
        })
    }

    /// Send an AS2 message to `url` using a `POST` with RFC 4130 §6 required
    /// headers.
    ///
    /// The headers computed by [`crate::as2::send_sync`] and stored in
    /// `output.http_headers` are forwarded as-is. `Content-Length` is appended
    /// automatically from the body length.
    ///
    /// # SSRF protection
    /// Private / loopback / link-local IP ranges and the `localhost` hostname
    /// are rejected unconditionally to prevent Server-Side Request Forgery.
    /// HTTPS is required for all outbound requests.
    ///
    /// # AS2 MDN handling
    /// When the partner sends a synchronous MDN in the HTTP response body,
    /// [`HttpSendOutcome::is_sync_mdn`] will return `true`. Pass the
    /// `outcome.body` to [`crate::as2::receive_sync`] to parse and
    /// classify the delivery outcome.
    ///
    /// # Errors
    /// Returns [`ErrorCode::InvalidInput`] for disallowed URLs.
    /// Returns [`ErrorCode::TransportFailure`] on network or TLS errors.
    pub async fn send(&self, url: &str, output: &As2SendOutput) -> Result<HttpSendOutcome> {
        let target = validate_egress_target_with_policy(url, "as2_transport_send").await?;

        let mut headers = reqwest::header::HeaderMap::new();

        for (name, value) in &output.http_headers {
            let key = reqwest::header::HeaderName::from_bytes(name.as_bytes()).map_err(|_| {
                AsxError::new(
                    ErrorCode::InvalidInput,
                    format!("invalid HTTP header name '{name}'"),
                    ErrorContext::new("as2_transport_send"),
                )
            })?;
            let val = reqwest::header::HeaderValue::from_str(value).map_err(|_| {
                AsxError::new(
                    ErrorCode::InvalidInput,
                    format!("invalid HTTP header value for '{name}'"),
                    ErrorContext::new("as2_transport_send"),
                )
            })?;
            headers.insert(key, val);
        }

        if let Some(traceparent) = &output.traceparent {
            let val = reqwest::header::HeaderValue::from_str(traceparent).map_err(|_| {
                AsxError::new(
                    ErrorCode::InvalidInput,
                    "invalid traceparent header value",
                    ErrorContext::new("as2_transport_send"),
                )
            })?;
            headers.insert(reqwest::header::HeaderName::from_static("traceparent"), val);
        }

        let body_bytes = output.mime.body.clone();

        let client = if let Some(host) = target.resolved_host.as_deref() {
            build_http_client(
                &self.runtime_config,
                "as2_transport_send",
                Some((host, &target.resolved_addrs)),
            )?
        } else {
            self.client.clone()
        };

        let response = client
            .post(target.url.clone())
            .headers(headers)
            .body(body_bytes.to_vec())
            .send()
            .await
            .map_err(|e| reqwest_to_asx(e, "as2_transport_send"))?;

        let status = response.status().as_u16();
        let resp_headers: Vec<(String, String)> = response
            .headers()
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
            .collect();

        let body = response
            .bytes()
            .await
            .map_err(|e| reqwest_to_asx(e, "as2_transport_recv_body"))?
            .to_vec()
            .into();

        Ok(HttpSendOutcome {
            status,
            headers: HttpHeaders::from_vec(resp_headers),
            body,
        })
    }

    /// Send an asynchronous AS2 MDN to the partner's `url` (RFC 4130 §7.9.3).
    ///
    /// Use this after receiving an AS2 message that requested an asynchronous
    /// MDN via the `Disposition-Notification-To` header. Build the MDN bytes
    /// with [`crate::as2::generate_mdn`], then pass them here.
    ///
    /// Required headers (`AS2-Version`, `AS2-From`, `AS2-To`,
    /// `Content-Type: multipart/report; ...`) are set automatically.
    /// `message_id` is wrapped in angle brackets per RFC 2822 §3.6.4.
    ///
    /// # SSRF protection
    /// The `url` is validated with the same private-address rejection rules as
    /// [`Self::send`].
    ///
    /// # Errors
    /// Returns [`ErrorCode::InvalidInput`] for disallowed URLs or empty IDs.
    /// Returns [`ErrorCode::TransportFailure`] on network errors.
    pub async fn send_async_mdn(&self, request: &As2AsyncMdnRequest) -> Result<HttpSendOutcome> {
        let target = validate_egress_target_with_policy(&request.url, "as2_async_mdn_send").await?;

        if request.as2_from.trim().is_empty() {
            return Err(AsxError::new(
                ErrorCode::InvalidInput,
                "As2AsyncMdnRequest.as2_from must not be empty",
                ErrorContext::new("as2_async_mdn_send"),
            ));
        }
        if request.as2_to.trim().is_empty() {
            return Err(AsxError::new(
                ErrorCode::InvalidInput,
                "As2AsyncMdnRequest.as2_to must not be empty",
                ErrorContext::new("as2_async_mdn_send"),
            ));
        }

        let stripped = request
            .original_message_id
            .trim()
            .trim_matches(|c| c == '<' || c == '>');
        let message_id = format!("<{stripped}>");
        let mdn_content_type =
            extract_as2_mdn_content_type(&request.mdn_bytes).unwrap_or_else(|| {
                "multipart/report; report-type=disposition-notification".to_string()
            });

        let client = if let Some(host) = target.resolved_host.as_deref() {
            build_http_client(
                &self.runtime_config,
                "as2_async_mdn_send",
                Some((host, &target.resolved_addrs)),
            )?
        } else {
            self.client.clone()
        };

        let response = client
            .post(target.url.clone())
            .header("AS2-Version", "1.2")
            .header("AS2-From", &request.as2_from)
            .header("AS2-To", &request.as2_to)
            .header("Message-ID", &message_id)
            .header("Content-Type", mdn_content_type)
            .header("MIME-Version", "1.0")
            .body(request.mdn_bytes.to_vec())
            .send()
            .await
            .map_err(|e| reqwest_to_asx(e, "as2_async_mdn_send"))?;

        let status = response.status().as_u16();
        let resp_headers: HttpHeaders = response
            .headers()
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
            .collect();
        let body = response
            .bytes()
            .await
            .map_err(|e| reqwest_to_asx(e, "as2_async_mdn_recv_body"))?
            .to_vec();

        Ok(HttpSendOutcome {
            status,
            headers: resp_headers,
            body: body.into(),
        })
    }
}

#[cfg(feature = "as2")]
fn extract_as2_mdn_content_type(mdn_bytes: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(mdn_bytes).ok()?;
    let (headers, _) = text.split_once("\r\n\r\n")?;
    headers.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        if name.trim().eq_ignore_ascii_case("Content-Type") {
            let ct = value.trim();
            if ct.is_empty() {
                None
            } else {
                Some(ct.to_string())
            }
        } else {
            None
        }
    })
}

/// Request parameters for dispatching an asynchronous AS2 MDN (RFC 4130 §7.9.3).
///
/// Build `mdn_bytes` with [`crate::as2::generate_mdn`], then pass
/// this struct to [`As2HttpTransport::send_async_mdn`].
#[cfg(feature = "as2")]
#[derive(Debug, Clone)]
pub struct As2AsyncMdnRequest {
    /// Partner's asynchronous MDN endpoint URL (from the inbound
    /// `Disposition-Notification-To` or `Receipt-Delivery-Option` header).
    pub url: String,
    /// `Message-ID` of the original inbound AS2 message being acknowledged.
    pub original_message_id: String,
    /// MDN body bytes generated by [`crate::as2::generate_mdn`].
    pub mdn_bytes: std::sync::Arc<[u8]>,
    /// This party's AS2 identifier (`AS2-From` header value).
    pub as2_from: String,
    /// Partner's AS2 identifier (`AS2-To` header value).
    pub as2_to: String,
}

// ── AS4 HTTP transport ──────────────────────────────────────────────────────

#[cfg(feature = "as4")]
/// Async SOAP-over-HTTP transport for AS4 messages, implementing the
/// eDelivery AS4 HTTP binding (SOAP 1.2).
///
/// The transport sets the following HTTP headers automatically:
/// - `Content-Type: application/soap+xml; charset=UTF-8; action="<action>"`
/// - `Content-Length: <bytes>`
///
/// where `<action>` is taken from [`As4SendOutput::action`].
pub struct As4HttpTransport {
    client: reqwest::Client,
    runtime_config: TransportConfig,
}

#[cfg(feature = "as4")]
impl As4HttpTransport {
    /// Create a new AS4 transport client from the given configuration.
    ///
    /// # Errors
    /// Returns an error if the underlying `reqwest::Client` cannot be built.
    pub fn new(config: TransportConfig) -> Result<Self> {
        let client = build_http_client(&config, "as4_transport_init", None)?;
        Ok(Self {
            client,
            runtime_config: config,
        })
    }

    /// Send an AS4 SOAP envelope to `url` using a `POST` with SOAP 1.2
    /// eDelivery HTTP binding headers.
    ///
    /// # SSRF protection
    /// Private / loopback / link-local IP ranges are rejected. HTTPS is
    /// required for all outbound requests.
    ///
    /// # Errors
    /// Returns [`ErrorCode::InvalidInput`] for disallowed URLs.
    /// Returns [`ErrorCode::TransportFailure`] on network or TLS errors.
    pub async fn send(&self, url: &str, output: &As4SendOutput) -> Result<HttpSendOutcome> {
        let target = validate_egress_target_with_policy(url, "as4_transport_send").await?;

        let client = if let Some(host) = target.resolved_host.as_deref() {
            build_http_client(
                &self.runtime_config,
                "as4_transport_send",
                Some((host, &target.resolved_addrs)),
            )?
        } else {
            self.client.clone()
        };

        let mut request = client
            .post(target.url.clone())
            .header("Content-Type", &output.http_content_type)
            .body(output.soap_envelope.body.to_vec());

        if let Some(traceparent) = &output.traceparent {
            request = request.header("traceparent", traceparent);
        }

        let response = request
            .send()
            .await
            .map_err(|e| reqwest_to_asx(e, "as4_transport_send"))?;

        let status = response.status().as_u16();
        let resp_headers: HttpHeaders = response
            .headers()
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
            .collect();

        let body: Vec<u8> = response
            .bytes()
            .await
            .map_err(|e| reqwest_to_asx(e, "as4_transport_recv_body"))?
            .to_vec();

        Ok(HttpSendOutcome {
            status,
            headers: resp_headers,
            body: body.into(),
        })
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transport_config_defaults_are_sensible() {
        let cfg = TransportConfig::default();
        assert_eq!(cfg.connect_timeout, Duration::from_secs(10));
        assert_eq!(cfg.request_timeout, Duration::from_secs(60));
        assert!(cfg.user_agent.starts_with("asx/"));
        assert!(cfg.pool_max_idle_per_host > 0);
    }

    #[test]
    fn http_send_outcome_is_success_range() {
        let make = |status: u16| HttpSendOutcome {
            status,
            headers: HttpHeaders::new(),
            body: vec![].into(),
        };
        assert!(make(200).is_success());
        assert!(make(204).is_success());
        assert!(!make(400).is_success());
        assert!(!make(500).is_success());
    }

    #[test]
    fn http_send_outcome_header_lookup_is_case_insensitive() {
        let outcome = HttpSendOutcome {
            status: 200,
            headers: HttpHeaders::from_vec(vec![(
                "content-type".into(),
                "multipart/report; boundary=foo".into(),
            )]),
            body: vec![].into(),
        };
        assert_eq!(
            outcome.header("Content-Type"),
            Some("multipart/report; boundary=foo")
        );
        assert!(outcome.is_sync_mdn());
    }

    #[test]
    fn http_send_outcome_is_sync_mdn_requires_multipart_report() {
        let outcome = HttpSendOutcome {
            status: 200,
            headers: HttpHeaders::from_vec(vec![(
                "Content-Type".into(),
                "application/pkcs7-mime".into(),
            )]),
            body: vec![].into(),
        };
        assert!(!outcome.is_sync_mdn());
    }

    #[cfg(feature = "as2")]
    #[test]
    fn as2_transport_builds_with_default_config() {
        As2HttpTransport::new(TransportConfig::default()).expect("should build without error");
    }

    #[cfg(feature = "as2")]
    #[test]
    fn extract_as2_mdn_content_type_reads_top_level_header() {
        let mdn = b"Content-Type: multipart/report; report-type=disposition-notification; boundary=\"b\"\r\n\
MIME-Version: 1.0\r\n\
\r\n\
--b\r\n\
Content-Type: text/plain\r\n\
\r\n\
ok\r\n\
--b--\r\n";

        let ct = extract_as2_mdn_content_type(mdn).expect("content type");
        assert!(ct.starts_with("multipart/report;"));
        assert!(ct.contains("boundary=\"b\""));
    }

    #[cfg(feature = "as4")]
    #[test]
    fn as4_transport_builds_with_default_config() {
        As4HttpTransport::new(TransportConfig::default()).expect("should build without error");
    }

    // ── SSRF protection ───────────────────────────────────────────────────────

    #[tokio::test]
    async fn validate_egress_url_rejects_non_http_scheme() {
        let err = validate_egress_url("ftp://example.com/file", "ctx")
            .await
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidInput);
        assert!(err.message.contains("ftp"));
    }

    #[tokio::test]
    async fn validate_egress_url_rejects_localhost() {
        for host in &["https://localhost/path", "https://localhost:8080/as2"] {
            let err = validate_egress_url(host, "ctx").await.unwrap_err();
            assert_eq!(err.code, ErrorCode::InvalidInput);
        }
    }

    #[tokio::test]
    async fn validate_egress_url_rejects_loopback_ipv4() {
        for url in &["https://127.0.0.1/as2", "https://127.1.2.3:8443/as2"] {
            let err = validate_egress_url(url, "ctx").await.unwrap_err();
            assert_eq!(
                err.code,
                ErrorCode::InvalidInput,
                "expected rejection for {url}"
            );
        }
    }

    #[tokio::test]
    async fn validate_egress_url_rejects_private_ipv4_ranges() {
        for url in &[
            "https://10.0.0.1/as2",
            "https://172.16.0.1/as2",
            "https://172.31.255.255/as2",
            "https://192.168.1.100/as2",
            "https://169.254.1.1/as2",
        ] {
            let err = validate_egress_url(url, "ctx").await.unwrap_err();
            assert_eq!(
                err.code,
                ErrorCode::InvalidInput,
                "expected rejection for {url}"
            );
        }
    }

    #[tokio::test]
    async fn validate_egress_url_rejects_private_ipv6_ranges() {
        for url in &[
            "https://[::1]/as4",
            "https://[fc00::1]/as4",
            "https://[fd12:3456:789a::1]/as4",
            "https://[fe80::1]/as4",
        ] {
            let err = validate_egress_url(url, "ctx").await.unwrap_err();
            assert_eq!(
                err.code,
                ErrorCode::InvalidInput,
                "expected rejection for {url}"
            );
        }
    }

    #[tokio::test]
    async fn validate_egress_url_accepts_public_https() {
        // 203.0.113.1 is in TEST-NET-3 (RFC 5737) — public, non-private, no DNS needed.
        validate_egress_url("https://203.0.113.1/as2/receive", "ctx")
            .await
            .expect("public HTTPS should be accepted");
    }

    #[tokio::test]
    async fn validate_egress_url_rejects_public_http_by_default() {
        let err = validate_egress_url("http://203.0.113.1/as4/receive", "ctx")
            .await
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::PolicyViolation);
    }

    #[tokio::test]
    async fn validate_egress_target_for_ip_literal_requires_no_dns_pinning() {
        let target = validate_egress_target_with_policy("https://203.0.113.1/as2/receive", "ctx")
            .await
            .expect("public ip literal should validate");

        assert!(target.resolved_host.is_none());
        assert!(target.resolved_addrs.is_empty());
    }

    #[tokio::test]
    async fn validate_egress_url_rejects_malformed() {
        let err = validate_egress_url("not a url at all", "ctx")
            .await
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidInput);
    }
}
