//! Hardened HTTPS egress: address pinning, private-address refusal, body
//! caps. The built-in [`crate::HttpClient`] (messages and revocation
//! fetches) and the SMP client are built on it.

use std::net::SocketAddr;
use std::time::Duration;
use zeroize::Zeroize;

use crate::core::{AsxError, ErrorCode, ErrorContext, Result};

// ── SSRF protection ─────────────────────────────────────────────────────────

/// Validate a **revocation URL** (a CRL distribution point or an OCSP
/// responder) and return a client pinned to the addresses that were
/// validated.
///
/// The URL comes out of a certificate a peer presented (CDP, AIA). The
/// check runs only after the signature and the sender rule, but the URL is
/// still the peer's choice: without this check it could point the fetch at
/// `169.254.169.254` or any internal address — an SSRF with an
/// attacker-supplied target.
///
/// Plain HTTP is permitted here and nowhere else; see [`EgressSchemePolicy`].
///
/// # Errors
///
/// [`ErrorCode::InvalidInput`] for a malformed URL, a non-HTTP scheme, or a
/// host that is (or resolves to) a private, loopback or link-local address.
#[cfg(all(feature = "http-client", any(feature = "as2", feature = "as4")))]
pub(crate) async fn validated_pinned_revocation_client(
    url: &str,
    config: &TransportConfig,
    context: &'static str,
) -> Result<reqwest::Client> {
    let target = validate_egress_target(
        url,
        context,
        EgressSchemePolicy::AllowPlaintextForSignedRevocation,
    )
    .await?;
    let pinned = target
        .resolved_host
        .as_deref()
        .map(|host| (host, target.resolved_addrs.as_slice()));
    build_revocation_http_client(config, context, pinned)
}

#[cfg(all(feature = "http-client", any(feature = "as2", feature = "as4")))]
fn build_revocation_http_client(
    config: &TransportConfig,
    context: &'static str,
    pinned_resolution: Option<(&str, &[SocketAddr])>,
) -> Result<reqwest::Client> {
    let mut builder = reqwest::Client::builder()
        // Not `https_only`: CDPs and RFC 6960 responders are commonly plain
        // HTTP and what they serve is signed (RFC 5280 §4.2.1.13).
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(config.connect_timeout)
        .timeout(config.request_timeout)
        .user_agent(&config.user_agent);

    // Deliberately no `config.client_identity`: a CDP or OCSP responder is a
    // third party, not the partner. Presenting the market-communication
    // client certificate to it would disclose our identity to an unrelated
    // service for no gain; CRL access is anonymous (CP SM-PKI §2.4).

    if let Some((host, addrs)) = pinned_resolution {
        builder = builder.resolve_to_addrs(host, addrs);
    }

    builder.build().map_err(|err| {
        AsxError::new(
            ErrorCode::TransportFailure,
            format!("failed to build revocation HTTP client: {err}"),
            ErrorContext::new(context),
        )
    })
}

/// Validate `url` and return a client **pinned to the addresses that were
/// validated**.
///
/// Validating DNS and then letting the HTTP client resolve again is a
/// time-of-check/time-of-use hole: an attacker controlling the DNS response
/// answers with a public address for the check and a private one for the
/// connection, and the SSRF control has done nothing. Everything that makes an
/// outbound request must go through this, not through
/// [`validate_egress_target_with_policy`] plus a client of its own.
///
/// # Errors
///
/// Whatever [`validate_egress_target_with_policy`] rejects, plus a
/// client-construction failure.
// Used by the built-in HTTP client and the SMP lookup.
#[cfg(any(feature = "as2", feature = "as4"))]
pub(crate) async fn validated_pinned_client(
    url: &str,
    config: &TransportConfig,
    context: &'static str,
) -> Result<reqwest::Client> {
    let target = validate_egress_target_with_policy(url, context).await?;
    match target.resolved_host.as_deref() {
        Some(host) => build_http_client(config, context, Some((host, &target.resolved_addrs))),
        // A bare-IP target was validated literally; there is no name to pin.
        None => build_http_client(config, context, None),
    }
}

#[derive(Debug, Clone)]
#[cfg_attr(not(any(feature = "as2", feature = "as4")), allow(dead_code))]
struct ValidatedEgressTarget {
    /// Hostname used in URL authority, if the target was DNS-resolved.
    resolved_host: Option<String>,
    /// Concrete destination addresses selected during validation.
    resolved_addrs: Vec<SocketAddr>,
}

/// Whether an egress target may use plain HTTP.
///
/// Almost nothing may: business payloads and SMP metadata go over TLS.
/// Revocation data is the exception the standards carve out — CRLs and RFC
/// 6960 responses are signed, so their integrity does not depend on the
/// transport, and CDPs and responders are routinely published as `http://`
/// URLs (RFC 5280 §4.2.1.13). Requiring HTTPS there would break revocation
/// checking against most PKIs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(any(feature = "as2", feature = "as4")), allow(dead_code))]
pub(crate) enum EgressSchemePolicy {
    /// HTTPS only.
    HttpsOnly,
    /// HTTPS or plain HTTP. Only for revocation fetches (CRL, OCSP).
    AllowPlaintextForSignedRevocation,
}

#[cfg(any(feature = "as2", feature = "as4", test))]
async fn validate_egress_target_with_policy(
    url: &str,
    context: &'static str,
) -> Result<ValidatedEgressTarget> {
    validate_egress_target(url, context, EgressSchemePolicy::HttpsOnly).await
}

/// Validation-only entry point for the tests below.
///
/// Production code must use [`validated_pinned_client`] instead: validating a
/// URL and then letting a separate client re-resolve DNS is the rebinding hole
/// this whole module exists to close.
#[cfg(test)]
async fn validate_egress_url(url: &str, context: &'static str) -> Result<()> {
    validate_egress_target_with_policy(url, context)
        .await
        .map(|_| ())
}

async fn validate_egress_target(
    url: &str,
    context: &'static str,
    scheme_policy: EgressSchemePolicy,
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
        "http" if scheme_policy == EgressSchemePolicy::AllowPlaintextForSignedRevocation => {}
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
        .https_only(true)
        // Never follow HTTP redirects: the SSRF/private-range validation and the
        // pinned DNS resolution (`resolve_to_addrs`) only cover the *initial*
        // target. A `3xx Location` to a different host would be resolved and
        // connected unchecked, defeating the SSRF control. B2B/OCSP/SMP
        // endpoints are fixed URLs and never legitimately redirect.
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(config.connect_timeout)
        .timeout(config.request_timeout)
        .user_agent(&config.user_agent)
        .pool_max_idle_per_host(config.pool_max_idle_per_host)
        .pool_idle_timeout(Some(config.pool_idle_timeout));

    // Mutual TLS: present the configured client certificate when the partner
    // asks for one during the handshake.
    if let Some(identity) = &config.client_identity {
        builder = builder.identity(identity.as_reqwest());
    }

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

/// Returns `true` when `addr` is a private/loopback/link-local/otherwise
/// non-globally-routable address that an egress transport must never contact
/// (SSRF defence).
///
/// IPv6 addresses are first mapped to their canonical form via
/// [`std::net::IpAddr::to_canonical`], so an IPv4-mapped address such as
/// `::ffff:127.0.0.1` or `::ffff:169.254.169.254` is evaluated under the IPv4
/// rules rather than slipping through as an ordinary public v6 address.
pub(crate) fn is_private_ip(addr: std::net::IpAddr) -> bool {
    // Collapse IPv4-mapped/compatible v6 addresses (e.g. `::ffff:127.0.0.1`)
    // down to their embedded IPv4 form before classification.
    match addr.to_canonical() {
        std::net::IpAddr::V4(ip) => is_private_ipv4(ip),
        std::net::IpAddr::V6(ip) => is_private_ipv6(ip),
    }
}

/// IPv4 ranges that must not be reachable from egress.
fn is_private_ipv4(ip: std::net::Ipv4Addr) -> bool {
    let [a, b, ..] = ip.octets();
    ip.is_loopback()            // 127.0.0.0/8
        || ip.is_private()      // 10/8, 172.16/12, 192.168/16
        || ip.is_link_local()   // 169.254.0.0/16 (incl. cloud metadata 169.254.169.254)
        || ip.is_broadcast()    // 255.255.255.255
        || ip.is_documentation()// 192.0.2/24, 198.51.100/24, 203.0.113/24
        || ip.is_multicast()    // 224.0.0.0/4
        || a == 0               // 0.0.0.0/8 ("this host"; 0.0.0.0 routes to localhost)
        || (a == 100 && (64..=127).contains(&b)) // 100.64.0.0/10 carrier-grade NAT
        || (a == 192 && b == 0) // 192.0.0.0/24 IETF protocol assignments
        || (a == 198 && (b == 18 || b == 19)) // 198.18.0.0/15 benchmarking (RFC 2544)
        || a >= 240 // 240.0.0.0/4 reserved (incl. 255/8)
}

/// IPv6 ranges that must not be reachable from egress.
///
/// Transition addresses that embed an IPv4 address — NAT64 `64:ff9b::/96`
/// (RFC 6052) and `64:ff9b:1::/48` (RFC 8215), 6to4 `2002::/16` (RFC 3056)
/// and IPv4-compatible `::/96` — are judged by the IPv4 they embed. Teredo
/// `2001::/32` (RFC 4380) is refused wholesale: its embedded server address is
/// not the destination.
fn is_private_ipv6(ip: std::net::Ipv6Addr) -> bool {
    let seg = ip.segments();
    let low32 = std::net::Ipv4Addr::new(
        (seg[6] >> 8) as u8,
        seg[6] as u8,
        (seg[7] >> 8) as u8,
        seg[7] as u8,
    );
    let nat64_wkp = seg[0] == 0x0064 && seg[1] == 0xff9b && seg[2..6] == [0, 0, 0, 0];
    let nat64_local = seg[0] == 0x0064 && seg[1] == 0xff9b && seg[2] == 0x0001;
    let ipv4_compatible = seg[0..6] == [0, 0, 0, 0, 0, 0];
    if nat64_wkp || nat64_local || ipv4_compatible {
        // `::` and `::1` fall here and are private as 0.0.0.0/8.
        return is_private_ipv4(low32);
    }
    if seg[0] == 0x2002 {
        let embedded = std::net::Ipv4Addr::new(
            (seg[1] >> 8) as u8,
            seg[1] as u8,
            (seg[2] >> 8) as u8,
            seg[2] as u8,
        );
        return is_private_ipv4(embedded);
    }

    ip.is_loopback()
        || ip.is_unspecified()
        || ip.is_multicast()
        // unique-local fc00::/7
        || (seg[0] & 0xfe00) == 0xfc00
        // link-local fe80::/10
        || (seg[0] & 0xffc0) == 0xfe80
        // Teredo 2001::/32
        || (seg[0] == 0x2001 && seg[1] == 0x0000)
        // documentation 2001:db8::/32
        || (seg[0] == 0x2001 && seg[1] == 0x0db8)
        // discard-only 100::/64 (RFC 6666)
        || seg[0..4] == [0x0100, 0, 0, 0]
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

/// A client certificate and its private key, presented during the TLS
/// handshake when the partner requires mutual TLS.
///
/// Built from PEM so the API stays independent of the TLS backend, and parsed
/// **once** at construction: a bad certificate/key pair fails where it is
/// configured rather than at the first message, and no send pays for a parse.
///
/// Several AS4 profiles — BDEW's *Regelungen zum Übertragungsweg* among them —
/// require client-certificate authentication on the wire in addition to the
/// WS-Security signature, and the two use different keys. This is the
/// transport-layer one.
#[derive(Clone)]
#[cfg_attr(not(any(feature = "as2", feature = "as4")), allow(dead_code))]
pub struct ClientIdentity {
    identity: reqwest::Identity,
    /// Retained for diagnostics only — the key material is not kept in PEM.
    cert_chain_len: usize,
}

impl std::fmt::Debug for ClientIdentity {
    /// Never prints key material.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientIdentity")
            .field(
                "cert_chain_pem",
                &format_args!("<{} bytes>", self.cert_chain_len),
            )
            .field("key_pem", &"<redacted>")
            .finish()
    }
}

impl ClientIdentity {
    /// Build an identity from a PEM certificate chain and a PEM private key.
    ///
    /// `cert_chain_pem` is the leaf certificate first, followed by any
    /// intermediates the partner needs to build a path. `key_pem` is the
    /// leaf's private key (PKCS#8, SEC1 or PKCS#1).
    ///
    /// # Errors
    /// [`ErrorCode::InvalidInput`] if either input is empty, or if the pair is
    /// not a usable certificate/key.
    pub fn from_pem(cert_chain_pem: impl AsRef<[u8]>, key_pem: impl AsRef<[u8]>) -> Result<Self> {
        let cert_chain_pem = cert_chain_pem.as_ref();
        let key_pem = key_pem.as_ref();
        if cert_chain_pem.is_empty() {
            return Err(AsxError::new(
                ErrorCode::InvalidInput,
                "client identity certificate chain is empty",
                ErrorContext::new("transport_client_identity"),
            ));
        }
        if key_pem.is_empty() {
            return Err(AsxError::new(
                ErrorCode::InvalidInput,
                "client identity private key is empty",
                ErrorContext::new("transport_client_identity"),
            ));
        }

        // reqwest wants one PEM buffer holding the key and the chain together.
        // It is a copy of the private key, so it is wiped before it is dropped.
        let mut combined = Vec::with_capacity(key_pem.len() + cert_chain_pem.len() + 1);
        combined.extend_from_slice(key_pem);
        if !key_pem.ends_with(b"\n") {
            combined.push(b'\n');
        }
        combined.extend_from_slice(cert_chain_pem);
        let parsed = reqwest::Identity::from_pem(&combined);
        combined.zeroize();

        Ok(Self {
            identity: parsed.map_err(|err| {
                AsxError::new(
                    ErrorCode::InvalidInput,
                    format!("invalid TLS client identity (certificate/key pair): {err}"),
                    ErrorContext::new("transport_client_identity"),
                )
            })?,
            cert_chain_len: cert_chain_pem.len(),
        })
    }

    /// The parsed backend identity.
    #[cfg_attr(not(any(feature = "as2", feature = "as4")), allow(dead_code))]
    fn as_reqwest(&self) -> reqwest::Identity {
        self.identity.clone()
    }
}

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
    /// `User-Agent` header value. Default: `asx/<crate version>`.
    pub user_agent: String,
    /// Maximum idle connections per host kept in the pool. Default: 4.
    pub pool_max_idle_per_host: usize,
    /// Idle keep-alive timeout. Default: 90 s.
    pub pool_idle_timeout: Duration,
    /// Client certificate presented when the partner requests one during the
    /// TLS handshake. Default: none (server-authenticated TLS only).
    pub client_identity: Option<ClientIdentity>,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(10),
            request_timeout: Duration::from_secs(60),
            user_agent: concat!("asx/", env!("CARGO_PKG_VERSION")).to_string(),
            pool_max_idle_per_host: 4,
            pool_idle_timeout: Duration::from_secs(90),
            client_identity: None,
        }
    }
}

// ── Error mapping ───────────────────────────────────────────────────────────

/// Read a response body, refusing more than `cap` bytes with
/// [`ErrorCode::PayloadTooLarge`].
///
/// A declared `Content-Length` over the cap is refused before anything is
/// read; otherwise chunks are accumulated until the cap would be exceeded, so
/// at most `cap` plus one chunk is ever buffered. Every egress response body
/// (partner sends, SMP, OCSP) goes through here: the peer chooses its size.
pub(crate) async fn read_body_capped(
    mut resp: reqwest::Response,
    cap: usize,
    stage: &'static str,
) -> Result<bytes::Bytes> {
    let too_large = |size: String| {
        AsxError::new(
            ErrorCode::PayloadTooLarge,
            format!("response body {size} exceeds the {cap} byte limit"),
            ErrorContext::new(stage),
        )
    };
    if let Some(declared) = resp.content_length()
        && declared > cap as u64
    {
        return Err(too_large(format!("of {declared} bytes (Content-Length)")));
    }
    let mut body = bytes::BytesMut::new();
    while let Some(chunk) = resp.chunk().await.map_err(|err| {
        AsxError::new(
            ErrorCode::TransportFailure,
            format!("failed to read response body: {err}"),
            ErrorContext::new(stage),
        )
    })? {
        if body.len().saturating_add(chunk.len()) > cap {
            return Err(too_large(format!(
                "of more than {} bytes",
                body.len().saturating_add(chunk.len())
            )));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body.freeze())
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Serve one HTTP response per connection: `head` then `body_chunks`.
    async fn serve_once(head: String, body_chunks: Vec<Vec<u8>>) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept");
            let mut request = [0u8; 1024];
            let _ = socket.read(&mut request).await;
            let _ = socket.write_all(head.as_bytes()).await;
            for chunk in body_chunks {
                if socket.write_all(&chunk).await.is_err() {
                    return;
                }
            }
            let _ = socket.shutdown().await;
        });
        format!("http://{addr}/")
    }

    #[tokio::test]
    async fn read_body_capped_refuses_oversized_bodies() {
        const CAP: usize = 1024;
        let client = reqwest::Client::new();

        // (a) A declared Content-Length over the cap.
        let url = serve_once(
            format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                CAP + 1
            ),
            vec![vec![b'a'; CAP + 1]],
        )
        .await;
        let resp = client.get(&url).send().await.expect("response");
        let err = read_body_capped(resp, CAP, "capped_test")
            .await
            .expect_err("a Content-Length over the cap must be refused");
        assert_eq!(err.code, ErrorCode::PayloadTooLarge, "{}", err.message);

        // (b) A chunked body that streams past the cap.
        let chunks: Vec<Vec<u8>> = (0..16)
            .map(|_| {
                let data = vec![b'b'; 256];
                let mut chunk = format!("{:x}\r\n", data.len()).into_bytes();
                chunk.extend_from_slice(&data);
                chunk.extend_from_slice(b"\r\n");
                chunk
            })
            .chain(std::iter::once(b"0\r\n\r\n".to_vec()))
            .collect();
        let url = serve_once(
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
                .to_string(),
            chunks,
        )
        .await;
        let resp = client.get(&url).send().await.expect("response");
        let err = read_body_capped(resp, CAP, "capped_test")
            .await
            .expect_err("a chunked body past the cap must be refused");
        assert_eq!(err.code, ErrorCode::PayloadTooLarge, "{}", err.message);

        // Control: a body within the cap is returned whole.
        let url = serve_once(
            format!("HTTP/1.1 200 OK\r\nContent-Length: {CAP}\r\nConnection: close\r\n\r\n"),
            vec![vec![b'c'; CAP]],
        )
        .await;
        let resp = client.get(&url).send().await.expect("response");
        let body = read_body_capped(resp, CAP, "capped_test")
            .await
            .expect("a body at the cap is accepted");
        assert_eq!(body.len(), CAP);
    }

    #[test]
    fn transition_benchmark_and_documentation_ranges_are_private() {
        let private = [
            "64:ff9b::10.0.0.1", // NAT64 (RFC 6052) embedding 10.0.0.1
            "64:ff9b:1::a00:1",  // local-use NAT64 (RFC 8215) embedding 10.0.0.1
            "2002:0a00:0001::1", // 6to4 (RFC 3056) embedding 10.0.0.1
            "::10.0.0.1",        // IPv4-compatible
            "2001:0::1",         // Teredo (RFC 4380)
            "198.18.0.1",        // benchmarking (RFC 2544)
            "2001:db8::1",       // documentation
            "100::1",            // discard-only (RFC 6666)
        ];
        for addr in private {
            let ip: std::net::IpAddr = addr.parse().expect(addr);
            assert!(is_private_ip(ip), "{addr} must be private");
        }
        let public = [
            "64:ff9b::8.8.8.8",
            "2002:0808:0808::1",
            "8.8.8.8",
            "2606:4700::1111",
        ];
        for addr in public {
            let ip: std::net::IpAddr = addr.parse().expect(addr);
            assert!(!is_private_ip(ip), "{addr} must stay public");
        }
    }

    #[test]
    fn transport_config_defaults_are_sensible() {
        let cfg = TransportConfig::default();
        assert_eq!(cfg.connect_timeout, Duration::from_secs(10));
        assert_eq!(cfg.request_timeout, Duration::from_secs(60));
        assert!(cfg.user_agent.starts_with("asx/"));
        assert!(cfg.pool_max_idle_per_host > 0);
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
    async fn validate_egress_url_rejects_ipv4_mapped_ipv6_and_reserved_v4() {
        // IPv4-mapped IPv6 addresses must be canonicalized and
        // classified under the v4 rules, and additional reserved v4 ranges
        // (0.0.0.0/8, CGNAT, documentation) must be blocked — otherwise these
        // are SSRF bypasses to loopback / link-local / internal targets.
        for url in &[
            "https://[::ffff:127.0.0.1]/as4",       // mapped loopback
            "https://[::ffff:169.254.169.254]/as4", // mapped cloud metadata
            "https://[::ffff:10.0.0.1]/as4",        // mapped RFC-1918
            "https://0.0.0.0/as4",                  // 0.0.0.0/8 (routes to localhost)
            "https://100.64.0.1/as4",               // carrier-grade NAT
            "https://203.0.113.9/as4",              // TEST-NET-3 documentation
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
        // 8.8.8.8 is a globally-routable public address (IP literal → no DNS
        // needed). RFC 5737 TEST-NET ranges are intentionally *not* used here:
        // they are reserved/unroutable and rejected as non-global.
        validate_egress_url("https://8.8.8.8/as2/receive", "ctx")
            .await
            .expect("public HTTPS should be accepted");
    }

    #[tokio::test]
    async fn validate_egress_url_rejects_public_http_by_default() {
        let err = validate_egress_url("http://8.8.8.8/as4/receive", "ctx")
            .await
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::PolicyViolation);
    }

    #[tokio::test]
    async fn validate_egress_target_for_ip_literal_requires_no_dns_pinning() {
        let target = validate_egress_target_with_policy("https://8.8.8.8/as2/receive", "ctx")
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
