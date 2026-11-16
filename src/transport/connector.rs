//! The built-in client's connector: every new connection is made here, so
//! the pooled client cannot reach an address that was not checked.
//!
//! For each connection, in order:
//!
//! 1. the host's operator pin (`Builder::resolve`), else DNS;
//! 2. the private-address filter on every resolved address (an SSRF guard:
//!    revocation URLs and asynchronous-MDN URLs are peer-chosen), skipped
//!    only for a pinned host;
//! 3. TCP to the address that was checked (no second resolution, so DNS
//!    rebinding cannot swap it);
//! 4. TLS with SNI for a DNS name (RzÜ AS4 2.6 Kap. 3, RFC 6066 §3) and
//!    host-name verification (RFC 6125) under the profile's [`TlsPolicy`];
//! 5. under BDEW, the server chain's revocation status from the client's CRL
//!    validator (BDEW AS4-Profil 1.2 Kap. 2.3.7) — before a request is written.
//!
//! Steps 1–4 share the connect timeout; step 5 is bounded by the revocation
//! fetch's own timeouts (3 s connect, 10 s request). Every failure is
//! [`NotWritten`]: nothing reached the peer.

use crate::core::{AsxError, ErrorCode, ErrorContext};
use crate::http_client::NotWritten;
use crate::transport::egress::is_private_ip;
use crate::transport::tls::TlsPolicy;
use hyper_util::client::legacy::connect::{Connected, Connection};
use openssl::ssl::SslConnector;
use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, OnceLock, Weak};
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio_openssl::SslStream;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Operator pins: lowercased host → the socket address every connection to
/// it uses.
pub(crate) type Pins = Arc<HashMap<String, SocketAddr>>;

/// The revocation validator the BDEW connector consults; set after the
/// client is built (the validator holds the client, so this is weak).
pub(crate) type RevocationHook = Arc<OnceLock<Weak<crate::revocation::Revocation>>>;

/// A connector for one pool.
#[derive(Clone)]
pub(crate) struct Connector {
    inner: Arc<Inner>,
}

struct Inner {
    tls: SslConnector,
    policy: TlsPolicy,
    pins: Pins,
    /// Plain `http` allowed (revocation fetches only: CRLs and OCSP
    /// responses are signed, RFC 5280 §4.2.1.13).
    allow_http: bool,
    connect_timeout: Duration,
    /// `Some` for the message pool under BDEW.
    revocation: Option<RevocationHook>,
    stage: &'static str,
}

impl std::fmt::Debug for Connector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Connector")
            .field("policy", &self.inner.policy)
            .field("pins", &self.inner.pins)
            .field("allow_http", &self.inner.allow_http)
            .finish_non_exhaustive()
    }
}

impl Connector {
    pub(crate) fn new(
        tls: SslConnector,
        policy: TlsPolicy,
        pins: Pins,
        allow_http: bool,
        connect_timeout: Duration,
        revocation: Option<RevocationHook>,
        stage: &'static str,
    ) -> Self {
        Self {
            inner: Arc::new(Inner {
                tls,
                policy,
                pins,
                allow_http,
                connect_timeout,
                revocation,
                stage,
            }),
        }
    }
}

fn refuse(code: ErrorCode, detail: impl Into<String>, stage: &'static str) -> BoxError {
    Box::new(NotWritten(AsxError::new(
        code,
        detail.into(),
        ErrorContext::new(stage),
    )))
}

impl tower_service::Service<http::Uri> for Connector {
    type Response = hyper_util::rt::TokioIo<Stream>;
    type Error = BoxError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, BoxError>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, uri: http::Uri) -> Self::Future {
        let inner = self.inner.clone();
        Box::pin(async move {
            let stage = inner.stage;
            let timeout = inner.connect_timeout;
            let stream = match tokio::time::timeout(timeout, connect(&inner, &uri)).await {
                Ok(result) => result?,
                Err(_) => {
                    return Err(refuse(
                        ErrorCode::TransportFailure,
                        format!(
                            "connecting to {uri} (TCP and TLS) did not complete within {} s",
                            timeout.as_secs()
                        ),
                        stage,
                    ));
                }
            };
            if let (Stream::Tls(tls), Some(hook)) = (&stream, &inner.revocation) {
                check_server_chain(hook, tls, stage).await?;
            }
            Ok(hyper_util::rt::TokioIo::new(stream))
        })
    }
}

/// The host of `uri` without IPv6 brackets.
fn bare_host(uri: &http::Uri) -> Option<&str> {
    uri.host()
        .map(|h| h.trim_start_matches('[').trim_end_matches(']'))
        .filter(|h| !h.is_empty())
}

async fn connect(inner: &Inner, uri: &http::Uri) -> Result<Stream, BoxError> {
    let stage = inner.stage;
    let tls = match uri.scheme_str() {
        Some("https") => true,
        Some("http") if inner.allow_http => false,
        Some("http") => {
            return Err(refuse(
                ErrorCode::PolicyViolation,
                "plain HTTP egress is not permitted; use HTTPS for all outbound transport",
                stage,
            ));
        }
        other => {
            return Err(refuse(
                ErrorCode::InvalidInput,
                format!(
                    "egress URL scheme {other:?} is not allowed; only http and https are permitted"
                ),
                stage,
            ));
        }
    };
    let Some(host) = bare_host(uri) else {
        return Err(refuse(
            ErrorCode::InvalidInput,
            format!("egress URL {uri} has no host"),
            stage,
        ));
    };
    let port = uri.port_u16().unwrap_or(if tls { 443 } else { 80 });

    let addrs = resolve(inner, host, port).await?;
    let tcp = connect_tcp(&addrs, stage).await?;
    if !tls {
        return Ok(Stream::Plain(tcp));
    }
    let stream = handshake(inner, host, tcp).await?;
    Ok(Stream::Tls(Box::new(stream)))
}

/// The addresses to connect to: the pin, the literal, or DNS — every one
/// checked against the private-address filter unless pinned.
async fn resolve(inner: &Inner, host: &str, port: u16) -> Result<Vec<SocketAddr>, BoxError> {
    let stage = inner.stage;
    if let Some(pinned) = inner.pins.get(&host.to_ascii_lowercase()) {
        return Ok(vec![*pinned]);
    }
    let private = |ip: IpAddr| {
        refuse(
            ErrorCode::InvalidInput,
            format!(
                "egress URL host '{host}' is or resolves to a private or loopback address ({ip}); \
                 outbound requests to internal networks are not permitted"
            ),
            stage,
        )
    };
    if let Ok(ip) = host.parse::<IpAddr>() {
        if is_private_ip(ip) {
            return Err(private(ip));
        }
        return Ok(vec![SocketAddr::new(ip, port)]);
    }
    if crate::transport::egress::is_private_host(host) {
        return Err(refuse(
            ErrorCode::InvalidInput,
            format!(
                "egress URL host '{host}' is a private or loopback address; \
                 outbound requests to internal networks are not permitted"
            ),
            stage,
        ));
    }
    let resolved: Vec<SocketAddr> = tokio::net::lookup_host((host, port))
        .await
        .map_err(|e| {
            refuse(
                ErrorCode::InvalidInput,
                format!("egress URL host '{host}' could not be resolved: {e}"),
                stage,
            )
        })?
        .collect();
    // Every answer is checked, not just the one connected to: a mixed
    // answer is a rebinding attempt.
    if let Some(bad) = resolved.iter().find(|a| is_private_ip(a.ip())) {
        return Err(private(bad.ip()));
    }
    if resolved.is_empty() {
        return Err(refuse(
            ErrorCode::InvalidInput,
            format!("egress URL host '{host}' resolved to no usable addresses"),
            stage,
        ));
    }
    Ok(resolved)
}

async fn connect_tcp(addrs: &[SocketAddr], stage: &'static str) -> Result<TcpStream, BoxError> {
    let mut last = None;
    for addr in addrs {
        match TcpStream::connect(addr).await {
            Ok(tcp) => {
                let _ = tcp.set_nodelay(true);
                return Ok(tcp);
            }
            Err(err) => last = Some((addr, err)),
        }
    }
    let detail = match last {
        Some((addr, err)) => format!("TCP connect to {addr} failed: {err}"),
        None => "no address to connect to".to_string(),
    };
    Err(refuse(ErrorCode::TransportFailure, detail, stage))
}

async fn handshake(
    inner: &Inner,
    host: &str,
    tcp: TcpStream,
) -> Result<SslStream<TcpStream>, BoxError> {
    let stage = inner.stage;
    let tls_err = |detail: String| refuse(ErrorCode::TransportFailure, detail, stage);
    let mut config = inner
        .tls
        .configure()
        .map_err(|e| tls_err(format!("TLS setup failed: {e}")))?;
    config
        .param_mut()
        .set_hostflags(inner.policy.hostname_flags());
    // `into_ssl` sends SNI for a DNS name (never for an IP literal, RFC 6066
    // §3) and verifies the certificate against the host name or IP.
    let ssl = config
        .into_ssl(host)
        .map_err(|e| tls_err(format!("TLS setup for {host} failed: {e}")))?;
    let mut stream =
        SslStream::new(ssl, tcp).map_err(|e| tls_err(format!("TLS setup failed: {e}")))?;
    if let Err(err) = Pin::new(&mut stream).connect().await {
        let verify = stream.ssl().verify_result();
        let detail = if verify == openssl::x509::X509VerifyResult::OK {
            format!("TLS handshake with {host} failed: {err}")
        } else {
            format!(
                "TLS handshake with {host} failed: the server certificate is not trusted ({})",
                verify.error_string()
            )
        };
        return Err(tls_err(detail));
    }
    Ok(stream)
}

/// BDEW Kap. 2.3.7: an SM-PKI certificate is trusted after its signature *and
/// its revocation status* are validated. Runs once per connection, before
/// the first request is written on it.
async fn check_server_chain(
    hook: &RevocationHook,
    stream: &SslStream<TcpStream>,
    stage: &'static str,
) -> Result<(), BoxError> {
    let Some(revocation) = hook.get().and_then(Weak::upgrade) else {
        return Err(refuse(
            ErrorCode::TransportFailure,
            "no revocation validator for the TLS server chain (the client is shutting down)",
            stage,
        ));
    };
    let path: Vec<openssl::x509::X509> = stream
        .ssl()
        .verified_chain()
        .map(|chain| chain.iter().map(|c| c.to_owned()).collect())
        .unwrap_or_default();
    let outcome = revocation.check(&path).await;
    if outcome.refused() {
        return Err(refuse(
            ErrorCode::TransportFailure,
            format!(
                "the TLS server certificate is refused: {}",
                outcome.describe()
            ),
            stage,
        ));
    }
    Ok(())
}

/// A connection: plain TCP (revocation fetches) or TLS.
#[derive(Debug)]
pub(crate) enum Stream {
    Plain(TcpStream),
    Tls(Box<SslStream<TcpStream>>),
}

impl Stream {
    /// The TLS session, when there is one.
    #[cfg(test)]
    pub(crate) fn ssl(&self) -> Option<&openssl::ssl::SslRef> {
        match self {
            Stream::Plain(_) => None,
            Stream::Tls(tls) => Some(tls.ssl()),
        }
    }
}

impl Connection for Stream {
    fn connected(&self) -> Connected {
        match self {
            Stream::Tls(tls) if tls.ssl().selected_alpn_protocol() == Some(b"h2") => {
                Connected::new().negotiated_h2()
            }
            _ => Connected::new(),
        }
    }
}

impl AsyncRead for Stream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Stream::Plain(s) => Pin::new(s).poll_read(cx, buf),
            Stream::Tls(s) => Pin::new(s.as_mut()).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for Stream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Stream::Plain(s) => Pin::new(s).poll_write(cx, buf),
            Stream::Tls(s) => Pin::new(s.as_mut()).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Stream::Plain(s) => Pin::new(s).poll_flush(cx),
            Stream::Tls(s) => Pin::new(s.as_mut()).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Stream::Plain(s) => Pin::new(s).poll_shutdown(cx),
            Stream::Tls(s) => Pin::new(s.as_mut()).poll_shutdown(cx),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tower_service::Service;

    fn connector(pins: &[(&str, SocketAddr)]) -> Connector {
        let policy = TlsPolicy::Platform;
        let tls = crate::transport::tls::connector(&policy, None, false).expect("tls");
        Connector::new(
            tls,
            policy,
            Arc::new(pins.iter().map(|(h, a)| (h.to_string(), *a)).collect()),
            true,
            Duration::from_secs(2),
            None,
            "test",
        )
    }

    fn not_written(err: &BoxError) -> String {
        err.downcast_ref::<NotWritten>()
            .map(|n| n.0.to_string())
            .expect("NotWritten")
    }

    #[tokio::test]
    async fn an_unpinned_loopback_host_is_refused() {
        let mut c = connector(&[]);
        for url in [
            "http://127.0.0.1:9/x",
            "http://localhost:9/x",
            "http://[::1]:9/x",
            "http://10.0.0.1/x",
        ] {
            let err = c.call(url.parse().unwrap()).await.expect_err(url);
            assert!(not_written(&err).contains("private or loopback"), "{url}");
        }
    }

    #[tokio::test]
    async fn a_pinned_host_reaches_its_address_and_nothing_else_does() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let mut c = connector(&[("msh.test", addr)]);
        let stream = c
            .call("http://MSH.test/x".parse().unwrap())
            .await
            .expect("pinned host connects");
        assert!(stream.inner().ssl().is_none());
        // The pin is exact: the same address under another name is refused.
        let err = c
            .call(format!("http://{addr}/x").parse().unwrap())
            .await
            .expect_err("unpinned literal");
        assert!(not_written(&err).contains("private or loopback"));
    }

    #[tokio::test]
    async fn plain_http_is_refused_unless_allowed() {
        let policy = TlsPolicy::Platform;
        let tls = crate::transport::tls::connector(&policy, None, false).expect("tls");
        let mut c = Connector::new(
            tls,
            policy,
            Arc::default(),
            false,
            Duration::from_secs(1),
            None,
            "test",
        );
        let err = c
            .call("http://example.org/".parse().unwrap())
            .await
            .expect_err("http");
        assert!(not_written(&err).contains("plain HTTP"));
    }

    #[tokio::test]
    async fn a_stalled_handshake_times_out_not_written() {
        // Accepts TCP, never answers the ClientHello.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let _hold = tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((s, _)) = listener.accept().await {
                held.push(s);
            }
        });
        let policy = TlsPolicy::Platform;
        let tls = crate::transport::tls::connector(&policy, None, true).expect("tls");
        let mut c = Connector::new(
            tls,
            policy,
            Arc::new(HashMap::from([("stall.test".to_string(), addr)])),
            false,
            Duration::from_millis(300),
            None,
            "test",
        );
        let started = tokio::time::Instant::now();
        let err = c
            .call("https://stall.test/".parse().unwrap())
            .await
            .expect_err("stalled");
        assert!(not_written(&err).contains("did not complete"));
        assert!(started.elapsed() < Duration::from_secs(2));
    }
}
