//! The one-method HTTP seam and the built-in client (feature
//! `http-client`): OpenSSL TLS under the profile's policy (BSI TR-03116-3
//! with Brainpool under BDEW), SNI, pooled connections, the private-address
//! filter on every connection, the mTLS identity from
//! `LocalParty::tls_identity`, a 10 s connect (TCP and TLS) and a 300 s
//! request timeout. A revocation fetch (marked by the crate-private
//! [`crate::revocation::RevocationFetch`]) may be plain `http`, presents no
//! identity, times out at 3 s / 10 s and reads at most its cap.

use crate::error::{BoxError, BoxFuture, Error, ErrorKind, Stage};

/// An HTTP exchange. The built-in implementation (feature `http-client`) is
/// HTTPS-only for messages, built on OpenSSL with connection pooling, sends
/// SNI, refuses private addresses unless pinned with `Builder::resolve`,
/// presents `LocalParty::tls_identity`, and under `Profile::bdew()` speaks
/// BSI TR-03116-3 (Brainpool), trusts only the builder's trust anchors (the
/// SM-PKI root) and checks the server chain's revocation status before
/// writing a request. An error of an embedder-supplied client is
/// classified [`ErrorKind::Indeterminate`]: the request may have been
/// written, and every target profile requires receiver duplicate detection,
/// so resending is safe.
///
/// The client also carries revocation fetches: a `GET` of a CRL
/// distribution point and a `POST` of an `application/ocsp-request`, both
/// to URLs taken from a verified, authorized partner certificate and
/// possibly plain `http` (CRLs and OCSP responses are signed; RFC 5280
/// §4.2.1.13). Their responses are refused above 10 MiB (CRL) and 64 KiB
/// (OCSP) whatever the client returns.
pub trait HttpClient: Send + Sync + std::fmt::Debug + 'static {
    /// Perform one exchange. A message URL was already validated as HTTPS.
    fn send(
        &self,
        request: http::Request<bytes::Bytes>,
    ) -> BoxFuture<
        '_,
        std::result::Result<http::Response<bytes::Bytes>, Box<dyn std::error::Error + Send + Sync>>,
    >;
}

/// The request was not written: connect, DNS, TLS or the address pin failed.
#[derive(Debug)]
#[cfg_attr(not(feature = "http-client"), allow(dead_code))]
pub(crate) struct NotWritten(pub(crate) crate::core::AsxError);

impl std::fmt::Display for NotWritten {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl std::error::Error for NotWritten {}

/// The request may have been written: timeout, reset, unreadable response.
#[derive(Debug)]
#[cfg_attr(not(feature = "http-client"), allow(dead_code))]
pub(crate) struct Written(pub(crate) crate::core::AsxError);

impl std::fmt::Display for Written {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl std::error::Error for Written {}

/// Classify an `HttpClient` error.
#[cfg_attr(not(any(feature = "as2", feature = "as4")), allow(dead_code))]
pub(crate) fn classify(err: BoxError) -> Error {
    let err = match err.downcast::<NotWritten>() {
        Ok(not_written) => return Error::from_internal(Stage::HttpNotWritten, not_written.0),
        Err(other) => other,
    };
    match err.downcast::<Written>() {
        Ok(written) => Error::from_internal(Stage::HttpAfterWrite, written.0),
        Err(other) => Error::new(
            ErrorKind::Indeterminate,
            format!("the HTTP client failed: {other}"),
        )
        .with_source(other),
    }
}

/// The largest response the built-in client reads (a receipt, an MDN or an
/// error signal; never a payload).
#[cfg(feature = "http-client")]
const MAX_RESPONSE_BYTES: usize = 16 * 1024 * 1024;

#[cfg(feature = "http-client")]
type Pool = hyper_util::client::legacy::Client<
    crate::transport::connector::Connector,
    http_body_util::Full<bytes::Bytes>,
>;

/// The built-in client (D92): two pooled hyper clients over the crate's
/// connector — one for messages (HTTPS only, the client identity, the
/// profile's TLS policy, under BDEW the server-chain revocation check) and
/// one for revocation fetches (HTTP or HTTPS, no identity, platform roots).
/// Both share the operator's pins. Cheap to clone; clones share the pools.
#[cfg(feature = "http-client")]
#[derive(Clone)]
pub(crate) struct BuiltinClient {
    messages: Pool,
    revocation: Pool,
    hook: crate::transport::connector::RevocationHook,
    pins: crate::transport::connector::Pins,
    policy: crate::transport::tls::TlsPolicy,
}

#[cfg(feature = "http-client")]
impl std::fmt::Debug for BuiltinClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BuiltinClient")
            .field("policy", &self.policy)
            .field("pins", &self.pins)
            .finish_non_exhaustive()
    }
}

#[cfg(feature = "http-client")]
impl BuiltinClient {
    /// Build both pools. The TLS identity is loaded into the TLS context
    /// here, so an unusable key fails `build()` instead of the first send.
    ///
    /// # Errors
    ///
    /// A description of what the TLS context refused.
    pub(crate) fn new(
        policy: crate::transport::tls::TlsPolicy,
        identity: Option<&crate::keys::KeyPair>,
        pins: crate::transport::connector::Pins,
    ) -> std::result::Result<Self, String> {
        use crate::transport::connector::Connector;
        use crate::transport::tls::{TlsPolicy, connector};
        use std::time::Duration;
        let hook: crate::transport::connector::RevocationHook = std::sync::Arc::default();
        let message_tls = connector(&policy, identity, true)?;
        let messages = Connector::new(
            message_tls,
            policy.clone(),
            pins.clone(),
            false,
            Duration::from_secs(10),
            policy.is_bdew().then(|| hook.clone()),
            "http_client",
        );
        // CDPs and responders are third parties: no client certificate
        // (CP SM-PKI §2.4: CRL access is anonymous), the platform's roots for
        // an https CDP (the CRL itself is signed), HTTP/1.1.
        let revocation_tls = connector(&TlsPolicy::Platform, None, false)?;
        let revocation = Connector::new(
            revocation_tls,
            TlsPolicy::Platform,
            pins.clone(),
            true,
            Duration::from_secs(3),
            None,
            "revocation_fetch",
        );
        let pool = |connector: Connector| -> Pool {
            hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
                .pool_timer(hyper_util::rt::TokioTimer::new())
                .pool_idle_timeout(Duration::from_secs(90))
                .pool_max_idle_per_host(4)
                .build(connector)
        };
        Ok(Self {
            messages: pool(messages),
            revocation: pool(revocation),
            hook,
            pins,
            policy,
        })
    }

    /// Wire the client's revocation validator into the BDEW server-chain
    /// check (it holds this client, hence weak).
    pub(crate) fn set_revocation(
        &self,
        revocation: std::sync::Weak<crate::revocation::Revocation>,
    ) {
        let _ = self.hook.set(revocation);
    }

    async fn exchange(
        &self,
        request: http::Request<bytes::Bytes>,
    ) -> std::result::Result<http::Response<bytes::Bytes>, BoxError> {
        use crate::core::{AsxError, ErrorCode, ErrorContext};
        use std::time::Duration;
        let (pool, stage, timeout, cap) = match request
            .extensions()
            .get::<crate::revocation::RevocationFetch>()
            .copied()
        {
            Some(fetch) => (
                &self.revocation,
                "revocation_fetch",
                Duration::from_secs(10),
                fetch.max_bytes,
            ),
            None => (
                &self.messages,
                "http_client",
                Duration::from_secs(300),
                MAX_RESPONSE_BYTES,
            ),
        };
        let mut request = request.map(http_body_util::Full::new);
        request.headers_mut().insert(
            http::header::USER_AGENT,
            http::HeaderValue::from_static(concat!("asx/", env!("CARGO_PKG_VERSION"))),
        );
        let url = request.uri().to_string();
        let exchange = async {
            let response = pool.request(request).await.map_err(|err| {
                // The connector's refusals arrive wrapped: unwrap them so the
                // caller sees what was refused and that nothing was written.
                if let Some(not_written) = find::<NotWritten>(&err) {
                    return Box::new(NotWritten(not_written.0.clone())) as BoxError;
                }
                let internal = AsxError::new(
                    ErrorCode::TransportFailure,
                    format!("HTTP request to {url} failed: {}", flatten(&err)),
                    ErrorContext::new(stage),
                );
                if err.is_connect() {
                    Box::new(NotWritten(internal))
                } else {
                    Box::new(Written(internal))
                }
            })?;
            let (parts, body) = response.into_parts();
            let mut out = http::Response::builder().status(parts.status);
            for (name, value) in &parts.headers {
                out = out.header(name, value);
            }
            let body = crate::transport::egress::read_body_capped(
                http::Response::from_parts(parts, body),
                cap,
                stage,
            )
            .await
            .map_err(|e| Box::new(Written(e)) as BoxError)?;
            out.body(body).map_err(|err| {
                Box::new(Written(AsxError::new(
                    ErrorCode::ParseFailed,
                    format!("unrepresentable HTTP response: {err}"),
                    ErrorContext::new(stage),
                ))) as BoxError
            })
        };
        // The connect timeout is the connector's (not written); past it the
        // request may have been written.
        match tokio::time::timeout(timeout, exchange).await {
            Ok(result) => result,
            Err(_) => Err(Box::new(Written(AsxError::new(
                ErrorCode::TransportFailure,
                format!(
                    "HTTP exchange with {url} did not complete within {} s",
                    timeout.as_secs()
                ),
                ErrorContext::new(stage),
            )))),
        }
    }
}

/// The first error of type `T` in `err`'s source chain.
#[cfg(feature = "http-client")]
fn find<'a, T: std::error::Error + 'static>(
    err: &'a (dyn std::error::Error + 'static),
) -> Option<&'a T> {
    let mut current = Some(err);
    while let Some(e) = current {
        if let Some(found) = e.downcast_ref::<T>() {
            return Some(found);
        }
        current = e.source();
    }
    None
}

#[cfg(feature = "http-client")]
fn flatten(err: &(dyn std::error::Error + 'static)) -> String {
    let mut message = err.to_string();
    let mut source = err.source();
    while let Some(cause) = source {
        message.push_str(": ");
        message.push_str(&cause.to_string());
        source = cause.source();
    }
    message
}

#[cfg(feature = "http-client")]
impl HttpClient for BuiltinClient {
    fn send(
        &self,
        request: http::Request<bytes::Bytes>,
    ) -> BoxFuture<'_, std::result::Result<http::Response<bytes::Bytes>, BoxError>> {
        Box::pin(self.exchange(request))
    }
}

#[cfg(all(test, feature = "http-client"))]
mod tests {
    use super::*;

    fn builtin(pins: &[(&str, std::net::SocketAddr)]) -> BuiltinClient {
        BuiltinClient::new(
            crate::transport::tls::TlsPolicy::Platform,
            None,
            Arc::new(pins.iter().map(|(h, a)| (h.to_string(), *a)).collect()),
        )
        .expect("client")
    }

    #[tokio::test]
    async fn plain_http_is_refused_before_writing() {
        let client = builtin(&[]);
        let err = client
            .send(
                http::Request::post("http://example.org/as4")
                    .body(bytes::Bytes::new())
                    .unwrap(),
            )
            .await
            .unwrap_err();
        assert_eq!(classify(err).kind(), ErrorKind::Transport);
    }

    #[tokio::test]
    async fn private_address_is_refused_before_writing() {
        let client = builtin(&[]);
        let err = client
            .send(
                http::Request::post("https://127.0.0.1:1/as4")
                    .body(bytes::Bytes::new())
                    .unwrap(),
            )
            .await
            .unwrap_err();
        let err = classify(err);
        assert_eq!(err.kind(), ErrorKind::Transport);
        assert!(!err.is_retryable());
    }

    // ── revocation fetches ───────────────────────────────────────────────────

    use crate::revocation::RevocationFetch;
    use std::sync::Arc;

    fn revocation_get(url: &str, max_bytes: usize) -> http::Request<bytes::Bytes> {
        let mut request = http::Request::get(url).body(bytes::Bytes::new()).unwrap();
        request
            .extensions_mut()
            .insert(RevocationFetch { max_bytes });
        request
    }

    /// A recording HTTP/1.1 server: answers every request with `response`
    /// and counts requests by path.
    async fn recording_server(
        response: &'static [u8],
    ) -> (std::net::SocketAddr, Arc<std::sync::Mutex<Vec<String>>>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
        let record = seen.clone();
        tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                let mut buf = vec![0u8; 4096];
                let n = socket.read(&mut buf).await.unwrap_or(0);
                let head = String::from_utf8_lossy(&buf[..n]).to_string();
                let path = head.split_whitespace().nth(1).unwrap_or("").to_string();
                record.lock().unwrap().push(path);
                let _ = socket.write_all(response).await;
                let _ = socket.shutdown().await;
            }
        });
        (addr, seen)
    }

    fn recorded(addr: std::net::SocketAddr) -> BuiltinClient {
        builtin(&[("crl.example", addr), ("ocsp.example", addr)])
    }

    #[tokio::test]
    async fn revocation_fetch_to_a_private_address_makes_no_connection() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let port = listener.local_addr().unwrap().port();
        let client = builtin(&[]);
        for url in [
            format!("http://127.0.0.1:{port}/root.crl"),
            format!("http://localhost:{port}/root.crl"),
            "http://169.254.169.254/latest/meta-data/".to_string(),
            "http://10.0.0.5/ca.crl".to_string(),
            "http://[::1]/ca.crl".to_string(),
        ] {
            let err = client.send(revocation_get(&url, 1024)).await.unwrap_err();
            assert!(err.downcast_ref::<NotWritten>().is_some(), "{url}: {err}");
        }
        assert!(listener.accept().is_err(), "nothing connected");
    }

    #[tokio::test]
    async fn revocation_fetch_with_another_scheme_is_refused() {
        let client = builtin(&[]);
        for url in [
            "ldap://dir.example/cn=ca",
            "gopher://x.example/",
            "ftp://x.example/ca.crl",
        ] {
            let err = client.send(revocation_get(url, 1024)).await.unwrap_err();
            assert!(err.downcast_ref::<NotWritten>().is_some(), "{url}: {err}");
        }
    }

    #[tokio::test]
    async fn revocation_may_use_plain_http_messages_may_not() {
        let client = builtin(&[]);
        let err = client
            .send(revocation_get(
                "http://crl.invalid-tld-for-tests./ca.crl",
                1024,
            ))
            .await
            .unwrap_err();
        assert!(
            !err.to_string()
                .contains("plain HTTP egress is not permitted"),
            "plain http passes the scheme rule for revocation: {err}"
        );
        // The same URL as a message request is refused for its scheme.
        let err = client
            .send(
                http::Request::get("http://crl.invalid-tld-for-tests./ca.crl")
                    .body(bytes::Bytes::new())
                    .unwrap(),
            )
            .await
            .unwrap_err();
        assert!(err.to_string().contains("plain HTTP"), "{err}");
    }

    #[tokio::test]
    async fn revocation_redirect_is_not_followed() {
        let (addr, seen) = recording_server(
            b"HTTP/1.1 302 Found\r\nLocation: http://crl.example/elsewhere.crl\r\nContent-Length: 0\r\n\r\n",
        )
        .await;
        let response = recorded(addr)
            .send(revocation_get("http://crl.example/root.crl", 1024))
            .await
            .unwrap();
        assert_eq!(response.status().as_u16(), 302);
        assert_eq!(seen.lock().unwrap().as_slice(), ["/root.crl"]);
    }

    #[tokio::test]
    async fn revocation_body_over_the_cap_is_not_read() {
        static BIG: std::sync::OnceLock<Vec<u8>> = std::sync::OnceLock::new();
        let big = BIG.get_or_init(|| {
            let mut r = b"HTTP/1.1 200 OK\r\nContent-Length: 70000\r\n\r\n".to_vec();
            r.extend(vec![0x30; 70_000]);
            r
        });
        let (addr, _) = recording_server(big).await;
        let err = recorded(addr)
            .send(revocation_get("http://ocsp.example/", 64 * 1024))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("exceeds"), "{err}");
        let ok = recorded(addr)
            .send(revocation_get(
                "http://crl.example/big.crl",
                10 * 1024 * 1024,
            ))
            .await
            .unwrap();
        assert_eq!(ok.body().len(), 70_000);
    }

    #[tokio::test]
    async fn a_chunked_body_past_the_cap_is_refused() {
        static CHUNKED: std::sync::OnceLock<Vec<u8>> = std::sync::OnceLock::new();
        let chunked = CHUNKED.get_or_init(|| {
            let mut r = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
            for _ in 0..16 {
                r.extend_from_slice(b"100\r\n");
                r.extend(vec![b'b'; 256]);
                r.extend_from_slice(b"\r\n");
            }
            r.extend_from_slice(b"0\r\n\r\n");
            r
        });
        let (addr, _) = recording_server(chunked).await;
        let err = recorded(addr)
            .send(revocation_get("http://crl.example/chunked.crl", 1024))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("exceeds"), "{err}");
    }

    #[test]
    fn custom_client_errors_are_indeterminate() {
        let err = classify("socket closed".into());
        assert_eq!(err.kind(), ErrorKind::Indeterminate);
        assert!(err.is_retryable());
    }

    #[test]
    fn not_written_is_transport_and_written_is_indeterminate() {
        use crate::core::{AsxError, ErrorCode, ErrorContext};
        let refused = NotWritten(AsxError::new(
            ErrorCode::TransportFailure,
            "connection refused",
            ErrorContext::new("t"),
        ));
        assert_eq!(classify(Box::new(refused)).kind(), ErrorKind::Transport);
        let stalled = Written(AsxError::new(
            ErrorCode::TransportFailure,
            "timed out",
            ErrorContext::new("t"),
        ));
        assert_eq!(classify(Box::new(stalled)).kind(), ErrorKind::Indeterminate);
    }
}
