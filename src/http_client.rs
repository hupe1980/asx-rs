//! The one-method HTTP seam and the built-in client (feature
//! `http-client`): HTTPS only, resolved addresses pinned, the mTLS
//! identity from `LocalParty::tls_identity`, a 10 s connect and a 300 s
//! request timeout. A revocation fetch (marked by the
//! crate-private [`crate::revocation::RevocationFetch`]) may be plain
//! `http`, presents no identity, times out at 3 s / 10 s and reads at most
//! its cap.

use crate::error::{BoxError, BoxFuture, Error, ErrorKind, Stage};

/// An HTTP exchange. The built-in implementation (feature `http-client`) is
/// HTTPS-only for messages, pins resolved addresses and presents
/// `LocalParty::tls_identity`. An error of an embedder-supplied client is
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

/// The built-in client.
#[cfg(all(feature = "http-client", any(feature = "as2", feature = "as4")))]
#[derive(Debug, Clone, Default)]
pub(crate) struct BuiltinClient {
    identity: Option<crate::transport::egress::ClientIdentity>,
    /// Unit tests only: connect revocation fetches to this local address
    /// instead of resolving (the recording server of the revocation tests).
    #[cfg(test)]
    test_resolve: Option<std::net::SocketAddr>,
}

#[cfg(all(feature = "http-client", any(feature = "as2", feature = "as4")))]
impl BuiltinClient {
    pub(crate) fn new(tls: Option<&crate::keys::KeyPair>) -> crate::error::Result<Self> {
        let identity = match tls {
            Some(pair) => Some(
                crate::transport::egress::ClientIdentity::from_pem(
                    pair.chain_pem(),
                    pair.key_pem(),
                )
                .map_err(Error::internal)?,
            ),
            None => None,
        };
        Ok(Self {
            identity,
            #[cfg(test)]
            test_resolve: None,
        })
    }

    /// A revocation fetch: `http` or `https`, the egress
    /// address filter and pinning, no redirects, no client identity, 3 s
    /// connect and 10 s request timeouts, at most `max_bytes` read.
    async fn revocation(
        &self,
        request: http::Request<bytes::Bytes>,
        max_bytes: usize,
    ) -> std::result::Result<http::Response<bytes::Bytes>, BoxError> {
        use crate::core::{AsxError, ErrorCode, ErrorContext};
        const STAGE: &str = "revocation_fetch";
        let config = crate::transport::egress::TransportConfig {
            connect_timeout: std::time::Duration::from_secs(3),
            request_timeout: std::time::Duration::from_secs(10),
            client_identity: None,
            ..crate::transport::egress::TransportConfig::default()
        };
        let url = request.uri().to_string();
        #[cfg(test)]
        let client = match self.test_resolve {
            Some(addr) => reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .resolve_to_addrs(request.uri().host().unwrap_or_default(), &[addr])
                .build()
                .map_err(|e| {
                    NotWritten(AsxError::new(
                        ErrorCode::TransportFailure,
                        e.to_string(),
                        ErrorContext::new(STAGE),
                    ))
                })?,
            None => {
                crate::transport::egress::validated_pinned_revocation_client(&url, &config, STAGE)
                    .await
                    .map_err(NotWritten)?
            }
        };
        #[cfg(not(test))]
        let client =
            crate::transport::egress::validated_pinned_revocation_client(&url, &config, STAGE)
                .await
                .map_err(NotWritten)?;
        let (parts, body) = request.into_parts();
        let method = match parts.method {
            http::Method::GET => reqwest::Method::GET,
            http::Method::POST => reqwest::Method::POST,
            _ => {
                return Err(Box::new(NotWritten(AsxError::new(
                    ErrorCode::InvalidInput,
                    "a revocation fetch is a GET or a POST",
                    ErrorContext::new(STAGE),
                ))));
            }
        };
        let mut builder = client.request(method, &url);
        for (name, value) in &parts.headers {
            builder = builder.header(name.as_str(), value.as_bytes());
        }
        let response = builder.body(body).send().await.map_err(|err| -> BoxError {
            Box::new(Written(AsxError::new(
                ErrorCode::TransportFailure,
                format!("revocation fetch failed: {}", flatten(&err)),
                ErrorContext::new(STAGE),
            )))
        })?;
        let status = response.status().as_u16();
        let body = crate::transport::egress::read_body_capped(response, max_bytes, STAGE)
            .await
            .map_err(Written)?;
        http::Response::builder()
            .status(status)
            .body(body)
            .map_err(|err| {
                Box::new(Written(AsxError::new(
                    ErrorCode::ParseFailed,
                    format!("unrepresentable HTTP response: {err}"),
                    ErrorContext::new(STAGE),
                ))) as BoxError
            })
    }

    async fn exchange(
        &self,
        request: http::Request<bytes::Bytes>,
    ) -> std::result::Result<http::Response<bytes::Bytes>, BoxError> {
        use crate::core::{AsxError, ErrorCode, ErrorContext};
        const STAGE: &str = "http_client";
        if let Some(fetch) = request
            .extensions()
            .get::<crate::revocation::RevocationFetch>()
            .copied()
        {
            return self.revocation(request, fetch.max_bytes).await;
        }
        let config = crate::transport::egress::TransportConfig {
            connect_timeout: std::time::Duration::from_secs(10),
            request_timeout: std::time::Duration::from_secs(300),
            client_identity: self.identity.clone(),
            ..crate::transport::egress::TransportConfig::default()
        };
        let url = request.uri().to_string();
        let client = crate::transport::egress::validated_pinned_client(&url, &config, STAGE)
            .await
            .map_err(NotWritten)?;
        let (parts, body) = request.into_parts();
        let method =
            reqwest::Method::from_bytes(parts.method.as_str().as_bytes()).map_err(|_| {
                NotWritten(AsxError::new(
                    ErrorCode::InvalidInput,
                    "bad method",
                    ErrorContext::new(STAGE),
                ))
            })?;
        let mut builder = client.request(method, &url);
        for (name, value) in &parts.headers {
            builder = builder.header(name.as_str(), value.as_bytes());
        }
        let response = builder.body(body).send().await.map_err(|err| -> BoxError {
            let internal = AsxError::new(
                ErrorCode::TransportFailure,
                format!("HTTP request failed: {}", flatten(&err)),
                ErrorContext::new(STAGE),
            );
            if err.is_connect() || err.is_builder() {
                Box::new(NotWritten(internal))
            } else {
                Box::new(Written(internal))
            }
        })?;
        let status = response.status().as_u16();
        let mut out = http::Response::builder().status(status);
        for (name, value) in response.headers() {
            out = out.header(name.as_str(), value.as_bytes());
        }
        let body = crate::transport::egress::read_body_capped(response, MAX_RESPONSE_BYTES, STAGE)
            .await
            .map_err(Written)?;
        out.body(body).map_err(|err| {
            Box::new(Written(AsxError::new(
                ErrorCode::ParseFailed,
                format!("unrepresentable HTTP response: {err}"),
                ErrorContext::new(STAGE),
            ))) as BoxError
        })
    }
}

#[cfg(all(feature = "http-client", any(feature = "as2", feature = "as4")))]
fn flatten(err: &reqwest::Error) -> String {
    let mut message = err.to_string();
    let mut source = std::error::Error::source(err);
    while let Some(cause) = source {
        message.push_str(": ");
        message.push_str(&cause.to_string());
        source = cause.source();
    }
    message
}

#[cfg(all(feature = "http-client", any(feature = "as2", feature = "as4")))]
impl HttpClient for BuiltinClient {
    fn send(
        &self,
        request: http::Request<bytes::Bytes>,
    ) -> BoxFuture<'_, std::result::Result<http::Response<bytes::Bytes>, BoxError>> {
        Box::pin(self.exchange(request))
    }
}

#[cfg(all(test, feature = "http-client", any(feature = "as2", feature = "as4")))]
mod tests {
    use super::*;

    #[tokio::test]
    async fn plain_http_is_refused_before_writing() {
        let client = BuiltinClient::default();
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
        let client = BuiltinClient::default();
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
        BuiltinClient {
            test_resolve: Some(addr),
            ..BuiltinClient::default()
        }
    }

    #[tokio::test]
    async fn revocation_fetch_to_a_private_address_makes_no_connection() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let port = listener.local_addr().unwrap().port();
        let client = BuiltinClient::default();
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
        let client = BuiltinClient::default();
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
        let client = BuiltinClient::default();
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
