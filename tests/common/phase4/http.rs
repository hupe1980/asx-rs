//! `PeerHttp`: the crate's transport to the container, and one-byte tampering.
//!
//! The preset requires an HTTPS partner endpoint; the peer serves plain HTTP
//! on a mapped port. `PeerHttp` implements the public `asx::HttpClient`
//! extension point: it forwards requests for exactly the host
//! `phase4.peer.test` to `http://127.0.0.1:<port>` and refuses every other
//! host. Signing, encryption, receipt verification and pinning run unchanged
//! inside the crate; TLS is not the claim this oracle makes.

use std::sync::{Arc, Mutex};

use asx::BoxFuture;
use bytes::Bytes;

use super::pki::PHASE4_HOST;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Where to flip one byte of the request body.
// The variant names are the harness contract other items' cases use.
#[allow(clippy::enum_variant_names)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tamper {
    /// A digit of the `eb:Timestamp` value inside the signed `eb:Messaging`
    /// (the XML stays well-formed; only the signature can catch it).
    FlipByteInSignedMessaging,
    /// A byte of the first `application/octet-stream` MIME part's content
    /// (the ciphertext of the first encrypted payload), 16 bytes after its headers.
    FlipByteInCiphertext,
    /// The byte at this offset.
    FlipByteAt(usize),
}

/// Flip one byte of `body` per `tamper`; returns the offset flipped.
pub fn apply_tamper(body: &mut [u8], tamper: Tamper) -> Result<usize, String> {
    let at = match tamper {
        Tamper::FlipByteAt(at) if at < body.len() => at,
        Tamper::FlipByteAt(at) => return Err(format!("offset {at} beyond {} bytes", body.len())),
        Tamper::FlipByteInSignedMessaging => signed_messaging_offset(body)?,
        Tamper::FlipByteInCiphertext => ciphertext_offset(body)?,
    };
    body[at] = flip(body[at]);
    Ok(at)
}

/// A different byte of the same class: digit → digit, letter → letter, else XOR 1.
fn flip(b: u8) -> u8 {
    match b {
        b'0'..=b'8' => b + 1,
        b'9' => b'0',
        b'a'..=b'y' | b'A'..=b'Y' => b + 1,
        b'z' => b'a',
        b'Z' => b'A',
        other => other ^ 0x01,
    }
}

fn find(hay: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    if from >= hay.len() {
        return None;
    }
    hay[from..]
        .windows(needle.len())
        .position(|w| w == needle)
        .map(|i| i + from)
}

/// The last digit of the first `…Timestamp>` value after `Messaging`.
fn signed_messaging_offset(body: &[u8]) -> Result<usize, String> {
    let messaging = find(body, b"Messaging", 0).ok_or("no eb:Messaging in the body")?;
    let ts = find(body, b"Timestamp>", messaging).ok_or("no eb:Timestamp in eb:Messaging")?;
    let start = ts + b"Timestamp>".len();
    let end = find(body, b"<", start).ok_or("unterminated eb:Timestamp")?;
    (start..end)
        .rev()
        .find(|&i| body[i].is_ascii_digit())
        .ok_or_else(|| "no digit in eb:Timestamp".to_string())
}

/// 16 bytes into the content of the first `application/octet-stream` part.
fn ciphertext_offset(body: &[u8]) -> Result<usize, String> {
    let lower: Vec<u8> = body.iter().map(u8::to_ascii_lowercase).collect();
    let mut from = 0;
    while let Some(ct) = find(&lower, b"content-type: application/octet-stream", from) {
        // Only a part header counts: the line must start the header block line.
        if let Some(end) = find(body, b"\r\n\r\n", ct) {
            let at = end + 4 + 16;
            if at < body.len() {
                return Ok(at);
            }
        }
        from = ct + 1;
    }
    Err("no application/octet-stream MIME part".into())
}

/// The crate's `HttpClient` for the job.
#[derive(Debug, Clone)]
pub struct PeerHttp {
    base: String,
    client: reqwest::Client,
    tamper: Option<Tamper>,
    sent: Arc<Mutex<Vec<Vec<u8>>>>,
    tampered_at: Arc<Mutex<Vec<usize>>>,
}

impl PeerHttp {
    /// Forward `https://phase4.peer.test/...` to `base` (`http://127.0.0.1:<port>`).
    pub fn new(base: impl Into<String>) -> PeerHttp {
        PeerHttp {
            base: base.into().trim_end_matches('/').to_string(),
            client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(60))
                .build()
                .expect("reqwest client"),
            tamper: None,
            sent: Arc::default(),
            tampered_at: Arc::default(),
        }
    }

    /// Flip one byte of every forwarded request body.
    pub fn tampering(mut self, tamper: Tamper) -> PeerHttp {
        self.tamper = Some(tamper);
        self
    }

    /// Request bodies as forwarded (after tampering).
    pub fn sent(&self) -> Vec<Vec<u8>> {
        self.sent.lock().unwrap().clone()
    }

    /// Offsets flipped, one per tampered request.
    pub fn tampered_at(&self) -> Vec<usize> {
        self.tampered_at.lock().unwrap().clone()
    }

    async fn forward(
        &self,
        request: http::Request<Bytes>,
    ) -> Result<http::Response<Bytes>, BoxError> {
        let uri = request.uri().clone();
        if uri.host() != Some(PHASE4_HOST) {
            return Err(format!("PeerHttp forwards only {PHASE4_HOST}, not {uri}").into());
        }
        let path = uri.path_and_query().map_or("/", |p| p.as_str());
        let url = format!("{}{path}", self.base);
        let (parts, body) = request.into_parts();
        let mut body = body.to_vec();
        if let Some(tamper) = self.tamper {
            let at = apply_tamper(&mut body, tamper)?;
            self.tampered_at.lock().unwrap().push(at);
        }
        self.sent.lock().unwrap().push(body.clone());
        let mut req = self.client.request(parts.method, url).body(body);
        for (name, value) in &parts.headers {
            if name != http::header::HOST && name != http::header::CONTENT_LENGTH {
                req = req.header(name, value);
            }
        }
        let resp = req.send().await?;
        let mut out = http::Response::builder().status(resp.status());
        for (name, value) in resp.headers() {
            out = out.header(name, value);
        }
        let bytes = resp.bytes().await?;
        Ok(out.body(bytes)?)
    }
}

impl asx::HttpClient for PeerHttp {
    fn send(
        &self,
        request: http::Request<Bytes>,
    ) -> BoxFuture<'_, Result<http::Response<Bytes>, BoxError>> {
        // A test CA's CRL: the crate checks the phase4 signer's
        // path against its distribution point.
        if let Some(crl) = asx_testkit::pki::published_crl(&request.uri().to_string()) {
            return Box::pin(async move {
                Ok(http::Response::builder()
                    .status(200)
                    .body(Bytes::from(crl))
                    .expect("response"))
            });
        }
        Box::pin(self.forward(request))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    async fn echo_server() -> SocketAddr {
        let app = axum::Router::new().fallback(|body: Bytes| async move { body });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        addr
    }

    fn request(url: &str, body: &'static [u8]) -> http::Request<Bytes> {
        http::Request::post(url)
            .header("content-type", "application/soap+xml")
            .body(Bytes::from_static(body))
            .unwrap()
    }

    #[tokio::test]
    async fn peer_http_forwards_the_mapped_host() {
        let addr = echo_server().await;
        let client = PeerHttp::new(format!("http://{addr}"));
        let resp = asx::HttpClient::send(
            &client,
            request("https://phase4.peer.test/as4/bdew", b"hello"),
        )
        .await
        .expect("forwarded");
        assert_eq!(resp.body().as_ref(), b"hello");
        assert_eq!(client.sent(), vec![b"hello".to_vec()]);
    }

    #[tokio::test]
    async fn peer_http_refuses_a_foreign_host() {
        let addr = echo_server().await;
        let client = PeerHttp::new(format!("http://{addr}"));
        let err = asx::HttpClient::send(&client, request("https://example.org/as4", b"x"))
            .await
            .expect_err("foreign host");
        assert!(err.to_string().contains("forwards only"), "{err}");
        assert!(client.sent().is_empty());
    }

    const SOAP: &[u8] = b"--b\r\nContent-Type: application/soap+xml\r\n\r\n<S:Envelope><S:Header><eb:Messaging><eb:UserMessage><eb:MessageInfo><eb:Timestamp>2026-10-16T12:34:56Z</eb:Timestamp></eb:MessageInfo></eb:UserMessage></eb:Messaging></S:Header></S:Envelope>\r\n--b\r\nContent-Type: application/octet-stream\r\nContent-ID: <p1>\r\n\r\n0123456789abcdef0123456789abcdef\r\n--b--\r\n";

    fn diff(a: &[u8], b: &[u8]) -> Vec<usize> {
        a.iter()
            .zip(b)
            .enumerate()
            .filter(|(_, (x, y))| x != y)
            .map(|(i, _)| i)
            .collect()
    }

    #[test]
    fn tamper_signed_messaging_flips_one_timestamp_digit() {
        let mut body = SOAP.to_vec();
        let at = apply_tamper(&mut body, Tamper::FlipByteInSignedMessaging).unwrap();
        assert_eq!(diff(SOAP, &body), vec![at]);
        let s = String::from_utf8(body).unwrap();
        assert!(
            s.contains("<eb:Timestamp>2026-10-16T12:34:57Z</eb:Timestamp>"),
            "{s}"
        );
    }

    #[test]
    fn tamper_ciphertext_flips_one_byte_of_the_octet_stream_part() {
        let mut body = SOAP.to_vec();
        let at = apply_tamper(&mut body, Tamper::FlipByteInCiphertext).unwrap();
        assert_eq!(diff(SOAP, &body), vec![at]);
        let content = find(SOAP, b"0123456789abcdef0123", 0).unwrap();
        assert_eq!(at, content + 16);
    }

    #[test]
    fn tamper_at_offset_flips_exactly_that_byte() {
        let mut body = SOAP.to_vec();
        assert_eq!(apply_tamper(&mut body, Tamper::FlipByteAt(3)).unwrap(), 3);
        assert_eq!(diff(SOAP, &body), vec![3]);
        assert!(apply_tamper(&mut body, Tamper::FlipByteAt(SOAP.len())).is_err());
    }
}
