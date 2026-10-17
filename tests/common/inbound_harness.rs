//! Post crafted or mutated AS4 messages to a real [`asx::Inbound`] and read
//! the response-table answer.
//!
//! The genuine material is what `As4::send` puts on the wire, captured from
//! the testkit `Loopback`. A mutation that touches signed content (the
//! `eb:Messaging` header, the SOAP Body) can be re-signed with the sender's
//! key through the doc-hidden `asx::__fuzz::wssec` hook, so a case refuses or
//! accepts *because of* the mutation, not because of a broken digest.
//! Include after `peers` (`#[path = "common/peers.rs"] mod peers;`).
#![allow(dead_code, unreachable_pub)]

use crate::peers::{self, Pair, Preset};
use asx::as4::UserMessage;
use asx::{MemoryDedup, Reject, Verified};
use bytes::Bytes;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use tower::ServiceExt;

/// The response of one post.
#[derive(Debug)]
pub struct Answer {
    pub status: http::StatusCode,
    pub body: String,
}

impl Answer {
    /// The `eb:Error/@errorCode`, if the body is an ebMS error signal.
    pub fn ebms_code(&self) -> Option<&str> {
        let at = self.body.find("errorCode=\"")? + "errorCode=\"".len();
        let end = at + self.body[at..].find('"')?;
        Some(&self.body[at..end])
    }

    /// The text of `eb:Description` (the refusal reason).
    pub fn description(&self) -> &str {
        let Some(open) = self.body.find("<eb:Description") else {
            return "";
        };
        let Some(start) = self.body[open..].find('>').map(|i| open + i + 1) else {
            return "";
        };
        let end = self.body[start..]
            .find('<')
            .map_or(self.body.len(), |i| start + i);
        &self.body[start..end]
    }

    /// HTTP 200 with a signed receipt.
    pub fn is_receipt(&self) -> bool {
        self.status == http::StatusCode::OK
            && self.body.contains("Receipt")
            && self.body.contains("SignatureValue")
            && self.ebms_code().is_none()
    }

    /// HTTP 400 with `code`.
    #[track_caller]
    pub fn assert_refused(&self, code: &str) {
        assert_eq!(self.status, http::StatusCode::BAD_REQUEST, "{self:?}");
        assert_eq!(self.ebms_code(), Some(code), "{self:?}");
    }

    /// HTTP 400 with `code`, for the reason named by `reason`.
    #[track_caller]
    pub fn assert_refused_because(&self, code: &str, reason: &str) {
        self.assert_refused(code);
        assert!(
            self.description().contains(reason),
            "expected {reason:?} in {:?}",
            self.description()
        );
    }

    /// Never a 5xx other than the dedup-backed 500/503, never a panic.
    #[track_caller]
    pub fn assert_well_formed(&self) {
        assert!(
            self.status.is_success() || self.status.is_client_error(),
            "{self:?}"
        );
    }
}

/// An `Inbound` of `b` with a fresh dedup and a counting handler.
pub struct Receiver {
    pub inbound: asx::Inbound,
    pub calls: Arc<AtomicUsize>,
    pub delivered: Arc<Mutex<Vec<Delivered>>>,
}

/// What the handler saw of one delivered message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Delivered {
    pub message_id: String,
    pub from: String,
    pub service: String,
    pub action: String,
    pub conversation_id: String,
    pub payloads: Vec<Vec<u8>>,
}

impl Receiver {
    pub fn of(pair: &Pair) -> Receiver {
        let calls = Arc::new(AtomicUsize::new(0));
        let delivered = Arc::new(Mutex::new(Vec::new()));
        let inbound = {
            let (calls, delivered) = (calls.clone(), delivered.clone());
            pair.receiver
                .inbound(MemoryDedup::default(), move |m: Verified<UserMessage>| {
                    let (calls, delivered) = (calls.clone(), delivered.clone());
                    async move {
                        calls.fetch_add(1, Ordering::SeqCst);
                        delivered.lock().unwrap().push(Delivered {
                            message_id: m.message_id().to_string(),
                            from: m.from().to_string(),
                            service: m.service().to_string(),
                            action: m.action().to_string(),
                            conversation_id: m.conversation_id().to_string(),
                            payloads: m.payloads().iter().map(|p| p.bytes().to_vec()).collect(),
                        });
                        Ok::<(), Reject>(())
                    }
                })
        };
        Receiver {
            inbound,
            calls,
            delivered,
        }
    }

    pub fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }

    pub async fn post(&self, request: http::Request<Bytes>) -> Answer {
        post(&self.inbound, request).await
    }

    /// Check the handler was not reached.
    #[track_caller]
    pub fn assert_not_delivered(&self) {
        assert_eq!(self.calls(), 0, "the handler must not be called");
    }

    /// The one delivered message.
    #[track_caller]
    pub fn delivered_once(&self) -> Delivered {
        let delivered = self.delivered.lock().unwrap();
        assert_eq!(delivered.len(), 1, "exactly one delivery: {delivered:?}");
        delivered[0].clone()
    }

    /// Post `request`; it must be refused with `code` and not delivered.
    pub async fn refused(&self, request: http::Request<Bytes>, code: &str) -> Answer {
        let answer = self.post(request).await;
        answer.assert_refused(code);
        self.assert_not_delivered();
        answer
    }

    /// Post `request`; it must be receipted and delivered once.
    pub async fn accepted(&self, request: http::Request<Bytes>) -> Delivered {
        let answer = self.post(request).await;
        assert!(answer.is_receipt(), "{answer:?}");
        self.delivered_once()
    }
}

pub async fn post(inbound: &asx::Inbound, request: http::Request<Bytes>) -> Answer {
    let response = inbound
        .clone()
        .oneshot(request.map(http_body_util::Full::new))
        .await
        .unwrap_or_else(|never| match never {});
    let status = response.status();
    let body = http_body_util::BodyExt::collect(response.into_body())
        .await
        .expect("body")
        .to_bytes();
    Answer {
        status,
        body: String::from_utf8_lossy(&body).into_owned(),
    }
}

/// A request to `b` with `content_type` and `body`.
pub fn request(content_type: &str, body: impl Into<Bytes>) -> http::Request<Bytes> {
    http::Request::post(peers::B_URL)
        .header(http::header::CONTENT_TYPE, content_type)
        .body(body.into())
        .expect("request")
}

/// A pair plus one genuine (signed, encrypted) message from `a` to `b`,
/// captured from the loopback after its first delivery.
pub struct Genuine {
    pub pair: Pair,
    pub request: http::Request<Bytes>,
}

pub async fn genuine(preset: Preset) -> Genuine {
    genuine_with(peers::pair(preset), b"adversarial-payload").await
}

pub async fn genuine_with(pair: Pair, body: &[u8]) -> Genuine {
    pair.sender
        .send(pair.preset.message(&pair.to_b, body))
        .await
        .expect("the genuine message is receipted");
    let request = pair.loopback.last_request().expect("captured request");
    Genuine { pair, request }
}

/// A MIME part of a captured multipart body.
#[derive(Debug, Clone)]
pub struct Part {
    pub headers: String,
    pub body: Vec<u8>,
}

impl Part {
    pub fn content_id(&self) -> Option<String> {
        self.headers.lines().find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.trim().eq_ignore_ascii_case("Content-ID").then(|| {
                value
                    .trim()
                    .trim_start_matches('<')
                    .trim_end_matches('>')
                    .to_string()
            })
        })
    }
}

fn find(haystack: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    haystack[from..]
        .windows(needle.len())
        .position(|w| w == needle)
        .map(|i| i + from)
}

impl Genuine {
    pub fn content_type(&self) -> String {
        self.request
            .headers()
            .get(http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string()
    }

    fn boundary(&self) -> String {
        let ct = self.content_type();
        let at = ct.find("boundary=").expect("boundary") + "boundary=".len();
        let rest = ct[at..].trim_start_matches('"');
        rest[..rest.find(['"', ';']).unwrap_or(rest.len())].to_string()
    }

    /// The MIME parts, SOAP root first.
    pub fn parts(&self) -> Vec<Part> {
        let body = self.request.body();
        let delimiter = format!("--{}", self.boundary()).into_bytes();
        let mut parts = Vec::new();
        let mut at = find(body, &delimiter, 0).expect("first delimiter");
        loop {
            let start = at + delimiter.len();
            if body[start..].starts_with(b"--") {
                break;
            }
            let start = start + 2; // CRLF
            let next = find(body, &delimiter, start).expect("next delimiter");
            let part = &body[start..next - 2]; // drop the CRLF before the delimiter
            let split = find(part, b"\r\n\r\n", 0).expect("part headers");
            parts.push(Part {
                headers: String::from_utf8_lossy(&part[..split]).into_owned(),
                body: part[split + 4..].to_vec(),
            });
            at = next;
        }
        parts
    }

    /// The SOAP envelope text (no XML declaration).
    pub fn soap(&self) -> String {
        let root = String::from_utf8(self.parts()[0].body.clone()).expect("utf8 SOAP part");
        let start = root.find("<soap:Envelope").expect("envelope");
        root[start..].to_string()
    }

    /// Reassemble `parts` under the genuine boundary.
    pub fn with_parts(&self, parts: &[Part]) -> http::Request<Bytes> {
        let boundary = self.boundary();
        let mut out = Vec::new();
        for part in parts {
            out.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
            out.extend_from_slice(part.headers.as_bytes());
            out.extend_from_slice(b"\r\n\r\n");
            out.extend_from_slice(&part.body);
            out.extend_from_slice(b"\r\n");
        }
        out.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
        request(&self.content_type(), out)
    }

    /// The genuine request with its SOAP envelope replaced by `soap`.
    pub fn with_soap(&self, soap: &str) -> http::Request<Bytes> {
        let mut parts = self.parts();
        parts[0].body = format!("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n{soap}").into_bytes();
        self.with_parts(&parts)
    }

    /// `mutate` the SOAP envelope, leaving the signature as it was.
    pub fn mutated(&self, mutate: impl FnOnce(String) -> String) -> http::Request<Bytes> {
        self.with_soap(&mutate(self.soap()))
    }

    /// The attachments before encryption (`cid:URI`, bytes): what the
    /// `cid:` references digest (sign, then encrypt). Decrypted with
    /// `b`'s key through the doc-hidden `asx::__fuzz::wssec::decrypt_swa`.
    pub fn plaintext_attachments(&self) -> Vec<(String, Vec<u8>)> {
        let soap = self.soap();
        let start = soap.find("<wsse:Security").expect("wsse:Security");
        let end =
            soap.find("</wsse:Security>").expect("wsse:Security end") + "</wsse:Security>".len();
        let parts: Vec<(String, Vec<u8>)> = self.parts()[1..]
            .iter()
            .map(|p| (p.content_id().expect("Content-ID"), p.body.clone()))
            .collect();
        let borrowed: Vec<(&str, &[u8])> = parts
            .iter()
            .map(|(cid, body)| (cid.as_str(), body.as_slice()))
            .collect();
        let plain = asx::__fuzz::wssec::decrypt_swa(
            &soap.as_bytes()[start..end],
            &borrowed,
            &self.pair.b.encryption.key_pem,
        )
        .expect("the genuine attachments decrypt");
        parts
            .iter()
            .zip(plain)
            .map(|((cid, _), bytes)| (format!("cid:{cid}"), bytes))
            .collect()
    }

    /// `mutate` the SOAP envelope, then sign it again with `a`'s key over the
    /// same references (a sender that signs exactly what is on the wire;
    /// `cid:` digests over the pre-encryption bytes).
    pub fn resigned(&self, mutate: impl FnOnce(String) -> String) -> http::Request<Bytes> {
        let attachments = self.plaintext_attachments();
        let soap = resign(&mutate(self.soap()), &attachments, &self.pair.a.signing);
        self.with_soap(&soap)
    }

    /// A fresh receiver for `b`.
    pub fn receiver(&self) -> Receiver {
        Receiver::of(&self.pair)
    }
}

/// Replace the `ds:Signature` in `soap` with a fresh one by `signer` over the
/// same reference URIs. `cid:` references digest `attachments` (raw octets:
/// the parts before encryption are gzip, not XML- or text-typed).
pub fn resign(
    soap: &str,
    attachments: &[(String, Vec<u8>)],
    signer: &asx::testkit::pki::KeyPair,
) -> String {
    const PLACEHOLDER: &str = "<!--asx-resign-->";
    let start = soap.find("<ds:Signature").expect("ds:Signature");
    let end = soap.find("</ds:Signature>").expect("ds:Signature end") + "</ds:Signature>".len();
    let signature = &soap[start..end];
    let key_info = if signature.contains("X509PKIPathv1") {
        asx::__fuzz::wssec::WsSecOutboundKeyInfoProfile::X509PKIPathv1
    } else {
        asx::__fuzz::wssec::WsSecOutboundKeyInfoProfile::BinarySecurityTokenX509v3
    };
    let uris: Vec<String> = signature
        .match_indices("<ds:Reference URI=\"")
        .map(|(i, m)| {
            let rest = &signature[i + m.len()..];
            rest[..rest.find('"').expect("URI end")].to_string()
        })
        .collect();
    let unsigned = format!("{}{PLACEHOLDER}{}", &soap[..start], &soap[end..]);
    let refs: Vec<&str> = uris.iter().map(String::as_str).collect();
    let external: Vec<(&str, &[u8])> = attachments
        .iter()
        .filter(|(cid, _)| uris.contains(cid))
        .map(|(cid, bytes)| (cid.as_str(), bytes.as_slice()))
        .collect();
    let fresh = asx::__fuzz::wssec::generate_xmlsig_signature_with_external_references(
        &unsigned,
        &refs,
        &external,
        &signer.key_pem,
        &signer.cert_pem,
        key_info,
    )
    .expect("re-sign the mutated envelope");
    unsigned.replace(PLACEHOLDER, &fresh)
}

/// Wrap a hand-crafted SOAP envelope as SwA (`multipart/related`, the SOAP
/// root plus one octet-stream attachment), so the parser judges the envelope
/// rather than refusing a non-SwA body.
pub fn swa(soap: &[u8]) -> http::Request<Bytes> {
    const BOUNDARY: &str = "asx-adversarial-boundary";
    let mut out = Vec::new();
    out.extend_from_slice(format!("--{BOUNDARY}\r\n").as_bytes());
    out.extend_from_slice(b"Content-Type: application/soap+xml; charset=UTF-8\r\n");
    out.extend_from_slice(b"Content-ID: <soap-root@example.com>\r\n\r\n");
    out.extend_from_slice(soap);
    out.extend_from_slice(format!("\r\n--{BOUNDARY}\r\n").as_bytes());
    out.extend_from_slice(
        b"Content-Type: application/octet-stream\r\nContent-ID: <body@example.com>\r\n\r\n",
    );
    out.extend_from_slice(b"adversarial-attachment");
    out.extend_from_slice(format!("\r\n--{BOUNDARY}--\r\n").as_bytes());
    request(
        &format!(
            "multipart/related; boundary=\"{BOUNDARY}\"; type=\"application/soap+xml\"; \
             start=\"<soap-root@example.com>\""
        ),
        out,
    )
}

/// Insert `xml` right after the opening `<soap:Header>` tag.
pub fn header_first(soap: &str, xml: &str) -> String {
    soap.replacen("<soap:Header>", &format!("<soap:Header>{xml}"), 1)
}

/// Insert `xml` right before `</soap:Header>`.
pub fn header_last(soap: &str, xml: &str) -> String {
    soap.replacen("</soap:Header>", &format!("{xml}</soap:Header>"), 1)
}

/// The `<ebms:Messaging …>…</ebms:Messaging>` element of a genuine envelope.
pub fn messaging(soap: &str) -> &str {
    let start = soap.find("<ebms:Messaging").expect("Messaging");
    let end = soap.find("</ebms:Messaging>").expect("Messaging end") + "</ebms:Messaging>".len();
    &soap[start..end]
}
