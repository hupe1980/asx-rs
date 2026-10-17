#![cfg(feature = "as4")]
//! Every inbound XML document goes through one hardened parser: a `DOCTYPE`, a document over its class byte limit, a
//! 5,000-level nesting, more nodes than the class allows and an element with
//! 1,000 attributes are each refused with `ParseFailed` naming the limit —
//! on a 256 KiB stack, so a parser that recursed per level would abort the
//! process instead.
//!
//! Each probe is a *valid* document of its kind with the probe injected, so
//! only the limit can refuse it. XML attachment digest input has no public
//! entry point and is covered by unit tests in `crypto::wssec::canonicalize`.

#[path = "common/peers.rs"]
mod peers;

use asx::__fuzz::{AsxError, ErrorCode};
use asx_testkit::pki::KeyAlg;
use peers::{HANDLER_ERR, Preset};
use std::sync::atomic::Ordering;
use tower::ServiceExt;

/// What a probe must be refused for, and the words the error must contain.
#[derive(Clone, Copy, Debug)]
enum Probe {
    Doctype,
    Oversize(usize),
    Depth,
    Nodes,
    Attributes,
}

impl Probe {
    fn needle(self) -> &'static str {
        match self {
            Probe::Doctype => "DOCTYPE",
            Probe::Oversize(_) => "byte limit",
            Probe::Depth => "depth limit",
            Probe::Nodes => "node limit",
            Probe::Attributes => "attribute limit",
        }
    }

    /// `base` with the probe injected: the DOCTYPE before the root element,
    /// everything else just before the root's closing tag.
    fn apply(self, base: &str) -> String {
        if let Probe::Doctype = self {
            let at = if base.starts_with("<?xml") {
                base.find("?>").expect("declaration end") + 2
            } else {
                0
            };
            return format!(
                "{}<!DOCTYPE r [<!ENTITY e \"x\">]>{}",
                &base[..at],
                &base[at..]
            );
        }
        let insert = match self {
            Probe::Oversize(limit) => format!("<!--{}-->", " ".repeat(limit)),
            Probe::Depth => format!("{}{}", "<x>".repeat(5_000), "</x>".repeat(5_000)),
            Probe::Nodes => "<x/>".repeat(20_001),
            Probe::Attributes => {
                let attrs: String = (0..1_000).map(|i| format!(" a{i}=\"v\"")).collect();
                format!("<x{attrs}/>")
            }
            Probe::Doctype => unreachable!(),
        };
        let at = base.rfind("</").expect("root closing tag");
        format!("{}{}{}", &base[..at], insert, &base[at..])
    }
}

const ENVELOPE_PROBES: [Probe; 5] = [
    Probe::Doctype,
    Probe::Oversize(4 * 1024 * 1024),
    Probe::Depth,
    Probe::Nodes,
    Probe::Attributes,
];

/// Run `f` on a thread with a 256 KiB stack.
fn on_small_stack<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
    std::thread::Builder::new()
        .stack_size(256 * 1024)
        .spawn(f)
        .expect("spawn")
        .join()
        .expect("the parse must not overflow a 256 KiB stack")
}

fn assert_refused(kind: &str, probe: Probe, result: Result<(), AsxError>) {
    let err = result.unwrap_err_or_else(kind, probe);
    assert_eq!(
        err.code,
        ErrorCode::ParseFailed,
        "{kind} {probe:?}: {}",
        err.message
    );
    assert!(
        err.message.contains(probe.needle()),
        "{kind} {probe:?}: the error must name the {} limit: {}",
        probe.needle(),
        err.message
    );
}

trait UnwrapErr {
    fn unwrap_err_or_else(self, kind: &str, probe: Probe) -> AsxError;
}

impl UnwrapErr for Result<(), AsxError> {
    fn unwrap_err_or_else(self, kind: &str, probe: Probe) -> AsxError {
        match self {
            Ok(()) => panic!("{kind} {probe:?}: the probe was accepted"),
            Err(err) => err,
        }
    }
}

/// Run `fut` to completion on a current-thread runtime. The future is boxed
/// so its state lives on the heap, not on the (small) calling stack.
fn block_on<T>(fut: impl std::future::Future<Output = T>) -> T {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime")
        .block_on(Box::pin(fut))
}

/// The internal error behind a public `asx::Error`.
fn internal(err: &asx::Error) -> AsxError {
    std::error::Error::source(err)
        .and_then(|s| s.downcast_ref::<AsxError>())
        .unwrap_or_else(|| panic!("no internal error behind {err}"))
        .clone()
}

const PUSH_ENVELOPE: &str = concat!(
    r#"<S12:Envelope xmlns:S12="http://www.w3.org/2003/05/soap-envelope" "#,
    r#"xmlns:eb="http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/" "#,
    r#"xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">"#,
    r#"<S12:Header><wsse:Security/><eb:Messaging S12:mustUnderstand="true"><eb:UserMessage>"#,
    r#"<eb:MessageInfo><eb:MessageId>probe@asx.test</eb:MessageId></eb:MessageInfo>"#,
    r#"</eb:UserMessage></eb:Messaging></S12:Header><S12:Body></S12:Body></S12:Envelope>"#
);

/// A probed envelope pushed to a receiving `Inbound` is refused with an
/// `EBMS:0004` error signal whose description names the limit.
#[test]
fn push_envelope_limits() {
    let p = peers::pair(Preset::Bdew);
    let inbound = p.receiver.inbound(
        peers::SharedDedup(p.dedup.clone()),
        |_m: asx::Verified<asx::as4::UserMessage>| async { Ok::<(), asx::Reject>(()) },
    );
    for probe in ENVELOPE_PROBES {
        let payload = probe.apply(PUSH_ENVELOPE).into_bytes();
        let inbound = inbound.clone();
        let (status, body) = on_small_stack(move || {
            block_on(async move {
                let mut request =
                    http::Request::new(http_body_util::Full::new(bytes::Bytes::from(payload)));
                *request.method_mut() = http::Method::POST;
                request.headers_mut().insert(
                    http::header::CONTENT_TYPE,
                    http::HeaderValue::from_static("application/soap+xml"),
                );
                let response = inbound
                    .oneshot(request)
                    .await
                    .unwrap_or_else(|never| match never {});
                let status = response.status();
                let body = http_body_util::BodyExt::collect(response.into_body())
                    .await
                    .unwrap()
                    .to_bytes();
                (status, String::from_utf8_lossy(&body).into_owned())
            })
        });
        assert_eq!(
            status,
            http::StatusCode::BAD_REQUEST,
            "push envelope {probe:?}: {body}"
        );
        assert!(
            body.contains("EBMS:0004"),
            "push envelope {probe:?}: {body}"
        );
        assert!(
            body.contains(probe.needle()),
            "push envelope {probe:?}: the error must name the {} limit: {body}",
            probe.needle()
        );
    }
}

/// An `HttpClient` answering every request with one recorded response, so
/// a probed signal reaches the sender without a receiver running on the
/// probe's small stack.
#[derive(Debug)]
struct Canned {
    status: http::StatusCode,
    headers: http::HeaderMap,
    body: bytes::Bytes,
}

impl asx::HttpClient for Canned {
    fn send(
        &self,
        _request: http::Request<bytes::Bytes>,
    ) -> asx::BoxFuture<
        '_,
        Result<http::Response<bytes::Bytes>, Box<dyn std::error::Error + Send + Sync>>,
    > {
        let mut response = http::Response::new(self.body.clone());
        *response.status_mut() = self.status;
        *response.headers_mut() = self.headers.clone();
        Box::pin(std::future::ready(Ok(response)))
    }
}

/// The partner's synchronous signal (receipt, or error signal when its
/// handler refuses) is recorded, probed, and replayed to the sender, which
/// must refuse it at the parser, naming the limit. The sender caps a signal
/// response at 256 KiB before the parser, so the oversize probe is not
/// repeated here.
fn sync_signal_limits(kind: &str, refuse: bool) {
    let p = peers::pair(Preset::Bdew);
    if refuse {
        p.mode.store(HANDLER_ERR, Ordering::SeqCst);
    }
    let recorded = std::sync::Arc::new(std::sync::Mutex::new(None));
    {
        let recorded = recorded.clone();
        p.loopback.intercept(move |resp| {
            *recorded.lock().unwrap() =
                Some((resp.status(), resp.headers().clone(), resp.body().clone()));
        });
    }
    // Control: the unprobed signal is accepted (a receipt verifies; an error
    // signal is read as the partner's refusal).
    let control = block_on(
        p.sender
            .send(Preset::Bdew.message(&p.to_b, b"limits payload")),
    );
    if refuse {
        let err = control.expect_err("the partner refused");
        assert_eq!(
            err.kind(),
            asx::ErrorKind::PartnerError,
            "{kind}: control: {err}"
        );
        assert!(err.ebms_code().is_some(), "{kind}: control: {err}");
    } else {
        control.unwrap_or_else(|e| panic!("{kind}: control must be accepted: {e}"));
    }
    let (status, headers, body) = recorded.lock().unwrap().take().expect("a recorded signal");
    let base = String::from_utf8(body.to_vec()).expect("utf8 signal");

    for probe in [
        Probe::Doctype,
        Probe::Depth,
        Probe::Nodes,
        Probe::Attributes,
    ] {
        let sender = asx::as4::As4::builder(Preset::Bdew.profile())
            .local(p.a.local())
            .trust_anchor(p.ca.anchor())
            .partner(p.to_b.clone())
            .http_client(Canned {
                status,
                headers: headers.clone(),
                body: bytes::Bytes::from(probe.apply(&base)),
            })
            .build()
            .expect("sender builds");
        let message = Preset::Bdew.message(&p.to_b, b"limits payload");
        let result = on_small_stack(move || block_on(sender.send(message)).map(|_| ()));
        let err = result.expect_err("the probe was accepted");
        assert_refused(kind, probe, Err(internal(&err)));
    }
}

#[test]
fn receipt_limits() {
    sync_signal_limits("receipt", false);
}

#[test]
fn error_signal_limits() {
    sync_signal_limits("error signal", true);
}

#[test]
fn smp_response_limits() {
    let smp = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/smp/peppol_production_signed_service_metadata.xml"
    ))
    .expect("SMP fixture");
    for probe in [
        Probe::Doctype,
        Probe::Oversize(2 * 1024 * 1024),
        Probe::Depth,
        Probe::Nodes,
        Probe::Attributes,
    ] {
        let xml = probe.apply(&smp);
        let result = on_small_stack(move || {
            asx::__fuzz::wssec::verify_enveloped_document_signature(
                &xml,
                &[],
                &asx::__fuzz::wssec::ChainPolicy::default(),
            )
            .map(|_| ())
        });
        assert_refused("SMP response", probe, result);
    }
}

/// SBDH documents are payloads (parsed after the envelope signature
/// verified): the depth and attribute bounds are wider than an envelope's
/// but still finite, and `DOCTYPE` is refused.
#[test]
fn sbdh_document_limits() {
    use asx::__fuzz::sbdh::{
        SbdhDocumentIdentification, SbdhHeader, SbdhParty, StandardBusinessDocument,
    };
    let base = String::from_utf8(
        StandardBusinessDocument {
            header: SbdhHeader {
                header_version: "1.0".into(),
                sender: SbdhParty {
                    identifier: "0088:s".into(),
                    authority: "iso6523-actorid-upis".into(),
                },
                receiver: SbdhParty {
                    identifier: "0088:r".into(),
                    authority: "iso6523-actorid-upis".into(),
                },
                document_identification: SbdhDocumentIdentification {
                    standard: "urn:x".into(),
                    type_version: "2.1".into(),
                    instance_identifier: "i".into(),
                    r#type: "Invoice".into(),
                    multiple_type: false,
                    creation_date_and_time: "2026-10-16T12:00:00Z".into(),
                },
                business_scope: vec![],
            },
            payload: b"<Invoice xmlns=\"urn:x\"/>".to_vec(),
        }
        .wrap()
        .expect("wrap"),
    )
    .unwrap();
    StandardBusinessDocument::unwrap(base.as_bytes()).expect("control");
    for probe in [Probe::Doctype, Probe::Depth, Probe::Attributes] {
        let xml = match probe {
            // 1,000 attributes exceed the payload class's 256.
            Probe::Attributes => probe.apply(&base),
            _ => probe.apply(&base),
        };
        let result =
            on_small_stack(move || StandardBusinessDocument::unwrap(xml.as_bytes()).map(|_| ()));
        assert_refused("SBDH document", probe, result);
    }
}

/// The encryption envelope (`decrypt_swa`) goes through
/// the hardened parser with the envelope limits.
#[test]
fn encrypted_payload_limits() {
    let pair = asx_testkit::pki::KeyPair::self_signed("limits-xmlenc", KeyAlg::Rsa2048);
    let (xml, bodies) = asx::__fuzz::wssec::encrypt_swa(
        &[("limits@asx.test", "application/gzip", b"limits")],
        &pair.cert_pem,
        asx::__fuzz::wssec::XmlEncPayloadAlgorithm::Aes128Gcm,
    )
    .expect("encrypt");
    let body = bodies[0].clone();
    asx::__fuzz::wssec::decrypt_swa(xml.as_bytes(), &[("limits@asx.test", &body)], &pair.key_pem)
        .expect("control");
    for probe in [Probe::Doctype, Probe::Depth, Probe::Attributes] {
        let probed = probe.apply(&xml);
        let key = pair.key_pem.clone();
        let body = body.clone();
        let result = on_small_stack(move || {
            asx::__fuzz::wssec::decrypt_swa(probed.as_bytes(), &[("limits@asx.test", &body)], &key)
                .map(|_| ())
        });
        assert_refused("encrypted payload", probe, result);
    }
}
