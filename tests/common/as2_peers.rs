//! Two AS2 clients wired through the testkit `Loopback`: `a` sends, `b`
//! receives with a controllable handler.
#![allow(dead_code, unreachable_pub)]

use asx::as2::{As2, Message, Received};
use asx::testkit::audit::MemoryAuditSink;
use asx::testkit::loopback::Loopback;
use asx::testkit::pki::{TestCa, TestParty};
use asx::{MemoryDedup, Partner, Payload, Profile, Reject, Verified};
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};

pub const A_ID: &str = "PARTY-A-AS2";
pub const B_ID: &str = "PARTY-B-AS2";
pub const A_URL: &str = "https://a.example/as2";
pub const B_URL: &str = "https://b.example/as2";
pub const EDI: &str = "application/edi-x12";

pub const HANDLER_OK: u8 = 0;
pub const HANDLER_ERR: u8 = 1;
pub const HANDLER_PANIC: u8 = 2;

/// (message id, AS2-From, payload, media type) of each delivery.
pub type Delivered = Arc<std::sync::Mutex<Vec<(String, String, Vec<u8>, String)>>>;

pub struct Pair {
    pub ca: TestCa,
    pub a: TestParty,
    pub b: TestParty,
    pub sender: As2,
    pub receiver: As2,
    pub to_b: Partner,
    pub loopback: Loopback,
    pub sender_audit: MemoryAuditSink,
    pub receiver_audit: MemoryAuditSink,
    pub dedup: Arc<MemoryDedup>,
    pub calls: Arc<AtomicUsize>,
    pub mode: Arc<AtomicU8>,
    pub delivered: Delivered,
}

pub fn pair() -> Pair {
    pair_with(|b| b.partner(B_URL), |a| a.partner(A_URL))
}

/// `sender_partner` adjusts the sender's view of `b`; `receiver_partner`
/// adjusts the receiver's view of `a`.
pub fn pair_with(
    sender_partner: impl FnOnce(&TestParty) -> Partner,
    receiver_partner: impl FnOnce(&TestParty) -> Partner,
) -> Pair {
    let ca = TestCa::new("asx-test AS2 root", asx::testkit::pki::KeyAlg::Rsa2048);
    let (a, b) = (ca.as2_party(A_ID), ca.as2_party(B_ID));
    let loopback = Loopback::new();
    let to_b = sender_partner(&b);
    let sender_audit = MemoryAuditSink::new();
    let receiver_audit = MemoryAuditSink::new();
    let sender = As2::builder(Profile::as2())
        .local(a.local())
        .trust_anchor(ca.anchor())
        .partner(to_b.clone())
        .http_client(loopback.clone())
        .audit(sender_audit.clone())
        .build()
        .expect("sender builds");
    let receiver = As2::builder(Profile::as2())
        .local(b.local())
        .trust_anchor(ca.anchor())
        .partner(receiver_partner(&a))
        .http_client(loopback.clone())
        .audit(receiver_audit.clone())
        .build()
        .expect("receiver builds");
    let dedup = Arc::new(MemoryDedup::default());
    let calls = Arc::new(AtomicUsize::new(0));
    let mode = Arc::new(AtomicU8::new(HANDLER_OK));
    let delivered: Delivered = Arc::default();
    let handler = handler(calls.clone(), mode.clone(), delivered.clone());
    loopback.mount(B_URL, receiver.inbound(SharedDedup(dedup.clone()), handler));
    Pair {
        ca,
        a,
        b,
        sender,
        receiver,
        to_b,
        loopback,
        sender_audit,
        receiver_audit,
        dedup,
        calls,
        mode,
        delivered,
    }
}

/// What the test handler returns.
pub type HandlerFuture =
    std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), Reject>> + Send>>;

/// The controllable receiving handler.
pub fn handler(
    calls: Arc<AtomicUsize>,
    mode: Arc<AtomicU8>,
    delivered: Delivered,
) -> impl Fn(Verified<Received>) -> HandlerFuture + Send + Sync + 'static {
    move |msg: Verified<Received>| {
        let (calls, mode, delivered) = (calls.clone(), mode.clone(), delivered.clone());
        Box::pin(async move {
            calls.fetch_add(1, Ordering::SeqCst);
            delivered.lock().unwrap().push((
                msg.message_id().to_string(),
                msg.from().to_string(),
                msg.payload().bytes().to_vec(),
                msg.payload().mime_type().to_string(),
            ));
            match mode.load(Ordering::SeqCst) {
                HANDLER_ERR => Err(Reject::new(std::io::Error::other(
                    "refused by the application",
                ))),
                HANDLER_PANIC => panic!("handler panicked on purpose"),
                _ => Ok(()),
            }
        })
    }
}

impl Pair {
    /// A message from `a` to `b`.
    pub fn message(&self, body: &[u8]) -> Message {
        Message::to(&self.to_b, Payload::new(body.to_vec(), EDI))
    }

    /// The signed MDN `b` would send, made with the doc-hidden generator: `b`'s
    /// key, the given Original-Message-ID, disposition and MIC.
    pub fn mdn_signed_by_b(
        &self,
        original_id: &str,
        disposition: &str,
        mic: Option<&str>,
    ) -> Vec<u8> {
        sign_mdn(&self.b.signing, original_id, disposition, mic)
    }
}

/// An MDN signed by `pair` with the doc-hidden generator.
pub fn sign_mdn(
    pair: &asx::testkit::pki::KeyPair,
    original_id: &str,
    disposition: &str,
    mic: Option<&str>,
) -> Vec<u8> {
    let session = asx::__fuzz::SessionContext::new("mdn-forger", B_ID, "strict").expect("session");
    asx::__fuzz::generate_signed_mdn(
        &session,
        original_id,
        disposition,
        mic,
        &asx::__fuzz::As2MdnSigningCredentials {
            signing_cert_pem: pair.cert_pem.clone(),
            signing_key_pem: pair.key_pem.clone(),
        },
    )
    .expect("signed MDN")
}

/// An unsigned MDN made with the doc-hidden generator.
pub fn unsigned_mdn(original_id: &str, disposition: &str, mic: Option<&str>) -> Vec<u8> {
    let session = asx::__fuzz::SessionContext::new("mdn-forger", B_ID, "strict").expect("session");
    asx::__fuzz::generate_mdn(&session, original_id, disposition, mic).expect("MDN")
}

/// Sign arbitrary MIME `entity` (an MDN shape of the test's choosing) as `pair`.
pub fn sign_entity(pair: &asx::testkit::pki::KeyPair, entity: &[u8]) -> Vec<u8> {
    asx::__fuzz::sign_smime_message(entity, &pair.key_pem, &pair.cert_pem).expect("signed")
}

/// The value of the first `name:` line in `body` (an MDN's notification).
pub fn field(body: &[u8], name: &str) -> Option<String> {
    let text = String::from_utf8_lossy(body);
    let mut lines = text
        .split('\n')
        .map(|l| l.trim_end_matches('\r'))
        .peekable();
    while let Some(line) = lines.next() {
        if let Some((n, v)) = line.split_once(':')
            && n.trim().eq_ignore_ascii_case(name)
        {
            let mut value = v.trim().to_string();
            while let Some(next) = lines.peek() {
                if next.starts_with(' ') || next.starts_with('\t') {
                    value.push(' ');
                    value.push_str(next.trim());
                    lines.next();
                } else {
                    break;
                }
            }
            return Some(value);
        }
    }
    None
}

/// Replace a response's body with `mdn`, setting its Content-Type.
pub fn replace_with(resp: &mut http::Response<bytes::Bytes>, mdn: Vec<u8>) {
    let content_type =
        field(&mdn, "Content-Type").unwrap_or_else(|| "multipart/signed".to_string());
    resp.headers_mut().insert(
        http::header::CONTENT_TYPE,
        http::HeaderValue::from_str(&content_type).expect("content type"),
    );
    *resp.body_mut() = bytes::Bytes::from(mdn);
}

/// A `DedupStore` view of a shared `MemoryDedup`, so a test can inspect it.
#[derive(Debug, Clone)]
pub struct SharedDedup(pub Arc<MemoryDedup>);

impl asx::DedupStore for SharedDedup {
    fn claim<'a>(
        &'a self,
        key: &'a str,
    ) -> asx::BoxFuture<'a, Result<asx::Claim, Box<dyn std::error::Error + Send + Sync>>> {
        self.0.claim(key)
    }
    fn accept<'a>(
        &'a self,
        key: &'a str,
        token: &'a asx::ClaimToken,
    ) -> asx::BoxFuture<'a, Result<(), Box<dyn std::error::Error + Send + Sync>>> {
        self.0.accept(key, token)
    }
    fn abandon<'a>(
        &'a self,
        key: &'a str,
        token: &'a asx::ClaimToken,
    ) -> asx::BoxFuture<'a, Result<(), Box<dyn std::error::Error + Send + Sync>>> {
        self.0.abandon(key, token)
    }
}

/// A durable sink that always fails.
#[derive(Debug, Default, Clone)]
pub struct FailingSink;

impl asx::AuditSink for FailingSink {
    fn durability(&self) -> asx::AuditDurability {
        asx::AuditDurability::Durable
    }
    fn record<'a>(
        &'a self,
        _record: &'a asx::AuditRecord,
    ) -> asx::BoxFuture<'a, Result<(), Box<dyn std::error::Error + Send + Sync>>> {
        Box::pin(std::future::ready(Err("the audit store is down".into())))
    }
}
