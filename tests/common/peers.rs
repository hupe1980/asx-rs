//! Two AS4 clients wired through the testkit `Loopback`: `a` sends, `b`
//! receives with a controllable handler.
#![allow(dead_code, unreachable_pub, clippy::type_complexity)]

use asx::as4::{As4, Message, UserMessage};
use asx::{MemoryDedup, Partner, Payload, Profile, Reject, Verified};
use asx_testkit::audit::MemoryAuditSink;
use asx_testkit::loopback::Loopback;
use asx_testkit::pki::{TestCa, TestParty};
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};

pub const MP: &str = "https://www.bdew.de/as4/communication/services/MP";
pub const A_URL: &str = "https://a.example/as4";
pub const B_URL: &str = "https://b.example/as4";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Preset {
    Bdew,
    Peppol,
    Edelivery,
    Entsog,
}

pub const AS4_PRESETS: [Preset; 4] = [
    Preset::Bdew,
    Preset::Peppol,
    Preset::Edelivery,
    Preset::Entsog,
];

impl Preset {
    pub fn profile(self) -> Profile {
        match self {
            Preset::Bdew => Profile::bdew(),
            Preset::Peppol => Profile::peppol(),
            Preset::Edelivery => Profile::edelivery_1_15(),
            Preset::Entsog => Profile::entsog(),
        }
    }

    pub fn parties(self, ca: &TestCa) -> (TestParty, TestParty) {
        match self {
            Preset::Bdew => (
                ca.bdew_party("9900000000001"),
                ca.bdew_party("9900000000002"),
            ),
            Preset::Peppol => (ca.peppol_party("POP000001"), ca.peppol_party("POP000002")),
            Preset::Edelivery | Preset::Entsog => {
                (ca.rsa_party("party-a"), ca.rsa_party("party-b"))
            }
        }
    }

    pub fn ca(self) -> TestCa {
        match self {
            Preset::Bdew => TestCa::sm_pki(),
            _ => TestCa::new("asx-test root", asx_testkit::pki::KeyAlg::Rsa2048),
        }
    }

    /// A valid business message under this preset.
    pub fn message(self, to: &Partner, body: &[u8]) -> Message {
        let payload = Payload::new(body.to_vec(), "application/octet-stream");
        match self {
            Preset::Bdew => Message::to(to).service(MP).payload(payload.named("UTILMD.txt")),
            Preset::Peppol => Message::to(to)
                .service("urn:fdc:peppol.eu:2017:poacc:billing:01:1.0")
                .action("busdox-docid-qns::urn:oasis:names:specification:ubl:schema:xsd:Invoice-2::Invoice##urn:cen.eu:en16931:2017::2.1")
                .payload(Payload::new(body.to_vec(), "application/xml")),
            Preset::Edelivery | Preset::Entsog => Message::to(to)
                .service("urn:example:service")
                .action("urn:example:action")
                .payload(payload.named("doc.bin")),
        }
    }
}

/// What the receiving handler does.
pub const HANDLER_OK: u8 = 0;
pub const HANDLER_ERR: u8 = 1;
pub const HANDLER_PANIC: u8 = 2;
pub const HANDLER_SLOW: u8 = 3;
/// The first call waits for `Pair::gate`; later calls succeed.
pub const HANDLER_GATED: u8 = 4;

pub struct Pair {
    pub preset: Preset,
    pub ca: TestCa,
    pub a: TestParty,
    pub b: TestParty,
    pub sender: As4,
    pub receiver: As4,
    pub to_b: Partner,
    pub loopback: Loopback,
    pub sender_audit: MemoryAuditSink,
    pub receiver_audit: MemoryAuditSink,
    pub dedup: Arc<MemoryDedup>,
    pub calls: Arc<AtomicUsize>,
    pub mode: Arc<AtomicU8>,
    pub delivered: Arc<std::sync::Mutex<Vec<(String, String, Vec<Vec<u8>>)>>>,
    pub gate: Arc<tokio::sync::Notify>,
}

pub fn pair(preset: Preset) -> Pair {
    pair_with(preset, |b| b.partner(B_URL), |a| a.partner(A_URL))
}

/// `sender_partner` adjusts the sender's view of `b`; `receiver_partner`
/// adjusts the receiver's view of `a`.
pub fn pair_with(
    preset: Preset,
    sender_partner: impl FnOnce(&TestParty) -> Partner,
    receiver_partner: impl FnOnce(&TestParty) -> Partner,
) -> Pair {
    let ca = preset.ca();
    let (a, b) = preset.parties(&ca);
    let loopback = Loopback::new();
    let to_b = sender_partner(&b);
    let sender_audit = MemoryAuditSink::new();
    let receiver_audit = MemoryAuditSink::new();
    let sender = As4::builder(preset.profile())
        .local(a.local())
        .trust_anchor(ca.anchor())
        .partner(to_b.clone())
        .http_client(loopback.clone())
        .audit(sender_audit.clone())
        .build()
        .expect("sender builds");
    let receiver = As4::builder(preset.profile())
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
    let delivered = Arc::new(std::sync::Mutex::new(Vec::new()));
    let gate = Arc::new(tokio::sync::Notify::new());
    let handler = {
        let (calls, mode, delivered, gate) =
            (calls.clone(), mode.clone(), delivered.clone(), gate.clone());
        move |msg: Verified<UserMessage>| {
            let (calls, mode, delivered, gate) =
                (calls.clone(), mode.clone(), delivered.clone(), gate.clone());
            async move {
                let call = calls.fetch_add(1, Ordering::SeqCst);
                if mode.load(Ordering::SeqCst) == HANDLER_GATED && call == 0 {
                    gate.notified().await;
                }
                delivered.lock().unwrap().push((
                    msg.message_id().to_string(),
                    msg.from().to_string(),
                    msg.payloads().iter().map(|p| p.bytes().to_vec()).collect(),
                ));
                match mode.load(Ordering::SeqCst) {
                    HANDLER_ERR => Err(Reject::new(std::io::Error::other(
                        "refused by the application",
                    ))),
                    HANDLER_PANIC => panic!("handler panicked on purpose"),
                    HANDLER_SLOW => {
                        tokio::time::sleep(std::time::Duration::from_secs(6 * 60)).await;
                        Ok(())
                    }
                    _ => Ok(()),
                }
            }
        }
    };
    loopback.mount(B_URL, receiver.inbound(SharedDedup(dedup.clone()), handler));
    Pair {
        preset,
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
        gate,
    }
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

/// The text of the SOAP part of a captured multipart body.
pub fn soap_part(body: &[u8]) -> String {
    let text = String::from_utf8_lossy(body);
    let start = text
        .find("<S12:Envelope")
        .or_else(|| text.find("Envelope"))
        .unwrap_or(0);
    let end = text[start..]
        .find("Envelope>")
        .map(|i| start + i + "Envelope>".len())
        .unwrap_or(text.len());
    text[start..end].to_string()
}
