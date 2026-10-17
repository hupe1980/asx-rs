#![cfg(all(feature = "as2", feature = "as4"))]
//! Fuzz and property smoke over the receive endpoints:
//! arbitrary bytes, genuine messages with bytes flipped, truncated or
//! inserted, and messages encrypted to someone else are posted to a real
//! `As4::inbound` / `As2::inbound`. Every answer is 2xx or 4xx — never a
//! panic, never a 5xx (the dedup store here cannot fail) — and nothing but
//! the untouched genuine message reaches the handler.

#[path = "common/inbound_harness.rs"]
mod inbound_harness;
#[path = "common/peers.rs"]
mod peers;

use asx::as2::{As2, Received};
use asx::testkit::loopback::Loopback;
use asx::testkit::pki::{KeyAlg, TestCa, TestParty};
use asx::{MemoryDedup, Payload, Profile, Reject, Verified};
use inbound_harness::{Answer, Genuine, Receiver, genuine, request};
use peers::{Preset, pair_with};
use proptest::prelude::*;
use std::sync::Arc;
use std::sync::atomic::Ordering;

fn pseudo_random_bytes(seed: u64, len: usize) -> Vec<u8> {
    let mut x = seed;
    let mut out = Vec::with_capacity(len);
    for _ in 0..len {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        out.push((x & 0xFF) as u8);
    }
    out
}

// ── AS4 ──────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn fuzz_smoke_as4_inbound_does_not_panic() {
    let p = peers::pair(Preset::Edelivery);
    let r = Receiver::of(&p);
    for i in 0..256usize {
        let body = pseudo_random_bytes(0xDEAD_2000_u64 + i as u64, i % 2048);
        for content_type in [
            "multipart/related; boundary=\"x\"; type=\"application/soap+xml\"",
            "application/soap+xml",
            "text/plain",
        ] {
            r.post(request(content_type, body.clone()))
                .await
                .assert_well_formed();
        }
    }
    r.assert_not_delivered();
}

/// The control: the untouched message is accepted, so the refusals below are
/// about the mutation, not the fixture.
#[tokio::test]
async fn a_genuine_as4_message_is_accepted() {
    let g = genuine(Preset::Edelivery).await;
    let r = g.receiver();
    let delivered = r.accepted(g.with_parts(&g.parts())).await;
    assert_eq!(delivered.payloads, vec![b"adversarial-payload".to_vec()]);
}

/// A flipped byte anywhere in the signed `eb:Messaging` or in the encrypted
/// attachment (its GCM tag) is refused and never delivered.
#[tokio::test]
async fn an_as4_message_with_a_flipped_byte_is_refused() {
    let g = genuine(Preset::Edelivery).await;
    let r = g.receiver();
    let body = g.request.body().to_vec();
    let text = String::from_utf8_lossy(&body).into_owned();
    let messaging = text.find("<ebms:Messaging").unwrap()..text.find("</ebms:Messaging>").unwrap();
    // The encrypted attachment: the body of the last MIME part (raw
    // `IV ‖ ciphertext ‖ tag`).
    let last = g.parts().pop().expect("an attachment part");
    let at = body
        .windows(last.body.len())
        .rposition(|w| w == last.body.as_slice())
        .expect("attachment bytes");
    let attachment = at..at + last.body.len();
    for range in [messaging, attachment] {
        for offset in range.step_by(11) {
            let mut tampered = body.clone();
            tampered[offset] ^= 0x01;
            let answer = r.post(request(&g.content_type(), tampered)).await;
            assert_eq!(
                answer.status,
                http::StatusCode::BAD_REQUEST,
                "offset {offset}: {answer:?}"
            );
        }
    }
    r.assert_not_delivered();
}

/// A message encrypted to another party's certificate cannot be decrypted:
/// EBMS:0102.
#[tokio::test]
async fn an_as4_message_for_another_recipient_is_refused() {
    let other = TestCa::new("other root", KeyAlg::Rsa2048).rsa_party("party-b");
    let p = pair_with(
        Preset::Edelivery,
        |b| {
            let partner = asx::Partner::new(&b.id)
                .endpoint(peers::B_URL)
                .signing_cert(b.signing.certificate())
                .encryption_cert(other.encryption.certificate());
            match &b.party_type {
                Some(t) => partner.party_type(t),
                None => partner,
            }
        },
        |a| a.partner(peers::A_URL),
    );
    let err = p
        .sender
        .send(Preset::Edelivery.message(&p.to_b, b"x"))
        .await
        .expect_err("not decryptable by b");
    assert_eq!(err.ebms_code(), Some("EBMS:0102"), "{err}");
    assert_eq!(p.calls.load(Ordering::SeqCst), 0);
}

/// How a genuine message is damaged.
#[derive(Debug, Clone)]
enum Mutation {
    Flip { at: usize, mask: u8 },
    Truncate { at: usize },
    Insert { at: usize, bytes: Vec<u8> },
    Delete { at: usize, len: usize },
}

fn mutation() -> impl Strategy<Value = Mutation> {
    prop_oneof![
        (any::<usize>(), 1u8..=255).prop_map(|(at, mask)| Mutation::Flip { at, mask }),
        any::<usize>().prop_map(|at| Mutation::Truncate { at }),
        (
            any::<usize>(),
            proptest::collection::vec(any::<u8>(), 1..32)
        )
            .prop_map(|(at, bytes)| Mutation::Insert { at, bytes }),
        (any::<usize>(), 1usize..64).prop_map(|(at, len)| Mutation::Delete { at, len }),
    ]
}

fn apply(body: &[u8], mutation: &Mutation) -> Vec<u8> {
    let mut out = body.to_vec();
    let n = out.len();
    match mutation {
        Mutation::Flip { at, mask } => out[at % n] ^= mask,
        Mutation::Truncate { at } => out.truncate(at % n),
        Mutation::Insert { at, bytes } => {
            out.splice(at % n..at % n, bytes.iter().copied());
        }
        Mutation::Delete { at, len } => {
            let start = at % n;
            out.drain(start..(start + len).min(n));
        }
    }
    out
}

struct As4Fixture {
    runtime: tokio::runtime::Runtime,
    genuine: Genuine,
}

fn as4_fixture() -> &'static As4Fixture {
    static FIXTURE: std::sync::OnceLock<As4Fixture> = std::sync::OnceLock::new();
    FIXTURE.get_or_init(|| {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let genuine = runtime.block_on(genuine(Preset::Edelivery));
        As4Fixture { runtime, genuine }
    })
}

fn post_blocking(
    runtime: &tokio::runtime::Runtime,
    r: &Receiver,
    req: http::Request<bytes::Bytes>,
) -> Answer {
    runtime.block_on(r.post(req))
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 96, ..ProptestConfig::default() })]

    /// Damaged genuine AS4 messages: 2xx or 4xx, never a panic or a 5xx. A
    /// mutation that leaves the signed and encrypted content intact (a MIME
    /// header the parser ignores) may still be accepted, so the property is
    /// the answer's shape; a refused message is never delivered and a
    /// delivered one carries the signed payload.
    #[test]
    fn mutated_as4_messages_get_a_well_formed_answer(
        mutations in proptest::collection::vec(mutation(), 1..4)
    ) {
        let fx = as4_fixture();
        let r = fx.genuine.receiver();
        let mut body = fx.genuine.request.body().to_vec();
        for m in &mutations {
            if !body.is_empty() {
                body = apply(&body, m);
            }
        }
        let answer = post_blocking(&fx.runtime, &r, request(&fx.genuine.content_type(), body));
        prop_assert!(
            answer.status.is_success() || answer.status.is_client_error(),
            "{mutations:?}: {answer:?}"
        );
        if !answer.status.is_success() {
            prop_assert_eq!(r.calls(), 0);
        }
        for delivered in r.delivered.lock().unwrap().iter() {
            prop_assert_eq!(&delivered.payloads, &vec![b"adversarial-payload".to_vec()]);
        }
    }
}

// ── AS2 ──────────────────────────────────────────────────────────────────────

const AS2_B_URL: &str = "https://b.example/as2";
const AS2_A_URL: &str = "https://a.example/as2";

struct As2Pair {
    ca: TestCa,
    a: TestParty,
    b: TestParty,
    sender: As2,
    to_b: asx::Partner,
    loopback: Loopback,
    inbound: asx::Inbound,
    delivered: Delivered,
}

/// An AS2 receive endpoint for `b` with its own dedup and handler count.
fn as2_inbound(
    ca: &TestCa,
    a: &TestParty,
    b: &TestParty,
    loopback: &Loopback,
) -> (asx::Inbound, Delivered) {
    let receiver = As2::builder(Profile::as2())
        .local(b.local())
        .trust_anchor(ca.anchor())
        .partner(a.partner(AS2_A_URL))
        .http_client(loopback.clone())
        .build()
        .expect("AS2 receiver");
    let delivered = Delivered::default();
    let inbound = {
        let delivered = delivered.clone();
        receiver.inbound(MemoryDedup::default(), move |m: Verified<Received>| {
            let delivered = delivered.clone();
            async move {
                delivered.lock().unwrap().push(m.payload().bytes().to_vec());
                Ok::<(), Reject>(())
            }
        })
    };
    (inbound, delivered)
}

/// The payloads an AS2 handler received.
type Delivered = Arc<std::sync::Mutex<Vec<Vec<u8>>>>;

fn as2_pair_with(to_b: impl FnOnce(&TestParty) -> asx::Partner) -> As2Pair {
    let ca = TestCa::new("asx-test AS2 root", KeyAlg::Rsa2048);
    let a = ca.as2_party("asx-fuzz-a");
    let b = ca.as2_party("asx-fuzz-b");
    let loopback = Loopback::new();
    let to_b = to_b(&b);
    let sender = As2::builder(Profile::as2())
        .local(a.local())
        .trust_anchor(ca.anchor())
        .partner(to_b.clone())
        .http_client(loopback.clone())
        .build()
        .expect("AS2 sender");
    let (inbound, delivered) = as2_inbound(&ca, &a, &b, &loopback);
    loopback.mount(AS2_B_URL, inbound.clone());
    As2Pair {
        ca,
        a,
        b,
        sender,
        to_b,
        loopback,
        inbound,
        delivered,
    }
}

fn as2_pair() -> As2Pair {
    as2_pair_with(|b| b.partner(AS2_B_URL))
}

fn as2_message(p: &As2Pair) -> asx::as2::Message {
    asx::as2::Message::to(
        &p.to_b,
        Payload::new(&b"fuzz-original"[..], "application/edi-x12"),
    )
}

/// The control: a genuine signed-and-encrypted AS2 message is delivered and
/// answered with a verified MDN.
#[tokio::test]
async fn a_genuine_as2_message_is_accepted() {
    let p = as2_pair();
    p.sender.send(as2_message(&p)).await.expect("verified MDN");
    assert_eq!(
        *p.delivered.lock().unwrap(),
        vec![b"fuzz-original".to_vec()]
    );
}

#[tokio::test]
async fn fuzz_smoke_as2_inbound_does_not_panic() {
    let p = as2_pair();
    for i in 0..256usize {
        let body = pseudo_random_bytes(0xA5A5_0000_u64 + i as u64, i % 1024);
        let request = http::Request::post(AS2_B_URL)
            .header(
                "Content-Type",
                "application/pkcs7-mime; smime-type=enveloped-data",
            )
            .header("AS2-From", "asx-fuzz-a")
            .header("AS2-To", "asx-fuzz-b")
            .header("Message-ID", format!("<fuzz-{i}@asx.test>"))
            .body(bytes::Bytes::from(body))
            .unwrap();
        inbound_harness::post(&p.inbound, request)
            .await
            .assert_well_formed();
    }
    assert!(p.delivered.lock().unwrap().is_empty());
}

/// A genuine AS2 message with one base64 digit of its EnvelopedData
/// changed: never a 5xx, and never delivered with altered content. The
/// EnvelopedData is not authenticated (a change in, say, the sender's own
/// `RecipientInfo` is harmless and the message is still processed); the
/// signature inside is what must catch a change to the content, so most
/// changes are refused.
#[tokio::test]
async fn an_as2_message_with_a_changed_digit_is_refused_or_intact() {
    let p = as2_pair();
    p.sender.send(as2_message(&p)).await.expect("genuine");
    let genuine = p.loopback.last_request().unwrap();
    let body = genuine.body().to_vec();
    // Past the MIME headers, outside the final base64 quantum; a flipped line
    // break would simply be ignored, so one digit becomes another.
    let digits = body.len() / 4..body.len() - 8;
    let (mut refused, mut processed) = (0, 0);
    for offset in digits
        .step_by(97)
        .filter(|&i| body[i].is_ascii_alphanumeric())
    {
        let mut tampered = body.clone();
        tampered[offset] = match tampered[offset] {
            b'Z' => b'A',
            b'z' => b'a',
            b'9' => b'0',
            c => c + 1,
        };
        let (fresh, delivered) = as2_inbound(&p.ca, &p.a, &p.b, &p.loopback);
        let mut request = http::Request::new(bytes::Bytes::from(tampered));
        *request.method_mut() = http::Method::POST;
        *request.uri_mut() = genuine.uri().clone();
        *request.headers_mut() = genuine.headers().clone();
        let answer = inbound_harness::post(&fresh, request).await;
        answer.assert_well_formed();
        let delivered = delivered.lock().unwrap().clone();
        if delivered.is_empty() {
            assert!(
                answer.status.is_client_error() || answer.body.contains("error"),
                "offset {offset}: refused without saying so: {answer:?}"
            );
            refused += 1;
        } else {
            assert_eq!(
                delivered,
                vec![b"fuzz-original".to_vec()],
                "offset {offset}"
            );
            processed += 1;
        }
    }
    assert!(
        refused > processed,
        "refused {refused}, processed {processed}"
    );
}

/// A message encrypted to another party's certificate: `decryption-failed`.
#[tokio::test]
async fn an_as2_message_for_another_recipient_is_refused() {
    let other = TestCa::new("other AS2 root", KeyAlg::Rsa2048).as2_party("asx-fuzz-b");
    let p = as2_pair_with(|b| {
        asx::Partner::new(&b.id)
            .endpoint(AS2_B_URL)
            .signing_cert(b.signing.certificate())
            .encryption_cert(other.encryption.certificate())
    });
    let err = p
        .sender
        .send(as2_message(&p))
        .await
        .expect_err("not decryptable by b");
    assert!(
        err.mdn_disposition()
            .is_some_and(|d| d.contains("decryption-failed")),
        "{err}"
    );
    assert!(p.delivered.lock().unwrap().is_empty());
}
