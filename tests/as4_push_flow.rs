#![cfg(feature = "as4")]
//! AS4 one-way push end to end: a real `As4::send` against a real partner
//! `Inbound`, through the testkit `Loopback`. Receipt verification is in
//! `as4_receipt_verification.rs` and `as4_send.rs`; dedup outcomes are in
//! `as4_receive.rs`.

#[path = "common/inbound_harness.rs"]
mod inbound_harness;
#[path = "common/peers.rs"]
mod peers;

use asx::ErrorKind;
use peers::{AS4_PRESETS, B_URL, Preset, pair, soap_part};
use std::sync::atomic::Ordering;

/// Every preset: the handler sees the sent ebMS fields and payload, the wire
/// carries a signed `eb:Messaging` that must be understood, and the sender
/// holds a receipt signed by the partner for exactly this message.
#[tokio::test]
async fn signed_push_is_delivered_and_receipted() {
    for preset in AS4_PRESETS {
        let p = pair(preset);
        let id = format!("push-flow-{preset:?}@asx.test");
        let receipt = p
            .sender
            .send(
                preset
                    .message(&p.to_b, b"push-flow-payload")
                    .message_id(&id),
            )
            .await
            .unwrap_or_else(|e| panic!("{preset:?}: {e}"));

        let soap = soap_part(p.loopback.last_request().unwrap().body());
        assert!(
            soap.contains("Messaging soap:mustUnderstand=\"true\""),
            "{preset:?}"
        );
        assert!(
            soap.contains("<ds:Reference URI=\"#as4-messaging\">"),
            "{preset:?}"
        );
        assert!(soap.contains("<ds:SignatureValue>"), "{preset:?}");

        let delivered = p.delivered.lock().unwrap().clone();
        assert_eq!(delivered.len(), 1, "{preset:?}");
        let (message_id, from, payloads) = &delivered[0];
        assert_eq!(message_id, &id, "{preset:?}");
        assert_eq!(from, &p.a.id, "{preset:?}");
        assert_eq!(payloads, &vec![b"push-flow-payload".to_vec()], "{preset:?}");

        assert_eq!(receipt.signer(), &p.b.signing.certificate(), "{preset:?}");
        let signal = String::from_utf8(receipt.evidence().signal().unwrap().to_vec()).unwrap();
        assert!(
            signal.contains(&format!("RefToMessageId>{id}<")),
            "{preset:?}: {signal}"
        );
    }
}

/// The receive half: a push stripped of its signature is refused before the
/// handler, with an ebMS error the sender can read.
#[tokio::test]
async fn push_missing_signature_is_refused() {
    let g = inbound_harness::genuine(Preset::Edelivery).await;
    let r = g.receiver();
    let unsigned = g.mutated(|s| {
        let start = s.find("<ds:Signature").expect("signature");
        let end = s.find("</ds:Signature>").expect("signature end") + "</ds:Signature>".len();
        format!("{}{}", &s[..start], &s[end..])
    });
    // Unsigned where a signature is required is EBMS:0103.
    r.refused(unsigned, "EBMS:0103")
        .await
        .assert_refused_because("EBMS:0103", "signature is required but not present");
}

/// A receipt whose `ds:SignatureValue` was altered in transit is not
/// evidence: `Indeterminate`, with the evidence kept for the record.
#[tokio::test]
async fn forged_receipt_signature_is_indeterminate() {
    let p = pair(Preset::Edelivery);
    p.loopback.intercept(|resp| {
        let text = String::from_utf8(resp.body().to_vec()).unwrap();
        let at = text.find("SignatureValue>").unwrap() + "SignatureValue>".len();
        let mut bytes = text.into_bytes();
        bytes[at] = if bytes[at] == b'A' { b'B' } else { b'A' };
        *resp.body_mut() = bytes::Bytes::from(bytes);
    });
    let err = p
        .sender
        .send(Preset::Edelivery.message(&p.to_b, b"x"))
        .await
        .expect_err("forged receipt");
    assert_eq!(err.kind(), ErrorKind::Indeterminate, "{err}");
    assert!(err.is_retryable());
    assert!(err.evidence().is_some());
    // The partner did take the message: the sender cannot know, hence
    // Indeterminate rather than PartnerError.
    assert_eq!(p.calls.load(Ordering::SeqCst), 1);
}

/// A receipt validly signed by a certificate from another CA, carried in the
/// receipt's own token: neither chained to the trust anchor nor pinned.
#[tokio::test]
async fn receipt_signed_by_an_untrusted_certificate_is_indeterminate() {
    use base64::Engine;
    let p = pair(Preset::Edelivery);
    let foreign = asx_testkit::pki::TestCa::new("foreign root", asx_testkit::pki::KeyAlg::Rsa2048)
        .rsa_party("party-b");
    let token =
        base64::engine::general_purpose::STANDARD.encode(foreign.signing.certificate().der());
    let signer = foreign.signing.clone();
    p.loopback.intercept(move |resp| {
        let text = String::from_utf8(resp.body().to_vec()).unwrap();
        let open = text.find("<wsse:BinarySecurityToken").unwrap();
        let start = open + text[open..].find('>').unwrap() + 1;
        let end = start + text[start..].find('<').unwrap();
        let swapped = format!("{}{token}{}", &text[..start], &text[end..]);
        let resigned = inbound_harness::resign(&swapped, &[], &signer);
        *resp.body_mut() = bytes::Bytes::from(resigned);
    });
    let err = p
        .sender
        .send(Preset::Edelivery.message(&p.to_b, b"x"))
        .await
        .expect_err("untrusted receipt signer");
    assert_eq!(err.kind(), ErrorKind::Indeterminate, "{err}");
    assert!(err.evidence().is_some());
}

/// A `DedupStore` whose every answer arrives after several yields, on the
/// real receive path under a multi-thread runtime: the claim is driven to
/// completion (not polled once), and the retransmission is a duplicate.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn async_backed_dedup_works_on_the_receive_path() {
    use asx::{BoxFuture, Claim, ClaimToken, DedupStore};
    use std::collections::HashMap;
    use std::sync::Mutex;

    type StoreResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

    /// key → (lease, accepted)
    #[derive(Debug, Default)]
    struct AsyncYieldingDedup {
        state: Mutex<HashMap<String, (String, bool)>>,
        leases: std::sync::atomic::AtomicUsize,
    }

    impl DedupStore for AsyncYieldingDedup {
        fn claim<'a>(&'a self, key: &'a str) -> BoxFuture<'a, StoreResult<Claim>> {
            Box::pin(async move {
                for _ in 0..4 {
                    tokio::task::yield_now().await;
                }
                let mut state = self.state.lock().unwrap();
                Ok(match state.get(key) {
                    Some((_, true)) => Claim::Duplicate,
                    Some((_, false)) => Claim::InFlight,
                    None => {
                        let lease = format!("lease-{}", self.leases.fetch_add(1, Ordering::SeqCst));
                        state.insert(key.to_string(), (lease.clone(), false));
                        Claim::Claimed(ClaimToken::new(lease))
                    }
                })
            })
        }

        fn accept<'a>(
            &'a self,
            key: &'a str,
            token: &'a ClaimToken,
        ) -> BoxFuture<'a, StoreResult<()>> {
            Box::pin(async move {
                tokio::task::yield_now().await;
                let mut state = self.state.lock().unwrap();
                match state.get_mut(key) {
                    Some((lease, accepted)) if lease == token.as_str() => {
                        *accepted = true;
                        Ok(())
                    }
                    _ => Err("stale claim".into()),
                }
            })
        }

        fn abandon<'a>(
            &'a self,
            key: &'a str,
            token: &'a ClaimToken,
        ) -> BoxFuture<'a, StoreResult<()>> {
            Box::pin(async move {
                tokio::task::yield_now().await;
                let mut state = self.state.lock().unwrap();
                if matches!(state.get(key), Some((lease, false)) if lease == token.as_str()) {
                    state.remove(key);
                }
                Ok(())
            })
        }
    }

    let p = pair(Preset::Edelivery);
    let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let handler = {
        let calls = calls.clone();
        move |_m: asx::Verified<asx::as4::UserMessage>| {
            let calls = calls.clone();
            async move {
                calls.fetch_add(1, Ordering::SeqCst);
                Ok::<(), asx::Reject>(())
            }
        }
    };
    p.loopback.mount(
        B_URL,
        p.receiver.inbound(AsyncYieldingDedup::default(), handler),
    );
    let message = Preset::Edelivery
        .message(&p.to_b, b"yielding")
        .message_id("yielding-dedup@asx.test");
    p.sender
        .send(message.clone())
        .await
        .expect("first delivery");
    // The retransmission is answered as a duplicate, not delivered.
    p.sender.send(message).await.expect("duplicate receipted");
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}
