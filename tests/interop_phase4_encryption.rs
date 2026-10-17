#![cfg(all(feature = "as4", feature = "http-client"))]
//! phase4 as the live counterparty for AS4 payload encryption: signed,
//! compressed and **encrypted** BDEW business messages (ECDH-ES + ConcatKDF on BrainpoolP256r1, SKI recipient, the WSS
//! SwA envelope) in both directions, two payloads each, receipts verified as
//! NRR evidence on both sides, and a ciphertext tamper per direction.
//!
//! Runs on the phase4 harness (`common/phase4/`); `#[ignore]`d, needs Docker:
//!
//! ```text
//! just interop
//! ASX_PHASE4_IMAGE=$(docker build -q tests/fixtures/phase4) cargo test --all-features --test interop_phase4_encryption -- --ignored --nocapture
//! ```
//!
//! The RSA-OAEP cases (`cef` vs `edelivery_1_15()`) are not covered here.
//!
//! # phase4 → crate encrypted
//!
//! `Phase4BDEWSender` (phase4 4.8.1) on its own sets `ECDH_ES_KEYWRAP_AES_128`
//! as a *key transport* algorithm with `setEncryptSymmetricSessionKey(false)`
//! and no WSS4J key-agreement method (`AS4Encryptor` configures ECDH-ES only
//! when `AS4CryptParams#hasKeyAgreementMethod()`), which yields an
//! `xenc:EncryptedData` with an empty `ds:KeyInfo` and no `xenc:EncryptedKey`
//! that nobody can decrypt. The peer's `ControlHandler` therefore sets
//! `ECDH_ES` + `CONCAT_KDF` + `AES_128` key wrap + encrypted session key +
//! X509 SKI on the builder's `cryptParams()`; phase4 then emits one
//! `xenc:EncryptedKey` (kw-aes128, `xenc11:AgreementMethod` ECDH-ES with
//! ConcatKDF/SHA-256, `OriginatorKeyInfo` ECKeyValue on brainpoolP256r1,
//! `RecipientKeyInfo/X509SKI`) carrying the `ReferenceList`, and one SwA
//! `EncryptedData` per part (`bdew_from_phase4_wire_shape`).

#[path = "common/phase4/mod.rs"]
mod phase4;

use phase4::exchange::{
    Case, Expectation, crate_to_phase4, edifact_payload, expect, phase4_to_crate,
    tampered_crate_to_phase4, tampered_phase4_to_crate,
};
use phase4::http::Tamper;
use phase4::inbound::CrateInbound;
use phase4::peer::{PeerConfig, PeerSendRequest, Phase4Peer, TestPayload};
use phase4::pki::RunPki;
use phase4::variant::ProfileVariant;
use std::time::Duration;

async fn start(variant: ProfileVariant) -> (Phase4Peer, RunPki) {
    let pki = RunPki::generate(&variant);
    let peer = Phase4Peer::start(PeerConfig {
        variants: vec![variant],
        pki: vec![(variant, &pki)],
        ..PeerConfig::default()
    })
    .await
    .unwrap_or_else(|e| panic!("{e}"));
    (peer, pki)
}

async fn crate_inbound(peer: &Phase4Peer, pki: &RunPki, v: &ProfileVariant) -> CrateInbound {
    let as4 = phase4::exchange::crate_client(
        pki,
        v,
        peer.http_client(),
        asx_testkit::audit::MemoryAuditSink::new(),
    )
    .unwrap_or_else(|e| panic!("{e}"));
    CrateInbound::start(&as4)
        .await
        .unwrap_or_else(|e| panic!("{e}"))
}

/// Two business payloads (MSCONS-like second part).
fn two_payloads() -> Case {
    Case::Payloads(vec![
        edifact_payload(),
        TestPayload {
            mime_type: "application/octet-stream".into(),
            bytes: b"UNA:+.? 'UNB+UNOC:3+9900000000001:500+9900000000002:500+261016:1201+ASX2'UNH+1+MSCONS:D:04B:UN:2.4c'UNT+2+1'UNZ+1+ASX2'".to_vec(),
        },
    ])
}

/// crate → phase4: phase4 decrypts both parts (SKI-referenced ECDH-ES key,
/// SwA `CipherReference`s), verifies the crate's signature over the
/// decrypted parts and returns a signed receipt `As4::send` verifies as NRR
/// evidence.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs Docker and the phase4 peer: just interop"]
async fn bdew_to_phase4() {
    let v = ProfileVariant::Bdew;
    let (peer, pki) = start(v).await;
    let result = crate_to_phase4(&peer, &pki, &v, &two_payloads()).await;
    if let Ok(evidence) = &result {
        println!(
            "phase4 decrypted and receipted {} ({} NRR digests)",
            evidence.message_id,
            evidence.audit["signal"]["nrr"]
                .as_array()
                .map_or(0, Vec::len)
        );
    }
    expect(result, Expectation::Pass, &peer.log().await);
}

/// phase4 → crate: the crate authenticates, decrypts phase4's envelope
/// (standalone `xenc:ReferenceList`), verifies the `cid:` digests over the
/// decrypted parts, delivers both and answers with a receipt phase4 accepts.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs Docker and the phase4 peer: just interop"]
async fn bdew_from_phase4() {
    let v = ProfileVariant::Bdew;
    let (peer, pki) = start(v).await;
    let inbound = crate_inbound(&peer, &pki, &v).await;
    let result = phase4_to_crate(&peer, &pki, &inbound, &v, &two_payloads(), true).await;
    if let Ok(evidence) = &result {
        println!(
            "the crate decrypted {} and phase4 accepted its receipt ({} NRR entries)",
            evidence.message_id, evidence.nrr_count
        );
    }
    expect(result, Expectation::Pass, &peer.log().await);
}

/// One ciphertext byte flipped on the way to phase4: refused, nothing
/// delivered (the untampered message is receipted first).
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs Docker and the phase4 peer: just interop"]
async fn tampered_to_phase4_is_refused() {
    let v = ProfileVariant::Bdew;
    let (peer, pki) = start(v).await;
    let result = tampered_crate_to_phase4(
        &peer,
        &pki,
        &v,
        &two_payloads(),
        Tamper::FlipByteInCiphertext,
    )
    .await;
    expect(result, Expectation::Pass, &peer.log().await);
}

/// One ciphertext byte of an encrypted phase4 push flipped before the
/// crate's `Inbound`: EBMS:0102, no handler call (the untampered replay is
/// receipted).
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs Docker and the phase4 peer: just interop"]
async fn tampered_from_phase4_is_refused() {
    let v = ProfileVariant::Bdew;
    let (peer, pki) = start(v).await;
    let inbound = crate_inbound(&peer, &pki, &v).await;
    let result = tampered_phase4_to_crate(
        &peer,
        &inbound,
        &v,
        &two_payloads(),
        true,
        Tamper::FlipByteInCiphertext,
    )
    .await;
    expect(result, Expectation::Pass, &peer.log().await);
}

/// The shape phase4 puts on the wire for an encrypted BDEW push (BDEW
/// AS4-Profil 2.2.6.2.2): one `xenc:EncryptedKey` (kw-aes128) whose
/// `ds:KeyInfo` holds an ECDH-ES `xenc11:AgreementMethod` with ConcatKDF and
/// the recipient referenced by X509 SKI, and one `EncryptedData` per
/// payload part. The capture is then fed to the crate, which must receipt
/// it.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs Docker and the phase4 peer: just interop"]
async fn bdew_from_phase4_wire_shape() {
    let v = ProfileVariant::Bdew;
    let (peer, pki) = start(v).await;
    let inbound = crate_inbound(&peer, &pki, &v).await;
    let _ = peer
        .send(PeerSendRequest {
            variant: v,
            to_url: inbound.capture_url(),
            message_id: format!("{}@asx.phase4.test", uuid::Uuid::new_v4()),
            ping: false,
            payloads: two_payloads().payloads(),
            encrypt: true,
        })
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    let captured = inbound
        .take_capture(Duration::from_secs(15))
        .await
        .expect("phase4 sent nothing to /capture");
    let body = String::from_utf8_lossy(&captured.body);
    let start = body.find("<wsse:Security").expect("wsse:Security");
    let end = body[start..].find("</wsse:Security>").expect("end") + start;
    let header = &body[start..end];
    println!("phase4 r2 wsse:Security:\n{header}");
    for needle in [
        "<xenc:EncryptedKey ",
        "Algorithm=\"http://www.w3.org/2001/04/xmlenc#kw-aes128\"",
        "AgreementMethod Algorithm=\"http://www.w3.org/2009/xmlenc11#ECDH-ES\"",
        "Algorithm=\"http://www.w3.org/2009/xmlenc11#ConcatKDF\"",
        "<xenc:RecipientKeyInfo><ds:X509Data><ds:X509SKI>",
        "<xenc:ReferenceList>",
    ] {
        assert!(
            header.contains(needle),
            "missing {needle} in phase4's wsse:Security"
        );
    }
    assert_eq!(header.matches("<xenc:EncryptedKey ").count(), 1);
    assert_eq!(
        header.matches("<xenc:EncryptedData ").count(),
        2,
        "one SwA EncryptedData per payload part"
    );
    let response = inbound.feed(&captured).await;
    assert!(
        response.is_receipt(),
        "the crate did not receipt phase4's encrypted push: {} {}",
        response.status,
        response.text()
    );
}
