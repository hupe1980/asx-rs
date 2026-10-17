#![cfg(all(feature = "as4", feature = "http-client"))]
//! phase4 as the live counterparty: the BDEW witness.
//!
//! phase4 (an independent, WSS4J/Santuario-based AS4 stack with its own BDEW
//! profile validator) runs in a digest-pinned container; the harness in
//! `common/phase4/` drives exchanges with `Profile::bdew()` in both
//! directions through the public API and asserts the evidence on both sides
//! (receipts verified as NRR evidence, phase4's inbox, the crate's handler).
//!
//! The image-pin, tamper-locator and expectation unit tests run in every
//! `cargo test`. The exchanges need Docker and are `#[ignore]`d:
//!
//! ```text
//! just interop
//! # or, against a locally built peer:
//! ASX_PHASE4_IMAGE=$(docker build -q tests/fixtures/phase4) cargo test --all-features --test interop_phase4_counterparty -- --ignored --nocapture
//! ```
//!
//! # What this file covers
//!
//! The signed BDEW cases: the test-service ping both ways (receipts verified
//! as NRR evidence on both sides) and the signed-byte tampers both ways, plus
//! the refusal of an unencrypted BDEW payload. The encrypted business round
//! trips and the ciphertext tampers are in `interop_phase4_encryption.rs`,
//! on this harness.
//!
//! Every payload `As4::send` sends under `Profile::bdew()` is encrypted and
//! compressed (the preset has no sign-only setting, and its ping must carry a
//! payload), so the crate → phase4 ping is signed, encrypted and compressed.
//! phase4's sender encrypts only when given a receiver certificate, so the
//! phase4 → crate ping is signed and compressed. A failure of these cases is
//! a defect report against the crate, not a known gap.

#[path = "common/phase4/mod.rs"]
mod phase4;

use phase4::exchange::{
    Case, Expectation, crate_to_phase4, edifact_payload, expect, phase4_to_crate,
    refused_phase4_to_crate, tampered_crate_to_phase4, tampered_phase4_to_crate,
};
use phase4::http::Tamper;
use phase4::inbound::CrateInbound;
use phase4::peer::{PeerConfig, Phase4Peer};
use phase4::pki::RunPki;
use phase4::variant::ProfileVariant;

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

// ── RunPki: no Docker ──────────────────────────────────────────────────────

#[test]
fn pki_bdew_builds_under_the_bdew_preset() {
    let v = ProfileVariant::Bdew;
    let pki = RunPki::generate(&v);
    asx::as4::As4::builder(v.profile())
        .local(pki.local_party(&v))
        .trust_anchor(pki.anchor())
        .partner(pki.phase4_partner(&v))
        .build()
        .expect("the harness identities pass Profile::bdew() build()");
}

#[test]
fn pki_debug_redacts_private_keys() {
    let pki = RunPki::generate(&ProfileVariant::Bdew);
    let all = format!("{:?} {:?}", pki.crate_side, pki.phase4_side);
    assert!(!all.contains("PRIVATE KEY"), "{all}");
    assert!(all.contains("EMT.MAK"), "{all}");
}

// ── BDEW, signed cases ─────────────────────────────────────────────────────

/// crate → phase4 test-service message (signed, encrypted, compressed: it
/// carries a payload): `Verified<Receipt>` signed by phase4, NRR digests ==
/// signed references in the audit record, phase4 decrypted it and verified
/// the crate's signature.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs Docker and the phase4 peer: just interop"]
async fn bdew_ping_crate_to_phase4() {
    let v = ProfileVariant::Bdew;
    let (peer, pki) = start(v).await;
    let result = crate_to_phase4(&peer, &pki, &v, &Case::Ping).await;
    if let Ok(evidence) = &result {
        println!(
            "phase4 receipted {} ({} NRR digests = signed references)",
            evidence.message_id,
            evidence.audit["signal"]["nrr"]
                .as_array()
                .map_or(0, Vec::len)
        );
    }
    expect(result, Expectation::Pass, &peer.log().await);
}

/// phase4 → crate test-service message: signed and compressed, not
/// encrypted; the crate receipts it (NRR) and never calls the handler;
/// phase4 verifies that receipt.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs Docker and the phase4 peer: just interop"]
async fn bdew_ping_phase4_to_crate() {
    let v = ProfileVariant::Bdew;
    let (peer, pki) = start(v).await;
    let inbound = crate_inbound(&peer, &pki, &v).await;
    let result = phase4_to_crate(&peer, &pki, &inbound, &v, &Case::Ping, false).await;
    if let Ok(evidence) = &result {
        println!(
            "phase4 accepted the crate's receipt for {} ({} NRR entries)",
            evidence.message_id, evidence.nrr_count
        );
    }
    expect(result, Expectation::Pass, &peer.log().await);
}

/// phase4 → crate business message signed and compressed but NOT
/// encrypted: BDEW requires payload encryption (AS4-Profil 1.2 §2.2.6.2.2),
/// so the crate answers with an ebMS error (`EBMS:0103`) and delivers nothing.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs Docker and the phase4 peer: just interop"]
async fn bdew_unencrypted_push_phase4_to_crate_is_refused() {
    let v = ProfileVariant::Bdew;
    let (peer, pki) = start(v).await;
    let inbound = crate_inbound(&peer, &pki, &v).await;
    let case = Case::Payloads(vec![edifact_payload()]);
    let result = refused_phase4_to_crate(&peer, &inbound, &v, &case, false)
        .await
        .and_then(|code| {
            if code == "EBMS:0103" {
                Ok(code)
            } else {
                Err(phase4::HarnessError::case(format!(
                    "refused with {code}, want EBMS:0103"
                )))
            }
        });
    expect(result, Expectation::Pass, &peer.log().await);
}

/// One byte of the crate's signed `eb:Messaging` flipped on the way to
/// phase4: refused (ebMS error → `PartnerError`), nothing delivered; the
/// untampered message is sent first and must be receipted.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs Docker and the phase4 peer: just interop"]
async fn bdew_crate_to_phase4_signed_byte_tampered_is_refused() {
    let v = ProfileVariant::Bdew;
    let (peer, pki) = start(v).await;
    let result = tampered_crate_to_phase4(
        &peer,
        &pki,
        &v,
        &Case::Ping,
        Tamper::FlipByteInSignedMessaging,
    )
    .await;
    expect(result, Expectation::Pass, &peer.log().await);
}

/// A phase4 ping captured and replayed into the crate's `Inbound` with one
/// byte of the signed `eb:Messaging` flipped: ebMS error, no receipt, no
/// handler call (the untampered replay is receipted).
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs Docker and the phase4 peer: just interop"]
async fn bdew_phase4_to_crate_signed_byte_tampered_is_refused() {
    let v = ProfileVariant::Bdew;
    let (peer, pki) = start(v).await;
    let inbound = crate_inbound(&peer, &pki, &v).await;
    let result = tampered_phase4_to_crate(
        &peer,
        &inbound,
        &v,
        &Case::Ping,
        false,
        Tamper::FlipByteInSignedMessaging,
    )
    .await;
    expect(result, Expectation::Pass, &peer.log().await);
}
