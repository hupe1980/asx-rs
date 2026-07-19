#![cfg(all(feature = "as2", feature = "as4", feature = "testing"))]

#[path = "common/as2_verifier.rs"]
mod common;

use asx_rs::as2::{
    As2MdnMode, As2ReceiveMdnRequest, As2ReceivePolicy, receive_sync as as2_receive,
    receive_with_mdn_with_reliability,
};
use asx_rs::as4::{
    As4PushPolicy, As4ReceivePushRequest, As4ReceivePushSyncRequest, receive_push_with_dedup_sync,
};
use asx_rs::core::SessionContext;
use asx_rs::lifecycle::TrustEvidence;
use asx_rs::observability::EventBus;
use common::DeterministicTrustVerifier as InsecureBypassTrustVerifier;

fn session() -> SessionContext {
    SessionContext::new("fuzz-s1", "partner-fuzz", "strict").expect("session")
}

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

fn trust_from_verdicts(signature_ok: bool, decryption_ok: bool) -> TrustEvidence {
    match (signature_ok, decryption_ok) {
        (true, true) => TrustEvidence::verified_and_decryptable(),
        (false, _) => TrustEvidence::signature_failed(),
        (true, false) => TrustEvidence::missing_decryption_material(),
    }
}

#[test]
fn fuzz_smoke_as2_receive_paths_do_not_panic() {
    let s = session();
    let bus = EventBus::new(64).expect("bus");

    for i in 0..256usize {
        let payload = pseudo_random_bytes(0xA5A5_0000_u64 + i as u64, i % 1024);
        let mdn = pseudo_random_bytes(0xC3C3_1000_u64 + i as u64, (i * 3) % 2048);
        let hook = asx_rs::reliability::InMemoryReconciliationHook::default();
        let dedup = asx_rs::reliability::InMemoryDedupBackend::default();
        let verifier =
            InsecureBypassTrustVerifier::new(trust_from_verdicts(i % 2 == 0, i % 3 != 0));
        let _ = as2_receive(&s, payload.clone(), &verifier);
        let _ = receive_with_mdn_with_reliability(
            &s,
            &bus,
            As2ReceiveMdnRequest {
                payload: payload.into(),
                mdn_payload: mdn.into(),
                mdn_mode: As2MdnMode::Synchronous,
                require_signed_mdn: false,
                expected_mic: None,
                policy: As2ReceivePolicy::default(),
                original_message_id: None,
            },
            &hook,
            &dedup,
            &verifier,
        );
    }
}

#[test]
fn fuzz_smoke_as4_receive_paths_do_not_panic() {
    let s = session();
    let bus = EventBus::new(64).expect("bus");

    for i in 0..256usize {
        let payload = pseudo_random_bytes(0xDEAD_2000_u64 + i as u64, i % 2048);
        let receipt = pseudo_random_bytes(0xBEEF_3000_u64 + i as u64, i % 1024);
        let dedup = asx_rs::reliability::InMemoryDedupBackend::default();

        let _ = receive_push_with_dedup_sync(
            &s,
            &bus,
            As4ReceivePushSyncRequest {
                request: As4ReceivePushRequest {
                    http_content_type: "multipart/related".into(),
                    payload: payload.into(),
                    receipt_payload: Some(receipt),
                    policy: As4PushPolicy::default(),
                    authenticated_sender_scope: None,
                },
                dedup_backend: &dedup,
            },
        );
    }
}
