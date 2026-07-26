#![cfg(all(
    feature = "as4",
    feature = "testing",
    feature = "client",
    feature = "server"
))]
//! End-to-end AS4 Reception Awareness / Non-Repudiation of Receipt (NRR) tests.
//!
//! These exercise the full outbound loop that regulated AS4 profiles (BDEW
//! AS4-Profil §4.6.3, eDelivery AS4 v1.15 §5.1) require:
//!
//! ```text
//! send_async  →  HTTP POST  →  counterparty MSH  →  signed eb:Receipt
//!                                                   └─ verify_sync_response
//! ```
//!
//! The point of the NRR check is that a receipt is only evidence of delivery
//! when its `MessagePartNRInformation` digests match the digests the *sent*
//! message was signed over.  `nrr_round_trip_is_verified_end_to_end` proves the
//! happy path; `unsigned_receipt_is_rejected_under_the_regulated_policy` proves
//! the library fails closed when the counterparty acknowledges without NRR.

use asx_rs::as4::mock_endpoint::MockAs4Endpoint;
use asx_rs::as4::{
    As4ReceiptPolicy, As4SendPolicyBuilder, As4SendRequest, As4SyncSignal, send_async,
};
use asx_rs::core::{CertHandle, ErrorCode, OcspFailureMode, OcspMode, SessionContextBuilder};
use asx_rs::fixtures::generate_self_signed_rsa_keypair;
use asx_rs::observability::EventBus;
use asx_rs::transport::As4HttpTransport;
use sha2::{Digest, Sha256};

fn fingerprint_hex(cert_pem: &[u8]) -> String {
    let cert = openssl::x509::X509::from_pem(cert_pem).expect("cert pem");
    let der = cert.to_der().expect("cert der");
    Sha256::digest(&der)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Sender session that pins the counterparty's receipt-signing certificate.
fn sender_session(
    signing_cert_pem: &[u8],
    signing_key_pem: &[u8],
    partner_cert_pem: &[u8],
) -> asx_rs::core::SessionContext {
    SessionContextBuilder::new("sender-session", "partner-gln")
        .profile_name("strict")
        .with_signing_material(
            String::from_utf8(signing_cert_pem.to_vec()).expect("utf8 cert"),
            String::from_utf8(signing_key_pem.to_vec()).expect("utf8 key"),
        )
        .cert_handle(CertHandle {
            key_id: "cert:partner-gln".into(),
            fingerprint_sha256: fingerprint_hex(partner_cert_pem),
            trust_anchor_pems: vec![String::from_utf8(partner_cert_pem.to_vec()).expect("utf8")],
            intermediate_ca_pems: vec![],
            revocation_crl_pems: vec![],
            ocsp_mode: OcspMode::Disabled,
            ocsp_failure_mode: OcspFailureMode::HardFail,
            stapled_ocsp_responses_der: vec![],
            responder_ocsp_responses_der: vec![],
            signing_cert_pem: Some(
                String::from_utf8(signing_cert_pem.to_vec()).expect("utf8 cert"),
            ),
            signing_key_pem: Some(zeroize::Zeroizing::new(
                String::from_utf8(signing_key_pem.to_vec()).expect("utf8 key"),
            )),
            recipient_cert_pem: None,
        })
        .build()
        .expect("sender session")
}

fn send_request(
    message_id: &str,
    signing_cert_pem: &[u8],
    signing_key_pem: &[u8],
) -> As4SendRequest {
    let (policy, credentials) = As4SendPolicyBuilder::new()
        .action("urn:test:as4:action")
        .service("urn:test:as4:service", "")
        .signing_cert_pem(signing_cert_pem.to_vec())
        .signing_key_pem(signing_key_pem.to_vec())
        .build()
        .expect("send policy");

    As4SendRequest {
        message_id: message_id.into(),
        payload: b"UNB+UNOC:3+sender+receiver+260726:1200+1'".to_vec(),
        policy,
        credentials: Some(credentials),
        payload_filename: None,
    }
}

#[tokio::test]
async fn nrr_round_trip_is_verified_end_to_end() {
    let (sender_cert, sender_key) = generate_self_signed_rsa_keypair("as4-sender", 2048);
    let (receiver_cert, receiver_key) = generate_self_signed_rsa_keypair("as4-receiver", 2048);

    let endpoint = MockAs4Endpoint::builder()
        .with_receipt_signing_material(receiver_cert.clone(), receiver_key.clone())
        .bind("127.0.0.1:0")
        .await
        .expect("bind mock endpoint");

    let session = sender_session(&sender_cert, &sender_key, &receiver_cert);
    let bus = EventBus::new_for_testing();
    let sent = send_async(
        &session,
        &bus,
        send_request(
            "urn:uuid:nrr-round-trip@asx.test",
            &sender_cert,
            &sender_key,
        ),
    )
    .await
    .expect("send_async");

    let transport = As4HttpTransport::new_for_localhost_testing().expect("transport");
    let outcome = transport
        .send_and_verify_to_localhost(
            &endpoint.local_url(),
            &session,
            &bus,
            &sent,
            &As4ReceiptPolicy::regulated(),
        )
        .await
        .expect("send_and_verify");

    assert_eq!(outcome.http.status, 200);

    let receipt = outcome
        .into_receipt()
        .expect("a receipt, not an error signal");
    assert!(
        receipt.is_non_repudiation_evidence(),
        "regulated policy must yield signed + digest-verified NRR evidence"
    );
    assert_eq!(receipt.ref_to_message_id, sent.message_id);
    assert!(receipt.signed);
    assert!(
        !receipt.non_repudiation.references().is_empty(),
        "the receipt must echo the sent message's ds:References"
    );
    assert_eq!(
        receipt.signer_fingerprint_sha256.as_deref(),
        Some(fingerprint_hex(&receiver_cert).as_str())
    );
}

#[tokio::test]
async fn unsigned_receipt_is_rejected_under_the_regulated_policy() {
    let (sender_cert, sender_key) = generate_self_signed_rsa_keypair("as4-sender-2", 2048);
    let (receiver_cert, _receiver_key) = generate_self_signed_rsa_keypair("as4-receiver-2", 2048);

    // No receipt signing material → the mock replies with a plain, unsigned
    // receipt carrying an empty <NonRepudiationInformation/>.
    let endpoint = MockAs4Endpoint::bind("127.0.0.1:0")
        .await
        .expect("bind mock endpoint");

    let session = sender_session(&sender_cert, &sender_key, &receiver_cert);
    let bus = EventBus::new_for_testing();
    let sent = send_async(
        &session,
        &bus,
        send_request("urn:uuid:nrr-unsigned@asx.test", &sender_cert, &sender_key),
    )
    .await
    .expect("send_async");

    let transport = As4HttpTransport::new_for_localhost_testing().expect("transport");
    let err = transport
        .send_and_verify_to_localhost(
            &endpoint.local_url(),
            &session,
            &bus,
            &sent,
            &As4ReceiptPolicy::regulated(),
        )
        .await
        .expect_err("an unsigned receipt is not NRR evidence");

    assert_eq!(err.code, ErrorCode::SecurityVerificationFailed);
}

#[tokio::test]
async fn unsigned_receipt_is_accepted_under_the_relaxed_policy() {
    let (sender_cert, sender_key) = generate_self_signed_rsa_keypair("as4-sender-3", 2048);
    let (receiver_cert, _receiver_key) = generate_self_signed_rsa_keypair("as4-receiver-3", 2048);

    let endpoint = MockAs4Endpoint::bind("127.0.0.1:0")
        .await
        .expect("bind mock endpoint");

    let session = sender_session(&sender_cert, &sender_key, &receiver_cert);
    let bus = EventBus::new_for_testing();
    let sent = send_async(
        &session,
        &bus,
        send_request("urn:uuid:nrr-relaxed@asx.test", &sender_cert, &sender_key),
    )
    .await
    .expect("send_async");

    let transport = As4HttpTransport::new_for_localhost_testing().expect("transport");
    let outcome = transport
        .send_and_verify_to_localhost(
            &endpoint.local_url(),
            &session,
            &bus,
            &sent,
            &As4ReceiptPolicy::relaxed(),
        )
        .await
        .expect("relaxed policy accepts an unsigned acknowledgement");

    let As4SyncSignal::Receipt(receipt) = outcome.signal else {
        panic!("expected a receipt");
    };
    assert!(!receipt.signed);
    assert!(
        !receipt.is_non_repudiation_evidence(),
        "an unsigned receipt must never be reported as NRR evidence"
    );
}

#[tokio::test]
async fn receipt_for_a_different_message_is_rejected() {
    let (sender_cert, sender_key) = generate_self_signed_rsa_keypair("as4-sender-4", 2048);
    let (receiver_cert, receiver_key) = generate_self_signed_rsa_keypair("as4-receiver-4", 2048);

    let endpoint = MockAs4Endpoint::builder()
        .with_receipt_signing_material(receiver_cert.clone(), receiver_key)
        .bind("127.0.0.1:0")
        .await
        .expect("bind mock endpoint");

    let session = sender_session(&sender_cert, &sender_key, &receiver_cert);
    let bus = EventBus::new_for_testing();

    // Send message A, then verify its receipt against a *different* sent
    // message B: correlation must fail even though the receipt is valid.
    let sent_a = send_async(
        &session,
        &bus,
        send_request("urn:uuid:nrr-a@asx.test", &sender_cert, &sender_key),
    )
    .await
    .expect("send_async A");
    let sent_b = send_async(
        &session,
        &bus,
        send_request("urn:uuid:nrr-b@asx.test", &sender_cert, &sender_key),
    )
    .await
    .expect("send_async B");

    let transport = As4HttpTransport::new_for_localhost_testing().expect("transport");
    let response = transport
        .send_to_localhost(&endpoint.local_url(), &sent_a)
        .await
        .expect("send A");

    let err = asx_rs::as4::verify_sync_response(
        &session,
        &bus,
        &sent_b,
        &response.body,
        "application/soap+xml",
        &As4ReceiptPolicy::regulated(),
    )
    .expect_err("a receipt for message A must not acknowledge message B");

    assert_eq!(err.code, ErrorCode::InteropViolation);
}
