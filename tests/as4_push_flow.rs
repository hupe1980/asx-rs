#![cfg(all(feature = "as4", feature = "testing"))]
//! AS4 push message receive flow end-to-end tests.
//!
//! **P0 Coverage (cryptographically-signed receipt handling):**
//! - Receipt signature verification with real XMLDSig + X.509 trust anchors
//! - RefToMessageId semantic validation (mismatch detected post-crypto-verify)
//! - Trust anchor enforcement (receipts from untrusted certs rejected)
//! - Negative path: forged/tampered signatures, namespace confusion
//!
//! **P1 Blocking Items (documented below):**
//! 1. **MIME attachment payload packaging** (blocking strict Peppol/CEF conformance)
//!    Currently: payloads embedded in SOAP `<asx:Base64>` within Body element
//!    Required: Standard MIME multipart attachment packaging with Content-ID references
//!    Impact: Strict AP networks expect MIME attachments per OpenPeppol AS4 profile
//!    See: FINDINGS.md Section 0 and critical finding #3
//!
//! 2. **Dynamic SMP-driven P-Mode materialization**
//!    Required for strict profile compliance: automatic endpoint/cert/service discovery
//!    See: FINDINGS.md P1 outcome #2

#[path = "common/as4_push.rs"]
mod common;

use crate::common::{
    as4_strict_push_policy, as4_unsigned_push_policy, dedup_backend, fixture, pki_fixture, session,
    session_with_trust_anchor_and_fingerprint_pin, signed_receipt_fixture,
};
use asx_rs::as4::{As4ReceivePushRequest, As4ReceivePushSyncRequest, receive_push_with_dedup_sync};
use asx_rs::core::{CertHandle, ErrorCode, OcspMode, SessionContext};
use asx_rs::observability::{AsxEvent, EventBus, ScopedEventTryRecvError};
use asx_rs::reliability::InMemoryDedupBackend;
use tokio::time::{Duration, timeout};

const PUSH_FLOW_BOUNDARY: &str = "asx-push-flow-boundary";

fn multipart_content_type() -> String {
    format!("multipart/related; boundary=\"{PUSH_FLOW_BOUNDARY}\"; type=\"application/soap+xml\"")
}

fn ensure_required_strict_properties_in_xml(xml: &str) -> String {
    let has_original_sender = xml.contains("name=\"originalSender\"");
    let has_final_recipient = xml.contains("name=\"finalRecipient\"");
    let has_tracking_identifier = xml.contains("name=\"trackingIdentifier\"");

    if has_original_sender && has_final_recipient && has_tracking_identifier {
        return xml.to_string();
    }

    let Some(user_message_close) = xml.find("</eb:UserMessage>") else {
        return xml.to_string();
    };

    let mut out = String::with_capacity(xml.len() + 256);
    out.push_str(&xml[..user_message_close]);
    out.push_str(
        "<eb:MessageProperties>\
            <eb:Property name=\"originalSender\">urn:test:sender</eb:Property>\
            <eb:Property name=\"finalRecipient\">urn:test:recipient</eb:Property>\
            <eb:Property name=\"trackingIdentifier\">urn:test:tracking</eb:Property>\
        </eb:MessageProperties>",
    );
    out.push_str(&xml[user_message_close..]);
    out
}

fn multipart_push_payload() -> Vec<u8> {
    let payload_cid = "push-flow-body@example.com";
    let mut soap =
        String::from_utf8(fixture("as4_push_user_message.golden")).expect("utf8 fixture");
    soap = ensure_required_strict_properties_in_xml(&soap);

    if !soap.contains("xmlns:xop=\"http://www.w3.org/2004/08/xop/include\"") {
        soap = soap.replacen(
            "<S12:Envelope ",
            "<S12:Envelope xmlns:xop=\"http://www.w3.org/2004/08/xop/include\" ",
            1,
        );
    }
    if soap.contains("<S12:Body/>") {
        soap = soap.replacen(
            "<S12:Body/>",
            &format!("<S12:Body><xop:Include href=\"cid:{payload_cid}\"/></S12:Body>"),
            1,
        );
    }

    let mut out = Vec::new();
    out.extend_from_slice(format!("--{PUSH_FLOW_BOUNDARY}\r\n").as_bytes());
    out.extend_from_slice(
        b"Content-Type: application/xop+xml; charset=UTF-8; type=\"application/soap+xml\"\r\n",
    );
    out.extend_from_slice(b"Content-ID: <soap-root@example.com>\r\n\r\n");
    out.extend_from_slice(soap.as_bytes());
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(format!("--{PUSH_FLOW_BOUNDARY}\r\n").as_bytes());
    out.extend_from_slice(
        format!("Content-Type: application/octet-stream\r\nContent-ID: <{payload_cid}>\r\n\r\n")
            .as_bytes(),
    );
    out.extend_from_slice(b"push-flow-detached-payload\r\n");
    out.extend_from_slice(format!("--{PUSH_FLOW_BOUNDARY}--\r\n").as_bytes());
    out
}

#[test]
fn as4_push_valid_without_receipt_when_unsigned_push_is_allowed() {
    let bus = EventBus::new(32).expect("bus");
    let _events = bus.subscribe_scoped_events();

    let dedup = dedup_backend();
    let out = receive_push_with_dedup_sync(
        &session(),
        &bus,
        As4ReceivePushSyncRequest {
            request: As4ReceivePushRequest {
                http_content_type: multipart_content_type(),
                payload: multipart_push_payload().into(),
                receipt_payload: None,
                policy: as4_unsigned_push_policy(),
                authenticated_sender_scope: None,
            },
            dedup_backend: &dedup,
        },
    )
    .expect("valid push flow");

    assert_eq!(out.user_message.message_id, "msg-push-1");
    assert_eq!(out.user_message.action, "SubmitOrder");
    assert_eq!(out.user_message.from_party_id(), "sender-a");
    assert_eq!(out.user_message.to_party_id(), "receiver-b");
    assert!(out.user_message.has_ws_security_header);
    assert!(out.receipt.is_none());
}

#[test]
fn as4_push_missing_signature_fails_when_required() {
    let bus = EventBus::new(32).expect("bus");
    let _events = bus.subscribe_scoped_events();

    let dedup = dedup_backend();
    let err = receive_push_with_dedup_sync(
        &session(),
        &bus,
        As4ReceivePushSyncRequest {
            request: As4ReceivePushRequest {
                http_content_type: multipart_content_type(),
                payload: multipart_push_payload().into(),
                receipt_payload: None,
                policy: as4_strict_push_policy(),
                authenticated_sender_scope: None,
            },
            dedup_backend: &dedup,
        },
    )
    .expect_err("missing signature must fail");

    assert_eq!(err.code, ErrorCode::SecurityVerificationFailed);
}

#[test]
fn forged_receipt_signature_fails_cryptographic_verification() {
    let bus = EventBus::new(32).expect("bus");
    let _events = bus.subscribe_scoped_events();
    let mut scoped_rx = bus.subscribe_scoped_events();
    let security_before = bus
        .metrics()
        .receipt_taxonomy_security_verification_failed();
    let signing_cert_pem = pki_fixture("receipt_signing.cert.pem");
    let trusted_session = session_with_trust_anchor_and_fingerprint_pin(&signing_cert_pem);

    let dedup = dedup_backend();
    let err = receive_push_with_dedup_sync(
        &trusted_session,
        &bus,
        As4ReceivePushSyncRequest {
            request: As4ReceivePushRequest {
                http_content_type: multipart_content_type(),
                payload: multipart_push_payload().into(),
                receipt_payload: Some(fixture("as4_push_signed_receipt.golden")),
                policy: as4_unsigned_push_policy(),
                authenticated_sender_scope: None,
            },
            dedup_backend: &dedup,
        },
    )
    .expect_err("forged receipt signature must fail");

    assert_eq!(err.code, ErrorCode::SecurityVerificationFailed);

    let mut saw_taxonomy = false;
    for _ in 0..16 {
        let evt = match scoped_rx.try_recv() {
            Ok(evt) => evt,
            Err(ScopedEventTryRecvError::Empty) => continue,
            Err(ScopedEventTryRecvError::Closed) | Err(_) => break,
        };
        if let AsxEvent::ReceiptTaxonomyOutcome {
            message_id,
            signal,
            outcome,
            detail,
        } = evt.event.as_ref()
            && message_id.as_ref() == "msg-push-1"
            && *signal == "as4"
            && *outcome == "security_verification_failed"
            && *detail == "receipt_signature_verification_failed"
        {
            saw_taxonomy = true;
            break;
        }
    }
    assert!(saw_taxonomy);
    let security_after = bus
        .metrics()
        .receipt_taxonomy_security_verification_failed();
    assert_eq!(security_after, security_before + 1);
}

#[test]
fn cryptographically_signed_receipt_passes_end_to_end() {
    let bus = EventBus::new(32).expect("bus");
    let _events = bus.subscribe_scoped_events();
    let signing_cert_pem = pki_fixture("receipt_signing.cert.pem");
    let trusted_session = session_with_trust_anchor_and_fingerprint_pin(&signing_cert_pem);

    let dedup = dedup_backend();
    let out = receive_push_with_dedup_sync(
        &trusted_session,
        &bus,
        As4ReceivePushSyncRequest {
            request: As4ReceivePushRequest {
                http_content_type: multipart_content_type(),
                payload: multipart_push_payload().into(),
                receipt_payload: Some(signed_receipt_fixture("msg-push-1")),
                policy: as4_unsigned_push_policy(),
                authenticated_sender_scope: None,
            },
            dedup_backend: &dedup,
        },
    )
    .expect("cryptographically signed receipt must be accepted");

    let receipt = out.receipt.expect("receipt");
    assert!(receipt.is_signed);
    assert!(receipt.has_non_repudiation_info);
    assert_eq!(receipt.ref_to_message_id, "msg-push-1");
}

#[test]
fn receipt_with_wrong_ref_to_message_id_detected_after_crypto_verify() {
    let bus = EventBus::new(32).expect("bus");
    let _events = bus.subscribe_scoped_events();
    let mut scoped_rx = bus.subscribe_scoped_events();
    let semantic_before = bus.metrics().receipt_taxonomy_semantic_interop_failure();
    let signing_cert_pem = pki_fixture("receipt_signing.cert.pem");
    let trusted_session = session_with_trust_anchor_and_fingerprint_pin(&signing_cert_pem);

    let dedup = dedup_backend();
    // Receipt is cryptographically valid but refers to a different message ID.
    let err = receive_push_with_dedup_sync(
        &trusted_session,
        &bus,
        As4ReceivePushSyncRequest {
            request: As4ReceivePushRequest {
                http_content_type: multipart_content_type(),
                payload: multipart_push_payload().into(),
                receipt_payload: Some(signed_receipt_fixture("msg-push-999")),
                policy: as4_unsigned_push_policy(),
                authenticated_sender_scope: None,
            },
            dedup_backend: &dedup,
        },
    )
    .expect_err("receipt with mismatched RefToMessageId must fail");

    // Verify that the error is about semantic interop violation, not crypto failure.
    // (Crypto verification passes, but the message ID link is broken.)
    assert_eq!(err.code, ErrorCode::InteropViolation);

    let mut saw_taxonomy = false;
    for _ in 0..16 {
        let evt = match scoped_rx.try_recv() {
            Ok(evt) => evt,
            Err(ScopedEventTryRecvError::Empty) => continue,
            Err(ScopedEventTryRecvError::Closed) | Err(_) => break,
        };
        if let AsxEvent::ReceiptTaxonomyOutcome {
            message_id,
            signal,
            outcome,
            detail,
        } = evt.event.as_ref()
            && message_id.as_ref() == "msg-push-1"
            && *signal == "as4"
            && *outcome == "semantic_interop_failure"
            && *detail == "receipt_ref_to_message_id_mismatch"
        {
            saw_taxonomy = true;
            break;
        }
    }
    assert!(saw_taxonomy);
    let semantic_after = bus.metrics().receipt_taxonomy_semantic_interop_failure();
    assert_eq!(semantic_after, semantic_before + 1);
}

#[test]
fn receipt_signed_by_untrusted_cert_rejected_even_if_cryptographically_valid() {
    let bus = EventBus::new(32).expect("bus");
    let _events = bus.subscribe_scoped_events();
    let signing_cert_pem = pki_fixture("receipt_signing.cert.pem");
    // Create a session WITHOUT the receipt signing cert in the trust anchor.
    let untrusted_session =
        SessionContext::new("as4-session-1", "partner-a", "strict").expect("session");
    let mut cert_handle = CertHandle::new("as4-receipt-signing-other");
    cert_handle.trust_anchor_pems = vec![]; // Empty trust anchor
    cert_handle.ocsp_mode = OcspMode::Disabled;
    cert_handle.fingerprint_sha256 = {
        let pinned_session = session_with_trust_anchor_and_fingerprint_pin(&signing_cert_pem);
        pinned_session.cert_handle().fingerprint_sha256.clone()
    };
    let untrusted_session = untrusted_session
        .with_cert_handle(cert_handle)
        .expect("session trust configuration");

    let dedup = dedup_backend();
    // Even though the receipt is cryptographically valid, it's signed by a cert
    // not in the trust anchor, so verification must fail.
    let err = receive_push_with_dedup_sync(
        &untrusted_session,
        &bus,
        As4ReceivePushSyncRequest {
            request: As4ReceivePushRequest {
                http_content_type: multipart_content_type(),
                payload: multipart_push_payload().into(),
                receipt_payload: Some(signed_receipt_fixture("msg-push-1")),
                policy: as4_unsigned_push_policy(),
                authenticated_sender_scope: None,
            },
            dedup_backend: &dedup,
        },
    )
    .expect_err("receipt signed by untrusted cert must fail");

    assert_eq!(err.code, ErrorCode::SecurityVerificationFailed);
}

#[tokio::test(flavor = "current_thread")]
async fn duplicate_push_ingress_emits_duplicate_detected_event() {
    let bus = EventBus::new(32).expect("bus");
    let _events = bus.subscribe_scoped_events();
    let mut events = bus
        .subscribe_session_events("as4-session-1")
        .expect("subscribe");
    let dedup = InMemoryDedupBackend::default();

    for _ in 0..2 {
        receive_push_with_dedup_sync(
            &session(),
            &bus,
            As4ReceivePushSyncRequest {
                request: As4ReceivePushRequest {
                    http_content_type: multipart_content_type(),
                    payload: multipart_push_payload().into(),
                    receipt_payload: None,
                    policy: as4_unsigned_push_policy(),
                    authenticated_sender_scope: None,
                },
                dedup_backend: &dedup,
            },
        )
        .expect("push with dedup");
    }

    let mut duplicate_seen = false;
    for _ in 0..6 {
        if let Ok(Some(evt)) = timeout(Duration::from_millis(200), events.recv()).await
            && let asx_rs::observability::AsxEvent::DuplicateDetected {
                message_id,
                ingress,
                ..
            } = evt.as_ref()
            && message_id.as_ref() == "msg-push-1"
            && *ingress == asx_rs::observability::AsxIngressStage::As4ReceivePush
        {
            duplicate_seen = true;
            break;
        }
    }

    assert!(duplicate_seen);
}
