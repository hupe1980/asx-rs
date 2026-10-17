#![cfg(all(feature = "as4", feature = "as2"))]
//! Auto traits and object safety of the public API.

use asx::as4::{As4, UserMessage};
use asx::{
    AuditDurability, AuditRecord, AuditSink, Decrypter, DedupStore, Handler, HttpClient,
    MemoryDedup, Profile, Reject, Signer, Verified,
};
use asx_testkit::loopback::Loopback;
use asx_testkit::pki::TestCa;
use std::sync::Arc;

fn assert_send_sync<T: Send + Sync>() {}

#[test]
fn public_types_are_send_sync() {
    assert_send_sync::<asx::Error>();
    assert_send_sync::<asx::ErrorKind>();
    assert_send_sync::<asx::Profile>();
    assert_send_sync::<asx::Quirk>();
    assert_send_sync::<asx::LocalParty>();
    assert_send_sync::<asx::Partner>();
    assert_send_sync::<asx::Certificate>();
    assert_send_sync::<asx::KeyPair>();
    assert_send_sync::<asx::SignatureAlgorithm>();
    assert_send_sync::<asx::KeyOp<'static>>();
    assert_send_sync::<asx::Claim>();
    assert_send_sync::<asx::ClaimToken>();
    assert_send_sync::<asx::MemoryDedup>();
    assert_send_sync::<asx::Inbound>();
    assert_send_sync::<asx::Reject>();
    assert_send_sync::<asx::Verified<asx::Receipt>>();
    assert_send_sync::<asx::Verified<UserMessage>>();
    assert_send_sync::<asx::Receipt>();
    assert_send_sync::<asx::Payload>();
    assert_send_sync::<asx::Builder<As4>>();
    assert_send_sync::<asx::Builder<asx::as2::As2>>();
    assert_send_sync::<As4>();
    assert_send_sync::<asx::as4::Message>();
    assert_send_sync::<UserMessage>();
    assert_send_sync::<asx::as2::As2>();
    assert_send_sync::<AuditRecord>();
    assert_send_sync::<AuditDurability>();
}

// ── object safety ───────────────────────────────────────────────────────────

fn takes_signer(_: Arc<dyn Signer>) {}
fn takes_decrypter(_: Arc<dyn Decrypter>) {}
fn takes_dedup(_: Arc<dyn DedupStore>) {}
fn takes_http(_: Arc<dyn HttpClient>) {}
fn takes_handler(_: Arc<dyn Handler<UserMessage>>) {}
fn takes_audit(_: Arc<dyn AuditSink>) {}

/// A minimal sink: the trait is implementable outside the crate.
#[derive(Debug)]
struct NullSink;

impl AuditSink for NullSink {
    fn durability(&self) -> AuditDurability {
        AuditDurability::BestEffort
    }

    fn record<'a>(
        &'a self,
        _record: &'a AuditRecord,
    ) -> asx::BoxFuture<'a, Result<(), Box<dyn std::error::Error + Send + Sync>>> {
        Box::pin(async { Ok(()) })
    }
}

async fn accept(_message: Verified<UserMessage>) -> Result<(), Reject> {
    Ok(())
}

#[test]
fn embedder_traits_are_object_safe() {
    let pair = TestCa::sm_pki()
        .bdew_party("9900000000001")
        .signing
        .key_pair();
    takes_signer(Arc::new(pair.clone()));
    takes_decrypter(Arc::new(pair));
    takes_dedup(Arc::new(MemoryDedup::default()));
    takes_http(Arc::new(Loopback::new()));
    takes_handler(Arc::new(accept));
    takes_handler(Arc::new(|_m: Verified<UserMessage>| async {
        Err::<(), Reject>(Reject::new("refused"))
    }));
    takes_audit(Arc::new(NullSink));
}

// ── Inbound as a tower Service ──────────────────────────────────────────────

#[tokio::test]
async fn inbound_is_a_tower_service_and_enforces_the_size_limit() {
    use tower::ServiceExt;

    let ca = TestCa::sm_pki();
    let a = ca.bdew_party("9900000000001");
    let b = ca.bdew_party("9900000000002");
    let client = As4::builder(Profile::bdew().max_message_bytes(16))
        .local(b.local())
        .trust_anchor(ca.anchor())
        .partner(a.partner("https://a.example/as4"))
        .http_client(Loopback::new())
        .build()
        .expect("client");
    let inbound = client.inbound(MemoryDedup::default(), accept);

    // Declared length above the limit.
    let request = http::Request::post("/as4")
        .header(http::header::CONTENT_LENGTH, "17")
        .body(http_body_util::Full::new(bytes::Bytes::from_static(
            b"0123456789abcdefX",
        )))
        .expect("request");
    let response = inbound.clone().oneshot(request).await.expect("infallible");
    assert_eq!(response.status(), http::StatusCode::PAYLOAD_TOO_LARGE);

    // No declared length: the body itself exceeds the limit.
    let request = http::Request::post("/as4")
        .body(http_body_util::Full::new(bytes::Bytes::from(vec![
            b'x';
            64
        ])))
        .expect("request");
    let response = inbound.oneshot(request).await.expect("infallible");
    assert_eq!(response.status(), http::StatusCode::PAYLOAD_TOO_LARGE);
}

/// `Inbound` mounts on a `Router<S>` with `route_service`, and the
/// application calls `with_state` afterwards.
#[test]
fn inbound_mounts_on_a_stateful_axum_router() {
    #[derive(Clone)]
    struct AppState;
    let ca = asx_testkit::pki::TestCa::sm_pki();
    let me = ca.bdew_party("9900000000001");
    let as4 = asx::as4::As4::builder(asx::Profile::bdew())
        .local(me.local())
        .trust_anchor(ca.anchor())
        .http_client(asx_testkit::loopback::Loopback::new())
        .build()
        .unwrap();
    let inbound = as4.inbound(
        asx::MemoryDedup::default(),
        |_m: asx::Verified<asx::as4::UserMessage>| async { Ok::<(), asx::Reject>(()) },
    );
    let _router: axum::Router = axum::Router::<AppState>::new()
        .route_service("/as4", inbound)
        .with_state(AppState);
}
