#![cfg(all(feature = "as2", feature = "as4"))]
//! Revocation through the public API: the one revocation validator on AS4
//! inbound, AS4 receipts, AS2 inbound and AS2 MDNs, under every profile, on
//! a current-thread runtime (`#[tokio::test]`). The test CAs publish CRLs at
//! their distribution points; `RevocationHttp` serves, overrides, fails and
//! counts revocation fetches and hands message traffic to a `Loopback`.
//! The three-day rule's boundaries are unit tests with a `ManualClock`
//! (`src/revocation/tests.rs`).

#[path = "common/revocation_net.rs"]
mod net;

use asx::as4::{As4, UserMessage};
use asx::testkit::loopback::Loopback;
use asx::testkit::pki::{Cdp, IssueOptions, KeyAlg, TestCa};
use asx::testkit::revocation::RevocationHttp;
use asx::{ErrorKind, MemoryDedup, Profile, Verified};
use net::peers::{B_URL, Preset};
use net::*;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::SystemTime;

// ── BDEW refuses from the CDP ───────────────────────────────────────────────

#[tokio::test]
async fn bdew_refuses_a_signer_revoked_in_its_sub_ca_crl() {
    let root = TestCa::sm_pki();
    let (a, b) = (
        bdew(&root, A, A, Cdp::Issuer),
        bdew(&root, B, B, Cdp::Issuer),
    );
    let net = as4_net(Preset::Bdew, &a, &b, &[root.anchor()], &[]);
    net.send(Preset::Bdew).await.expect("control: accepted");
    root.revoke(&a.signing);
    // A fresh client: the first one cached the CRL that listed nothing.
    let net = as4_net(Preset::Bdew, &a, &b, &[root.anchor()], &[]);
    assert_refused_0101(net.send(Preset::Bdew).await);
    assert_eq!(
        net.calls.load(Ordering::SeqCst),
        0,
        "the handler is not called"
    );
    assert_eq!(net.b_http.requests_to(root.crl_url()), 1);
}

#[tokio::test]
async fn bdew_refuses_a_sub_ca_listed_in_the_indirect_root_crl() {
    let root = TestCa::sm_pki();
    let signer = root.crl_signer("CCRL-S(Root)", KeyAlg::EcBrainpoolP256r1);
    let url = "http://crl.sm-pki.example/root-indirect.crl";
    let sub = root.sub_ca_with_options(
        "SM Sub-CA",
        KeyAlg::EcBrainpoolP256r1,
        IssueOptions {
            cdp: Cdp::Indirect {
                uris: vec![url.into()],
                crl_issuer: signer.clone(),
            },
            ..IssueOptions::default()
        },
    );
    let (a, b) = (bdew(&sub, A, A, Cdp::Issuer), bdew(&sub, B, B, Cdp::Issuer));
    let indirect = |revoked: bool| {
        let builder = signer.crl_builder().idp(asx::testkit::pki::Idp {
            uris: vec![url.into()],
            indirect: true,
            ..Default::default()
        });
        if revoked {
            builder.revoke_ca_issued_by(&sub, &root)
        } else {
            builder
        }
        .build()
    };
    let signers = [signer.certificate()];
    let net = as4_net(Preset::Bdew, &a, &b, &[root.anchor()], &signers);
    net.b_http.serve(url, indirect(false));
    net.a_http.serve(url, indirect(false));
    net.send(Preset::Bdew)
        .await
        .expect("control: the indirect root CRL lists nothing");
    assert_eq!(net.calls.load(Ordering::SeqCst), 1);

    let net = as4_net(Preset::Bdew, &a, &b, &[root.anchor()], &signers);
    net.b_http.serve(url, indirect(true));
    assert_refused_0101(net.send(Preset::Bdew).await);
    assert_eq!(net.calls.load(Ordering::SeqCst), 0);

    // Without the configured CRL signer nothing can verify the root CRL.
    let net = as4_net(Preset::Bdew, &a, &b, &[root.anchor()], &[]);
    net.b_http.serve(url, indirect(false));
    assert_refused_0101(net.send(Preset::Bdew).await);
}

#[tokio::test]
async fn bdew_accepts_with_current_crls_and_asks_no_responder() {
    let root = TestCa::sm_pki();
    let sub = root.sub_ca("SM Sub-CA", KeyAlg::EcBrainpoolP256r1);
    let (a, b) = (bdew(&sub, A, A, Cdp::Issuer), bdew(&sub, B, B, Cdp::Issuer));
    let net = as4_net(Preset::Bdew, &a, &b, &[root.anchor()], &[]);
    net.send(Preset::Bdew)
        .await
        .expect("accepted and receipted");
    assert_eq!(net.calls.load(Ordering::SeqCst), 1);
    let urls = net.b_http.urls();
    assert!(
        urls.iter().all(|u| u.ends_with(".crl")),
        "CRLs only: {urls:?}"
    );
    assert_eq!(
        net.b_http.requests_to(root.crl_url()),
        1,
        "the Sub-CA is checked"
    );
    assert_eq!(
        net.b_http.requests_to(sub.crl_url()),
        1,
        "the leaf is checked"
    );
    // Cached: a second message makes no fetch.
    net.send(Preset::Bdew).await.expect("accepted");
    assert_eq!(net.b_http.requests(), 2);
}

#[tokio::test]
async fn bdew_refuses_a_chain_certificate_without_a_distribution_point() {
    let root = TestCa::sm_pki();
    let (a, b) = (bdew(&root, A, A, Cdp::None), bdew(&root, B, B, Cdp::Issuer));
    let net = as4_net(Preset::Bdew, &a, &b, &[root.anchor()], &[]);
    assert_refused_0101(net.send(Preset::Bdew).await);
    assert_eq!(net.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn bdew_refuses_when_the_crl_does_not_verify() {
    let root = TestCa::sm_pki();
    let (a, b) = (
        bdew(&root, A, A, Cdp::Issuer),
        bdew(&root, B, B, Cdp::Issuer),
    );
    let net = as4_net(Preset::Bdew, &a, &b, &[root.anchor()], &[]);
    let stranger = TestCa::new("asx-testkit SM-PKI root", KeyAlg::EcBrainpoolP256r1);
    net.b_http
        .serve(root.crl_url(), stranger.crl_builder().build());
    assert_refused_0101(net.send(Preset::Bdew).await);
    // A delta CRL from the right key is not a complete CRL either.
    let net = as4_net(Preset::Bdew, &a, &b, &[root.anchor()], &[]);
    net.b_http
        .serve(root.crl_url(), root.crl_builder().delta().build());
    assert_refused_0101(net.send(Preset::Bdew).await);
}

#[tokio::test]
async fn a_revoked_receipt_signer_leaves_the_delivery_indeterminate() {
    let root = TestCa::sm_pki();
    let (a, b) = (
        bdew(&root, A, A, Cdp::Issuer),
        bdew(&root, B, B, Cdp::Issuer),
    );
    root.revoke(&b.signing);
    let net = as4_net(Preset::Bdew, &a, &b, &[root.anchor()], &[]);
    let err = net.send(Preset::Bdew).await.expect_err("indeterminate");
    assert_eq!(err.kind(), ErrorKind::Indeterminate, "{err}");
    assert!(err.is_retryable());
    assert!(err.to_string().contains("receipt signer"), "{err}");
    // A locally indeterminate receipt carries no ebMS error code.
    assert_eq!(err.ebms_code(), None);
}

// ── Nothing is fetched for an unauthenticated or unauthorized sender

#[tokio::test]
async fn an_unauthorized_signer_triggers_no_revocation_request() {
    let root = TestCa::sm_pki();
    // `a` claims MP-ID A but its certificate carries another MP-ID, and the
    // receiver has no configured partner A (BDEW §2.3.4.4 sender rule).
    let a = bdew(&root, A, "9900000000009", Cdp::Issuer);
    let b = bdew(&root, B, B, Cdp::Issuer);
    let loopback = Loopback::new();
    let b_http = RevocationHttp::new().with_fallback(loopback.clone());
    let receiver = As4::builder(Profile::bdew())
        .local(b.local())
        .trust_anchor(root.anchor())
        .http_client(b_http.clone())
        .build()
        .unwrap();
    loopback.mount(
        B_URL,
        receiver.inbound(MemoryDedup::default(), |_m: Verified<UserMessage>| async {
            Ok::<(), asx::Reject>(())
        }),
    );
    let sender = As4::builder(Profile::bdew())
        .local(a.local())
        .trust_anchor(root.anchor())
        .partner(b.partner(B_URL))
        .http_client(loopback.clone())
        .build()
        .unwrap();
    let to_b = b.partner(B_URL);
    assert_refused_0101(
        sender
            .send(Preset::Bdew.message(&to_b, b"unauthorized"))
            .await,
    );
    assert_eq!(
        b_http.requests(),
        0,
        "no CRL fetch for an unauthorized signer"
    );
}

#[tokio::test]
async fn a_broken_signature_triggers_no_revocation_request() {
    use tower::ServiceExt;
    let root = TestCa::sm_pki();
    let (a, b) = (
        bdew(&root, A, A, Cdp::Issuer),
        bdew(&root, B, B, Cdp::Issuer),
    );
    let net = as4_net(Preset::Bdew, &a, &b, &[root.anchor()], &[]);
    // Capture a genuine request, then flip one byte of its signed header.
    let capture = Capture::default();
    let sender = As4::builder(Profile::bdew())
        .local(a.local())
        .trust_anchor(root.anchor())
        .partner(b.partner(B_URL))
        .http_client(capture.clone())
        .build()
        .unwrap();
    let _ = sender
        .send(Preset::Bdew.message(&b.partner(B_URL), b"x"))
        .await;
    let request = capture.0.lock().unwrap().take().expect("captured");
    let (parts, body) = request.into_parts();
    let mut bytes = body.to_vec();
    let at = String::from_utf8_lossy(&bytes)
        .find("communication/services/MP")
        .expect("the signed eb:Service value")
        + 3;
    bytes[at] ^= 0x01;
    let tampered =
        http::Request::from_parts(parts, http_body_util::Full::new(bytes::Bytes::from(bytes)));
    let _response = net.inbound.clone().oneshot(tampered).await.unwrap();
    assert_eq!(
        net.b_http.requests(),
        0,
        "no CRL fetch before the signature verifies"
    );
    assert_eq!(net.calls.load(Ordering::SeqCst), 0);
}

#[derive(Debug, Clone, Default)]
struct Capture(Arc<std::sync::Mutex<Option<http::Request<bytes::Bytes>>>>);

impl asx::HttpClient for Capture {
    fn send(
        &self,
        request: http::Request<bytes::Bytes>,
    ) -> asx::BoxFuture<
        '_,
        Result<http::Response<bytes::Bytes>, Box<dyn std::error::Error + Send + Sync>>,
    > {
        if request.uri() == B_URL {
            *self.0.lock().unwrap() = Some(request);
        }
        Box::pin(async { Err("captured".into()) })
    }
}

// ── CRL-DP, then OCSP, under the other profiles ────────────────────────────

const OCSP: &str = "http://ocsp.peppol.example/";

#[tokio::test]
async fn peppol_falls_back_to_ocsp_when_the_crl_is_not_obtainable() {
    let ca = TestCa::new("asx peppol root", KeyAlg::Rsa2048);
    let dead = "http://crl.down.example/ca.crl".to_string();
    let a = rsa(
        &ca,
        "POP000001",
        Preset::Peppol,
        IssueOptions {
            cdp: Cdp::Points(vec![vec![dead.clone()]]),
            ocsp: vec![OCSP.into()],
            ..IssueOptions::default()
        },
    );
    let b = rsa(&ca, "POP000002", Preset::Peppol, IssueOptions::default());
    let now = SystemTime::now();
    let case = |revoked: Option<bool>| {
        let net = as4_net(Preset::Peppol, &a, &b, &[ca.anchor()], &[]);
        net.b_http.fail(&dead);
        match revoked {
            Some(r) => net
                .b_http
                .serve(OCSP, ca.ocsp(&a.signing, r, now - HOUR, now + HOUR)),
            None => net.b_http.fail(OCSP),
        }
        net
    };
    let net = case(Some(false));
    net.send(Preset::Peppol).await.expect("OCSP good suffices");
    assert_eq!(net.b_http.requests_to(OCSP), 1);
    assert_refused_0101(case(Some(true)).send(Preset::Peppol).await);
    assert_refused_0101(case(None).send(Preset::Peppol).await);
}

#[tokio::test]
async fn a_revoked_crl_is_final_whatever_ocsp_says() {
    let ca = TestCa::new("asx peppol root", KeyAlg::Rsa2048);
    let a = rsa(
        &ca,
        "POP000001",
        Preset::Peppol,
        IssueOptions {
            ocsp: vec![OCSP.into()],
            ..IssueOptions::default()
        },
    );
    let b = rsa(&ca, "POP000002", Preset::Peppol, IssueOptions::default());
    let now = SystemTime::now();
    ca.revoke(&a.signing);
    let net = as4_net(Preset::Peppol, &a, &b, &[ca.anchor()], &[]);
    net.b_http
        .serve(OCSP, ca.ocsp(&a.signing, false, now - HOUR, now + HOUR));
    assert_refused_0101(net.send(Preset::Peppol).await);
    assert_eq!(
        net.b_http.requests_to(OCSP),
        0,
        "a revoked CRL needs no OCSP"
    );
}

#[tokio::test]
async fn a_certificate_without_any_source_follows_the_profile() {
    for (preset, accepted) in [
        (Preset::Edelivery, true),
        (Preset::Entsog, true),
        (Preset::Peppol, false),
    ] {
        let ca = TestCa::new("asx bare root", KeyAlg::Rsa2048);
        let bare = IssueOptions {
            cdp: Cdp::None,
            ..IssueOptions::default()
        };
        let (a_id, b_id) = match preset {
            Preset::Peppol => ("POP000001", "POP000002"),
            _ => ("party-a", "party-b"),
        };
        let a = rsa(&ca, a_id, preset, bare);
        let b = rsa(&ca, b_id, preset, IssueOptions::default());
        let net = as4_net(preset, &a, &b, &[ca.anchor()], &[]);
        let result = net.send(preset).await;
        if accepted {
            result.unwrap_or_else(|e| panic!("{preset:?}: {e}"));
        } else {
            assert_refused_0101(result);
        }
    }
}

// ── AS2: the same module, the whole path, and the MDN signer ────────────────

#[tokio::test]
async fn as2_refuses_a_signer_whose_intermediate_is_revoked() {
    let root = TestCa::new("asx as2 root", KeyAlg::Rsa2048);
    let sub = root.sub_ca("asx as2 sub", KeyAlg::Rsa2048);
    // `b` (the MDN signer) under the root, `a` under the Sub-CA.
    let (a, b) = (
        as2_party(&sub, "PARTY-A-AS2"),
        as2_party(&root, "PARTY-B-AS2"),
    );
    // AS2 verifies with PKCS7_NOINTERN: the intermediate is configured.
    let anchors = [root.anchor(), sub.certificate()];
    let net = as2_net(&a, &b, &anchors);
    net.send().await.expect("control: accepted");
    assert_eq!(
        net.b_http.requests_to(root.crl_url()),
        1,
        "the intermediate is checked"
    );
    root.revoke_ca(&sub);
    let net = as2_net(&a, &b, &anchors);
    let err = net.send().await.expect_err("refused");
    assert_eq!(err.kind(), ErrorKind::PartnerError, "{err}");
    assert!(
        err.mdn_disposition()
            .is_some_and(|d| d.contains("authentication-failed")),
        "{err}"
    );
    assert_eq!(net.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn as2_a_revoked_mdn_signer_leaves_the_delivery_indeterminate() {
    let root = TestCa::new("asx as2 root", KeyAlg::Rsa2048);
    let (a, b) = (
        as2_party(&root, "PARTY-A-AS2"),
        as2_party(&root, "PARTY-B-AS2"),
    );
    root.revoke(&b.signing);
    let net = as2_net(&a, &b, &[root.anchor()]);
    // The receiver checks `a` (good) and delivers; the sender checks the MDN
    // signer `b` (revoked).
    let err = net.send().await.expect_err("indeterminate");
    assert_eq!(err.kind(), ErrorKind::Indeterminate, "{err}");
    assert!(err.to_string().contains("MDN signer"), "{err}");
    assert_eq!(net.calls.load(Ordering::SeqCst), 1);
}
