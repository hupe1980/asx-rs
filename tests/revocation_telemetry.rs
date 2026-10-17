#![cfg(all(feature = "as2", feature = "as4"))]
//! The `asx.revocation` span through the public API. One
//! test in its own binary, with the runtime built inside the capture (a
//! thread-local subscriber races callsite registration from parallel
//! tests, as in `telemetry_contract.rs`).

#[path = "common/revocation_net.rs"]
mod net;

use asx_testkit::pki::{Cdp, IssueOptions, KeyAlg, TestCa};
use asx_testkit::trace::TraceCapture;
use net::peers::Preset;
use net::*;

#[test]
fn revocation_spans_carry_method_source_outcome_and_reason() {
    let capture = TraceCapture::new();
    {
        let _guard = capture.set_default();
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                // BDEW: a signer revoked in its CA's CRL.
                let root = TestCa::sm_pki();
                let (a, b) = (
                    bdew(&root, A, A, Cdp::Issuer),
                    bdew(&root, B, B, Cdp::Issuer),
                );
                root.revoke(&a.signing);
                let net = as4_net(Preset::Bdew, &a, &b, &[root.anchor()], &[]);
                assert_refused_0101(net.send(Preset::Bdew).await);

                // eDelivery: a pinned signer without any revocation source.
                let ca = TestCa::new("asx bare root", KeyAlg::Rsa2048);
                let bare = IssueOptions {
                    cdp: Cdp::None,
                    ..IssueOptions::default()
                };
                let a = rsa(&ca, "party-a", Preset::Edelivery, bare);
                let b = rsa(&ca, "party-b", Preset::Edelivery, IssueOptions::default());
                let net = as4_net(Preset::Edelivery, &a, &b, &[ca.anchor()], &[]);
                net.send(Preset::Edelivery)
                    .await
                    .expect("accepted, recorded");
            });
    }
    let spans = capture.spans_named("asx.revocation");
    let field = |s: &asx_testkit::trace::CapturedSpan, f: &str| s.fields.get(f).cloned();
    let revoked = spans
        .iter()
        .find(|s| field(s, "outcome").as_deref() == Some("revoked"))
        .unwrap_or_else(|| panic!("a revoked span: {spans:?}"));
    assert_eq!(field(revoked, "method").as_deref(), Some("crl"));
    assert_eq!(field(revoked, "source").as_deref(), Some("network"));
    assert!(field(revoked, "signer.fingerprint").is_some());
    let no_source = spans
        .iter()
        .find(|s| field(s, "reason").as_deref() == Some("no_source"))
        .unwrap_or_else(|| panic!("a no_source span: {spans:?}"));
    assert_eq!(field(no_source, "outcome").as_deref(), Some("unknown"));
    let warned = capture.events().iter().any(|e| {
        e.span == Some("asx.revocation") && e.message() == "certificate revocation status"
    });
    assert!(warned, "the WARN event inside asx.revocation");
}
