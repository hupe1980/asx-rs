#![cfg(feature = "as4")]
//! PKIX and revocation vectors. Path validation is offline
//! (`validate_certificate_chain`); revocation is driven here at a fixed instant on material the test CA mints with CRL
//! distribution points and OCSP responders (`asx::__fuzz::revocation`).

use asx::__fuzz::revocation::{decide, ocsp_status};
use asx::__fuzz::wssec::{ChainPolicy, validate_certificate_chain};
use asx::Profile;
use asx_testkit::pki::{Cdp, IssueOptions, KeyAlg, KeyPair, TestCa};
use openssl::x509::X509;
use std::time::{Duration, SystemTime};

const HOUR: Duration = Duration::from_secs(3600);

fn der(pem: &[u8]) -> Vec<u8> {
    X509::from_pem(pem)
        .expect("certificate")
        .to_der()
        .expect("der")
}

fn leaf_chain_der() -> Vec<Vec<u8>> {
    vec![
        include_bytes!("fixtures/pki/leaf.cert.der").to_vec(),
        include_bytes!("fixtures/pki/intermediate.cert.der").to_vec(),
    ]
}

fn root_anchor_pem() -> Vec<String> {
    vec![
        String::from_utf8(include_bytes!("fixtures/pki/root.cert.pem").to_vec())
            .expect("root pem utf8"),
    ]
}

fn chain_policy(anchors: &[String]) -> ChainPolicy<'_> {
    ChainPolicy {
        trust_anchor_pems: anchors,
        require_chain_validation: true,
        ..ChainPolicy::default()
    }
}

#[test]
fn vector_positive_anchor_present_returns_the_path() {
    let anchors = root_anchor_pem();
    let path = validate_certificate_chain(&leaf_chain_der(), &chain_policy(&anchors))
        .expect("expected PKIX chain to validate");
    assert_eq!(path.len(), 3, "leaf, intermediate, root");
    assert_eq!(path[0], leaf_chain_der()[0], "signer first");
}

#[test]
fn vector_negative_anchor_missing_fails_closed() {
    let err = validate_certificate_chain(&leaf_chain_der(), &chain_policy(&[]))
        .expect_err("missing trust anchors must fail");
    assert_eq!(err.code, asx::__fuzz::ErrorCode::SecurityVerificationFailed);
}

// ── revocation, by the module ───────────────────────────────────────────────

struct Pki {
    root: TestCa,
    sub: TestCa,
    leaf: KeyPair,
}

fn pki(options: IssueOptions) -> Pki {
    let root = TestCa::new("asx vector root", KeyAlg::EcP256);
    let sub = root.sub_ca("asx vector sub", KeyAlg::EcP256);
    let leaf = sub.issue_with_options("asx vector leaf", KeyAlg::EcP256, options);
    Pki { root, sub, leaf }
}

impl Pki {
    fn path(&self) -> Vec<Vec<u8>> {
        vec![
            der(&self.leaf.cert_pem),
            der(self.sub.cert_pem()),
            der(self.root.cert_pem()),
        ]
    }
}

fn block_on<F: std::future::Future>(f: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("runtime")
        .block_on(f)
}

#[test]
fn crl_listing_the_leaf_or_its_sub_ca_refuses_it() {
    let now = SystemTime::now();
    let p = pki(IssueOptions::default());
    let root_crl = |revoked: bool| {
        let b = p.root.crl_builder();
        if revoked { b.revoke_ca(&p.sub) } else { b }.build()
    };
    let sub_crl = |revoked: bool| {
        let b = p.sub.crl_builder();
        if revoked { b.revoke(&p.leaf) } else { b }.build()
    };
    let served = |root: bool, sub: bool| {
        vec![
            (p.root.crl_url().to_string(), root_crl(root)),
            (p.sub.crl_url().to_string(), sub_crl(sub)),
        ]
    };
    for profile in [
        Profile::bdew(),
        Profile::peppol(),
        Profile::edelivery_1_15(),
    ] {
        block_on(decide(&profile, &p.path(), &[], served(false, false), now))
            .expect("control: current CRLs listing nothing");
        let err = block_on(decide(&profile, &p.path(), &[], served(false, true), now))
            .expect_err("a listed leaf is refused");
        assert!(
            err.contains("revoked") && err.contains("asx vector leaf"),
            "{err}"
        );
        let err = block_on(decide(&profile, &p.path(), &[], served(true, false), now))
            .expect_err("a listed Sub-CA is refused");
        assert!(err.contains("asx vector sub"), "{err}");
    }
}

#[test]
fn bdew_refuses_a_crl_past_next_update_and_a_missing_distribution_point() {
    let now = SystemTime::now();
    let p = pki(IssueOptions::default());
    let stale = p
        .sub
        .crl_builder()
        .this_update(now - 72 * HOUR)
        .next_update(Some(now - 24 * HOUR))
        .build();
    let served = vec![
        (p.root.crl_url().to_string(), p.root.crl_builder().build()),
        (p.sub.crl_url().to_string(), stale),
    ];
    let err = block_on(decide(&Profile::bdew(), &p.path(), &[], served, now))
        .expect_err("a stale CRL distrusts its CA");
    assert!(
        err.contains("not renewed within its validity period"),
        "{err}"
    );

    let bare = pki(IssueOptions {
        cdp: Cdp::None,
        ..IssueOptions::default()
    });
    let served = vec![(
        bare.root.crl_url().to_string(),
        bare.root.crl_builder().build(),
    )];
    let err = block_on(decide(
        &Profile::bdew(),
        &bare.path(),
        &[],
        served.clone(),
        now,
    ))
    .expect_err("no CDP under bdew");
    assert!(err.contains("no CRL distribution point"), "{err}");
    block_on(decide(
        &Profile::edelivery_1_15(),
        &bare.path(),
        &[],
        served,
        now,
    ))
    .expect("accepted and recorded under a pin-based profile");
}

fn ocsp_leaf() -> (TestCa, KeyPair) {
    let root = TestCa::new("asx ocsp root", KeyAlg::EcP256);
    let leaf = root.issue_with_options(
        "asx ocsp leaf",
        KeyAlg::EcP256,
        IssueOptions {
            cdp: Cdp::None,
            ocsp: vec!["http://ocsp.vector.example/".into()],
            ..IssueOptions::default()
        },
    );
    (root, leaf)
}

#[test]
fn ocsp_revoked_refuses_good_accepts_stale_is_not_obtainable() {
    let now = SystemTime::now();
    let (root, leaf) = ocsp_leaf();
    let path = vec![der(&leaf.cert_pem), der(root.cert_pem())];
    let run = |response: Vec<u8>| {
        block_on(decide(
            &Profile::peppol(),
            &path,
            &[],
            vec![("http://ocsp.vector.example/".into(), response)],
            now,
        ))
    };
    let err = run(root.ocsp(&leaf, true, now - HOUR, now + HOUR)).expect_err("revoked");
    assert!(err.contains("revoked"), "{err}");
    run(root.ocsp(&leaf, false, now - HOUR, now + HOUR)).expect("good");
    let err = run(root.ocsp(&leaf, false, now - 48 * HOUR, now - 24 * HOUR))
        .expect_err("a two-day-old response is not fresh");
    assert!(err.contains("not obtainable"), "{err}");
    // BDEW consults no OCSP: the same certificate has no source.
    let err = block_on(decide(&Profile::bdew(), &path, &[], Vec::new(), now)).unwrap_err();
    assert!(err.contains("no CRL distribution point"), "{err}");
}

/// `leaf_stale.ocsp.der` (`thisUpdate` 2026-05-17) is permanently stale: the
/// one intentionally stale fixture, kept as the freshness control.
#[test]
fn ocsp_stale_response_is_refused_for_freshness() {
    let leaf = include_bytes!("fixtures/pki/leaf.cert.der");
    let issuer = include_bytes!("fixtures/pki/intermediate.cert.der");
    let err = ocsp_status(
        include_bytes!("fixtures/pki/leaf_stale.ocsp.der"),
        leaf,
        issuer,
        SystemTime::now(),
    )
    .expect_err("a stale OCSP response must be refused");
    assert!(
        err.contains("too old") || err.contains("expired") || err.contains("trusted"),
        "{err}"
    );
}

#[test]
fn a_minted_ocsp_response_is_judged_at_the_given_instant() {
    let (root, leaf) = ocsp_leaf();
    let now = SystemTime::now();
    let response = root.ocsp(&leaf, false, now - HOUR, now + HOUR);
    let (leaf_der, root_der) = (der(&leaf.cert_pem), der(root.cert_pem()));
    assert_eq!(
        ocsp_status(&response, &leaf_der, &root_der, now),
        Ok("good")
    );
    assert!(ocsp_status(&response, &leaf_der, &root_der, now + 3 * HOUR).is_err());
}
