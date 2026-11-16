//! The built-in client against a real TLS MSH on 127.0.0.1 (`TlsMsh`):
//! BDEW mutual TLS with BrainpoolP256r1 SM-PKI certificates (BDEW
//! AS4-Profil 1.2 §2.2.6.1, §2.3.4.4; BSI TR-03116-3 §4), SNI
//! (RzÜ AS4 2.6 Kap. 3), connection reuse, and every server-side refusal:
//! unknown CA, wrong host, missing serverAuth, revoked, a suite outside
//! TR-03116-3.
//! Each refusal happens before a request is written (the MSH serves none).
//!
//! The client reaches the loopback MSH only through `Builder::resolve`, the
//! explicit pin; nothing here relaxes a check.

use asx::as4::{As4, Message, UserMessage};
use asx::testkit::pki::{CRL_HOST, Eku, IssueOptions, KeyAlg, Nid, TestCa, TestParty};
use asx::testkit::revocation::RevocationHttp;
use asx::testkit::tls::TlsMsh;
use asx::{ErrorKind, MemoryDedup, Payload, Profile, Verified};

const MP: &str = "https://www.bdew.de/as4/communication/services/MP";
const US: &str = "9900000000001";
const THEM: &str = "9900000000002";
const THEM_URL: &str = "https://msh.test/as4";

struct World {
    ca: TestCa,
    us: TestParty,
    them: TestParty,
}

fn world() -> World {
    let ca = TestCa::sm_pki();
    World {
        us: ca.bdew_party(US),
        them: ca.bdew_party_at(THEM, THEM_URL),
        ca,
    }
}

/// The receiving side: `them`, verifying `us`; its revocation fetches are
/// served in-process.
fn receiver(w: &World) -> asx::Inbound {
    let receiver = As4::builder(Profile::bdew())
        .local(w.them.local())
        .trust_anchor(w.ca.anchor())
        .partner(w.us.partner(w.us.endpoint.as_deref().expect("endpoint")))
        .http_client(RevocationHttp::new())
        .build()
        .expect("receiver builds");
    receiver.inbound(
        MemoryDedup::default(),
        |_msg: Verified<UserMessage>| async { Ok(()) },
    )
}

/// The sending side over the built-in client, pinned to `msh`.
fn sender(w: &World, msh: &TlsMsh) -> As4 {
    As4::builder(Profile::bdew())
        .local(w.us.local())
        .trust_anchor(w.ca.anchor())
        .partner(w.them.partner(msh.url()))
        .resolve(msh.host(), msh.addr())
        .resolve(CRL_HOST, msh.crl_addr())
        .build()
        .expect("sender builds")
}

fn message(w: &World, msh: &TlsMsh) -> Message {
    Message::to(&w.them.partner(msh.url())).service(MP).payload(
        Payload::new(b"UNA:+.? 'UNB+UNOC:3'".to_vec(), "application/edifact")
            .property("BDEWDocumentType", "UTILMD")
            .property("BDEWDocumentDate", "2026-11-16")
            .property("BDEWDocumentNo", "ABC123"),
    )
}

/// A TLS certificate for `them` with one thing changed.
fn tls_cert(ca: &TestCa, host: &str, eku: Vec<Eku>, alg: KeyAlg) -> asx::testkit::pki::KeyPair {
    ca.issue_with_options(
        "tls",
        alg,
        IssueOptions {
            subject: vec![
                (Nid::COMMONNAME, "Test MP tls".to_string()),
                (Nid::ORGANIZATIONALUNITNAME, THEM.to_string()),
            ],
            uri_sans: vec![THEM_URL.to_string()],
            dns_sans: vec![host.to_string()],
            eku,
            ..IssueOptions::default()
        },
    )
}

async fn refused_before_writing(w: &World, server: &TestParty) -> (asx::Error, usize) {
    let msh = TlsMsh::start(server, &w.ca, receiver(w)).await;
    let err = sender(w, &msh)
        .send(message(w, &msh))
        .await
        .expect_err("the handshake must be refused");
    (err, msh.requests())
}

#[tokio::test]
async fn bdew_mutual_tls_with_brainpool_delivers_and_presents_the_tls_identity() {
    let w = world();
    let msh = TlsMsh::start(&w.them, &w.ca, receiver(&w)).await;
    let client = sender(&w, &msh);
    for _ in 0..3 {
        let receipt = client.send(message(&w, &msh)).await.expect("receipt");
        assert_eq!(receipt.evidence().partner(), THEM);
    }
    // One handshake carries all three sends.
    assert_eq!(msh.handshakes(), 1, "the connection is pooled");
    assert_eq!(msh.requests(), 3);
    // The configured TLS identity reached the wire.
    let chains = msh.client_certificates();
    assert_eq!(chains[0][0], w.us.tls.certificate());
    // RzÜ AS4 2.6 Kap. 3: SNI is the endpoint host.
    assert_eq!(msh.server_names(), vec![Some("msh.test".to_string())]);
}

#[tokio::test]
async fn a_server_certificate_from_an_unknown_ca_is_refused() {
    let w = world();
    let stranger = TestCa::sm_pki();
    let server = TestParty {
        tls: tls_cert(
            &stranger,
            "msh.test",
            vec![Eku::ServerAuth],
            KeyAlg::EcBrainpoolP256r1,
        ),
        ..w.them.clone()
    };
    let (err, requests) = refused_before_writing(&w, &server).await;
    assert_eq!(err.kind(), ErrorKind::Transport, "{err}");
    assert!(err.to_string().contains("not trusted"), "{err}");
    assert_eq!(requests, 0);
}

#[tokio::test]
async fn a_server_certificate_for_another_host_is_refused() {
    let w = world();
    let server = TestParty {
        tls: tls_cert(
            &w.ca,
            "other.test",
            vec![Eku::ServerAuth],
            KeyAlg::EcBrainpoolP256r1,
        ),
        ..w.them.clone()
    };
    let (err, requests) = refused_before_writing(&w, &server).await;
    assert_eq!(err.kind(), ErrorKind::Transport, "{err}");
    assert!(err.to_string().contains("not trusted"), "{err}");
    assert_eq!(requests, 0);
}

#[tokio::test]
async fn a_server_certificate_without_server_auth_is_refused() {
    let w = world();
    let server = TestParty {
        tls: tls_cert(
            &w.ca,
            "msh.test",
            vec![Eku::ClientAuth],
            KeyAlg::EcBrainpoolP256r1,
        ),
        ..w.them.clone()
    };
    let (err, requests) = refused_before_writing(&w, &server).await;
    assert_eq!(err.kind(), ErrorKind::Transport, "{err}");
    assert_eq!(requests, 0);
}

#[tokio::test]
async fn a_revoked_server_certificate_is_refused_before_writing() {
    let w = world();
    w.ca.revoke(&w.them.tls);
    let (err, requests) = refused_before_writing(&w, &w.them).await;
    assert_eq!(err.kind(), ErrorKind::Transport, "{err}");
    assert!(err.to_string().contains("revoked"), "{err}");
    assert_eq!(requests, 0, "nothing was written to a revoked server");
}

#[tokio::test]
async fn a_server_outside_tr_03116_is_refused() {
    // An RSA server certificate: no TR-03116-3 suite (ECDHE-ECDSA only)
    // can be negotiated with it.
    let w = world();
    let server = TestParty {
        tls: tls_cert(&w.ca, "msh.test", vec![Eku::ServerAuth], KeyAlg::Rsa2048),
        ..w.them.clone()
    };
    let (err, requests) = refused_before_writing(&w, &server).await;
    assert_eq!(err.kind(), ErrorKind::Transport, "{err}");
    assert_eq!(requests, 0);
}

#[tokio::test]
async fn without_the_pin_the_loopback_msh_is_unreachable() {
    let w = world();
    let msh = TlsMsh::start(&w.them, &w.ca, receiver(&w)).await;
    // The CRL host is pinned, the MSH is not: msh.test does not resolve
    // (and a loopback answer would be refused).
    let client = As4::builder(Profile::bdew())
        .local(w.us.local())
        .trust_anchor(w.ca.anchor())
        .partner(w.them.partner(msh.url()))
        .resolve(CRL_HOST, msh.crl_addr())
        .build()
        .expect("builds");
    let err = client.send(message(&w, &msh)).await.expect_err("unpinned");
    assert_eq!(err.kind(), ErrorKind::Transport, "{err}");
    assert_eq!(msh.handshakes(), 0);
}

#[tokio::test]
async fn the_pin_is_visible_in_debug() {
    let w = world();
    let builder = As4::builder(Profile::bdew())
        .local(w.us.local())
        .resolve("MSH.test", "127.0.0.1:4443".parse().unwrap());
    let shown = format!("{builder:?}");
    assert!(
        shown.contains("msh.test") && shown.contains("127.0.0.1:4443"),
        "{shown}"
    );
}

#[tokio::test]
async fn bdew_mutual_tls_over_tls_1_2() {
    // The path a peer on OpenSSL before 3.2 takes: Brainpool ECDHE and ECDSA
    // in TLS 1.2.
    let w = world();
    let msh = TlsMsh::start_tls12(&w.them, &w.ca, receiver(&w)).await;
    sender(&w, &msh)
        .send(message(&w, &msh))
        .await
        .expect("receipt over TLS 1.2");
    assert_eq!(msh.client_certificates()[0][0], w.us.tls.certificate());
}
