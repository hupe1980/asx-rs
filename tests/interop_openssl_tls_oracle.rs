//! TLS oracle: the OpenSSL command line as the foreign implementation of
//! BDEW mutual TLS (BDEW AS4-Profil 1.2 Kap. 2.2.6.1; BSI TR-03116-3 §4).
//!
//! - **asx → `openssl s_server`**: the built-in client completes a mutually
//!   authenticated BrainpoolP256r1 handshake with a server that demands a
//!   client certificate (`-Verify 1 -verify_return_error`), and the server
//!   reports the configured TLS identity's subject. Without a TLS identity
//!   `build()` refuses the BDEW configuration; with a TLS identity the
//!   server does not trust, the server ends the handshake.
//! - **`openssl s_client` → `TlsMsh`**: the testkit MSH speaks the same TLS
//!   to a foreign client, verifies its client certificate and records it.
//!
//! Requires an `openssl` binary (CI's interop job installs it). `#[ignore]`d
//! to keep `cargo test` hermetic:
//!
//! ```text
//! cargo test --all-features --test interop_openssl_tls_oracle -- --ignored --nocapture
//! ```

use asx::as4::{As4, Message, UserMessage};
use asx::testkit::pki::{CRL_HOST, TestCa, TestParty};
use asx::testkit::revocation::RevocationHttp;
use asx::testkit::tls::TlsMsh;
use asx::{MemoryDedup, Payload, Profile, Verified};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

const MP: &str = "https://www.bdew.de/as4/communication/services/MP";
const THEM_URL: &str = "https://msh.test/as4";

struct World {
    ca: TestCa,
    us: TestParty,
    them: TestParty,
    dir: PathBuf,
}

fn world(test: &str) -> World {
    let ca = TestCa::sm_pki();
    let dir = std::env::temp_dir().join(format!("asx-tls-{test}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    World {
        us: ca.bdew_party("9900000000001"),
        them: ca.bdew_party_at("9900000000002", THEM_URL),
        ca,
        dir,
    }
}

fn write(dir: &Path, name: &str, bytes: &[u8]) -> PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, bytes).expect("write");
    path
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("bind")
        .local_addr()
        .expect("addr")
        .port()
}

/// `openssl s_server` with `them`'s TLS certificate, demanding a client
/// certificate under `client_ca`.
fn s_server(w: &World, port: u16, client_ca: &TestCa) -> Child {
    let cert = write(&w.dir, "server.pem", &w.them.tls.cert_pem);
    let key = write(&w.dir, "server.key", &w.them.tls.key_pem);
    let ca = write(&w.dir, "client-ca.pem", client_ca.cert_pem());
    let child = Command::new("openssl")
        .args(["s_server", "-accept"])
        .arg(format!("127.0.0.1:{port}"))
        .arg("-cert")
        .arg(&cert)
        .arg("-key")
        .arg(&key)
        .arg("-CAfile")
        .arg(&ca)
        .args(["-Verify", "1", "-verify_return_error"])
        // Open stdin: s_server ends at EOF on it.
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("an openssl binary on PATH");
    // Wait until it listens.
    for _ in 0..100 {
        if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    child
}

fn output(mut child: Child) -> String {
    let _ = child.kill();
    let _ = child.wait();
    let mut out = String::new();
    if let Some(mut s) = child.stdout.take() {
        let _ = s.read_to_string(&mut out);
    }
    if let Some(mut s) = child.stderr.take() {
        let _ = s.read_to_string(&mut out);
    }
    out
}

/// A receiver whose CRLs a `TlsMsh` serves: the client's server-chain
/// revocation check fetches them from its CRL listener.
async fn crl_server(w: &World) -> TlsMsh {
    let receiver = As4::builder(Profile::bdew())
        .local(w.them.local())
        .trust_anchor(w.ca.anchor())
        .http_client(RevocationHttp::new())
        .build()
        .expect("receiver");
    let inbound = receiver.inbound(MemoryDedup::default(), |_m: Verified<UserMessage>| async {
        Ok(())
    });
    TlsMsh::start(&w.them, &w.ca, inbound).await
}

fn client(w: &World, port: u16, crl: &TlsMsh, local: asx::LocalParty) -> asx::Result<As4> {
    As4::builder(Profile::bdew())
        .local(local)
        .trust_anchor(w.ca.anchor())
        .partner(w.them.partner(THEM_URL))
        .resolve("msh.test", format!("127.0.0.1:{port}").parse().unwrap())
        .resolve(CRL_HOST, crl.crl_addr())
        .build()
}

fn message(w: &World) -> Message {
    Message::to(&w.them.partner(THEM_URL)).service(MP).payload(
        Payload::new(b"UNB".to_vec(), "application/edifact")
            .property("BDEWDocumentType", "UTILMD")
            .property("BDEWDocumentDate", "2026-11-16")
            .property("BDEWDocumentNo", "1"),
    )
}

#[tokio::test]
#[ignore = "needs the openssl CLI"]
async fn openssl_s_server_accepts_our_brainpool_client_certificate() {
    let w = world("s-server");
    let crl = crl_server(&w).await;
    let port = free_port();
    let server = s_server(&w, port, &w.ca);
    // s_server prints the peer certificate and never answers the POST: the
    // handshake is what the oracle judges, so the send is cut short.
    let as4 = client(&w, port, &crl, w.us.local()).expect("builds");
    let _ = tokio::time::timeout(Duration::from_secs(3), as4.send(message(&w))).await;
    let out = output(server);
    assert!(
        out.contains("OU=9900000000001") || out.contains("OU = 9900000000001"),
        "s_server saw our TLS certificate:\n{out}"
    );
    assert!(!out.contains("verify error"), "{out}");
}

#[tokio::test]
#[ignore = "needs the openssl CLI"]
async fn openssl_s_server_refuses_an_untrusted_client_certificate() {
    let w = world("s-server-untrusted");
    let crl = crl_server(&w).await;
    let port = free_port();
    // The server trusts only another CA for client certificates.
    let server = s_server(&w, port, &TestCa::sm_pki());
    let as4 = client(&w, port, &crl, w.us.local()).expect("builds");
    let err = tokio::time::timeout(Duration::from_secs(10), as4.send(message(&w)))
        .await
        .expect("the handshake ends promptly")
        .expect_err("the server ends the handshake");
    let out = output(server);
    assert!(!out.contains("OU=9900000000001,"), "{out}");
    // TLS 1.2 refuses inside the handshake (not written: Transport); TLS 1.3
    // completes the client's side first and the server's alert arrives with
    // the response (possibly written: Indeterminate). Both are retryable
    // failures, never a receipt.
    assert!(
        matches!(
            err.kind(),
            asx::ErrorKind::Transport | asx::ErrorKind::Indeterminate
        ),
        "{err}"
    );
    assert!(
        err.to_string().contains("alert") || err.to_string().contains("TLS"),
        "{err}"
    );
}

#[tokio::test]
#[ignore = "needs the openssl CLI"]
async fn without_a_tls_identity_a_bdew_client_does_not_build() {
    let w = world("no-identity");
    let crl = crl_server(&w).await;
    let local = asx::LocalParty::new(&w.us.id)
        .party_type(asx::testkit::pki::BDEW_PARTY_TYPE)
        .signer(w.us.signing.key_pair())
        .decrypter(w.us.encryption.key_pair());
    let err = client(&w, free_port(), &crl, local).expect_err("Kap. 2.2.6.1");
    assert!(
        err.to_string().contains("LocalParty::tls_identity"),
        "{err}"
    );
    assert!(
        err.to_string().contains("BDEW AS4-Profil 1.2 Kap. 2.2.6.1"),
        "{err}"
    );
}

#[tokio::test]
#[ignore = "needs the openssl CLI"]
async fn openssl_s_client_verifies_the_testkit_msh() {
    let w = world("s-client");
    let msh = crl_server(&w).await;
    let cert = write(&w.dir, "client.pem", &w.us.tls.cert_pem);
    let key = write(&w.dir, "client.key", &w.us.tls.key_pem);
    let ca = write(&w.dir, "ca.pem", w.ca.cert_pem());
    let addr = msh.addr();
    let run = move |with_cert: bool| {
        let mut cmd = Command::new("openssl");
        cmd.args(["s_client", "-connect"])
            .arg(addr.to_string())
            .args(["-servername", "msh.test", "-verify_hostname", "msh.test"])
            .args(["-verify_return_error", "-brief"])
            .arg("-CAfile")
            .arg(&ca);
        if with_cert {
            cmd.arg("-cert").arg(&cert).arg("-key").arg(&key);
        }
        let out = cmd
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .expect("an openssl binary on PATH");
        format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        )
    };
    let out = tokio::task::spawn_blocking(move || run(true))
        .await
        .unwrap();
    assert!(out.contains("Verification: OK"), "{out}");
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(msh.handshakes(), 1, "{out}");
    assert_eq!(msh.client_certificates()[0][0], w.us.tls.certificate());
    // Without a client certificate the MSH refuses the handshake.
    let run = move || {
        Command::new("openssl")
            .args(["s_client", "-connect"])
            .arg(addr.to_string())
            .args(["-servername", "msh.test", "-brief"])
            .stdin(Stdio::null())
            .output()
            .expect("openssl")
    };
    let _ = tokio::task::spawn_blocking(run).await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        msh.handshakes(),
        1,
        "no handshake without a client certificate"
    );
}
