#![cfg(feature = "as2")]
//! AS2 S/MIME oracle: validate asx's AS2 wire output with the `openssl smime`
//! CLI — the most widely deployed S/MIME implementation — and asx's AS2
//! receive path with messages **produced by** that CLI.
//!
//! Every in-crate AS2 test verifies asx output with asx's own verifier, which
//! proves self-consistency, not interoperability. This oracle covers both
//! directions of the trust question without any container:
//!
//! - **asx → openssl**: a signed (and a signed+encrypted) AS2 message is
//!   verified/decrypted by `openssl smime`, and the recovered entity must
//!   round-trip the payload byte-for-byte.
//! - **openssl → asx**: `openssl smime -sign`/`-encrypt` produce inbound
//!   messages that an `As2::inbound` must verify, decrypt and deliver. openssl output
//!   differs from asx output in ways that matter — a MIME preamble line
//!   before the first boundary and the legacy
//!   `application/x-pkcs7-signature` protocol parameter — so this direction
//!   exercises tolerance the round-trip tests cannot.
//!
//! Requires an `openssl` binary. `#[ignore]`d to keep `cargo test` hermetic:
//!
//! ```text
//! cargo test --all-features --test interop_openssl_smime_oracle -- --ignored --nocapture
//! ```

use std::path::{Path, PathBuf};
use std::process::Command;

/// A self-signed RSA-2048 certificate and key from the test PKI.
fn self_signed_rsa(subject_cn: &str) -> (Vec<u8>, Vec<u8>) {
    let pair =
        asx_testkit::pki::KeyPair::self_signed(subject_cn, asx_testkit::pki::KeyAlg::Rsa2048);
    (pair.cert_pem, pair.key_pem)
}

const PAYLOAD: &[u8] = b"ISA*00*          *00*          *ZZ*ORACLE~";
const CONTENT_TYPE: &str = "application/edi-x12";

struct Identity {
    cert_pem: String,
    key_pem: Vec<u8>,
    dir: PathBuf,
}

fn identity(test: &str) -> Identity {
    let (cert, key) = self_signed_rsa("asx-smime-oracle");
    let cert_pem = String::from_utf8(cert).expect("utf8 cert");
    let dir = std::env::temp_dir().join(format!("asx-smime-{test}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("dir");
    std::fs::write(dir.join("cert.pem"), &cert_pem).expect("cert");
    std::fs::write(dir.join("key.pem"), &key).expect("key");
    Identity {
        cert_pem,
        key_pem: key,
        dir,
    }
}

/// An AS2 entity as asx emits it: signed by `id`, and encrypted to `id` when
/// `encrypt` (the client's packaging, through `asx::__fuzz::as2_raw_message`).
/// Returns `(Content-Type, body)`.
fn send(id: &Identity, encrypt: bool) -> (String, Vec<u8>) {
    asx::__fuzz::as2_raw_message(
        PAYLOAD,
        CONTENT_TYPE,
        "oracle-sender",
        Some((id.cert_pem.as_bytes(), &id.key_pem)),
        encrypt.then_some(id.cert_pem.as_bytes()),
    )
    .expect("as2 send")
}

/// Write an AS2 wire message as a standalone MIME file the `openssl smime`
/// CLI can consume. asx wire bodies may already embed the outer MIME headers
/// (OpenSSL `SMIME_write_*` output does); only synthesize them when absent.
fn write_eml(dir: &Path, name: &str, content_type: &str, body: &[u8]) -> PathBuf {
    let path = dir.join(name);
    let has_headers = body.starts_with(b"MIME-Version")
        || body.starts_with(b"Content-Type")
        || body.starts_with(b"Content-Disposition");
    let mut eml = if has_headers {
        Vec::new()
    } else {
        format!("MIME-Version: 1.0\r\nContent-Type: {content_type}\r\n\r\n").into_bytes()
    };
    eml.extend_from_slice(body);
    std::fs::write(&path, eml).expect("write eml");
    path
}

fn openssl(dir: &Path, args: &[&str]) -> Vec<u8> {
    let out = Command::new("openssl")
        .args(args)
        .current_dir(dir)
        .output()
        .expect("run openssl (is an openssl binary installed?)");
    assert!(
        out.status.success(),
        "openssl {args:?} failed:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    out.stdout
}

/// Split a MIME file into (Content-Type header value, body bytes).
fn split_eml(raw: &[u8]) -> (String, Vec<u8>) {
    let text = String::from_utf8_lossy(raw);
    // Line endings are not uniform: openssl writes LF while embedded entities
    // may use CRLF. Take whichever header/body separator comes first.
    let crlf = text.find("\r\n\r\n").map(|i| (i, 4));
    let lf = text.find("\n\n").map(|i| (i, 2));
    let (idx, sep) = match (crlf, lf) {
        (Some(a), Some(b)) => {
            if a.0 <= b.0 {
                a
            } else {
                b
            }
        }
        (Some(a), None) => a,
        (None, Some(b)) => b,
        (None, None) => panic!("MIME header/body separator"),
    };
    let headers = &text[..idx];
    let mut content_type = String::new();
    let mut in_ct = false;
    for line in headers.lines() {
        if line.to_ascii_lowercase().starts_with("content-type:") {
            content_type = line["content-type:".len()..].trim().to_string();
            in_ct = true;
        } else if in_ct && (line.starts_with(' ') || line.starts_with('\t')) {
            content_type.push(' ');
            content_type.push_str(line.trim());
        } else {
            in_ct = false;
        }
    }
    assert!(!content_type.is_empty(), "Content-Type header present");
    (content_type, raw[idx + sep..].to_vec())
}

// ── asx → openssl ───────────────────────────────────────────────────────────

#[test]
#[ignore = "requires an openssl binary; run with --ignored"]
fn openssl_verifies_asx_signed_message_and_recovers_the_payload() {
    let id = identity("out-signed");
    let (content_type, body) = send(&id, false);
    let eml = write_eml(&id.dir, "asx-signed.eml", &content_type, &body);

    // `-purpose any`: the fixture certificate carries no S/MIME EKU, and the
    // oracle question is signature/entity correctness, not certificate policy.
    let verified = openssl(
        &id.dir,
        &[
            "smime",
            "-verify",
            "-in",
            eml.to_str().unwrap(),
            "-CAfile",
            "cert.pem",
            "-purpose",
            "any",
        ],
    );

    // The verified octets are the RFC 4130 signed entity: the payload's own
    // MIME headers plus the payload, exactly as MIC'd.
    let text = String::from_utf8_lossy(&verified);
    assert!(
        text.contains(CONTENT_TYPE),
        "signed entity must carry the payload Content-Type: {text}"
    );
    assert!(
        verified
            .windows(PAYLOAD.len())
            .any(|window| window == PAYLOAD),
        "signed entity must contain the payload verbatim"
    );

    let _ = std::fs::remove_dir_all(&id.dir);
}

#[test]
#[ignore = "requires an openssl binary; run with --ignored"]
fn openssl_decrypts_and_verifies_asx_encrypted_signed_message() {
    let id = identity("out-enc");
    let (content_type, body) = send(&id, true);
    let eml = write_eml(&id.dir, "asx-enc.eml", &content_type, &body);

    let decrypted = openssl(
        &id.dir,
        &[
            "smime",
            "-decrypt",
            "-in",
            eml.to_str().unwrap(),
            "-recip",
            "cert.pem",
            "-inkey",
            "key.pem",
        ],
    );
    std::fs::write(id.dir.join("decrypted.eml"), &decrypted).expect("write");

    // The decrypted content is the signed entity; verify it too.
    let verified = openssl(
        &id.dir,
        &[
            "smime",
            "-verify",
            "-in",
            "decrypted.eml",
            "-CAfile",
            "cert.pem",
            "-purpose",
            "any",
        ],
    );
    assert!(
        verified
            .windows(PAYLOAD.len())
            .any(|window| window == PAYLOAD),
        "decrypt→verify must recover the payload"
    );

    let _ = std::fs::remove_dir_all(&id.dir);
}

// ── openssl → asx `Inbound` → openssl ───────────────────────────────────────

#[path = "common/as2_peers.rs"]
mod as2_peers;

/// An openssl-driven partner `OPENSSL` sending to the `Inbound` of
/// `as2_peers::B_ID`. Both are issued by one test CA; openssl gets the
/// partner's key and certificate, the receiver's certificate and the CA as
/// files.
struct OracleInbound {
    dir: PathBuf,
    loopback: asx_testkit::loopback::Loopback,
    delivered: as2_peers::Delivered,
}

const ORACLE_ID: &str = "OPENSSL";

fn oracle_inbound(test: &str) -> OracleInbound {
    use std::sync::Arc;
    let ca = asx_testkit::pki::TestCa::new("asx-oracle root", asx_testkit::pki::KeyAlg::Rsa2048);
    let (partner, receiver) = (ca.as2_party(ORACLE_ID), ca.as2_party(as2_peers::B_ID));
    let dir = std::env::temp_dir().join(format!("asx-smime-{test}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("dir");
    std::fs::write(dir.join("cert.pem"), &partner.signing.cert_pem).expect("cert");
    std::fs::write(dir.join("key.pem"), &partner.signing.key_pem).expect("key");
    std::fs::write(dir.join("receiver.pem"), &receiver.encryption.cert_pem).expect("receiver");
    std::fs::write(dir.join("ca.pem"), ca.cert_pem()).expect("ca");
    let loopback = asx_testkit::loopback::Loopback::new();
    let client = asx::as2::As2::builder(asx::Profile::as2())
        .local(receiver.local())
        .trust_anchor(ca.anchor())
        .partner(partner.partner("https://oracle.example/as2"))
        .http_client(loopback.clone())
        .build()
        .expect("receiver builds");
    let delivered: as2_peers::Delivered = Arc::default();
    let handler = as2_peers::handler(Arc::default(), Arc::default(), delivered.clone());
    loopback.mount(
        as2_peers::B_URL,
        client.inbound(asx::MemoryDedup::default(), handler),
    );
    OracleInbound {
        dir,
        loopback,
        delivered,
    }
}

impl OracleInbound {
    /// The RFC 4130 entity, signed by openssl as the partner.
    fn signed(&self) -> (Vec<u8>, String, Vec<u8>) {
        let entity = format!(
            "Content-Type: {CONTENT_TYPE}\r\n\r\n{}",
            String::from_utf8_lossy(PAYLOAD)
        );
        std::fs::write(self.dir.join("entity.bin"), entity.as_bytes()).expect("entity");
        let signed = openssl(
            &self.dir,
            &[
                "smime",
                "-sign",
                "-binary",
                "-in",
                "entity.bin",
                "-signer",
                "cert.pem",
                "-inkey",
                "key.pem",
            ],
        );
        let (content_type, body) = split_eml(&signed);
        (entity.into_bytes(), content_type, body)
    }

    /// Signed, then encrypted to the receiver (AS2 sign-then-encrypt).
    fn signed_and_encrypted(&self) -> (Vec<u8>, String, Vec<u8>) {
        let (entity, signed_ct, signed_body) = self.signed();
        write_eml(&self.dir, "signed-full.eml", &signed_ct, &signed_body);
        let encrypted = openssl(
            &self.dir,
            &[
                "smime",
                "-encrypt",
                "-binary",
                "-aes256",
                "-in",
                "signed-full.eml",
                "receiver.pem",
            ],
        );
        let (content_type, body) = split_eml(&encrypted);
        (entity, content_type, body)
    }

    async fn post(
        &self,
        message_id: &str,
        content_type: &str,
        body: Vec<u8>,
    ) -> http::Response<bytes::Bytes> {
        let request = http::Request::post(as2_peers::B_URL)
            .header("AS2-Version", "1.2")
            .header("AS2-From", ORACLE_ID)
            .header("AS2-To", as2_peers::B_ID)
            .header("Message-ID", format!("<{message_id}>"))
            .header("Content-Type", content_type)
            .header("Disposition-Notification-To", ORACLE_ID)
            .header(
                "Disposition-Notification-Options",
                "signed-receipt-protocol=optional, pkcs7-signature; signed-receipt-micalg=optional, sha-256",
            )
            .body(bytes::Bytes::from(body))
            .unwrap();
        self.loopback.exchange(request).await.expect("mounted")
    }

    /// openssl verifies the MDN's signature against the CA and returns the
    /// signed report.
    fn openssl_verifies_mdn(&self, mdn: &http::Response<bytes::Bytes>) -> String {
        let content_type = mdn.headers()["content-type"].to_str().unwrap().to_string();
        write_eml(&self.dir, "mdn.eml", &content_type, mdn.body());
        let report = openssl(
            &self.dir,
            &[
                "smime", "-verify", "-in", "mdn.eml", "-CAfile", "ca.pem", "-purpose", "any",
            ],
        );
        String::from_utf8_lossy(&report).into_owned()
    }
}

fn report_field(report: &str, name: &str) -> Option<String> {
    report.lines().find_map(|line| {
        let (n, v) = line.split_once(':')?;
        n.trim()
            .eq_ignore_ascii_case(name)
            .then(|| v.trim().to_string())
    })
}

#[tokio::test]
#[ignore = "requires an openssl binary; run with --ignored"]
async fn inbound_accepts_openssl_signed_and_encrypted_and_openssl_verifies_the_mdn_and_mic() {
    use base64::Engine as _;
    use sha2::Digest as _;
    let oracle = oracle_inbound("inbound-0-16");
    let (entity, content_type, body) = oracle.signed_and_encrypted();
    let resp = oracle.post("oracle-1@test", &content_type, body).await;
    assert_eq!(resp.status(), http::StatusCode::OK);
    let report = oracle.openssl_verifies_mdn(&resp);
    let disposition = report_field(&report, "Disposition").expect("Disposition");
    assert!(disposition.ends_with("; processed"), "{disposition}");
    assert_eq!(
        report_field(&report, "Original-Message-ID").as_deref(),
        Some("<oracle-1@test>")
    );
    // The MIC is over the entity openssl signed, octet for octet.
    let expected = base64::engine::general_purpose::STANDARD.encode(sha2::Sha256::digest(&entity));
    assert_eq!(
        report_field(&report, "Received-Content-MIC").as_deref(),
        Some(format!("{expected}, sha-256").as_str())
    );
    let delivered = oracle.delivered.lock().unwrap();
    assert_eq!(delivered[0].2, PAYLOAD);
    assert_eq!(delivered[0].1, ORACLE_ID);
    let _ = std::fs::remove_dir_all(&oracle.dir);
}

#[tokio::test]
#[ignore = "requires an openssl binary; run with --ignored"]
async fn inbound_refuses_an_openssl_signed_but_unencrypted_message() {
    let oracle = oracle_inbound("inbound-0-16-unenc");
    let (_, content_type, body) = oracle.signed();
    let resp = oracle.post("oracle-2@test", &content_type, body).await;
    let report = oracle.openssl_verifies_mdn(&resp);
    let disposition = report_field(&report, "Disposition").expect("Disposition");
    assert!(
        disposition.ends_with("processed/error: insufficient-message-security"),
        "{disposition}"
    );
    assert!(oracle.delivered.lock().unwrap().is_empty());
    let _ = std::fs::remove_dir_all(&oracle.dir);
}

// ── External keys ───────────────────────────────────────────────────────────

/// openssl decrypts and verifies what `As2::send` produced with an external
/// ECDSA signer (the CMS `SignedData` assembled around one `Signer::sign`),
/// and the receiving `Inbound` accepted it.
#[tokio::test]
#[ignore = "requires an openssl binary; run with --ignored"]
async fn openssl_verifies_a_client_message_signed_by_an_external_ec_signer() {
    use asx_testkit::keys::CountingKeys;
    use asx_testkit::pki::{KeyAlg, TestCa};
    let ca = TestCa::new("asx-oracle ext root", KeyAlg::Rsa2048);
    let (a, b) = (ca.as2_party(as2_peers::A_ID), ca.as2_party(as2_peers::B_ID));
    let ec = ca.issue("asx-oracle ec signer", KeyAlg::EcP256);
    let signer = CountingKeys::new(&ec);
    let loopback = asx_testkit::loopback::Loopback::new();
    let to_b = b.partner(as2_peers::B_URL);
    let sender = asx::as2::As2::builder(asx::Profile::as2())
        .local(
            asx::LocalParty::new(as2_peers::A_ID)
                .signer(signer.clone())
                .decrypter(CountingKeys::new(&a.encryption)),
        )
        .trust_anchor(ca.anchor())
        .partner(to_b.clone())
        .http_client(loopback.clone())
        .build()
        .expect("sender builds");
    let receiver = asx::as2::As2::builder(asx::Profile::as2())
        .local(b.local())
        .trust_anchor(ca.anchor())
        .partner(
            asx::Partner::new(as2_peers::A_ID)
                .endpoint(as2_peers::A_URL)
                .signing_cert(ec.certificate())
                .encryption_cert(a.encryption.certificate()),
        )
        .http_client(loopback.clone())
        .build()
        .expect("receiver builds");
    let delivered: as2_peers::Delivered = std::sync::Arc::default();
    loopback.mount(
        as2_peers::B_URL,
        receiver.inbound(
            asx::MemoryDedup::default(),
            as2_peers::handler(Default::default(), Default::default(), delivered.clone()),
        ),
    );
    sender
        .send(asx::as2::Message::to(
            &to_b,
            asx::Payload::new(PAYLOAD.to_vec(), CONTENT_TYPE),
        ))
        .await
        .expect("delivered with an external EC signer");
    assert_eq!(signer.signs(), 1, "one signature per message");
    assert_eq!(delivered.lock().unwrap()[0].2, PAYLOAD);

    let dir = std::env::temp_dir().join(format!("asx-smime-ext-ec-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("dir");
    std::fs::write(dir.join("b.pem"), &b.encryption.cert_pem).expect("cert");
    std::fs::write(dir.join("b.key"), &b.encryption.key_pem).expect("key");
    std::fs::write(dir.join("ca.pem"), ca.cert_pem()).expect("ca");
    let request = loopback.last_request().expect("the message was posted");
    let content_type = request.headers()["content-type"]
        .to_str()
        .unwrap()
        .to_string();
    let eml = write_eml(&dir, "sent.eml", &content_type, request.body());
    let decrypted = openssl(
        &dir,
        &[
            "smime",
            "-decrypt",
            "-in",
            eml.to_str().unwrap(),
            "-recip",
            "b.pem",
            "-inkey",
            "b.key",
        ],
    );
    std::fs::write(dir.join("signed.eml"), &decrypted).expect("write");
    let verified = openssl(
        &dir,
        &[
            "smime",
            "-verify",
            "-in",
            "signed.eml",
            "-CAfile",
            "ca.pem",
            "-purpose",
            "any",
        ],
    );
    assert!(
        verified
            .windows(PAYLOAD.len())
            .any(|window| window == PAYLOAD),
        "openssl recovers the payload from the externally signed entity"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// openssl `cms -encrypt -keyid` (an SKI `RecipientIdentifier`) with
/// AES-128-CBC: the `Inbound` selects the decrypter by SKI and opens it.
#[tokio::test]
#[ignore = "requires an openssl binary; run with --ignored"]
async fn inbound_opens_an_openssl_cms_aes128_message_addressed_by_ski() {
    let oracle = oracle_inbound("inbound-ski-aes128");
    let (_, signed_ct, signed_body) = oracle.signed();
    write_eml(&oracle.dir, "signed-full.eml", &signed_ct, &signed_body);
    let encrypted = openssl(
        &oracle.dir,
        &[
            "cms",
            "-encrypt",
            "-binary",
            "-keyid",
            "-aes128",
            "-in",
            "signed-full.eml",
            "receiver.pem",
        ],
    );
    let (content_type, body) = split_eml(&encrypted);
    let resp = oracle.post("oracle-ski@test", &content_type, body).await;
    let report = oracle.openssl_verifies_mdn(&resp);
    let disposition = report_field(&report, "Disposition").expect("Disposition");
    assert!(disposition.ends_with("; processed"), "{disposition}");
    assert_eq!(oracle.delivered.lock().unwrap()[0].2, PAYLOAD);
    let _ = std::fs::remove_dir_all(&oracle.dir);
}
