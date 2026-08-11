#![cfg(all(feature = "as2", feature = "testing"))]
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
//!   messages that asx must verify, decrypt and deliver. openssl output
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

use asx_rs::as2::{
    As2IngressReceiveRequest, As2MicAlgorithm, As2SendPolicy, As2SendRequest,
    CmsSmimeTrustVerifier, SmimeCipher, receive_from_ingress, send_sync,
};
use asx_rs::core::{InteropMode, OcspMode, SessionContextBuilder};
use asx_rs::fixtures::generate_self_signed_rsa_keypair;
use asx_rs::observability::EventBus;

const PAYLOAD: &[u8] = b"ISA*00*          *00*          *ZZ*ORACLE~";
const CONTENT_TYPE: &str = "application/edi-x12";

struct Identity {
    cert_pem: String,
    key_pem: Vec<u8>,
    fingerprint: String,
    dir: PathBuf,
}

fn identity(test: &str) -> Identity {
    let (cert, key) = generate_self_signed_rsa_keypair("asx-smime-oracle", 2048);
    let cert_pem = String::from_utf8(cert).expect("utf8 cert");

    let x509 = openssl::x509::X509::from_pem(cert_pem.as_bytes()).expect("x509");
    let fingerprint = x509
        .digest(openssl::hash::MessageDigest::sha256())
        .expect("fingerprint")
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();

    let dir = std::env::temp_dir().join(format!("asx-smime-{test}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("dir");
    std::fs::write(dir.join("cert.pem"), &cert_pem).expect("cert");
    std::fs::write(dir.join("key.pem"), &key).expect("key");

    Identity {
        cert_pem,
        key_pem: key,
        fingerprint,
        dir,
    }
}

fn session(id: &Identity) -> asx_rs::core::SessionContext {
    SessionContextBuilder::new("smime-oracle", "partner-oracle")
        .with_trust_anchor_pem(id.cert_pem.clone())
        // AS2 verification runs with PKCS7_NOINTERN: the signer leaf must be
        // supplied out-of-band.
        .with_intermediate_ca_pem(id.cert_pem.clone())
        .with_fingerprint_sha256(id.fingerprint.clone())
        .with_ocsp_mode(OcspMode::Disabled)
        .build()
        .expect("session")
        .with_strict_runtime_bootstrap_validated(true)
}

fn send(id: &Identity, sign: bool, encrypt: bool) -> asx_rs::as2::As2SendOutput {
    let bus = EventBus::new(16).expect("bus");
    let creds = asx_rs::as2::As2SendCredentials {
        signing_cert_pem: Some(id.cert_pem.clone().into_bytes().into()),
        signing_key_pem: Some(id.key_pem.clone()),
        recipient_cert_pem: Some(id.cert_pem.clone().into_bytes().into()),
    };
    send_sync(
        &session(id),
        &bus,
        As2SendRequest {
            message_id: "smime-oracle-msg".to_string(),
            payload: PAYLOAD.to_vec(),
            policy: As2SendPolicy {
                interop_mode: InteropMode::Strict,
                fail_closed_audit_events: false,
                sign,
                encrypt,
                compress: false,
                payload_content_type: Some(CONTENT_TYPE),
                as2_from_id: "oracle-sender".to_string(),
                mic_algorithm: As2MicAlgorithm::Sha256,
                encryption_cipher: SmimeCipher::Aes256Cbc,
            },
            credentials: Some(creds),
        },
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

fn receive(id: &Identity, content_type: &str, body: &[u8]) -> asx_rs::as2::As2InboundResult {
    let sess = session(id);
    let verifier = CmsSmimeTrustVerifier::with_decryption_credentials(
        id.key_pem.clone(),
        id.cert_pem.clone().into_bytes(),
    );
    receive_from_ingress(As2IngressReceiveRequest {
        session: &sess,
        payload: body,
        content_type,
        original_message_id: Some("smime-oracle-msg"),
        as2_from_header: "partner-oracle",
        disposition_notification_to: Some("http://oracle.test/mdn"),
        disposition_notification_options: Some("signed-receipt-micalg=required,sha-256"),
        mdn_signing_credentials: None,
        verifier: &verifier,
    })
    .expect("as2 receive")
}

// ── asx → openssl ───────────────────────────────────────────────────────────

#[test]
#[ignore = "requires an openssl binary; run with --ignored"]
fn openssl_verifies_asx_signed_message_and_recovers_the_payload() {
    let id = identity("out-signed");
    let out = send(&id, true, false);
    let eml = write_eml(
        &id.dir,
        "asx-signed.eml",
        &out.mime.content_type,
        &out.mime.body,
    );

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
    let out = send(&id, true, true);
    let eml = write_eml(
        &id.dir,
        "asx-enc.eml",
        &out.mime.content_type,
        &out.mime.body,
    );

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

// ── openssl → asx ───────────────────────────────────────────────────────────

/// Sign an RFC 4130 entity with openssl. `-binary` keeps the entity octets
/// verbatim as the first part of the resulting `multipart/signed`.
fn openssl_signed_message(id: &Identity) -> (String, Vec<u8>) {
    let entity = format!(
        "Content-Type: {CONTENT_TYPE}\r\n\r\n{}",
        String::from_utf8_lossy(PAYLOAD)
    );
    std::fs::write(id.dir.join("entity.bin"), entity.as_bytes()).expect("entity");

    let signed = openssl(
        &id.dir,
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
    split_eml(&signed)
}

#[test]
#[ignore = "requires an openssl binary; run with --ignored"]
fn asx_receives_an_openssl_signed_message() {
    let id = identity("in-signed");
    // openssl output differs from asx output on purpose: it carries a MIME
    // preamble ("This is an S/MIME signed message") and declares the legacy
    // protocol="application/x-pkcs7-signature".
    let (content_type, body) = openssl_signed_message(&id);

    let inbound = receive(&id, &content_type, &body);
    assert!(
        inbound.received_content_mic.is_some(),
        "a MIC must be computed for the MDN"
    );
    let content = inbound.content.into_inner();
    assert_eq!(
        &content[..],
        PAYLOAD,
        "asx must deliver the payload from an openssl-signed message"
    );

    let _ = std::fs::remove_dir_all(&id.dir);
}

#[test]
#[ignore = "requires an openssl binary; run with --ignored"]
fn asx_receives_an_openssl_signed_and_encrypted_message() {
    let id = identity("in-enc");
    let (signed_ct, signed_body) = openssl_signed_message(&id);

    // Re-assemble the full signed MIME message and encrypt it, as AS2
    // sign-then-encrypt requires.
    write_eml(&id.dir, "signed-full.eml", &signed_ct, &signed_body);
    let encrypted = openssl(
        &id.dir,
        &[
            "smime",
            "-encrypt",
            "-binary",
            "-aes256",
            "-in",
            "signed-full.eml",
            "cert.pem",
        ],
    );
    let (content_type, body) = split_eml(&encrypted);

    let inbound = receive(&id, &content_type, &body);
    let content = inbound.content.into_inner();
    assert_eq!(
        &content[..],
        PAYLOAD,
        "asx must decrypt, verify and deliver the payload"
    );

    let _ = std::fs::remove_dir_all(&id.dir);
}
