//! Dated test material: certificates
//! with a chosen validity window, and CRLs and OCSP responses with chosen
//! `thisUpdate`/`nextUpdate`. The dates are checked with the `openssl` CLI,
//! a foreign parser; a missing tool fails the test, it never skips it.

use asx::testkit::pki::{KeyAlg, KeyPair, TestCa, Validity};
use openssl::asn1::Asn1Time;
use openssl::x509::X509;
use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const HOUR: Duration = Duration::from_secs(3600);
const DAY: Duration = Duration::from_secs(86_400);

/// Whole seconds: certificate, CRL and OCSP times carry no fraction.
fn secs(t: SystemTime) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(t.duration_since(UNIX_EPOCH).unwrap().as_secs())
}

/// `t` as OpenSSL prints an ASN.1 time (`Jan  2 03:04:05 2026 GMT`).
fn printed(t: SystemTime) -> String {
    let unix = t.duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
    Asn1Time::from_unix(unix).unwrap().to_string()
}

struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Scratch {
        let dir = std::env::temp_dir().join(format!("asx-testkit-dated-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&dir).unwrap();
        Scratch(dir)
    }

    fn file(&self, name: &str, bytes: &[u8]) -> PathBuf {
        let path = self.0.join(name);
        std::fs::write(&path, bytes).unwrap();
        path
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).ok();
    }
}

fn openssl(args: &[&std::ffi::OsStr]) -> String {
    let out = Command::new("openssl")
        .args(args)
        .output()
        .unwrap_or_else(|err| {
            panic!("the `openssl` command-line tool is required ({err}); put it on PATH")
        });
    assert!(
        out.status.success(),
        "openssl {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&out.stderr));
    text
}

#[test]
fn default_validity_is_an_hour_back_to_thirty_days_ahead() {
    let before = SystemTime::now();
    let validity = Validity::default();
    let after = SystemTime::now();
    assert!(validity.not_before >= before - HOUR && validity.not_before <= after - HOUR);
    assert!(validity.not_after >= before + 30 * DAY && validity.not_after <= after + 30 * DAY);
}

#[test]
fn issue_with_sets_the_given_validity() {
    let ca = TestCa::new("asx-dated-ca", KeyAlg::EcP256);
    let not_before = secs(SystemTime::now() - 40 * DAY);
    let not_after = secs(SystemTime::now() - 10 * DAY);
    let leaf = ca.issue_with(
        "asx-dated-leaf",
        KeyAlg::Rsa2048,
        Validity {
            not_before,
            not_after,
        },
    );
    let cert = X509::from_pem(&leaf.cert_pem).unwrap();
    assert_eq!(cert.not_before().to_string(), printed(not_before));
    assert_eq!(cert.not_after().to_string(), printed(not_after));

    let scratch = Scratch::new();
    let path = scratch.file("leaf.pem", &leaf.cert_pem);
    let dates = openssl(&[
        "x509".as_ref(),
        "-noout".as_ref(),
        "-dates".as_ref(),
        "-in".as_ref(),
        path.as_os_str(),
    ]);
    assert!(
        dates.contains(&format!("notBefore={}", printed(not_before))),
        "{dates}"
    );
    assert!(
        dates.contains(&format!("notAfter={}", printed(not_after))),
        "{dates}"
    );
}

fn expired() -> Validity {
    let now = SystemTime::now();
    Validity {
        not_before: now - 60 * DAY,
        not_after: now - DAY,
    }
}

/// A client whose signing certificate has expired is refused at `build()`.
#[test]
fn an_expired_signer_is_refused_at_build_as_config() {
    let ca = TestCa::new("asx-dated-ca", KeyAlg::Rsa2048);
    let partner = ca.as2_party("PARTNERAS2");
    let signing = ca.issue_with("LOCALAS2", KeyAlg::Rsa2048, expired());
    let decrypting = ca.issue("LOCALAS2 enc", KeyAlg::Rsa2048);
    let local = asx::LocalParty::new("LOCALAS2")
        .signer(signing.key_pair())
        .decrypter(decrypting.key_pair());
    let err = asx::as2::As2::builder(asx::Profile::as2())
        .local(local)
        .trust_anchor(ca.anchor())
        .partner(partner.partner("https://as2.example.org/in"))
        .build()
        .unwrap_err();
    assert_eq!(err.kind(), asx::ErrorKind::Config);
    assert!(
        err.to_string().contains("expired or not yet valid"),
        "{err}"
    );

    // Control: the same configuration with a current certificate builds.
    let current = ca.issue("LOCALAS2", KeyAlg::Rsa2048);
    asx::as2::As2::builder(asx::Profile::as2())
        .local(
            asx::LocalParty::new("LOCALAS2")
                .signer(current.key_pair())
                .decrypter(decrypting.key_pair()),
        )
        .trust_anchor(ca.anchor())
        .partner(partner.partner("https://as2.example.org/in"))
        .build()
        .expect("a current certificate builds");
}

/// A partner first met at send time with an expired certificate is
/// refused before anything is sent.
#[tokio::test]
async fn an_expired_partner_certificate_is_refused_at_send_as_config() {
    let ca = TestCa::new("asx-dated-ca", KeyAlg::Rsa2048);
    let local = ca.rsa_party("sender");
    let client = asx::as4::As4::builder(asx::Profile::edelivery_1_15())
        .local(local.local())
        .trust_anchor(ca.anchor())
        .build()
        .unwrap();
    let stale: KeyPair = ca.issue_with("receiver enc", KeyAlg::Rsa2048, expired());
    let partner = asx::Partner::new("receiver")
        .party_type(asx::testkit::pki::UNREGISTERED_PARTY_TYPE)
        .endpoint("https://as4.example.org/msh")
        .encryption_cert(stale.certificate());
    let message = asx::as4::Message::to(&partner)
        .service("http://example.org/service")
        .action("urn:example:action")
        .payload(asx::Payload::new(b"<a/>".to_vec(), "application/xml"));
    let err = client.send(message).await.unwrap_err();
    assert_eq!(err.kind(), asx::ErrorKind::Config);
    assert!(
        err.to_string().contains("expired or not yet valid"),
        "{err}"
    );
}

#[test]
fn a_crl_carries_the_given_dates_and_revoked_serials() {
    let ca = TestCa::new("asx-dated-ca", KeyAlg::EcP256);
    let revoked = ca.issue("asx-revoked", KeyAlg::EcP256);
    let kept = ca.issue("asx-kept", KeyAlg::EcP256);
    let this_update = secs(SystemTime::now() - 5 * DAY);
    let next_update = secs(SystemTime::now() - 2 * DAY);
    let crl = ca.crl(&[&revoked], this_update, next_update);

    let scratch = Scratch::new();
    let path = scratch.file("ca.crl", &crl);
    let ca_path = scratch.file("ca.pem", ca.cert_pem());
    let text = openssl(&[
        "crl".as_ref(),
        "-inform".as_ref(),
        "DER".as_ref(),
        "-in".as_ref(),
        path.as_os_str(),
        "-noout".as_ref(),
        "-text".as_ref(),
        "-CAfile".as_ref(),
        ca_path.as_os_str(),
    ]);
    assert!(text.contains("verify OK"), "{text}");
    assert!(
        text.contains(&format!("Last Update: {}", printed(this_update))),
        "{text}"
    );
    assert!(
        text.contains(&format!("Next Update: {}", printed(next_update))),
        "{text}"
    );
    assert!(text.contains("Key Compromise"), "{text}");
    let serial = |pair: &KeyPair| {
        X509::from_pem(&pair.cert_pem)
            .unwrap()
            .serial_number()
            .to_bn()
            .unwrap()
            .to_hex_str()
            .unwrap()
            .to_string()
    };
    let compact = text.replace([' ', ':', '\n'], "").to_uppercase();
    assert!(
        compact.contains(&format!("SERIALNUMBER{}", serial(&revoked))),
        "{text}"
    );
    assert!(!compact.contains(&serial(&kept)), "{text}");

    // An empty CRL is well formed too.
    let empty = ca.crl(&[], this_update, next_update);
    let path = scratch.file("empty.crl", &empty);
    let text = openssl(&[
        "crl".as_ref(),
        "-inform".as_ref(),
        "DER".as_ref(),
        "-in".as_ref(),
        path.as_os_str(),
        "-noout".as_ref(),
        "-text".as_ref(),
        "-CAfile".as_ref(),
        ca_path.as_os_str(),
    ]);
    assert!(
        text.contains("verify OK") && text.contains("No Revoked Certificates"),
        "{text}"
    );
}

#[test]
fn an_ocsp_response_carries_the_given_dates_and_status() {
    for alg in [KeyAlg::Rsa2048, KeyAlg::EcP256] {
        let ca = TestCa::new("asx-dated-ca", alg);
        let leaf = ca.issue("asx-ocsp-leaf", KeyAlg::EcP256);
        let this_update = secs(SystemTime::now() - 3 * HOUR);
        let next_update = secs(SystemTime::now() + 21 * HOUR);

        let scratch = Scratch::new();
        let ca_path = scratch.file("ca.pem", ca.cert_pem());
        let leaf_path = scratch.file("leaf.pem", &leaf.cert_pem);
        for (revoked, status) in [(false, "good"), (true, "revoked")] {
            let der = ca.ocsp(&leaf, revoked, this_update, next_update);
            let path = scratch.file("resp.der", &der);
            let text = openssl(&[
                "ocsp".as_ref(),
                "-respin".as_ref(),
                path.as_os_str(),
                "-resp_text".as_ref(),
                "-CAfile".as_ref(),
                ca_path.as_os_str(),
                "-issuer".as_ref(),
                ca_path.as_os_str(),
                "-cert".as_ref(),
                leaf_path.as_os_str(),
            ]);
            assert!(text.contains("Response verify OK"), "{alg:?}: {text}");
            assert!(
                text.contains(&format!("leaf.pem: {status}")),
                "{alg:?}: {text}"
            );
            assert!(
                text.contains(&format!("Cert Status: {status}")),
                "{alg:?}: {text}"
            );
            assert!(
                text.contains(&format!("This Update: {}", printed(this_update))),
                "{alg:?}: {text}"
            );
            assert!(
                text.contains(&format!("Next Update: {}", printed(next_update))),
                "{alg:?}: {text}"
            );
        }
    }
}
