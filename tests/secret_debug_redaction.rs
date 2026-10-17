#![cfg(feature = "as4")]
//! No secret reaches a `Debug` or `Display` rendering (`KeyPair` prints its
//! certificate only).
//!
//! Every public value that holds key material — the key pair, the local
//! party, a builder, a built client (its sessions hold the keys), an inbound
//! endpoint, the external-key stand-in — is rendered with `{:?}` and `{:#?}`
//! and must be free of the private key in every form a derived `Debug` could
//! print it: PEM body lines, the `PRIVATE KEY` label, and runs of the DER
//! bytes as a decimal list or as hex. Errors about keys must not echo the key
//! either.

use asx::as4::{As4, UserMessage};
use asx::testkit::keys::CountingKeys;
use asx::testkit::pki::{KeyAlg, TestCa};
use asx::{KeyPair, Profile, Reject, Verified};

const SENTINEL: &str = "S3NT1NEL";

/// Every rendering of a private key that must never appear.
fn key_renderings(key_pem: &[u8]) -> Vec<String> {
    let text = String::from_utf8(key_pem.to_vec()).expect("utf8 key");
    let mut secrets: Vec<String> = text
        .lines()
        .filter(|line| !line.starts_with("-----") && line.len() >= 32)
        .map(str::to_string)
        .collect();
    secrets.push("PRIVATE KEY".to_string());
    let der = openssl::pkey::PKey::private_key_from_pem(key_pem)
        .expect("key")
        .private_key_to_der()
        .expect("der");
    // A window of 12 bytes from deep inside the key (the private exponent /
    // scalar, not the public header), in each rendering a derive could use.
    let window = &der[der.len() / 2..der.len() / 2 + 12];
    secrets.push(
        window
            .iter()
            .map(u8::to_string)
            .collect::<Vec<_>>()
            .join(", "),
    );
    secrets.push(window.iter().map(|b| format!("{b:02x}")).collect());
    secrets.push(window.iter().map(|b| format!("{b:02X}")).collect());
    secrets
}

fn assert_redacted(name: &str, value: &dyn std::fmt::Debug, secrets: &[String]) {
    for rendering in [format!("{value:?}"), format!("{value:#?}")] {
        for secret in secrets {
            assert!(
                !rendering.contains(secret.as_str()),
                "{name}: Debug output contains a secret ({secret:?}):\n{rendering}"
            );
        }
    }
}

#[test]
fn key_pair_debug_prints_the_certificate_only() {
    for alg in [KeyAlg::Rsa2048, KeyAlg::EcP256] {
        let pair = asx::testkit::pki::KeyPair::self_signed("debug", alg);
        let secrets = key_renderings(&pair.key_pem);
        let key_pair = KeyPair::from_pem(&pair.cert_pem, &pair.key_pem).expect("key pair");
        assert_redacted("KeyPair", &key_pair, &secrets);
        // The certificate is what it shows.
        let text = format!("{key_pair:?}");
        assert!(
            text.contains(&format!("{:?}", pair.certificate())),
            "{text}"
        );
        assert_redacted("CountingKeys", &CountingKeys::new(&pair), &secrets);
    }
}

#[test]
fn parties_builders_clients_and_inbounds_redact_their_keys() {
    let ca = TestCa::new("asx-test redaction root", KeyAlg::Rsa2048);
    let a = ca.rsa_party("redact-a");
    let b = ca.rsa_party("redact-b");
    let mut secrets = key_renderings(&a.signing.key_pem);
    secrets.extend(key_renderings(&a.encryption.key_pem));
    secrets.extend(key_renderings(&a.tls.key_pem));

    let local = a.local();
    assert_redacted("LocalParty", &local, &secrets);
    let builder = As4::builder(Profile::edelivery_1_15())
        .local(local)
        .trust_anchor(ca.anchor())
        .partner(b.partner("https://b.example/as4"));
    assert_redacted("Builder<As4>", &builder, &secrets);
    let client = builder.build().expect("client");
    assert_redacted("As4", &client, &secrets);
    let inbound = client.inbound(
        asx::MemoryDedup::default(),
        |_m: Verified<UserMessage>| async { Ok::<(), Reject>(()) },
    );
    assert_redacted("Inbound", &inbound, &secrets);

    // An external key behind the Signer/Decrypter seams.
    let external = CountingKeys::new(&a.signing);
    let local = asx::LocalParty::new(&a.id)
        .signer(external.clone())
        .decrypter(CountingKeys::new(&a.encryption));
    assert_redacted("LocalParty(external)", &local, &secrets);
}

#[test]
fn key_errors_never_echo_the_key() {
    let pair = asx::testkit::pki::KeyPair::self_signed("debug", KeyAlg::Rsa2048);
    let other = asx::testkit::pki::KeyPair::self_signed("other", KeyAlg::Rsa2048);

    // A key that does not match the leaf.
    let mut secrets = key_renderings(&other.key_pem);
    let err = KeyPair::from_pem(&pair.cert_pem, &other.key_pem).expect_err("mismatched key");
    secrets.retain(|s| s != "PRIVATE KEY"); // the message may name the input kind
    assert_redacted("Error(mismatch)", &err, &secrets);
    for secret in &secrets {
        assert!(!err.to_string().contains(secret.as_str()), "Display: {err}");
    }

    // A key PEM that does not parse, carrying a sentinel body.
    let garbage = format!(
        "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
        SENTINEL.repeat(8)
    );
    let err = KeyPair::from_pem(&pair.cert_pem, garbage.as_bytes()).expect_err("unparseable key");
    let sentinel = vec![SENTINEL.to_string()];
    assert_redacted("Error(garbage)", &err, &sentinel);
    assert!(!err.to_string().contains(SENTINEL), "Display: {err}");
    let mut source = std::error::Error::source(&err);
    while let Some(cause) = source {
        assert!(!cause.to_string().contains(SENTINEL), "source: {cause}");
        source = cause.source();
    }
}
