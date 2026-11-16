#![cfg(feature = "as4")]
//! `Certificate::same_key`: the key comparison `build()` and inbound key
//! selection use, as an embedder sees it.

use asx::testkit::pki::{IssueOptions, KeyAlg, KeyPair as TestKeyPair, TestCa};

/// A certificate over `pair`'s key (another serial), optionally with the EC
/// point compressed.
fn recertify(ca: &TestCa, pair: &TestKeyPair, alg: KeyAlg, compressed: bool) -> TestKeyPair {
    ca.issue_with_options(
        "recertified",
        alg,
        IssueOptions {
            key_pem: Some(pair.key_pem.clone()),
            compressed_point: compressed,
            ..IssueOptions::default()
        },
    )
}

/// The EC point as the certificate encodes it: the BIT STRING that follows
/// the brainpoolP256r1 curve OID in its `subjectPublicKeyInfo`.
fn point(pair: &TestKeyPair) -> Vec<u8> {
    const BRAINPOOL_P256R1: &[u8] = &[
        0x06, 0x09, 0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x07,
    ];
    let der = openssl::x509::X509::from_pem(&pair.cert_pem)
        .unwrap()
        .to_der()
        .unwrap();
    let at = der
        .windows(BRAINPOOL_P256R1.len())
        .position(|w| w == BRAINPOOL_P256R1)
        .expect("a brainpoolP256r1 key")
        + BRAINPOOL_P256R1.len();
    assert_eq!(der[at], 0x03, "BIT STRING");
    let len = der[at + 1] as usize;
    assert_eq!(der[at + 2], 0x00, "no unused bits");
    der[at + 3..at + 2 + len].to_vec()
}

#[test]
fn one_key_in_two_point_encodings_is_one_key() {
    let ca = TestCa::sm_pki();
    let original = ca.issue("enc", KeyAlg::EcBrainpoolP256r1);
    let compressed = recertify(&ca, &original, KeyAlg::EcBrainpoolP256r1, true);
    let (a, b) = (original.certificate(), compressed.certificate());
    let (pa, pb) = (point(&original), point(&compressed));
    assert_eq!(pa.len(), 65, "uncompressed: 04 ‖ x ‖ y");
    assert_eq!(pa[0], 0x04);
    assert_eq!(pb.len(), 33, "compressed: 02/03 ‖ x");
    assert!(matches!(pb[0], 0x02 | 0x03));
    assert_ne!(a, b, "two certificates");
    assert!(a.same_key(&b) && b.same_key(&a));
    // The compressed certificate and its key load as one key pair.
    let pair = compressed.key_pair();
    assert!(asx::Decrypter::certificate(&pair).same_key(&a));
}

#[test]
fn distinct_keys_and_key_types_differ() {
    let ca = TestCa::sm_pki();
    let one = ca.issue("one", KeyAlg::EcBrainpoolP256r1).certificate();
    let two = ca.issue("two", KeyAlg::EcBrainpoolP256r1).certificate();
    assert!(!one.same_key(&two) && !two.same_key(&one));
    let rsa = TestCa::new("rsa root", KeyAlg::Rsa2048)
        .issue("rsa", KeyAlg::Rsa2048)
        .certificate();
    assert!(!one.same_key(&rsa) && !rsa.same_key(&one));
}

#[test]
fn a_certificate_certifies_its_own_key() {
    let ca = TestCa::new("rsa root", KeyAlg::Rsa2048);
    let pair = ca.issue("rsa", KeyAlg::Rsa2048);
    let renewed = recertify(&ca, &pair, KeyAlg::Rsa2048, false);
    let (a, b) = (pair.certificate(), renewed.certificate());
    assert!(a.same_key(&a));
    assert!(a.same_key(&b) && b.same_key(&a));
    assert_ne!(a, b);
}
