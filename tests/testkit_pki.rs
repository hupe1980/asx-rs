//! The test PKI produces chains that verify and keys that never leak.
//! (That the production verifiers accept its parties is exercised by every
//! client suite under `tests/`.)

use asx::testkit::pki::{KeyAlg, TestCa};
use openssl::stack::Stack;
use openssl::x509::store::X509StoreBuilder;
use openssl::x509::{X509, X509StoreContext};

#[test]
fn a_leaf_verifies_against_its_ca() {
    let ca = TestCa::new("asx-testkit-ca", KeyAlg::Rsa2048);
    let leaf = ca.issue("asx-testkit-leaf", KeyAlg::EcP256);

    let ca_cert = X509::from_pem(ca.cert_pem()).expect("ca cert");
    let leaf_cert = X509::from_pem(&leaf.cert_pem).expect("leaf cert");
    let mut store = X509StoreBuilder::new().expect("store");
    store.add_cert(ca_cert).expect("anchor");
    let store = store.build();
    let chain = Stack::new().expect("chain");
    let mut ctx = X509StoreContext::new().expect("ctx");
    let ok = ctx
        .init(&store, &leaf_cert, &chain, |c| c.verify_cert())
        .expect("verify");
    assert!(ok, "the leaf must chain to its CA");

    let other = TestCa::new("asx-testkit-other-ca", KeyAlg::Rsa2048);
    let foreign = other.issue("asx-testkit-foreign", KeyAlg::Rsa2048);
    let foreign_cert = X509::from_pem(&foreign.cert_pem).expect("foreign cert");
    let mut ctx = X509StoreContext::new().expect("ctx");
    let ok = ctx
        .init(&store, &foreign_cert, &chain, |c| c.verify_cert())
        .expect("verify");
    assert!(!ok, "a leaf of another CA must not chain");
}

#[test]
fn key_pair_debug_never_prints_the_private_key() {
    let pair = TestCa::new("asx-testkit-ca", KeyAlg::Rsa2048).issue("leaf", KeyAlg::Rsa2048);
    let rendered = format!("{pair:?}");
    assert!(!rendered.contains("PRIVATE KEY"), "{rendered}");
}

#[test]
fn ec_p521_key_pairs_are_on_secp521r1() {
    use asx::testkit::pki::KeyPair;
    use openssl::nid::Nid;

    let pair = KeyPair::self_signed("asx-testkit-p521", KeyAlg::EcP521);
    let cert = X509::from_pem(&pair.cert_pem).expect("cert");
    let ec = cert
        .public_key()
        .expect("public key")
        .ec_key()
        .expect("ec key");
    assert_eq!(ec.group().curve_name(), Some(Nid::SECP521R1));

    let ca = TestCa::new("asx-testkit-p521-ca", KeyAlg::EcP521);
    let leaf = ca.issue("asx-testkit-p521-leaf", KeyAlg::EcP521);
    let leaf = X509::from_pem(&leaf.cert_pem).expect("leaf");
    let ec = leaf
        .public_key()
        .expect("public key")
        .ec_key()
        .expect("ec key");
    assert_eq!(ec.group().curve_name(), Some(Nid::SECP521R1));
}
