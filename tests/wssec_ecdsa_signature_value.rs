#![cfg(feature = "as4")]
//! ECDSA `ds:SignatureValue` is XMLDSig 1.1 `r ‖ s` in both directions
//! (XMLDSig 1.1 §6.4.3, RFC 9231 §2.3.6; BDEW AS4-Profil 1.2
//! §2.2.6.2.1 mandates `ecdsa-sha256` on brainpoolP256r1).
//!
//! The blocking foreign witness is `tests/fixtures/wssec/ecdsa/`: documents
//! signed by xmlsec1 1.3.11 (verified here) and documents signed by this crate
//! that xmlsec1 1.3.11 verified at capture time (see its README). The live
//! xmlsec1 runs are in `tests/interop_xmlsec_oracle.rs`.

#[path = "common/peers.rs"]
mod peers;

use std::path::{Path, PathBuf};

use asx::__fuzz::CertFingerprint;
use asx::__fuzz::ErrorCode;
use asx::__fuzz::wssec::{
    WsSecOutboundKeyInfoProfile, WsSecVerifyOptions, generate_xmlsig_signature,
    verify_enveloped_signature,
};
use asx::testkit::pki::{KeyAlg, KeyPair};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use openssl::bn::BigNum;
use openssl::ecdsa::EcdsaSig;

const CURVES: [(&str, usize); 4] = [("p256", 64), ("bp256", 64), ("p384", 96), ("p521", 132)];

fn fixture_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/wssec/ecdsa")
}

fn fixture(name: &str) -> String {
    std::fs::read_to_string(fixture_dir().join(name))
        .unwrap_or_else(|e| panic!("fixture {name}: {e}"))
}

fn fixture_cert(curve: &str) -> Vec<u8> {
    fixture(&format!("{curve}.cert.pem")).into_bytes()
}

/// The `ds:SignatureValue` text span of `xml`.
fn signature_value_span(xml: &str) -> std::ops::Range<usize> {
    let open = xml.find("SignatureValue>").expect("a ds:SignatureValue") + "SignatureValue>".len();
    let close = open + xml[open..].find("</").expect("SignatureValue close tag");
    open..close
}

fn decoded_signature_value(xml: &str) -> Vec<u8> {
    let text: String = xml[signature_value_span(xml)]
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    B64.decode(text).expect("base64 SignatureValue")
}

fn with_signature_value(xml: &str, value: &[u8]) -> String {
    let span = signature_value_span(xml);
    format!(
        "{}{}{}",
        &xml[..span.start],
        B64.encode(value),
        &xml[span.end..]
    )
}

/// DER `ECDSA-Sig-Value` of the `(r, s)` in a wire value.
fn der_of(wire: &[u8]) -> Vec<u8> {
    let (r, s) = wire.split_at(wire.len() / 2);
    EcdsaSig::from_private_components(
        BigNum::from_slice(r).unwrap(),
        BigNum::from_slice(s).unwrap(),
    )
    .unwrap()
    .to_der()
    .unwrap()
}

fn verify_pinned(xml: &str, cert_pem: &[u8]) -> asx::__fuzz::Result<()> {
    let pin = [CertFingerprint::from_cert_pem(cert_pem).expect("fingerprint")];
    verify_enveloped_signature(
        xml,
        WsSecVerifyOptions::new().with_expected_fingerprints(&pin),
    )
}

/// The envelope a signature from this crate is spliced into (the template
/// without its `ds:Signature`).
fn unsigned_envelope() -> String {
    fixture("envelope.xml")
}

fn splice_signature(envelope: &str, signature: &str) -> String {
    envelope.replacen(
        "<wsse:Security></wsse:Security>",
        &format!("<wsse:Security>{signature}</wsse:Security>"),
        1,
    )
}

/// Independent check of an emitted signature: split the value, rebuild the
/// OpenSSL signature and verify it over the emitted (already canonical)
/// `ds:SignedInfo` bytes with the certificate's key — no crate code involved.
fn independently_verifies(signature_xml: &str, cert_pem: &[u8]) -> bool {
    let doc = roxmltree::Document::parse(signature_xml).expect("signature parses");
    let signed_info = doc
        .descendants()
        .find(|n| n.tag_name().name() == "SignedInfo")
        .expect("SignedInfo");
    let signed_info_bytes = &signature_xml[signed_info.range()];
    let wire = decoded_signature_value(signature_xml);
    let (r, s) = wire.split_at(wire.len() / 2);
    let sig = EcdsaSig::from_private_components(
        BigNum::from_slice(r).unwrap(),
        BigNum::from_slice(s).unwrap(),
    )
    .unwrap();
    let cert = openssl::x509::X509::from_pem(cert_pem).unwrap();
    let key = cert.public_key().unwrap().ec_key().unwrap();
    let digest = openssl::sha::sha256(signed_info_bytes.as_bytes());
    sig.verify(&digest, &key).unwrap()
}

fn sign_fresh(alg: KeyAlg) -> (KeyPair, String) {
    let pair = KeyPair::self_signed("asx-ecdsa-fresh", alg);
    let signature = generate_xmlsig_signature(
        &unsigned_envelope(),
        &["#body"],
        &pair.key_pem,
        &pair.cert_pem,
        WsSecOutboundKeyInfoProfile::X509DataOnly,
    )
    .expect("sign");
    (pair, signature)
}

fn assert_r_concat_s(alg: KeyAlg, width: usize) {
    let (pair, signature) = sign_fresh(alg);
    assert!(signature.contains("xmldsig-more#ecdsa-sha256"));
    let value = decoded_signature_value(&signature);
    assert_eq!(value.len(), width, "{alg:?}: decoded SignatureValue width");
    assert!(
        independently_verifies(&signature, &pair.cert_pem),
        "{alg:?}: the value must verify as (r, s) over the emitted SignedInfo"
    );
    // And the crate verifies what it signs.
    let signed = splice_signature(&unsigned_envelope(), &signature);
    verify_pinned(&signed, &pair.cert_pem).expect("self-verification");
}

#[test]
fn signature_value_is_r_concat_s_p256() {
    assert_r_concat_s(KeyAlg::EcP256, 64);
}

#[test]
fn signature_value_is_r_concat_s_bp256() {
    assert_r_concat_s(KeyAlg::EcBrainpoolP256r1, 64);
}

#[test]
fn signature_value_is_r_concat_s_p384() {
    assert_r_concat_s(KeyAlg::EcP384, 96);
}

#[test]
fn signature_value_is_r_concat_s_p521() {
    assert_r_concat_s(KeyAlg::EcP521, 132);
}

/// A BDEW (brainpoolP256r1) message from `a` to `b` through the loopback:
/// the SOAP part of the request and the signed receipt `b` returned.
fn bdew_exchange() -> (String, String, Vec<u8>) {
    let p = peers::pair(peers::Preset::Bdew);
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let receipt = rt
        .block_on(p.sender.send(peers::Preset::Bdew.message(
            &p.to_b,
            b"UNB+UNOC:3+9900000000001:500+9900000000002:500+261016:1200+1'",
        )))
        .expect("send");
    let request = p.loopback.last_request().expect("request");
    let soap = peers::soap_part(request.body());
    let signal = String::from_utf8(receipt.evidence().signal().expect("signal").to_vec()).unwrap();
    (soap, signal, p.b.signing.cert_pem.clone())
}

#[test]
fn receipt_values_are_r_concat_s() {
    let (_soap, receipt, receiver_cert) = bdew_exchange();
    assert_eq!(decoded_signature_value(&receipt).len(), 64, "receipt");
    verify_pinned(&receipt, &receiver_cert).expect("receipt verifies");
}

fn bdew_signed_message() -> String {
    bdew_exchange().0
}

#[test]
fn as4_send_bdew_signature_value_is_64_octets() {
    let soap = bdew_signed_message();
    assert!(soap.contains("xmldsig-more#ecdsa-sha256"), "{soap}");
    assert_eq!(decoded_signature_value(&soap).len(), 64);
}

/// `cargo test --all-features --test wssec_ecdsa_signature_value -- --ignored --nocapture dump_bdew_signed_message`
#[test]
#[ignore = "prints a BDEW-signed (brainpoolP256r1) AS4 SOAP part for inspection"]
fn dump_bdew_signed_message() {
    let soap = bdew_signed_message();
    println!("{soap}");
    let value = decoded_signature_value(&soap);
    println!(
        "ds:SignatureValue: {} octets (r ‖ s), hex {}",
        value.len(),
        value.iter().map(|b| format!("{b:02x}")).collect::<String>()
    );
}

// ── The foreign witness: xmlsec1 1.3.11 fixtures ────────────────────────────

fn assert_xmlsec1_fixture_verifies(curve: &str, width: usize) {
    let xml = fixture(&format!("xmlsec1-{curve}.xml"));
    assert_eq!(decoded_signature_value(&xml).len(), width, "{curve}");
    verify_pinned(&xml, &fixture_cert(curve))
        .unwrap_or_else(|e| panic!("xmlsec1-{curve}.xml must verify: {}", e.message));
}

#[test]
fn xmlsec1_fixture_verifies_p256() {
    assert_xmlsec1_fixture_verifies("p256", 64);
}

#[test]
fn xmlsec1_fixture_verifies_bp256() {
    assert_xmlsec1_fixture_verifies("bp256", 64);
}

#[test]
fn xmlsec1_fixture_verifies_p384() {
    assert_xmlsec1_fixture_verifies("p384", 96);
}

#[test]
fn xmlsec1_fixture_verifies_p521() {
    assert_xmlsec1_fixture_verifies("p521", 132);
}

fn assert_wrong_length(xml: &str, cert_pem: &[u8], received: usize, required: usize) {
    let err = verify_pinned(xml, cert_pem).expect_err("wrong length must be refused");
    assert_eq!(err.code, ErrorCode::SecurityVerificationFailed);
    assert!(
        err.message.contains(&format!("{received} octets"))
            && err.message.contains(&required.to_string()),
        "must name received {received} and required {required}: {}",
        err.message
    );
}

/// Any length other than `2·l` — DER, another curve's width,
/// xmlsec1 1.3.6's zero-padded 512 octets, a value whose `r` lost its
/// leading zero — is refused naming both lengths, before any signature
/// operation. DER is never parsed inbound.
#[test]
fn wrong_length_rejected() {
    for (curve, width) in CURVES {
        let xml = fixture(&format!("xmlsec1-{curve}.xml"));
        let wire = decoded_signature_value(&xml);
        let der = der_of(&wire);
        assert_wrong_length(
            &with_signature_value(&xml, &der),
            &fixture_cert(curve),
            der.len(),
            width,
        );
    }

    let p256 = fixture("xmlsec1-p256.xml");
    let p384_value = decoded_signature_value(&fixture("xmlsec1-p384.xml"));
    assert_wrong_length(
        &with_signature_value(&p256, &p384_value),
        &fixture_cert("p256"),
        96,
        64,
    );

    let wire = decoded_signature_value(&p256);
    let mut padded = vec![0u8; 512];
    padded[256 - 32..256].copy_from_slice(&wire[..32]);
    padded[512 - 32..].copy_from_slice(&wire[32..]);
    assert_wrong_length(
        &with_signature_value(&p256, &padded),
        &fixture_cert("p256"),
        512,
        64,
    );

    assert_wrong_length(
        &with_signature_value(&p256, &wire[1..]),
        &fixture_cert("p256"),
        63,
        64,
    );
}

/// The signature method's key family must match the signer
/// certificate's key, checked before any signature operation.
#[test]
fn key_family_must_match_method() {
    let ec = fixture("xmlsec1-p256.xml").replace(
        "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256",
        "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
    );
    let err = verify_pinned(&ec, &fixture_cert("p256")).expect_err("RSA method, EC key");
    assert_eq!(err.code, ErrorCode::SecurityVerificationFailed);
    assert!(
        err.message.contains("rsa-sha256") && err.message.contains("EC"),
        "{}",
        err.message
    );

    let rsa = KeyPair::self_signed("asx-rsa-family", KeyAlg::Rsa2048);
    let signature = generate_xmlsig_signature(
        &unsigned_envelope(),
        &["#body"],
        &rsa.key_pem,
        &rsa.cert_pem,
        WsSecOutboundKeyInfoProfile::X509DataOnly,
    )
    .unwrap()
    .replace(
        "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
        "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256",
    );
    let xml = splice_signature(&unsigned_envelope(), &signature);
    let err = verify_pinned(&xml, &rsa.cert_pem).expect_err("ECDSA method, RSA key");
    assert_eq!(err.code, ErrorCode::SecurityVerificationFailed);
    assert!(
        err.message.contains("ecdsa-sha256") && err.message.contains("RSA"),
        "{}",
        err.message
    );
}

/// The right length but a value that does not verify.
#[test]
fn tampered_value_rejected() {
    for (curve, _) in CURVES {
        let xml = fixture(&format!("xmlsec1-{curve}.xml"));
        let mut wire = decoded_signature_value(&xml);
        let last = wire.len() - 1;
        wire[last] ^= 0x01;
        let err = verify_pinned(&with_signature_value(&xml, &wire), &fixture_cert(curve))
            .expect_err("tampered value");
        assert_eq!(err.code, ErrorCode::SecurityVerificationFailed, "{curve}");
    }
}

// ── This crate's signatures, verified by xmlsec1 1.3.11 at capture time ─────

/// Sign the fixture envelope's `#body` with the committed key of `curve`.
fn asx_sign(curve: &str) -> String {
    let signature = generate_xmlsig_signature(
        &unsigned_envelope(),
        &["#body"],
        fixture(&format!("{curve}.key.pem")).as_bytes(),
        &fixture_cert(curve),
        WsSecOutboundKeyInfoProfile::X509DataOnly,
    )
    .expect("sign");
    splice_signature(&unsigned_envelope(), &signature)
}

/// Re-capture `asx-{curve}.xml`, then verify it with xmlsec1 as the README
/// shows: `cargo test --all-features --test wssec_ecdsa_signature_value -- --ignored capture_asx_fixtures`.
#[test]
#[ignore = "rewrites tests/fixtures/wssec/ecdsa/asx-*.xml"]
fn capture_asx_fixtures() {
    for (curve, _) in CURVES {
        std::fs::write(
            fixture_dir().join(format!("asx-{curve}.xml")),
            asx_sign(curve),
        )
        .expect("write fixture");
    }
}

fn signed_info_bytes(xml: &str) -> String {
    let start = xml.find("<ds:SignedInfo").expect("SignedInfo");
    let end = xml.find("</ds:SignedInfo>").expect("SignedInfo end") + "</ds:SignedInfo>".len();
    xml[start..end].to_string()
}

fn assert_asx_fixture(curve: &str, width: usize) {
    let captured = fixture(&format!("asx-{curve}.xml"));
    // 1. It verifies here (xmlsec1 verified it at capture time: README).
    assert_eq!(decoded_signature_value(&captured).len(), width, "{curve}");
    verify_pinned(&captured, &fixture_cert(curve))
        .unwrap_or_else(|e| panic!("asx-{curve}.xml must verify: {}", e.message));
    // 2. Its DER rewrite is refused (as xmlsec1 refused it).
    let der = der_of(&decoded_signature_value(&captured));
    assert_wrong_length(
        &with_signature_value(&captured, &der),
        &fixture_cert(curve),
        der.len(),
        width,
    );
    // 3. The current signer still emits the captured SignedInfo bytes (ECDSA
    //    is randomized, so the value differs; its width does not).
    let fresh = asx_sign(curve);
    assert_eq!(
        signed_info_bytes(&fresh),
        signed_info_bytes(&captured),
        "{curve}"
    );
    assert_eq!(decoded_signature_value(&fresh).len(), width, "{curve}");
}

#[test]
fn asx_fixture_verifies_p256() {
    assert_asx_fixture("p256", 64);
}

#[test]
fn asx_fixture_verifies_bp256() {
    assert_asx_fixture("bp256", 64);
}

#[test]
fn asx_fixture_verifies_p384() {
    assert_asx_fixture("p384", 96);
}

#[test]
fn asx_fixture_verifies_p521() {
    assert_asx_fixture("p521", 132);
}
