#![cfg(feature = "as4")]
//! A `wsse:BinarySecurityToken` of ValueType `#X509PKIPathv1` carries the
//! signer's path **issuer first**: WSS X.509 Token Profile 1.1 §3.1 defines
//! PkiPath as an ordered sequence from the trust anchor to the end entity, so
//! the signer is the **last** certificate.

use asx::__fuzz::CertFingerprint;
use asx::__fuzz::wssec::{
    ChainPolicy, WsSecOutboundKeyInfoProfile, WsSecVerifyOptions, generate_xmlsig_signature,
    verify_enveloped_signature,
};
use asx::testkit::pki::{KeyAlg, TestCa};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;

fn der(pem: &[u8]) -> Vec<u8> {
    openssl::x509::X509::from_pem(pem)
        .unwrap()
        .to_der()
        .unwrap()
}

/// DER `SEQUENCE OF Certificate`.
fn pkipath(certs: &[Vec<u8>]) -> Vec<u8> {
    let body: Vec<u8> = certs.concat();
    let mut out = vec![0x30];
    let len = body.len();
    if len < 0x80 {
        out.push(len as u8);
    } else if len < 0x100 {
        out.extend_from_slice(&[0x81, len as u8]);
    } else {
        out.extend_from_slice(&[0x82, (len >> 8) as u8, len as u8]);
    }
    out.extend_from_slice(&body);
    out
}

fn signed_with_path(path: &[u8], leaf_key: &[u8], leaf_cert: &[u8]) -> String {
    let token = format!(
        "<wsse:BinarySecurityToken wsu:Id=\"X509PKIPathToken\" \
         EncodingType=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary\" \
         ValueType=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509PKIPathv1\">{}</wsse:BinarySecurityToken>",
        B64.encode(path)
    );
    let envelope = format!(
        "<S:Envelope xmlns:S=\"http://www.w3.org/2003/05/soap-envelope\" \
         xmlns:wsse=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\" \
         xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\">\
         <S:Header><wsse:Security>{token}</wsse:Security></S:Header>\
         <S:Body wsu:Id=\"body\"><p xmlns=\"urn:asx:pkipath\">payload</p></S:Body></S:Envelope>"
    );
    let signature = generate_xmlsig_signature(
        &envelope,
        &["#body"],
        leaf_key,
        leaf_cert,
        WsSecOutboundKeyInfoProfile::X509PKIPathv1,
    )
    .expect("sign");
    envelope.replacen(
        "</wsse:BinarySecurityToken>",
        &format!("</wsse:BinarySecurityToken>{signature}"),
        1,
    )
}

#[test]
fn pkipath_signer_is_the_last_certificate() {
    let ca = TestCa::new("asx-pkipath-ca", KeyAlg::Rsa2048);
    let leaf = ca.issue("asx-pkipath-leaf", KeyAlg::Rsa2048);
    let anchors = [String::from_utf8(ca.cert_pem().to_vec()).unwrap()];
    let pin = [CertFingerprint::from_cert_pem(&leaf.cert_pem).unwrap()];
    let policy = || ChainPolicy {
        trust_anchor_pems: &anchors,
        require_chain_validation: true,
        ..ChainPolicy::default()
    };

    // Issuer first, leaf last: the WSS-defined order.
    let path = pkipath(&[der(ca.cert_pem()), der(&leaf.cert_pem)]);
    let xml = signed_with_path(&path, &leaf.key_pem, &leaf.cert_pem);
    verify_enveloped_signature(
        &xml,
        WsSecVerifyOptions::new()
            .with_expected_fingerprints(&pin)
            .with_chain_policy(policy()),
    )
    .unwrap_or_else(|e| {
        panic!(
            "an issuer-first PkiPath must verify with the leaf: {}",
            e.message
        )
    });

    // A single-certificate path (what this crate emits) is unchanged.
    let path = pkipath(&[der(&leaf.cert_pem)]);
    let xml = signed_with_path(&path, &leaf.key_pem, &leaf.cert_pem);
    verify_enveloped_signature(
        &xml,
        WsSecVerifyOptions::new()
            .with_expected_fingerprints(&pin)
            .with_chain_policy(policy()),
    )
    .expect("a one-certificate PkiPath verifies");
}
