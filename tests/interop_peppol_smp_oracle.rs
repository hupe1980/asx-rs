#![cfg(all(feature = "peppol", feature = "http-client"))]
//! Foreign-implementation oracle for the SMP enveloped-signature path.
//!
//! # Why this exists
//!
//! The SMP response decides **where a message goes** and **which key it is
//! encrypted to**. Until this test, nothing outside this crate had ever
//! checked that path: `tests/smp_enveloped_signature.rs` exercises our
//! verifier against documents our own signer produced, which proves the logic
//! and the tamper detection but not byte-level agreement with another stack.
//! Its module comment said so, and named the fix — "a captured real PEPPOL SMP
//! response". This is that response.
//!
//! # Provenance
//!
//! `tests/fixtures/smp/peppol_production_signed_service_metadata.xml` was
//! fetched from the **live Peppol production network** on 2026-09-20:
//!
//! 1. BDXL U-NAPTR lookup of participant `0088:5790002590993` in
//!    `participant.sml.prod.tech.peppol.org` resolved to `https://smp.logiq.no`.
//! 2. Its `ServiceGroup` listed the Invoice document type.
//! 3. That `SignedServiceMetadata` is the fixture, byte for byte — it cannot be
//!    reformatted, because the signature covers the exact octets.
//!
//! An SMP is a *public* directory by design; the document contains only
//! published endpoints and certificates.
//!
//! # What makes it a witness
//!
//! The specimen differs from everything this crate generates, in ways that
//! exercise real code paths rather than cosmetics:
//!
//! | Property | This fixture | Our own test documents |
//! |---|---|---|
//! | `Signature` namespace | **default `xmlns`**, no prefix | `ds:` prefix |
//! | `CanonicalizationMethod` | **inclusive** C14N 1.0 | exclusive C14N |
//! | Reference transforms | enveloped-signature **only** | enveloped + explicit C14N |
//!
//! The first pins prefix-agnostic parsing against a real signer. The second and
//! third pin the canonicalization default: a reference that declares no
//! canonicalization transform is canonicalized **inclusively**, and the
//! enclosing method is inclusive C14N over a document subset, as confirmed by
//! an independent implementation.
//!
//! # Fixture lifetime
//!
//! The signer certificate expires **2028-02-23**. After that the PKIX check
//! fails and [`the_fixture_signer_has_not_expired`] says so in as many words,
//! rather than leaving a maintainer to decode a chain error. Re-capture with
//! the three steps above.

use asx::__fuzz::ErrorCode;
use asx::__fuzz::wssec::{ChainPolicy, OwnedChainPolicy, verify_enveloped_document_signature};

const SIGNED_SERVICE_METADATA: &str =
    include_str!("fixtures/smp/peppol_production_signed_service_metadata.xml");
const SIGNER_CERT_PEM: &str = include_str!("fixtures/smp/peppol_production_smp_signer.cert.pem");
/// `PEPPOL SERVICE METADATA PUBLISHER CA - G3`, fetched from the AIA URL in the
/// signer certificate. Valid to 2035-01-13.
const PEPPOL_SMP_CA_PEM: &str = include_str!("fixtures/smp/peppol_smp_ca_g3.cert.pem");
/// `PEPPOL Root CA - G3`, self-signed, from the intermediate's AIA URL.
/// Valid to 2035-01-14.
const PEPPOL_ROOT_CA_PEM: &str = include_str!("fixtures/smp/peppol_root_ca_g3.cert.pem");

/// The real Peppol PKI: the self-signed root as the anchor, with the issuing CA
/// available so the path can be built.
///
/// This is the deployment configuration, not a shortcut — the signature is
/// checked against the chain a Peppol access point would check it against.
///
/// No revocation: the signature check is offline (the SMP signer's CRL/OCSP
/// check is `Smp::lookup`'s), and whether DigiCert is reachable
/// from CI is not what this test is about.
fn the_real_peppol_pki() -> OwnedChainPolicy {
    OwnedChainPolicy::production(vec![
        PEPPOL_ROOT_CA_PEM.to_string(),
        PEPPOL_SMP_CA_PEM.to_string(),
    ])
}

/// **The oracle.** A real production Peppol SMP signature verifies.
#[test]
fn a_real_peppol_smp_signature_verifies() {
    let owned = the_real_peppol_pki();
    let verified = verify_enveloped_document_signature(
        SIGNED_SERVICE_METADATA,
        &[],
        &ChainPolicy::from(&owned),
    )
    .expect(
        "a signature produced by a live Peppol SMP must verify; if this fails, our \
         canonicalization or digest handling disagrees with the deployed network",
    );

    assert_eq!(
        verified.signer_fingerprint_sha256,
        asx::__fuzz::CertFingerprint::from_cert_pem(SIGNER_CERT_PEM.as_bytes())
            .expect("fixture signer PEM")
            .to_string(),
        "the verified signer must be the certificate the document carries"
    );
}

/// The same document with one byte of *signed content* changed must fail.
///
/// Without this, the test above would also pass against a verifier that
/// returned `Ok(())` unconditionally.
#[test]
fn a_tampered_endpoint_breaks_the_real_signature() {
    // The AS4 endpoint is inside the signed content; redirect it.
    const REAL_ENDPOINT_HOST: &str = "peppol2.logiq.no";
    assert!(
        SIGNED_SERVICE_METADATA.contains(REAL_ENDPOINT_HOST),
        "the fixture must contain the endpoint host being tampered with"
    );
    let tampered = SIGNED_SERVICE_METADATA.replacen(REAL_ENDPOINT_HOST, "ap.evil.example", 1);

    let owned = the_real_peppol_pki();
    let err = verify_enveloped_document_signature(&tampered, &[], &ChainPolicy::from(&owned))
        .expect_err("redirecting the endpoint must break the digest");
    assert_eq!(err.code, ErrorCode::SecurityVerificationFailed);
}

/// Truncating the signature value must fail rather than be tolerated.
#[test]
fn a_truncated_signature_value_is_rejected() {
    let marker = "<SignatureValue>";
    let start = SIGNED_SERVICE_METADATA
        .find(marker)
        .expect("fixture carries a SignatureValue")
        + marker.len();
    let mut tampered = SIGNED_SERVICE_METADATA.to_string();
    tampered.replace_range(start..start + 8, "AAAAAAAA");

    let owned = the_real_peppol_pki();
    let err = verify_enveloped_document_signature(&tampered, &[], &ChainPolicy::from(&owned))
        .expect_err("a corrupted SignatureValue must not verify");
    assert_eq!(err.code, ErrorCode::SecurityVerificationFailed);
}

/// Pin the properties that make this specimen worth keeping.
///
/// If a future re-capture happens to use the `ds:` prefix and exclusive C14N,
/// the fixture stops being a witness for the paths it was captured for — and
/// this test says so instead of quietly passing.
#[test]
fn the_fixture_still_exercises_the_paths_it_was_captured_for() {
    assert!(
        SIGNED_SERVICE_METADATA
            .contains(r#"<Signature xmlns="http://www.w3.org/2000/09/xmldsig#">"#),
        "the signature must use the default namespace, not a ds: prefix — that is \
         half the reason this fixture is a distinct specimen"
    );
    assert!(
        SIGNED_SERVICE_METADATA
            .contains(r#"Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315""#),
        "the fixture must use inclusive C14N 1.0 — the D49 path"
    );
    assert!(
        SIGNED_SERVICE_METADATA.contains(r#"<Reference URI="">"#),
        "the reference must be whole-document"
    );
    assert!(
        !SIGNED_SERVICE_METADATA.contains("xml-exc-c14n"),
        "the reference must declare no explicit C14N transform, so the inclusive \
         default is what gets exercised"
    );
}

/// Say plainly when the captured certificate has expired.
#[test]
fn the_fixture_signer_has_not_expired() {
    let cert = openssl::x509::X509::from_pem(SIGNER_CERT_PEM.as_bytes()).expect("fixture PEM");
    let now = openssl::asn1::Asn1Time::days_from_now(0).expect("clock");
    assert!(
        cert.not_after() > now.as_ref(),
        "the captured Peppol SMP signer expired ({}). This fixture is a real \
         production certificate and has a finite life: re-capture it with the \
         three steps in this file's module documentation.",
        cert.not_after()
    );
}
