#![cfg(feature = "as4")]
//! Independent-oracle conformance tests: verify ASX-produced WS-Security
//! signatures with **xmlsec1**, the W3C XMLDSig reference implementation,
//! running in a container.
//!
//! # Why this exists
//!
//! Every other signature test in this repository verifies ASX output with
//! ASX's own verifier. That proves self-consistency, not conformance — if the
//! canonicalizer and the digest computation share a mistake, both sides agree
//! and the suite stays green.
//!
//! `xmlsec1` is an independent implementation of Exclusive C14N, digest
//! computation and XMLDSig verification. If it accepts our signature, the
//! canonicalization and reference digests are right by someone else's rules.
//!
//! # Running
//!
//! These are `#[ignore]`d so the default `cargo test` stays hermetic:
//!
//! ```text
//! cargo test --all-features --test interop_xmlsec_oracle -- --ignored --nocapture
//! ```
//!
//! Requires a working Docker daemon. The interop suites are listed in
//! `site/content/docs/conformance.md`.

use std::path::Path;
use std::time::Duration;

use testcontainers::core::{Mount, WaitFor, wait::ExitWaitStrategy};
use testcontainers::runners::SyncRunner;
use testcontainers::{GenericImage, ImageExt};

/// A self-signed RSA-2048 certificate and key from the test PKI.
fn self_signed_rsa(subject_cn: &str) -> (Vec<u8>, Vec<u8>) {
    let pair =
        asx_testkit::pki::KeyPair::self_signed(subject_cn, asx_testkit::pki::KeyAlg::Rsa2048);
    (pair.cert_pem, pair.key_pem)
}

/// Alpine ships xmlsec1 built against OpenSSL; pinned **by digest** so a
/// base-image bump cannot silently change what "the reference implementation"
/// means here. `alpine:3.24` carries xmlsec1 1.3.11, the first release that
/// emits XMLDSig 1.1 fixed-width ECDSA values (1.3.6 in `alpine:3.20`
/// zero-padded them to 512 octets). The same digest signed the captured
/// fixtures in `tests/fixtures/wssec/ecdsa/` (see its README).
const ORACLE_IMAGE: &str = "alpine";
const ORACLE_TAG: &str =
    "3.24@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6";
/// Oldest xmlsec1 whose ECDSA behaviour the EC cases rely on.
const MIN_XMLSEC1_VERSION: (u32, u32, u32) = (1, 3, 11);

/// Filename the attachment is written to inside the mounted directory.
const ATTACHMENT_FILE: &str = "payload.bin";
/// Absolute `file://` URI for it. xmlsec1 rejects a bare relative filename in
/// a `ds:Reference URI`, so the retarget has to be absolute.
const ATTACHMENT_URI: &str = "file:///work/payload.bin";

/// Run `xmlsec1 --verify` in a container over `dir`, which must contain
/// `signed.xml`, `cert.pem` and any referenced attachment files.
///
/// Managed by testcontainers: the directory is bind-mounted at `/work`, the
/// container is waited on until it exits, and it is removed when the handle
/// drops — including if an assertion panics mid-test.
///
/// `--id-attr:<attr> <node-ns>:<node-name>` names the *element* carrying the id
/// attribute, not the attribute's namespace; `wsu:Id` is not a schema-declared
/// ID, so xmlsec1 has to be told about each element that uses one.
fn xmlsec_verify(dir: &Path) -> (bool, String) {
    const SCRIPT: &str = "apk add --no-cache xmlsec >/dev/null 2>&1; \
         cd /work; \
         xmlsec1 --version; \
         xmlsec1 --verify --verbose \
             --trusted-pem cert.pem \
             --id-attr:Id 'http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/:Messaging' \
             --id-attr:Id 'http://www.w3.org/2003/05/soap-envelope:Body' \
             --enabled-reference-uris empty,same-doc,local \
             signed.xml";

    run_oracle(dir, SCRIPT)
}

/// Run `script` (POSIX `sh`) in the pinned oracle image with `dir` mounted at
/// `/work`; returns whether it exited 0 and the combined log. The script must
/// print `xmlsec1 --version` first: the version is asserted here.
fn run_oracle(dir: &Path, script: &str) -> (bool, String) {
    let container = GenericImage::new(ORACLE_IMAGE, ORACLE_TAG)
        .with_wait_for(WaitFor::Exit(ExitWaitStrategy::new()))
        .with_mount(Mount::bind_mount(dir.display().to_string(), "/work"))
        .with_cmd(["sh", "-c", script])
        .with_startup_timeout(Duration::from_secs(180))
        .start()
        .expect("start the xmlsec1 oracle container (is the Docker daemon running?)");

    let read = |bytes: std::result::Result<Vec<u8>, _>| {
        bytes
            .map(|b| String::from_utf8_lossy(&b).into_owned())
            .unwrap_or_default()
    };
    let stdout = read(container.stdout_to_vec());
    let stderr = read(container.stderr_to_vec());
    let exit_code = container.exit_code().ok().flatten();
    let log =
        format!("--- exit: {exit_code:?} ---\n--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}");

    assert_xmlsec1_version(&log);
    (exit_code == Some(0), log)
}

/// Fail unless the oracle reports `xmlsec1 X.Y.Z` with X.Y.Z ≥
/// [`MIN_XMLSEC1_VERSION`]; print the version so the CI log records it.
fn assert_xmlsec1_version(log: &str) {
    let line = log
        .lines()
        .find(|l| l.trim_start().starts_with("xmlsec1 "))
        .unwrap_or_else(|| panic!("the oracle did not print `xmlsec1 --version`:\n{log}"));
    println!("oracle: {}", line.trim());
    let version = line.split_whitespace().nth(1).unwrap_or_default();
    let mut parts = version.split('.').map(|p| p.parse::<u32>().unwrap_or(0));
    let found = (
        parts.next().unwrap_or(0),
        parts.next().unwrap_or(0),
        parts.next().unwrap_or(0),
    );
    assert!(
        found >= MIN_XMLSEC1_VERSION,
        "xmlsec1 {version} is older than {MIN_XMLSEC1_VERSION:?}: the pinned image changed"
    );
}

/// Parse xmlsec1's `SignedInfo References (ok/all): N/M` line.
///
/// This is the assertion that matters. Every `ds:Reference` digest is
/// recomputed by an independent implementation of Exclusive C14N — if all of
/// them match, our canonicalization and digest computation agree with the
/// reference implementation, which is the whole interoperability question.
fn reference_tally(log: &str) -> Option<(u32, u32)> {
    let line = log
        .lines()
        .find(|l| l.contains("SignedInfo References (ok/all):"))?;
    let counts = line.rsplit(':').next()?.trim();
    let (ok, all) = counts.split_once('/')?;
    Some((ok.trim().parse().ok()?, all.trim().parse().ok()?))
}

/// Content-ID of the detached payload part.
const PAYLOAD_CID: &str = "payload-1@asx.test";

/// Produce a signed AS4 message the way the send path signs one: an ebMS
/// envelope with a detached payload, signed over `eb:Messaging`, the SOAP
/// Body and the `cid:` attachment, with the signature in `wsse:Security`.
/// Returns (certificate, SOAP envelope, attachment octets).
fn signed_as4_message() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    use asx::__fuzz::soap_builder::{SoapEnvelopeBuilder, WsSecurityHeaderBuilder};
    use asx::__fuzz::wssec::{
        WsSecOutboundKeyInfoProfile, generate_xmlsig_signature_with_external_references,
    };

    let (cert, key) = self_signed_rsa("asx-xmlsec-oracle");
    let payload = b"UNB+UNOC:3+sender+receiver+260804:1200+1'".to_vec();

    let envelope = SoapEnvelopeBuilder::new(
        "urn:uuid:xmlsec-oracle@asx.test",
        "oracle-sender",
        "partner-oracle",
    )
    .with_message_timestamp("2026-10-16T12:00:00Z")
    .with_action("urn:test:as4:action")
    .with_service("urn:test:as4:service", "")
    .with_detached_payload_reference()
    .with_payload_content_id(PAYLOAD_CID)
    .with_payload_mime_type("application/octet-stream")
    .build()
    .expect("envelope");
    let envelope = String::from_utf8(envelope).expect("utf8 envelope");

    let cid = format!("cid:{PAYLOAD_CID}");
    // xmlsec1 is a plain XMLDSig verifier: it resolves ds:X509Data but not
    // the wsse:SecurityTokenReference of the WSS BST profile ("unexpected
    // node: SecurityTokenReference"). The oracle checks canonicalization and
    // digests, not WSS token resolution, so pin the XMLDSig-friendly KeyInfo
    // shape here.
    let signature = generate_xmlsig_signature_with_external_references(
        &envelope,
        &["#as4-messaging", "#as4-body", &cid],
        &[(&cid, &payload)],
        &key,
        &cert,
        WsSecOutboundKeyInfoProfile::X509DataAndRsaKeyValue,
    )
    .expect("sign");
    let security = WsSecurityHeaderBuilder::new()
        .with_signature_xml(signature)
        .build()
        .expect("wsse:Security");
    let security = String::from_utf8(security).expect("utf8 header");

    // The `wsse:Security` header goes first in the SOAP Header, outside both
    // signed subtrees (as the send path's security slot does).
    let header_open = envelope.find(":Header>").expect("SOAP Header") + ":Header>".len();
    let soap = format!(
        "{}{}{}",
        &envelope[..header_open],
        security,
        &envelope[header_open..]
    );
    (cert, soap.into_bytes(), payload)
}

/// ASX signs with a `cid:` reference to the detached attachment. `xmlsec1`
/// cannot resolve `cid:` URIs, so point the reference at a local file holding
/// the identical octets — the digest is over the same bytes either way, so this
/// changes nothing the signature commits to.
fn retarget_cid_reference_to_local_file(soap: &str, filename: &str) -> String {
    let start = soap
        .find("URI=\"cid:")
        .expect("a cid: reference in the signature");
    let value_start = start + "URI=\"".len();
    let value_end = value_start
        + soap[value_start..]
            .find('"')
            .expect("closing quote on the cid reference");
    format!("{}{}{}", &soap[..value_start], filename, &soap[value_end..])
}

/// ASX declares the WSS SwA `Attachment-Content-Signature-Transform` on the
/// `cid:` reference (mandated by the AS4 profile; consumed by WSS4J-based
/// stacks). xmlsec1 does not implement the SwA profile, so strip that
/// `ds:Transforms` block from the retargeted reference. For binary content the
/// transform's digest input *is* the raw attachment octets, which is exactly
/// what xmlsec1 digests for a file URI without transforms — the digest input
/// is unchanged.
fn strip_swa_transform_from_retargeted_reference(soap: &str) -> String {
    const SWA_TRANSFORMS_BLOCK: &str = "<ds:Transforms\
><ds:Transform Algorithm=\"http://docs.oasis-open.org/wss/oasis-wss-SwAProfile-1.1#Attachment-Content-Signature-Transform\"\
></ds:Transform\
></ds:Transforms>";
    let stripped = soap.replacen(SWA_TRANSFORMS_BLOCK, "", 1);
    assert!(
        stripped.len() < soap.len(),
        "expected the SwA content transform on the cid: reference"
    );
    stripped
}

/// Apply the harness transformations. `KeyInfo` is left intact: ASX emits
/// `ds:X509Data/ds:X509Certificate`, which xmlsec1 resolves natively given
/// `--trusted-pem`.
///
/// Note that both transformations edit `ds:SignedInfo`, which the signature
/// value covers — the overall `SignatureValue` check is therefore expected to
/// fail against the rewritten document, and the tests deliberately assert the
/// **reference digest tally** instead. Recomputing every reference digest is
/// the canonicalization/digest interop question this oracle exists to answer.
fn prepare_for_oracle(soap: &str, attachment_file: &str) -> String {
    let retargeted = retarget_cid_reference_to_local_file(soap, attachment_file);
    strip_swa_transform_from_retargeted_reference(&retargeted)
}

#[test]
#[ignore = "requires a Docker daemon; run with --ignored"]
fn asx_signature_verifies_under_the_xmldsig_reference_implementation() {
    let (cert, soap, attachment) = signed_as4_message();
    let soap_text = String::from_utf8(soap).expect("utf8 soap");
    assert!(
        soap_text.contains("<ds:Signature"),
        "the fixture must actually be signed"
    );

    let dir = std::env::temp_dir().join(format!("asx-xmlsec-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp dir");

    let rewritten = prepare_for_oracle(&soap_text, ATTACHMENT_URI);

    std::fs::write(dir.join("signed.xml"), &rewritten).expect("write soap");
    std::fs::write(dir.join(ATTACHMENT_FILE), &attachment).expect("write attachment");
    std::fs::write(dir.join("cert.pem"), &cert).expect("write cert");

    let (_ok, log) = xmlsec_verify(&dir);
    let _ = std::fs::remove_dir_all(&dir);

    let (verified, total) = reference_tally(&log).unwrap_or_else(|| {
        panic!(
            "xmlsec1 produced no reference tally:
{log}"
        )
    });

    assert!(
        total >= 3,
        "expected eb:Messaging, SOAP Body and the attachment to be referenced, got {total}:
{log}"
    );
    assert_eq!(
        verified, total,
        "xmlsec1 recomputed {total} reference digests and only {verified} matched.
\
         Our Exclusive C14N disagrees with the XMLDSig reference implementation — \
         a real interoperability defect, not a harness problem.
{log}"
    );
}

/// The oracle must be able to fail: flipping one payload byte has to break the
/// attachment reference digest. Without this, a harness bug that made xmlsec1
/// verify nothing at all would look like a pass.
#[test]
#[ignore = "requires a Docker daemon; run with --ignored"]
fn the_oracle_rejects_a_tampered_attachment() {
    let (cert, soap, mut attachment) = signed_as4_message();
    let soap_text = String::from_utf8(soap).expect("utf8 soap");

    attachment[0] ^= 0xff;

    let dir = std::env::temp_dir().join(format!("asx-xmlsec-neg-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp dir");

    let rewritten = prepare_for_oracle(&soap_text, ATTACHMENT_URI);

    std::fs::write(dir.join("signed.xml"), &rewritten).expect("write soap");
    std::fs::write(dir.join(ATTACHMENT_FILE), &attachment).expect("write attachment");
    std::fs::write(dir.join("cert.pem"), &cert).expect("write cert");

    let (_ok, log) = xmlsec_verify(&dir);
    let _ = std::fs::remove_dir_all(&dir);

    let (verified, total) = reference_tally(&log).unwrap_or_else(|| {
        panic!(
            "xmlsec1 produced no reference tally:
{log}"
        )
    });

    assert!(
        verified < total,
        "the oracle accepted a tampered attachment ({verified}/{total}) — it is \
         not actually verifying the attachment reference, so a pass in the \
         positive test would be meaningless.
{log}"
    );
}

// ── ECDSA: XMLDSig 1.1 `r ‖ s` in both directions ──────────────────────────
//
// No `SignedInfo` rewriting here: xmlsec1 checks the signature value itself,
// which is exactly the BDEW interoperability question (brainpoolP256r1).

const ECDSA_TEMPLATE: &str = include_str!("fixtures/wssec/ecdsa/template.xml");
const ECDSA_ENVELOPE: &str = include_str!("fixtures/wssec/ecdsa/envelope.xml");

fn ecdsa_dir(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("asx-xmlsec-ecdsa-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("temp dir");
    dir
}

fn ecdsa_key(alg: asx_testkit::pki::KeyAlg) -> asx_testkit::pki::KeyPair {
    asx_testkit::pki::KeyPair::self_signed("asx-xmlsec-ecdsa", alg)
}

fn xmlsec_verify_script(file: &str) -> String {
    format!(
        "apk add --no-cache xmlsec >/dev/null 2>&1; cd /work; xmlsec1 --version; \
         xmlsec1 --verify --lax-key-search --trusted-pem cert.pem \
         --id-attr:Id http://www.w3.org/2003/05/soap-envelope:Body {file}"
    )
}

fn asx_ecdsa_signed(pair: &asx_testkit::pki::KeyPair) -> String {
    let signature = asx::__fuzz::wssec::generate_xmlsig_signature(
        ECDSA_ENVELOPE,
        &["#body"],
        &pair.key_pem,
        &pair.cert_pem,
        asx::__fuzz::wssec::WsSecOutboundKeyInfoProfile::X509DataOnly,
    )
    .expect("sign");
    ECDSA_ENVELOPE.replacen(
        "<wsse:Security></wsse:Security>",
        &format!("<wsse:Security>{signature}</wsse:Security>"),
        1,
    )
}

fn assert_asx_ecdsa_verifies_under_xmlsec1(alg: asx_testkit::pki::KeyAlg, width: usize) {
    let pair = ecdsa_key(alg);
    let signed = asx_ecdsa_signed(&pair);
    let value = signature_value_octets(&signed);
    assert_eq!(value.len(), width, "{alg:?}");

    let dir = ecdsa_dir(&format!("{alg:?}"));
    std::fs::write(dir.join("signed.xml"), &signed).expect("write");
    std::fs::write(dir.join("cert.pem"), &pair.cert_pem).expect("cert");
    let (ok, log) = run_oracle(&dir, &xmlsec_verify_script("signed.xml"));
    let _ = std::fs::remove_dir_all(&dir);
    assert!(
        ok && log.contains("Verification status: OK"),
        "xmlsec1 must verify this crate's {alg:?} signature as-is:\n{log}"
    );
}

fn signature_value_octets(xml: &str) -> Vec<u8> {
    use base64::Engine;
    let open = xml.find("SignatureValue>").expect("SignatureValue") + "SignatureValue>".len();
    let close = open + xml[open..].find("</").expect("close");
    base64::engine::general_purpose::STANDARD
        .decode(xml[open..close].split_whitespace().collect::<String>())
        .expect("base64")
}

#[test]
#[ignore = "requires a Docker daemon; run with --ignored"]
fn asx_ecdsa_verifies_under_xmlsec1_p256() {
    assert_asx_ecdsa_verifies_under_xmlsec1(asx_testkit::pki::KeyAlg::EcP256, 64);
}

#[test]
#[ignore = "requires a Docker daemon; run with --ignored"]
fn asx_ecdsa_verifies_under_xmlsec1_bp256() {
    assert_asx_ecdsa_verifies_under_xmlsec1(asx_testkit::pki::KeyAlg::EcBrainpoolP256r1, 64);
}

#[test]
#[ignore = "requires a Docker daemon; run with --ignored"]
fn asx_ecdsa_verifies_under_xmlsec1_p384() {
    assert_asx_ecdsa_verifies_under_xmlsec1(asx_testkit::pki::KeyAlg::EcP384, 96);
}

#[test]
#[ignore = "requires a Docker daemon; run with --ignored"]
fn asx_ecdsa_verifies_under_xmlsec1_p521() {
    assert_asx_ecdsa_verifies_under_xmlsec1(asx_testkit::pki::KeyAlg::EcP521, 132);
}

fn assert_xmlsec1_ecdsa_verifies_here(alg: asx_testkit::pki::KeyAlg, width: usize) {
    let pair = ecdsa_key(alg);
    let dir = ecdsa_dir(&format!("sign-{alg:?}"));
    std::fs::write(dir.join("template.xml"), ECDSA_TEMPLATE).expect("template");
    std::fs::write(dir.join("key.pem"), &pair.key_pem).expect("key");
    std::fs::write(dir.join("cert.pem"), &pair.cert_pem).expect("cert");
    let script = "apk add --no-cache xmlsec >/dev/null 2>&1; cd /work; xmlsec1 --version; \
         xmlsec1 --sign --lax-key-search --privkey-pem key.pem,cert.pem \
         --id-attr:Id http://www.w3.org/2003/05/soap-envelope:Body \
         --output signed.xml template.xml && chmod 644 signed.xml";
    let (ok, log) = run_oracle(&dir, script);
    assert!(ok, "xmlsec1 must sign:\n{log}");
    let signed = std::fs::read_to_string(dir.join("signed.xml")).expect("signed output");
    let _ = std::fs::remove_dir_all(&dir);

    assert_eq!(signature_value_octets(&signed).len(), width, "{alg:?}");
    let pin = [asx::__fuzz::CertFingerprint::from_cert_pem(&pair.cert_pem).expect("pin")];
    asx::__fuzz::wssec::verify_enveloped_signature(
        &signed,
        asx::__fuzz::wssec::WsSecVerifyOptions::new().with_expected_fingerprints(&pin),
    )
    .unwrap_or_else(|e| {
        panic!(
            "xmlsec1's {alg:?} signature must verify here: {}",
            e.message
        )
    });
}

#[test]
#[ignore = "requires a Docker daemon; run with --ignored"]
fn xmlsec1_ecdsa_verifies_here_p256() {
    assert_xmlsec1_ecdsa_verifies_here(asx_testkit::pki::KeyAlg::EcP256, 64);
}

#[test]
#[ignore = "requires a Docker daemon; run with --ignored"]
fn xmlsec1_ecdsa_verifies_here_bp256() {
    assert_xmlsec1_ecdsa_verifies_here(asx_testkit::pki::KeyAlg::EcBrainpoolP256r1, 64);
}

#[test]
#[ignore = "requires a Docker daemon; run with --ignored"]
fn xmlsec1_ecdsa_verifies_here_p384() {
    assert_xmlsec1_ecdsa_verifies_here(asx_testkit::pki::KeyAlg::EcP384, 96);
}

#[test]
#[ignore = "requires a Docker daemon; run with --ignored"]
fn xmlsec1_ecdsa_verifies_here_p521() {
    assert_xmlsec1_ecdsa_verifies_here(asx_testkit::pki::KeyAlg::EcP521, 132);
}

/// The negative: xmlsec1 refuses the DER `ECDSA-Sig-Value` of a valid
/// `(r, s)`.
#[test]
#[ignore = "requires a Docker daemon; run with --ignored"]
fn xmlsec1_rejects_der_ecdsa_value() {
    use base64::Engine;
    let pair = ecdsa_key(asx_testkit::pki::KeyAlg::EcBrainpoolP256r1);
    let signed = asx_ecdsa_signed(&pair);
    let wire = signature_value_octets(&signed);
    let (r, s) = wire.split_at(32);
    let der = openssl::ecdsa::EcdsaSig::from_private_components(
        openssl::bn::BigNum::from_slice(r).unwrap(),
        openssl::bn::BigNum::from_slice(s).unwrap(),
    )
    .unwrap()
    .to_der()
    .unwrap();
    let open = signed.find("SignatureValue>").unwrap() + "SignatureValue>".len();
    let close = open + signed[open..].find("</").unwrap();
    let der_signed = format!(
        "{}{}{}",
        &signed[..open],
        base64::engine::general_purpose::STANDARD.encode(der),
        &signed[close..]
    );

    let dir = ecdsa_dir("der");
    std::fs::write(dir.join("signed.xml"), &signed).expect("write");
    std::fs::write(dir.join("der.xml"), &der_signed).expect("write");
    std::fs::write(dir.join("cert.pem"), &pair.cert_pem).expect("cert");
    let (_ok, log) = run_oracle(
        &dir,
        &format!(
            "{}; {}",
            xmlsec_verify_script("signed.xml"),
            xmlsec_verify_script("der.xml").replace(
                "apk add --no-cache xmlsec >/dev/null 2>&1; cd /work; xmlsec1 --version; ",
                ""
            )
        ),
    );
    let _ = std::fs::remove_dir_all(&dir);
    let statuses: Vec<&str> = log
        .lines()
        .filter(|l| l.contains("Verification status:"))
        .collect();
    assert_eq!(statuses.len(), 2, "{log}");
    assert!(
        statuses[0].contains("OK"),
        "control (r ‖ s) must verify:\n{log}"
    );
    assert!(
        !statuses[1].contains("OK"),
        "xmlsec1 must refuse the DER form:\n{log}"
    );
}

// ── The payload-less BDEW path-switch signature ─────────────────────────────

#[path = "common/peers.rs"]
mod peers;

/// The plain SOAP envelope of a `requestSwitch` exactly as `As4::send` puts
/// it on the wire (signed over `#as4-messaging` and `#as4-body`, no `cid:`
/// reference), and the sender's signing certificate.
fn sent_path_switch() -> (String, Vec<u8>) {
    let runtime = tokio::runtime::Runtime::new().expect("runtime");
    runtime.block_on(async {
        let pair = peers::pair(peers::Preset::Bdew);
        pair.sender
            .send(asx::as4::Message::path_switch(
                &pair.to_b,
                asx::as4::PathSwitch::Request,
            ))
            .await
            .expect("the path switch is receipted");
        let request = pair.loopback.last_request().expect("captured");
        (
            String::from_utf8(request.body().to_vec()).expect("utf8"),
            pair.a.signing.cert_pem.clone(),
        )
    })
}

/// xmlsec1 recomputes both same-document references of a payload-less
/// path-switch message and verifies its brainpoolP256r1 signature value
/// (`References (ok/all)` = 2/2).
#[test]
#[ignore = "requires a Docker daemon; run with --ignored"]
fn payload_less_path_switch() {
    let (soap, cert) = sent_path_switch();
    assert!(!soap.contains("cid:"), "no attachment reference");
    let run = |tag: &str, soap: &str| {
        let dir = ecdsa_dir(tag);
        std::fs::write(dir.join("signed.xml"), soap).expect("write");
        std::fs::write(dir.join("cert.pem"), &cert).expect("cert");
        let script = "apk add --no-cache xmlsec >/dev/null 2>&1; cd /work; xmlsec1 --version; \
             xmlsec1 --verify --verbose --lax-key-search --pubkey-cert-pem cert.pem \
             --id-attr:Id 'http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/:Messaging' \
             --id-attr:Id 'http://www.w3.org/2003/05/soap-envelope:Body' \
             --enabled-reference-uris same-doc signed.xml";
        let (ok, log) = run_oracle(&dir, script);
        let _ = std::fs::remove_dir_all(&dir);
        (ok, log)
    };
    let (ok, log) = run("path-switch", &soap);
    assert_eq!(reference_tally(&log), Some((2, 2)), "{log}");
    assert!(ok && log.contains("Verification status: OK"), "{log}");

    // The oracle can fail: a changed Action breaks the eb:Messaging digest.
    let tampered = soap.replace("requestSwitch", "confirmSwitch");
    let (ok, log) = run("path-switch-neg", &tampered);
    assert!(!ok || !log.contains("Verification status: OK"), "{log}");
}
