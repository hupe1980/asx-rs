#![cfg(all(feature = "as4", feature = "testing"))]
//! Independent-oracle conformance tests: verify ASX-produced WS-Security
//! signatures with **xmlsec1**, the W3C XMLDSig reference implementation,
//! running in a container.
//!
//! # Why this exists
//!
//! Every other signature test in this repository verifies ASX output with
//! ASX's own verifier. That proves self-consistency, not conformance — if the
//! canonicalizer and the digest computation share a mistake, both sides agree
//! and the suite stays green. Four of the five defects found in the 0.12.0
//! audit were receive-path bugs of exactly that shape, and one of them
//! (`href='cid:…'` in single quotes) was sitting *inside* our own fixtures,
//! masked, for however long.
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
//! Requires a working Docker daemon. See `docs/conformance.md` for the wider
//! interop plan (real AS4 counterparties via testcontainers, and the free EC
//! eDelivery conformance service).

use std::path::Path;
use std::time::Duration;

use testcontainers::core::{Mount, WaitFor, wait::ExitWaitStrategy};
use testcontainers::runners::SyncRunner;
use testcontainers::{GenericImage, ImageExt};

use asx_rs::as4::{As4SendPolicyBuilder, As4SendRequest, send_sync};
use asx_rs::core::SessionContextBuilder;
use asx_rs::fixtures::generate_self_signed_rsa_keypair;
use asx_rs::observability::EventBus;

/// Alpine ships xmlsec1 built against OpenSSL; pinned so a base-image bump
/// cannot silently change what "the reference implementation" means here.
const ORACLE_IMAGE: &str = "alpine";
const ORACLE_TAG: &str = "3.20";

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
         xmlsec1 --verify --verbose \
             --trusted-pem cert.pem \
             --id-attr:Id 'http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/:Messaging' \
             --id-attr:Id 'http://www.w3.org/2003/05/soap-envelope:Body' \
             --enabled-reference-uris empty,same-doc,local \
             signed.xml";

    let container = GenericImage::new(ORACLE_IMAGE, ORACLE_TAG)
        .with_wait_for(WaitFor::Exit(ExitWaitStrategy::new()))
        .with_mount(Mount::bind_mount(dir.display().to_string(), "/work"))
        .with_cmd(["sh", "-c", SCRIPT])
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

    (
        exit_code == Some(0),
        format!("--- exit: {exit_code:?} ---\n--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}"),
    )
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

/// Produce a signed AS4 message and split it into the SOAP envelope and its
/// payload attachment.
fn signed_as4_message() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let (cert, key) = generate_self_signed_rsa_keypair("asx-xmlsec-oracle", 2048);

    let session = SessionContextBuilder::new("oracle-session", "partner-oracle")
        .profile_name("strict")
        .with_signing_material(
            String::from_utf8(cert.clone()).expect("utf8 cert"),
            String::from_utf8(key.clone()).expect("utf8 key"),
        )
        .build()
        .expect("session")
        .test_only_mark_strict_runtime_bootstrap_validated();

    let bus = EventBus::new_for_testing();

    let (policy, credentials) = As4SendPolicyBuilder::new()
        .action("urn:test:as4:action")
        .service("urn:test:as4:service", "")
        // xmlsec1 is a plain XMLDSig verifier: it resolves ds:X509Data but not
        // the wsse:SecurityTokenReference of the (default) WSS BST profile
        // ("unexpected node: SecurityTokenReference"). The oracle checks
        // canonicalization and digests, not WSS token resolution, so pin the
        // XMLDSig-friendly KeyInfo shape here.
        .outbound_key_info_profile(
            asx_rs::crypto::wssec::WsSecOutboundKeyInfoProfile::X509DataAndRsaKeyValue,
        )
        .signing_cert_pem(cert.clone())
        .signing_key_pem(key.clone())
        .build()
        .expect("send policy");

    let out = send_sync(
        &session,
        &bus,
        As4SendRequest {
            message_id: "urn:uuid:xmlsec-oracle@asx.test".into(),
            payload: b"UNB+UNOC:3+sender+receiver+260804:1200+1'".to_vec(),
            policy,
            credentials: Some(credentials),
            payload_filename: None,
            ..As4SendRequest::default()
        },
    )
    .expect("send_sync");

    let (soap, attachment) = split_multipart(&out.soap_envelope.body, &out.http_content_type);
    (cert, soap, attachment)
}

/// Minimal multipart/related splitter: returns (root SOAP part, first attachment).
fn split_multipart(body: &[u8], content_type: &str) -> (Vec<u8>, Vec<u8>) {
    let boundary = content_type
        .split(';')
        .find_map(|seg| {
            let seg = seg.trim();
            seg.strip_prefix("boundary=")
                .map(|v| v.trim_matches('"').to_string())
        })
        .expect("boundary in content-type");
    let delim = format!("--{boundary}");

    let text = String::from_utf8_lossy(body).to_string();
    let mut parts: Vec<Vec<u8>> = Vec::new();
    for raw in text.split(&delim) {
        let raw = raw.trim_start_matches("\r\n");
        if raw.is_empty() || raw.starts_with("--") {
            continue;
        }
        // Split headers from body at the blank line.
        let Some(idx) = raw.find("\r\n\r\n") else {
            continue;
        };
        let body_part = &raw[idx + 4..];
        let body_part = body_part.strip_suffix("\r\n").unwrap_or(body_part);
        parts.push(body_part.as_bytes().to_vec());
    }

    assert!(
        parts.len() >= 2,
        "expected a SOAP root part and a payload attachment, got {}",
        parts.len()
    );
    (parts[0].clone(), parts[1].clone())
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
