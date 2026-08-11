#![cfg(all(feature = "as4", feature = "testing", feature = "client"))]
//! Live cross-implementation interop: exchange a **signed AS4 push with
//! Non-Repudiation of Receipt** against Holodeck B2B — an independent,
//! WSS4J-based ebMS3/AS4 implementation — running in a container.
//!
//! # Why this exists
//!
//! The xmlsec1 oracle (`interop_xmlsec_oracle.rs`) proves the C14N and digest
//! layer agrees with the XMLDSig reference implementation. It cannot prove the
//! *protocol* layer interoperates: P-Mode resolution against party
//! identifiers, the mandatory `eb:Role`, `eb:AgreementRef`, receipt
//! generation, or that a WSS4J-based stack accepts our WS-Security header
//! shape end to end. This test closes that gap:
//!
//! 1. asx signs and pushes a UserMessage to Holodeck B2B.
//! 2. Holodeck verifies our signature (WSS4J), resolves its P-Mode, delivers
//!    the payload, and answers with a **signed receipt** carrying
//!    `NonRepudiationInformation`.
//! 3. asx verifies that receipt — signature, signer identity (an `X509v3`
//!    `BinarySecurityToken`, the default WSS4J KeyInfo shape), and NRR digest
//!    echo — via `verify_sync_response`.
//!
//! A pass is third-party evidence for both directions of the crypto and both
//! halves of the MEP.
//!
//! # Trust material
//!
//! All identities are **generated fresh per run** (no fixture keys, nothing to
//! expire): asx builds two self-signed RSA-2048 identities, converts party B's
//! to PKCS#12 via the local `openssl` binary, and a one-shot run of the same
//! container image assembles the three JKS keystores Holodeck reads (the JDK's
//! `keytool` does the JKS work — JKS is a Java-proprietary format that OpenSSL
//! cannot write).
//!
//! # Running
//!
//! `#[ignore]`d so the default `cargo test` stays hermetic. Requires Docker
//! and an `openssl` binary:
//!
//! ```text
//! cargo test --all-features --test interop_holodeck_counterparty -- --ignored --nocapture
//! ```

use std::path::Path;
use std::process::Command;
use std::time::Duration;

use testcontainers::core::{IntoContainerPort, Mount, WaitFor, wait::ExitWaitStrategy};
use testcontainers::runners::SyncRunner;
use testcontainers::{GenericImage, ImageExt};

use asx_rs::as4::{
    As4AdditionalPayload, As4ReceiptPolicy, As4SendPolicyBuilder, As4SendRequest, As4SyncSignal,
    send_sync,
};
use asx_rs::core::{CertHandle, OcspFailureMode, OcspMode, SessionContextBuilder};
use asx_rs::fixtures::generate_self_signed_rsa_keypair;
use asx_rs::observability::EventBus;
use asx_rs::transport::As4HttpTransport;

const HOLODECK_IMAGE: &str = "cosmo83/holodeckb2b";
const HOLODECK_TAG: &str = "latest";

/// Party identifiers and collaboration values — these must agree byte-for-byte
/// between the P-Mode installed into Holodeck and the asx send policy.
const FROM_PARTY: &str = "org:asx:test:company:A";
const TO_PARTY: &str = "org:asx:test:company:B";
const AGREEMENT: &str = "http://agreements.asx.test/interop0";
const SERVICE: &str = "Test";
const SERVICE_TYPE: &str = "org:asx:test:services";
const ACTION: &str = "StoreMessage";

/// The P-Mode installed into the container: One-Way/Push, both directions
/// signed, receipt on the HTTP response, file delivery. `BSTReference` makes
/// Holodeck identify its receipt signer via an `X509v3`
/// `wsse:BinarySecurityToken` — the standard WSS4J KeyInfo shape, and the one
/// asx must resolve in-document.
fn pmode_xml() -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<PMode xmlns="http://holodeck-b2b.org/schemas/2014/10/pmode">
    <id>asx-hb2b-push-nrr</id>
    <mep>http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/oneWay</mep>
    <mepBinding>http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/push</mepBinding>
    <Initiator>
        <PartyId>{FROM_PARTY}</PartyId>
        <Role>Sender</Role>
        <SecurityConfiguration>
            <Signing>
                <KeystoreAlias>partya</KeystoreAlias>
            </Signing>
        </SecurityConfiguration>
    </Initiator>
    <Responder>
        <PartyId>{TO_PARTY}</PartyId>
        <Role>Receiver</Role>
        <SecurityConfiguration>
            <Signing>
                <KeystoreAlias password="ExampleB">partyb</KeystoreAlias>
                <KeyReferenceMethod>BSTReference</KeyReferenceMethod>
                <Algorithm>http://www.w3.org/2001/04/xmldsig-more#rsa-sha256</Algorithm>
            </Signing>
        </SecurityConfiguration>
    </Responder>
    <Agreement>
        <name>{AGREEMENT}</name>
    </Agreement>
    <Leg>
        <Receipt>
            <ReplyPattern>RESPONSE</ReplyPattern>
        </Receipt>
        <DefaultDelivery>
            <DeliveryMethod>org.holodeckb2b.backend.file.NotifyAndDeliverOperation</DeliveryMethod>
            <Parameter>
                <name>format</name>
                <value>ebms</value>
            </Parameter>
            <Parameter>
                <name>deliveryDirectory</name>
                <value>data/msg_in</value>
            </Parameter>
        </DefaultDelivery>
        <UserMessageFlow>
            <BusinessInfo>
                <Action>{ACTION}</Action>
                <Service>
                    <name>{SERVICE}</name>
                    <type>{SERVICE_TYPE}</type>
                </Service>
            </BusinessInfo>
        </UserMessageFlow>
    </Leg>
</PMode>
"#
    )
}

/// Convert party B's PEM identity into PKCS#12 with the local `openssl`
/// binary. Retries without `-legacy` for LibreSSL, and with it for OpenSSL 3
/// (whose default PBES2/AES encryption a JDK 8 `keytool` cannot read).
fn write_pkcs12(dir: &Path, key_pem: &Path, cert_pem: &Path, out_p12: &Path) {
    let base_args = |extra: &[&str]| {
        let mut args = vec![
            "pkcs12".to_string(),
            "-export".to_string(),
            "-inkey".to_string(),
            key_pem.display().to_string(),
            "-in".to_string(),
            cert_pem.display().to_string(),
            "-name".to_string(),
            "partyb".to_string(),
            "-passout".to_string(),
            "pass:exportpw".to_string(),
            "-out".to_string(),
            out_p12.display().to_string(),
        ];
        args.extend(extra.iter().map(ToString::to_string));
        args
    };

    let legacy = Command::new("openssl")
        .args(base_args(&["-legacy"]))
        .current_dir(dir)
        .output()
        .expect("run openssl pkcs12 (is an openssl binary installed?)");
    if legacy.status.success() {
        return;
    }
    let plain = Command::new("openssl")
        .args(base_args(&[]))
        .current_dir(dir)
        .output()
        .expect("run openssl pkcs12");
    assert!(
        plain.status.success(),
        "openssl pkcs12 failed with and without -legacy:\n{}\n{}",
        String::from_utf8_lossy(&legacy.stderr),
        String::from_utf8_lossy(&plain.stderr)
    );
}

/// Assemble the three JKS keystores Holodeck's default Certificate Manager
/// reads, using `keytool` from the container image's own JDK. Passwords match
/// the stock `conf/certmanager_config.xml`, so the container runs unmodified
/// except for the mounted `certs/` and `pmodes/` directories.
fn build_jks_keystores(work_dir: &Path) {
    const SCRIPT: &str = "set -e; \
        keytool -importkeystore -noprompt \
            -srckeystore /work/partyb.p12 -srcstoretype PKCS12 \
            -srcstorepass exportpw -srcalias partyb \
            -destkeystore /work/certs/privatekeys.jks \
            -deststorepass secrets -destkeypass ExampleB -destalias partyb; \
        keytool -importcert -noprompt -file /work/partya.cert.pem \
            -keystore /work/certs/partnerkeys.jks -storepass nosecrets -alias partya; \
        keytool -importcert -noprompt -file /work/partyb.cert.pem \
            -keystore /work/certs/partnerkeys.jks -storepass nosecrets -alias partyb; \
        keytool -importcert -noprompt -file /work/partya.cert.pem \
            -keystore /work/certs/trustedcerts.jks -storepass trusted -alias partya; \
        keytool -importcert -noprompt -file /work/partyb.cert.pem \
            -keystore /work/certs/trustedcerts.jks -storepass trusted -alias partyb";

    let container = GenericImage::new(HOLODECK_IMAGE, HOLODECK_TAG)
        .with_entrypoint("sh")
        .with_wait_for(WaitFor::Exit(ExitWaitStrategy::new()))
        .with_mount(Mount::bind_mount(work_dir.display().to_string(), "/work"))
        .with_cmd(["-c", SCRIPT])
        .with_startup_timeout(Duration::from_secs(120))
        .start()
        .expect("start keytool container (is the Docker daemon running?)");

    let exit = container.exit_code().ok().flatten();
    let stderr: String = container
        .stderr_to_vec()
        .map(|bytes: Vec<u8>| String::from_utf8_lossy(&bytes).into_owned())
        .unwrap_or_default();
    assert_eq!(exit, Some(0), "keytool keystore assembly failed:\n{stderr}");
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

#[test]
#[ignore = "requires a Docker daemon and an openssl binary; run with --ignored"]
fn signed_push_with_nrr_roundtrips_against_holodeck_b2b() {
    // ── 1. Fresh identities ─────────────────────────────────────────────────
    let (partya_cert, partya_key) = generate_self_signed_rsa_keypair("asx-interop-partya", 2048);
    let (partyb_cert, partyb_key) = generate_self_signed_rsa_keypair("asx-interop-partyb", 2048);

    let dir = std::env::temp_dir().join(format!("asx-hb2b-{}", std::process::id()));
    let certs_dir = dir.join("certs");
    let pmodes_dir = dir.join("pmodes");
    std::fs::create_dir_all(&certs_dir).expect("certs dir");
    std::fs::create_dir_all(&pmodes_dir).expect("pmodes dir");

    std::fs::write(dir.join("partya.cert.pem"), &partya_cert).expect("write partya cert");
    std::fs::write(dir.join("partyb.cert.pem"), &partyb_cert).expect("write partyb cert");
    std::fs::write(dir.join("partyb.key.pem"), &partyb_key).expect("write partyb key");
    std::fs::write(pmodes_dir.join("asx-push-nrr.xml"), pmode_xml()).expect("write pmode");

    write_pkcs12(
        &dir,
        &dir.join("partyb.key.pem"),
        &dir.join("partyb.cert.pem"),
        &dir.join("partyb.p12"),
    );
    build_jks_keystores(&dir);

    // ── 2. Start Holodeck B2B with our P-Mode and trust material ────────────
    let holodeck = GenericImage::new(HOLODECK_IMAGE, HOLODECK_TAG)
        .with_exposed_port(8080.tcp())
        .with_wait_for(WaitFor::message_on_stdout("Started server"))
        .with_mount(Mount::bind_mount(
            certs_dir.display().to_string(),
            "/opt/holodeck/repository/certs",
        ))
        .with_mount(Mount::bind_mount(
            pmodes_dir.display().to_string(),
            "/opt/holodeck/repository/pmodes",
        ))
        .with_startup_timeout(Duration::from_secs(180))
        .start()
        .expect("start Holodeck B2B container");
    let port = holodeck
        .get_host_port_ipv4(8080)
        .expect("mapped Holodeck port");
    let endpoint = format!("http://127.0.0.1:{port}/holodeckb2b/as4");

    // "Started server" prints before the Axis2 HTTP listener binds, and
    // Docker's port proxy accepts TCP even while the backend is still down —
    // so readiness must be probed at the HTTP level: any status line counts.
    let deadline = std::time::Instant::now() + Duration::from_secs(90);
    loop {
        let probe = || -> std::io::Result<bool> {
            use std::io::{Read, Write};
            let mut stream = std::net::TcpStream::connect(("127.0.0.1", port))?;
            stream.set_read_timeout(Some(Duration::from_secs(3)))?;
            stream.write_all(
                format!("GET /holodeckb2b/as4 HTTP/1.0\r\nHost: 127.0.0.1:{port}\r\n\r\n")
                    .as_bytes(),
            )?;
            let mut buf = [0u8; 12];
            let n = stream.read(&mut buf)?;
            Ok(n > 0 && buf.starts_with(b"HTTP/"))
        };
        match probe() {
            Ok(true) => break,
            _ if std::time::Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(500));
            }
            other => panic!("Holodeck HTTP listener never answered on {port}: {other:?}"),
        }
    }

    // ── 3. asx session pinned to party B as the receipt signer ──────────────
    let partyb_x509 = openssl::x509::X509::from_pem(&partyb_cert).expect("partyb x509");
    let partyb_fingerprint = sha256_hex(&partyb_x509.to_der().expect("partyb der"));

    let session = SessionContextBuilder::new("asx-hb2b-session", TO_PARTY)
        .profile_name("strict")
        .with_signing_material(
            String::from_utf8(partya_cert.clone()).expect("utf8 cert"),
            String::from_utf8(partya_key.clone()).expect("utf8 key"),
        )
        .build()
        .expect("session")
        .with_strict_runtime_bootstrap_validated(true)
        .with_cert_handle(CertHandle {
            trust_anchor_pems: vec![String::from_utf8(partyb_cert.clone()).expect("utf8")],
            fingerprint_sha256: partyb_fingerprint,
            ocsp_mode: OcspMode::Disabled,
            ocsp_failure_mode: OcspFailureMode::HardFail,
            ..CertHandle::new("holodeck-partyb")
        })
        .expect("cert handle");

    let bus = EventBus::new_for_testing();

    // ── 4. Sign and send; collaboration values mirror the P-Mode ────────────
    let (policy, credentials) = As4SendPolicyBuilder::new()
        .action(ACTION)
        .service(SERVICE, SERVICE_TYPE)
        .from_party(FROM_PARTY)
        .to_party(TO_PARTY)
        .party_id_types(None, None) // the P-Mode declares untyped PartyIds
        .roles("Sender", "Receiver")
        .agreement_ref(AGREEMENT, None)
        .signing_cert_pem(partya_cert.clone())
        .signing_key_pem(partya_key.clone())
        .build()
        .expect("send policy");

    let sent = send_sync(
        &session,
        &bus,
        As4SendRequest {
            message_id: format!("urn:uuid:asx-hb2b-{}@asx.test", std::process::id()),
            payload: b"<Invoice xmlns='urn:asx:test:invoice'>interop-payload</Invoice>".to_vec(),
            policy,
            credentials: Some(credentials),
            payload_filename: None,
            payload_mime_type: Some("application/xml".to_string()),
            // A second part makes this a multi-payload UserMessage: Holodeck
            // must verify both attachment signatures and its NRR receipt must
            // echo both digest references for asx's verification to pass.
            additional_payloads: vec![
                As4AdditionalPayload::new(
                    b"<Annex xmlns='urn:asx:test:invoice'>attachment-two</Annex>".to_vec(),
                    "application/xml",
                )
                .with_content_id("annex@asx.test"),
            ],
            ..As4SendRequest::default()
        },
    )
    .expect("send_sync");

    // Persist the exact wire bytes: on failure they allow offline replay
    // (`curl --data-binary @message.bin -H "Content-Type: $(cat ct.txt)"`).
    std::fs::write(dir.join("message.bin"), &sent.soap_envelope.body).expect("dump message");
    std::fs::write(dir.join("ct.txt"), &sent.http_content_type).expect("dump content type");

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    let outcome = runtime.block_on(async {
        let transport = As4HttpTransport::new_for_localhost_testing().expect("transport");
        transport
            .send_and_verify_to_localhost(
                &endpoint,
                &session,
                &bus,
                &sent,
                &As4ReceiptPolicy::regulated(),
            )
            .await
    });

    // On failure, surface Holodeck's own log — it names the exact processing
    // step (P-Mode resolution, signature verification, …) that rejected us.
    let holodeck_log = || -> String {
        holodeck
            .stdout_to_vec()
            .map(|bytes: Vec<u8>| String::from_utf8_lossy(&bytes).into_owned())
            .unwrap_or_default()
    };
    let outcome = outcome.unwrap_or_else(|err| {
        panic!(
            "send+verify against Holodeck failed: {err:?}\n--- holodeck log ---\n{}",
            holodeck_log()
        )
    });

    // ── 5. The verified signal must be a receipt with NRR evidence ──────────
    match outcome.signal {
        As4SyncSignal::Receipt(receipt) => {
            assert!(
                receipt.is_non_repudiation_evidence(),
                "receipt verified but carries no NRR evidence\n--- holodeck log ---\n{}",
                holodeck_log()
            );
        }
        As4SyncSignal::Error(err) => panic!(
            "Holodeck rejected the message with an ebMS error: {}\n--- holodeck log ---\n{}",
            err.summary(),
            holodeck_log()
        ),
        other => panic!("unexpected sync signal variant: {other:?}"),
    }

    let _ = std::fs::remove_dir_all(&dir);
}
