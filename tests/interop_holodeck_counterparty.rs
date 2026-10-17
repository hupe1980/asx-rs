#![cfg(all(feature = "as4", feature = "http-client"))]
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
//!    echo — inside `As4::send`, which returns only a `Verified<Receipt>`.
//!
//! A pass is third-party evidence for both directions of the crypto and both
//! halves of the MEP.
//!
//! # Trust material
//!
//! All identities are **generated fresh per run** (no fixture keys, nothing to
//! expire): the testkit issues two RSA-2048 parties under one test CA (party
//! B signs and decrypts with one key pair, as a Holodeck keystore alias
//! holds one key), converts party B's to PKCS#12 via the local `openssl`
//! binary, and a one-shot run of the same container image assembles the
//! three JKS keystores Holodeck reads (the JDK's `keytool` does the JKS work —
//! JKS is a Java-proprietary format that OpenSSL cannot write).
//!
//! # Wire values
//!
//! The client takes its collaboration values from
//! `Profile::edelivery_1_15()`: typed `unregistered` PartyIds, the ebMS
//! default initiator/responder roles, no `AgreementRef`, an untyped service,
//! gzip compression and encryption (AES-128-GCM, RSA-OAEP). The P-Mode below
//! mirrors them.
//! The client's egress is HTTPS-only, so the partner endpoint is a
//! placeholder `https` URL that a test `HttpClient` maps to the container's
//! plain-HTTP port.
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

use asx::as4::{As4, Message};
use asx::{Payload, Profile};
use asx_testkit::pki::{KeyAlg, TestCa, TestParty};

const HOLODECK_IMAGE: &str = "cosmo83/holodeckb2b";
const HOLODECK_TAG: &str = "latest";

/// The only published `cosmo83/holodeckb2b` manifest is `linux/arm64`, so on an
/// amd64 host Docker either refuses the image or runs it under emulation, where
/// the first `sh` fails with `exec format error` and the JVM never starts
/// within this test's timeouts. Say that plainly rather than leaving the next
/// reader to decode an exec failure from a Java gateway.
const ARCH_NOTE: &str = "the Holodeck image is linux/arm64 only; on amd64 this \
                         fails as `exec format error`. Run it on an arm64 host \
                         (CI uses an arm64 runner for this oracle).";

/// Party identifiers and collaboration values — these must agree byte-for-byte
/// between the P-Mode installed into Holodeck and what asx puts on the wire.
const FROM_PARTY: &str = "org:asx:test:company:A";
const TO_PARTY: &str = "org:asx:test:company:B";
const PARTY_TYPE: &str = "urn:oasis:names:tc:ebcore:partyid-type:unregistered";
const SERVICE: &str = "urn:asx:test:services:Test";
const ACTION: &str = "StoreMessage";
const EBMS_NS: &str = "http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704";
/// The partner endpoint asx is configured with (HTTPS-only egress); the
/// test client maps it to the container.
const PLACEHOLDER_ENDPOINT: &str = "https://holodeck.invalid/holodeckb2b/as4";

/// The P-Mode installed into the container: One-Way/Push, both directions
/// signed, the push encrypted to party B, receipt on the HTTP response, file
/// delivery. `BSTReference` makes Holodeck identify its receipt signer via an
/// `X509v3` `wsse:BinarySecurityToken` — the standard WSS4J KeyInfo shape,
/// and the one asx must resolve in-document.
fn pmode_xml() -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<PMode xmlns="http://holodeck-b2b.org/schemas/2014/10/pmode">
    <id>asx-hb2b-push-nrr</id>
    <mep>{EBMS_NS}/oneWay</mep>
    <mepBinding>{EBMS_NS}/push</mepBinding>
    <Initiator>
        <PartyId type="{PARTY_TYPE}">{FROM_PARTY}</PartyId>
        <Role>{EBMS_NS}/initiator</Role>
        <SecurityConfiguration>
            <Signing>
                <KeystoreAlias>partya</KeystoreAlias>
            </Signing>
        </SecurityConfiguration>
    </Initiator>
    <Responder>
        <PartyId type="{PARTY_TYPE}">{TO_PARTY}</PartyId>
        <Role>{EBMS_NS}/responder</Role>
        <SecurityConfiguration>
            <Signing>
                <KeystoreAlias password="ExampleB">partyb</KeystoreAlias>
                <KeyReferenceMethod>BSTReference</KeyReferenceMethod>
                <Algorithm>http://www.w3.org/2001/04/xmldsig-more#rsa-sha256</Algorithm>
            </Signing>
            <Encryption>
                <KeystoreAlias password="ExampleB">partyb</KeystoreAlias>
            </Encryption>
        </SecurityConfiguration>
    </Responder>
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
fn write_pkcs12(dir: &Path, key_pem: &Path, cert_pem: &Path, chain_pem: &Path, out_p12: &Path) {
    let base_args = |extra: &[&str]| {
        let mut args = vec![
            "pkcs12".to_string(),
            "-export".to_string(),
            "-inkey".to_string(),
            key_pem.display().to_string(),
            "-in".to_string(),
            cert_pem.display().to_string(),
            "-certfile".to_string(),
            chain_pem.display().to_string(),
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
        keytool -importcert -noprompt -file /work/ca.cert.pem \
            -keystore /work/certs/trustedcerts.jks -storepass trusted -alias asx-test-ca";

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
    assert_eq!(
        exit,
        Some(0),
        "keytool keystore assembly failed ({ARCH_NOTE}):\n{stderr}"
    );
}

/// An `asx::HttpClient` that maps [`PLACEHOLDER_ENDPOINT`] to the
/// container's plain-HTTP listener. Test-only: the library's own client is
/// HTTPS-only behind an SSRF guard.
#[derive(Debug, Clone)]
struct ContainerClient {
    target: String,
    client: reqwest::Client,
}

impl asx::HttpClient for ContainerClient {
    fn send(
        &self,
        request: http::Request<bytes::Bytes>,
    ) -> asx::BoxFuture<
        '_,
        Result<http::Response<bytes::Bytes>, Box<dyn std::error::Error + Send + Sync>>,
    > {
        Box::pin(async move {
            assert_eq!(request.uri().to_string(), PLACEHOLDER_ENDPOINT);
            let mut outgoing = self.client.post(&self.target);
            for (name, value) in request.headers() {
                outgoing = outgoing.header(name.as_str(), value.as_bytes());
            }
            let response = outgoing.body(request.body().to_vec()).send().await?;
            let mut out = http::Response::builder().status(response.status().as_u16());
            for (name, value) in response.headers() {
                out = out.header(name.as_str(), value.as_bytes());
            }
            Ok(out.body(response.bytes().await?)?)
        })
    }
}

/// A party whose signing and encryption keys are one pair (one keystore
/// alias on the Holodeck side).
fn party(ca: &TestCa, id: &str) -> TestParty {
    let pair = ca.issue(id, KeyAlg::Rsa2048);
    TestParty {
        id: id.to_string(),
        party_type: Some(PARTY_TYPE.to_string()),
        signing: pair.clone(),
        encryption: pair,
        ..ca.rsa_party(id)
    }
}

#[test]
#[ignore = "requires a Docker daemon and an openssl binary; run with --ignored"]
fn signed_push_with_nrr_roundtrips_against_holodeck_b2b() {
    // ── 1. Fresh identities ─────────────────────────────────────────────────
    let ca = TestCa::new("asx-interop root", KeyAlg::Rsa2048);
    let party_a = party(&ca, FROM_PARTY);
    let party_b = party(&ca, TO_PARTY);

    let dir = std::env::temp_dir().join(format!("asx-hb2b-{}", std::process::id()));
    let certs_dir = dir.join("certs");
    let pmodes_dir = dir.join("pmodes");
    std::fs::create_dir_all(&certs_dir).expect("certs dir");
    std::fs::create_dir_all(&pmodes_dir).expect("pmodes dir");

    std::fs::write(dir.join("ca.cert.pem"), ca.cert_pem()).expect("write CA cert");
    std::fs::write(dir.join("partya.cert.pem"), &party_a.signing.cert_pem)
        .expect("write partya cert");
    std::fs::write(dir.join("partyb.cert.pem"), &party_b.signing.cert_pem)
        .expect("write partyb cert");
    std::fs::write(dir.join("partyb.key.pem"), &party_b.signing.key_pem).expect("write partyb key");
    std::fs::write(pmodes_dir.join("asx-push-nrr.xml"), pmode_xml()).expect("write pmode");

    write_pkcs12(
        &dir,
        &dir.join("partyb.key.pem"),
        &dir.join("partyb.cert.pem"),
        &dir.join("ca.cert.pem"),
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
        .unwrap_or_else(|e| panic!("start Holodeck B2B container ({ARCH_NOTE}): {e}"));
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

    // ── 3. An eDelivery client pinned to party B as the receipt signer ──────
    let client = As4::builder(Profile::edelivery_1_15())
        .local(party_a.local())
        .trust_anchor(ca.anchor())
        .partner(party_b.partner(PLACEHOLDER_ENDPOINT))
        .http_client(ContainerClient {
            target: endpoint.clone(),
            client: reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .expect("reqwest client"),
        })
        .build()
        .expect("eDelivery client");

    // ── 4. Sign, encrypt and send; collaboration values mirror the P-Mode ───
    // A second part makes this a multi-payload UserMessage: Holodeck must
    // verify both attachment signatures and its NRR receipt must echo both
    // digest references for asx's verification to pass.
    let message = Message::to(&party_b.partner(PLACEHOLDER_ENDPOINT))
        .service(SERVICE)
        .action(ACTION)
        .message_id(format!("asx-hb2b-{}@asx.test", std::process::id()))
        .payload(Payload::new(
            &b"<Invoice xmlns='urn:asx:test:invoice'>interop-payload</Invoice>"[..],
            "application/xml",
        ))
        .payload(Payload::new(
            &b"<Annex xmlns='urn:asx:test:invoice'>attachment-two</Annex>"[..],
            "application/xml",
        ));

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    let outcome = runtime.block_on(client.send(message));

    // On failure, surface Holodeck's own log — it names the exact processing
    // step (P-Mode resolution, decryption, signature verification, …) that
    // rejected us.
    let holodeck_log = || -> String {
        holodeck
            .stdout_to_vec()
            .map(|bytes: Vec<u8>| String::from_utf8_lossy(&bytes).into_owned())
            .unwrap_or_default()
    };
    let receipt = outcome.unwrap_or_else(|err| {
        panic!(
            "send+verify against Holodeck failed: {err} (ebMS code {:?})\n--- holodeck log ---\n{}",
            err.ebms_code(),
            holodeck_log()
        )
    });

    // ── 5. The verified receipt carries NRR evidence for both parts ──────────
    let signal = String::from_utf8_lossy(receipt.evidence().signal().unwrap_or_default());
    assert!(
        signal.matches("MessagePartNRInformation").count() >= 2 * 4,
        "the receipt must echo eb:Messaging, the Body and both parts\n{signal}"
    );
    assert_eq!(receipt.signer(), &party_b.signing.certificate());

    let _ = std::fs::remove_dir_all(&dir);
}
