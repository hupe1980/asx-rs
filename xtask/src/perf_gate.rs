use std::collections::HashMap;
use std::fs;
use std::path::Path;
#[cfg(any(feature = "as2", feature = "as4"))]
use std::time::Instant;

#[cfg(feature = "as4")]
use memchr::memmem;

#[cfg(all(feature = "as2", feature = "testing"))]
use asx::core::ReceivedBodyHandle;
#[cfg(any(feature = "as2", feature = "as4"))]
use asx::core::SessionContext;
#[cfg(all(feature = "as2", feature = "testing"))]
use asx::lifecycle::TrustEvidence;
#[cfg(any(feature = "as2", feature = "as4"))]
use asx::observability::EventBus;
#[cfg(all(any(feature = "as2", feature = "as4"), feature = "testing"))]
use asx::reliability::InMemoryDedupBackend;
#[cfg(all(feature = "as2", feature = "testing"))]
use asx::reliability::InMemoryReconciliationHook;

#[cfg(all(feature = "as2", feature = "testing"))]
use asx::as2::{
    As2MdnMode, As2ReceiveMdnRequest, As2ReceivePolicy, As2TrustVerifier, TrustResult,
    TrustVerifierSeal, receive_with_mdn_with_reliability,
};
#[cfg(feature = "as2")]
use asx::as2::{
    As2SendCredentials, As2SendPolicy, generate_mdn as as2_generate_mdn, send_sync as as2_send,
};
#[cfg(feature = "as4")]
use asx::as4::generate_receipt as as4_generate_receipt;
#[cfg(all(feature = "as4", feature = "testing"))]
use asx::as4::{
    As4PushPolicyBuilder, As4ReceivePushRequest, As4ReceivePushSyncRequest,
    receive_push_with_dedup_sync,
};
#[cfg(feature = "as2")]
use openssl::asn1::Asn1Time;
#[cfg(feature = "as2")]
use openssl::bn::BigNum;
#[cfg(feature = "as2")]
use openssl::hash::MessageDigest;
#[cfg(feature = "as2")]
use openssl::nid::Nid;
#[cfg(feature = "as2")]
use openssl::pkey::PKey;
#[cfg(feature = "as2")]
use openssl::rsa::Rsa;
#[cfg(feature = "as2")]
use openssl::x509::{X509, X509NameBuilder};

#[derive(Debug, Clone)]
struct BenchResult {
    name: &'static str,
    iterations: u64,
    ns_per_op: f64,
}

#[cfg(all(feature = "as2", feature = "testing"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DeterministicTrustVerifier {
    trust: TrustEvidence,
}

#[cfg(all(feature = "as2", feature = "testing"))]
impl DeterministicTrustVerifier {
    fn new(trust: TrustEvidence) -> Self {
        Self { trust }
    }
}

#[cfg(all(feature = "as2", feature = "testing"))]
impl TrustVerifierSeal for DeterministicTrustVerifier {}

#[cfg(all(feature = "as2", feature = "testing"))]
impl As2TrustVerifier for DeterministicTrustVerifier {
    fn verify_and_decrypt(
        &self,
        _session: &SessionContext,
        _body: &ReceivedBodyHandle,
    ) -> asx::core::Result<TrustResult> {
        Ok(TrustResult {
            signature: self.trust.signature,
            decryption: self.trust.decryption,
            decrypted_payload: None,
        })
    }
}

#[cfg(feature = "as2")]
fn bench_as2_credentials() -> As2SendCredentials {
    let rsa = Rsa::generate(2048).expect("rsa");
    let pkey = PKey::from_rsa(rsa).expect("pkey");

    let mut name = X509NameBuilder::new().expect("name builder");
    name.append_entry_by_nid(Nid::COMMONNAME, "asx-bench-signer")
        .expect("cn");
    let name = name.build();

    let mut serial = BigNum::new().expect("serial");
    serial
        .pseudo_rand(64, openssl::bn::MsbOption::MAYBE_ZERO, false)
        .expect("serial rand");
    let serial = serial.to_asn1_integer().expect("serial asn1");

    let mut builder = X509::builder().expect("x509 builder");
    builder.set_version(2).expect("version");
    builder.set_serial_number(&serial).expect("serial");
    builder.set_subject_name(&name).expect("subject");
    builder.set_issuer_name(&name).expect("issuer");
    builder.set_pubkey(&pkey).expect("pubkey");
    let not_before = Asn1Time::days_from_now(0).expect("not_before");
    let not_after = Asn1Time::days_from_now(365).expect("not_after");
    builder.set_not_before(&not_before).expect("nb");
    builder.set_not_after(&not_after).expect("na");
    builder
        .sign(&pkey, MessageDigest::sha256())
        .expect("sign cert");
    let cert = builder.build();

    As2SendCredentials {
        signing_cert_pem: Some(cert.to_pem().expect("cert pem")),
        signing_key_pem: Some(pkey.private_key_to_pem_pkcs8().expect("private key pem")),
        recipient_cert_pem: Some(cert.to_pem().expect("recipient cert pem")),
    }
}

#[cfg(any(feature = "as2", feature = "as4"))]
fn bench(mut f: impl FnMut(), name: &'static str, iterations: u64) -> BenchResult {
    for _ in 0..100 {
        f();
    }

    let start = Instant::now();
    for _ in 0..iterations {
        f();
    }
    let elapsed = start.elapsed();
    let ns_per_op = elapsed.as_nanos() as f64 / iterations as f64;

    BenchResult {
        name,
        iterations,
        ns_per_op,
    }
}

#[cfg(all(feature = "as4", feature = "testing"))]
fn as4_multipart_payload_from_fixture(soap_xml: &[u8]) -> Vec<u8> {
    let boundary = "asx-perf-boundary";
    let payload_cid = "perf-body@example.com";
    let mut soap = String::from_utf8_lossy(soap_xml).into_owned();

    if !soap.contains("xmlns:xop=\"http://www.w3.org/2004/08/xop/include\"") {
        soap = soap.replacen(
            "<S12:Envelope ",
            "<S12:Envelope xmlns:xop=\"http://www.w3.org/2004/08/xop/include\" ",
            1,
        );
    }
    if soap.contains("<S12:Body/>") {
        soap = soap.replacen(
            "<S12:Body/>",
            &format!("<S12:Body><xop:Include href=\"cid:{payload_cid}\"/></S12:Body>"),
            1,
        );
    }

    let mut out = Vec::new();
    out.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
    out.extend_from_slice(
        b"Content-Type: application/xop+xml; charset=UTF-8; type=\"application/soap+xml\"\r\n",
    );
    out.extend_from_slice(b"Content-ID: <soap-root@example.com>\r\n\r\n");
    out.extend_from_slice(soap.as_bytes());
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
    out.extend_from_slice(
        format!("Content-Type: application/octet-stream\r\nContent-ID: <{payload_cid}>\r\n\r\n")
            .as_bytes(),
    );
    out.extend_from_slice(b"perf-detached-payload\r\n");
    out.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
    out
}

fn parse_arg(args: &[String], key: &str) -> Option<String> {
    let mut idx = 0;
    while idx + 1 < args.len() {
        if args[idx] == key {
            return Some(args[idx + 1].clone());
        }
        idx += 1;
    }
    None
}

fn parse_u64_arg(args: &[String], key: &str, default: u64) -> u64 {
    parse_arg(args, key)
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(default)
}

fn parse_f64_arg(args: &[String], key: &str, default: f64) -> f64 {
    parse_arg(args, key)
        .and_then(|v| v.parse::<f64>().ok())
        .unwrap_or(default)
}

fn load_baseline(path: &Path) -> Result<HashMap<String, f64>, String> {
    let text = fs::read_to_string(path)
        .map_err(|e| format!("failed to read baseline {}: {e}", path.display()))?;
    let mut map = HashMap::new();

    for (line_no, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((k, v)) = line.split_once('=') else {
            return Err(format!(
                "invalid baseline line {} in {}",
                line_no + 1,
                path.display()
            ));
        };
        let value = v
            .trim()
            .parse::<f64>()
            .map_err(|e| format!("invalid number for key {}: {e}", k.trim()))?;
        map.insert(k.trim().to_string(), value);
    }

    Ok(map)
}

fn write_baseline(path: &Path, results: &[BenchResult]) -> Result<(), String> {
    let mut out = String::from("# ns_per_op baseline\n");
    for r in results {
        out.push_str(&format!("{}={:.3}\n", r.name, r.ns_per_op));
    }
    fs::write(path, out)
        .map_err(|e| format!("failed to write baseline {}: {e}", path.display()))?;
    Ok(())
}

fn print_results(results: &[BenchResult]) {
    println!("benchmark,iterations,ns_per_op");
    for r in results {
        println!("{},{},{:.3}", r.name, r.iterations, r.ns_per_op);
    }
}

fn run_results(#[allow(unused_variables)] iterations: u64) -> Vec<BenchResult> {
    #[allow(unused_mut)]
    let mut results = Vec::new();

    #[cfg(feature = "as2")]
    {
        let session = SessionContext::new("bench-s-as2", "bench-p", "strict").expect("session");
        let bus = EventBus::new(256).expect("bus");
        let _events = bus.subscribe_scoped_events();
        let payload = vec![b'A'; 2048];
        let credentials = bench_as2_credentials();

        results.push(bench(
            || {
                let _ = as2_send(
                    &session,
                    &bus,
                    asx::as2::As2SendRequest {
                        message_id: "msg-bench-1".to_string(),
                        payload: payload.clone(),
                        policy: As2SendPolicy {
                            interop_mode: asx::core::InteropMode::Strict,
                            sign: true,
                            encrypt: true,
                            compress: false,
                            ..As2SendPolicy::default()
                        },
                        credentials: credentials.clone(),
                    },
                )
                .expect("as2 send");
            },
            "as2_sign_encrypt",
            iterations,
        ));

        results.push(bench(
            || {
                let _ = as2_generate_mdn(
                    &session,
                    "<msg-bench-1@example.com>",
                    "automatic-action/MDN-sent-automatically; processed",
                    Some("abc123, sha-256"),
                )
                .expect("as2 mdn");
            },
            "as2_mdn_generation",
            iterations,
        ));

        #[cfg(feature = "testing")]
        {
            let mdn_payload =
                fs::read("tests/fixtures/as2_mdn_sync_ok.golden").expect("mdn fixture");
            let verifier =
                DeterministicTrustVerifier::new(TrustEvidence::verified_and_decryptable());
            results.push(bench(
                || {
                    let hook = InMemoryReconciliationHook::default();
                    let dedup = InMemoryDedupBackend::default();
                    let _ = receive_with_mdn_with_reliability(
                        &session,
                        &bus,
                        As2ReceiveMdnRequest {
                            payload: std::sync::Arc::from([1u8]),
                            mdn_payload: std::sync::Arc::from(mdn_payload.as_slice()),
                            mdn_mode: As2MdnMode::Synchronous,
                            expected_mic: Some(
                                "KUPgyYBxFU9pqBBAxdTOeAw3hlDAepf6m2Pfoy8VI0g=".to_string(),
                            ),
                            policy: As2ReceivePolicy::default(),
                            original_message_id: None,
                        },
                        &hook,
                        &dedup,
                        &verifier,
                    )
                    .expect("as2 receive mdn");
                },
                "as2_verify_decrypt_mdn",
                iterations,
            ));
        }
    }

    #[cfg(feature = "as4")]
    {
        let session = SessionContext::new("bench-s-as4", "bench-p", "strict").expect("session");
        let bus = EventBus::new(256).expect("bus");
        let _events = bus.subscribe_scoped_events();
        let marker_payload =
            fs::read("tests/fixtures/as4_push_user_message.golden").expect("as4 fixture precheck");

        #[cfg(feature = "testing")]
        let payload =
            std::sync::Arc::<[u8]>::from(as4_multipart_payload_from_fixture(&marker_payload));

        #[cfg(feature = "testing")]
        {
            let bench_policy = As4PushPolicyBuilder::new()
                .interop(asx::core::InteropMode::Strict)
                .fail_closed_audit_events(false)
                .allow_unsigned_push(true)
                .build()
                .expect("bench policy");

            results.push(bench(
                || {
                    let dedup = InMemoryDedupBackend::default();
                    let _ = receive_push_with_dedup_sync(
                        &session,
                        &bus,
                        As4ReceivePushSyncRequest {
                            request: As4ReceivePushRequest {
                                http_content_type: "multipart/related".into(),
                                payload: std::sync::Arc::clone(&payload),
                                receipt_payload: None,
                                policy: bench_policy.clone(),
                                authenticated_sender_scope: None,
                            },
                            dedup_backend: &dedup,
                        },
                    )
                    .expect("as4 receive");
                },
                "as4_verify_decrypt",
                iterations,
            ));
        }

        results.push(bench(
            || {
                let required: [&[u8]; 5] = [
                    b"Envelope",
                    b"Header",
                    b"Body",
                    b"Messaging",
                    b"UserMessage",
                ];
                let header_pos = memmem::find(&marker_payload, b"Header");
                let marker_count = required
                    .iter()
                    .filter(|marker| memmem::find(&marker_payload, marker).is_some())
                    .count();
                let header_span_ok = header_pos
                    .and_then(|pos| memmem::find(&marker_payload[pos + b"Header".len()..], b"Body"))
                    .map(|span| span <= 256 * 1024)
                    .unwrap_or(false);
                let _ = (marker_count, header_span_ok);
            },
            "as4_precheck_markers",
            iterations,
        ));

        results.push(bench(
            || {
                let _ = as4_generate_receipt(&session, "msg-bench-1", "ref-bench-1")
                    .expect("as4 receipt generation");
            },
            "as4_receipt_generation",
            iterations,
        ));
    }

    results
}

fn check_regressions(
    baseline: &HashMap<String, f64>,
    results: &[BenchResult],
    max_regression: f64,
) -> Result<(), String> {
    let mut failures = Vec::new();

    for r in results {
        if let Some(base) = baseline.get(r.name) {
            let limit = *base * (1.0 + max_regression);
            if r.ns_per_op > limit {
                failures.push(format!(
                    "{} regressed: {:.3} ns/op > allowed {:.3} ns/op (baseline {:.3})",
                    r.name, r.ns_per_op, limit, base
                ));
            }
        }
    }

    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures.join("\n"))
    }
}

pub fn run(args: &[String]) -> Result<(), String> {
    let iterations = parse_u64_arg(args, "--iterations", 2000);
    let max_regression = parse_f64_arg(args, "--max-regression", 0.25);

    let results = run_results(iterations);
    if results.is_empty() {
        return Err("no benchmarks compiled for active feature set".to_string());
    }

    print_results(&results);

    if let Some(path) = parse_arg(args, "--write-baseline") {
        write_baseline(Path::new(&path), &results)?;
        println!("baseline written: {path}");
    }

    if let Some(path) = parse_arg(args, "--check-baseline") {
        let baseline = load_baseline(Path::new(&path))?;
        check_regressions(&baseline, &results, max_regression)
            .map_err(|err| format!("performance gate failed:\n{err}"))?;
        println!("performance gate passed against {path}");
    }

    Ok(())
}
