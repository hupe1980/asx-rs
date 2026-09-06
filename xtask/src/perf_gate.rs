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
            protected_entity: None,
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
        signing_cert_pem: Some(cert.to_pem().expect("cert pem").into()),
        signing_key_pem: Some(pkey.private_key_to_pem_pkcs8().expect("private key pem")),
        recipient_cert_pem: Some(cert.to_pem().expect("recipient cert pem").into()),
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
/// Boundary shared by the payload builder and the `Content-Type` the bench
/// hands the receive path. They have to agree: a `multipart/related` header
/// without the boundary the body actually uses is rejected before any
/// protocol work happens, so the bench measures a parse error instead of the
/// verify/decrypt path it names.
const AS4_BENCH_BOUNDARY: &str = "asx-perf-boundary";

/// The `Content-Type` matching [`as4_multipart_payload_from_fixture`]'s output.
#[cfg(all(feature = "as4", feature = "testing"))]
fn as4_bench_content_type() -> String {
    format!(
        "multipart/related; boundary=\"{AS4_BENCH_BOUNDARY}\"; \
         type=\"application/xop+xml\"; start=\"<soap-root@example.com>\""
    )
}

#[cfg(all(feature = "as4", feature = "testing"))]
fn as4_multipart_payload_from_fixture(soap_xml: &[u8]) -> Vec<u8> {
    let boundary = AS4_BENCH_BOUNDARY;
    let payload_cid = "perf-body@example.com";
    let mut soap = String::from_utf8_lossy(soap_xml).into_owned();

    if !soap.contains("xmlns:xop=\"http://www.w3.org/2004/08/xop/include\"") {
        soap = soap.replacen(
            "<S12:Envelope ",
            "<S12:Envelope xmlns:xop=\"http://www.w3.org/2004/08/xop/include\" ",
            1,
        );
    }
    // Strict interop requires the four-corner routing properties (ebMS3
    // `originalSender` / `finalRecipient`), which the shared golden fixture
    // does not carry. Injected here rather than added to the fixture, because
    // the fixture is also the input to tests that assert on its exact shape.
    if !soap.contains("eb:MessageProperties") {
        soap = soap.replacen(
            "</eb:CollaborationInfo>",
            "</eb:CollaborationInfo>\
             <eb:MessageProperties>\
             <eb:Property name=\"originalSender\">urn:asx:perf:sender</eb:Property>\
             <eb:Property name=\"finalRecipient\">urn:asx:perf:recipient</eb:Property>\
             <eb:Property name=\"trackingIdentifier\">asx-perf-tracking-1</eb:Property>\
             </eb:MessageProperties>",
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

/// Mint a real strict-runtime token and bind it, so the benchmarked path is the
/// one production takes. The alternative — a `testing`-gated marker — is not
/// available here: the perf gate deliberately builds without `testing`, because
/// that feature disables the WS-Security enforcement being measured.
/// A durable audit sink for the benchmarked paths.
///
/// Not decoration: the receive policies these benches use are fail-closed on
/// audit events, so a bus without a production-durable sink makes every
/// measured call return `ReliabilityFailure` instead of exercising the
/// protocol. The gate must benchmark the path production takes.
#[cfg(any(feature = "as2", feature = "as4"))]
#[derive(Debug)]
struct BenchSink;

#[cfg(any(feature = "as2", feature = "as4"))]
const _: () = {
    use asx::core::Result as AsxResult;
    use asx::observability::audit_sink::{
        AuditEvent, AuditSinkDurability, DurableAuditSink, ReplayCursor,
    };

    impl DurableAuditSink for BenchSink {
        fn durability(&self) -> AuditSinkDurability {
            AuditSinkDurability::Durable
        }
        fn has_replay_cursor_integrity_protection(&self) -> bool {
            true
        }
        fn store_event(&self, _event: &AuditEvent) -> AsxResult<()> {
            Ok(())
        }
        fn retrieve_events_from(
            &self,
            _cursor: &ReplayCursor,
            _limit: usize,
        ) -> AsxResult<Vec<AuditEvent>> {
            Ok(Vec::new())
        }
        fn current_cursor(&self) -> AsxResult<ReplayCursor> {
            Ok(ReplayCursor {
                last_event_id: "0".to_string(),
                position: 0,
                last_timestamp: 0,
                integrity_tag_b64: String::new(),
            })
        }
        fn acknowledge_cursor(&self, _cursor: &ReplayCursor) -> AsxResult<()> {
            Ok(())
        }
        fn clear(&self) -> AsxResult<()> {
            Ok(())
        }
    }
};

#[cfg(any(feature = "as2", feature = "as4"))]
fn strict_bench_session(session_id: &str) -> SessionContext {
    use asx::core::Result as AsxResult;
    use asx::presets::StrictRuntimeBootstrap;
    use asx::reliability::ReconciliationRequest;
    use asx::storage::{BoxFuture, DedupStorage, ReconciliationStorage};
    use std::sync::Arc;

    #[derive(Debug)]
    struct BenchDedup;
    impl DedupStorage for BenchDedup {
        fn is_durable(&self) -> bool {
            true
        }
        fn cluster_safe(&self) -> bool {
            true
        }
        fn first_seen<'a>(&'a self, _key: &'a str) -> BoxFuture<'a, AsxResult<bool>> {
            Box::pin(async { Ok(true) })
        }
    }

    #[derive(Debug)]
    struct BenchReconciliation;
    impl ReconciliationStorage for BenchReconciliation {
        fn is_durable(&self) -> bool {
            true
        }
        fn cluster_safe(&self) -> bool {
            true
        }
        fn enqueue<'a>(&'a self, _r: ReconciliationRequest) -> BoxFuture<'a, AsxResult<bool>> {
            Box::pin(async { Ok(true) })
        }
        fn queued_requests(&self) -> BoxFuture<'_, AsxResult<Vec<ReconciliationRequest>>> {
            Box::pin(async { Ok(Vec::new()) })
        }
        fn resolve<'a>(&'a self, _key: &'a str) -> BoxFuture<'a, AsxResult<bool>> {
            Box::pin(async { Ok(true) })
        }
    }

    let bus = EventBus::new_regulated(16, Arc::new(BenchSink)).expect("regulated bus");
    let token = StrictRuntimeBootstrap::new("perf_gate")
        .event_bus(&bus)
        .dedup(&BenchDedup)
        .reconciliation(&BenchReconciliation)
        .validate()
        .expect("startup validation");

    token.bind(&SessionContext::new(session_id, "bench-p", "strict").expect("session"))
}

/// The bus the benchmarked paths run on.
///
/// Two properties are load-bearing. The receive policies here are fail-closed
/// on audit events, so the bus needs a **production-durable** sink or every
/// measured call returns `ReliabilityFailure` instead of exercising the
/// protocol. And it must hold no subscription that nothing drains, because a
/// full channel fails emission under a strict mode. `StrictWithAuditFallback`
/// persists to the sink when no subscriber is live — the shape a regulated
/// deployment runs (D37).
#[cfg(any(feature = "as2", feature = "as4"))]
fn bench_bus() -> EventBus {
    use asx::observability::EventEmissionMode;
    EventBus::builder()
        .capacity(256)
        .audit_sink(std::sync::Arc::new(BenchSink))
        .emission_mode(EventEmissionMode::StrictWithAuditFallback)
        .build()
        .expect("bench bus")
}

fn run_results(#[allow(unused_variables)] iterations: u64) -> Vec<BenchResult> {
    #[allow(unused_mut)]
    let mut results = Vec::new();

    #[cfg(feature = "as2")]
    {
        let session = strict_bench_session("bench-s-as2");
        let bus = bench_bus();
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
                            fail_closed_audit_events: false,
                            ..As2SendPolicy::default()
                        },
                        credentials: Some(credentials.clone()),
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
                            require_signed_mdn: false,
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
        let session = strict_bench_session("bench-s-as4");
        #[cfg(feature = "testing")]
        let bus = bench_bus();
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
                                http_content_type: as4_bench_content_type(),
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

/// Compare measurements against the baseline.
///
/// A baseline entry with no matching measurement is a **failure**, not a
/// skip. The alternative is what this gate used to do: the baseline named six
/// benchmarks, the feature set the gate is invoked with compiles four, and the
/// two most expensive ones — the AS2 and AS4 receive paths — were silently
/// unchecked for as long as the entries sat there. A gate that quietly measures
/// less than its baseline claims is the same shape as a test that cannot fail.
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

    let measured: std::collections::HashSet<&str> = results.iter().map(|r| r.name).collect();
    let mut unmeasured: Vec<&str> = baseline
        .keys()
        .map(String::as_str)
        .filter(|name| !measured.contains(name))
        .collect();
    unmeasured.sort_unstable();
    for name in unmeasured {
        failures.push(format!(
            "{name} is in the baseline but was not measured: this feature set does not \
             compile it, so its baseline line checks nothing. Remove the line, or invoke \
             the gate with the features that build the benchmark"
        ));
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
