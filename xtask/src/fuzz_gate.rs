use asx::core::{ErrorCode, InteropMode, SessionContext};
use asx::http::{HttpRequest, PartnerEndpointGovernance};
use asx::interop::{
    BaseProfile, CanonicalizationPolicy, PartnerProfileOverlay, ProfileExtension, ProfileOverride,
    ProfilePolicyOverrides, ProfileStack, RegionalProfilePack, SecurityPolicy, ValidationPolicy,
};
use asx::wire::{
    StreamLimits, WireEnvelope, canonical_transfer_fingerprint,
    read_bounded_stream_into_memory_async,
};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STD;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::io::Cursor;
use std::time::Instant;

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
enum FuzzTarget {
    ProfileLoader,
    PolicyResolver,
    WireParsing,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum FailureKind {
    Panic,
    InvariantViolation,
}

#[derive(Debug, Clone)]
struct FuzzCase {
    id: usize,
    target: FuzzTarget,
    input: Vec<u8>,
}

#[derive(Debug, Clone, Serialize)]
struct FailureRecord {
    id: usize,
    target: FuzzTarget,
    kind: FailureKind,
    message: String,
    input_len: usize,
    minimized_input_len: usize,
    reproducer_file: String,
}

#[derive(Debug, Clone, Serialize)]
struct FuzzReport {
    gate: &'static str,
    seed: u64,
    requested_iterations: usize,
    executed_iterations: usize,
    budget_ms: u64,
    elapsed_ms: u64,
    target_counts: TargetCounts,
    panic_count: usize,
    invariant_violation_count: usize,
    failures: Vec<FailureRecord>,
}

#[derive(Debug, Clone, Default, Serialize)]
struct TargetCounts {
    profile_loader: usize,
    policy_resolver: usize,
    wire_parsing: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum CaseOutcome {
    Ok,
    Panic(String),
    InvariantViolation(String),
}

#[derive(Debug, Clone)]
struct Lcg {
    state: u64,
}

impl Lcg {
    fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    fn next_u64(&mut self) -> u64 {
        self.state = self
            .state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.state
    }

    fn next_u8(&mut self) -> u8 {
        (self.next_u64() & 0xff) as u8
    }

    fn next_usize(&mut self, max_exclusive: usize) -> usize {
        if max_exclusive <= 1 {
            return 0;
        }
        (self.next_u64() as usize) % max_exclusive
    }

    fn bytes(&mut self, len: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(len);
        for _ in 0..len {
            out.push(self.next_u8());
        }
        out
    }
}

pub fn run(args: &[String]) -> Result<(), String> {
    let mut args = args.iter();

    let requested_iterations = args
        .next()
        .map(|v| v.parse::<usize>())
        .transpose()
        .map_err(|err| format!("invalid iterations: {err}"))?
        .unwrap_or(4000);
    let budget_ms = args
        .next()
        .map(|v| v.parse::<u64>())
        .transpose()
        .map_err(|err| format!("invalid budget_ms: {err}"))?
        .unwrap_or(2500);
    let output_dir = args
        .next()
        .cloned()
        .unwrap_or_else(|| "artifacts/fuzz".to_string());

    if args.next().is_some() {
        return Err("usage: fuzz-gate [iterations] [budget_ms] [output_dir]".to_string());
    }

    let seed = 0xA5A5_C0DE_D00D_BEEF_u64;
    let mut rng = Lcg::new(seed);
    let start = Instant::now();

    let mut target_counts = TargetCounts::default();
    let mut executed_iterations = 0usize;
    let mut failures: Vec<FailureRecord> = Vec::new();

    while executed_iterations < requested_iterations
        || start.elapsed().as_millis() < budget_ms as u128
    {
        let target = match executed_iterations % 3 {
            0 => FuzzTarget::ProfileLoader,
            1 => FuzzTarget::PolicyResolver,
            _ => FuzzTarget::WireParsing,
        };
        let input_len = 1 + rng.next_usize(4096);
        let input = rng.bytes(input_len);

        match target {
            FuzzTarget::ProfileLoader => target_counts.profile_loader += 1,
            FuzzTarget::PolicyResolver => target_counts.policy_resolver += 1,
            FuzzTarget::WireParsing => target_counts.wire_parsing += 1,
        }

        let case = FuzzCase {
            id: executed_iterations,
            target,
            input,
        };

        let outcome = run_case(&case.target, &case.input);
        if let Some((kind, message)) = failure_from_outcome(&outcome) {
            let minimized = minimize_input(&case, kind);
            let repro_file = write_reproducer(&output_dir, &case, kind, &minimized)?;

            failures.push(FailureRecord {
                id: case.id,
                target: case.target,
                kind,
                message,
                input_len: case.input.len(),
                minimized_input_len: minimized.len(),
                reproducer_file: repro_file,
            });
        }

        executed_iterations += 1;
    }

    let elapsed_ms = start.elapsed().as_millis() as u64;
    let panic_count = failures
        .iter()
        .filter(|f| f.kind == FailureKind::Panic)
        .count();
    let invariant_violation_count = failures
        .iter()
        .filter(|f| f.kind == FailureKind::InvariantViolation)
        .count();

    let report = FuzzReport {
        gate: "adversarial-fuzz",
        seed,
        requested_iterations,
        executed_iterations,
        budget_ms,
        elapsed_ms,
        target_counts,
        panic_count,
        invariant_violation_count,
        failures,
    };

    std::fs::create_dir_all(&output_dir)
        .map_err(|err| format!("failed creating output directory {output_dir}: {err}"))?;
    let report_path = format!("{output_dir}/report.json");
    let report_json = serde_json::to_string_pretty(&report)
        .map_err(|err| format!("failed to serialize fuzz report: {err}"))?;
    std::fs::write(&report_path, &report_json)
        .map_err(|err| format!("failed writing fuzz report {report_path}: {err}"))?;

    println!("{report_json}");

    if panic_count > 0 || invariant_violation_count > 0 {
        return Err(format!(
            "found {panic_count} panic(s) and {invariant_violation_count} invariant violation(s); see {report_path}"
        ));
    }

    Ok(())
}

fn failure_from_outcome(outcome: &CaseOutcome) -> Option<(FailureKind, String)> {
    match outcome {
        CaseOutcome::Ok => None,
        CaseOutcome::Panic(msg) => Some((FailureKind::Panic, msg.clone())),
        CaseOutcome::InvariantViolation(msg) => {
            Some((FailureKind::InvariantViolation, msg.clone()))
        }
    }
}

fn run_case(target: &FuzzTarget, input: &[u8]) -> CaseOutcome {
    let result = std::panic::catch_unwind(|| match target {
        FuzzTarget::ProfileLoader => run_profile_loader_case(input),
        FuzzTarget::PolicyResolver => run_policy_resolver_case(input),
        FuzzTarget::WireParsing => run_wire_parsing_case(input),
    });

    match result {
        Ok(Ok(())) => CaseOutcome::Ok,
        Ok(Err(msg)) => CaseOutcome::InvariantViolation(msg),
        Err(_) => CaseOutcome::Panic("panic during adversarial execution".to_string()),
    }
}

fn run_profile_loader_case(input: &[u8]) -> Result<(), String> {
    let raw = String::from_utf8_lossy(input);
    match RegionalProfilePack::from_json(&raw) {
        Ok(pack) => {
            let stack = base_stack();
            match stack.apply_regional_pack(&pack) {
                Ok(merged) => {
                    let session = SessionContext::new("fuzz-loader", "partner-fuzz", "profile")
                        .map_err(|err| format!("session init failed: {err}"))?;
                    let first = merged.resolve(&session);
                    let second = merged.resolve(&session);
                    if first != second {
                        return Err("loader path produced non-deterministic resolution".to_string());
                    }
                }
                Err(err) => {
                    if err.message.trim().is_empty() {
                        return Err("regional pack apply returned empty error message".to_string());
                    }
                }
            }
        }
        Err(err) => {
            if err.code == ErrorCode::ParseFailed && err.message.trim().is_empty() {
                return Err("regional pack parse failed with empty message".to_string());
            }
        }
    }

    Ok(())
}

fn run_policy_resolver_case(input: &[u8]) -> Result<(), String> {
    let b = |idx: usize| -> bool { input.get(idx).copied().unwrap_or_default() & 1 == 1 };
    let mode = InteropMode::Strict;

    let stack = ProfileStack {
        base: BaseProfile {
            name: "base".to_string(),
            version: "1".to_string(),
            mode,
            canonicalization: CanonicalizationPolicy::default(),
            security: SecurityPolicy {
                require_signature: !b(1),
                require_encryption: !b(2),
            },
            validation: ValidationPolicy {
                reject_ambiguous_headers: !b(4),
                enforce_payload_limits: !b(5),
                require_as2_mic: !b(6),
            },
        },
        extensions: vec![ProfileExtension {
            name: "ext-fuzz".to_string(),
            overrides: ProfilePolicyOverrides {
                mode: Some(InteropMode::Strict),
                ..ProfilePolicyOverrides::default()
            },
        }],
        overrides: vec![ProfileOverride {
            name: "ov-fuzz".to_string(),
            overrides: ProfilePolicyOverrides {
                ..ProfilePolicyOverrides::default()
            },
        }],
        partner_overrides: vec![PartnerProfileOverlay {
            name: "partner-fuzz".to_string(),
            partner_id: "partner-fuzz".to_string(),
            overrides: ProfilePolicyOverrides {
                mode: Some(InteropMode::Strict),
                ..ProfilePolicyOverrides::default()
            },
        }],
    };

    let session = SessionContext::new("fuzz-resolver", "partner-fuzz", "profile")
        .map_err(|err| format!("session init failed: {err}"))?;

    let first = stack.resolve(&session);
    let second = stack.resolve(&session);
    if first != second {
        return Err("resolver produced non-deterministic effective profile".to_string());
    }

    match stack.validate() {
        Ok(report) => {
            if report
                .lints
                .iter()
                .any(|lint| lint.remediation_hint.trim().is_empty())
            {
                return Err("lint entry had empty remediation hint".to_string());
            }
        }
        Err(failure) => {
            if failure.errors.is_empty() {
                return Err("validation failure returned empty error list".to_string());
            }
            if failure
                .errors
                .iter()
                .any(|issue| issue.remediation_hint.trim().is_empty())
            {
                return Err("validation issue had empty remediation hint".to_string());
            }
        }
    }

    Ok(())
}

fn run_wire_parsing_case(input: &[u8]) -> Result<(), String> {
    let pick = |idx: usize| -> u8 { input.get(idx).copied().unwrap_or_default() };

    let content_type = match pick(0) % 4 {
        0 => "multipart/signed; boundary=fuzz",
        1 => "application/soap+xml",
        2 => "application/octet-stream",
        _ => "application/not-supported",
    };

    let method = if pick(1) % 7 == 0 { "" } else { "POST" };
    let uri = if pick(2) % 11 == 0 {
        ""
    } else {
        "https://partner.example/fuzz"
    };

    let body_len = (pick(3) as usize) * 16;
    let body = input
        .iter()
        .copied()
        .cycle()
        .take(body_len)
        .collect::<Vec<u8>>();

    let expected_body_digest = Sha256::digest(&body);
    let request = HttpRequest {
        method: method.to_string(),
        uri: uri.to_string(),
        headers: vec![
            ("Content-Type".to_string(), content_type.to_string()),
            ("X-Fuzz".to_string(), format!("{}", pick(4))),
        ]
        .into(),
        body: body.into(),
    };

    let limits = StreamLimits {
        max_body_bytes: 64 + (pick(5) as usize) * 32,
        chunk_bytes: 1 + (pick(6) as usize % 64),
    };

    let _ = canonical_transfer_fingerprint(&request);

    match WireEnvelope::try_from_http_request_with_limits(
        request,
        limits,
        "fuzz-partner",
        &PartnerEndpointGovernance::ingress_strict(),
    ) {
        Ok(envelope) => {
            if Sha256::digest(&envelope.body) != expected_body_digest {
                return Err("wire envelope body diverged from request body".to_string());
            }
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|err| format!("failed to create runtime for wire fuzz read: {err}"))?;
            let (stream_buf, metrics): (std::sync::Arc<[u8]>, asx::wire::StreamReadMetrics) = rt
                .block_on(read_bounded_stream_into_memory_async(
                    Cursor::new(envelope.body.clone()),
                    limits,
                    "fuzz_wire_stream",
                ))
                .map_err(|err| {
                    format!("bounded stream should succeed for accepted envelope: {err}")
                })?;

            if stream_buf.len() != envelope.body.len() {
                return Err("stream buffer length mismatch".to_string());
            }
            if metrics.total_bytes != envelope.body.len() {
                return Err("stream metrics total_bytes mismatch".to_string());
            }
        }
        Err(err) => {
            if err.message.trim().is_empty() {
                return Err("wire parsing error had empty message".to_string());
            }
        }
    }

    Ok(())
}

fn minimize_input(case: &FuzzCase, kind: FailureKind) -> Vec<u8> {
    let mut best = case.input.clone();
    if best.len() <= 1 {
        return best;
    }

    let mut probe = best.len() / 2;
    while probe >= 1 {
        let candidate = best[..probe].to_vec();
        let outcome = run_case(&case.target, &candidate);
        let still_fails = matches!(
            (kind, outcome),
            (FailureKind::Panic, CaseOutcome::Panic(_))
                | (
                    FailureKind::InvariantViolation,
                    CaseOutcome::InvariantViolation(_)
                )
        );
        if still_fails {
            best = candidate;
        }

        if probe == 1 {
            break;
        }
        probe /= 2;
    }

    best
}

fn write_reproducer(
    output_dir: &str,
    case: &FuzzCase,
    kind: FailureKind,
    minimized: &[u8],
) -> Result<String, String> {
    let repro_dir = format!("{output_dir}/reproducers");
    std::fs::create_dir_all(&repro_dir)
        .map_err(|err| format!("failed creating reproducer dir {repro_dir}: {err}"))?;

    let target = match case.target {
        FuzzTarget::ProfileLoader => "profile_loader",
        FuzzTarget::PolicyResolver => "policy_resolver",
        FuzzTarget::WireParsing => "wire_parsing",
    };
    let kind_str = match kind {
        FailureKind::Panic => "panic",
        FailureKind::InvariantViolation => "invariant",
    };

    let path = format!("{repro_dir}/case_{:06}_{target}_{kind_str}.json", case.id);
    let payload = serde_json::json!({
        "id": case.id,
        "target": target,
        "kind": kind_str,
        "bytes_base64": BASE64_STD.encode(minimized),
        "bytes_len": minimized.len(),
    });
    std::fs::write(
        &path,
        serde_json::to_string_pretty(&payload)
            .map_err(|err| format!("failed serializing reproducer payload: {err}"))?,
    )
    .map_err(|err| format!("failed writing reproducer file {path}: {err}"))?;

    Ok(path)
}

fn base_stack() -> ProfileStack {
    ProfileStack {
        base: BaseProfile {
            name: "base".to_string(),
            version: "1".to_string(),
            mode: InteropMode::Strict,
            canonicalization: CanonicalizationPolicy::default(),
            security: SecurityPolicy::default(),
            validation: ValidationPolicy::default(),
        },
        extensions: vec![],
        overrides: vec![],
        partner_overrides: vec![],
    }
}
