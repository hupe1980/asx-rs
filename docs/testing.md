# Testing

## Overview

ASX has a multi-layer test strategy:

| Layer | Location | Scope |
|---|---|---|
| Unit tests | `src/**` (`#[cfg(test)]`) | Individual functions, edge cases |
| Integration tests | `tests/` | End-to-end protocol flows, concurrency |
| Property tests | `tests/profile_property_invariants.rs` | Randomized profile stack invariants |
| Interop matrix | `tests/fixtures/interop/` | Governed fixture corpus across strict/relaxed modes |
| WS-Security vectors | `tests/wssec_c14n_vectors.rs`, `tests/wssec_strict_matrix.rs` | C14N golden vectors, strict signature/reference verification |
| Session isolation | `tests/session_isolation_concurrency.rs` | Per-session policy isolation under concurrency |
| Fuzz / adversarial | `artifacts/fuzz/` | Adversarial inputs to profile loader, policy resolver, wire parser |
| Performance gate | `xtask/` | Regression detection against baseline ns/op values |

---

## Running the Full Test Suite

```bash
cargo test --all-features
```

Runs all 224+ unit and integration tests. Zero failures expected.

Run specific feature combinations:
```bash
cargo test --features "as2,client"
cargo test --features "as4,server"
cargo test --features "as2,as4,client,server"
```

---

## Integration Test Suites

### AS2 flows

```bash
cargo test --all-features as2_send_golden
cargo test --all-features as2_receive_mdn
```

Covers: MIME packaging, MIC computation (RFC 4130 §7.3.1), MDN generation/parsing, MDN signature verification, sync/async MDN modes, `As2MdnMode::None`.

### AS4 flows

```bash
cargo test --all-features as4_push_flow
cargo test --all-features as4_pull_flow
```

Covers: SOAP envelope construction, WS-Security signing and verification, AES-128-GCM encrypt/decrypt, RSA-OAEP/MGF1-SHA256 key wrap, pull store enqueue/dequeue, signed pull request generation, Two-Way MEP correlation, Test Service detection.

---

## Interop Fixture Repository

The interop fixture corpus governs AS2 MIME and AS4 SOAP strict/relaxed flows with declared expected outcomes.

### Fixture catalog

Location: `tests/fixtures/interop/catalog.json`

Schema (`schema_version: "1.0"`):

```json
{
  "schema_version": "1.0",
  "fixtures": [
    {
      "fixture_id": "as2-strict-001",
      "protocol": "As2Mime",
      "mode": "Strict",
      "grouping": {
        "partner_id": "partner-a",
        "profile_name": "strict-edelivery",
        "protocol_stage": "send"
      },
      "payload_path": "partner-a/strict/send/payload.mime",
      "expected_outcome": "SuccessConfirmed",
      "reason_annotations": ["RFC 4130 §6 compliant headers, signed"]
    }
  ]
}
```

### Required coverage

The catalog must contain at least one fixture for each combination:
- `As2Mime/Strict`
- `As2Mime/Relaxed`
- `As4Soap/Strict`
- `As4Soap/Relaxed`

### Validate the repository

```bash
cargo run -p xtask -- fixture-repo-validate tests/fixtures/interop/catalog.json
```

Validation checks: schema version, non-empty fixture set, unique IDs, non-empty grouping metadata, non-empty reason annotations, payload file existence, protocol-specific file extension (`.mime` for AS2, `.xml` for AS4).

---

## Interop Matrix Executor

Runs all interop fixtures across policy/profile combinations and produces a machine-readable `MatrixSummary`:

```bash
cargo run -p xtask --all-features -- interop-matrix \
  tests/fixtures/interop/catalog.json \
  tests/fixtures/interop/quarantine.json \
  3    # iteration count for flake detection
# or:
scripts/run_interop_matrix.sh
```

`MatrixSummary` output includes per-fixture pass/fail, observed error code, flakiness status, and quarantine owner.

### Quarantine policy

Flaky fixtures are allowed in CI only when listed in `tests/fixtures/interop/quarantine.json` with an owner assignment. Unquarantined flaky fixtures are blocking. The matrix runner exits non-zero when:
- Any fixture fails
- Any fixture is flaky without a quarantine entry

---

## WS-Security Canonicalization Golden Vectors

`tests/wssec_c14n_vectors.rs` validates the custom Exclusive C14N implementation against deterministic golden vectors:

```bash
cargo test --all-features wssec_c14n_vectors
cargo test --all-features wssec_strict_matrix
# Run as explicit gate:
scripts/run_wssec_vector_gate.sh
# or:
cargo run -p xtask --all-features -- wssec-vector-gate
```

Covered scenarios:
- Strict canonicalization against golden vector file
- Signature reference verification for a signed fixture
- Wrapped reference URI rejection under strict URI normalization rules
- Whitespace-preserving digest mismatch rejection under strict canonicalization rules
- Namespace propagation, attribute ordering, text/attribute escaping
- PI node forwarding, comment stripping, comment preservation
- InclusiveNamespaces PrefixList with ancestor binding rendering

Vector mismatch output uses `canonical_vector_diff(expected, actual)` — deterministic line-based diffs with expected/actual markers for reproducible triage.

---

## Session Isolation and Concurrency

`tests/session_isolation_concurrency.rs` validates session-scoped policy isolation under concurrent execution:

```bash
cargo test --all-features session_isolation_concurrency
```

Covered:
- Strict and relaxed session pairs executing concurrently without policy leakage
- Session-scoped exception behavior remains isolated
- Cross-session contamination attempts fail
- Per-session event ordering validated for critical audit/signing sequences
- AS2 concurrent strict-vs-relaxed MDN boundary-quirk flow
- AS4 concurrent strict-vs-relaxed UserMessage parse flow

---

## Property Tests

`tests/profile_property_invariants.rs` uses randomized inputs to verify profile stack invariants:

```bash
cargo test --all-features profile_property_invariants
```

Covered invariants:
- Deterministic resolution stability under randomized layer combinations (same input always produces same output)
- Monotonic precedence for partner overlays (last applicable partner layer wins)
- Fail-fast validation for malformed/conflicting policy combinations

---

## Fuzz and Adversarial Testing

The adversarial fuzz gate runs seeded adversarial cases over three targets:

1. **Profile loader** — `RegionalProfilePack::from_json` + regional pack application
2. **Policy resolver** — `ProfileStack::validate` + `resolve` determinism
3. **Wire parsing** — `WireEnvelope::from_http_request_with_limits`, stream bounded reads, transfer fingerprinting

```bash
scripts/run_fuzz_gate.sh 4000 2500 artifacts/fuzz
# or:
cargo run -p xtask --all-features -- fuzz-gate 4000 2500 artifacts/fuzz
```

Arguments: `[iterations] [budget_ms] [output_dir]`

Fail conditions:
- Any panic
- Determinism violation (different output for same input)
- Missing remediation hints or empty error messaging
- Stream/accounting mismatch

**Reproducer handling**: On failure, the gate minimizes the input payload by deterministic truncation and stores a reproducer in `artifacts/fuzz/reproducers/` as JSON with base64 bytes. CI uploads `artifacts/fuzz/` as a triage artifact.

---

## Performance Gate

Reference baseline values (ns/op):

| Operation | Baseline (ns/op) |
|---|---|
| `as2_sign_encrypt` | 8 262 |
| `as2_mdn_generation` | 200 |
| `as2_verify_decrypt_mdn` | 2 072 |
| `as4_verify_decrypt` | 42 |
| `as4_verify_decrypt_receipt` | 5 962 |
| `as4_receipt_generation` | 59 |

These values are environment-relative. CI enforces a **25% maximum regression** threshold. Do not use them for absolute hardware claims.

Run the performance gate:
```bash
# Write new baseline:
cargo run --release -p xtask --all-features -- \
  perf-gate --iterations 2000 --write-baseline docs/perf-baseline.txt

# Check against baseline (fails if any operation regresses >25%):
cargo run --release -p xtask --all-features -- \
  perf-gate --iterations 2000 --check-baseline docs/perf-baseline.txt --max-regression 0.25
```

---

## Transport Server Tests (No Network)

Server handler tests use `tower::ServiceExt::oneshot` — no listening socket required:

```toml
[dev-dependencies]
tower = { version = "0.4", features = ["util"] }
```

```rust
use tower::ServiceExt;

let response = as2_router(Arc::new(handler), "/as2/receive")
    .oneshot(request)
    .await
    .unwrap();
assert_eq!(response.status(), 200);
```

12 server integration tests ship with the crate and run as part of `cargo test --all-features`.

---

## Testing Feature Flag

```toml
asx = { version = "0.1", features = ["testing"] }
```

The `testing` feature exposes `asx::fixtures` and `asx::matrix` — test scaffold modules with `InteropFixtureMetadata`, `FixtureCatalog`, `MatrixSummary`, and related helpers. These are not part of the production library surface and are absent from builds without this feature.
