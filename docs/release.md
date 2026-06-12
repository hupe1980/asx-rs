# Release Process

## Prerequisites

Before tagging a release candidate:

1. The CI release-candidate-gate workflow is green.
2. No unquarantined flaky tests in the interop matrix.

---

## One-Shot Release Gate

```bash
bash scripts/release_gate.sh
```

This runs all mandatory gates in sequence. Individual gates can be run independently (see sections below).

---

## Mandatory Gates

### 1. Formatting

```bash
cargo fmt --all -- --check
```

### 2. Compile checks

```bash
cargo check --all-targets
RUSTFLAGS='-D warnings' cargo check --all-targets --all-features
```

### 3. Lint

```bash
cargo clippy --all-targets --all-features -- -D warnings
```

### 4. Feature-aware test sweep

```bash
cargo test --all-features --lib
for t in $(find tests -maxdepth 1 -name '*.rs' -print | sed -E 's@.*/@@; s@\.rs$@@' | sort); do
  cargo test --all-features --test "$t"
done
```

This preserves full integration coverage while emitting per-suite output that makes failures easier to localize than a single broad `cargo test --all-features` invocation.

### 5. Test quarantine validation

```bash
bash scripts/check_test_quarantine.sh docs/test-quarantine.txt
```

Validates that all entries in the quarantine file are still referenced in the test suite.

### 6. Interop matrix gate

```bash
bash scripts/run_interop_matrix.sh
```

Runs the full interop fixture corpus. Exits non-zero if any fixture fails or any flaky fixture lacks a quarantine entry.

### 7. WS-Security vector gate

```bash
bash scripts/run_wssec_vector_gate.sh
```

Validates all C14N golden vectors and strict WS-Security matrix scenarios.

### 8. Profile / interop coverage gate

```bash
bash scripts/check_profile_coverage.sh 85 src/interop.rs
```

Enforces ≥85% line coverage on `src/interop.rs` using `cargo llvm-cov`.

### 9. Adversarial fuzz gate

```bash
bash scripts/run_fuzz_gate.sh 4000 2500 artifacts/fuzz
```

Arguments: `[iterations] [budget_ms] [output_dir]`. Runs 4000 iterations with a 2500 ms budget per target.

### 10. Feature matrix compile checks

```bash
cargo check --no-default-features --features "as2,client"
cargo check --no-default-features --features "as4,server"
cargo check --no-default-features --features "as2,as4,client,server"
```

### 11. Performance gate

```bash
cargo run --release -p xtask --all-features -- \
  perf-gate --iterations 2000 \
  --check-baseline docs/perf-baseline.txt \
  --max-regression 0.25
```

Fails if any operation regresses more than 25% from the recorded baseline.

### 12. Hygiene scan

```bash
if rg -n "TODO|FIXME|HACK" src tests docs .github scripts \
  --glob '!docs/release-checklist.md' \
  --glob '!docs/release.md' \
  --glob '!scripts/release_gate.sh'; then
  exit 1
fi
if rg -n "allow\(deprecated\)|#\[deprecated" src tests benches; then
  exit 1
fi
```

Any matches are blocking. Deprecation scanning is intentionally code-focused to
avoid false positives from descriptive documentation text.

### 13. Spool hygiene benchmark regression gate

```bash
bash scripts/check_spool_hygiene_bench.sh 20 0.2 0.6
```

Runs the dedicated startup-heavy and steady-state spool hygiene Criterion lanes,
then validates broad, anti-flaky regression invariants from
`target/criterion/.../new/estimates.json` slope estimates.

Default thresholds can be tuned via environment variables:
`ASX_SPOOL_HYGIENE_MAX_ENABLED_UNIQUE_NS`,
`ASX_SPOOL_HYGIENE_MAX_DISABLED_UNIQUE_NS`,
`ASX_SPOOL_HYGIENE_MAX_STEADY_STATE_NS`,
`ASX_SPOOL_HYGIENE_MIN_ENABLED_DISABLED_RATIO`, and
`ASX_SPOOL_HYGIENE_MIN_ENABLED_STEADY_RATIO`.

---

## CI Workflow

File: `.github/workflows/rust.yml`

Required jobs (all must be green for `release-candidate-gate` to pass):

| Job | What it runs |
|---|---|
| `check-test` | `cargo check` + `cargo test` across feature matrix |
| `lint` | `cargo fmt --check` + `cargo clippy -- -D warnings` |
| `perf-gate` | `xtask perf-gate` against baseline |
| `perf-matrix-smoke` | Perf smoke across feature combinations |
| `interop-fixtures-required` | Required AS2/AS4 interop fixture suites |
| `property-and-fuzz-smoke` | Property and fuzz-smoke suites |
| `interop-matrix-and-vector-required` | `run_interop_matrix.sh` + `run_wssec_vector_gate.sh` |
| `fuzz-adversarial-required` | `run_fuzz_gate.sh` |
| `session-isolation-required` | `session_isolation_concurrency` suite |
| `coverage-profile-interop` | Profile/interop coverage ≥85% |
| `flaky-quarantine-policy` | `check_test_quarantine.sh` |
| `release-candidate-gate` | Aggregates all above jobs |

There is no manual override path in the release workflow. All jobs must pass.

---

## Release Checklist

- [ ] `cargo fmt --all -- --check` passes
- [ ] `cargo check --all-targets` passes
- [ ] `RUSTFLAGS='-D warnings' cargo check --all-targets --all-features` passes
- [ ] `cargo clippy --all-targets --all-features -- -D warnings` passes
- [ ] Feature-aware lib + integration sweep passes (`cargo test --all-features --lib` plus each `cargo test --all-features --test <target>` from `tests/*.rs`)
- [ ] `run_interop_matrix.sh` — no blocking failures
- [ ] `run_wssec_vector_gate.sh` — all vectors pass
- [ ] `check_profile_coverage.sh 85 src/interop.rs` — ≥85% coverage
- [ ] `run_fuzz_gate.sh 4000 2500 artifacts/fuzz` — no panics or invariant violations
- [ ] Feature compile matrix passes (`as2,client` / `as4,server` / `as2,as4,client,server`)
- [ ] Performance gate — no operation regresses >25%
- [ ] Spool hygiene benchmark gate passes (`check_spool_hygiene_bench.sh`)
- [ ] Hygiene scan — no TODO/FIXME/HACK and no code-level deprecated markers
- [ ] `docs/perf-baseline.txt` updated if performance characteristics changed
- [ ] `Cargo.toml` version bumped
- [ ] `CHANGELOG.md` entry written
- [ ] Git tag `v{version}` created
- [ ] `cargo publish --dry-run` succeeds

---

## Updating the Performance Baseline

When the performance profile intentionally improves (or a new benchmark is added), update the baseline:

```bash
cargo run --release -p xtask --all-features -- \
  perf-gate --iterations 2000 --write-baseline docs/perf-baseline.txt
```

Commit `docs/perf-baseline.txt` alongside the change. Do not update the baseline to hide regressions.

---

## Known Risks at Release

| Risk | Mitigation |
|---|---|
| XML Signature C14N variance | WS-Security strict matrix + golden vector gate |
| Relaxed interop exception creep | Scoped exception allow-lists with reason-code audit trail |
| Duplicate ingress side effects | Idempotency-key dedup backend with concurrency-tested behavior |
| Oversized payload memory pressure | Hard payload limits + `read_bounded_stream` |
| Performance regression in hot paths | CI perf gate at 25% threshold |
