# Release Process

## Prerequisites

Before tagging a release candidate:

1. The CI release-candidate-gate workflow is green.
2. No unquarantined flaky tests in the interop matrix.
3. [`CHANGELOG.md`](../CHANGELOG.md) has an entry for the release, and the
   version bump matches the [SemVer policy](../CHANGELOG.md#semver-policy) — see
   [gate 12](#12-changelog-and-version-classification).

---

## One-Shot Release Gate

```bash
just release-gate
```

This runs every mandatory gate in sequence. Individual gates can be run
independently — `just --list` shows them all, and each section below names the
recipe alongside the raw command.

`just ci` is the faster pre-push subset (lint + strict check + tests + feature
matrix), matching what the CI `lint` and `check-test` jobs run.

Every gate documented below exists and runs. Two aspirational gates — a
test-quarantine validator and a spool-hygiene benchmark regression check — were
described here in full, including tunable environment variables, while their
scripts had never been written. They were removed in 0.13.0: a checklist that
lists gates nobody can run teaches readers to skip the checklist.

---

## Mandatory Gates

### 1. Formatting

```bash
just fmt-check        # cargo fmt --all -- --check
```

### 2. Compile checks

```bash
just check            # cargo check --all-targets --all-features
just check-strict     # RUSTFLAGS='-D warnings' cargo check --all-targets --all-features
```

### 3. Lint

```bash
just clippy           # cargo clippy --workspace --all-targets --all-features -- -D warnings
```

### 4. Feature-aware test sweep

```bash
just test-sweep
```

This preserves full integration coverage while emitting per-suite output that makes failures easier to localize than a single broad `cargo test --all-features` invocation.

### 5. Interop matrix gate

```bash
just interop-matrix   # bash scripts/run_interop_matrix.sh
```

Runs the full interop fixture corpus. Exits non-zero if any fixture fails or any flaky fixture lacks a quarantine entry.

### 6. WS-Security vector gate

```bash
just wssec-vectors    # bash scripts/run_wssec_vector_gate.sh
```

Validates all C14N golden vectors and strict WS-Security matrix scenarios.

### 7. Profile / interop coverage gate

```bash
just profile-coverage # bash scripts/check_profile_coverage.sh 85 src/interop.rs
```

Enforces ≥85% line coverage on `src/interop.rs` using `cargo llvm-cov`.

### 8. Adversarial fuzz gate

```bash
just fuzz-gate        # bash scripts/run_fuzz_gate.sh 4000 2500 artifacts/fuzz
```

Arguments: `[iterations] [budget_ms] [output_dir]`. Runs 4000 iterations with a 2500 ms budget per target.

### 9. Feature matrix compile checks

```bash
just matrix
```

Compiles **and tests** each combination from the CI matrix.

### 10. Performance gate

```bash
just perf-gate
```

Fails if any operation regresses more than 25% from the recorded baseline.

Note the explicit feature list rather than `--all-features`: the crate refuses
to compile a `--release` build with the `testing` feature (it disables
WS-Security enforcement gates), so `cargo run --release -p xtask --all-features`
fails to build. `just perf-gate` uses the same feature set as CI.

### 11. Hygiene scan

```bash
just hygiene
```

Scans `src tests docs .github scripts` for `TODO`/`FIXME`/`HACK` (excluding this
file, which names the markers to describe the gate) and `src tests benches` for
`allow(deprecated)` / `#[deprecated]`.

Any matches are blocking. Deprecation scanning is intentionally code-focused to
avoid false positives from descriptive documentation text.

---

### 12. CHANGELOG and version classification

Every release adds a [`CHANGELOG.md`](../CHANGELOG.md) entry that separates the
two kinds of change an integrator has to reason about:

- **Wire / crypto behaviour** — what goes on the network, or what is accepted
  from it. Breaks interop with a counterparty even when consumer code compiles
  unchanged.
- **API** — signatures, types, feature gates. Breaks the build, which is the
  safe direction.

Then classify the release against the
[SemVer policy](../CHANGELOG.md#semver-policy). Two rules do most of the work:

1. **A wire-behaviour change is never a patch release.** If the bytes on the
   wire changed, or the set of accepted inbound messages changed, it is a minor
   bump (`0.x` → `0.x+1`) even when the Rust API is untouched.
2. **Security defaults tighten in minor releases, not patches.** If the release
   starts rejecting something it previously accepted, say so explicitly in the
   entry so integrators can schedule the upgrade.

Checklist for the entry:

- [ ] Every breaking API change has a before/after migration snippet
- [ ] Every wire/crypto change is labelled as such, not buried under "Changed"
- [ ] Newly enforced rejections appear under `### Security`
- [ ] The version bump matches the policy table

---

## CI Workflow

File: `.github/workflows/ci.yml`

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

`just release-gate` covers every implemented item below in one run.

- [ ] `just fmt-check` passes
- [ ] `just check` and `just check-strict` pass
- [ ] `just clippy` passes
- [ ] `just test-sweep` passes (lib + every integration suite)
- [ ] `just interop-matrix` — no blocking failures
- [ ] `just wssec-vectors` — all vectors pass
- [ ] `just profile-coverage` — ≥85% coverage on `src/interop.rs`
- [ ] `just fuzz-gate` — no panics or invariant violations
- [ ] `just matrix` — every CI feature combination compiles and tests
- [ ] `just perf-gate` — no operation regresses >25%
- [ ] `just hygiene` — no TODO/FIXME/HACK and no code-level deprecated markers
- [ ] `docs/perf-baseline.txt` updated if performance characteristics changed
- [ ] `Cargo.toml` version bumped per the [SemVer policy](../CHANGELOG.md#semver-policy)
- [ ] `CHANGELOG.md` entry written, wire/crypto changes labelled separately from API changes
- [ ] Git tag `v{version}` created
- [ ] `just publish-dry` succeeds

---

## Updating the Performance Baseline

When the performance profile intentionally improves (or a new benchmark is added), update the baseline with `just perf-baseline-write`, or directly:

```bash
cargo run --release -p xtask \
  --no-default-features --features "as2,as4,client,server,trace,compression,async-ocsp,interop-strict" -- \
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
