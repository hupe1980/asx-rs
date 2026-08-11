# asx-rs task runner — run `just` to list recipes.
#
# Recipes mirror .github/workflows/rust.yml and the mandatory gates in
# RELEASING.md. When a gate changes there, change it here too (and vice
# versa) so local runs and CI cannot drift apart.

set shell := ["bash", "-euo", "pipefail", "-c"]

# Feature sets kept in sync with the CI `check-test` matrix.
ci_feature_matrix := "as2,client as4,server as2,as4,client,server,trace"

# Perf gate deliberately omits `testing` — the crate refuses to build release
# artefacts with that feature (it disables WS-Security enforcement gates).
perf_features := "as2,as4,client,server,trace,compression,async-ocsp,interop-strict"

perf_iterations := "2000"
perf_max_regression := "0.25"
perf_baseline := "benches/perf-baseline.txt"

coverage_threshold := "85"
coverage_files := "src/interop.rs"

fuzz_iterations := "4000"
fuzz_budget_ms := "2500"
fuzz_artifacts := "artifacts/fuzz"

_default:
    @just --list --unsorted

# ---------------------------------------------------------------------------
# Everyday
# ---------------------------------------------------------------------------

# Build with all features.
[group('dev')]
build:
    cargo build --all-features

# Type-check every target with all features.
[group('dev')]
check:
    cargo check --all-targets --all-features

# Type-check with warnings escalated to errors (release gate 2).
[group('dev')]
check-strict:
    RUSTFLAGS='-D warnings' cargo check --all-targets --all-features

# Run the whole test suite. Extra args are forwarded: `just test receipt_verify`.
[group('dev')]
test *args:
    cargo test --all-features {{ args }}

# Unit tests only — fastest useful feedback loop.
[group('dev')]
test-lib *args:
    cargo test --all-features --lib {{ args }}

# Run one integration suite by file stem: `just test-suite as4_push_flow`.
[group('dev')]
test-suite name *args:
    cargo test --all-features --test {{ name }} {{ args }}

# Format the workspace.
[group('dev')]
fmt:
    cargo fmt --all

# Apply rustfmt and every machine-applicable clippy suggestion.
[group('dev')]
fix:
    cargo fmt --all
    cargo clippy --workspace --all-targets --all-features --fix --allow-dirty --allow-staged

# Build rustdoc for this crate only.
[group('dev')]
doc:
    cargo doc --all-features --no-deps

# Build and open rustdoc.
[group('dev')]
doc-open:
    cargo doc --all-features --no-deps --open

# ---------------------------------------------------------------------------
# Lint gates (release gates 1 and 3)
# ---------------------------------------------------------------------------

# Formatting check only — never rewrites files.
[group('lint')]
fmt-check:
    cargo fmt --all -- --check

# Clippy with warnings as errors, exactly as CI runs it.
[group('lint')]
clippy:
    cargo clippy --workspace --all-targets --all-features -- -D warnings

# fmt-check + clippy — the CI `lint` job.
[group('lint')]
lint: fmt-check clippy

# Hygiene scan: no TODO/FIXME/HACK markers, no code-level deprecations.
#
# Deprecation scanning is code-only on purpose: prose in site/ legitimately
# describes deprecated behaviour without introducing any.
[group('lint')]
[doc('Scan for TODO/FIXME/HACK markers and code-level deprecations')]
hygiene:
    #!/usr/bin/env bash
    set -euo pipefail
    if command -v rg >/dev/null 2>&1; then
        scan() { rg -n "$1" src tests docs .github scripts \
            --glob '!RELEASING.md' || true; }
        scan_code() { rg -n "$1" src tests benches || true; }
    else
        scan() { grep -rnE "$1" src tests docs .github scripts \
            --exclude=release.md || true; }
        scan_code() { grep -rnE "$1" src tests benches || true; }
    fi
    failed=0
    markers=$(scan 'TODO|FIXME|HACK')
    if [ -n "$markers" ]; then
        echo "hygiene: unresolved work markers found:" >&2
        echo "$markers" >&2
        failed=1
    fi
    deprecations=$(scan_code 'allow\(deprecated\)|#\[deprecated')
    if [ -n "$deprecations" ]; then
        echo "hygiene: code-level deprecation markers found:" >&2
        echo "$deprecations" >&2
        failed=1
    fi
    [ "$failed" -eq 0 ] && echo "hygiene: clean"
    exit "$failed"

# ---------------------------------------------------------------------------
# Test sweeps
# ---------------------------------------------------------------------------

# Lib tests plus each integration suite separately (release gate 4).
#
# Slower than `just test`, but a failure names the suite that broke instead of
# burying it in one combined run.
[group('test')]
[doc('Lib tests plus each integration suite separately (release gate 4)')]
test-sweep:
    #!/usr/bin/env bash
    set -euo pipefail
    cargo test --all-features --lib
    for target in $(find tests -maxdepth 1 -name '*.rs' | sed -E 's@.*/@@; s@\.rs$@@' | sort); do
        echo "── tests/${target}.rs"
        cargo test --all-features --test "$target"
    done

# Compile and test each CI feature combination (release gate 10).
#
# Catches feature-gating breakage that `--all-features` hides — a symbol behind
# the wrong `cfg` compiles fine when everything is on.
[group('test')]
[doc('Compile and test each CI feature combination (release gate 10)')]
matrix:
    #!/usr/bin/env bash
    set -euo pipefail
    for features in {{ ci_feature_matrix }}; do
        echo "── features: ${features}"
        cargo check --no-default-features --features "$features"
        cargo test --no-default-features --features "$features"
    done

# Compile the benchmarks without running them.
#
# Uses the perf feature set, not `--all-features`: `cargo bench` builds in
# release profile, where the `testing` feature is a hard compile error.
[group('test')]
[doc('Compile the benchmarks without running them')]
bench-check:
    cargo bench --no-default-features --features "{{ perf_features }}" --no-run

# Run the Criterion benchmarks.
[group('perf')]
bench *args:
    cargo bench --no-default-features --features "{{ perf_features }}" {{ args }}

# ---------------------------------------------------------------------------
# Protocol / security gates
# ---------------------------------------------------------------------------

# Adversarial fuzz gate over profile loading, policy resolution and wire parsing.
[group('gate')]
fuzz-gate iterations=fuzz_iterations budget_ms=fuzz_budget_ms out=fuzz_artifacts:
    bash scripts/run_fuzz_gate.sh {{ iterations }} {{ budget_ms }} {{ out }}

# Interop fixture matrix (release gate 6).
[group('gate')]
interop-matrix:
    bash scripts/run_interop_matrix.sh

# WS-Security canonicalization / signature vector gate (release gate 7).
[group('gate')]
wssec-vectors:
    bash scripts/run_wssec_vector_gate.sh

# Lint the profile stack for dead overrides and missing invariants.
[group('gate')]
profile-lint:
    cargo run --quiet -p xtask --all-features -- profile-lint-gate

# Validate the interop fixture catalogue against the repository.
[group('gate')]
fixtures-validate:
    cargo run --quiet -p xtask --all-features -- fixture-repo-validate

# Line-coverage gate on the profile resolver (release gate 8).
#
# Requires cargo-llvm-cov: `cargo install cargo-llvm-cov`.
[group('gate')]
[doc('Line-coverage gate on the profile resolver (release gate 8)')]
profile-coverage threshold=coverage_threshold files=coverage_files:
    bash scripts/check_profile_coverage.sh {{ threshold }} {{ files }}

# Diff two effective-policy snapshots and classify the risk of the change.
[group('gate')]
profile-diff before after:
    cargo run --quiet -p xtask --all-features -- profile-diff-gate {{ before }} {{ after }}

# ---------------------------------------------------------------------------
# Performance
# ---------------------------------------------------------------------------

# Perf gate against the recorded baseline (release gate 11).
[group('perf')]
perf-gate:
    cargo run --release -p xtask --no-default-features --features "{{ perf_features }}" -- \
        perf-gate --iterations {{ perf_iterations }} \
        --check-baseline {{ perf_baseline }} \
        --max-regression {{ perf_max_regression }}

# Fast perf smoke run, no baseline comparison.
[group('perf')]
perf-smoke iterations="500":
    cargo run --release -p xtask --no-default-features --features "{{ perf_features }}" -- \
        perf-gate --iterations {{ iterations }}

# Rewrite the perf baseline. Only run when a change intentionally moves timings,
# and commit the result with the change that caused it.
[group('perf')]
[doc('Rewrite the perf baseline (only for intentional timing changes)')]
perf-baseline-write:
    cargo run --release -p xtask --no-default-features --features "{{ perf_features }}" -- \
        perf-gate --iterations {{ perf_iterations }} --write-baseline {{ perf_baseline }}

# ---------------------------------------------------------------------------
# Composite
# ---------------------------------------------------------------------------

# Pre-push check: everything CI's `lint` and `check-test` jobs run.
[group('composite')]
ci: lint check-strict test matrix

# Every mandatory release gate, in the order RELEASING.md lists them.
#
# Long-running. `just ci` is the fast pre-push subset.
[group('composite')]
[doc('Every mandatory release gate, in RELEASING.md order (slow)')]
release-gate: fmt-check check check-strict clippy test-sweep interop-matrix wssec-vectors fuzz-gate matrix perf-gate hygiene profile-lint fixtures-validate
    @echo "release-gate: all implemented gates passed"

# Verify the crate packages cleanly for crates.io.
[group('composite')]
publish-dry:
    cargo publish --dry-run --all-features

# Remove build artefacts, including gate output.
[group('composite')]
clean:
    cargo clean
    rm -rf {{ fuzz_artifacts }}
