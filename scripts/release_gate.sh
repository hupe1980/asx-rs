#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$repo_root"

echo "[release-gate] validating quarantine policy"
bash scripts/check_test_quarantine.sh docs/test-quarantine.txt

echo "[release-gate] formatting"
cargo fmt --all -- --check

echo "[release-gate] compile checks"
cargo check --all-targets
RUSTFLAGS='-D warnings' cargo check --all-targets --all-features

echo "[release-gate] lint"
cargo clippy --workspace --all-targets --all-features -- -D warnings

echo "[release-gate] docs drift checks"
bash scripts/check_docs_drift.sh

echo "[release-gate] feature-aware test sweep (lib + integration targets)"
cargo test --all-features --lib

mapfile -t integration_tests < <(find tests -maxdepth 1 -type f -name '*.rs' -print | sed -E 's@.*/@@; s@\.rs$@@' | sort)
for test_name in "${integration_tests[@]}"; do
  echo "[release-gate] running integration suite: ${test_name}"
  cargo test --all-features --test "$test_name"
done

echo "[release-gate] interop matrix and ws-security vector gates"
bash scripts/run_interop_matrix.sh
bash scripts/run_wssec_vector_gate.sh

echo "[release-gate] profile/interop coverage threshold"
bash scripts/check_profile_coverage.sh 85 src/interop.rs

echo "[release-gate] profile lint fail-fast gate"
cargo run -p xtask --features as4 -- profile-lint-gate

echo "[release-gate] AS4 strict deprecations source-policy gate"
bash scripts/check_as4_strict_deprecations.sh

echo "[release-gate] adversarial fuzz gate"
bash scripts/run_fuzz_gate.sh 4000 2500 artifacts/fuzz

echo "[release-gate] feature matrix checks"
cargo check --no-default-features --features "as2,client"
cargo check --no-default-features --features "as4,server"
cargo check --no-default-features --features "as2,as4,client,server"

echo "[release-gate] performance regression gate"
cargo run --release -p xtask --all-features -- perf-gate \
  --iterations 2000 \
  --check-baseline docs/perf-baseline.txt \
  --max-regression 0.25

echo "[release-gate] spool hygiene benchmark regression gate"
bash scripts/check_spool_hygiene_bench.sh 20 0.2 0.6

echo "[release-gate] hygiene scan"
if rg -n "TODO|FIXME|HACK" src tests docs .github scripts \
  --glob '!docs/release-checklist.md' \
  --glob '!docs/release.md' \
  --glob '!scripts/release_gate.sh'; then
  echo "[release-gate] hygiene scan failed: unresolved TODO/FIXME/HACK markers found" >&2
  exit 1
fi
echo "[release-gate] hygiene scan passed"

echo "[release-gate] code-level deprecated API scan"
if rg -n "allow\(deprecated\)|#\[deprecated" src tests benches; then
  echo "[release-gate] deprecated API scan failed: code-level deprecated markers found" >&2
  exit 1
fi
echo "[release-gate] code-level deprecated API scan passed"

echo "[release-gate] passed"
