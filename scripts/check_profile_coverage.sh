#!/usr/bin/env bash
set -euo pipefail

threshold="${1:-85}"
filters="${2:-src/interop.rs}"

if ! command -v cargo-llvm-cov >/dev/null 2>&1; then
  echo "cargo-llvm-cov is required for coverage gate" >&2
  exit 2
fi

cargo llvm-cov --all-features --json --output-path target/llvm-cov.json
cargo run --quiet -p xtask -- profile-coverage-gate target/llvm-cov.json "$threshold" "$filters"
