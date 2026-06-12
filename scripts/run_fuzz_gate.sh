#!/usr/bin/env bash
set -euo pipefail

iterations="${1:-4000}"
budget_ms="${2:-2500}"
output_dir="${3:-artifacts/fuzz}"

cargo run --quiet -p xtask --all-features -- fuzz-gate "$iterations" "$budget_ms" "$output_dir"
