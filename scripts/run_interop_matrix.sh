#!/usr/bin/env bash
set -euo pipefail

catalog_path="${1:-tests/fixtures/interop/catalog.json}"
quarantine_path="${2:-tests/fixtures/interop/quarantine.json}"
iterations="${3:-3}"

cargo run --quiet -p xtask --all-features -- interop-matrix "$catalog_path" "$quarantine_path" "$iterations"
