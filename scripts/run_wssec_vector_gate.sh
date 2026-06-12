#!/usr/bin/env bash
set -euo pipefail

cargo run --quiet -p xtask --all-features -- wssec-vector-gate
