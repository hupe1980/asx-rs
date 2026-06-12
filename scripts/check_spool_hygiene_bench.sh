#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$repo_root"

sample_size="${1:-20}"
warmup_time="${2:-0.2}"
measurement_time="${3:-0.6}"

# Broad thresholds are intentional to avoid flaky failures while still catching
# material regressions in the startup-heavy and steady-state lanes.
max_enabled_unique_ns="${ASX_SPOOL_HYGIENE_MAX_ENABLED_UNIQUE_NS:-2500000}"
max_disabled_unique_ns="${ASX_SPOOL_HYGIENE_MAX_DISABLED_UNIQUE_NS:-50000}"
max_steady_state_ns="${ASX_SPOOL_HYGIENE_MAX_STEADY_STATE_NS:-5000}"
min_enabled_disabled_ratio="${ASX_SPOOL_HYGIENE_MIN_ENABLED_DISABLED_RATIO:-20}"
min_enabled_steady_ratio="${ASX_SPOOL_HYGIENE_MIN_ENABLED_STEADY_RATIO:-200}"

bench_name="spool_headroom_hygiene"
enabled_unique_lane="startup_checks_enabled_unique_dir"
disabled_unique_lane="startup_checks_disabled_unique_dir"
steady_state_lane="startup_checks_enabled_reused_dir_steady_state"

estimates_file() {
  local lane="$1"
  echo "target/criterion/${bench_name}/${lane}/new/estimates.json"
}

read_slope_ns() {
  local file="$1"
  jq -r '.slope.point_estimate' "$file"
}

assert_file_exists() {
  local file="$1"
  if [[ ! -f "$file" ]]; then
    echo "[spool-hygiene-bench] missing Criterion estimates file: $file" >&2
    exit 1
  fi
}

assert_le() {
  local label="$1"
  local value="$2"
  local limit="$3"
  if ! awk -v v="$value" -v l="$limit" 'BEGIN { exit !(v <= l) }'; then
    echo "[spool-hygiene-bench] FAIL: ${label}=${value}ns exceeds limit ${limit}ns" >&2
    exit 1
  fi
}

assert_ge() {
  local label="$1"
  local value="$2"
  local limit="$3"
  if ! awk -v v="$value" -v l="$limit" 'BEGIN { exit !(v >= l) }'; then
    echo "[spool-hygiene-bench] FAIL: ${label}=${value} is below required minimum ${limit}" >&2
    exit 1
  fi
}

format_us() {
  local value_ns="$1"
  awk -v n="$value_ns" 'BEGIN { printf "%.3f", n / 1000.0 }'
}

format_ratio() {
  local lhs="$1"
  local rhs="$2"
  awk -v a="$lhs" -v b="$rhs" 'BEGIN { printf "%.3f", a / b }'
}

echo "[spool-hygiene-bench] running Criterion benchmark"
cargo bench --bench spool_headroom_hygiene --features as4 -- \
  --sample-size "$sample_size" \
  --warm-up-time "$warmup_time" \
  --measurement-time "$measurement_time"

enabled_file="$(estimates_file "$enabled_unique_lane")"
disabled_file="$(estimates_file "$disabled_unique_lane")"
steady_file="$(estimates_file "$steady_state_lane")"

assert_file_exists "$enabled_file"
assert_file_exists "$disabled_file"
assert_file_exists "$steady_file"

enabled_ns="$(read_slope_ns "$enabled_file")"
disabled_ns="$(read_slope_ns "$disabled_file")"
steady_ns="$(read_slope_ns "$steady_file")"

enabled_disabled_ratio="$(format_ratio "$enabled_ns" "$disabled_ns")"
enabled_steady_ratio="$(format_ratio "$enabled_ns" "$steady_ns")"

echo "[spool-hygiene-bench] measured slopes"
echo "  ${enabled_unique_lane}: ${enabled_ns}ns ($(format_us "$enabled_ns")us)"
echo "  ${disabled_unique_lane}: ${disabled_ns}ns ($(format_us "$disabled_ns")us)"
echo "  ${steady_state_lane}: ${steady_ns}ns ($(format_us "$steady_ns")us)"
echo "  enabled/disabled ratio: ${enabled_disabled_ratio}x"
echo "  enabled/steady ratio: ${enabled_steady_ratio}x"

assert_le "$enabled_unique_lane" "$enabled_ns" "$max_enabled_unique_ns"
assert_le "$disabled_unique_lane" "$disabled_ns" "$max_disabled_unique_ns"
assert_le "$steady_state_lane" "$steady_ns" "$max_steady_state_ns"
assert_ge "enabled/disabled ratio" "$enabled_disabled_ratio" "$min_enabled_disabled_ratio"
assert_ge "enabled/steady ratio" "$enabled_steady_ratio" "$min_enabled_steady_ratio"

echo "[spool-hygiene-bench] passed"
