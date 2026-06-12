#!/usr/bin/env bash
set -euo pipefail

file_path="${1:-docs/test-quarantine.txt}"

if [[ ! -f "$file_path" ]]; then
  echo "quarantine file missing: $file_path" >&2
  exit 1
fi

errors=0
entries=0

while IFS= read -r raw_line || [[ -n "$raw_line" ]]; do
  line="${raw_line%%$'\r'}"
  trimmed="$(echo "$line" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"

  if [[ -z "$trimmed" || "$trimmed" == \#* ]]; then
    continue
  fi

  entries=$((entries + 1))
  IFS='|' read -r test_name owner deadline reason extra <<<"$trimmed"

  if [[ -n "${extra:-}" ]]; then
    echo "invalid quarantine entry (too many fields): $trimmed" >&2
    errors=$((errors + 1))
    continue
  fi

  if [[ -z "${test_name:-}" || -z "${owner:-}" || -z "${deadline:-}" || -z "${reason:-}" ]]; then
    echo "invalid quarantine entry (missing field): $trimmed" >&2
    errors=$((errors + 1))
    continue
  fi

  if ! [[ "$deadline" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]]; then
    echo "invalid deadline format in quarantine entry: $trimmed" >&2
    errors=$((errors + 1))
  fi
done <"$file_path"

if [[ $errors -gt 0 ]]; then
  echo "quarantine validation failed with $errors error(s)" >&2
  exit 2
fi

if [[ $entries -eq 0 ]]; then
  echo "quarantine validation passed: no quarantined tests"
else
  echo "quarantine validation passed: $entries quarantined test(s)"
fi
