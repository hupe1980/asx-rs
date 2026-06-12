#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$repo_root"

echo "[docs-drift] checking README status claims"
if rg -n "Outbound AS4 user-message envelopes do not yet include a WS-Security wsu:Timestamp" README.md >/dev/null; then
  echo "[docs-drift] stale README claim detected: AS4 wsu:Timestamp gap is no longer valid"
  exit 1
fi

echo "[docs-drift] checking reliability model docs"
rg -n "pub reason: ReconciliationReason" docs/reliability.md >/dev/null
if rg -n "should_await_receipt|queued_at|retry_count|last_attempt|RetryClass::Terminal|RetryClass::Transient" docs/reliability.md >/dev/null; then
  echo "[docs-drift] stale reliability schema terms detected in docs/reliability.md"
  exit 1
fi

echo "[docs-drift] checking observability default semantics docs"
rg -n "strict subscriber requirements|new_best_effort" docs/observability.md >/dev/null

echo "[docs-drift] passed"
