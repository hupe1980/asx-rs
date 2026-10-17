#!/usr/bin/env bash
# The blocking public-API gate (spec 042 T077, FR-003, FR-031, research R15).
#
#   1. The snapshot `cargo +nightly public-api -sss --all-features` equals
#      tests/public-api.txt (regenerate with `just public-api-update` and
#      review the diff in the same change).
#   2. The declared item count is at most 160: lines starting with `pub `,
#      excluding members of `impl Trait for Type` blocks (fixed by the trait).
#   3. No name in scripts/deleted-names.txt is a segment of an `asx::` path.
#   4. FR-003: no declared item name selects signing, encryption, compression,
#      an algorithm, a token reference, or a receipt/MDN/MIC requirement —
#      outside the contract's allowlisted items (the `Profile`/`Quirk` data,
#      the key-custody seam and trust material).
#
# Usage: scripts/public-api-check.sh [--update]
#   --update rewrites tests/public-api.txt; review the diff in the same change.
set -euo pipefail
cd "$(dirname "$0")/.."

BUDGET=160
committed=tests/public-api.txt
failed=0

current=$(cargo +nightly public-api -sss --all-features -p asx-rs 2>/dev/null)
if [ "${1:-}" = "--update" ]; then
    printf '%s\n' "$current" >"$committed"
fi

# count SNAPSHOT: declared items (see 2. above).
count() {
printf '%s\n' "$1" | awk '
    /^impl/ {
        self = ""
        if ($0 ~ / for /) {
            self = $0
            sub(/^.* for /, "", self)
            sub(/ where .*$/, "", self)
        }
        next
    }
    {
        line = $0
        while (line ~ /^#\[[^]]*\] /) sub(/^#\[[^]]*\] /, "", line)
        if (line !~ /^pub /) next
        path = line
        sub(/^pub (unsafe |async |const )*(fn|type|const|static) /, "", path)
        if (self != "" && index(path, self "::") == 1) next
        count++
    }
    END { print count + 0 }
'
}

# 1. Snapshot equality.
if ! diff -u "$committed" <(printf '%s\n' "$current") >&2; then
    echo "public-api: the public API differs from $committed (scripts/public-api-check.sh --update)" >&2
    failed=1
fi

# 2. Budget.
count=$(count "$current")
echo "public items: $count (budget $BUDGET)"
if [ "$count" -gt "$BUDGET" ]; then
    echo "public-api: $count declared items exceed the budget of $BUDGET" >&2
    failed=1
fi

# 3. Deleted names.
while IFS= read -r name; do
    case "$name" in '' | '#'*) continue ;; esac
    if printf '%s\n' "$current" |
        grep -E "(^|[^A-Za-z0-9_])asx(::[A-Za-z0-9_]+)*::${name}([^A-Za-z0-9_]|$)" >&2; then
        echo "public-api: deleted name '$name' is public again (contracts/deletions.md)" >&2
        failed=1
    fi
done <scripts/deleted-names.txt

# 4. FR-003 word check over declared item paths.
# `Builder::crl_signer` is trust material (the indirect-CRL signer, like a
# trust anchor), not a setting (spec 026 research R10).
allow='^asx::(Profile|Quirk|SignatureAlgorithm|Signer|Receipt|KeyOp|ClaimToken)(::|<|$)|^asx::KeyPair::sign$|^asx::LocalParty::signer$|^asx::Partner::(signing_cert|encryption_cert)$|^asx::Builder<C>::crl_signer$|^asx::Verified<T>::signer$|^asx::AuditRecord::signal$|^asx::Claim::Claimed$'
words=$(printf '%s\n' "$current" | awk '
    {
        line = $0
        while (line ~ /^#\[[^]]*\] /) sub(/^#\[[^]]*\] /, "", line)
        if (line !~ /^pub /) next
        sub(/^pub (unsafe |async |const )*(fn|struct|enum|trait|type|mod|const|static|union) /, "", line)
        sub(/^pub /, "", line)
        sub(/[( ].*$/, "", line)
        sub(/:$/, "", line)
        sub(/<[^:]*>$/, "", line)
        print line
    }' | grep -iE 'sign|encrypt|compress|algorithm|token|receipt|mic' | grep -vE "$allow" || true)
if [ -n "$words" ]; then
    echo "public-api: item names that select a security or wire setting (FR-003):" >&2
    echo "$words" >&2
    failed=1
fi

if [ "$failed" -ne 0 ]; then
    exit 1
fi
echo "public-api: snapshot equal, $count ≤ $BUDGET items, no deleted name, FR-003 clean"
