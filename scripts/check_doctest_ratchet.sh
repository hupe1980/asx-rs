#!/usr/bin/env bash
# Ratchet on uncompiled doctests.
#
# ```ignore``` blocks are NOT compiled by `cargo test --doc`. They render in
# rustdoc looking like checked Rust and rot silently: the example that no longer
# compiles is exactly the one a user copies. (```no_run``` IS compiled — it just
# does not execute — so it is not counted here.)
#
# This does not demand zero. It demands the number never grows, so every new
# example is a working one and every conversion is a visible improvement.
set -euo pipefail

BUDGET="${1:-41}"

count=$(grep -rhoE '^[[:space:]]*(///|//!)[[:space:]]*```(rust,)?ignore' src/ | wc -l | tr -d ' ')

printf 'uncompiled doctests (```ignore```): %s (budget %s)\n' "$count" "$BUDGET"

if [ "$count" -gt "$BUDGET" ]; then
    cat >&2 <<MSG

error: $((count - BUDGET)) new uncompiled doctest(s).

  A \`\`\`ignore\`\`\` block is never compiled, so it looks checked and is not.
  Either make the example compile — \`\`\`no_run\`\`\` is compiled without being
  executed, and hidden \`#\` lines can supply the setup — or, if it is genuinely
  pseudo-code, mark it \`\`\`text\`\`\` so it does not claim to be Rust.

  New offenders are among:
MSG
    grep -rnE '^[[:space:]]*(///|//!)[[:space:]]*```(rust,)?ignore' src/ >&2
    exit 1
fi

if [ "$count" -lt "$BUDGET" ]; then
    printf '\nThe budget can be lowered to %s in justfile.\n' "$count"
fi
