#!/usr/bin/env bash
# The rules a compiler cannot check in the published Markdown (README.md and
# site/content/**/*.md). The compile half is `src/docs.rs` (doctests).
#
#   hidden-line   a line starting with `# ` (or equal to `#`) inside a rust
#                 block: Zola renders it, so the reader sees setup rustdoc hides.
#   ignore        a ```rust,ignore block not preceded (previous non-blank line)
#                 by `<!-- ignore: <reason> -->`, or more reasoned ignores than
#                 DOCS_IGNORE_BUDGET (default 0).
#   golden        the README's three golden-path blocks differ from
#                 examples/{as4_send,as4_receive_axum,as2_send_mdn}.rs (byte for
#                 byte, after the info string).
#   deleted-name  a name from scripts/deleted-names.txt (0.15 API) appears
#                 outside the migration page.
#   migration     a name from scripts/deleted-names.txt is missing from the
#                 migration page.
#   citation      a BDEW document cited with "§": the BDEW AS4-Profil and the
#                 Regelungen zum Übertragungsweg number their sections as
#                 Kapitel ("BDEW AS4-Profil 1.2 Kap. 2.3.4.4", "RzÜ AS4 2.6
#                 Kap. 5.2", the profile tables' "B Kap. 2.3.1.1"), also in a
#                 list ("Kap. 2.2.6.1, 2.3.4.4", never "…, §2.3.4.4") and
#                 across a line break. "§" stays for the English-language
#                 sources on the same line ("…; BSI TR-03116-3 §4"). Checked
#                 in the Markdown above, THREAT_MODEL.md, SECURITY.md,
#                 concepts/*.md and the Rust sources of src/, examples/,
#                 xtask/ and benches/.
set -euo pipefail

cd "$(dirname "$0")/.."
NAMES=scripts/deleted-names.txt
BUDGET="${DOCS_IGNORE_BUDGET:-0}"

# check ROOT: run every rule on ROOT/README.md and ROOT/site/content (and
# ROOT/examples for the golden rule). Prints findings, returns 1 on any.
check() {
    local root="$1"
    python3 -I - "$root" "$NAMES" "$BUDGET" <<'PY'
import os, re, sys

root, names_file, budget = sys.argv[1], sys.argv[2], int(sys.argv[3])
files = []
if os.path.exists(os.path.join(root, "README.md")):
    files.append(os.path.join(root, "README.md"))
for d, _, fs in os.walk(os.path.join(root, "site", "content")):
    files += [os.path.join(d, f) for f in sorted(fs) if f.endswith(".md")]

names = [l.strip() for l in open(names_file) if l.strip() and not l.startswith("#")]
# Identifier-like names match as words; plain lower-case module names would
# match English prose or telemetry values (`storage`, `transport`), so they
# only count as a path segment (`x::name`, `name::x`).
def pattern(n):
    if re.search(r"[A-Z_]", n):
        return re.compile(r"(?<![A-Za-z0-9_])" + re.escape(n) + r"(?![A-Za-z0-9_])")
    e = re.escape(n)
    return re.compile(r"(::%s\b|\b%s::)" % (e, e))
patterns = [(n, pattern(n)) for n in names]

fence = re.compile(r"^(\s*)(```+)(.*)$")
findings = []
ignores = 0
for path in files:
    rel = os.path.relpath(path, root)
    lines = open(path, encoding="utf-8").read().split("\n")
    in_block, info, prev = False, "", ""
    for i, line in enumerate(lines, 1):
        m = fence.match(line)
        if m and not in_block:
            in_block, info = True, m.group(3).strip()
            if info.startswith("rust") and "ignore" in info.split(","):
                if re.match(r"<!--\s*ignore:\s*\S.*-->", prev.strip()):
                    ignores += 1
                else:
                    findings.append(f"{rel}:{i}: ignore: ```{info} without a preceding <!-- ignore: reason -->")
            continue
        if m and in_block:
            in_block = False
            prev = line
            continue
        if in_block and info.startswith("rust") and (line.startswith("# ") or line.strip() == "#"):
            findings.append(f"{rel}:{i}: hidden-line: Zola renders `# ` lines; write the sample as a complete item")
        if line.strip():
            prev = line
    if not rel.endswith(os.path.join("docs", "migration.md")):
        text = "\n".join(lines)
        for n, p in patterns:
            for mm in p.finditer(text):
                ln = text.count("\n", 0, mm.start()) + 1
                findings.append(f"{rel}:{ln}: deleted-name: {n} (0.15 API; only migration.md may name it)")
if ignores > budget:
    findings.append(f"ignore: {ignores} reasoned ```rust,ignore blocks, budget {budget}")

migration = os.path.join(root, "site", "content", "docs", "migration.md")
if os.path.exists(migration):
    text = open(migration, encoding="utf-8").read()
    missing = [n for n in names if n not in text]
    for n in missing:
        findings.append(f"site/content/docs/migration.md: migration: {n} is not mapped")

readme = os.path.join(root, "README.md")
if os.path.exists(readme):
    blocks = re.findall(r"^```rust[^\n]*\n(.*?)^```", open(readme, encoding="utf-8").read(), re.S | re.M)
    golden = [b for b in blocks if b.startswith("//! Golden path")]
    expected = ["as4_send", "as4_receive_axum", "as2_send_mdn"]
    if len(golden) != len(expected):
        findings.append(f"README.md: golden: {len(golden)} golden-path blocks, expected {len(expected)}")
    for block, name in zip(golden, expected):
        ex = os.path.join(root, "examples", name + ".rs")
        if not os.path.exists(ex) or open(ex, encoding="utf-8").read() != block:
            findings.append(f"README.md: golden: block for examples/{name}.rs is not byte-identical to the file")

# A BDEW document name directly followed by "§", or "§" continuing a "Kap."
# list. `doc_end` finds a document name, or an open "Kap." list, at the end of a line whose citation
# continues on the next.
BDEW_DOC = (r"(?<![\w.\-])(?:BDEW(?: AS4-Profil)?(?: \d\.\d+)?|AS4-Profil(?: \d\.\d+)?"
            r"|B|RzÜ(?: AS4)?(?: \d\.\d+)?|Regelungen zum Übertragungsweg AS4\*?(?: \d\.\d+)?)")
citation = re.compile(BDEW_DOC + r" §\d")
kap_list = re.compile(r"Kap\. \d[\d.]*(?:(?:, ?|/|–)(?:Kap\. )?\d[\d.]*)*(?:, ?|/|–)§\d")
doc_end = re.compile(BDEW_DOC + r"\s*$|Kap\. \d[\d.]*(?:, ?\d[\d.]*)*,\s*$")
next_section = re.compile(r"^\s*(?:///?!?|\*|#)?\s*§\d")
cited = list(files)
for extra in ("THREAT_MODEL.md", "SECURITY.md"):
    if os.path.exists(os.path.join(root, extra)):
        cited.append(os.path.join(root, extra))
concepts = os.path.join(root, "concepts")
if os.path.isdir(concepts):
    cited += [os.path.join(concepts, f) for f in sorted(os.listdir(concepts)) if f.endswith(".md")]
for code in ("src", "examples", "xtask", "benches"):
    for d, _, fs in os.walk(os.path.join(root, code)):
        cited += [os.path.join(d, f) for f in sorted(fs) if f.endswith(".rs")]
for path in cited:
    lines = open(path, encoding="utf-8").read().split("\n")
    for i, line in enumerate(lines, 1):
        split = doc_end.search(line) and i < len(lines) and next_section.match(lines[i])
        if citation.search(line) or kap_list.search(line) or split:
            findings.append(f"{os.path.relpath(path, root)}:{i}: citation: BDEW documents number sections as Kapitel (\"BDEW AS4-Profil 1.2 Kap. N\", \"RzÜ AS4 2.6 Kap. N\")")

for f in findings:
    print(f)
sys.exit(1 if findings else 0)
PY
}

if check .; then
    echo "check-docs: README.md and site/content pass"
else
    echo "check-docs: failed (rules: see the header of scripts/check-docs.sh)" >&2
    exit 1
fi
