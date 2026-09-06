# asx-rs task runner — run `just` to list recipes.
#
# Recipes mirror .github/workflows/rust.yml and the mandatory gates in
# RELEASING.md. When a gate changes there, change it here too (and vice
# versa) so local runs and CI cannot drift apart.

set shell := ["bash", "-euo", "pipefail", "-c"]

# Feature sets kept in sync with the CI `check-test` matrix.
# Mirrors the `check-test` matrix in `.github/workflows/ci.yml`. Keep the two
# in step: a combination only CI builds is one only CI can break.
ci_feature_matrix := "as2,client as4,server as2,as4,client,server,trace as2,as4,testing as2,as4,testing,interop-relaxed as2,as4,compression as4,client,dns"

# Perf gate deliberately omits `testing` — the crate refuses to build release
# artefacts with that feature (it disables WS-Security enforcement gates).
perf_features := "as2,as4,client,server,trace,compression,async-ocsp,interop-strict"

perf_iterations := "2000"
perf_max_regression := "0.25"
perf_baseline := "benches/perf-baseline.txt"

# Uncompiled (```ignore```) doctests. Lower this whenever an example is
# converted; `just doctest-ratchet` says when it can drop.
doctest_ignore_budget := "39"

coverage_threshold := "85"
coverage_files := "src/interop.rs"

fuzz_iterations := "4000"
fuzz_budget_ms := "2500"
fuzz_artifacts := "artifacts/fuzz"

_default:
    @just --list --unsorted

# ---------------------------------------------------------------------------
# Everyday
# ---------------------------------------------------------------------------

# Build with all features.
[group('dev')]
build:
    cargo build --all-features

# Type-check every target with all features.
[group('dev')]
check:
    cargo check --all-targets --all-features

# Type-check with warnings escalated to errors (release gate 2).
[group('dev')]
check-strict:
    RUSTFLAGS='-D warnings' cargo check --all-targets --all-features

# Run the whole test suite. Extra args are forwarded: `just test receipt_verify`.
[group('dev')]
test *args:
    cargo test --all-features {{ args }}

# Unit tests only — fastest useful feedback loop.
[group('dev')]
test-lib *args:
    cargo test --all-features --lib {{ args }}

# Run one integration suite by file stem: `just test-suite as4_push_flow`.
[group('dev')]
test-suite name *args:
    cargo test --all-features --test {{ name }} {{ args }}

# Format the workspace.
[group('dev')]
fmt:
    cargo fmt --all

# Apply rustfmt and every machine-applicable clippy suggestion.
[group('dev')]
fix:
    cargo fmt --all
    cargo clippy --workspace --all-targets --all-features --fix --allow-dirty --allow-staged

# Build rustdoc for this crate only.
[group('dev')]
doc:
    cargo doc --all-features --no-deps

# Build and open rustdoc.
[group('dev')]
doc-open:
    cargo doc --all-features --no-deps --open

# ---------------------------------------------------------------------------
# Lint gates (release gates 1 and 3)
# ---------------------------------------------------------------------------

# Formatting check only — never rewrites files.
[group('lint')]
fmt-check:
    cargo fmt --all -- --check

# Clippy with warnings as errors, exactly as CI runs it.
[group('lint')]
clippy:
    cargo clippy --workspace --all-targets --all-features -- -D warnings

# fmt-check + clippy — the CI `lint` job.
[group('lint')]
lint: fmt-check clippy

# Hygiene scan: no TODO/FIXME/HACK markers, no code-level deprecations.
#
# Deprecation scanning is code-only on purpose: prose in site/ legitimately
# describes deprecated behaviour without introducing any.
[group('lint')]
[doc('Scan for TODO/FIXME/HACK markers and code-level deprecations')]
hygiene:
    #!/usr/bin/env bash
    set -euo pipefail
    if command -v rg >/dev/null 2>&1; then
        scan() { rg -n "$1" src tests site/content .github scripts \
            --glob '!RELEASING.md' || true; }
        scan_code() { rg -n "$1" src tests benches || true; }
    else
        scan() { grep -rnE "$1" src tests site/content .github scripts \
            --exclude=release.md || true; }
        scan_code() { grep -rnE "$1" src tests benches || true; }
    fi
    failed=0
    markers=$(scan 'TODO|FIXME|HACK')
    if [ -n "$markers" ]; then
        echo "hygiene: unresolved work markers found:" >&2
        echo "$markers" >&2
        failed=1
    fi
    deprecations=$(scan_code 'allow\(deprecated\)|#\[deprecated')
    if [ -n "$deprecations" ]; then
        echo "hygiene: code-level deprecation markers found:" >&2
        echo "$deprecations" >&2
        failed=1
    fi
    [ "$failed" -eq 0 ] && echo "hygiene: clean"
    exit "$failed"

# ---------------------------------------------------------------------------
# Test sweeps
# ---------------------------------------------------------------------------

# Lib tests plus each integration suite separately (release gate 4).
#
# Slower than `just test`, but a failure names the suite that broke instead of
# burying it in one combined run.
[group('test')]
[doc('Lib tests plus each integration suite separately (release gate 4)')]
test-sweep:
    #!/usr/bin/env bash
    set -euo pipefail
    cargo test --all-features --lib
    for target in $(find tests -maxdepth 1 -name '*.rs' | sed -E 's@.*/@@; s@\.rs$@@' | sort); do
        echo "── tests/${target}.rs"
        cargo test --all-features --test "$target"
    done

# Compile and test each CI feature combination (release gate 10).
#
# Catches feature-gating breakage that `--all-features` hides — a symbol behind
# the wrong `cfg` compiles fine when everything is on.
[group('test')]
[doc('Compile and test each CI feature combination (release gate 10)')]
matrix:
    #!/usr/bin/env bash
    set -euo pipefail
    for features in {{ ci_feature_matrix }}; do
        echo "── features: ${features}"
        RUSTFLAGS='-D warnings' cargo check --no-default-features --features "$features"
        cargo test --no-default-features --features "$features"
    done

# Compile the benchmarks without running them.
#
# Uses the perf feature set, not `--all-features`: `cargo bench` builds in
# release profile, where the `testing` feature is a hard compile error.
[group('test')]
[doc('Compile the benchmarks without running them')]
bench-check:
    cargo bench --no-default-features --features "{{ perf_features }}" --no-run

# Run the Criterion benchmarks.
[group('perf')]
bench *args:
    cargo bench --no-default-features --features "{{ perf_features }}" {{ args }}

# ---------------------------------------------------------------------------
# Protocol / security gates
# ---------------------------------------------------------------------------

# Adversarial fuzz gate over profile loading, policy resolution and wire parsing.
[group('gate')]
fuzz-gate iterations=fuzz_iterations budget_ms=fuzz_budget_ms out=fuzz_artifacts:
    bash scripts/run_fuzz_gate.sh {{ iterations }} {{ budget_ms }} {{ out }}

# Interop fixture matrix (release gate 6).
[group('gate')]
interop-matrix:
    bash scripts/run_interop_matrix.sh

# WS-Security canonicalization / signature vector gate (release gate 7).
[group('gate')]
wssec-vectors:
    bash scripts/run_wssec_vector_gate.sh

# Lint the profile stack for dead overrides and missing invariants.
[group('gate')]
profile-lint:
    cargo run --quiet -p xtask --all-features -- profile-lint-gate

# Fail on a broken intra-doc link.
#
# These ship to docs.rs as dead references, and rustdoc only reports them as
# warnings — so they accumulate silently.
[group('gate')]
[doc('Fail on broken rustdoc intra-doc links')]
doc-links:
    RUSTDOCFLAGS='-D warnings' cargo doc --all-features --no-deps

# Walk the feature powerset.
#
# A hand-written matrix only covers combinations someone thought of. This is
# the gate that catches a `#[cfg]` whose callee is gated on a different
# feature, and a guard that only applies outside `testing` builds — neither of
# which `--all-features` can see.
#
# Requires cargo-hack: `cargo install cargo-hack`.
[group('gate')]
[doc('Check the feature powerset (depth 2)')]
powerset:
    cargo hack check --feature-powerset --depth 2 \
        --at-least-one-of as2,as4 \
        --exclude-features prometheus,opentelemetry \
        --lib --tests

# Ratchet on uncompiled doctests.
#
# A ```ignore``` block is never compiled, so it renders in rustdoc looking like
# checked Rust while being free to rot. This does not demand zero — it demands
# the number never grows.
[group('gate')]
[doc('Fail if the number of uncompiled (```ignore```) doctests grows')]
doctest-ratchet budget=doctest_ignore_budget:
    bash scripts/check_doctest_ratchet.sh {{ budget }}

# Validate the interop fixture catalogue against the repository.
[group('gate')]
fixtures-validate:
    cargo run --quiet -p xtask --all-features -- fixture-repo-validate

# Line-coverage gate on the profile resolver (release gate 8).
#
# Requires cargo-llvm-cov: `cargo install cargo-llvm-cov`.
[group('gate')]
[doc('Line-coverage gate on the profile resolver (release gate 8)')]
profile-coverage threshold=coverage_threshold files=coverage_files:
    bash scripts/check_profile_coverage.sh {{ threshold }} {{ files }}

# Diff two effective-policy snapshots and classify the risk of the change.
[group('gate')]
profile-diff before after:
    cargo run --quiet -p xtask --all-features -- profile-diff-gate {{ before }} {{ after }}

# ---------------------------------------------------------------------------
# Performance
# ---------------------------------------------------------------------------

# Perf gate against the recorded baseline (release gate 11).
[group('perf')]
perf-gate:
    cargo run --release -p xtask --no-default-features --features "{{ perf_features }}" -- \
        perf-gate --iterations {{ perf_iterations }} \
        --check-baseline {{ perf_baseline }} \
        --max-regression {{ perf_max_regression }}

# Fast perf smoke run, no baseline comparison.
[group('perf')]
perf-smoke iterations="500":
    cargo run --release -p xtask --no-default-features --features "{{ perf_features }}" -- \
        perf-gate --iterations {{ iterations }}

# Rewrite the perf baseline. Only run when a change intentionally moves timings,
# and commit the result with the change that caused it.
[group('perf')]
[doc('Rewrite the perf baseline (only for intentional timing changes)')]
perf-baseline-write:
    cargo run --release -p xtask --no-default-features --features "{{ perf_features }}" -- \
        perf-gate --iterations {{ perf_iterations }} --write-baseline {{ perf_baseline }}

# ---------------------------------------------------------------------------
# Documentation site
# ---------------------------------------------------------------------------

# Build the documentation site. Also fails on broken internal links and
# dangling heading anchors.
[group('site')]
[doc('Build the documentation site (fails on broken links and anchors)')]
site:
    zola --root site build

# Serve the site locally with rewritten URLs.
#
# `zola build` emits absolute URLs from `base_url`, so opening `site/public`
# from disk or a plain file server loads the *deployed* CSS and JS, not the
# local ones. Use this, not a static server, to preview a change.
[group('site')]
[doc('Serve the site locally with rewritten URLs')]
site-serve:
    zola --root site serve

# Regenerate the social card PNG from its SVG source.
#
# Social platforms — X, LinkedIn, Facebook, Slack — do not render SVG previews,
# so `og:image` must point at a raster file. The PNG is committed because the
# deploy job has no SVG rasteriser.
#
# Requires librsvg: `brew install librsvg` / `apt install librsvg2-bin`.
[group('site')]
[doc('Regenerate the social-card PNG from its SVG source (needs librsvg)')]
site-social-card:
    rsvg-convert -w 1200 -h 630 site/static/social-card.svg -o site/static/social-card.png
    @echo "regenerated site/static/social-card.png"

# ---------------------------------------------------------------------------
# Primary sources
# ---------------------------------------------------------------------------

# Download the RFCs, OASIS/W3C standards, network profiles and national
# regulations this crate is written against into specs/ (gitignored;
# specs/README.md is the index and says what each document governs).
#
# Existing files are kept, so a re-run only fills gaps. Anything the publisher
# refuses to a non-browser client is listed at the end for a manual download —
# keep the file name the index uses.
[group('specs')]
[doc('Fetch the primary sources into specs/ (gitignored; see specs/README.md)')]
specs:
    #!/usr/bin/env bash
    set -uo pipefail
    ua='Mozilla/5.0'
    missing=""
    # fetch DIR FILE URL
    fetch() {
        mkdir -p "specs/$1"
        if [ -s "specs/$1/$2" ]; then echo "kept     $1/$2"; return 0; fi
        if curl -fsSL -A "$ua" --retry 3 --retry-delay 5 --max-time 900 \
                -o "specs/$1/$2.part" "$3" && [ -s "specs/$1/$2.part" ]; then
            mv "specs/$1/$2.part" "specs/$1/$2"; echo "fetched  $1/$2"; return 0
        fi
        rm -f "specs/$1/$2.part"
        echo "MISSING  $1/$2  <- $3" >&2
        missing="$missing  $1/$2  <- $3"$'\n'
    }
    # rfc NUMBER SLUG — the IETF text is the normative form; PDFs add nothing.
    rfc() { fetch rfc "rfc$1-$2.txt" "https://www.rfc-editor.org/rfc/rfc$1.txt"; }

    # rfc/ — AS2 and everything AS2 is made of
    rfc 4130 as2-applicability-statement-2
    rfc 3335 ediint-as1-mime-edi
    rfc 5402 as2-compressed-data
    rfc 3274 cms-compressed-data
    rfc 6362 ediint-multiple-attachments
    rfc 6017 ediint-features-header
    rfc 5652 cms
    rfc 5751 smime-3.2-message-specification
    rfc 8551 smime-4.0-message-specification
    rfc 5754 sha2-in-cms
    rfc 4134 smime-example-messages
    rfc 8017 pkcs1-rsa-oaep
    rfc 3394 aes-key-wrap
    rfc 3798 mdn-message-disposition-notification
    rfc 8098 mdn-message-disposition-notification-obsoletes-3798
    rfc 6522 multipart-report
    rfc 2045 mime-1-format
    rfc 2046 mime-2-media-types
    rfc 2047 mime-3-header-extensions
    rfc 2049 mime-5-conformance
    rfc 2387 multipart-related
    rfc 2392 cid-mid-url
    rfc 5322 internet-message-format
    rfc 5280 pkix-certificate-and-crl-profile
    rfc 6960 ocsp
    rfc 5019 ocsp-lightweight-profile
    rfc 9110 http-semantics
    rfc 9112 http-1.1
    rfc 8446 tls-1.3

    # oasis/ — ebMS3 and AS4 themselves
    fetch oasis ebms_core-3.0-spec-os.pdf \
        'https://docs.oasis-open.org/ebxml-msg/ebms/v3.0/core/os/ebms_core-3.0-spec-os.pdf'
    fetch oasis ebms-header-3_0-200704.xsd \
        'https://docs.oasis-open.org/ebxml-msg/ebms/v3.0/core/os/ebms-header-3_0-200704.xsd'
    fetch oasis ebms-v3-part2-advanced-features.pdf \
        'https://docs.oasis-open.org/ebxml-msg/ebms/v3.0/part2/201004/ebms-v3-part2.pdf'
    fetch oasis mf.xsd \
        'https://docs.oasis-open.org/ebxml-msg/ebms/v3.0/part2/201004/mf.xsd'
    fetch oasis AS4-profile-v1.0-os.pdf \
        'https://docs.oasis-open.org/ebxml-msg/ebms/v3.0/profiles/AS4-profile/v1.0/os/AS4-profile-v1.0-os.pdf'
    fetch oasis ebcore-PartyIdType-1.0.pdf \
        'https://docs.oasis-open.org/ebcore/PartyIdType/v1.0/PartyIdType-1.0.pdf'
    fetch oasis bdx-smp-v1.0-os.pdf \
        'https://docs.oasis-open.org/bdxr/bdx-smp/v1.0/os/bdx-smp-v1.0-os.pdf'
    fetch oasis bdx-smp-v2.0-os.pdf \
        'https://docs.oasis-open.org/bdxr/bdx-smp/v2.0/os/bdx-smp-v2.0-os.pdf'
    fetch oasis BDX-Location-v1.0-os.pdf \
        'https://docs.oasis-open.org/bdxr/BDX-Location/v1.0/os/BDX-Location-v1.0-os.pdf'

    # wss/ — WS-Security: the security header AS4 signs and encrypts in
    fetch wss wss-SOAPMessageSecurity-v1.1.1-os.pdf \
        'https://docs.oasis-open.org/wss-m/wss/v1.1.1/os/wss-SOAPMessageSecurity-v1.1.1-os.pdf'
    fetch wss wss-x509TokenProfile-v1.1.1-os.pdf \
        'https://docs.oasis-open.org/wss-m/wss/v1.1.1/os/wss-x509TokenProfile-v1.1.1-os.pdf'
    fetch wss wss-SwAProfile-v1.1.1-os.pdf \
        'https://docs.oasis-open.org/wss-m/wss/v1.1.1/os/wss-SwAProfile-v1.1.1-os.pdf'
    fetch wss oasis-200401-wss-wssecurity-secext-1.0.xsd \
        'https://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd'
    fetch wss oasis-200401-wss-wssecurity-utility-1.0.xsd \
        'https://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd'
    fetch wss oasis-wss-wssecurity-secext-1.1.xsd \
        'https://docs.oasis-open.org/wss/oasis-wss-wssecurity-secext-1.1.xsd'

    # w3c/ — signature, encryption and the canonicalization both digest through
    fetch w3c xmldsig-core1.html         'https://www.w3.org/TR/xmldsig-core1/'
    fetch w3c xmldsig1-schema.xsd \
        'https://www.w3.org/TR/2013/REC-xmldsig-core1-20130411/xmldsig1-schema.xsd'
    fetch w3c xmldsig-core-schema.xsd \
        'https://www.w3.org/TR/2002/REC-xmldsig-core-20020212/xmldsig-core-schema.xsd'
    fetch w3c xmldsig-bestpractices.html 'https://www.w3.org/TR/xmldsig-bestpractices/'
    fetch w3c xmlenc-core1.html          'https://www.w3.org/TR/xmlenc-core1/'
    fetch w3c xenc-schema.xsd \
        'https://www.w3.org/TR/2002/REC-xmlenc-core-20021210/xenc-schema.xsd'
    fetch w3c xenc-schema-11.xsd \
        'https://www.w3.org/TR/2013/REC-xmlenc-core1-20130411/xenc-schema-11.xsd'
    fetch w3c xml-exc-c14n.html \
        'https://www.w3.org/TR/2002/REC-xml-exc-c14n-20020718/'
    fetch w3c xml-c14n-1.0.html \
        'https://www.w3.org/TR/2001/REC-xml-c14n-20010315'
    fetch w3c xml-c14n11.html            'https://www.w3.org/TR/xml-c14n11/'
    fetch w3c soap-1.1.html              'https://www.w3.org/TR/2000/NOTE-SOAP-20000508/'
    fetch w3c soap12-part1.html          'https://www.w3.org/TR/soap12-part1/'
    fetch w3c soap-envelope-1.2.xsd      'https://www.w3.org/2003/05/soap-envelope/'
    fetch w3c ws-addr-core.html          'https://www.w3.org/TR/ws-addr-core/'
    fetch w3c xop10.html                 'https://www.w3.org/TR/xop10/'
    fetch w3c soap12-mtom.html           'https://www.w3.org/TR/soap12-mtom/'

    # edelivery/ — the CEF profile of AS4 (published as Confluence pages)
    fetch edelivery edelivery-as4-2.0.html \
        'https://ec.europa.eu/digital-building-blocks/sites/spaces/DIGITAL/pages/845480153/eDelivery+AS4+-+2.0'
    fetch edelivery edelivery-as4-1.16.html \
        'https://ec.europa.eu/digital-building-blocks/sites/x/voA4O'
    fetch edelivery edelivery-as4-1.15.html \
        'https://ec.europa.eu/digital-building-blocks/sites/display/DIGITAL/eDelivery+AS4+-+1.15'
    fetch edelivery edelivery-conformance-testing-as4-user-guide-1.20.pdf \
        'https://ec.europa.eu/digital-building-blocks/sites/download/attachments/467118600/(eDelivery).(Conformance%20Testing%20Service).(User%20Guide).(v1.20).pdf'

    # peppol/ — the largest AS4 network in production
    fetch peppol peppol-as4-profile.html \
        'https://docs.peppol.eu/edelivery/as4/specification/'
    fetch peppol Peppol-EDN-Service-Metadata-Publishing-1.4.0-2025-02-06.pdf \
        'https://docs.peppol.eu/edelivery/smp/Peppol-EDN-Service-Metadata-Publishing-1.4.0-2025-02-06.pdf'
    fetch peppol Peppol-EDN-Service-Metadata-Locator-1.3.0-2025-02-06.pdf \
        'https://docs.peppol.eu/edelivery/sml/Peppol-EDN-Service-Metadata-Locator-1.3.0-2025-02-06.pdf'
    fetch peppol Peppol-EDN-Policy-for-use-of-identifiers-4.4.0-2025-02-06.pdf \
        'https://docs.peppol.eu/edelivery/policies/Peppol-EDN-Policy-for-use-of-identifiers-4.4.0-2025-02-06.pdf'
    fetch peppol PEPPOL-EDN-Policy-for-Transport-Security-1.1.0-2020-04-20.pdf \
        'https://docs.peppol.eu/edelivery/policies/PEPPOL-EDN-Policy-for-Transport-Security-1.1.0-2020-04-20.pdf'
    fetch peppol Peppol-EDN-Business-Message-Envelope-2.0.2-2026-07-02.pdf \
        'https://docs.peppol.eu/edelivery/envelope/Peppol-EDN-Business-Message-Envelope-2.0.2-2026-07-02.pdf'
    fetch peppol Peppol-Network-Policy-1.0.0-2026-07-02.pdf \
        'https://docs.peppol.eu/edelivery/policies/Peppol%20Network%20Policy%201.0.0%202026-07-02.pdf'

    # bdew/ — the German energy market's AS4 profile and the BSI crypto it cites
    fetch bdew bdew-as4-profil-1.2-20260401.pdf \
        'https://www.bundesnetzagentur.de/DE/Beschlusskammern/BK06/BK6_83_Zug_Mess/835_mitteilungen_datenformate/Mitteilung_56/Anlagen/AS4-Profil_1_2_20260401.pdf?__blob=publicationFile&v=1'
    fetch bdew bdew-as4-profil-1.1-v14.pdf \
        'https://bdew-mako.de/pdf/AS4-Profil_1.1_v14.pdf'
    fetch bdew bdew-as4-profil-1.0-20220901.pdf \
        'https://www.bundesnetzagentur.de/DE/Beschlusskammern/1_GZ/BK6-GZ/2021/BK6-21-282/Mitteilung02/AS4%20Profil.pdf?__blob=publicationFile&v=1'
    fetch bdew regelungen-zum-uebertragungsweg-as4-2.4.pdf \
        'https://bdew-mako.de/pdf/Regelungen_zum_%C3%9Cbertragungsweg_AS4_2.4.pdf'
    fetch bdew regelungen-zum-uebertragungsweg-as4-2.2.pdf \
        'https://www.bundesnetzagentur.de/DE/Beschlusskammern/BK06/BK6_83_Zug_Mess/835_mitteilungen_datenformate/Mitteilung_41/Anlagen/Regelungen_zum_%C3%9Cbertragungsweg_AS4_2.2.pdf?__blob=publicationFile&v=1'
    fetch bdew bsi-tr-03116-3.pdf \
        'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Publikationen/TechnischeRichtlinien/TR03116/BSI-TR-03116-3.pdf?__blob=publicationFile&v=4'
    fetch bdew bsi-tr-02102-2-tls.pdf \
        'https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/TechGuidelines/TG02102/BSI-TR-02102-2.pdf?__blob=publicationFile&v=4'

    # entsog/ — the European gas market's AS4 usage profile
    fetch entsog entsog-as4-usage-profile-4.0-final.pdf \
        'https://www.entsog.eu/sites/default/files/2025-09/INT2819_25%20AS4%20Usage%20Profile_Version%204.0%20Final.pdf'

    # nist/ — the key-derivation the BDEW ECDH-ES key transport is defined by
    fetch nist NIST.SP.800-56Ar3.pdf \
        'https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Ar3.pdf'

    # market/ — the implementations this crate is measured against
    fetch market phase4-master.zip \
        'https://github.com/phax/phase4/archive/refs/heads/master.zip'
    fetch market Holodeck-B2B-master.zip \
        'https://github.com/holodeck-b2b/Holodeck-B2B/archive/refs/heads/master.zip'
    fetch market as2-lib-master.zip \
        'https://github.com/phax/as2-lib/archive/refs/heads/master.zip'
    fetch market OpenAs2App-master.zip \
        'https://github.com/OpenAS2/OpenAs2App/archive/refs/heads/master.zip'
    fetch market oxalis-master.zip \
        'https://github.com/OxalisCommunity/oxalis/archive/refs/heads/master.zip'

    if [ -n "$missing" ]; then
        printf '\nNot fetched (download in a browser, keep the file name):\n%s' "$missing" >&2
    fi

# ---------------------------------------------------------------------------
# Composite
# ---------------------------------------------------------------------------

# Pre-push check: everything CI's `lint` and `check-test` jobs run.
[group('composite')]
ci: lint check-strict test matrix powerset

# Every mandatory release gate, in the order RELEASING.md lists them.
#
# Long-running. `just ci` is the fast pre-push subset.
[group('composite')]
[doc('Every mandatory release gate, in RELEASING.md order (slow)')]
release-gate: fmt-check check check-strict clippy doc-links test-sweep powerset interop-matrix wssec-vectors fuzz-gate matrix perf-gate hygiene profile-lint fixtures-validate doctest-ratchet site
    @echo "release-gate: all implemented gates passed"

# Verify the crate packages cleanly for crates.io.
[group('composite')]
publish-dry:
    cargo publish --dry-run --all-features

# Remove build artefacts, including gate output.
[group('composite')]
clean:
    cargo clean
    rm -rf {{ fuzz_artifacts }}
