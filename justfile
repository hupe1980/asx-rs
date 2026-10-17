# asx-rs tasks — run `just` to list them. `just ci` runs locally what the CI
# jobs check, features, msrv and deny run; `just interop` is the CI interop job.

set shell := ["bash", "-euo", "pipefail", "-c"]

_default:
    @just --list --unsorted

# Build with all features.
build:
    cargo build --workspace --all-features

# Run the tests, doctests included (README and site samples). Args are forwarded.
test *args:
    cargo test --workspace --all-features {{ args }}

# Format the workspace.
fmt:
    cargo fmt --all

# fmt check, clippy, rustdoc and the docs rules.
lint:
    cargo fmt --all -- --check
    cargo clippy --locked --workspace --all-features --all-targets -- -D warnings
    RUSTDOCFLAGS='-D warnings' cargo doc --locked --all-features --no-deps
    bash scripts/check-docs.sh
    bash scripts/concepts-check.sh

# No default features, each feature alone, all features (needs cargo-hack).
features:
    RUSTFLAGS='-D warnings' CARGO_TARGET_DIR=target/features cargo hack check --locked -p asx-rs --each-feature --lib --tests

# Build on the MSRV floor (Cargo.toml rust-version).
msrv:
    cargo +1.88 check --locked --workspace --all-features

# Dependency policy, deny.toml (needs cargo-deny).
deny:
    cargo deny --workspace --all-features check advisories licenses bans sources

# What CI runs, minus interop.
ci: lint test features msrv deny

# Holodeck B2B (arm64-only image, not in CI) runs by hand:
#   cargo test --all-features --test interop_holodeck_counterparty -- --ignored
[doc('Interop oracles: openssl, xmlsec1, Redis, phase4 (Docker; builds the phase4 peer unless ASX_PHASE4_IMAGE is set)')]
interop:
    #!/usr/bin/env bash
    set -euo pipefail
    export ASX_PHASE4_IMAGE="${ASX_PHASE4_IMAGE:-$(docker build -q --provenance=false tests/fixtures/phase4)}"
    for t in interop_openssl_smime_oracle interop_xmlsec_oracle interop_redis_storage_conformance \
             interop_phase4_counterparty interop_phase4_encryption interop_phase4_path_switch; do
        echo "── $t"
        cargo test --locked --all-features --test "$t" -- --ignored --test-threads=1
    done

# `bash scripts/public-api-check.sh --update` rewrites tests/public-api.txt.
[doc('Public-API gate: snapshot, at most 160 items, no deleted name (nightly + cargo-public-api)')]
public-api:
    bash scripts/public-api-check.sh

# No published file cites concepts/, specs/, .specify/ or .claude/; roadmap ↔ specs.
concepts-check:
    bash scripts/concepts-check.sh

# Criterion benchmarks (AS4 parsing, C14N, MIME scanning).
bench *args:
    cargo bench --features as4 {{ args }}

# Build the site (fails on broken links and anchors).
site:
    zola --root site build

# Serve the site locally.
site-serve:
    zola --root site serve

# Download the RFCs, OASIS/W3C standards, network profiles and national
# regulations this crate is written against into concepts/references/
# (gitignored; concepts/references/README.md is the index and says what each
# document governs).
#
# Existing files are kept, so a re-run only fills gaps. Anything the publisher
# refuses to a non-browser client is listed at the end for a manual download —
# keep the file name the index uses.
[doc('Fetch the primary sources into concepts/references/ (gitignored; see its README.md)')]
references:
    #!/usr/bin/env bash
    set -uo pipefail
    ua='Mozilla/5.0'
    missing=""
    # fetch DIR FILE URL
    fetch() {
        mkdir -p "concepts/references/$1"
        if [ -s "concepts/references/$1/$2" ]; then echo "kept     $1/$2"; return 0; fi
        if curl -fsSL -A "$ua" --retry 3 --retry-delay 5 --max-time 900 \
                -o "concepts/references/$1/$2.part" "$3" && [ -s "concepts/references/$1/$2.part" ]; then
            mv "concepts/references/$1/$2.part" "concepts/references/$1/$2"; echo "fetched  $1/$2"; return 0
        fi
        rm -f "concepts/references/$1/$2.part"
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

    # Added 2026-10-16: the second algorithm generation, the BDEW rules in force,
    # and the Peppol MLS phase-in and G3 PKI (see concepts/RESEARCH.md).
    rfc 9231 xmldsig-more-uris
    rfc 8410 ed25519-x25519-in-pkix
    rfc 5869 hkdf
    fetch edelivery edelivery2-as4-security-validator.html \
        'https://ec.europa.eu/digital-building-blocks/sites/pages/viewpage.action?pageId=900018554'
    fetch peppol peppol-mls-1.1.0-spec.html \
        'https://docs.peppol.eu/edelivery/specs/mls/v1.1.0/mls/spec/'
    fetch peppol SPOG-on-MLS-1.0.0-2026-07-02.pdf \
        'https://docs.peppol.eu/edelivery/guidelines/mls/SPOG%20on%20MLS%201.0.0%202026-07-02.pdf'
    fetch peppol Peppol-MLS-Phase-In-1.0.0-2026-07-02.pdf \
        'https://docs.peppol.eu/edelivery/changelog/2026-07/Peppol%20MLS%20Phase-In%201.0.0%202026-07-02.pdf'
    fetch peppol Peppol-MLR-Phase-Out-1.0.0-2026-07-02.pdf \
        'https://docs.peppol.eu/edelivery/changelog/2026-07/Peppol%20MLR%20Phase-Out%201.0.0%202026-07-02.pdf'
    fetch peppol peppol-pki-g3-migration-plan.html \
        'https://openpeppol.atlassian.net/wiki/spaces/OPMA/pages/3977936899'
    fetch bdew regelungen-zum-uebertragungsweg-as4-2.6-20260401.pdf \
        'https://www.bundesnetzagentur.de/DE/Beschlusskammern/BK06/BK6_83_Zug_Mess/835_mitteilungen_datenformate/Mitteilung_56/Anlagen/Regelungen_zum_Uebertragungsweg_AS4_2_6_20260401.pdf?__blob=publicationFile&v=1'
    # The SM-PKI documents RzÜ §5.4 points to (spec 026).
    fetch bdew bsi-tr-03109-4-sm-pki-1.2.1.pdf \
        'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Publikationen/TechnischeRichtlinien/TR03109/TR-03109-4_PKI.pdf?__blob=publicationFile&v=3'
    fetch bdew sm-pki-certificate-policy-1.1.2.pdf \
        'https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Publikationen/TechnischeRichtlinien/TR03109/PKI_Certificate_Policy.pdf?__blob=publicationFile&v=8'
    fetch entsog entsog-as4-faq-2025-v0.2.pdf \
        'https://www.entsog.eu/sites/default/files/2025-06/INT2879_25%20ENTSOG%20AS4%20FAQs%202025%20ver%200.2%20FINAL%20PUBLISHED.pdf'
    fetch market oxalis-ng-master.zip \
        'https://github.com/OxalisCommunity/oxalis-ng/archive/refs/heads/master.zip'

    if [ -n "$missing" ]; then
        printf '\nNot fetched (download in a browser, keep the file name):\n%s' "$missing" >&2
    fi
