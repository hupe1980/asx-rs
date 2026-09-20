# asx-rs

**AS2 and AS4 B2B messaging for Rust — async-native, memory-safe, and fail-closed by default.**

[![Crates.io](https://img.shields.io/crates/v/asx-rs.svg)](https://crates.io/crates/asx-rs)
[![Docs.rs](https://docs.rs/asx-rs/badge.svg)](https://docs.rs/asx-rs)
[![License](https://img.shields.io/crates/l/asx-rs.svg)](#license)

`asx-rs` implements [AS2 (RFC 4130)](https://www.rfc-editor.org/rfc/rfc4130) and
[AS4 (OASIS ebMS3 / eDelivery)](https://docs.oasis-open.org/ebxml-msg/ebms/v3.0/profiles/AS4-profile/v1.0/)
— the wire protocols behind PEPPOL, CEF eDelivery, BDEW, and a large share of the
world's EDI trading-partner connections.

It is an **embeddable library**, not a gateway. There is no container to run, no
database to provision, and no JVM. You get the protocol and the cryptography;
storage, key management and deployment stay yours.

📖 **[Documentation](https://hupe1980.github.io/asx-rs)** ·
🦀 **[API reference](https://docs.rs/asx-rs)** ·
📋 **[Changelog](CHANGELOG.md)**

---

## Install

```bash
cargo add asx-rs --features as4,client,server
```

`as2` and `as4` are **not** on by default — enable the protocols you need.

| Flag | Enables | Default |
|------|---------|---------|
| `crypto` | Shared OpenSSL gate (RSA/ECDSA, X.509, CMS, OCSP) — pulled in by `as2`/`as4` | via protocol |
| `as2` | AS2 send/receive, S/MIME, MDN | ❌ |
| `as4` | AS4 send/receive, pull store, WS-Security, XML encryption | ❌ |
| `client` | HTTP egress via `reqwest` (HTTPS-only, SSRF-validated, optional mTLS client identity) | ❌ |
| `server` | Axum router integration for inbound | ❌ |
| `compression` | AS2 (RFC 5402 CMS) and AS4 (gzip) payload compression | ✅ |
| `async-ocsp` | Async OCSP responder fetching | ✅ |
| `interop-strict` | Strict interop mode as the compile-time default | ✅ |
| `interop-relaxed` | Relaxed-mode helpers for legacy partners | ❌ |
| `trace` | `tracing` instrumentation on hot paths | ✅ |
| `prometheus` / `opentelemetry` | Metrics sink adapters | ❌ |
| `dns` | Built-in BDXL/NAPTR resolver for Peppol participant discovery | ❌ |
| `testing` | Bypass verifiers, mock endpoint, keypair generators | ❌ |

> The `testing` feature raises a `compile_error!` in release builds. It cannot
> reach a production binary by accident.

## Example

Send a signed AS4 message and verify the counterparty's receipt:

```rust
use asx_rs::as4::{send_async, As4ReceiptPolicy, As4SendPolicyBuilder, As4SendRequest};
use asx_rs::transport::egress::{As4HttpTransport, TransportConfig};

let (policy, credentials) = As4SendPolicyBuilder::new()
    .action("urn:example:action")
    .service("urn:example:service", "")
    .signing_cert_pem(cert_pem)
    .signing_key_pem(key_pem)
    .build()?;

let sent = send_async(&session, &bus, As4SendRequest {
    message_id: message_id.clone(),
    payload,
    policy,
    credentials: Some(credentials),
    ..Default::default()
}).await?;

let outcome = As4HttpTransport::new(TransportConfig::default())?
    .send_and_verify(&url, &session, &bus, &sent, &As4ReceiptPolicy::regulated())
    .await?;
```

A receipt is only evidence of delivery once its signature and non-repudiation
digests are checked against the message you sent. `send_and_verify` does both in
one call, so that step cannot be skipped by accident.

More examples — AS2 send, inbound routers, encryption enforcement, testing
without a PKI — are in the
**[getting-started guide](https://hupe1980.github.io/asx-rs/docs/getting-started/)**.

## What makes it different

**The type system enforces the trust boundary.** Payloads move through
`UntrustedBytes → StructurallyParsed → CryptographicallyVerified →
ContentDecrypted → DomainReady`. Application code cannot receive bytes that
skipped a gate, because no value exists in that state.

**Insecure configurations are unreachable by omission.** Signatures are required,
AS4 pull is denied, SMP lookup results are not trusted, P-Modes sign *and*
encrypt, and encrypted-spool profiles refuse to run without a key — until you
explicitly choose otherwise. Every relaxation is a named variant you select,
never a field you forgot.

**A verified signature is not an identity.** Every access point shares its
network's trust anchors, so "it verifies" proves membership, not who sent it. A
signed message whose claimed `eb:From` has no pinned certificate is refused;
`As4SignerPins` resolves the permitted signer per partner, so a match is proof.

**Deduplication is two-phase.** A first-seen message hands you an unsettled
claim: `accept` it once the message is durably yours, `abandon` it if not, and
the partner's retransmission is processed rather than swallowed as a duplicate.

**Integration points are traits, not built-ins.** Dedup, reconciliation, durable
audit, DNS resolution and spool-encryption keys are interfaces you implement
against your own PostgreSQL, Redis, resolver, KMS or HSM. The crate does not
guess at their protocols — it ships a conformance suite instead, so "durable"
and "cluster-safe" are things your backend *demonstrates* rather than declares.
And it does not ship what it cannot know: there is no retry scheduler, no
storage backend and no alerting engine, because a retry budget and a failure-rate
threshold are properties of your partners and your topology, not of a protocol.

See the **[security model](https://hupe1980.github.io/asx-rs/docs/security/)** for
trust boundaries, defaults, and what the library does *not* protect against.

## Status

**Beta.** Core AS2 and AS4 flows are implemented and covered by ~1,000 unit and
integration tests, plus property, fuzz, golden-vector and cross-implementation
gates. The library contains no `unsafe` — `#![forbid(unsafe_code)]` keeps it
that way — and is clippy-clean at `--all-features --all-targets`.
MSRV is Rust 1.88, and CI builds on that exact floor.

Implemented:

- AS2 send/receive — signed, encrypted, compressed, sync and async MDN
- AS4 push send/receive — signed, encrypted, two-phase dedup, fragment reassembly
- AS4 pull with reliability classification and MPC authorization
- WS-Security: RSA-SHA256, ECDSA-SHA256, RSA-OAEP, ECDH-ES + ConcatKDF + AES-KW
- Cross-implementation interop, tested live: a containerized **Holodeck B2B**
  counterparty exchanges a signed AS4 push for a signed NRR receipt;
  C14N/digests are verified against **xmlsec1**; AS2 S/MIME is exchanged in
  both directions with the **openssl** CLI; a **real production Peppol SMP
  signature** is verified against the real Peppol PKI; and `DedupStorage` runs
  the full conformance contract against a **real Redis**
- Reception Awareness / Non-Repudiation of Receipt, verified end to end
- OCSP and PKIX chain validation
- Mutual TLS on egress — a PEM client certificate and key, parsed once at
  construction, presented on every outbound connection
- Per-partner signer pinning, resolved from the claimed `eb:From` and checked
  against the verified WS-Security signer
- Multi-payload AS4, both directions — every `eb:PartInfo` attachment signed,
  verified, and independently compressed/encrypted
- ebMS3 Test Service (§5.2.2): a connectivity ping is acknowledged and reported
  as one, never delivered as a business document
- Peppol/CEF dynamic discovery — BDXL U-NAPTR participant lookup against the
  OpenPeppol SML zones, plus SMP 1.0 **and** 2.0 `ServiceMetadata`, with the
  DNS query behind a trait so DNSSEC validation stays your choice
- Peppol Business Message Envelope — `BusinessScope` with the reserved scope
  keys, and the Message Level Status seam that Network Policy 1.0.0 made
  mandatory

Known gaps:

- **No official conformance certificate.** The self-hosted counterparty loop
  passes, but the EC eDelivery conformance service tests a deployed access
  point, and this crate ships neither a binary nor a SUT Controller — see the
  [conformance guide](https://hupe1980.github.io/asx-rs/docs/conformance/).
- **No storage backends ship in-tree.** `DedupStorage`, `ReconciliationStorage`
  and `DurableAuditSink` are trait-defined; you supply the implementation —
  and `asx_rs::storage::conformance` is the suite that proves yours is durable
  and its `claim` atomic, rather than taking your word for it.

## Development

```bash
just ci             # fast pre-push subset: lint, check, test, feature matrix
just release-gate   # every mandatory gate (slow)
just --list         # all recipes
```

Recipes mirror [`.github/workflows/ci.yml`](.github/workflows/ci.yml) and
[`RELEASING.md`](RELEASING.md); when a gate changes in one, change it in the
other.

The documentation site is built with [Zola](https://www.getzola.org):

```bash
zola --root site serve   # http://127.0.0.1:1111
zola --root site build   # also fails on broken links and dangling anchors
```

## Versioning

Pre-1.0, breaking changes ship in minor versions. The
[changelog](CHANGELOG.md) separates **wire/crypto behaviour** — which can break
interoperability with a counterparty even when your code compiles unchanged —
from **API** changes, which break the build instead.

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your option.
