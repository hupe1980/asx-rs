+++
title = "Architecture"
description = "How asx-rs is layered: the transport boundary, wire format, protocol modules, and the type-state lifecycle that keeps unverified bytes away from application code."
+++

## Overview

`asx-rs` is a single-crate, async-native Rust library for the AS2 (RFC 4130) and AS4 (OASIS ebMS3 + eDelivery v1.15) EDI transport protocols. The design goal is protocol completeness with zero compromises on memory safety, streaming throughput, and async runtime compatibility.

## Module Map

```text
        inbound HTTP                                    outbound HTTP
              │                                               ▲
              ▼                                               │
   ┌──────────────────────┐                     ┌──────────────────────┐
   │ transport::ingress   │                     │ transport::egress    │
   │ framework-agnostic   │                     │ `client` · SSRF +    │
   │                      │                     │ pinned DNS           │
   └──────────┬───────────┘                     └──────────────────────┘
              ▼
   ┌──────────────────────┐   ┌──────────┐   ┌──────────────────────┐
   │ wire  bounded reads  │   │ http     │   │ interop              │
   │ content-type, limits │   │ headers  │   │ profile stack + floor│
   └──────────┬───────────┘   └──────────┘   └──────────────────────┘
              ▼
   ┌────────────────────── core ───────────────────────┐
   │ AsxError · SessionContext · CertHandle            │
   └──────────┬────────────────────────────┬───────────┘
              ▼                            ▼
   ┌──────────────────────┐   ┌──────────────────────────────────────┐
   │ crypto               │   │ lifecycle  (type-state)              │
   │ s/mime · wssec       │──▶│ Untrusted → Parsed → Verified →      │
   │ xmlenc · ocsp        │   │ Decrypted → DomainReady              │
   └──────────────────────┘   └──────────────┬───────────────────────┘
                                 ┌───────────┴───────────┐
                                 ▼                       ▼
                          ┌────────────┐          ┌────────────┐
                          │ as2        │          │ as4        │
                          └────────────┘          └────────────┘

   seams the embedder implements:
   storage · reliability · observability
```


| Module | Responsibility |
|---|---|
| `core` | Shared types, errors (`AsxError`), session context (`SessionContext`), interop mode |
| `wire` | Bounded I/O (`read_bounded_stream_into_memory_async`, `read_bounded_stream_into_handle_async`), content-type classification, HTTP header normalization, streaming frame limits |
| `http` | HTTP binding types (`HttpRequest`), header policy, governance |
| `transport` | Framework-agnostic ingress (`As2HttpIngress`, `As4HttpIngress`); async egress clients (`client` feature); axum server routers (`server` feature) |
| `crypto` | S/MIME, WS-Security XML signatures, XML encryption/decryption, OCSP, compression |
| `crypto/wssec` | XML Exclusive C14N, signature reference handling, WS-Security transforms, InclusiveNamespaces PrefixList |
| `reliability` | Delivery outcomes, retry classification (`RetryDecision`), idempotency-key derivation, dead-letter sink |
| `storage` | `DedupStorage` and `ReconciliationStorage` traits, in-memory implementations, and the [conformance suite](@/docs/persistence.md#conformance-kit-run-this-against-your-backend) an embedder runs against its own backend |
| `interop` | Profile stack (base → extension → override → partner overlay), `InteropMode` (`Strict`/`Relaxed`), exception policies |
| `observability` | `EventBus`, `AuditEvent`, `DurableAuditSink`, backpressure policy, metrics, and the incident-channel traits |
| `presets` | `StrictRuntimeBootstrap` — the regulated startup gate and the token it mints |
| `lifecycle` | Type-state progression: `UntrustedBytes` → `StructurallyParsed` → `CryptographicallyVerified` → `ContentDecrypted` → `DomainReady` |
| `as2` | AS2 MIME packaging, MIC computation, MDN generation/parsing, S/MIME crypto (behind `as2` feature) |
| `as4` | AS4 SOAP envelope, ebMS3 headers, WS-Security signing/verification, pull store, P-Mode registry, Test Service, SBDH (behind `as4` feature) |
| `sbdh` | Standard Business Document Header (SBDH) wrap/unwrap; Peppol-compatible |
| `send_pipeline` | Shared send validation and event emission helpers (internal) |

## Design Decisions

### Single crate, feature-gated

All protocol code lives in one crate to share the crypto, canonicalization, and session model without version skew. Feature flags (`as2`, `as4`, `client`, `server`, …) compile only what you use; neither protocol is on by default.

### Async-only public API

All I/O-facing functions are `async`. There is no blocking wrapper in the main crate. This eliminates the async/sync API split maintenance burden and ensures correct Tokio runtime behavior. Async-contended shared state uses `tokio::sync` primitives; read-heavy internal registries (e.g. the `EventBus` session-sender map) use `std::sync::RwLock` for low-overhead read-path access.

### Type-state lifecycle progression

Inbound messages progress through explicit type states (`UntrustedBytes` → `StructurallyParsed` → `CryptographicallyVerified` → `ContentDecrypted` → `DomainReady`). No stage may be skipped without an explicit policy decision recorded in an audit event. Parse success does not imply trust; trust is established at cryptographic verification only.

### Fail-closed security defaults

- An empty trust anchor set **fails closed** — PKIX chain validation is refused rather than skipped.
- Signature verification failure is propagated immediately; results are never discarded.
- An empty `cert_handle.fingerprint_sha256` disables fingerprint pinning (opt-in, not bypass-by-default).
- `InsecureBypassTrustVerifier` skips all cryptographic checks and is intended **exclusively** for testing.

### Layered profile stack

Interop behavior is governed by a four-layer profile stack:

```
base profile → extension profile → global override → partner overlay
```

Each layer can add, override, or restrict policy fields. The effective policy for a session is the result of deterministic resolution through all layers. A machine-readable snapshot (`EffectivePolicySnapshot`) can be serialized and compared across releases for regression detection.

### Bounded streaming

All inbound reads go through the bounded readers with a hard ceiling (default 256 MiB, configurable per session). Unbounded reads are not possible through the public API. The streaming crypto pipeline avoids materialising the full payload in memory before processing.

### Transport layer separation

The `transport` module is split into three independent layers:
- **Ingress** (`ingress.rs`): framework-agnostic header validation — usable without either `client` or `server` features.
- **Egress** (`egress.rs`, `client` feature): reqwest-based async HTTP clients.
- **Server** (`server.rs`, `server` feature): axum router builders with typed handler traits.

This means protocol logic never depends on a specific HTTP framework.

## Envelope Lifecycle

The type-state pattern in `lifecycle.rs` is the only lifecycle mechanism. Protocol functions (`asx_rs::as2::receive_sync`, `asx_rs::as4::receive_push_with_dedup_sync`) use it exclusively.

Allowed progression (forward-only):

```
UntrustedBytes<T>
  -> StructurallyParsed<T>
    -> CryptographicallyVerified<T>
      -> ContentDecrypted<T>
        -> DomainReady<T>
```

## Error Model

Every fallible function returns `Result<T, AsxError>`:

```rust
pub struct AsxError {
    pub code: ErrorCode,          // match on this
    pub message: String,          // for operators, never for matching
    pub context: Box<ErrorContext>,
}
```

`ErrorCode` is a closed enum — `ParseFailed`, `SecurityVerificationFailed`,
`DecryptionFailed`, `PolicyViolation`, `InteropViolation`,
`ReliabilityFailure`, `PayloadTooLarge`, `CertificateRevoked` and a few more.
It is load-bearing rather than decorative: ingress handlers map it to an HTTP
status, `RetryDecision` classifies on it, and the incident taxonomies group on
it. `ErrorContext` carries the `stage` plus optional `session_id`,
`partner_id` and `message_id` for correlation.

The context is boxed on purpose. The error variant's width is paid on the
success path too, so an inline `ErrorContext` made *every* `Result` in the
crate 120 bytes wide, `Result<()>` included. Boxing brings that to 40 while
`err.context.session_id` keeps working through `Deref`.

## Session Context

`SessionContext` is the operational boundary for a single partner exchange. It carries:
- Session/partner/profile identity (`session_id`, `partner_id`, `profile_name`)
- Certificate and trust material (`CertHandle` — signing material, trust anchors, OCSP material, optional fingerprint pin)
- Correlation scope metadata for end-to-end tracing
- Optional resolved effective-policy snapshot JSON and strict-runtime bootstrap validation marker

Sessions are created via `SessionContext::new()` or `SessionContext::builder(...)` and can be updated with explicit certificate-rotation and metadata APIs (`with_cert_handle`, `rotate_cert_handle`, `with_effective_policy_snapshot_json`, strict-runtime marker setters).
