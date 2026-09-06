+++
title = "AS2 reference"
description = "AS2 (RFC 4130) in asx-rs: send and receive, S/MIME signing and encryption, MDN generation, and how the RFC 4130 section 7.3.1 MIC is computed."
+++

Requires feature flag: `as2`

## Overview

AS2 (RFC 4130) support in `asx-rs` is exposed through free functions in `asx_rs::as2`.

Primary flows:

1. Outbound send with optional compression, signing, and encryption.
2. Inbound receive with trust verification/decryption.
3. MDN generation and parse/classification.
4. Reliability and dedup integration for MDN-linked receive paths.

## Public Entry Points

### Send

```rust
pub fn send_sync(
    session: &SessionContext,
    event_bus: &EventBus,
    request: As2SendRequest,
) -> Result<As2SendOutput>
```

Async-safe wrapper for Tokio services:

```rust
pub async fn send_async(
    session: &SessionContext,
    event_bus: &EventBus,
    request: As2SendRequest,
) -> Result<As2SendOutput>
```

Behavior notes:

1. RFC 5402 order is enforced for compression-enabled messages: `compress -> sign -> encrypt`.
2. Compression produces a CMS `CompressedData` structure (RFC 5402 / RFC 3274, ZLIB),
   carried as `application/pkcs7-mime; smime-type=compressed-data` — not a bare gzip stream.
3. Policy-controlled protocol events are emitted via `EventBus`.

### MIC computation

The `Received-Content-MIC` a receiver returns in the MDN must digest exactly the
octets the sender digested, and RFC 4130 §7.3.1 makes that input depend on which
protection was applied:

| Message | MIC input |
|---|---|
| Signed (with or without encryption) | the **signed MIME entity** — headers, blank line, content |
| Encrypted but unsigned | the **decrypted MIME entity** — headers and content |
| Neither signed nor encrypted | the **content only**, with no MIME headers |

The last row is deliberate: unprotected messages pass through intermediaries
that reorder and rewrite headers, so including them would make the MIC
unreproducible.

Consequences worth knowing:

- `As2SendPolicy::payload_content_type` appears on the wire as the signed
  entity's `Content-Type`, so it is part of the MIC. Setting it to the payload's
  real media type (`application/edi-x12`, `application/edifact`, …) is required
  for the partner to compute the same value.
- Binary content (compressed or encrypted payloads) is transfer-encoded with
  `base64` before signing, per RFC 5751 §3.1.1 — MIME line-ending
  canonicalization would otherwise rewrite bytes inside the blob and break the
  signature. Text payloads keep `binary` transfer encoding.
- Nothing is trimmed, re-folded, or normalized before hashing; the entity is
  digested as transmitted.

### Receive (owned payload)

```rust
pub fn receive_sync(
    session: &SessionContext,
    payload: Vec<u8>,
    verifier: &dyn As2TrustVerifier,
) -> Result<DomainReady<Arc<[u8]>>>
```

Async-safe wrapper for Tokio services:

```rust
pub async fn receive_async(
    session: &SessionContext,
    payload: Vec<u8>,
    verifier: Arc<dyn As2TrustVerifier + Send + Sync>,
) -> Result<DomainReady<Arc<[u8]>>>
```

### Token-enforced strict runtime sessions

For regulated deployments that require explicit startup proof, bind validated
session context once and then use standard AS2 entry points:

```rust
let strict_session = bootstrap_token.bind(&session);

let received = asx_rs::as2::receive_sync(&strict_session, payload, verifier)?;
```

`bootstrap_token` comes from
[`StrictRuntimeBootstrap::validate`](@/docs/getting-started.md#regulated-startup-gate-strict-production).
In non-testing builds, strict-interop AS2 entry points refuse a session with no
token binding, and there is no other way to set the marker.

### Receive (streaming ingress)

```rust
pub async fn receive_stream<R: tokio::io::AsyncRead + Unpin>(
    session: &SessionContext,
    policy: &As2ReceivePolicy,
    reader: R,
    verifier: &dyn AsyncAs2TrustVerifier,
    limits: StreamLimits,
) -> Result<DomainReady<Arc<[u8]>>>
```

```rust
pub async fn receive_stream_with_metrics<R: tokio::io::AsyncRead + Unpin>(
    session: &SessionContext,
    policy: &As2ReceivePolicy,
    reader: R,
    verifier: &dyn AsyncAs2TrustVerifier,
    limits: StreamLimits,
) -> Result<(DomainReady<Arc<[u8]>>, StreamReadMetrics)>
```

### Receive + MDN + reliability

```rust
pub fn receive_with_mdn_with_reliability(
    session: &SessionContext,
    event_bus: &EventBus,
    request: As2ReceiveMdnRequest,
    reconciliation_hook: &dyn ReconciliationStorage,
    dedup_backend: &dyn DedupStorage,
    verifier: &dyn As2TrustVerifier,
) -> Result<As2ReceiveMdnOutput>
```

Borrowed variant:

```rust
pub fn receive_with_mdn_with_reliability_mdn_ref(
    session: &SessionContext,
    event_bus: &EventBus,
    request: As2ReceiveMdnRefRequest<'_>,
    reconciliation_hook: &dyn ReconciliationStorage,
    dedup_backend: &dyn DedupStorage,
    verifier: &dyn As2TrustVerifier,
) -> Result<As2ReceiveMdnOutput>
```

### MDN generation

```rust
pub fn generate_mdn(
    session: &SessionContext,
    event_bus: &EventBus,
    request: As2GenerateMdnRequest,
) -> Result<As2MdnOutput>
```

## Core Types

1. `As2SendPolicy`: outbound cryptographic/interop behavior.
2. `As2SendCredentials`: PEM signing/encryption material.
3. `As2SendOutput`: transport headers/body/MIC for HTTP send.
4. `As2ReceiveMdnRequest`: payload + MDN + policy input for reliability path.
5. `ParsedAs2Mdn`: parsed disposition/MIC/signature metadata.

## Interop Notes

1. Strict mode is the default profile.
2. Relaxed mode remains feature-gated (`interop-relaxed`) and should be used only with scoped, audit-visible exception policies.
3. Production deployments should keep strict mode unless exceptions are explicitly governed.

## Audit Events

AS2 flows emit protocol events through `EventBus` (for example: outbound prepared, MIC computed, message signed/encrypted, MDN received, duplicate detected).

`EventBus` is strict by default. Use `EventBus::new_regulated(..)` in regulated deployments; opt into best-effort explicitly via `EventBus::builder().emission_mode(EventEmissionMode::BestEffort)` only where transport progress must not depend on subscriber liveness.
