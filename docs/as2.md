# AS2 Protocol Reference

Requires feature flag: `as2`

## Overview

AS2 (RFC 4130) support in `asx` is exposed through free functions in `asx_rs::as2`.

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
2. MIC is computed over the exact octet sequence `Content-Type: ...\r\n\r\n<payload>` (RFC 4130 section 7.3.1).
3. MIC canonicalization does not trim, normalize, or transfer-decode bytes before hashing; both `Content-Type` and payload bytes are hashed exactly as supplied to send/ingress paths (RFC 4130 §7.3.1 / §7.4.2 alignment).
4. Policy-controlled protocol events are emitted via `EventBus`.

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
let strict_session = asx_rs::presets::session_with_strict_runtime_bootstrap_token(
    "as2_receive_sync",
    &bootstrap_token,
    &session,
)?;

let received = asx_rs::as2::receive_sync(&strict_session, payload, verifier)?;
```

In non-testing builds, strict interop AS2 entry points fail closed unless the
session is startup-validated with
`asx_rs::presets::session_with_strict_runtime_bootstrap_token(...)`.

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

EventBus constructors are strict by default. Use fail-closed mode in regulated deployments and opt into best-effort explicitly via `EventBus::new_with_config_and_mode(..., EventEmissionMode::BestEffort)` only where transport progress must not depend on subscriber liveness.
