+++
title = "Getting started"
description = "Install asx-rs, pick feature flags, build a session, and send your first AS2 or AS4 message."
+++

## Installation

Because AS2 and AS4 are feature-gated, select at least one protocol:

```bash
# AS2 only
cargo add asx-rs --features as2

# AS4 only
cargo add asx-rs --features as4

# Both protocols, with the HTTP client (outbound) and server (inbound)
cargo add asx-rs --features as2,as4,client,server

# Relaxed interop for explicitly scoped partner exceptions
cargo add asx-rs --features as2,as4,interop-relaxed
```

`compression` and `async-ocsp` are on by default; disable defaults with
`--no-default-features` if you need a leaner build.

> **Note:** The default feature set is `["interop-strict", "async-ocsp"]`. Adding `asx-rs` without explicit features gives you only the shared infrastructure — no AS2 or AS4 protocol functions are compiled.

## Feature Flag Reference

| Feature | Enables | Default |
|---|---|---|
| `as2` | `as2::send_sync` / `as2::receive_sync`, async wrappers, MDN generation/parsing, MIC computation | No |
| `as4` | `as4::send_sync` / `as4::receive_push_sync`, pull APIs, P-Mode registry, Test Service, SBDH | No |
| `compression` | Zlib/GZIP payload compression via `flate2` | **Yes** |
| `async-ocsp` | Async OCSP responder fetching via reqwest | **Yes** |
| `interop-strict` | Strict interop mode as the default profile | **Yes** |
| `interop-relaxed` | Relaxed-mode controls for explicitly scoped partner exception policies | No |
| `client` | Async HTTP egress (`As2HttpTransport`, `As4HttpTransport` via reqwest) | No |
| `server` | Axum HTTP server routers (`as2_router`, `as4_router`) | No |
| `trace` | `tracing` instrumentation on send/receive paths | **Yes** |
| `prometheus` | Built-in Prometheus/OpenMetrics `MetricsSink` adapter | No |
| `opentelemetry` | OpenTelemetry metrics `MetricsSink` adapter | No |
| `testing` | `InsecureBypassAs4Verifier`, `MockAs4Endpoint` (with `builder().with_decryption_key_pem()` / `.with_receipt_signing_material()`), `EventBus::new_for_testing()`, `As4HttpTransport::new_for_localhost_testing()`, keypair generators, interop matrix executor | No |

## Tokio Runtime

`asx-rs` requires the Tokio async runtime. Add to `Cargo.toml`:

```toml
[dependencies]
tokio = { version = "1", features = ["rt-multi-thread", "macros"] }
```

## Regulated Startup Gate (Strict Production)

In regulated deployments, validate the runtime wiring before accepting traffic.
`StrictRuntimeBootstrap` checks every component in one place and hands back a
token; the token is the only way to mark a session as startup-validated.

```rust
use std::sync::Arc;

use asx_rs::as4::{As4ConversationOrderGate, As4PullStore};
use asx_rs::observability::EventBus;
use asx_rs::observability::audit_sink::DurableAuditSink;
use asx_rs::presets::{DeploymentTopology, StrictRuntimeBootstrap, StrictRuntimeBootstrapToken};
use asx_rs::storage::{DedupStorage, ReconciliationStorage};

fn bootstrap_strict_runtime(
    reconciliation: Arc<dyn ReconciliationStorage>,
    dedup: Arc<dyn DedupStorage>,
    audit_sink: Arc<dyn DurableAuditSink>,
    pull_store: &As4PullStore,
    conversation_gate: &As4ConversationOrderGate,
) -> asx_rs::Result<(EventBus, StrictRuntimeBootstrapToken)> {
    let bus = EventBus::new_regulated(1024, audit_sink)?;

    let token = StrictRuntimeBootstrap::new("startup")
        .event_bus(&bus)
        .reconciliation(reconciliation.as_ref())
        .dedup(dedup.as_ref())
        .topology(DeploymentTopology::Clustered)
        .as4_pull_store(pull_store)
        .as4_conversation_gate(conversation_gate)
        .validate()?;

    Ok((bus, token))
}
```

It fails closed when any strict-production invariant is missing: a best-effort
event bus, a missing durable audit sink, a dedup or reconciliation backend that
does not declare itself durable **and** cluster-safe, or a clustered AS4
deployment whose pull store or conversation gate is process-local.

Bind the token to each session once, then call the ordinary entry points:

```rust
# fn f(token: &asx_rs::presets::StrictRuntimeBootstrapToken, session: &asx_rs::core::SessionContext) {
let session = token.bind(session);
# let _ = session;
# }
```

In non-testing builds, strict-interop entry points refuse a session that carries
no token binding. The marker cannot be set any other way — there is no public
setter for it, because a marker any caller could raise would assert that
validation ran without it having run.

## Session Configuration (`SessionContextBuilder`)

`SessionContextBuilder` is the primary way to configure sessions. All convenience
setters auto-derive `key_id` from `partner_id` — no manual `CertHandle` construction
needed for common cases:

```rust
use asx_rs::core::SessionContextBuilder;

// Minimal trust-anchor-only session (receive path)
let session = SessionContextBuilder::new("sess-recv", "partner-gln")
    .with_trust_anchor_pem(partner_root_ca_pem)
    .with_fingerprint_sha256("aabb1122...")   // optional: pin exact partner cert
    .build()?;

// Send session: signing material + trust in one chain
let session = SessionContextBuilder::new("sess-send", "partner-gln")
    .with_signing_material(our_cert_pem, our_key_pem) // sets both cert + key together
    .with_trust_anchor_pem(partner_root_ca_pem)
    .build()?;

// Combine with per-request credential override (partial override merges with session)
// Only recipient_cert_pem is overridden; signing material falls back to session
let credentials = Some(As4SendCredentials {
    recipient_cert_pem: Some(partner_enc_cert),
    ..Default::default()  // signing_{cert,key}_pem = None → falls back to session
});
```

`CertHandle` is now a **pure data struct** (all fields `pub`) — struct update syntax works
from external crates with no restrictions:

```rust
let ch = asx_rs::core::CertHandle {
    trust_anchor_pems: vec![root_ca_pem],
    fingerprint_sha256: "aa...".into(),
    ..asx_rs::core::CertHandle::new("my-key")  // ← no E0451 compile error in 0.8
};
// Assign signing key without depending on `zeroize` directly:
ch.set_signing_key_pem(my_key_pem);
```

## Quick Start: AS2 Send

```rust
use asx_rs::as2::{send_sync, As2SendCredentials, As2SendPolicy, As2SendRequest};
use asx_rs::core::SessionContextBuilder;
use asx_rs::observability::EventBus;

fn main() -> asx_rs::Result<()> {
    // Fluent session builder — key_id auto-derived, signing material validated eagerly
    let session = SessionContextBuilder::new("sess-as2-1", "partner-acme")
        .with_signing_material(
            std::fs::read_to_string("sender-cert.pem")?,
            std::fs::read_to_string("sender-key.pem")?,
        )
        .with_trust_anchor_pem(std::fs::read_to_string("partner-root-ca.pem")?)
        .build()?;
    let bus = EventBus::new(64)?;

    let policy = As2SendPolicy { sign: true, encrypt: true, ..Default::default() };
    let creds = As2SendCredentials {
        // signing material is optional here — falls back to session when None
        recipient_cert_pem: Some(std::fs::read("partner-cert.pem")?),
        ..Default::default()
    };

    let output = send_sync(
        &session,
        &bus,
        As2SendRequest {
            message_id: "msg-001@example.com".to_string(),
            payload: b"ISA*...".to_vec(),
            policy,
            credentials: creds,
        },
    )?;
    // output.http_headers          — ready-to-send AS2 HTTP headers
    // output.mime.body             — MIME body bytes to POST
    // output.mime.content_type     — HTTP Content-Type header value
    // output.as_received_content_mic() — MIC string for MDN cross-check
    Ok(())
}
```

## Quick Start: AS4 Send

```rust
use asx_rs::as4::{send_sync, As4SendPolicyBuilder, As4SendRequest};
use asx_rs::core::SessionContextBuilder;
use asx_rs::observability::EventBus;

fn main() -> asx_rs::Result<()> {
    // Session carries signing material; no per-request credentials needed
    let session = SessionContextBuilder::new("sess-as4-1", "partner-b")
        .with_signing_material(
            std::fs::read_to_string("sender-cert.pem")?,
            std::fs::read_to_string("sender-key.pem")?,
        )
        .with_trust_anchor_pem(std::fs::read_to_string("partner-root-ca.pem")?)
        .build()?;
    let bus = EventBus::new(64)?;

    let (policy, creds) = As4SendPolicyBuilder::new()
        .signing_cert_pem(std::fs::read("sender-cert.pem")?)
        .signing_key_pem(std::fs::read("sender-key.pem")?)
        .build()?;

    let output = send_sync(
        &session,
        &bus,
        As4SendRequest {
            message_id: "uuid-001@example.com".to_string(),
            payload: b"<Order>...</Order>".to_vec(),
            policy,
            credentials: Some(creds),
            payload_filename: None,
        },
    )?;
    // output.soap_envelope.body — multipart/related bytes
    // output.http_content_type  — HTTP Content-Type for transport
    Ok(())
}
```

## Quick Start: AS2 Receive (Framework-Agnostic)

```rust
use asx_rs::as2::{receive_sync, CmsSmimeTrustVerifier};
use asx_rs::transport::ingress::{As2HttpIngress, as2_ingress_from_http};
use asx_rs::http::HttpRequest;
use asx_rs::core::SessionContext;

fn main() -> asx_rs::Result<()> {
    // Build a framework-agnostic HttpRequest (e.g., from your web framework)
    let http_req = HttpRequest { /* ... */ };
    let ingress = as2_ingress_from_http(http_req)?; // validates required headers

    let session = SessionContext::new("sess-as2-2", "partner-acme", "strict")?;
    let verifier = CmsSmimeTrustVerifier::default();
    let trusted = receive_sync(&session, ingress.body.to_vec(), &verifier)?;

    // trusted holds the cryptographically verified/decrypted domain payload.
    println!("payload bytes: {}", trusted.as_ref().len());
    Ok(())
}
```

## Quick Start: Axum HTTP Server (AS2)

Enable the `server` and `as2` features, then:

```rust
use asx_rs::transport::server::{as2_router, As2AxumHandler, HandlerOutcome};
use asx_rs::transport::ingress::As2HttpIngress;
use std::sync::Arc;

struct MyAs2Handler;

#[async_trait::async_trait]
impl As2AxumHandler for MyAs2Handler {
    async fn handle(&self, ingress: As2HttpIngress) -> HandlerOutcome {
        // process ingress.body, ingress.as2_from, ingress.as2_to, ingress.message_id, etc.
        HandlerOutcome::ok()
    }
}

#[tokio::main]
async fn main() {
    let handler = Arc::new(MyAs2Handler);
    let app = as2_router(handler, "/as2/receive");
    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
```

## End-to-End AS2: Send, Receive MDN, and Verify

This example shows the complete AS2 cycle: build a message, send it over HTTP,
receive the synchronous MDN from the partner, and verify the MIC.

```rust
use asx_rs::as2::{
    send_sync, receive_with_mdn_with_reliability,
    As2SendCredentials, As2SendPolicy, As2SendRequest,
    As2ReceiveMdnRequest, As2MdnMode, As2ReceivePolicy, CmsSmimeTrustVerifier,
};
use asx_rs::core::SessionContext;
use asx_rs::observability::{BackpressurePolicy, EventBus, EventEmissionMode};
use asx_rs::storage::{InMemoryReconciliationStorage, TtlDedupStorage};
use std::sync::Arc;

fn end_to_end_as2() -> asx_rs::Result<()> {
    // 1. Build a reusable session (one per trading-partner relationship).
    let session = SessionContext::new("sess-acme-prod", "partner-acme", "strict")?;
    let bus = EventBus::builder()
        .capacity(128)
        .emission_mode(EventEmissionMode::BestEffort)
        .build()?;

    // 2. Prepare credentials (load once; reuse across messages).
    let creds = As2SendCredentials {
        signing_cert_pem: Some(std::fs::read("sender-cert.pem")?),
        signing_key_pem:  Some(std::fs::read("sender-key.pem")?),
        recipient_cert_pem: Some(std::fs::read("partner-cert.pem")?),
        ..Default::default()
    };

    // 3. Build and sign/encrypt the AS2 message.
    let payload: Arc<[u8]> = b"ISA*00*...".to_vec().into();
    let msg_id = "msg-001@acme.example.com";
    let output = send_sync(
        &session,
        &bus,
        As2SendRequest {
            message_id: msg_id.to_string(),
            payload: payload.to_vec(),
            policy: As2SendPolicy { sign: true, encrypt: true, ..Default::default() },
            credentials: creds,
        },
    )?;
    // POST output.mime.body to the partner AS2 URL using output.mime.content_type
    // as the HTTP Content-Type header, plus the headers in output.http_headers.

    // 4. Receive the synchronous MDN bytes from the HTTP response body.
    //    In production use `As2HttpTransport` (feature = "client") or your HTTP client.
    let mdn_response_bytes: Vec<u8> = vec![/* raw MDN HTTP response body */];

    // 5. Verify the MDN and check the MIC matches.
    //    Use TtlDedupStorage / durable backends instead of in-memory in production.
    let dedup: Arc<dyn asx_rs::storage::DedupStorage> =
        Arc::new(TtlDedupStorage::new(std::time::Duration::from_secs(48 * 3600)));
    let reconciliation = InMemoryReconciliationStorage::new(1024);
    let verifier = CmsSmimeTrustVerifier::default();

    let mdn_result = receive_with_mdn_with_reliability(
        &session,
        &bus,
        As2ReceiveMdnRequest {
            payload: Arc::clone(&payload),
            mdn_payload: mdn_response_bytes.into(),
            mdn_mode: As2MdnMode::Synchronous,
            // output.as_received_content_mic() returns "base64==, sha-256" for cross-check
            expected_mic: Some(output.as_received_content_mic()),
            policy: As2ReceivePolicy::default(),
            original_message_id: Some(msg_id.to_string()),
        },
        &reconciliation,
        Arc::clone(&dedup),
        &verifier,
    )?;

    // mdn_result.outcome — SuccessConfirmed, Indeterminate, or AcceptedPendingVerification
    println!("AS2 message {} MDN outcome: {:?}", msg_id, mdn_result.outcome);

    // 6. Settle the dedup claim once the outcome is durably recorded. Use
    //    `abandon()` instead if recording it failed, so a retransmitted MDN is
    //    processed rather than swallowed as a duplicate.
    if let Some(claim) = mdn_result.dedup.into_claim() {
        claim.accept_blocking()?;
    }
    Ok(())
}
```

**Key points:**
- `output.as_received_content_mic()` returns the RFC 4130 MIC string — pass it to `expected_mic` so the MDN cross-check validates both digest value and algorithm.
- `receive_with_mdn_with_reliability` verifies the MDN signature, checks the MIC, emits audit events, and queues a `ReconciliationRequest` for indeterminate outcomes.
- The `session` is long-lived; recreating it per message wastes cert-validation work.
- `TtlDedupStorage` is in-memory: use a durable `DedupStorage` backend in production, and set the TTL to the replay window you need (48h per RFC 4130 §5.2.1)
- Deduplication is two-phase: settle the claim on `mdn_result.dedup` once the delivery outcome is durable — see [Reliability](@/docs/reliability.md#deduplication).

## Quick Start: AS4 Receive (Push)

```rust
use asx_rs::as4::{As4PushPolicy, As4ReceiveOutcome};
use asx_rs::transport::ingress::{As4HttpIngress, As4IngressReceivePushSyncRequest};
use asx_rs::core::SessionContext;
use asx_rs::observability::EventBus;
use asx_rs::storage::DedupStorage;
use std::sync::Arc;

fn receive_as4_push(
    ingress: As4HttpIngress,           // built from your HTTP framework's request
    dedup: Arc<dyn DedupStorage>,      // persistent dedup store (prevents replay)
    session: &SessionContext,
    bus: &EventBus,
) -> asx_rs::Result<()> {
    let outcome = ingress.receive_push_sync(As4IngressReceivePushSyncRequest {
        session,
        event_bus: bus,
        policy: As4PushPolicy::default(),
        dedup: Arc::clone(&dedup),
        // A signed message from an unpinned sender is refused; None uses the
        // session's single-partner pin.
        signer_pins: None,
        receipt_payload: None,
    })?;

    let (received, claim) = match outcome {
        // First sight: the claim is unsettled and is yours to resolve.
        As4ReceiveOutcome::FirstSeen { output, claim } => (output, claim),
        // Previously accepted — return a receipt without re-dispatching.
        As4ReceiveOutcome::Duplicate { .. } => return Ok(()),
        // A concurrent delivery holds the claim. Do NOT acknowledge: answer 503
        // so the sender retransmits once that attempt settles.
        _ => return Ok(()),
    };

    // received.payload — DomainReady<Arc<[u8]>>: verified, decrypted domain payload
    // received.user_message.message_id — ebMS3 MessageId (dedup-checked)
    // received.user_message.from_party_id() — primary sender party ID
    println!(
        "Received AS4 push: {} ({} bytes)",
        received.user_message.message_id,
        received.payload.as_ref().len(),
    );

    // Settle only after the payload is durably yours — persisted, queued, or
    // dead-lettered. On failure, `claim.abandon_blocking()` lets the sender's
    // retransmission be processed instead of answered as a duplicate.
    claim.accept_blocking()?;
    Ok(())
}
```

## Next Steps

- [Architecture](@/docs/architecture.md) — module map and design decisions
- [AS2 Protocol Reference](@/docs/as2.md) — send, receive, MDN, MIC, compression
- [AS4 Protocol Reference](@/docs/as4.md) — send, receive push/pull, WS-Security, P-Mode, SBDH
- [HTTP Transport](@/docs/transport.md) — client and server integration
- [Security Model](@/docs/security.md) — trust model, certificate handling, crypto algorithms
- [Reliability](@/docs/reliability.md) — dedup, reconciliation, retry
- [Persistence How-To](@/docs/persistence.md) — production persistence adapters for dedup/reconciliation/audit
- [Observability](@/docs/observability.md) — EventBus, audit events, backpressure, audit sinks
- [Interoperability](@/docs/interop.md) — profile stack, strict/relaxed modes
- [Testing](@/docs/testing.md) — test harness, fuzz testing, interop matrix
- [Release Process](https://github.com/hupe1980/asx-rs/blob/main/RELEASING.md) — quality gates, CI, checklist
