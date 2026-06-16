# Getting Started

## Installation

Add `asx-rs` to `Cargo.toml`. Because AS2 and AS4 are feature-gated, you must select at least one protocol:

```toml
[dependencies]
# AS2 only
asx-rs = { version = "0.3", features = ["as2", "async-ocsp"] }

# AS4 only
asx-rs = { version = "0.3", features = ["as4", "async-ocsp"] }

# Both protocols
asx-rs = { version = "0.3", features = ["as2", "as4", "async-ocsp"] }

# Both protocols with payload compression (RFC 5402)
asx-rs = { version = "0.3", features = ["as2", "as4", "compression", "async-ocsp"] }

# HTTP client (outbound) + server (inbound) with both protocols
asx-rs = { version = "0.3", features = ["as2", "as4", "client", "server", "async-ocsp"] }

# Relaxed interop for explicitly scoped partner exceptions
asx-rs = { version = "0.3", features = ["as2", "as4", "interop-relaxed", "async-ocsp"] }
```

> **Note:** The default feature set is `["interop-strict", "async-ocsp"]`. Adding `asx-rs` without explicit features gives you only the shared infrastructure — no AS2 or AS4 protocol functions are compiled.

## Feature Flag Reference

| Feature | Enables | Default |
|---|---|---|
| `as2` | `as2::send_sync` / `as2::receive_sync`, async wrappers, MDN generation/parsing, MIC computation | No |
| `as4` | `as4::send_sync` / `as4::receive_push_with_dedup_sync`, pull APIs, P-Mode registry, Test Service, SBDH | No |
| `compression` | Zlib/GZIP payload compression via `flate2` | No |
| `async-ocsp` | Async OCSP responder fetching via reqwest | **Yes** |
| `interop-strict` | Strict interop mode as the default profile | **Yes** |
| `interop-relaxed` | Relaxed-mode controls for explicitly scoped partner exception policies | No |
| `client` | Async HTTP egress (`As2HttpTransport`, `As4HttpTransport` via reqwest) | No |
| `server` | Axum 0.7 HTTP server routers (`as2_router`, `as4_router`) | No |
| `trace` | `tracing` instrumentation on send/receive paths | No |
| `postgres-storage` | PostgreSQL-backed durable, cluster-safe dedup/reconciliation backends | No |
| `testing` | Exposes `fixtures` and `matrix` test-scaffold modules | No |

## Tokio Runtime

`asx-rs` requires the Tokio async runtime. Add to `Cargo.toml`:

```toml
[dependencies]
tokio = { version = "1", features = ["rt-multi-thread", "macros"] }
```

## Regulated Startup Gate (Strict Production)

In regulated deployments, validate runtime wiring before accepting traffic:

```rust
use std::sync::Arc;

use asx_rs::presets::{
    DeploymentTopology,
    StrictRuntimeBootstrapToken,
    issue_strict_runtime_bootstrap_token_with_as4_topology,
    strict_production_event_bus,
};
use asx_rs::storage::{DedupStorage, ReconciliationStorage};
use asx_rs::as4::{As4ConversationOrderGate, As4PullStore};

fn bootstrap_strict_runtime(
    reconciliation: Arc<dyn ReconciliationStorage>,
    dedup: Arc<dyn DedupStorage>,
    audit_sink: Arc<dyn asx_rs::observability::audit_sink::DurableAuditSink>,
    pull_store: &As4PullStore,
    conversation_gate: &As4ConversationOrderGate,
) -> asx_rs::Result<asx_rs::observability::EventBus> {
    let bus = strict_production_event_bus(1024, audit_sink)?;

    let _token: StrictRuntimeBootstrapToken = issue_strict_runtime_bootstrap_token_with_as4_topology(
        "startup",
        &bus,
        reconciliation.as_ref(),
        dedup.as_ref(),
        DeploymentTopology::Clustered,
        Some(pull_store),
        Some(conversation_gate),
    )?;

    Ok(bus)
}
```

This fails closed when any strict-production invariant is missing (non-transactional event mode, missing durable audit sink, non-durable or non-cluster-safe reliability backends, or clustered AS4 startup with process-local pull/order coordination). In non-testing builds, strict interop entry points also fail closed unless startup validation is bound to the session with `asx_rs::presets::session_with_strict_runtime_bootstrap_token`.

Migration note: bind strict-runtime once per session with `session_with_strict_runtime_bootstrap_token(...)`, then call standard AS2/AS4 ingress helper methods.

## Quick Start: AS2 Send

```rust
use asx_rs::as2::{send_sync, As2SendCredentials, As2SendPolicy, As2SendRequest};
use asx_rs::core::SessionContext;
use asx_rs::observability::{BackpressurePolicy, EventBus, EventEmissionMode};

fn main() -> asx_rs::Result<()> {
    let session = SessionContext::new("sess-as2-1", "partner-acme", "strict")?;
    let bus = EventBus::new_with_config_and_mode(
        64,
        None,
        BackpressurePolicy::default(),
        EventEmissionMode::BestEffort,
    )?;

    let policy = As2SendPolicy { sign: true, encrypt: true, ..Default::default() };
    let creds = As2SendCredentials {
        signing_cert_pem: Some(std::fs::read("sender-cert.pem")?),
        signing_key_pem: Some(std::fs::read("sender-key.pem")?),
        recipient_cert_pem: Some(std::fs::read("partner-cert.pem")?),
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
use asx_rs::core::SessionContext;
use asx_rs::observability::{BackpressurePolicy, EventBus, EventEmissionMode};

fn main() -> asx_rs::Result<()> {
    let session = SessionContext::new("sess-as4-1", "partner-b", "strict")?;
    let bus = EventBus::new_with_config_and_mode(
        64,
        None,
        BackpressurePolicy::default(),
        EventEmissionMode::BestEffort,
    )?;

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
            credentials: creds,
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
use asx_rs::storage::{InMemoryDedupStorage, InMemoryReconciliationStorage};
use std::sync::Arc;

fn end_to_end_as2() -> asx_rs::Result<()> {
    // 1. Build a reusable session (one per trading-partner relationship).
    let session = SessionContext::new("sess-acme-prod", "partner-acme", "strict")?;
    let bus = EventBus::new_with_config_and_mode(
        128,
        None,
        BackpressurePolicy::default(),
        EventEmissionMode::BestEffort,
    )?;

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
    let dedup = InMemoryDedupStorage::default();
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
        &dedup,
        &verifier,
    )?;

    // mdn_result.outcome — SuccessConfirmed, Indeterminate, or AcceptedPendingVerification
    println!("AS2 message {} MDN outcome: {:?}", msg_id, mdn_result.outcome);
    Ok(())
}
```

**Key points:**
- `output.as_received_content_mic()` returns the RFC 4130 MIC string — pass it to `expected_mic` so the MDN cross-check validates both digest value and algorithm.
- `receive_with_mdn_with_reliability` verifies the MDN signature, checks the MIC, emits audit events, and queues a `ReconciliationRequest` for indeterminate outcomes.
- The `session` is long-lived; recreating it per message wastes cert-validation work.
- Use `TtlDedupStorage` (or a distributed backend) rather than `InMemoryDedupStorage` in production.

## Quick Start: AS4 Receive (Push)

```rust
use asx_rs::as4::As4PushPolicy;
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
    let received = ingress.receive_push_with_dedup_sync(As4IngressReceivePushSyncRequest {
        session,
        event_bus: bus,
        policy: As4PushPolicy::default(),
        dedup_backend: dedup.as_ref(),
        receipt_payload: None,
    })?;

    // received.payload — DomainReady<Arc<[u8]>>: verified, decrypted domain payload
    // received.user_message.message_id — ebMS3 MessageId (dedup-checked)
    // received.user_message.from_party_id() — primary sender party ID
    println!(
        "Received AS4 push: {} ({} bytes)",
        received.user_message.message_id,
        received.payload.as_ref().len(),
    );
    Ok(())
}
```

## Next Steps

- [Architecture](architecture.md) — module map and design decisions
- [AS2 Protocol Reference](as2.md) — send, receive, MDN, MIC, compression
- [AS4 Protocol Reference](as4.md) — send, receive push/pull, WS-Security, P-Mode, SBDH
- [HTTP Transport](transport.md) — client and server integration
- [Security Model](security.md) — trust model, certificate handling, crypto algorithms
- [Reliability](reliability.md) — dedup, reconciliation, retry
- [Persistence How-To](persistence-howto.md) — production persistence adapters for dedup/reconciliation/audit
- [Observability](observability.md) — EventBus, audit events, backpressure, audit sinks
- [Interoperability](interop.md) — profile stack, strict/relaxed modes
- [Testing](testing.md) — test harness, fuzz testing, interop matrix
- [Release Process](release.md) — quality gates, CI, checklist
