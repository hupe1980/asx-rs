# 📦 asx-rs

**Async-native, memory-safe AS2 + AS4 EDI transport library for Rust.**

`asx-rs` implements the [AS2 (RFC 4130)](https://www.rfc-editor.org/rfc/rfc4130) and
[AS4 (OASIS ebMS3 + eDelivery)](https://docs.oasis-open.org/ebxml-msg/ebms/v3.0/profiles/AS4-profile/v1.0/)
protocols — the wire formats used by PEPPOL, CEF eDelivery, BDEW, and tens of thousands of
EDI trading partner connections worldwide.

---

## ✨ Features

### 📨 AS2 (RFC 4130 / RFC 5751)
- Send and receive signed payloads (CMS/S/MIME, RSA-SHA256)
- Synchronous and asynchronous MDN (Message Disposition Notification)
- MIC computation for end-to-end integrity verification
- Payload compression (RFC 5402 / zlib, `compression` feature)
- Configurable interop mode: strict vs. relaxed for legacy partners
- Retry classification (`SuccessConfirmed` / `Indeterminate` / `AcceptedPendingVerification`)

### 📬 AS4 (ebMS3 + OASIS eDelivery AS4 v1.15)
- One-Way/Push send and receive (SOAP 1.1 and 1.2)
- One-Way/Pull with bounded in-memory pull store per MPC partition
- **WS-Security XMLDSig signing** — RSA-SHA256 *and* **ECDSA-SHA256**; algorithm is
  auto-detected from the signing certificate key type. Works with NIST P-256/P-384/P-521
  and BSI BrainpoolP256r1/P384r1 (required by BDEW AS4-Profil §2.2.6.2.1 / BSI TR-03116-3 §9.1).
- **XML Encryption (XMLenc11)** — auto-dispatches on recipient certificate key type:
  - **RSA recipient** → RSA-OAEP (SHA-256/MGF1-SHA-256) — PEPPOL / CEF eDelivery
  - **EC recipient** → ECDH-ES + ConcatKDF (NIST SP 800-56A §5.8.1) + AES-128 Key Wrap
    (RFC 3394) — BDEW AS4-Profil §2.2.6.2.2 / BSI TR-03116-3 §9.2
- `X509PKIPathv1` BST token type (`WsSecOutboundKeyInfoProfile::X509PKIPathv1`)
- `require_encrypted_inbound` policy field — rejects unencrypted push messages at the policy
  layer (symmetric to `require_signed_push`)
- Streaming receive path with bounded memory; conversation-ordered delivery gate
- P-Mode registry for per-partner MEP/security configuration
- SBDH 1.3 envelope wrap/unwrap for PEPPOL and CEF eDelivery

### 🔒 Security & Reliability
- **Type-state lifecycle machine** — compiler enforces `UntrustedBytes → StructurallyParsed
  → CryptographicallyVerified → ContentDecrypted → DomainReady`; payloads cannot reach
  application code without every gate passing
- OCSP stapling + responder-based revocation checking (`async-ocsp` feature)
- PKIX certificate chain validation (fail-closed on empty trust store)
- `TtlDedupStorage` / `BoundedFifoDedupStorage` prevents replay attacks
- Reconciliation hooks for async delivery confirmation

### 🌐 HTTP Transport
- Axum server integration (`server` feature) — drop-in `Router` for AS2 and AS4 ingress
- Async HTTP egress via `reqwest` (`client` feature)
- Inbound endpoint governance against unexpected sources

### 🔍 Observability
- `EventBus` with fan-out broadcast and ordered mpsc audit channel
- `DurableAuditSink` trait for pluggable persistent audit backends
- `EventBusMetrics` with lock-free `AtomicU64` counters
- Optional Prometheus/OpenMetrics sink (`prometheus` feature)

### 🧩 Interop
- Profile stacking with regional packs and per-partner overlays
- `interop-strict` (default) and `interop-relaxed` feature-gated modes
- Exception policies (`InteropExceptionPolicy`) for well-known deviations

### 🧪 Testing (`testing` feature — never enable in production)
- **`InsecureBypassAs4Verifier`** — skips all WS-Security verification; parity with
  `InsecureBypassTrustVerifier` on the AS2 side
- **`MockAs4Endpoint`** (`testing + server`) — local HTTP AS4 server that accepts any push,
  records messages in an async channel, and returns synchronous AS4 receipts; no BDEW WIRK
  or PEPPOL test PKI certificates required
- **`DurableInMemoryDedupBackend`** — in-memory dedup with `is_durable() = true`; passes
  the strict durable-backend guard without a real persistent store
- **`generate_self_signed_ec_keypair(cn, curve)`** — self-signed EC cert+key (P-256 through
  BrainpoolP512r1); no openssl/rcgen dev-dependency needed in downstream crates
- **`generate_self_signed_rsa_keypair(cn, bits)`** — same for RSA
- **`verifier_seal`** — re-export of the `As4Verifier` sealed trait; allows downstream
  crates to write custom verifiers (recording, fault-injection, etc.)

---

## 🚀 Quick Start

```toml
[dependencies]
# AS4 — PEPPOL / CEF eDelivery (RSA) or BDEW (EC/ECDH-ES) — same code, key type decides
asx-rs = { version = "0.7", features = ["as4", "client", "server", "async-ocsp"] }

# AS2 + AS4 with compression
asx-rs = { version = "0.7", features = ["as2", "as4", "compression", "client", "server", "async-ocsp"] }

[dev-dependencies]
# Testing without PKI certificates (MockAs4Endpoint, bypass verifier, keypair generators)
asx-rs = { version = "0.7", features = ["as4", "testing", "server"] }
```

> `as2` and `as4` are **not** in the default feature set — add them explicitly.
> The `testing` feature is **compile-error-guarded** against release profile builds.

---

## 📖 Examples

### AS4 — Send a signed push message

The signing algorithm is chosen automatically from the key type — no configuration needed:
- RSA certificate → RSA-SHA256 (PEPPOL / CEF eDelivery)
- EC certificate (P-256, BrainpoolP256r1, …) → ECDSA-SHA256 (BDEW, BSI TR-03116-3 §9.1)

```rust
use asx_rs::as4::{send_async, As4SendPolicyBuilder, As4SendRequest};
use asx_rs::core::SessionContext;
use asx_rs::observability::EventBus;

// RSA or EC signing key — auto-detected:
let (policy, creds) = As4SendPolicyBuilder::new()
    .action("urn:bdew:as4:service:UTILMD")
    .service("urn:bdew:as4:service", "")
    .signing_cert_pem(my_signing_cert_pem)     // RSA or EC
    .signing_key_pem(my_signing_key_pem)
    .recipient_cert_pem(partner_enc_cert_pem)  // RSA → RSA-OAEP; EC → ECDH-ES
    .encrypt(true)
    .build()?;

let session = SessionContext::new("sess-001", "partner-gln", "strict")?;
let bus = EventBus::new(1024)?;

let output = send_async(
    &session, &bus,
    As4SendRequest {
        message_id: "urn:uuid:abc123@my-host".into(),
        payload: edifact_bytes,
        policy,
        credentials: Some(creds),
        payload_filename: None,
    },
).await?;
// output.soap_envelope.body  → multipart/related bytes to POST
// output.http_content_type   → HTTP Content-Type header value
```

### AS4 — Receive push with encryption enforcement

```rust
use asx_rs::as4::{receive_push_with_dedup_async, As4PushPolicyBuilder, As4ReceivePushRequest};
use std::sync::Arc;

let policy = As4PushPolicyBuilder::new()
    .inbound_decryption_key_pem(my_ec_or_rsa_private_key_pem)
    .require_encrypted_inbound(true)   // fail-closed: reject any unencrypted message
    .build()?;

let outcome = receive_push_with_dedup_async(
    &session, &bus,
    As4ReceivePushRequest {
        http_content_type,
        payload,
        receipt_payload: None,
        policy,
        authenticated_sender_scope: None,
    },
    dedup_backend,
).await?;
```

### AS4 — Testing without PKI certificates

```rust
use asx_rs::as4::mock_endpoint::MockAs4Endpoint;
use tokio::time::{timeout, Duration};

// Bind to a random port — no cert, no WIRK, no PEPPOL test PKI needed
let endpoint = MockAs4Endpoint::bind("127.0.0.1:0").await?;
let url = endpoint.local_url(); // "http://127.0.0.1:PORT/as4/inbox"

// Send an AS4 message to `url` via any client library...

let msg = timeout(Duration::from_secs(5), endpoint.next_message())
    .await??;
assert_eq!(msg.action, "urn:bdew:as4:service:UTILMD");
assert!(!msg.payload.is_empty());
```

### AS4 — Generate EC or RSA test keypairs

```rust
use asx_rs::fixtures::{EcCurve, generate_self_signed_ec_keypair, generate_self_signed_rsa_keypair};

// BrainpoolP256r1 — required by BDEW AS4-Profil §2.2.6.2.1
let (cert_pem, key_pem) = generate_self_signed_ec_keypair("test-ap", EcCurve::BrainpoolP256r1);

// P-256 — standard for PEPPOL Access Points
let (cert_pem, key_pem) = generate_self_signed_ec_keypair("peppol-ap", EcCurve::P256);

// RSA-2048 — classic PEPPOL style
let (cert_pem, key_pem) = generate_self_signed_rsa_keypair("rsa-ap", 2048);
```

### AS4 — Custom verifier (testing feature)

```rust
use asx_rs::as4::{As4Verifier, verifier_seal, types::As4PushPolicy};
use asx_rs::core::{Result, SessionContext};

struct RecordingVerifier {
    calls: std::sync::atomic::AtomicUsize,
}
impl verifier_seal::Sealed for RecordingVerifier {}
impl As4Verifier for RecordingVerifier {
    fn verify_security(
        &self, _session: &SessionContext, _policy: &As4PushPolicy,
        _soap_xml: &str, _soap_doc: &roxmltree::Document<'_>,
        _message_id: &str, _external_reference: Option<(&str, &[u8])>,
    ) -> Result<()> {
        self.calls.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Ok(())
    }
}
```

### AS2 — Send a signed message

```rust
use asx_rs::as2::{send_async, As2SendCredentials, As2SendPolicy, As2SendRequest};
use asx_rs::core::SessionContext;
use asx_rs::observability::EventBus;

let policy = As2SendPolicy {
    sign: true, encrypt: false, compress: false,
    as2_from_id: "my-company".into(),
    ..Default::default()
};
let creds = As2SendCredentials {
    signing_cert_pem: Some(std::fs::read("my-cert.pem")?),
    signing_key_pem: Some(std::fs::read("my-key.pem")?),
    ..Default::default()
};
let session = SessionContext::new("sess-001", "partner-a", "strict")?;
let bus = EventBus::new(1024)?;
let output = send_async(
    &session, &bus,
    As2SendRequest {
        message_id: "msg-001@example.com".into(),
        payload: b"<Invoice/>".to_vec(),
        policy,
        credentials: creds,
    },
).await?;
```

### Strict production startup

```rust
use asx_rs::presets::{
    DeploymentTopology, issue_strict_runtime_bootstrap_token_with_as4_topology,
    strict_production_event_bus,
};
use asx_rs::as4::{As4ConversationOrderGate, As4PullStore};
use std::sync::Arc;

let bus = strict_production_event_bus(1024, durable_audit_sink)?;
let _token = issue_strict_runtime_bootstrap_token_with_as4_topology(
    "startup", &bus,
    reconciliation.as_ref(), dedup.as_ref(),
    DeploymentTopology::Clustered,
    Some(pull_store), Some(conversation_gate),
)?;
// _token must be passed to session_with_strict_runtime_bootstrap_token()
// before any protocol entry point is called
```

### SBDH — PEPPOL / CEF eDelivery

```rust
use asx_rs::sbdh::{StandardBusinessDocument, SbdhHeader, SbdhParty, SbdhDocumentIdentification};

let wrapped = StandardBusinessDocument {
    header: SbdhHeader {
        header_version: "1.0".into(),
        sender:   SbdhParty { identifier: "0007:9876543210987".into(), authority: "iso6523-actorid-upis".into() },
        receiver: SbdhParty { identifier: "0007:1234567890123".into(), authority: "iso6523-actorid-upis".into() },
        document_identification: SbdhDocumentIdentification {
            standard: "urn:oasis:names:specification:ubl:schema:xsd:Invoice-2".into(),
            type_version: "2.1".into(),
            instance_identifier: "urn:uuid:550e8400-e29b-41d4-a716-446655440000".into(),
            r#type: "Invoice".into(),
            multiple_type: false,
            creation_date_and_time: "2026-01-01T12:00:00+00:00".into(),
        },
    },
    payload: invoice_xml_bytes,
}.wrap()?;
```

---

## 🎛️ Feature Flags

| Flag | Enables | Default |
|------|---------|---------|
| `as2` | AS2 send/receive (`as2::send_sync/async`, `as2::receive_sync/async`) | ❌ |
| `as4` | AS4 send/receive, pull store, WS-Security, ECDH-ES + ECDSA support | ❌ |
| `client` | HTTP egress via `reqwest` | ❌ |
| `server` | Axum router integration (`as2_router`, `as4_router`) | ❌ |
| `compression` | Zlib/GZIP payload compression (RFC 5402) | ✅ |
| `async-ocsp` | Async OCSP responder fetching | ✅ |
| `interop-strict` | Strict interop mode as compile-time default | ✅ |
| `interop-relaxed` | Relaxed mode helpers for legacy partners | ❌ |
| `trace` | `tracing` instrumentation on hot paths | ❌ |
| `prometheus` | Built-in Prometheus/OpenMetrics `MetricsSink` | ❌ |
| `postgres-storage` | PostgreSQL-backed durable cluster-safe storage | ❌ |
| `testing` | `InsecureBypassAs4Verifier`, `DurableInMemoryDedupBackend`, keypair generators, `verifier_seal`, interop matrix executor | ❌ |
| `testing + server` | Also: `MockAs4Endpoint` | ❌ |

> **Security:** The `testing` feature triggers a `compile_error!` in release profile builds.
> It must never appear in production binaries.

---

## 🏗️ Architecture

```
asx-rs
├── as2/            AS2 send, receive, MDN handling
├── as4/            AS4 push/pull, P-Mode registry, pull store, conversation gate
│   ├── pmode.rs      P-Mode registry + resolution
│   ├── parser.rs     ebMS3 UserMessage XML parser
│   ├── pull_store/   Bounded in-memory pull queue (per-MPC)
│   └── mock_endpoint/ In-process test endpoint (testing + server)
├── crypto/
│   ├── as2_smime     CMS/S/MIME signing + verification
│   ├── wssec/        WS-Security (XMLDSig, XMLenc11, OCSP, Exc-C14N)
│   │   └── xmlenc    AES-GCM + (RSA-OAEP | ECDH-ES + ConcatKDF + AES-KW)
│   └── soap_builder  SOAP envelope construction
├── transport/
│   ├── ingress       HTTP request normalisation + validation
│   ├── egress        HTTP send with endpoint governance
│   └── server        Axum router builders (server feature)
├── lifecycle         Type-state trust transition machine
├── reliability       Retry classification, dedup, reconciliation
├── storage/          DedupStorage + ReconciliationStorage traits + in-memory impls
├── observability/    EventBus, audit sink, back-pressure policy
├── interop           Profile stacks, regional packs, exception policies
├── sbdh              UN/CEFACT SBDH 1.3 wrap/unwrap
├── wire              Bounded stream reading, MIME utilities
└── core              Error types, SessionContext, shared utilities
```

### 🔐 Trust lifecycle

```
UntrustedBytes
    │  structural parse (MIME / SOAP envelope)
    ▼
StructurallyParsed
    │  cryptographic verify (S/MIME or XMLDSig)
    ▼
CryptographicallyVerified
    │  decrypt (S/MIME EnvelopedData or XMLenc11)
    ▼
ContentDecrypted
    │  dedup check + domain validation
    ▼
DomainReady  ← your application code starts here
```

### 🔑 XML Encryption: automatic key transport selection

`encrypt_payload_xmlenc` inspects the recipient certificate's key type at call time:

| Recipient cert key | Key transport | Key reference | Profiles |
|---|---|---|---|
| RSA | RSA-OAEP (SHA-256 / MGF1-SHA-256) | `BinarySecurityToken` | PEPPOL, CEF eDelivery |
| EC (any named curve) | ECDH-ES ephemeral + ConcatKDF (NIST SP 800-56A) + AES-128-KW (RFC 3394) | `X509SKI` | BDEW AS4-Profil §2.2.6.2.2, BSI TR-03116-3 §9.2 |

No configuration knob is needed — pass the recipient's certificate and the right algorithm
follows from the key type.

---

## 🔒 Security Notes

- **`InsecureBypassAs4Verifier` / `InsecureBypassTrustVerifier`** bypass all cryptographic
  checks. They are strictly limited to the `testing` feature, which is blocked in release
  builds via `compile_error!`.
- PKIX chain validation is **fail-closed**: an empty `trust_anchor_pems` store with
  `require_chain_validation = true` rejects every certificate.
- OCSP is **disabled by default** (`OcspMode::Disabled`). Set
  `OcspMode::ResponderOnly` or `OcspMode::StapledAndResponder` in production.
- Outbound HTTP egress validates URL scheme and blocks private / link-local targets.

---

## 📊 Status

`asx-rs` is **beta quality**. Core AS2 and AS4 push/pull flows are implemented, tested
(887+ tests across unit + integration suites), and exercised in production integrations.

- ✅ AS2 send/receive (signed, encrypted, compressed, sync + async)
- ✅ AS4 push send/receive (signed, encrypted, dedup, fragment reassembly)
- ✅ AS4 pull (with reliability classification)
- ✅ WS-Security (RSA-SHA256, ECDSA-SHA256, ECDH-ES + ConcatKDF + AES-KW, XMLenc11)
- ✅ OCSP + PKIX chain validation
- ✅ Strict-mode production validation gate
- ✅ Comprehensive testing infrastructure (bypass verifier, mock endpoint, keypair generators)
- ⚠️  Persistent storage backends (dedup/reconciliation) are trait-defined but not shipped
  in-tree; deployers provide their own Redis/PostgreSQL/DynamoDB implementations.

---

## 📜 License

Licensed under either of:

- [MIT License](./LICENSE-MIT)
- [Apache License, Version 2.0](./LICENSE-APACHE)

at your option.


---

## ✨ Features

### 📨 AS2 (RFC 4130 / RFC 5751)
- Send and receive signed payloads (CMS/S/MIME, RSA-SHA256)
- Synchronous and asynchronous MDN (Message Disposition Notification)
- MIC computation for end-to-end integrity verification
- Payload compression (RFC 5402 / zlib, enabled by default via `compression`)
- Configurable interop mode: strict vs. relaxed for legacy partners
- Retry classification (`SuccessConfirmed` / `Indeterminate` / `AcceptedPendingVerification`)

### 📬 AS4 (ebMS3 + OASIS eDelivery)
- One-Way/Push send and receive
- One-Way/Pull with bounded in-memory pull store per MPC partition
- WS-Security XMLDSig signing (RSA-SHA256, Exc-C14N) and verification
- XML encryption / decryption (XMLenc11 AES-GCM + RSA-OAEP)
- Streaming receive path with bounded memory
- P-Mode registry for per-partner MEP/security configuration
- SBDH 1.3 envelope wrap/unwrap for PEPPOL and CEF eDelivery

### 🔒 Security & Reliability
- **Type-state lifecycle machine** — compiler enforces the full trust chain: `UntrustedBytes → StructurallyParsed → CryptographicallyVerified → ContentDecrypted → DomainReady`. Payload bytes cannot reach application code without every gate passing.
- OCSP stapling + responder-based revocation checking (`async-ocsp` feature)
- PKIX certificate chain validation (fail-closed on empty trust store)
- Dedup storage (`InMemoryDedupStorage`, `TtlDedupStorage`) prevents replay
- Reconciliation hooks for async delivery confirmation

### 🌐 HTTP Transport
- Axum server integration (`server` feature) — drop-in `Router` for AS2 and AS4 ingress
- Async HTTP egress via `reqwest` (`client` feature)
- Inbound endpoint governance (`HttpEndpointPolicy`) against unexpected sources

### 🔍 Observability
- `EventBus` with fan-out broadcast and ordered mpsc audit channel
- `DurableAuditSink` trait for pluggable audit backends
- Configurable back-pressure policy (`BackpressurePolicy`)
- `EventBusMetrics` with lock-free `AtomicU64` counters
- Optional built-in Prometheus/OpenMetrics text sink (`prometheus` feature)

### 🧩 Interop
- Profile stacking with regional packs and per-partner overlays
- `interop-strict` (default) and `interop-relaxed` feature-gated modes
- Exception policies (`InteropExceptionPolicy`) for well-known deviations
- Interop matrix executor (`testing` feature) — built-in fixture-based conformance runner

---

## 🚀 Quick Start

Add to `Cargo.toml`:

```toml
[dependencies]
# AS2 client + server with OCSP
asx-rs = { version = "0.7", features = ["as2", "client", "server", "async-ocsp"] }

# AS4 only
asx-rs = { version = "0.7", features = ["as4", "client", "server", "async-ocsp"] }

# Both protocols with compression (default)
asx-rs = { version = "0.7", features = ["as2", "as4", "compression", "client", "server", "async-ocsp"] }
```

> `as2` and `as4` are **not** enabled by default — add them explicitly.

---

## 📖 Examples

### AS2 — Send a signed message

```rust
use asx_rs::as2::{send_sync, As2SendCredentials, As2SendPolicy, As2SendRequest};
use asx_rs::core::SessionContext;
use asx_rs::observability::{BackpressurePolicy, EventBus, EventEmissionMode};

let policy = As2SendPolicy {
    sign: true,
    encrypt: false,
    compress: false,
    as2_from_id: "my-company".into(),
    ..Default::default()
};

let creds = As2SendCredentials {
    signing_cert_pem: Some(std::fs::read("my-cert.pem")?),
    signing_key_pem: Some(std::fs::read("my-key.pem")?),
    ..Default::default()
};

let session = SessionContext::new("sess-001", "partner-a", "strict")?;
let bus = EventBus::new_with_config_and_mode(
    1024,
    None,
    BackpressurePolicy::default(),
    EventEmissionMode::BestEffort,
)?;
let output = send_sync(
    &session,
    &bus,
    As2SendRequest {
        message_id: "msg-001@example.com".to_string(),
        payload: b"<Invoice/>".to_vec(),
        policy,
        credentials: creds,
    },
)?;
// output.mime.body — body bytes to POST to partner's AS2 URL
// output.mime.content_type — HTTP Content-Type header value
// output.http_headers — required AS2 HTTP headers (AS2-From, AS2-To, etc.)
```

### AS2 — Receive and verify

```rust
use asx_rs::as2::{receive_sync, CmsSmimeTrustVerifier};
use asx_rs::core::SessionContext;

let session = SessionContext::new("sess-002", "partner-a", "strict")?;
let verifier = CmsSmimeTrustVerifier;
let trusted = receive_sync(&session, raw_http_body.to_vec(), &verifier)?;

println!("payload bytes: {}", trusted.as_ref().len());
```

### AS4 — Send a push message

```rust
use asx_rs::as4::{send_sync, As4SendPolicyBuilder, As4SendRequest};
use asx_rs::core::SessionContext;
use asx_rs::observability::{BackpressurePolicy, EventBus, EventEmissionMode};

let (policy, creds) = As4SendPolicyBuilder::new()
    .signing_cert_pem(signing_cert_pem)
    .signing_key_pem(signing_key_pem)
    .build()?;
let session = SessionContext::new("sess-003", "partner-a", "strict")?;
let bus = EventBus::new_with_config_and_mode(
    1024,
    None,
    BackpressurePolicy::default(),
    EventEmissionMode::BestEffort,
)?;

let output = send_sync(
    &session,
    &bus,
    As4SendRequest {
        message_id: "msg-001@example.com".to_string(),
        payload: b"<Invoice/>".to_vec(),
        policy,
        credentials: creds,
        payload_filename: None,
    },
)?;
// output.soap_envelope.body -> multipart/related bytes ready to POST
```

### AS4 — Axum server (ingress)

```rust
use std::sync::Arc;
use axum::Router;
use async_trait::async_trait;
use asx_rs::transport::server::{As4AxumHandler, as4_router, HandlerOutcome};
use asx_rs::transport::As4HttpIngress;

struct MyAs4Handler;

#[async_trait]
impl As4AxumHandler for MyAs4Handler {
    async fn handle(&self, ingress: As4HttpIngress) -> HandlerOutcome {
        // Feed ingress.body into asx_rs::as4::receive_push_with_dedup_sync(…)
        HandlerOutcome::ok()
    }
}

#[tokio::main]
async fn main() {
    let app: Router = as4_router(Arc::new(MyAs4Handler), "/as4/inbox");
    let listener = tokio::net::TcpListener::bind("0.0.0.0:4080").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
```

### Strict production startup validation

```rust
use std::sync::Arc;

use asx_rs::presets::{
    DeploymentTopology,
    StrictRuntimeBootstrapToken,
    issue_strict_runtime_bootstrap_token_with_as4_topology,
    strict_production_event_bus,
};
use asx_rs::as4::{As4ConversationOrderGate, As4PullStore};
use asx_rs::storage::{DedupStorage, ReconciliationStorage};

fn strict_runtime_bootstrap(
    reconciliation: Arc<dyn ReconciliationStorage>,
    dedup: Arc<dyn DedupStorage>,
    audit_sink: Arc<dyn asx_rs::observability::audit_sink::DurableAuditSink>,
    pull_store: &As4PullStore,
    conversation_gate: &As4ConversationOrderGate,
) -> asx_rs::Result<asx_rs::observability::EventBus> {
    let bus = strict_production_event_bus(1024, audit_sink)?;

    // Fail closed before serving traffic if strict invariants are not met.
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

In non-testing builds, strict interop protocol entry points fail closed unless
startup validation is bound to the session by explicitly applying
`asx_rs::presets::session_with_strict_runtime_bootstrap_token(...)`.

For AS2 HTTP server flows, bind a strict session once with
`session_with_strict_runtime_bootstrap_token(...)` and then call
`As2HttpIngress::receive_and_generate_mdn(...)` or
`As2HttpIngress::receive_and_generate_mdn_with_signing(...)`.

For AS4 HTTP server flows, bind a strict session once with
`session_with_strict_runtime_bootstrap_token(...)` and then call
`As4HttpIngress::receive_push_with_dedup_sync(...)` with an optional receipt payload.

### SBDH — PEPPOL / CEF eDelivery envelope

```rust
use asx_rs::sbdh::{StandardBusinessDocument, SbdhHeader, SbdhParty, SbdhDocumentIdentification};

let doc = StandardBusinessDocument {
    header: SbdhHeader {
        header_version: "1.0".into(),
        sender:   SbdhParty { identifier: "0007:9876543210987".into(), authority: "iso6523-actorid-upis".into() },
        receiver: SbdhParty { identifier: "0007:1234567890123".into(), authority: "iso6523-actorid-upis".into() },
        document_identification: SbdhDocumentIdentification {
            standard: "urn:oasis:names:specification:ubl:schema:xsd:Invoice-2".into(),
            type_version: "2.1".into(),
            instance_identifier: "urn:uuid:550e8400-e29b-41d4-a716-446655440000".into(),
            r#type: "Invoice".into(),
            multiple_type: false,
            creation_date_and_time: "2026-01-01T12:00:00+00:00".into(),
        },
    },
    payload: invoice_xml_bytes,
};

let wrapped = doc.wrap()?;
// wrapped → send via AS4 push to PEPPOL access point
```

---

## 🎛️ Feature Flags

| Flag | Enables | Default |
|------|---------|---------|
| `as2` | AS2 send/receive free functions (`as2::send_sync`, `as2::receive_sync`) | ❌ |
| `as4` | AS4 send/receive free functions (`as4::send_sync`, `as4::receive_push_with_dedup_sync`) and `As4PullStore` | ❌ |
| `client` | HTTP egress via `reqwest` (`As2HttpTransport`, `As4HttpTransport`) | ❌ |
| `server` | Axum router integration (`as2_router`, `as4_router`) | ❌ |
| `compression` | Zlib/GZIP compression via `flate2` | ✅ |
| `async-ocsp` | Async OCSP responder fetching via `reqwest` | ✅ |
| `interop-strict` | Strict interop mode as default | ✅ |
| `interop-relaxed` | Relaxed mode helpers for legacy partners | ❌ |
| `trace` | `tracing` instrumentation stubs | ❌ |
| `prometheus` | Built-in `PrometheusMetricsSink` adapter for `MetricsSink` | ❌ |
| `postgres-storage` | PostgreSQL-backed durable, cluster-safe dedup/reconciliation storage | ❌ |
| `testing` | Exposes fixture catalog and matrix executor | ❌ |

---

## 🏗️ Architecture

```
asx-rs
├── as2/            AS2 send, receive, MDN handling
├── as4/            AS4 push/pull, P-Mode registry, pull store
│   ├── pmode.rs    P-Mode registry + resolution
│   ├── parser.rs   ebMS3 UserMessage XML parser
│   └── pull_store  Bounded in-memory pull queue
├── crypto/
│   ├── as2_smime   CMS/S/MIME signing + verification
│   ├── wssec       WS-Security (XMLDSig, XMLenc, OCSP, Exc-C14N)
│   └── soap_builder SOAP envelope construction
├── transport/
│   ├── ingress     HTTP request normalisation
│   ├── egress      HTTP send with endpoint governance
│   └── server      Axum router builders (server feature)
├── lifecycle       Type-state trust transition machine
├── reliability     Retry classification, dedup, reconciliation
├── storage/        DedupStorage + ReconciliationStorage traits + in-memory impls
├── observability/  EventBus, audit sink, back-pressure policy
├── interop         Profile stacks, regional packs, exception policies
├── sbdh            UN/CEFACT SBDH 1.3 wrap/unwrap
├── wire            Bounded stream reading, MIME utilities
└── core            Error types, SessionContext, shared utilities
```

### 🔐 Trust lifecycle

Every inbound byte travels a compiler-enforced path before reaching your application:

```
UntrustedBytes
    │ structural parse (MIME / SOAP envelope)
    ▼
StructurallyParsed
    │ cryptographic verify (S/MIME or XMLDSig)
    ▼
CryptographicallyVerified
    │ decrypt (S/MIME EnvelopedData or XMLenc)
    ▼
ContentDecrypted
    │ dedup check + domain validation
    ▼
DomainReady  ← your application code starts here
```

---

## 🔒 Security Notes

- **`InsecureBypassTrustVerifier`** skips all cryptographic verification. It is intended **exclusively for testing**. Never use it in production.
- PKIX chain validation is **fail-closed**: an empty `trust_anchor_pems` store rejects every certificate.
- OCSP checking is **opt-in** via `OcspMode` in `CertHandle`. The default is `OcspMode::Disabled` — set `OcspMode::ResponderOnly` or `OcspMode::StapledAndResponder` in production.
- Outbound HTTP egress validates URL scheme and blocks private/loopback/link-local targets (including DNS-rebinding to private addresses).

---

## 📊 Status

`asx-rs` is **alpha quality**. Core AS2 send/receive and AS4 push/pull flows are implemented and tested, but the crate is not yet production-hardened.

Current constraints to evaluate before production rollout:
- Core send/receive entry points are synchronous, but async-safe wrappers are now available (`as2::send_async`, `as2::receive_async`, `as4::send_async`, `as4::receive_push_with_dedup_async`) to isolate blocking work on Tokio blocking threads.
- Production persistence adapters (Redis/PostgreSQL/DynamoDB) are trait-based and not yet shipped in-tree; deployers must provide backend implementations.

---

## 📜 License

Licensed under either of:

- [MIT License](./LICENSE-MIT)
- [Apache License, Version 2.0](./LICENSE-APACHE)

at your option.
