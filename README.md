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
- `CmsSmimeTrustVerifier::requiring_signature()` — reject encrypted-only (unsigned)
  inbound messages so sender authentication can be enforced
- Signed-receipt enforcement: an unsigned MDN is rejected when a signed receipt was
  requested (`As2ReceiveMdnRequest::require_signed_mdn`) — no silent non-repudiation downgrade
- Payload compression (RFC 5402 / zlib, `compression` feature)
- Configurable interop mode: strict vs. relaxed for legacy partners
- Retry classification (`SuccessConfirmed` / `Indeterminate` / `AcceptedPendingVerification`)

### 📬 AS4 (ebMS3 + OASIS eDelivery AS4 v1.15)
- One-Way/Push send and receive (SOAP 1.1 and 1.2)
- One-Way/Pull with bounded in-memory pull store per MPC partition
- **WS-Security XMLDSig signing** — RSA-SHA256 *and* **ECDSA-SHA256**; algorithm is
  auto-detected from the signing certificate key type. Works with NIST P-256/P-384/P-521
  and BSI BrainpoolP256r1/P384r1 (required by BDEW AS4-Profil §2.2.6.2.1 / BSI TR-03116-3 §9.1).
  The signature covers the **entire `eb:Messaging` header block** (all UserMessage
  routing/authorization metadata), the SOAP Body, and each payload attachment. On
  receive, the consumed `eb:Messaging` block is bound to the verified signature
  (XML-Signature-Wrapping defence). Signing certificates weaker than RSA-2048 are rejected.
- **XML Encryption (XMLenc11)** — auto-dispatches on recipient certificate key type:
  - **RSA recipient** → RSA-OAEP (SHA-256/MGF1-SHA-256) — PEPPOL / CEF eDelivery
  - **EC recipient** → ECDH-ES + ConcatKDF (NIST SP 800-56A §5.8.1) + AES-128 Key Wrap
    (RFC 3394) — BDEW AS4-Profil §2.2.6.2.2 / BSI TR-03116-3 §9.2
- `X509PKIPathv1` BST token type (`WsSecOutboundKeyInfoProfile::X509PKIPathv1`)
- **Reception Awareness / Non-Repudiation of Receipt, verified end to end** —
  `verify_sync_response` parses the counterparty's synchronous `eb:Receipt`
  namespace-correctly (prefix-agnostic, CDATA-aware), verifies its WS-Security
  signature against the pinned partner certificate, and checks every
  `MessagePartNRInformation` digest against the digests the sent message was
  actually signed over. The signal it acts on must itself be covered by that
  signature, so a counterparty cannot leave a genuinely signed element in place
  and append an unsigned acknowledgement (XML Signature Wrapping). An `eb:Error`
  reply comes back as a typed signal with the ebMS3 code intact, so
  retry-vs-dead-letter routing keys on the real reason.
  `As4HttpTransport::send_and_verify` does send + verify in one call.
- `require_encrypted_inbound` policy field — rejects unencrypted push messages at the policy
  layer (symmetric to `require_signed_push`); use
  `As4PushPolicy::regulated_with_decryption_key(pem)` to set it together with the
  key that satisfies it
- **Multi-payload messages** — several `eb:PartInfo` attachments per `UserMessage`
  are resolved in `xop:Include` order, each decrypted and signature-verified
  independently; reachable via `As4ReceivePushOutput::payloads()` (send is
  currently single-payload)
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
- **Security floor** (`BaseProfile::security_floor`, default sign *and* encrypt) —
  no override or partner overlay can resolve below it; enforced per partner by
  `validate()`, or against a host mandate with `validate_with_floor(..)`
- Session-free resolution (`resolve_all_partners`) for startup audits
- `interop-strict` (default) and `interop-relaxed` feature-gated modes —
  these govern header/ambiguity handling, **not** the security policy
- Exception policies (`InteropExceptionPolicy`) for well-known deviations

### 🧪 Testing (`testing` feature — never enable in production)
- **`InsecureBypassAs4Verifier`** — skips all WS-Security verification. There is no
  AS2 counterpart exposed to dependent crates: AS2's bypass verifier is `#[cfg(test)]`
  and crate-internal. For AS2, implement `As2TrustVerifier` against a local fixture —
  the `testing` feature unseals the trait via `TrustVerifierSeal`
- **`MockAs4Endpoint`** (`testing + server`) — local HTTP AS4 server that accepts any push
  (signed, unsigned, encrypted, or plain), records messages in an async channel, and
  returns synchronous AS4 receipts.  Configure decryption via
  `MockAs4Endpoint::builder().with_decryption_key_pem(key_pem).bind(addr).await?`, and
  signed NRR receipts via `.with_receipt_signing_material(cert_pem, key_pem)` so the
  full receipt-verification round trip is exercisable without real PKI
- **`EventBus::new_for_testing()`** — zero-config `BestEffort` bus; never fails on emit
  when no subscriber is active — no more `new_with_config_and_mode(...)` boilerplate
- **`DurableInMemoryDedupBackend`** — in-memory dedup with `is_durable() = true`; passes
  the strict durable-backend guard without a real persistent store
- **`As4HttpTransport::new_for_localhost_testing()`** — plain-HTTP transport for
  integration tests against `MockAs4Endpoint` on `http://127.0.0.1:…`; SSRF guards
  disabled for the test binary only.  `send_and_verify_to_localhost` is the
  receipt-verifying counterpart
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
asx-rs = { version = "0.12", features = ["as4", "client", "server", "async-ocsp"] }

# AS2 + AS4 with compression
asx-rs = { version = "0.12", features = ["as2", "as4", "compression", "client", "server", "async-ocsp"] }

[dev-dependencies]
# Testing without PKI certificates (MockAs4Endpoint, bypass verifier, keypair generators)
asx-rs = { version = "0.12", features = ["as4", "testing", "server"] }
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
use asx_rs::core::SessionContextBuilder;
use asx_rs::observability::EventBus;

// Session with trust anchor + signing material — one fluent chain:
let session = SessionContextBuilder::new("sess-001", "partner-gln")
    .with_signing_material(my_signing_cert_pem, my_signing_key_pem)
    .with_trust_anchor_pem(partner_root_ca_pem)
    .with_fingerprint_sha256(partner_cert_sha256_hex) // optional hard pin
    .build()?;

// RSA or EC signing key — auto-detected:
let (policy, creds) = As4SendPolicyBuilder::new()
    .action("urn:bdew:as4:service:UTILMD")
    .service("urn:bdew:as4:service", "")
    .signing_cert_pem(my_signing_cert_pem)     // RSA or EC
    .signing_key_pem(my_signing_key_pem)
    .recipient_cert_pem(partner_enc_cert_pem)  // RSA → RSA-OAEP; EC → ECDH-ES
    .encrypt(true)
    .build()?;

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

### AS4 — Send and verify the receipt (Non-Repudiation of Receipt)

A receipt is only evidence of delivery once its digests have been checked
against the message you actually sent. Never scan the response body for
`<eb:Receipt` — a conformant counterparty may use a different namespace prefix
or CDATA, and a substring match cannot verify NRR at all.

```rust
use asx_rs::as4::{As4ReceiptPolicy, As4SyncSignal};
use asx_rs::transport::{As4HttpTransport, TransportConfig};

let transport = As4HttpTransport::new(TransportConfig::default())?;

let outcome = transport
    .send_and_verify(
        "https://partner.example/as4",
        &session,
        &bus,
        &output,
        &As4ReceiptPolicy::regulated(), // signed receipt + NRR digests required
    )
    .await?;

match outcome.signal {
    As4SyncSignal::Receipt(receipt) => {
        // Signed by the pinned partner cert AND every ds:Reference digest of the
        // sent message was echoed and matched. Persist as delivery evidence.
        assert!(receipt.is_non_repudiation_evidence());
    }
    As4SyncSignal::Error(err) => {
        // Typed ebMS3 diagnostics — route retry vs dead-letter on the code.
        tracing::error!(detail = %err.summary(), "counterparty rejected the message");
    }
}
```

Already have the response bytes? Verify them directly:

```rust
let receipt = asx_rs::as4::verify_sync_response(
    &session, &bus, &output,
    &http_response_body, content_type,
    &As4ReceiptPolicy::regulated(),
)?
.into_receipt()?; // eb:Error becomes an Err here
```

`As4ReceiptPolicy::relaxed()` accepts unsigned acknowledgements for interop
bring-up — but a digest or signature that *is* present is always verified, and a
mismatch is always an error.

### AS4 — Receive push with encryption enforcement

```rust
use asx_rs::as4::{receive_push_with_dedup_async, As4PushPolicyBuilder, As4ReceivePushRequest};
use std::sync::Arc;

// Sets the decryption key and `require_encrypted_inbound = true` together, so
// the invariant cannot be split — there is no ordering to get wrong.
let policy = As4PushPolicyBuilder::regulated()
    .with_mandatory_inbound_encryption(my_ec_or_rsa_private_key_pem)
    .build()?;

let outcome = receive_push_with_dedup_async(
    &session, &bus,
    As4ReceivePushRequest {
        http_content_type,
        payload,
        receipt_payload: None,
        policy,
        // Fragment-scope policy applies to fragmented messages only, so a
        // non-fragmenting profile always passes None here.
        authenticated_sender_scope: None,
    },
    dedup_backend,
).await?;
```

### AS4 — Testing without PKI certificates

```rust
use asx_rs::as4::mock_endpoint::MockAs4Endpoint;
use asx_rs::observability::EventBus;
use tokio::time::{timeout, Duration};

// Plain receive: bind to a random port — no cert, no WIRK, no PEPPOL test PKI needed
let endpoint = MockAs4Endpoint::bind("127.0.0.1:0").await?;

// Receive encrypted messages: configure decryption key via builder
let endpoint = MockAs4Endpoint::builder()
    .with_decryption_key_pem(my_ec_or_rsa_private_key_pem)
    .bind("127.0.0.1:0")
    .await?;

let url = endpoint.local_url(); // "http://127.0.0.1:PORT/as4/inbox"

// Test EventBus: zero-config, never fails on emit (BestEffort)
let bus = EventBus::new_for_testing(); // requires `testing` feature

// Wait for the first message (returns None if the endpoint is dropped).
let msg = timeout(Duration::from_secs(5), endpoint.next_message())
    .await??;
assert_eq!(msg.action, "urn:bdew:as4:service:UTILMD");
assert!(!msg.payload.is_empty());
// from_party_ids contains the sender GLN; to_party_ids the receiver GLN
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
| `trace` | `tracing` instrumentation on hot paths | ✅ |
| `prometheus` | Built-in Prometheus/OpenMetrics `MetricsSink` | ❌ |
| `opentelemetry` | OpenTelemetry metrics `MetricsSink` adapter | ❌ |
| `testing` | `InsecureBypassAs4Verifier`, `DurableInMemoryDedupBackend`, keypair generators, `verifier_seal`, interop matrix executor, **`EventBus::new_for_testing()`** | ❌ |
| `testing + server` | Also: **`MockAs4Endpoint`** (with `builder().with_decryption_key_pem()`) | ❌ |

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
- Minimum signing-key strength is enforced: RSA moduli below 2048 bits are rejected.
- OCSP is **disabled by default** (`OcspMode::Disabled`). Set
  `OcspMode::ResponderOnly` or `OcspMode::StapledAndResponder` in production.
- **SSRF-hardened egress**: URL scheme and private/loopback/link-local/CGNAT/IPv4-mapped-IPv6
  ranges are blocked, DNS resolution is pinned against rebinding, and **HTTP redirects are
  never followed** (a redirect cannot escape the validated target). Applies to AS2/AS4
  egress, OCSP, and SMP clients.
- **Signature conformance is checked against an independent implementation**, not
  only against ourselves: `tests/interop_xmlsec_oracle.rs` verifies ASX output with
  **xmlsec1**, the W3C XMLDSig reference implementation, in a container
  (`cargo test --test interop_xmlsec_oracle -- --ignored`). See
  [docs/conformance.md](docs/conformance.md).
- **AS4 message integrity**: the WS-Security signature covers the whole `eb:Messaging`
  metadata block; the receive path binds the consumed block to the verified signature
  (XML-Signature-Wrapping defence) **and requires the payload attachment to be covered
  by a verified `ds:Reference URI="cid:…"`** — signing the envelope proves nothing
  about the detached MIME part that carries the actual business document.
- **SMP discovery signature verification**: `SmpSignaturePolicy::Verify` checks the
  enveloped XMLDSig on the `ServiceMetadata` response and chains the SMP certificate
  to the network's SMP CA, so the endpoint URL and recipient certificate are
  authenticated rather than trusted on TLS alone. Unsigned responses are rejected by
  default even without it — see [docs/security.md](docs/security.md).
- **Profile security invariants are floors, not defaults**: `BaseProfile::security_floor`
  defaults to sign-and-encrypt and cannot be lowered by any extension, override,
  partner overlay, or regional pack. `validate()` enforces it against the resolved
  policy of every declared partner, and the profile-diff gate blocks a release that
  lowers it. Interop mode is a separate axis and does not affect it.

---

## 📊 Status

`asx-rs` is **beta quality**. Core AS2 and AS4 push/pull flows are implemented, tested
(1000+ tests across unit + integration suites), and exercised in production integrations.

- ✅ AS2 send/receive (signed, encrypted, compressed, sync + async)
- ✅ AS4 push send/receive (signed, encrypted, dedup, fragment reassembly)
- ✅ AS4 pull (with reliability classification)
- ✅ WS-Security (RSA-SHA256, ECDSA-SHA256, ECDH-ES + ConcatKDF + AES-KW, XMLenc11)
- ✅ AS4 Reception Awareness / Non-Repudiation of Receipt, verified end to end
- ✅ OCSP + PKIX chain validation
- ✅ Strict-mode production validation gate
- ✅ Comprehensive testing infrastructure (bypass verifier, mock endpoint, keypair generators)
- ✅ Multi-payload AS4 receive (every `eb:PartInfo` attachment verified and decrypted)
- ⚠️  Persistent storage backends (dedup/reconciliation) are trait-defined but not shipped
  in-tree; deployers provide their own Redis/PostgreSQL/DynamoDB implementations.
- ⚠️  AS4 **send** is single-payload; multi-payload send is the remaining eDelivery
  conformance gap — see [docs/conformance.md](docs/conformance.md).
- ⚠️  No third-party conformance certificate yet. Official EC eDelivery conformance
  testing is **free of charge**; what it needs from us (a publicly reachable access
  point + a SUT Controller) and a testcontainers-based interop plan that runs in CI
  are written up in [docs/conformance.md](docs/conformance.md).

### Development

Common tasks are wrapped in a [`justfile`](./justfile) ([just](https://github.com/casey/just)):

```bash
just              # list every recipe
just test         # cargo test --all-features
just lint         # fmt --check + clippy -D warnings
just ci           # pre-push: lint + strict check + tests + feature matrix
just release-gate # every mandatory gate from docs/release.md (slow)
```

Recipes mirror `.github/workflows/rust.yml` and [docs/release.md](./docs/release.md),
so a local run and CI enforce the same thing.

### Versioning

`asx-rs` is pre-1.0, so **minor** bumps (`0.x` → `0.x+1`) are the breaking ones.
Wire/crypto behaviour changes and security-default tightenings always get their
own minor version and are called out separately from API changes — see the
[CHANGELOG](./CHANGELOG.md) and its [SemVer policy](./CHANGELOG.md#semver-policy)
before moving between minor versions.

---

## 📜 License

Licensed under either of:

- [MIT License](./LICENSE-MIT)
- [Apache License, Version 2.0](./LICENSE-APACHE)

at your option.
