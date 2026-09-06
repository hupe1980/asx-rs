+++
title = "AS4 reference"
description = "AS4 (OASIS ebMS3) in asx-rs: WS-Security signing, XML encryption, verified receipts, push and pull MEPs, large messages, and SMP discovery."
+++

Requires feature flag: `as4`

## Overview

AS4 (ebMS3 + eDelivery) support in `asx-rs` is exposed through free functions in `asx_rs::as4`.

Primary flows:

1. Outbound AS4 UserMessage send (signed, optionally encrypted).
2. Inbound push receive with dedup, WS-Security verification, and optional XML decryption.
3. Ordered push receive with conversation gate.
4. Pull receive with reliability integration.
5. Signal generation (receipt, error, pull request).

## Important Packaging Rule

Outbound payload packaging is MIME-only (`multipart/related`) with detached payload
attachments and cid references.  Embedded SOAP payload mode is unsupported for receive
and rejected on send.

---

## Signing: RSA-SHA256 and ECDSA-SHA256

`asx-rs` selects the XMLDSig signature algorithm automatically from the private key type:

| Key type | Algorithm URI | Profiles |
|---|---|---|
| RSA | `http://www.w3.org/2001/04/xmldsig-more#rsa-sha256` | PEPPOL, CEF eDelivery |
| EC (any curve) | `http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256` | BDEW AS4-Profil §2.2.6.2.1, BSI TR-03116-3 §9.1 |

No policy knob is required — pass the signing cert+key PEM and the library detects the
type.  BrainpoolP256r1 (BSI) and NIST P-256/P-384/P-521 are all supported.

### X509PKIPathv1 outbound token type

BDEW AS4-Profil §2.2.6.2.1 requires the `wsse:BinarySecurityToken` to use
`ValueType="...#X509PKIPathv1"` (a DER-encoded PKI path).  Enable it on the send policy:

```rust
use asx_rs::crypto::wssec::WsSecOutboundKeyInfoProfile;

let (policy, creds) = As4SendPolicyBuilder::new()
    .outbound_key_info_profile(WsSecOutboundKeyInfoProfile::X509PKIPathv1)
    // ... signing_cert_pem, signing_key_pem, action, service
    .build()?;
```

When `X509PKIPathv1` is set, the send path automatically:
1. Builds a `wsse:BinarySecurityToken` with `ValueType="...#X509PKIPathv1"` in the
   Security header (DER SEQUENCE { leaf certificate })
2. Emits `<wsse:SecurityTokenReference>` in `ds:KeyInfo` pointing to that token by
   `wsu:Id="X509PKIPathToken"`

---

## XML Encryption: automatic key transport selection

`asx-rs` selects the XML Encryption key transport algorithm from the recipient
certificate's public key type at call time.  No configuration is needed.

| Recipient cert key | Key transport | Key reference | Profiles |
|---|---|---|---|
| RSA | RSA-OAEP (SHA-256/MGF1-SHA-256) | `BinarySecurityToken` | PEPPOL, CEF eDelivery |
| EC (NIST P-256/P-384/P-521, BrainpoolP256r1/P384r1) | ECDH-ES ephemeral + ConcatKDF (NIST SP 800-56A §5.8.1) + AES Key Wrap (RFC 3394), sized to the content key | `X509SKI` | BDEW AS4-Profil §2.2.6.2.2, BSI TR-03116-3 §9.2 |

### EC encryption XML structure

When the recipient has an EC key the outbound `<xenc:EncryptedKey>` uses:

```xml
<xenc:EncryptedKey>
  <!-- kw-aes256 for an AES-256-GCM payload, kw-aes128 for AES-128-GCM -->
  <xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#kw-aes256"/>
  <ds:KeyInfo>
    <xenc:AgreementMethod Algorithm="http://www.w3.org/2009/xmlenc11#ECDH-ES">
      <xenc11:KeyDerivationMethod Algorithm="http://www.w3.org/2009/xmlenc11#ConcatKDF">
        <xenc11:ConcatKDFParams AlgorithmID="" PartyUInfo="" PartyVInfo="">
          <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
        </xenc11:ConcatKDFParams>
      </xenc11:KeyDerivationMethod>
      <xenc:OriginatorKeyInfo>
        <ds:KeyValue>
          <dsig11:ECKeyValue>
            <dsig11:NamedCurve URI="urn:oid:1.3.36.3.3.2.8.1.1.7"/>  <!-- BrainpoolP256r1 -->
            <dsig11:PublicKey>BASE64_EPHEMERAL_PUBLIC_KEY</dsig11:PublicKey>
          </dsig11:ECKeyValue>
        </ds:KeyValue>
      </xenc:OriginatorKeyInfo>
      <xenc:RecipientKeyInfo>
        <ds:X509Data><ds:X509SKI>BASE64_SKI</ds:X509SKI></ds:X509Data>
      </xenc:RecipientKeyInfo>
    </xenc:AgreementMethod>
  </ds:KeyInfo>
  <xenc:CipherData><xenc:CipherValue>WRAPPED_CEK</xenc:CipherValue></xenc:CipherData>
</xenc:EncryptedKey>
```

`AlgorithmID`, `PartyUInfo`, and `PartyVInfo` are empty strings per BDEW AS4-Profil
(BSI TR-03116-3 §9.2 with the referenced default ConcatKDF parameters).

### ConcatKDF parameters

| Parameter | Value | Source |
|---|---|---|
| Hash | SHA-256 | XMLenc11 |
| Counter | 1 (single round, keydatalen ≤ 256 bits) | NIST SP 800-56A §5.8.1 |
| keydatalen | Matches the key-wrap algorithm: 128 bits for kw-aes128, 256 for kw-aes256 — output truncation only | Derived from key-wrap algorithm |
| AlgorithmID | `""` (empty) | BDEW AS4-Profil / BSI TR-03116-3 |
| PartyUInfo | `""` | BDEW AS4-Profil |
| PartyVInfo | `""` | BDEW AS4-Profil |

The derived key material is `SHA-256(counter ‖ Z ‖ OtherInfo)` with
`OtherInfo = AlgorithmID ‖ PartyUInfo ‖ PartyVInfo` (a **raw** concatenation per
SP 800-56A §5.8.1 — no embedded `keydatalen`, no per-field length prefixes; the
length-prefixed form belongs to the JOSE Concat KDF, RFC 7518, and is *not* used
here). With the empty default parameters this reduces to `SHA-256(counter ‖ Z)`,
and the KEK is the leftmost `keydatalen/8` bytes.

On receive, non-empty `ConcatKDFParams` attributes from a peer are decoded per
XML Encryption 1.1 §5.4.1: `xs:hexBinary` **bit strings** whose first octet is
the padding-bit count (W3C xmlenc-core1 Example 25 — `AlgorithmID="0000"` is
the single octet `0x00`). Only byte-aligned values (padding count 0) are
accepted; invalid hex and sub-byte bit strings are rejected with named errors
rather than silently mis-derived into an undiagnosable AEAD failure.

---

## Multi-Payload Messages

ebMS3 allows several `eb:PartInfo` entries per `UserMessage`. On receive, every
part referenced by an `href="cid:…"` — `eb:PartInfo` in the signed header
(SwA) or legacy MTOM `xop:Include` — is resolved, in document order:

```rust
let out = /* As4ReceivePushOutput */;

out.payload;                 // primary (first) attachment
out.payload_content_id;      // its Content-ID, no `cid:` prefix
out.additional_payloads;     // the rest, in eb:PartInfo order
out.payload_count();         // always >= 1

for (content_id, payload) in out.payloads() { /* uniform iteration */ }
out.payload_by_content_id("cid:xmlpayload2@gitb");
```

Each attachment is treated on equal terms:

| Check | Applied to |
|---|---|
| WS-Security `cid:` signature coverage | **every** attachment — a signature referencing only payload 1 leaves 2..n swappable |
| XML-Encryption decryption | each attachment independently |
| `require_encrypted_inbound` | each attachment independently — one plaintext part fails the message |

Bounds and failure modes:

- At most 16 attachments per message (`MAX_INBOUND_PAYLOADS`), so a body full of
  `cid:` references cannot induce unbounded work.
- A `cid:` reference with no matching MIME `Content-ID` is an error, not a skip.
- MIME parts not referenced by any `cid:` href are ignored without allocation.
- An envelope with **no** `cid:` reference is rejected: with no Content-ID there is
  nothing to tie a part to a `ds:Reference URI="cid:…"`, so it could never be
  shown to be signature-covered.

### Multi-payload send

`As4SendRequest::additional_payloads` attaches further parts; each gets its own
signed `eb:PartInfo`, its own `ds:Reference`, and — when the policy says so —
per-part compression and encryption:

```rust
use asx_rs::as4::As4AdditionalPayload;

As4SendRequest {
    payload: invoice_xml,
    payload_mime_type: Some("application/xml".into()),
    payload_content_id: Some("xmlpayload@gitb".into()),
    additional_payloads: vec![
        As4AdditionalPayload::new(annex_xml, "application/xml")
            .with_content_id("xmlpayload2@gitb"),
        As4AdditionalPayload::new(binary, "application/octet-stream"),
    ],
    ..As4SendRequest::default()
}
```

Attachment digests follow the WSS SwA transform by the part's **wire**
content type — XML parts are digested over their Exclusive C14N form, `text/*`
over CRLF-normalized octets, everything else raw — which is what WSS4J-based
receivers recompute. Compressed parts travel as `application/gzip` and
encrypted parts as `application/octet-stream` on the wire, while the signed
`eb:PartInfo` MimeType always names the original media type.

---

## `As4PushPolicy` — inbound receive policy

```rust
pub struct As4PushPolicy {
    /// Interop mode (Strict is default and required for production).
    pub interop: InteropMode,

    /// Reject inbound messages without a valid WS-Security signature.
    /// Default: `true` (fail-closed). Set `false` only for legacy partners.
    pub require_signed_push: bool,

    /// Reject inbound messages that are NOT XML-encrypted.
    ///
    /// Default: `false` (backward-compatible). Set `true` when encryption is
    /// mandatory (e.g. BDEW AS4-Profil §2.2.6.2.2).  The builder fails at
    /// construction if this is `true` but `inbound_decryption_key_pem` is unset.
    pub require_encrypted_inbound: bool,

    /// Private key PEM for decrypting inbound XML-encrypted payloads.
    /// Accepts both RSA and EC keys:
    ///   - RSA → RSA-OAEP (PEPPOL/CEF)
    ///   - EC  → ECDH-ES + ConcatKDF + AES-128 Key Wrap (BDEW)
    pub inbound_decryption_key_pem: Option<Arc<[u8]>>,

    /// Whether receipt verification failures close the operation.
    pub require_signed_receipt: bool,

    /// Timestamp freshness window (default: 5 minutes per eDelivery AS4 v1.15 §5.1.3).
    pub timestamp_freshness_window: Option<std::time::Duration>,

    /// Fail-closed audit event emission.
    pub fail_closed_audit_events: bool,

    /// Fragment group sender-scope policy.
    ///
    /// Applies to **fragmented messages only** — see the note below.
    pub fragment_scope_policy: FragmentScopePolicy,
}
```

### `fragment_scope_policy` applies to fragmented messages only

`FragmentScopePolicy::RequireAuthenticatedScope` (the default) is consulted only
after an inbound message has been identified as carrying an
`mf:MessageFragment` (ebMS3 Part 2 §5). An ordinary single-`eb:UserMessage` push
never reaches that check.

So a profile that never fragments — BDEW MaKo, for example — should keep the
secure default and pass `authenticated_sender_scope: None`:

```rust
let policy = As4PushPolicyBuilder::regulated().build()?;  // RequireAuthenticatedScope

let request = As4ReceivePushRequest {
    // ...
    authenticated_sender_scope: None,  // ← correct for non-fragmented messages
};
```

Do **not** switch to `UseSoapSenderId` to "make `None` safe" — it already is,
and the downgrade only weakens the policy on the day a fragment does arrive.

### Builder example — regulated deployment with mandatory encryption

`require_encrypted_inbound` and `inbound_decryption_key_pem` form one invariant:
the builder rejects the first without the second. Set both in one call so they
cannot drift apart:

```rust
let policy = As4PushPolicyBuilder::regulated()
    .with_mandatory_inbound_encryption(my_ec_private_key_pem)
    .build()?;

// Equivalent, without the builder:
let policy = As4PushPolicy::regulated_with_decryption_key(my_ec_private_key_pem);
```

The two settings remain individually available
(`inbound_decryption_key_pem(..)` / `require_encrypted_inbound(true)`) for
callers that genuinely need to configure decryption without mandating it.

### Builder example — testing without PKI

```rust
// Only available with `testing` feature:
let policy = As4PushPolicyBuilder::new()
    .allow_unsigned_push(true)
    .fail_closed_audit_events(false)
    .timestamp_freshness_window(None)
    .build()?;
```

---

## `As4SendPolicy` — outbound send policy

Key fields:

| Field | Default | Notes |
|---|---|---|
| `sign` | `true` | Require signing in strict mode |
| `encrypt` | `false` | Set `true` + `recipient_cert_pem` for encrypted send |
| `outbound_key_info_profile` | `BinarySecurityTokenX509v3` (WSS 1.1.1 §7.7 STR shape; what WSS4J-based peers require) | Use `X509PKIPathv1` for BDEW; bare-`X509Data` profiles exist for plain-XMLDSig consumers |
| `outbound_xmlenc_payload_algorithm` | `Aes128Gcm` | AES-128-GCM (eDelivery v1.15 default) |
| `payload_packaging_mode` | `MimeAttachment` | MIME-only (strict default) |

---

## Error Codes

| Code | Scenario | Notes |
|---|---|---|
| `ParseFailed` | Malformed SOAP/MIME/XML | Retry unlikely |
| `DecryptionFailed` | Wrong key, corrupt ciphertext, bad AES-KW integrity | Reject + audit |
| `SecurityVerificationFailed` | Bad signature, untrusted cert, timestamp out of window | Reject + audit |
| `PolicyViolation` | Unsigned but signing required; unencrypted but encryption required | Reject + signal error |
| `InteropViolation` | Missing required ebMS3 element (strict mode) | Reject |
| `ReliabilityFailure` | Non-durable dedup backend in strict mode | Fix configuration |

---



### Send

```rust
pub fn send_sync(
    session: &SessionContext,
    event_bus: &EventBus,
    request: As4SendRequest,
) -> Result<As4SendOutput>
```

Async-safe wrapper for Tokio services:

```rust
pub async fn send_async(
    session: &SessionContext,
    event_bus: &EventBus,
    request: As4SendRequest,
) -> Result<As4SendOutput>
```

Behavior notes:

1. SOAP envelope is generated with SwA packaging: empty Body, payload referenced from the signed `eb:PartInfo`.
2. MIME package is emitted as `multipart/related` output.
3. The WS-Security signature covers three references: the whole `eb:Messaging`
   header block (`wsu:Id="as4-messaging"` — all UserMessage routing/authorization
   metadata), the SOAP Body, and a detached `cid:` reference for the MIME
   attachment. On receive, the `eb:Messaging` block that the pipeline routes on is
   bound to the verified signature (there must be exactly one such block and its
   `wsu:Id` must be in the verified reference set) — an XML-Signature-Wrapping
   defence.
4. Optional XML encryption is applied before outbound packaging.

### Verify the synchronous response

```rust
pub fn verify_sync_response(
    session: &SessionContext,
    event_bus: &EventBus,
    sent: &As4SendOutput,
    response_body: &[u8],
    response_content_type: &str,
    policy: &As4ReceiptPolicy,
) -> Result<As4SyncSignal>
```

In the One-Way/Push MEP with Reception Awareness (eDelivery AS4 v1.15 §5.1,
BDEW AS4-Profil §4.6.3) the receiving MSH answers on the same HTTP connection
with an `eb:Receipt` or an `eb:Error`. `verify_sync_response` turns that raw
body into a typed, verified outcome. Checks, in order:

| # | Check | Failure code |
|---|---|---|
| 1 | Body non-empty and within `max_receipt_bytes` (256 KiB default) | `ParseFailed` / `PayloadTooLarge` |
| 2 | Namespace-resolved parse of the `eb:SignalMessage` (prefix-agnostic, CDATA-aware) | `ParseFailed` |
| 3 | At most one `eb:Messaging` / `eb:SignalMessage`; no repeated `eb:MessageInfo` child; `NonRepudiationInformation` only inside the `eb:Receipt` | `SecurityVerificationFailed` |
| 4 | `eb:Error` classified and returned as `As4SyncSignal::Error`; a signal carrying both Receipt and Error is ambiguous | — / `InteropViolation` |
| 5 | Receipt `ds:Signature` verified against the pinned partner certificate, trust anchors and revocation policy | `SecurityVerificationFailed` |
| 6 | The `eb:SignalMessage` acted on is covered by that signature, directly or via a signed ancestor (XML Signature Wrapping defence) | `SecurityVerificationFailed` |
| 7 | `eb:RefToMessageId` equals the sent `message_id`; an `eb:Error` correlating elsewhere is not attributed to this message | `InteropViolation` |
| 8 | Every sent `ds:Reference` echoed by a `MessagePartNRInformation` entry with matching digest algorithm and value | `SecurityVerificationFailed` |
| 9 | `eb:Timestamp` present and inside the replay window | `SecurityVerificationFailed` |

Step 8 is what makes a receipt evidence rather than decoration: it proves the
counterparty signed a statement about the exact bytes that were sent. The digest
set is read from the sent message's own signature, unwrapping the
`multipart/related` MIME package first, so `cid:` attachment references are
covered too.

There is deliberately **no** result variant for a digest mismatch — a mismatch is
always an error, never a value the caller can ignore.

Steps 3 and 6 are the wrapping defences: without them a counterparty could leave
an element it genuinely signed in place, so the signature still verifies against
the pinned certificate, and append an unsigned element acknowledging a different
message. The same defences apply to the inbound `receipt_payload` path, which
shares this parser.

`As4SyncSignal::Error` reports what the connection returned, not a proven fact —
error signals are typically unsigned. Treat one as a routing hint (retry vs
dead-letter); only `As4VerifiedReceipt::is_non_repudiation_evidence()` asserts a
cryptographically proven outcome.

#### Presets

| Preset | Signature | NRR digests | Interop | Freshness |
|---|---|---|---|---|
| `As4ReceiptPolicy::regulated()` (default) | required | required | Strict | 5 min |
| `As4ReceiptPolicy::strict()` | alias for `regulated()` | | | |
| `As4ReceiptPolicy::relaxed()` | optional | optional | Relaxed | disabled |

Under `relaxed()` a signature or digest that *is* present is still fully
verified; only their absence is tolerated.

#### Transport wrapper

```rust
pub async fn send_and_verify(
    &self,
    url: &str,
    session: &SessionContext,
    event_bus: &EventBus,
    output: &As4SendOutput,
    policy: &As4ReceiptPolicy,
) -> Result<As4SendAndVerifyOutcome>
```

`As4SendAndVerifyOutcome` keeps the raw `HttpSendOutcome` alongside the verified
signal so the wire evidence can be logged or persisted. A non-2xx status whose
body carries a parseable `eb:Error` is returned as that error signal — the ebMS3
diagnostics are more actionable than the HTTP status. A non-2xx status with an
unparseable body becomes `TransportFailure`.

```rust
let outcome = transport
    .send_and_verify(&url, &session, &bus, &sent, &As4ReceiptPolicy::regulated())
    .await?;

match outcome.signal {
    As4SyncSignal::Receipt(receipt) => assert!(receipt.is_non_repudiation_evidence()),
    As4SyncSignal::Error(err) => {
        // As4ErrorCode::from_ebms_code drives retry vs dead-letter.
        for entry in &err.errors {
            tracing::error!(code = %entry.error_code, detail = %entry.summary());
        }
    }
}
```

#### Asynchronous MEP

`verify_sync_response` rejects an empty body: the synchronous MEP requires a
signal on the same connection. Deployments using the asynchronous MEP receive
the receipt as a separate inbound request and should handle it through the
receive path instead.

### Receive push (owned)

```rust
pub fn receive_push_with_dedup_sync(
    session: &SessionContext,
    event_bus: &EventBus,
    request: As4ReceivePushSyncRequest<'_>,
) -> Result<As4ReceivePushOutput>
```

Sync fragment-aware wrapper for large-message reassembly:

```rust
pub fn receive_push_with_dedup_sync_fragment_aware(
    session: &SessionContext,
    event_bus: &EventBus,
    request: As4ReceivePushSyncFragmentAwareRequest<'_>,
) -> Result<As4ReceivePushProgress>
```

Async-safe wrapper for Tokio services:

```rust
pub async fn receive_push_with_dedup_async(
    session: &SessionContext,
    event_bus: &EventBus,
    request: As4ReceivePushRequest,
    dedup_backend: Arc<dyn DedupStorage>,
) -> Result<As4ReceivePushOutput>
```

### Receive push (ordered)

```rust
pub async fn receive_push_ordered(
    session: &SessionContext,
    event_bus: &EventBus,
    request: As4ReceivePushOrderedRequest<'_>,
) -> Result<As4Ordered<As4ReceiveOutcome>>
```

Ordered delivery (ebMS3 §5.1.5), with two properties the signature encodes:

- **The place in the queue is taken on arrival.** The `eb:ConversationId` is
  read from the raw bytes with a bounded scan *before* parse, verification and
  decryption, which still run in parallel across messages.
- **The turn is held until you drop it.** `As4Ordered<T>` is a guard — deliver
  the message while you hold it.

```rust
let ordered = receive_push_ordered(&session, &bus, request).await?;

if let As4ReceiveOutcome::FirstSeen(output) = ordered.get() {
    application.deliver(output).await?;   // turn still held
}

drop(ordered);                            // next message may proceed
```

| Method | Behaviour |
|---|---|
| `get()` | Borrow the outcome; the turn stays held |
| `holds_turn()` | `false` for a duplicate or an incomplete fragment group — neither is delivered |
| `into_inner()` | Take the outcome and **end the turn** |

The scanned conversation id is unauthenticated, so it is compared against the
verified `eb:ConversationId` after parsing; a mismatch is a
`SecurityVerificationFailed`. A `UserMessage` carrying two `eb:ConversationId`
elements is rejected rather than resolved by document order.

### Receive pull with reliability

```rust
pub async fn receive_pull_with_reliability(
    session: &SessionContext,
    event_bus: &EventBus,
    request: As4ReceivePullWithReliabilityRequest<'_>,
) -> Result<As4ReceivePullOutput>
```

#### Authorizing a pull (required)

Pull inverts the usual trust direction. In push, the sender proves who it is by
signing a message it hands you. In pull, a peer asks you to **hand over** queued
messages — and the ebMS3 `PullRequest` signal is unsigned. An MPC URI is not a
secret either: it appears in P-Mode configuration, agreements and log lines. The
authorization check is therefore the only thing between a caller and another
party's business documents.

`As4PullPolicy::authorization` must be set explicitly; it defaults to
[`As4PullAuthorization::Deny`], which refuses every `PullRequest`:

```rust
use asx_rs::as4::{As4PullAuthorization, As4PullPolicyBuilder};

// Shared secret compared against eb:AuthorizationInfo in constant time.
let policy = As4PullPolicyBuilder::new()
    .mpc("urn:example:mpc:invoices")
    .authorization(As4PullAuthorization::SharedSecret(secret))
    .build()?;

// Or: mTLS terminates at the reverse proxy, which maps the client certificate
// to this MPC before the request reaches the library.
let policy = As4PullPolicyBuilder::new()
    .mpc("urn:example:mpc:invoices")
    .authorization(As4PullAuthorization::EnforcedByTransport)
    .build()?;
```

ebMS3 §5.2.3.1 makes `eb:AuthorizationInfo` optional *at the protocol level*,
which is why this is a policy decision rather than a wire requirement. That
flexibility exists for deployments where the transport layer owns the boundary —
which is what `EnforcedByTransport` states explicitly. Leaving pull open is not
reachable by omission, only by choosing it.

An empty `SharedSecret` is rejected at build time: it would compare equal to an
absent `AuthorizationInfo` and silently authorize everyone.

### Token-enforced strict runtime sessions

For regulated deployments that require explicit startup proof, bind validated
session context once and then use standard AS4 entry points:

```rust
let strict_session = bootstrap_token.bind(&session);

let out = asx_rs::as4::receive_push_with_dedup_sync(
    &strict_session,
    &event_bus,
    asx_rs::as4::As4ReceivePushSyncRequest {
        request,
        dedup_backend,
    },
)?;
```

`bootstrap_token` comes from
[`StrictRuntimeBootstrap::validate`](@/docs/getting-started.md#regulated-startup-gate-strict-production).
In non-testing builds, strict-interop AS4 entry points refuse a session with no
token binding, and there is no other way to set the marker.

### Strict production clustered topology gate

`As4PullStore` and `As4ConversationOrderGate` are process-local components: in a
cluster each replica would believe it holds the whole queue, or the whole
conversation. Declaring the topology makes that a startup error rather than a
silent correctness loss:

```rust
use asx_rs::presets::{DeploymentTopology, StrictRuntimeBootstrap};

let token = StrictRuntimeBootstrap::new("startup")
    .event_bus(&event_bus)
    .dedup(dedup.as_ref())
    .reconciliation(reconciliation.as_ref())
    .topology(DeploymentTopology::Clustered)
    .as4_pull_store(pull_store)
    .as4_conversation_gate(conversation_gate)
    .validate()?;
```

### Queue pull payload with reliability

```rust
pub async fn enqueue_pull_with_reliability(
    session: &SessionContext,
    event_bus: &EventBus,
    request: As4EnqueuePullWithReliabilityRequest<'_>,
) -> Result<As4PullEnqueueOutcome>
```

Use this API for production integrations. It emits overflow audit events and
queues reconciliation for dropped/rejected messages under configured overflow
policy.

### Signal generation

`generate_receipt`, `generate_receipt_with_nri`, `generate_signed_receipt_with_nri`,
`generate_signed_receipt_for_output`, `generate_error_signal`, and
`generate_pull_request` are available in `asx_rs::as4`.

Signal *verification* on the send side is
[`verify_sync_response`](#verify-the-synchronous-response).

## Core Types

1. `As4SendPolicy` / `As4SendPolicyBuilder`
2. `As4PushPolicy` / `As4PushPolicyBuilder`
3. `As4PullPolicy`
4. `As4ReceivePushRequest`
5. `As4ReceivePushOrderedRequest`
6. `As4ReceivePushOrderedFragmentAwareRequest`
7. `As4ReceivePushAsyncFragmentAwareRequest`
8. `As4ReceivePushSyncFragmentAwareRequest`
9. `As4ReceivePushSyncRequest`
10. `As4SendOutput` and `As4ReceivePushOutput`
11. `As4EnqueuePullWithReliabilityRequest`
12. `As4ReceivePullWithReliabilityRequest`
13. `PMode` / `PModeRegistry`
14. `As4ReceiptPolicy` — synchronous-signal verification policy
15. `As4SyncSignal` — verified `eb:Receipt` or typed `eb:Error`
16. `As4VerifiedReceipt` / `As4NonRepudiation` — delivery evidence
17. `As4ErrorSignal` / `As4ReceivedError` — parsed ebMS3 error diagnostics

## Interop Notes

1. Strict mode is default and recommended.
2. Relaxed interop remains available by feature/profile policy for scoped exceptions.
3. Inbound payloads must be multipart/related with detached attachment bytes.
4. Signed inbound messages are validated in pinned-sender mode and require `SessionContext.cert_handle.fingerprint_sha256` to be configured. The same pin is used to verify counterparty receipt signatures; override it with `As4ReceiptPolicy::with_expected_signer_fingerprint` when a partner signs receipts with a different certificate.
5. Never detect a receipt by scanning the response body for `<eb:Receipt`. Prefixes are arbitrary (`eb:`, `eb3:`, `ns2:`, default namespace) and element text may be CDATA-wrapped; `verify_sync_response` resolves namespaces properly.

## Test Service and P-Mode

ebMS3 Core §5.2.2 reserves a Service and Action URI for connectivity testing,
and the eDelivery conformance suite exercises it as the `PING` profile. A
conformant MSH acknowledges such a message with a receipt and **does not deliver
it to the application** — its payload is empty or a loopback, so handing it to a
business pipeline manufactures a document out of a health check.

`asx_rs::as4::test_service` carries the reserved URIs, a send-policy helper and
the detector. To send a ping:

```rust
use asx_rs::as4::test_service::test_service_send_policy;

let (policy, creds) = test_service_send_policy()
    .signing_cert_pem(cert_pem)
    .signing_key_pem(key_pem)
    .build()?;
```

On receive, ask the output before delivering anything:

```rust
if out.is_test_service_ping() {
    // The receipt is already generated. Stop here — do not deliver.
    return;
}
```

`is_test_service_ping` is derived from the parsed `eb:Service` and `eb:Action`,
so it cannot drift from what was on the wire, and **both** must match: a
business message that happens to reuse one of the URIs is not a ping.

`asx_rs::as4::pmode` provides the P-Mode registry for standards-aligned partner
agreements.

## SMP Integration: Dynamic Partner Discovery (PEPPOL / CEF)

In Peppol and CEF eDelivery networks, Access Points discover each other
dynamically. Before sending, the sender resolves the recipient's endpoint URL
and signing certificate — and that takes two steps, not one.

**1. Find the SMP (BDXL).** The participant identifier is hashed into a DNS
name, and a U-NAPTR record there names the SMP that holds the metadata:

```text
name = strip-trailing(base32(sha256(lowercase(ID-VALUE))), "=") + "." + ID-SCHEME + "." + ZONE

2M2UFGZNGSS25JOOMOV2S4VGG7PW64KIVYNONDSVZSRT4EAZVCLQ.iso6523-actorid-upis.participant.sml.prod.tech.peppol.org.
    IN NAPTR 100 10 "U" "Meta:SMP" "!.*!https://smp.example.org!" .
```

Only the identifier **value** is hashed — not `scheme::value` — and the scheme
appears as its own DNS label.

**2. Ask the SMP** for the `ServiceMetadata` of that participant, document type
and process, and verify its signature.

Enable the `smp` module with the `client` feature, and `dns` for the built-in
resolver:

```toml
asx-rs = { version = "0.14", features = ["as4", "client", "async-ocsp", "dns"] }
```

| Network | SML zone |
|---|---|
| Peppol production | `participant.sml.prod.tech.peppol.org` |
| Peppol test (SMK) | `participant.sml.test.tech.peppol.org` |

`SmpConfig::peppol_production()` and `peppol_test()` carry these. The European
Commission zones (`edelivery.tech.ec.europa.eu`) stopped answering participant
lookups on 31 August 2026 and are not usable.

### Lookup and Register a Runtime P-Mode

```rust
use asx_rs::smp::{HickoryBdxlResolver, SmpClient, SmpConfig, SmpLookupRequest, SmpSignaturePolicy};
use asx_rs::as4::pmode::{PMode, PModeRegistry, MepType, PModeSecurity};
use std::sync::Arc;

async fn build_registry_from_smp(smp_ca_pem: String) -> asx_rs::Result<Arc<PModeRegistry>> {
    // 1. Look up the recipient endpoint via PEPPOL SMP, verifying the response.
    //
    //    An SMP lookup decides where the message goes and which key it is
    //    encrypted to. TLS authenticates the SMP *host*, not the metadata it
    //    serves, so the enveloped XMLDSig must be verified against the
    //    network's SMP CA. `SmpSignaturePolicy` defaults to `Deny` precisely so
    //    this cannot be skipped by omission.
    let config = SmpConfig {
        signature_policy: SmpSignaturePolicy::verify_with_trust_anchors(vec![smp_ca_pem]),
        ..SmpConfig::peppol_test()
    };
    let client = SmpClient::with_config(config)
        // BDXL needs a NAPTR query, which `getaddrinfo` cannot serve. The
        // built-in resolver comes from the `dns` feature; implement
        // `BdxlResolver` yourself to use a DNSSEC-validating or mesh-aware
        // client instead.
        .with_resolver(Arc::new(HickoryBdxlResolver::from_system_config()?));
    let endpoint = client.lookup_endpoint(SmpLookupRequest::new(
        "0088:1234567890123",       // recipient participant ID
        "urn:cen.eu:en16931:2017#compliant#urn:fdc:peppol.eu:2017:poacc:billing:3.0::2.1",
        "urn:fdc:peppol.eu:2017:poacc:billing:01:1.0",
    )).await?;

    // The signature verified: `endpoint.verified_signer_fingerprint_sha256` is
    // `Some`, and the URL and certificate below really came from the network's SMP.

    // 2. Validate the SMP-provided certificate against your trust anchors before use.
    //    The certificate_der_b64 field holds a base64-encoded DER X.509 certificate.
    let partner_cert_pem: String = if let Some(cert_b64) = &endpoint.certificate_der_b64 {
        // Convert DER → PEM (pseudocode; use openssl::x509::X509::from_der in production).
        format!("-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n", cert_b64)
    } else {
        return Err(asx_rs::AsxError::new(
            asx_rs::ErrorCode::InvalidInput,
            "SMP endpoint has no certificate",
            asx_rs::ErrorContext::new("smp_lookup"),
        ));
    };

    // 3. Build a P-Mode from the resolved endpoint.
    let pmode = PMode {
        partner_id:      "partner-acme".to_string(),
        service:         "urn:cen.eu:en16931:2017#compliant#urn:fdc:peppol.eu:2017:poacc:billing:3.0::2.1".to_string(),
        action:          "urn:fdc:peppol.eu:2017:poacc:billing:01:1.0".to_string(),
        mep:             MepType::OneWayPush,
        endpoint_url:    endpoint.url.clone(),
        security:        PModeSecurity {
            sign:    true,
            encrypt: false, // PEPPOL BIS Billing 3.0 mandates sign-only
            ..Default::default()
        },
        ..Default::default()
    };

    // 4. Register the P-Mode for use at send time.
    let mut registry = PModeRegistry::new();
    registry.register(pmode);
    Ok(Arc::new(registry))
}
```

### Verifying the SMP response

`SmpSignaturePolicy` controls how a `ServiceMetadata` response is authenticated:

| Variant | Meaning |
|---|---|
| `Deny` (**default**) | Refuse to use the lookup result. An unverified response does not silently become a routing decision. |
| `Verify(..)` | Verify the enveloped `ds:Signature` and chain the signer to the supplied SMP CA. **Use this on any public network.** |
| `RequireSignaturePresent` | Check that a `ds:Signature` element exists, nothing more. Catches an unsigned SMP and nothing else. |
| `AllowUnsigned` | Accept unsigned responses. Closed and test networks only. |

Under `Verify`, `SmpEndpoint::verified_signer_fingerprint_sha256` names the
signer whose signature was checked; under the weaker policies it is `None` and
the endpoint fields are unauthenticated.

`SmpConfig::peppol_test()` and `peppol_production()` carry the network's
identity — SML zone, participant scheme, transport profile — but not its trust
anchors, which belong to your deployment. Set `signature_policy` yourself.

### Discovery modes

| Mode | Finds the SMP by |
|---|---|
| `SmlDiscovery::Naptr` (**default**) | A BDXL U-NAPTR record in the SML zone. Needs a `BdxlResolver`. |
| `SmlDiscovery::LegacyCname` | `https://B-<md5>.<scheme>.<zone>/` used directly. Closed networks only — the public Peppol zones do not publish these records. |
| `SmlDiscovery::Static { .. }` | A fixed SMP base URL — a bilateral agreement or a test SMP. No DNS, no resolver. |

`SmpClient::discovery_dns_name(participant_id)` returns the name a lookup will
query — worth logging, since an unregistered participant and a misconfigured
zone look identical otherwise.

### SSRF Considerations

The SMP URL is validated **and pinned** to the addresses that were checked
before any request is issued, so a host that passed validation cannot be
swapped for a private address on the connection.

With NAPTR discovery the SMP URL comes *out of a DNS record*, so the record
decides where metadata is fetched from. A U-NAPTR replacement is taken
literally: backreferences are refused (RFC 4848 §2.2 forbids them), and a
non-`https` replacement is refused rather than used.

DNSSEC validation is the resolver's job — the Peppol SML zones are signed;
supply a validating `BdxlResolver` if you need it. `sml_zone` is
operator-controlled; never pass user-supplied data as the SML zone.

### Certificate Pinning After SMP Lookup

Always validate the certificate returned by SMP before adding it to a
`SessionContext`:

1. Decode the `certificate_der_b64` field and parse it with `openssl::x509::X509::from_der`.
2. Check the certificate against your PEPPOL trust anchor (e.g. the PEPPOL
   Intermediate CA certificate for the relevant PKI zone).
3. Only then construct a `CertHandle` with `fingerprint_sha256` set to the
   certificate's SHA-256 fingerprint and `trust_anchor_pems` containing your
   validated PEPPOL root CA.

Accepting an SMP certificate without trust-anchor validation exposes you to
SMP-layer MITM attacks.

### Refreshing P-Modes

SMP endpoint records are time-limited (see `service_expiration_date`).
Implement a background task that re-resolves expiring or expired entries and
calls `PModeRegistry::register` on a new registry instance, then swaps the
`Arc<PModeRegistry>` atomically.  Because `PModeRegistry` is immutable after
construction, in-flight sends always use a consistent snapshot.
