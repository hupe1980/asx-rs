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

### Receive push

```rust
pub struct As4ReceivePush<'a> {
    pub request: As4ReceivePushRequest,
    pub dedup: Arc<dyn DedupStorage>,
    /// `None` = process on arrival. `Some(gate)` = preserve per-conversation order.
    pub ordering: Option<&'a dyn ConversationOrderGate>,
    /// Which certificate each claimed `eb:From` party may sign with.
    /// `None` falls back to the session's single-partner pin.
    pub signer_pins: Option<Arc<dyn As4SignerPins>>,
}

pub async fn receive_push(
    session: &SessionContext,
    event_bus: &EventBus,
    push: As4ReceivePush<'_>,
) -> Result<As4Ordered<As4ReceiveOutcome>>
```

Parse, signature verification and decryption run on Tokio's blocking pool, so
this is safe to call from an async handler.

> **A signed message from an unpinned sender is refused.** Set `signer_pins`,
> or pin one partner on the session — see
> [certificate fingerprint pinning](@/docs/security.md#certificate-fingerprint-pinning-required-not-optional).

**Ordering is a field, not a different function.** Whether a deployment
preserves per-conversation arrival order (ebMS3 §5.1.5) is a property of that
deployment, so turning it on is a configuration change rather than a call-site
rewrite.

```rust
// Unordered — the common case. The guard holds no turn.
let outcome = receive_push(&session, &bus, As4ReceivePush {
    request,
    dedup,
    ordering: None,
    signer_pins: None,   // session pin; Some(..) for many partners
})
.await?
.into_inner();
```

```rust
// Ordered — the same call, with a gate.
let ordered = receive_push(&session, &bus, As4ReceivePush {
    request,
    dedup,
    ordering: Some(&gate),
    signer_pins: None,
})
.await?;

if let As4ReceiveOutcome::FirstSeen { output, .. } = ordered.get() {
    application.deliver(output).await?;   // turn still held
}

drop(ordered);                            // next message may proceed
```

Two properties the ordered signature encodes:

- **The place in the queue is taken on arrival.** The `eb:ConversationId` is
  read from the raw bytes with a bounded scan *before* parse, verification and
  decryption, which still run in parallel across messages.
- **The turn is held until you drop it.** `As4Ordered<T>` is a guard — deliver
  the message while you hold it.

### Receive push (fragments)

```rust
pub async fn receive_push_fragment_aware(
    session: &SessionContext,
    event_bus: &EventBus,
    push: As4ReceivePush<'_>,
    fragments: Arc<Mutex<As4FragmentJoiner>>,
) -> Result<As4Ordered<As4ReceivePushProgress>>
```

Fragment-awareness *is* a different method, because it is the axis that changes
the answer: an incomplete group produces `As4ReceivePushProgress::PendingFragment`,
which `receive_push` has no way to report. Only a completed message takes a turn.

### The Peppol envelope (SBDH)

Peppol carries the business document inside a Standard Business Document
Header, and its parameters live in `BusinessScope` as `<Scope>` entries. An
envelope without `DOCUMENTID` and `PROCESSID` is rejected by every access
point.

```rust
use asx_rs::sbdh::{SbdhScope, StandardBusinessDocument, peppol_scope};

let header = SbdhHeader {
    // ... sender, receiver, document_identification ...
    business_scope: vec![
        SbdhScope::with_scheme(
            peppol_scope::DOCUMENT_ID,
            "urn:oasis:names:specification:ubl:schema:xsd:Invoice-2::Invoice##urn:cen.eu:en16931:2017#compliant#urn:fdc:peppol.eu:2017:poacc:billing:3.0::2.1",
            "busdox-docid-qns",
        ),
        SbdhScope::with_scheme(
            peppol_scope::PROCESS_ID,
            "urn:fdc:peppol.eu:2017:poacc:billing:01:1.0",
            "cenbii-procid-ubl",
        ),
        SbdhScope::new(peppol_scope::COUNTRY_C1, "BE"),
    ],
    ..header
};

let wrapped = StandardBusinessDocument { header, payload }.wrap()?;
```

Reading them back:

```rust
let doc = StandardBusinessDocument::unwrap(&bytes)?;
let process = doc.header.scope_value(peppol_scope::PROCESS_ID);
```

`Scope` is the whole extensibility mechanism — reserved Peppol keys and your
own attributes share it. [`peppol_scope`] has the reserved ones, including
`MLS_TO` and `MLS_TYPE` for the Message Level Status customisations that Peppol
Network Policy 1.0.0 made mandatory.

An empty `business_scope` emits **no** `<BusinessScope>` element, because the
Peppol schema gives `Scope` a lower bound of 1 — an empty container fails
validation.

[`peppol_scope`]: https://docs.rs/asx-rs/latest/asx_rs/sbdh/peppol_scope/

#### Non-XML payloads

The envelope expects XML. A PDF or an EDIFACT interchange needs a wrapper:

```rust
use asx_rs::sbdh::{wrap_binary_payload, wrap_text_payload};

let pdf = wrap_binary_payload(pdf_bytes, "application/pdf", None);
let edifact = wrap_text_payload(interchange, "Application/EDIFACT");
```

Neither is for XML — a plain XML payload goes in directly.

### Synchronous variants

`receive_push_sync` and `receive_push_sync_fragment_aware` take
`As4ReceivePushSync` (no `ordering` — reserving a turn means waiting for it, and
waiting is async) and block on the calling thread.

The `FirstSeen` variant also carries an unsettled `DedupClaim` — settle it once
delivery is durable. See [Reliability](@/docs/reliability.md#deduplication).

| Method | Behaviour |
|---|---|
| `get()` | Borrow the outcome; the turn stays held |
| `holds_turn()` | `false` for a duplicate or an incomplete fragment group — neither is delivered |
| `into_inner()` | Take the outcome and **end the turn** |

The scanned conversation id is unauthenticated, so it is compared against the
verified `eb:ConversationId` after parsing; a mismatch is a
`SecurityVerificationFailed`. A `UserMessage` carrying two `eb:ConversationId`
elements is rejected rather than resolved by document order.

#### A distributed gate

`As4ConversationOrderGate` is in-process. Multi-replica deployments implement
`ConversationOrderGate` over a shared primitive (a Redis lock, a database
advisory lock, a ZooKeeper node), and it is a **two-phase** trait:

```rust
impl ConversationOrderGate for RedisOrderGate {
    // Take a sequence number. Returns immediately — this is arrival order.
    fn reserve_ordered_turn<'a>(&'a self, conversation_id: &'a str, _s: &'a SessionContext)
        -> ReserveTurnFuture<'a> { /* … */ }

    fn record_message_ordering<'a>(/* … */) -> /* … */ { /* … */ }
}

impl ConversationTurnHandle for RedisTicket {
    // Wait for the number's turn. This is where the blocking belongs.
    fn wait_for_turn(self: Box<Self>) -> TurnFuture<'static> { /* … */ }
}
```

Reserving and waiting must be separable, because everything expensive happens
between them. `acquire_ordered_turn` (reserve + wait in one call) is provided
for callers with nothing to overlap.

Mutual exclusion alone is not sequencing: unless all messages for a
`ConversationId` reach the same replica, or the primitive enforces a global
sequence, replicas that receive out of order still deliver out of order.

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

let out = asx_rs::as4::receive_push_sync(
    &strict_session,
    &event_bus,
    asx_rs::as4::As4ReceivePushSync { request, dedup },
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

Signal *verification* on the send side is `verify_sync_response`; see
[AS4 send with receipt verification](@/docs/transport.md#as4-send-with-receipt-verification-recommended).

## Core Types

1. `As4SendPolicy` / `As4SendPolicyBuilder`
2. `As4PushPolicy` / `As4PushPolicyBuilder`
3. `As4PullPolicy`
4. `As4ReceivePushRequest` — the inbound bytes, content type and push policy
5. `As4ReceivePush` — async push receive: the request plus `dedup`, `ordering` and `signer_pins`
6. `As4ReceivePushSync` — the blocking equivalent
7. `As4SendOutput` and `As4ReceivePushOutput`
8. `As4EnqueuePullWithReliabilityRequest`
9. `As4ReceivePullWithReliabilityRequest`
10. `PMode` / `PModeRegistry`
11. `As4ReceiptPolicy` — synchronous-signal verification policy
12. `As4SyncSignal` — verified `eb:Receipt` or typed `eb:Error`
13. `As4VerifiedReceipt` / `As4NonRepudiation` — delivery evidence
14. `As4ErrorSignal` / `As4ReceivedError` — parsed ebMS3 error diagnostics

## Interop Notes

1. Strict mode is default and recommended.
2. Relaxed interop remains available by feature/profile policy for scoped exceptions.
3. Inbound payloads must be multipart/related with detached attachment bytes.
4. Signed inbound messages are validated in pinned-sender mode. Set `As4ReceivePush::signer_pins` to an `As4SignerPins` resolver to pin per partner, keyed on the claimed `eb:From`; with no resolver, `SessionContext.cert_handle.fingerprint_sha256` is the single pin for the session. The session pin also verifies counterparty receipt signatures; override it with `As4ReceiptPolicy::with_expected_signer_fingerprint` when a partner signs receipts with a different certificate.
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
asx-rs = { version = "0.15", features = ["as4", "client", "async-ocsp", "dns"] }
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
            // Peppol uses the Peppol PKI for signature *and* encryption at AS4
            // message level (Peppol AS4 profile §1, §4.7): the encryption
            // certificate is the receiving AP's, fetched from the SMP.
            sign:    true,
            encrypt: true,
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
