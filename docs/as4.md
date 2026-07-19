# AS4 Protocol Reference

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
| EC (NIST P-256/P-384/P-521, BrainpoolP256r1/P384r1) | ECDH-ES ephemeral + ConcatKDF (NIST SP 800-56A §5.8.1) + AES-128 Key Wrap (RFC 3394) | `X509SKI` | BDEW AS4-Profil §2.2.6.2.2, BSI TR-03116-3 §9.2 |

### EC encryption XML structure

When the recipient has an EC key the outbound `<xenc:EncryptedKey>` uses:

```xml
<xenc:EncryptedKey>
  <xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#kw-aes128"/>
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
| keydatalen | 128 bits (for kw-aes128) | Derived from key-wrap algorithm |
| AlgorithmID | `""` (empty) | BDEW AS4-Profil / BSI TR-03116-3 |
| PartyUInfo | `""` | BDEW AS4-Profil |
| PartyVInfo | `""` | BDEW AS4-Profil |

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
    pub fragment_scope_policy: FragmentScopePolicy,
}
```

### Builder example — regulated deployment with mandatory encryption

```rust
let policy = As4PushPolicyBuilder::new()
    .inbound_decryption_key_pem(my_ec_private_key_pem)
    .require_encrypted_inbound(true)  // ← reject unencrypted messages fail-closed
    .build()?;
```

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
| `outbound_key_info_profile` | `X509DataAndRsaKeyValue` | Use `X509PKIPathv1` for BDEW |
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

1. SOAP envelope is generated and adapted for XOP/cid references.
2. MIME package is emitted as `multipart/related` output.
3. WS-Security signatures include detached payload reference for MIME attachment.
4. Optional XML encryption is applied before outbound packaging.

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
) -> Result<As4ReceivePushOutput>
```

### Receive pull with reliability

```rust
pub async fn receive_pull_with_reliability(
    session: &SessionContext,
    event_bus: &EventBus,
    request: As4ReceivePullWithReliabilityRequest<'_>,
) -> Result<As4ReceivePullOutput>
```

### Token-enforced strict runtime sessions

For regulated deployments that require explicit startup proof, bind validated
session context once and then use standard AS4 entry points:

```rust
let strict_session = asx_rs::presets::session_with_strict_runtime_bootstrap_token(
    "as4_receive_push_sync",
    &bootstrap_token,
    &session,
)?;

let out = asx_rs::as4::receive_push_with_dedup_sync(
    &strict_session,
    &event_bus,
    asx_rs::as4::As4ReceivePushSyncRequest {
        request,
        dedup_backend,
    },
)?;
```

In non-testing builds, strict interop AS4 entry points fail closed unless the
session is startup-validated with
`asx_rs::presets::session_with_strict_runtime_bootstrap_token(...)`.

### Strict production clustered topology gate

`As4PullStore` and `As4ConversationOrderGate` are process-local components.
Before accepting traffic in clustered deployments, fail closed unless you have
distributed replacements:

```rust
use asx_rs::presets::{
    DeploymentTopology,
    validate_strict_production_as4_topology_readiness,
};

validate_strict_production_as4_topology_readiness(
    "startup",
    DeploymentTopology::Clustered,
    Some(pull_store),
    Some(conversation_gate),
)?;
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

`generate_receipt`, `generate_receipt_with_nri`, `generate_error_signal`, and
`generate_pull_request` are available in `asx_rs::as4`.

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

## Interop Notes

1. Strict mode is default and recommended.
2. Relaxed interop remains available by feature/profile policy for scoped exceptions.
3. Inbound payloads must be multipart/related with detached attachment bytes.
4. Signed inbound messages are validated in pinned-sender mode and require `SessionContext.cert_handle.fingerprint_sha256` to be configured.

## Test Service and P-Mode

`asx_rs::as4::test_service` and `asx_rs::as4::pmode` provide profile/test-service helpers for standards-aligned partner agreements and conformance workflows.

## SMP Integration: Dynamic Partner Discovery (PEPPOL / CEF)

In PEPPOL and CEF eDelivery networks, Access Points (APs) discover each other
dynamically via the **Service Metadata Publisher (SMP)** protocol
([OASIS BDX SMP 1.0](https://docs.peppol.eu/edelivery/smp/)).  Before sending
an AS4 message, the sender resolves the recipient's endpoint URL and signing
certificate from the SMP.

Enable the `smp` module with the `client` feature:

```toml
asx-rs = { version = "0.8", features = ["as4", "client", "async-ocsp"] }
```

### Lookup and Register a Runtime P-Mode

```rust
use asx_rs::smp::{SmpClient, SmpLookupRequest};
use asx_rs::as4::pmode::{PMode, PModeRegistry, MepType, PModeSecurity};
use std::sync::Arc;

async fn build_registry_from_smp() -> asx_rs::Result<Arc<PModeRegistry>> {
    // 1. Look up the recipient endpoint via PEPPOL SMP.
    let client = SmpClient::new("acc.edelivery.tech.ec.europa.eu");
    let endpoint = client.lookup_endpoint(SmpLookupRequest::peppol(
        "0088:1234567890123",       // recipient participant ID
        "urn:cen.eu:en16931:2017#compliant#urn:fdc:peppol.eu:2017:poacc:billing:3.0::2.1",
        "urn:fdc:peppol.eu:2017:poacc:billing:01:1.0",
    )).await?;

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

### SSRF Considerations

The SMP client validates the constructed URL (scheme, host, path) before
making any network request.  The `sml_zone` value in `SmpClient::new(...)` is
**operator-controlled** — never pass user-supplied data as the SML zone.  See
the `smp` module documentation for the full SSRF mitigation notes.

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
