# Security Model

## Design Principles

1. **Fail-closed by default** — absent configuration causes rejection, not acceptance.
2. **Explicit trust transitions** — trust is not implicit; it must be established at each cryptographic stage.
3. **No silent bypasses** — signature verification results are always propagated; `let _ = verify(...)` is forbidden.
4. **Algorithm agility with compliance first** — AS4 WS-Security runtime verification is strict-only (no legacy inbound fallback paths); any non-default compatibility behavior must be explicit and scoped through interop policy outside WS-Security cryptographic verification.

---

## Certificate and Trust Configuration

All certificate and trust material is carried in `CertHandle`, which is set on `SessionContext` via `.with_cert_handle(handle)`.

```rust
pub struct CertHandle {
    pub signing_key_pem: String,          // PEM private key for signing (AS2 S/MIME or AS4 WS-Security)
    pub signing_cert_pem: String,         // PEM certificate corresponding to signing_key_pem
    pub encryption_cert_pem: String,      // PEM certificate for encrypting to this party
    pub trust_anchor_pems: Vec<String>,   // PEM CA certificates for PKIX chain validation
    pub fingerprint_sha256: String,       // Expected SHA-256 fingerprint of partner's signing cert (empty = pinning disabled)
    pub ocsp_config: OcspConfig,          // OCSP mode and responder override
}
```

### PKIX chain validation

When `RevocationPolicy::require_chain_validation = true` (the default when at least one trust anchor is provided), all signer certificates are validated against `trust_anchor_pems` using PKIX chain building. An empty `trust_anchor_pems` with `require_chain_validation = true` **fails closed** — no certificate will pass validation.

To explicitly allow any certificate (testing only):
```rust
RevocationPolicy {
    require_chain_validation: false,
    trust_anchor_pems: vec![],
    ..Default::default()
}
```

### Certificate fingerprint pinning

When `fingerprint_sha256` is non-empty, the signer certificate's SHA-256 fingerprint is compared against this value after PKIX validation. A mismatch fails the receive.

For AS4 push receive, `As4PushPolicy` now controls trust mode explicitly:
1. Pinned sender mode: requires `fingerprint_sha256` to be configured for signed inbound message verification.

```rust
CertHandle {
    fingerprint_sha256: "AA:BB:CC:...".to_string(),  // enforce pinning
    ..
}
```

---

## OCSP (Online Certificate Status Protocol)

OCSP is configured per session via `OcspConfig` in `CertHandle`:

```rust
pub struct OcspConfig {
    pub mode: OcspMode,
    pub responder_override: Option<String>,  // Optional URL override
}

pub enum OcspMode {
    Disabled,
    Required,
    BestEffort,  // OCSP failure does not fail the receive
}
```

OCSP responses are fetched via `reqwest` (`async-ocsp` feature, enabled by default). The async path (`fetch_ocsp_responses_with_cache_async*`) is the preferred entry point and runs entirely on the caller's Tokio runtime with no additional thread overhead. The sync compatibility wrapper (`fetch_ocsp_responses_with_cache_provider_scoped`) bridges into async by using `tokio::task::block_in_place` + `block_on` on the current runtime handle — no dedicated OS thread is spawned. Responses are cached (`ProcessLocalOcspResponseCache`, 5-minute TTL, max 512 entries with lazy eviction) to minimise live round-trips — in steady state, most certificate checks are served from cache.

### Response freshness

OCSP responses are validated for freshness:
- `thisUpdate` must be within 300 seconds of the current time (clock skew tolerance).
- `nextUpdate` must not be more than 86400 seconds (24 hours) in the past.

Stale or expired OCSP responses are rejected.

---

## Cryptographic Algorithms

### AS2 (S/MIME)

| Operation | Algorithm |
|---|---|
| Signing | S/MIME CMS — RSA + SHA-256 |
| Encryption | S/MIME CMS — AES-256 CBC (or AES-128-GCM for newer partners) |
| MIC computation | SHA-256 over `Content-Type: …\r\n\r\n<payload>` (RFC 4130 §7.3.1) |

### AS4 (WS-Security / XML Encryption)

| Operation | Algorithm | URI |
|---|---|---|
| Payload encryption (outbound) | AES-256-GCM (XMLenc11) | `http://www.w3.org/2009/xmlenc11#aes256-gcm` |
| Payload encryption (inbound) | AES-128-GCM or AES-256-GCM (XMLenc11) | `http://www.w3.org/2009/xmlenc11#aes128-gcm`, `http://www.w3.org/2009/xmlenc11#aes256-gcm` |
| Key transport | RSA-OAEP (XMLenc11) | `http://www.w3.org/2009/xmlenc11#rsa-oaep` |
| Key transport MGF | MGF1-SHA256 | `http://www.w3.org/2009/xmlenc11#mgf1sha256` |
| Key transport digest | SHA-256 | `http://www.w3.org/2001/04/xmlenc#sha256` |
| XML Signature | RSA-SHA256 | `http://www.w3.org/2001/04/xmldsig-more#rsa-sha256` |
| Canonicalization | Exclusive C14N | `http://www.w3.org/2001/10/xml-exc-c14n#` |

ASX uses **AES-256-GCM** (authenticated encryption) for outbound AS4 encryption and accepts only XMLenc11 AES-GCM inbound. Legacy AES-CBC and XMLenc 1.0 OAEP variants are rejected fail-closed to reduce downgrade and padding-oracle risk.

---

## WS-Security XML Signatures

### Canonicalization (C14N)

WS-Security signature computation uses XML Exclusive C14N (W3C `exc-c14n`). The implementation:
- Correctly handles namespace propagation for visibly-utilized namespaces.
- Forwards processing instruction nodes (`<?target data?>`).
- Implements `InclusiveNamespaces PrefixList` per W3C Exc-C14N §2.1 — ancestor namespace bindings for listed prefixes are rendered even when not directly utilized at the element.
- Strips comments in default mode; preserves them when `include_comments = true`.
- Sorts attributes in lexicographic order (namespace URI, local name) as required by C14N.

Validated against W3C C14N test vectors (namespace propagation, attribute ordering, text/attribute escaping, PI forwarding, comment stripping, comment preservation).

### Signed scope and XML Signature Wrapping defence

The AS4 push signature covers **three** references: the entire `eb:Messaging`
header block (`wsu:Id="as4-messaging"` — all `UserMessage` routing/authorization
metadata: From, To, Service, Action, MPC, MessageProperties, PartInfo), the SOAP
Body, and a detached `cid:` reference for the MIME payload attachment. (Earlier
revisions signed only `ebms:MessageId`, leaving the routing metadata tamperable.)

On receive, verification returns the set of verified same-document `wsu:Id`s and
the AS4 layer requires that the document contains **exactly one** `eb:Messaging`
block whose `wsu:Id` is in that set. This binds the block the pipeline routes on
to the block the signature actually covered, defeating XML Signature Wrapping
(relocating the signed element and injecting an unsigned replacement).

### Signature verification

Signature verification uses:
1. Digest verification over C14N-serialized referenced elements.
2. RSA/ECDSA signature verification using `secure_eq` (constant-time comparison) for digest values.
3. Minimum signing-key strength enforcement (RSA `< 2048` bits is rejected).
4. PKIX chain validation of the signing certificate.
5. OCSP status check (if configured).
6. Binding of the consumed `eb:Messaging` block to the verified signature (above).

Verification is fail-closed: any error at any step propagates immediately via `?`. The caller cannot ignore a failed verification.

### `wsu:Timestamp` validation

Inbound WS-Security timestamps are validated:
- `wsu:Created` must be within 5 minutes of the current time.
- `wsu:Expires` (if present) must not be in the past.

Outbound timestamps include `wsu:Created` (now) and `wsu:Expires` (now + 5 minutes).

---

## `InsecureBypassTrustVerifier`

```rust
use asx_rs::lifecycle::InsecureBypassTrustVerifier;
```

**For testing only.** This verifier passes any payload as fully trusted and decryptable without performing any cryptographic checks. Its name is intentionally explicit.

Never use `InsecureBypassTrustVerifier` in production. It bypasses:
- Signature verification
- PKIX chain validation
- OCSP status checking
- Fingerprint pinning

---

## Payload Size Limits

All inbound reads are bounded. The default limit is **256 MiB** (`DEFAULT_MAX_BODY_BYTES`). This applies to:
- `asx_rs::as2::receive_with_mdn_with_reliability`
- `asx_rs::as4::receive_push_with_dedup_sync`
- `transport::server` layer (axum handlers)

Override per-session:
```rust
As2PushPolicy::builder().max_body_bytes(64 * 1024 * 1024)  // 64 MiB
```

---

## Temp File Security

Streaming receive operations that require on-disk spooling (e.g., for signature verification rewinding) use `tempfile::NamedTempFile` for atomic, exclusive temp file creation. This prevents symlink attacks on world-writable `/tmp`.

---

## Operator Hardening Expectations (Core Dumps and Host Memory)

ASX zeroizes owned private-key PEM buffers on drop where possible, and recent send-path refactors minimize transient key-buffer duplication. However, ASX is only a library and cannot enforce host OS process-dump policy, swap policy, or debugger attach policy.

Production operators are expected to harden runtime environments accordingly:

1. Disable process core dumps for ASX-hosting services (for example `ulimit -c 0`, systemd `LimitCORE=0`, container runtime equivalents).
2. Restrict dumpability and ptrace/debug attachment to trusted operators only.
3. Ensure swap/pagefile policy is encrypted or disabled for regulated deployments handling private keys.
4. Keep crash-reporting pipelines from uploading raw process memory unless a formally approved secret-scrubbing policy is in place.

These controls are mandatory complements to in-process zeroization when handling cryptographic private key material in production.

---

## Known Limitations

| Limitation | Mitigation |
|---|---|
| Custom XML Exclusive C14N implementation | Validated against W3C test vectors and interop compatibility matrix; not yet replaced by a vetted library |
| In-memory dedup provides no replay protection across restarts | Use `TtlDedupStorage` with a distributed backend for production; document required 48h window per RFC 4130 §5.2.1 |
| No TLS mutual authentication (mTLS) at the library level | Configure mTLS at the TLS terminator / reverse proxy layer |
| OCSP `thisUpdate`/`nextUpdate` clock skew tolerance is fixed at ±300s / 86400s | Adjust via `OcspConfig` if partner OCSP responders have larger clock drift |
| OCSP sync wrapper uses `block_in_place`/`block_on` (not a new OS thread) — must be called from a multi-thread Tokio runtime | Use the async `fetch_ocsp_responses_with_cache_async` entry point directly from async call sites; at very high message rates with many distinct certificates, consider a shared persistent OCSP cache backend |

---

## Crypto Backend Roadmap

### Current State: Mixed OpenSSL + Pure-Rust

`asx-rs` currently uses two separate crypto ecosystems:

| Subsystem | Current backend | Role |
|---|---|---|
| AS2 S/MIME signing / encryption | `openssl` (C FFI) | CMS `SignedData` / `EnvelopedData` |
| AS4 WS-Security XML signing | `openssl` (C FFI) | RSA-SHA256 `ds:Signature`, RSA-OAEP key wrap |
| AS4 payload symmetric encryption | `aes-gcm` (pure Rust) | AES-128/256-GCM `xenc:EncryptedData` |
| X.509 certificate parsing | `openssl` (C FFI) | Trust-anchor validation, chain building, OCSP |

This mixed model has several implications:

- **Build system**: consumers must have a working OpenSSL installation (or
  accept the `openssl-sys` vendored build). Cross-compilation (e.g., to
  `x86_64-unknown-linux-musl` static binaries) requires extra care.
- **FIPS compliance**: OpenSSL can be compiled in FIPS mode; the `aes-gcm`
  crate is *not* FIPS 140-2 validated. Regulated deployments (US federal,
  healthcare) requiring FIPS-validated crypto across **all** algorithms must
  either replace `aes-gcm` with the OpenSSL AES-GCM primitives or wait for
  the pure-Rust migration path below.
- **Vulnerability management**: OpenSSL and `aes-gcm` have separate CVE
  timelines and patch cadences. Both must be tracked independently.

### Migration Path: Full Pure-Rust Crypto

The long-term goal is to eliminate the OpenSSL C-FFI dependency and converge
on a single pure-Rust crypto stack. The planned migration path is:

1. **Phase 1 (in progress)**: Symmetric crypto is already pure Rust (`aes-gcm`).
2. **Phase 2**: Replace OpenSSL X.509 parsing with `x509-cert` + `rustls-pki-types`.
3. **Phase 3**: Replace OpenSSL RSA operations (CMS key wrap, WS-Security signing)
   with `rsa` (pure Rust) or `aws-lc-rs` (FIPS-validated pure-Rust interface).
4. **Phase 4**: Remove the `openssl` crate dependency entirely. Provide an
   optional `openssl-fips` feature gate for regulated environments that require
   FIPS 140-2 validated modules.

> **Note**: Phases 2–4 are pre-1.0 roadmap items and will be treated as
> breaking-dependency changes. Subscribe to the GitHub releases feed or
> `CHANGELOG.md` for status.

### FIPS Deployment Today

If you need FIPS-validated crypto today, use the following configuration:

1. Compile OpenSSL in FIPS mode (OpenSSL 3.x with `OPENSSL_FIPS=1`).
2. Do **not** enable AS4 XML encryption (set `As4SendPolicy { encrypt: false, .. }` for
   outbound; for inbound, `As4PushPolicy::default()` already allows unencrypted payloads
   when none arrive encrypted), since the `aes-gcm` symmetric layer is not FIPS
   140-2 validated.
3. Contact your compliance officer before enabling AS4 payload encryption in
   a regulated deployment until Phase 3 is complete.


