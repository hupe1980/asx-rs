# Changelog

All notable changes to `asx-rs` are documented here.

Each entry separates the two kinds of change that matter to an integrator:

- **Wire / crypto behaviour** — what goes on the network, or what is accepted
  from it. These can break interop with a counterparty even when your code
  compiles unchanged.
- **API** — signatures, types and feature gates. These break the build, which
  is the safe direction.

Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning follows the [SemVer policy](#semver-policy) below.

---

## [0.11.0] — unreleased

Driven by integrator feedback from a BDEW Marktkommunikation deployment.

### Added

**API — AS4 receipt verification.** The send path can now verify the
counterparty's synchronous signal, closing the gap that forced consumers to
substring-scan the SOAP response and left Non-Repudiation of Receipt unchecked
end to end.

- `as4::verify_sync_response(session, bus, sent, body, content_type, policy)`
  → `As4SyncSignal` — namespace-correct, CDATA-aware parsing of the response;
  verifies the receipt signature *and that the signature covers the signal
  acted on*, checks `RefToMessageId` against the sent message, verifies every
  `MessagePartNRInformation` digest against the digests the sent message was
  actually signed over, and enforces a replay window on `eb:Timestamp`.
- `As4HttpTransport::send_and_verify(...)` → `As4SendAndVerifyOutcome` — send
  and verify in one call. `send_and_verify_to_localhost` under `testing`.
- New types: `As4ReceiptPolicy` (`regulated()` / `strict()` / `relaxed()`),
  `As4SyncSignal`, `As4VerifiedReceipt`, `As4NonRepudiation`, `As4ErrorSignal`,
  `As4ReceivedError`, `As4SendAndVerifyOutcome`.
- An `eb:Error` response is returned as typed `As4SyncSignal::Error` with the
  ebMS3 code, severity and description intact — not as "no receipt found" — so
  retry-vs-dead-letter routing can key on the actual reason.
  `As4SyncSignal::into_receipt()` collapses it to an error when the distinction
  does not matter.
- `As4ErrorCode::from_ebms_code` and `As4ErrorSeverity::from_ebms_severity` map
  received values onto the modelled variants; unmodelled codes keep their raw
  string rather than being dropped. A missing `severity` attribute is treated as
  a failure, not silently downgraded to a warning.

**API — regulated inbound decryption.** The
`inbound_decryption_key_pem` / `require_encrypted_inbound` invariant can no
longer be split across two calls:

- `As4PushPolicy::regulated_with_decryption_key(pem)`
- `As4PushPolicyBuilder::regulated()`
- `As4PushPolicyBuilder::with_mandatory_inbound_encryption(pem)`

**API — testing.** `MockAs4EndpointBuilder::with_receipt_signing_material(cert_pem, key_pem)`
makes the mock answer with a *signed* receipt whose `MessagePartNRInformation`
echoes the inbound signature, so the full NRR round trip is exercisable without
real PKI.

### Changed

**API (breaking) — AS2-only fields removed from the shared `ValidationPolicy`.**
`ValidationPolicy::require_as2_mic` moved to a new
`As2ValidationPolicy { require_mic }`. AS4 profiles no longer carry — or have to
explicitly disable — a knob that cannot apply to them.

- `ValidationPolicy` loses `require_as2_mic`.
- `BaseProfile`, `EffectiveProfile` and `EffectivePolicySnapshot` gain
  `as2_validation: As2ValidationPolicy`.
- `ProfilePolicyOverrides` gains `as2_validation: Option<As2ValidationPolicy>`.
- `ResolutionField` gains the `As2Validation` variant.

Migration:

```rust
// before
ValidationPolicy { require_as2_mic: false, ..Default::default() }
// after
As2ValidationPolicy { require_mic: false }
```

Serialized `RegionalProfilePack` JSON keeps deserializing: `as2_validation` is
`#[serde(default)]` and a stale `require_as2_mic` key inside `validation` is
ignored. Profile-diff risk grading is unchanged — an AS2 MIC change stays
`Medium` / non-blocking, exactly as when the field lived in `ValidationPolicy`.

**Wire / API (breaking) — oversize payloads now report `PayloadTooLarge`.**
`wire::enforce_payload_limit` returned `ErrorCode::PolicyViolation`, which maps
to HTTP 403 and reported an oversize body as an authorization failure. It now
returns `ErrorCode::PayloadTooLarge` (HTTP 413), matching
`transport::ingress`. Affects the AS2 receive, AS2 MDN, AS4 receive and bounded
stream paths. Callers matching on `PolicyViolation` for size failures must
update.

### Fixed

**Docs — fragment scope policy.** The `as4::receive` module docs stated
that `authenticated_sender_scope` "**must** be `Some(_)`" under the default
`FragmentScopePolicy::RequireAuthenticatedScope`, without saying that the policy
is consulted for **fragmented messages only**. Non-fragmenting profiles (BDEW
MaKo among them) were switching to `UseSoapSenderId` to make a `None` scope
"safe" when it already was — a change that only weakens the policy if a fragment
ever arrives. No behaviour change; docs corrected on `FragmentScopePolicy`,
`As4PushPolicy::fragment_scope_policy` and `As4PushPolicy::regulated`, and
pinned by a regression test.

### Security

**XML Signature Wrapping on AS4 receipts — inbound path fixed, outbound path
hardened at introduction.**

The inbound receipt check (`receipt_payload` on `As4ReceivePushRequest`, present
since the receipt-verification feature shipped) verified that *a* signature on
the response was valid, but never bound that signature to the `eb:Messaging`
block whose `RefToMessageId` it then trusted. A counterparty could leave a
genuinely signed element in place — so the signature still verified against the
pinned certificate — and add an unsigned element acknowledging a different
message. The `eb:UserMessage` path already had this defence; the receipt path
did not.

Both the inbound and the new outbound path now require that the
`eb:SignalMessage` acted on is itself covered by the verified signature, either
directly or through a signed ancestor (both `eb:Messaging`-signed and
`eb:SignalMessage`-signed receipts are conformant and both are accepted).

Deployments consuming `receipt_payload` should treat this as a security fix.
Receipts that were previously accepted and are now rejected with
`SecurityVerificationFailed` were not proving what they appeared to prove.

Alongside it, the shared signal parser now rejects the structural shapes that
make a signal ambiguous:

- more than one `eb:Messaging` block, or more than one `eb:SignalMessage`
  (bundled signals cannot be unambiguously correlated to one sent message);
- a repeated `eb:MessageId` / `eb:RefToMessageId` / `eb:Timestamp`, which
  first-wins extraction would let an injected duplicate shadow;
- `NonRepudiationInformation` outside the `eb:Receipt` it belongs to;
- a signal carrying both an `eb:Receipt` and an `eb:Error`.

Further hardening in the new outbound path:

- Receipt Non-Repudiation is genuinely verified rather than assumed. A receipt
  whose digests do not match the sent message is rejected with
  `SecurityVerificationFailed`; there is no result variant that lets a mismatch
  pass as a value the caller can ignore.
- Receipt signatures are verified against the session's pinned partner
  fingerprint, trust anchors and revocation policy — the same material the
  inbound path uses. A `ds:Signature` that is not a verifiable enveloped
  signature is a verification failure, never a downgrade to "unsigned".
- A receipt with **no** `eb:Timestamp` is rejected while a freshness window is
  configured, so the replay guard cannot be bypassed by dropping the element.
- An `eb:Error` whose correlation points at a different message is rejected
  instead of being attributed to this one, which would dead-letter a message the
  counterparty never rejected.
- Receipt parsing is bounded (256 KiB default, element-count cap, capped NRI and
  error entries) and rejects duplicate `MessagePartNRInformation` URIs, which
  could otherwise let a hostile MSH satisfy the digest check with one entry while
  smuggling a second.

Note that `As4SyncSignal::Error` reports what the connection returned, not a
proven fact: error signals are typically unsigned. Only
`As4VerifiedReceipt::is_non_repudiation_evidence()` asserts a cryptographically
proven outcome.

---

## [0.10.0] — 2026-07-20

### Added

- **Wire / API** — signed AS4 receipts (Non-Repudiation of Receipt):
  `generate_signed_receipt_with_nri`, `generate_signed_receipt_for_output`, and
  the `As4ReceiptCredentials` type. Receipts now carry a WS-Security XML
  Signature over `eb:Messaging` and the SOAP Body as required by profiles such
  as BDEW AS4-Profil §2.2.4.

---

## [0.9.0] — 2026-07-19

### Changed

- **Wire / crypto** — security hardening audit: SSRF egress guard, XML Signature
  Wrapping defences and signed-metadata enforcement, and crypto conformance
  fixes.

---

## [0.8.0] — 2026-07-19

### Added

- **API** — `SessionContextBuilder::with_signing_material(cert, key)`; `key_id`
  is derived as `cert:{partner_id}` (was: hand-built `CertHandle` plus a
  `zeroize` dependency in consumer code).
- **API** — `MockAs4Endpoint::builder().with_decryption_key_pem(pem)` for
  encrypt round-trip tests.
- **API** — `EventBus::new_for_testing()`, zero-config `BestEffort`.
- **API** — `As4HttpTransport::new_for_localhost_testing()`, an explicit opt-out
  from the SSRF URL guard for loopback tests.
- **API** — partial `As4SendCredentials`: supplying only `recipient_cert_pem`
  now falls back to the session signing certificate.

---

## [0.7.0] — 2026-07-16

### Changed

- **Wire / crypto** — ECDH-ES key agreement is auto-detected from the recipient
  certificate's key type: EC → ECDH-ES + ConcatKDF + AES key wrap, RSA →
  RSA-OAEP. No configuration required.

---

## [0.6.0] — 2026-07-16

### Added

- **API** — testing primitives: `InsecureBypassAs4Verifier`, `MockAs4Endpoint`,
  and self-signed EC/RSA keypair generators under the `testing` feature.

---

## [0.5.0] and earlier

Pre-`0.5.0` history is not reconstructed here; see the git log. Entries for
`0.6.0`–`0.10.0` above were reconstructed from release tags and are summaries
rather than exhaustive lists. `0.11.0` onward are written at release time.

---

## SemVer policy

`asx-rs` is pre-`1.0`, so under Cargo's rules a **minor** bump (`0.x` → `0.x+1`)
is the compatibility-breaking one. This project uses that slot deliberately:

| Change | Version bump |
|---|---|
| Breaking API change (signature, type, removed item, feature gate) | minor — `0.10.0` → `0.11.0` |
| Change to bytes on the wire, or to what is accepted from the wire | minor — even when the Rust API is untouched |
| Tightening a security default (rejecting something previously accepted) | minor |
| New API, new opt-in policy field with a backward-compatible default | minor |
| Bug fix, doc fix, internal refactor, performance work | patch — `0.11.0` → `0.11.1` |

Two consequences worth stating explicitly:

1. **A wire-behaviour change is never a patch release.** A counterparty can
   start rejecting your messages without a single line of your code changing, so
   crypto and protocol changes always get their own minor version and a
   "Wire / crypto behaviour" entry above.
2. **Security defaults tighten in minor releases, not patches.** If a release
   starts rejecting something it previously accepted, it is a minor bump and the
   entry says so — pin exactly (`asx-rs = "=0.11.0"`) if you need to schedule
   that.

Pinning guidance: `asx-rs = "0.11"` tracks patches only. Read the wire/crypto
entries before moving between minor versions.

The `testing` feature is exempt from all of the above — it is never for
production builds and its API may change in any release.
