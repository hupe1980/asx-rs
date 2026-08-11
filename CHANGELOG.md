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

## [0.13.0] — unreleased

Everything since 0.12.0. It is a **hard cut**: wire format, defaults and APIs
changed without compatibility shims.

### Wire / crypto — AS4

- **Multi-payload send.** `As4SendRequest::additional_payloads` attaches
  further parts, each with its own signed `eb:PartInfo`, `ds:Reference`, and
  per-part compression/encryption; `payload_mime_type` / `payload_content_id`
  control the primary part (eDelivery payload profiles pin both). Attachment
  digests follow the WSS SwA transform by wire content type — XML parts are
  digested over their Exclusive C14N form, `text/*` over CRLF-normalized
  octets — matching WSS4J receivers. Compressed/encrypted parts travel as
  `application/gzip`/`application/octet-stream` while the signed PartInfo
  keeps the original media type.
- **`CompressionType` survives encryption.** The property is emitted whenever
  compression was applied — previously it was suppressed for encrypted
  payloads, so the receiver decrypted and then delivered gzip bytes as the
  business document.
- **SwA packaging.** Outbound messages use the AS4 packaging: an
  `application/soap+xml` root part, an **empty** SOAP Body, and payload
  attachments referenced from the signed `eb:PartInfo href="cid:…"` entries.
  The previous MTOM/XOP shape (`application/xop+xml` root, `xop:Include` in
  the Body) is gone from send — WSS4J-based receivers reject it before
  signature verification — but is still accepted inbound.
- **WSS-conformant KeyInfo by default.** `ds:KeyInfo` now carries a
  `wsse:SecurityTokenReference` to an `X509v3` `wsse:BinarySecurityToken`
  (WSS 1.1.1 §7.7). The BST content is base64(DER) — it previously encoded the
  PEM text, which no consumer could parse. Bare-`ds:X509Data` profiles remain
  selectable for plain-XMLDSig consumers.
- **Complete ebMS3 envelope.** `eb:Role` (schema-mandatory) is always emitted,
  `eb:ConversationId` always present (default `"1"`), and `eb:AgreementRef`,
  `eb:PartyId/@type` (including untyped) and explicit From/To party IDs are
  configurable on the send policy.
- **SwA attachment transform.** `cid:` references declare the WSS
  `Attachment-Content-Signature-Transform` on send and accept it on verify;
  the `Complete` variant is rejected by name.
- **Verification accepts the deployed WSS4J shapes**: `X509v3` and
  `X509PKIPathv1` BinarySecurityTokens resolved via SecurityTokenReference,
  and the `InclusiveNamespaces PrefixList` on `ds:SignedInfo`'s own
  `CanonicalizationMethod` is honored.
- **Exclusive C14N hardening.** Elements and attributes are serialized with
  their source prefixes (correct under same-URI prefix rebinding, which
  Axiom-built envelopes produce); `xmlns=""` undeclarations are rendered per
  Exc-C14N §2.3; whitespace-only text nodes are never stripped.
- **Fail-closed signature resolution.** Documents with multiple `ds:Signature`
  elements resolve to the single signature inside `wsse:Security` or are
  rejected as ambiguous — never picked by document order.
- **XML Encryption.** `ConcatKDFParams` attributes are decoded as hexBinary
  bit-strings per XML Encryption 1.1 (previously base64, which silently
  mis-decoded conformant peers' values); RFC 3394 key wrap supports
  128/192/256-bit KEKs sized to the content key; AES-256 content keys are no
  longer wrapped under 128-bit KEKs.
- **Compression is integrity-protected.** The `CompressionType` part property
  is emitted on send and consumed from the signed header on receive, both
  directions.
- **Pull is authorized or denied.** `As4PullAuthorization` defaults to `Deny`;
  `SharedSecret` (constant-time) and `EnforcedByTransport` are the explicit
  alternatives.

### Wire / crypto — AS2

- **MIC per RFC 4130 §7.3.1.** The MIC digests the exact protected MIME
  entity (after compression, before signing on send; the verified entity on
  receive). Sender and receiver MICs now round-trip; previously they were
  digests of different byte sequences.
- **Receive delivers the payload**, not the S/MIME envelope, with
  content-transfer-encoding reversed and the entity's own `Content-Type`
  surfaced.
- **Compression is RFC 5402 CMS `CompressedData`** (RFC 3274 ZLIB) in both
  directions, with decompression-bomb bounds — previously a bare gzip stream
  no conformant partner could unwrap, and inbound compression was never
  reversed.
- **Unsigned messages are modelled, not mangled**: `As2SignaturePolicy`
  (default `Required`, fail-closed) replaces the boolean, and legitimately
  unsigned messages surface as `SignatureVerification::NotSigned`.
- **Both HTTP body shapes are accepted.** Partners differ in whether the AS2
  body repeats the outer MIME headers; asx now synthesizes them from the
  transport `Content-Type` when absent, so `multipart/signed` content, raw
  PKCS#7 DER under a binary content-transfer-encoding, MIME preambles, and the
  legacy `application/x-pkcs7-*` media types all verify.

### Wire / crypto — WS-Security & SMP

- An X.509 signer token is required unconditionally; a signature verifying
  only against an inline `ds:RSAKeyValue` authenticates nobody and is
  rejected.
- SMP results default to `SmpSignaturePolicy::Deny`; `Verify` performs full
  enveloped-signature verification (`URI=""` + enveloped-signature transform).
- Uppercase and mixed-case `wsu:Id` fragments are accepted (NCName-conformant
  partners were previously rejected).

### API

- `As4SendPolicyBuilder`: `from_party`, `to_party`, `party_id_types`, `roles`,
  `agreement_ref` (all new); `WsSecOutboundKeyInfoProfile` gains
  `BinarySecurityTokenX509v3` (the new default).
- Spool encryption keys are injected: `SpoolEncryptionKeyProvider` is public,
  `StaticSpoolKey` is the one built-in, and the crate's environment-variable
  surface went from 31 variables to 1. The bespoke KMS/HSM HTTP client
  (~1.9 kLOC) is removed.
- `InMemoryAuditSink::new()` returns `Result` instead of silently downgrading
  to a derivable HMAC key.
- Transport errors include the full cause chain (connection refused/reset/
  timeout), not just reqwest's one-line summary.
- Removed: `inject_xop_include`, the `strip_blank_text` C14N knob, the spool
  KMS provider enum and its environment variables.

### Interop verification

- `tests/interop_holodeck_counterparty.rs` — live exchange with **Holodeck
  B2B 6.1.1** (WSS4J) in Docker: asx's signed **two-payload** push is verified
  and delivered by Holodeck; Holodeck's signed NRR receipt — echoing every
  attachment digest — is verified by asx. Identities are generated fresh per
  run.
- `tests/interop_xmlsec_oracle.rs` — reference digests recomputed by
  **xmlsec1**, the W3C XMLDSig reference implementation.
- `tests/interop_openssl_smime_oracle.rs` — AS2 S/MIME in both directions
  against the `openssl smime` CLI: openssl verifies/decrypts asx output, and
  asx verifies/decrypts openssl-produced messages.
- CI runs a `cargo hack` feature powerset in addition to the fixed matrix.

## [0.12.0] — 2026-08-04

Two workstreams:

1. **Integrator feedback** from a BDEW Marktkommunikation deployment
   integrating `asx-rs` 0.11.0 — two defects and two feature requests, plus a
   release-gate gap found while fixing them.
2. **A full-surface security audit**, which closed the items left tracked
   after the 0.8.0 pass and found new defects in the AS4 attachment, pull and
   XML-canonicalization paths.

### Fixed

**Wire/crypto — XML canonicalization stripped whitespace, so no conformant
counterparty could verify an ASX signature.** ⚠ **This is the most
interop-significant fix in the crate's history.**

`WsSecCanonicalizationProfile` defaulted to `strip_blank_text: true` and the
canonicalizer dropped whitespace-only text nodes. Neither Canonical XML 1.0 nor
Exclusive C14N does that — they differ only in namespace rendering. Because AS4
envelopes are pretty-printed, **every signed message ASX produced was
unverifiable by a conformant peer, and every signed message it received from
one was rejected.** ASX's own verifier stripped too, so signer and verifier
agreed and 998 tests passed; one test even asserted the behaviour as correct.

- `strip_blank_text` is **removed from `WsSecCanonicalizationProfile`**, not
  merely defaulted to `false`. No W3C canonicalization strips whitespace, so
  the knob had no valid setting.
- Same-document `ds:Reference` elements now declare
  `<ds:Transforms><ds:Transform Algorithm="…xml-exc-c14n#"/></ds:Transforms>`.
  XMLDSig §4.3.3.2 makes *inclusive* C14N the default for a transform-less
  same-document reference, so the exclusive algorithm must be stated. `cid:`
  references correctly carry no transform (octet stream, not a node-set).
- Verified by `tests/interop_xmlsec_oracle.rs`, which checks ASX output with
  **xmlsec1**, the W3C XMLDSig reference implementation, in a testcontainers-
  managed container: 3/3 reference digests match (0/3 before). Run it with
  `cargo test --all-features --test interop_xmlsec_oracle -- --ignored`.
  Adds a `testcontainers` **dev-dependency**; the tests are `#[ignore]`d, so a
  normal `cargo test` never starts a container.

**Any deployment on 0.11.x or earlier that appeared to interoperate was either
talking only to other ASX instances or not verifying signatures.**

**Security — multi-payload AS4 messages silently lost every attachment but the
first.** `MultipartAs4Payload` held a single attachment and the Content-ID
scanner returned only the first `xop:Include`. ebMS3 permits several
`eb:PartInfo` entries per `UserMessage`; a sender using them had payloads 2..n
discarded with no error on either side — silent business-data loss, and an
eDelivery conformance blocker (the conformance payload profiles define four
parts).

The receive pipeline now carries a payload *collection* end to end:

- Every referenced part is resolved in `xop:Include` document order, in one
  pass over the MIME parts, bounded by 16 attachments. A reference with no
  matching MIME part is an error rather than a silent drop.
- Each attachment is decrypted and policy-checked independently, so a message
  that encrypts payload 1 and leaves payload 2 in plaintext is rejected under
  `require_encrypted_inbound`.
- Every attachment must be signature-covered, not just the first.

**Security — the AS4 payload attachment was not required to be signed.** The
receive path enforced that the `eb:Messaging` header block was covered by the
WS-Security signature (the XML-Signature-Wrapping defence added in 0.9.0), but
nothing required the *payload* — the actual business document, which travels as
a detached MIME part — to be covered. A signature over the header and body
alone verified happily, so an intermediary could swap the attachment without
invalidating it, and the pipeline handed the substituted bytes to the
application as `DomainReady`.

- `VerifiedSignatureCoverage` now also reports `signed_cid_references`; `cid:`
  references were previously parsed, digest-checked, and then discarded from
  the coverage set.
- `As4WsSecVerifier` rejects a message whose payload attachment is not covered
  by a verified `ds:Reference URI="cid:…"`.
- The multipart reader no longer adopts "the next MIME part" as the payload
  when the SOAP body has no `xop:Include`. With no Content-ID there is nothing
  to tie such a part to a signature reference, so it could never be shown to be
  covered.

**Interop — a single-quoted `xop:Include href` was not recognised.**
`href='cid:…'` is legal XML and several stacks emit it, but the Content-ID
scanner matched only the double-quoted form. The attachment then fell through
to the positional path above. The scanner now accepts both quoting styles,
optional whitespace around `=`, and a case-insensitive `cid:` scheme.

**Security — a replayed AS4 PullRequest could dequeue a second message.**
`check_duplicate_pull` returned whether the PullRequest `MessageId` had been
seen; the call site discarded it. Inside the FIFO-bounded served-response cache
a replay still returned the original response, but past that window it fell
through to a fresh dequeue: the initiator received a *different* message under
the same PullRequest id, and the original was silently consumed. A replay now
returns the cached response or, if it has been evicted, no payload at all — it
never dequeues. (An in-crate test asserted the old behaviour and has been
corrected.)

**Security — an unauthorized PullRequest poisoned the dedup store.**
`check_duplicate_pull` runs `first_seen`, which *records* the MessageId, and it
ran before `validate_pull_authorization_info`. An unauthorized peer could
insert arbitrary keys into a durable, shared dedup backend and burn a MessageId
for its legitimate owner. Authorization is now checked first.

**Interop — `ds:CanonicalizationMethod` was written but never read.**
Verification canonicalizes `SignedInfo` as Exclusive C14N unconditionally. A
signature declaring Inclusive C14N was canonicalized as exclusive anyway and
failed with an opaque "signature value mismatch", sending operators hunting for
a key problem that did not exist. The declared algorithm is now validated and a
non-exclusive one is rejected by name (`ErrorCode::InteropViolation`). A missing
`ds:CanonicalizationMethod` is also rejected — XMLDSig requires it, and several
in-crate test fixtures had been getting away without one.

**Security — SMP `ServiceMetadata` signatures are now verified.** The SMP
lookup decides where a message is sent and which key it is encrypted to, and
TLS authenticates the SMP host rather than the metadata it serves. Previously
ASX parsed the response without checking its signature at all.

- New `crypto::wssec::verify_enveloped_document_signature` — verifies an
  **enveloped whole-document** XML signature (`ds:Reference URI=""` plus the
  XMLDSig `enveloped-signature` transform). This is the shape SMP responses
  use; AS4 never does, which is why the WS-Security verifier could not handle
  it before. Backed by a new `canonicalize_enveloped_document`, which
  canonicalizes the document with the `ds:Signature` subtree removed.
- `SmpSignaturePolicy` gains `Verify(OwnedRevocationPolicy)` — chains the SMP
  signing certificate to the network's SMP CA. Construct it with
  `SmpSignaturePolicy::verify_with_trust_anchors(vec![smp_ca_pem])`.
- `SmpEndpoint::verified_signer_fingerprint_sha256` is `Some` only when the
  signature was actually verified, so callers can assert authentication from
  the return value instead of trusting their own configuration.
- Unsigned responses remain rejected by default
  (`SmpSignaturePolicy::RequireSignaturePresent`);
  `SmpEndpoint::signed_document` still exposes the raw bytes.

The enveloped path is newer than the AS4 signing path and is not yet
cross-validated against an independent implementation — see
`docs/security.md`.

**Security — a partner overlay could silently disable encryption.** Profile
validation only rejected a layer that turned *both* signature and encryption
off. A layer that kept signing and dropped encryption validated cleanly, so a
single partner overlay could downgrade one counterparty to plaintext while the
profile reported itself valid. This breaks BDEW AS4-Profil v1.2 §2.2.6.2.2,
PEPPOL, and CEF eDelivery, all of which mandate both.

- New `BaseProfile::security_floor: SecurityPolicy` (default
  `SIGN_AND_ENCRYPT`) — a minimum no layer may resolve below. It lives on the
  base profile only, so no extension, global override, partner overlay, or
  regional pack can lower it.
- `ProfileStack::validate()` now enforces it, reporting
  `ProfileValidationCode::SecurityFloorViolation`.
- A layer that weakens security while still clearing the floor is reported as a
  `ProfileLintCode::SecurityRelaxation` lint at
  `ProfileLintSeverity::Critical`, so a deliberate downgrade is visible rather
  than silent.

**Validation — one partner's overlay contaminated another's findings.**
Validation walked every partner overlay in a single cumulative chain, so a
downgrade declared for partner A was also attributed to partner B, and B's
overlay was evaluated against A's resolved state. Validation now resolves the
deployment baseline once and forks it per partner. Every finding carries
`partner_id`, and errors are raised against the **resolved** policy per scope —
a dip that a later overlay restores is a lint, not an error, because it has no
runtime effect.

**Release gate — lowering the security floor was invisible.**
`EffectivePolicySnapshot` now records `security_floor`, and
`diff_effective_policy_snapshots` grades a *lowered* floor as `High` risk
(`release_blocked`). Without this, relaxing the floor changed nothing in the
snapshot — the resolved policy is unchanged — yet every future overlay had
become free to relax security. Raising the floor is graded `Medium`.

**`xtask profile-lint-gate`** reported `profiles_checked: 0` unconditionally,
and validated each profile against its own floor rather than the shipped
mandate. It now counts the catalog, asserts
`validate_with_floor(SIGN_AND_ENCRYPT)` so a profile cannot opt out of the gate
by lowering its own floor, and renders findings through `Display` alongside the
JSON.

### Added

**API — `ProfileValidationFailure` is now a real error type.** It sits in the
error half of the crate's own `ProfileValidationResult` alias but implemented
neither `Display` nor `std::error::Error`, so consumers could not use
`thiserror`'s `#[from]` / `#[error(transparent)]`, `?` into `anyhow::Error`, or
`Box<dyn Error>` — and had to render it through `Debug`.

- `Display` + `std::error::Error` for `ProfileValidationFailure` (with the first
  issue as `source()`) and for `ProfileValidationIssue`; `Display` for
  `ProfileLintFinding`, `ProfileValidationCode`, `ProfileLintCode`,
  `ProfileLintSeverity`, `SecurityPolicy` and `SecurityRequirement`.
- `Display` renders a bounded one-line summary (first
  `ProfileValidationFailure::DISPLAY_ERROR_LIMIT` errors, then `(+N more)`);
  `ProfileValidationFailure::report()` renders every error and lint across
  multiple lines for a startup log.
- `From<ProfileValidationFailure> for AsxError` (`ErrorCode::PolicyViolation`),
  so `stack.validate()?` works in any function returning the crate's `Result`.
- Accessors: `first_error()`, `has_code(code)`, `affected_partners()`.
- `as_str()` on `ProfileValidationCode`, `ProfileLintCode` and
  `ProfileLintSeverity` for stable log fields and alert rules.

**API — session-free profile resolution.** `resolve(&SessionContext)` needs a
live session, which startup validation does not have; consumers were
re-implementing layer resolution to audit their partners.

- `ProfileStack::resolve_all_partners()` → `Vec<ResolvedPolicyView>` — the
  deployment baseline, then one view per distinct partner.
- `ProfileStack::resolve_baseline()`, `resolve_partner(id)`, `partner_ids()`.
- `ResolvedPolicyView` with `scope_label()` and `satisfies(floor)`.
- All of these share one resolution path with `resolve()`, so a session-free
  view cannot drift from what a live session receives.

**API — floor enforcement knobs.**

- `ProfileStack::validate_with_floor(floor)` — assert a host mandate without
  trusting the profile's own floor. The two are combined with
  `SecurityPolicy::strengthen`, so a deployment floor can only tighten.
- `ProfileStack::validate_with(&ProfileValidationOptions)` with
  `with_security_floor(..)` and `forbidding_security_relaxation()`.
- `SecurityPolicy` lattice: constants `SIGN_AND_ENCRYPT`, `SIGN_ONLY`,
  `ENCRYPT_ONLY`, `UNCONSTRAINED`; `satisfies`, `unmet_by`, `relaxations_to`,
  `requires`, `strengthen` (join), `weaken` (meet); new `SecurityRequirement`
  enum naming which protection a layer dropped.
- `ProfileLintFinding::severity` and `ProfileValidationReport::
  highest_lint_severity()` / `lints_at_least(..)`.
- `BaseProfile::new(name, version)`, `BaseProfile::with_security_floor(..)`, and
  `impl Default for BaseProfile` (strict, fail-closed).

### Changed

**API — breaking.**

- `SmpEndpoint` gains a required `signed_document: Arc<[u8]>` field, and
  `SmpConfig` a required `signature_policy: SmpSignaturePolicy`. Unsigned SMP
  responses are rejected by default; set `SmpSignaturePolicy::AllowUnsigned`
  for a closed or test network.
- A multipart AS4 message whose SOAP body has no `xop:Include` is now rejected
  with "no MIME payload attachment" rather than silently using the next part.
- A signed AS4 message whose payload attachment carries no matching
  `ds:Reference URI="cid:…"` is now rejected.
- `As4ReceivePushOutput` gains `payload_content_id: String` and
  `additional_payloads: Vec<As4ReceivedPayload>`, plus `payloads()`,
  `payload_count()` and `payload_by_content_id()`. `payload` still holds the
  primary attachment, so single-payload callers are unaffected.
- `As4Verifier::verify_security` takes `external_references: &[(&str, &[u8])]`
  instead of `Option<(&str, &[u8])>` — custom verifiers built under the
  `testing` feature must update the signature.
- A `ds:SignedInfo` with a missing or non-exclusive `ds:CanonicalizationMethod`
  is now rejected.
- `WsSecCanonicalizationProfile` loses its `strip_blank_text` field. Struct
  literals must drop it; `..Default::default()` is unaffected.
- `SmpSignaturePolicy` is no longer `Copy`/`PartialEq` (it now carries a
  revocation policy) and `SmpEndpoint` gains
  `verified_signer_fingerprint_sha256: Option<String>`.

- `BaseProfile` gains a required `security_floor` field. Existing struct
  literals must add it; `BaseProfile::new(..)` or `..BaseProfile::default()`
  supply the fail-closed value.
- `EffectivePolicySnapshot` and `EffectiveProfile` gain a required
  `security_floor` field. Snapshot JSON written by 0.11.x lacks the key and no
  longer deserializes — regenerate snapshots before diffing across the upgrade.
- `ProfileLintFinding` gains `severity`; `ProfileLintFinding` and
  `ProfileValidationIssue` gain `partner_id: Option<String>` (`#[serde(default)]`).
- `ProfileValidationCode`, `ProfileLintCode` and `ResolutionField` are now
  `#[non_exhaustive]` and carry new variants (`SecurityFloorViolation`,
  `SecurityRelaxation`, `SecurityFloor`). Match arms need a wildcard.
- `ProfileValidationCode::NoCriticalSecurityInvariant` is now only raised when
  the floor is permissive enough not to preempt it; a default floor reports
  `SecurityFloorViolation` instead.

**Documentation — rustdoc links.** 18 broken intra-doc links across `core`,
`crypto`, `as2`, `as4`, `reliability`, `smp` and `observability` rendered as
plain text instead of links; `cargo doc` now builds clean under
`RUSTDOCFLAGS="-D warnings"`. Two of them were factual errors rather than typos:

- `smp::fetch_*` documented `ErrorCode::TransportError`, which does not exist —
  the code raises `ErrorCode::TransportFailure`.
- `As2TrustVerifier` claimed that "enabling `testing` unlocks
  `InsecureBypassTrustVerifier`", and the README claimed AS2/AS4 parity for it.
  AS2's bypass verifier is `#[cfg(test)]` and reachable only inside this
  crate's own tests — unlike `InsecureBypassAs4Verifier`, which is
  `testing`-gated and downstream-visible. Downstream AS2 tests must implement
  `As2TrustVerifier` against a local fixture, which `TrustVerifierSeal`
  permits. The gating is unchanged; only the false claim is.
- `SessionContext::with_incoming_traceparent` referenced
  `parse_as2_ingress_request` / `parse_as4_ingress_request`, which are named
  `as2_ingress_from_http` / `as4_ingress_from_http`.

**Documentation.** `SecurityPolicy` and `InteropMode` now state explicitly that
the interop axis and the security axis are independent — `interop-strict` does
not imply a strict security policy. `docs/interop.md` gains security-floor,
session-free-resolution and error-handling sections, and its stale claims are
corrected (a `ProfileStack::builder()` that never existed, a `validate()` that
returned a flat finding list, a `diff_effective_policy_snapshots` shown as
fallible, a `resolve_for_session` shown as returning a snapshot, and a
`BaseProfile` example missing `as2_validation`).

---

## [0.11.0] — 2026-07-26

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
