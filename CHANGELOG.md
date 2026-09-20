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

## [0.15.0] — unreleased

Deduplication became two-phase, which is a breaking change to the storage seam
and to both receive outcomes. The change was forced by a delivery-correctness
defect: a message this crate *rejected* had already spent its replay
protection, so the sender's retransmission was answered as a duplicate and the
message was lost.

### Added

- **A foreign-implementation oracle for the SMP signature path**
  (`tests/interop_peppol_smp_oracle.rs`). A `SignedServiceMetadata` captured
  from the **live Peppol production network**, verified against the real Peppol
  PKI (root and issuing CA), with tamper cases. The specimen differs from
  everything this crate generates in ways that exercise real paths: the
  signature uses the **default `xmlns`** rather than a `ds:` prefix, inclusive
  C14N, and a reference with no explicit canonicalization transform — the D49
  path, confirmed by an independent implementation for the first time. It found
  a defect immediately; see the wire section.

- **The storage seam, against a real network-backed store**
  (`tests/interop_redis_storage_conformance.rs`). A Redis `DedupStorage`
  written the way the persistence guide says to — atomic claim and abandon as
  Lua scripts — run through the whole `DedupConformance` contract in a
  container, plus a deliberately `GET`-then-`SET` implementation that must
  **fail** the race check. Closes the residual of D61 out of tree: only
  in-memory backends had ever driven the async half of the trait.

  Both run in a new `interop-docker-oracles` CI job, alongside the Holodeck
  exchange, which until now ran nowhere.

- **`asx_rs::peppol::mls` — the Peppol Message Level Status seam.** Network
  Policy 1.0.0 rule MLS-1 makes MLS mandatory for every Service Provider.
  Resolving *who* it goes to (`MLS_TO`, else the sender's registered SPIS ID),
  *whether* it is wanted (`MLS_TYPE`, absent meaning `FAILURE_ONLY` per rule
  MLS-3), and *when* it is due (milestone M1 is the original message's
  `eb:MessageInfo/Timestamp`; SLR windows 20 and 25 minutes) is transport and
  lives here. Building the MLS document is not: it is a Peppol business
  document, and belongs where UBL does (D69).

- **The SBDH module produces a Peppol Business Message Envelope.**
  `SbdhHeader::business_scope` carries `<Scope>` entries, which is how Peppol
  expresses every envelope parameter — `DOCUMENTID`, `PROCESSID`, `COUNTRY_C1`,
  and the `MLS_TO` / `MLS_TYPE` customisations that Network Policy 1.0.0 made
  mandatory. `asx_rs::sbdh::peppol_scope` has the reserved keys.

  The module previously emitted none of them, so every envelope it produced was
  rejected by every Peppol access point — while its documentation said
  "Peppol-compatible". Nothing in-tree could see it: the only test was our
  serializer round-tripping through our own parser. The regression test now
  parses the **specification's own printed example** (BME 2.0.2 §3.1).

  `wrap_binary_payload` / `wrap_text_payload` cover the non-XML payload
  wrappers (BME §2.3.1–2.3.2). An empty `business_scope` emits no
  `<BusinessScope>` element, because the schema gives `Scope` a lower bound of
  1 (D67).

- **Per-partner signer pinning** (`As4SignerPins`, `As4SignerPinMap`,
  `As4ReceivePush::signer_pins`). Every access point on a network shares that
  network's trust anchors, so a signature that verifies and chains to one
  proves *membership*, not the identity of the sender. The pin is what
  attributes it — and it was a single string on the session's `CertHandle`, so
  a receiver with N counterparties needed N sessions, each costing a
  `rotate_cert_handle` that drops the trust-anchor and X509-store caches, and
  had to pick the right session from the claimed `eb:From` before calling
  receive. That put the claimed-sender ↔ verified-signer binding outside the
  library, where nothing checked it.

  The resolver is keyed on the claimed `eb:From` and compared against the
  verified signer, so a match *is* the proof. Several fingerprints per party
  are permitted, which is what a certificate rollover needs. `None` falls back
  to the session pin (D64).

- **`CertFingerprint`** (`asx_rs::crypto`) — `from_cert_pem`, `from_cert_der`,
  `parse`. A pinned fingerprint is required to receive signed AS4 and the crate
  offered no public way to compute one: the only PEM → DER → SHA-256 was a
  `cfg(test)` helper, so every integrator reimplemented it. `parse` requires
  exactly **64 hex digits**, so a truncated or SHA-1 value is rejected where it
  is configured rather than surfacing later as "signature does not match" and
  reading as the counterparty's fault (D65).

- **Mutual TLS on egress** (`ClientIdentity`, `TransportConfig::with_client_identity`).
  Several AS4 profiles require client-certificate authentication on the wire in
  addition to the WS-Security signature — BDEW's *Regelungen zum
  Übertragungsweg* among them — and `TransportConfig` had nowhere to put the
  certificate, so the only way to satisfy them was to abandon this crate's
  transport and reimplement its SSRF and DNS-pinning guards. The pair goes in as
  PEM and is parsed **once**, at construction, so a bad certificate/key fails
  where it is configured rather than at the first message. The OCSP fetcher
  deliberately does **not** present it: a responder is a third party and its
  response is signed, not client-authenticated. Inbound mTLS remains the
  terminator's — this crate never owns a listener (D60).

### Wire / crypto — SMP signature verification

- **No conformant Peppol SMP response could be verified.** `SignedInfo` was
  canonicalized as exclusive C14N unconditionally, and a signature declaring
  anything else was rejected with an error citing "the AS4 profiles". But the
  same verifier serves the **SMP** path, and Peppol SMP §5.5.1 *mandates*
  inclusive Canonical XML 1.0 — it changed it from exclusive in SMP 1.4.0. So
  `SmpSignaturePolicy::Verify` could not verify a single conformant response:
  the path that decides **where a message goes and which key it is encrypted
  to** was unusable against the live network.

  `SignedInfo` is now canonicalized with the algorithm the signer **declared**,
  which is the only correct input — the signature was computed over whatever
  `ds:CanonicalizationMethod` names. A prefix list under inclusive
  canonicalization is rejected as the contradiction it is, and the
  comment-preserving variants of both algorithms remain refused.

  Nothing caught this because the tests signed with our own signer using
  exclusive C14N — and one of them, `inclusive_c14n_is_rejected_by_name`,
  asserted the defect as correct. Found on first contact by the new oracle
  (D68).

### Wire / crypto — deduplication and retransmission

- **A message this crate rejected could never be redelivered.** The dedup key
  was recorded by a single `first_seen(key) -> bool` call placed immediately
  after WS-Security verification, with three fallible steps still to run:
  timestamp freshness, payload materialization and receipt verification. Any of
  them failing returned an error to the caller — but the key was already spent.
  The sender's `ReceptionAwareness` retransmission carries the **same**
  `eb:MessageId`, so it came back as `Duplicate`, and this crate's own
  documentation told callers to acknowledge a duplicate with a receipt. A
  verified message from a real partner was therefore rejected, acknowledged as
  received, and lost. The AS2 MDN path had the same shape: every audit emission
  and the reconciliation enqueue after the dedup call is fallible under
  `fail_closed_audit_events`.

  Signature verification runs *before* the dedup call, then and now, so this was
  never reachable by an unauthenticated peer — it takes a validly signed message
  from a real partner. It is a delivery-correctness defect, not a replay hole.

  **Deduplication is now two-phase.** `claim` takes the key, `accept` settles it
  as handled, `abandon` releases it. `claim` answers with three verdicts rather
  than a boolean: `Claimed`, `Duplicate` (previously **accepted**), and
  `InFlight` (a concurrent delivery holds an unsettled claim — neither a replay
  nor a first sight, and the one case the old shape could not express). A
  first-seen message hands the caller an unsettled `DedupClaim`, because this
  crate knows a message parsed, verified and decrypted, and only the caller
  knows whether it was *handled*. An unsettled claim expires by lease, so a
  process that dies mid-handling delays redelivery instead of wedging that
  `eb:MessageId` forever (D59).

  A receiver should now answer `InFlight` with **no receipt** — 503 — so the
  sender retransmits once the other attempt settles.

### Fixed — async storage backends were unusable

- **A durable, cluster-safe dedup backend panicked on the first inbound
  message.** `DedupStorage` and `ReconciliationStorage` return `BoxFuture` so
  that Redis/PostgreSQL/DynamoDB backends can implement them natively, and
  `cluster_safe()` — which the strict production startup gate *requires* —
  means an out-of-process store by definition. Every such store yields at least
  once. The internal bridge polled the future exactly once with a no-op waker
  and panicked on `Poll::Pending`, so the only backends that worked were the
  in-memory ones the gate rejects. Both entry points were affected:
  `receive_push_with_dedup_async` runs the pipeline inside `spawn_blocking` and
  drove the future synchronously too — and the panic message named it as the
  remedy.

  Nothing caught this because every in-tree backend resolves immediately. The
  bridge now polls once (so the in-memory fast path stays free and needs no
  runtime at all) and then drives a genuinely pending future on the current
  runtime, via `block_in_place` + `block_on` — the same pattern the OCSP client
  already used. The regression test drives the **end-to-end AS4 receive path**
  with a yielding backend and fails against the previous implementation (D61).

### Fixed — documentation contradicted the specification

- **Five places said Peppol is sign-only.** The Peppol AS4 profile says the
  opposite in its first paragraph — the Peppol PKI is used "for signature and
  encryption on AS4 message level", and `PMode[].Security.X509.Encryption.Certificate`
  is the receiving AP's certificate fetched from the SMP (§1, §4.7). One of the
  five was a **code example in the published docs** that set `encrypt: false`
  with the comment "PEPPOL BIS Billing 3.0 mandates sign-only", so anyone
  following it produced non-conformant Peppol traffic.

  `src/interop.rs` had it right (`SIGN_AND_ENCRYPT` is the default floor "which
  is what PEPPOL, CEF eDelivery and BDEW require"), so the crate contradicted
  itself. Corrected in the AS4 guide, `concepts/MARKET_LANDSCAPE.md`,
  `concepts/INTEROP.md`, `concepts/ROADMAP.md` and the reference index (R19).

### Fixed — test isolation

- **Two fixture-repository tests could share a scratch directory.** Both named
  it from `SystemTime::now().as_nanos()`, and `SystemTime` is microsecond-granular
  on macOS, so two tests running on different threads could land on the same
  value, share a directory and overwrite each other's `catalog.json`. The
  result was a gate that failed a few times out of a hundred for no reason
  attributable to the code under test. The name is now keyed on the test as
  well as the clock.

### API — hard cuts

- **`SbdhHeader` gained `business_scope: Vec<SbdhScope>`.** Existing struct
  literals need the field; `Vec::new()` reproduces the old (non-Peppol)
  output.

- **`PModeSecurity::default()` now encrypts**, and P-Mode materialization
  refuses `encrypt = false` in non-testing builds on the same terms as
  `sign = false`. The check looked like a security floor and was half of one: a
  P-Mode with encryption off materialized cleanly and sent signed plaintext,
  and the *default* was itself `encrypt: false`. All four target networks
  mandate both — see the Peppol correction above (D66).
- **`As4Verifier::verify_security` takes one `As4SecurityVerification`** instead
  of eight positional parameters, and carries the claimed `from_party_id` and
  the resolved `permitted_signers`.
- **`WsSecVerifyOptions::with_expected_fingerprint(Option<&str>)` is
  `with_expected_fingerprints(&[CertFingerprint])`** — pinning is a set, so a
  certificate rollover does not need a flag day.
- **`As4IngressReceivePushSyncRequest::dedup_backend` is `dedup`**, and the
  struct gained `signer_pins`.

- **Six AS4 push-receive entry points and five request structs become four and
  two.** Conversation ordering is now a **field** on one request rather than a
  separate pair of functions, because whether a deployment preserves
  per-conversation arrival order is a property of that deployment — encoding it
  in the function name put a deployment decision at every call site.

  | Was | Now |
  |---|---|
  | `receive_push_with_dedup_async(s, b, req, dedup)` | `receive_push(s, b, As4ReceivePush { request, dedup, ordering: None })` |
  | `receive_push_ordered(s, b, As4ReceivePushOrderedRequest { .., gate })` | `receive_push(s, b, As4ReceivePush { request, dedup, ordering: Some(gate) })` |
  | `receive_push_with_dedup_async_fragment_aware(..)` | `receive_push_fragment_aware(s, b, push, fragments)` |
  | `receive_push_ordered_fragment_aware(..)` | `receive_push_fragment_aware(s, b, push, fragments)` |
  | `receive_push_with_dedup_sync(s, b, As4ReceivePushSyncRequest { .. })` | `receive_push_sync(s, b, As4ReceivePushSync { request, dedup })` |
  | `receive_push_with_dedup_sync_fragment_aware(..)` | `receive_push_sync_fragment_aware(s, b, push, fragments)` |

  Every **async** receive now returns `As4Ordered<T>`. With `ordering: None`
  the guard holds no turn and `.into_inner()` is free; with a gate it holds the
  conversation's turn until dropped, as `receive_push_ordered` did. The async
  entry point also takes a request struct instead of positional arguments, like
  its siblings.

  Fragment-awareness stays a separate method: it is the one axis that changes
  the answer, because an incomplete group produces `PendingFragment`.

  `As4ReceivePushSyncRequest`, `As4ReceivePushSyncFragmentAwareRequest`,
  `As4ReceivePushAsyncFragmentAwareRequest`, `As4ReceivePushOrderedRequest` and
  `As4ReceivePushOrderedFragmentAwareRequest` are replaced by `As4ReceivePush`
  and `As4ReceivePushSync`. The `dedup_backend` field is `dedup` on all of them,
  including `As4IngressReceivePushSyncRequest` (D63).
- **Two of the three in-memory dedup backends are gone.**
  `InMemoryDedupStorage` grew without bound and its own documentation told you
  not to use it in production — while carrying the name most likely to be
  picked. `BoundedFifoDedupStorage` evicted by insertion order, so it could
  drop a key that was still inside the replay window: bounded memory bought
  with a silent replay hole, in the component whose only job is preventing
  replays. Neither was used anywhere outside its own tests.

  `TtlDedupStorage` is the one in-tree backend. Its memory is bounded by the
  replay window, which is what RFC 4130 §5.2.1 actually specifies — a duration,
  not a count. `asx_rs::storage::DEFAULT_CLAIM_LEASE` is now exported alongside
  it (D62).
- **`DedupStorage` is a three-method trait.** `first_seen(&str) -> Result<bool>`
  is replaced by `claim(&str) -> Result<DedupVerdict>`, `accept(&str)` and
  `abandon(&str)`. Every backend must be updated; `DedupConformance` gained five
  checks covering the new settlement rules and will tell you which one is wrong.
  The reference SQL schema in the [persistence
  guide](https://hupe1980.github.io/asx-rs/docs/persistence/) gained a `state`
  column and a claim-lease expiry.
- **`As4ReceiveOutcome::FirstSeen` is a struct variant** carrying `output` and
  the unsettled `claim`, and has a third variant `InFlight { message_id }`.
  `As4ReceivePushProgress::Complete` changed the same way. `into_output` and
  `unwrap_output` return `(As4ReceivePushOutput, DedupClaim)`. The enums no
  longer derive `Clone`/`PartialEq`/`Eq` — a claim is an obligation and cannot
  be duplicated.
- **`As2ReceiveMdnOutput::dedup`** is a new field of type `As2MdnDedup`
  (`FirstSeen(DedupClaim)` / `Duplicate` / `InFlight`), and the struct no longer
  derives `Clone`/`PartialEq`/`Eq`. `As4ReceivePullOutput` gained `claim:
  Option<DedupClaim>` for the message it dequeued, on the same terms.
- **The dedup backend is `Arc<dyn DedupStorage>` on every receive path**, where
  the synchronous half previously borrowed `&dyn DedupStorage`. This affects
  `As4ReceivePushSyncRequest` (which lost its lifetime parameter),
  `As4ReceivePushSyncFragmentAwareRequest`, `As4IngressReceivePushSyncRequest`
  and `receive_with_mdn_with_reliability`. A claim outlives the call that
  produced it, so it has to own its handle to the backend.
- **`AsxEvent::DuplicateInFlight`** joins the taxonomy beside
  `DuplicateDetected`. A sustained rate of it means claims are being dropped
  unsettled, or the claim lease outlasts the sender's retransmission interval.

---

## [0.14.0] — 2026-09-06

Everything since 0.13.0. It is a **hard cut**: wire format, defaults and APIs
changed without compatibility shims.

### Added

- **Peppol/CEF participant discovery actually works** (`asx_rs::smp::bdxl`).
  `SmlDiscovery` selects BDXL U-NAPTR (the default), the withdrawn legacy CNAME
  construction, or a statically configured SMP. `BdxlResolver` is the DNS seam,
  with `StaticBdxlResolver` for tests and a `hickory`-backed
  `HickoryBdxlResolver` behind the new **`dns`** feature. `bdxl_dns_name` and
  `legacy_cname_host` are public pure functions so a deployment can check what
  a lookup will ask for; `SmpClient::discovery_dns_name` reports it for a
  configured client. See the wire section below for what this replaced.
- **A live-network oracle for discovery** (`tests/interop_peppol_sml_discovery.rs`,
  `#[ignore]`d). It queries the real Peppol production SML and requires the name
  this crate computes to be the name the network answers on — the one assertion
  no offline test can make, and the one that would have caught all four defects
  below.
- **OASIS SMP 2.0 `ServiceMetadata` is parsed** — for real this time. The
  version is detected from the document element and each generation is read by
  its own rules.
- **`SmpLookupRequest::new` / `with_transport_profile`.** The struct was
  literal-only, and the documented example called a constructor that did not
  exist.
- **`asx_rs::storage::conformance` — a conformance suite for storage
  backends** (`testing` feature). `is_durable()` and `cluster_safe()` are
  self-declarations, and the strict startup gate can only check that a claim was
  made. Implement one factory trait returning a *fresh handle onto the same
  store*, and `DedupConformance` / `ReconciliationConformance` drive the
  properties the protocol paths depend on — above all that **`first_seen` is
  atomic under concurrency**, which a `SELECT`-then-`INSERT` backend fails only
  in production. Returns a printable report rather than panicking, and its own
  tests require a lying backend and a non-atomic backend to fail. Every in-tree
  backend runs against it in CI. **`AuditSinkConformance`** covers the third
  trait: an event that was stored is readable, replay resumes from a cursor
  instead of restarting, the cursor advances, state survives a fresh handle,
  and a sink claiming cursor integrity protection refuses an edited cursor.
  Its own tests require a sink that forgets on reconnect and one that accepts a
  forged cursor to fail.
- **`As4ReceivePushOutput::is_test_service_ping()`** — ebMS3 Core §5.2.2 says a
  Test Service message is acknowledged and **not delivered**, and the receive
  path previously gave the caller no way to tell, so an empty connectivity ping
  reached the business pipeline as a document. Derived from the parsed
  `eb:Service` and `eb:Action`, and both must match.
- `SoapEnvelopeBuilder::with_ws_security_placeholder` and
  `splice_ws_security_header`.

### Security

- **Private keys no longer leak through `Debug`.** Nine public types carried
  key material or a shared secret behind a derived `Debug`:
  `As2SendCredentials`, `As2MdnSigningCredentials`, `As4SendCredentials`,
  `As4PullRequestCredentials`, `As4ReceiptCredentials`, `PartnerCredentials`,
  `CmsSmimeTrustVerifier`, and `As4PullAuthorization::SharedSecret`. A single
  `tracing::debug!(?credentials)` or a `{:?}` in a panic message wrote the
  private key into the log. Each now has a hand-written `Debug` that renders
  secret fields as `<redacted>`; `CertHandle` already did, which is what made
  the omission visible.
- **SSRF via an attacker-supplied OCSP responder URL.** The responder URL comes
  out of the certificate's AIA extension, so on an inbound AS2/AS4 message it is
  chosen by whoever presented the certificate — and revocation checking runs
  *while* trust is being established, i.e. before that party is trusted at all.
  `ReqwestOcspTransport` performed **no** URL validation: a peer could point the
  responder at `169.254.169.254`, `127.0.0.1` or any internal address and have
  the process issue an HTTP POST to it. Responder URLs are now validated against
  the private/loopback/link-local ranges and the connection is pinned to the
  addresses that were checked. Plain HTTP stays permitted here and nowhere else,
  because RFC 6960 responses are signed and public PKIs publish `http://`
  responders.
- **DNS-rebinding hole in SMP lookup.** `SmpClient` validated the lookup URL —
  resolving DNS to check for private ranges — and then issued the request
  through a long-lived client that resolved DNS **again**. An attacker
  controlling the response answers the check with a public address and the
  connection with a private one. The lookup now validates and pins in one step,
  as the AS2/AS4 egress path already did; the unpinned `validate_egress_url`
  helper that made this mistake possible is deleted rather than documented.
- **The strict-runtime bootstrap marker is unforgeable.**
  `SessionContext::set_strict_runtime_bootstrap_validated` and
  `with_strict_runtime_bootstrap_validated` were public, and
  `SessionMetadata::strict_runtime_bootstrap_validated` was a public field — so
  the entire startup-validation gate was one assignment away from being
  bypassed while still reporting itself as enforced. The marker is now
  crate-private and can only be raised by
  [`StrictRuntimeBootstrapToken::bind`], which needs a token that only
  `StrictRuntimeBootstrap::validate` can mint. Tests use
  `SessionContext::test_only_mark_strict_runtime_bootstrap_validated`, gated
  behind `testing` (a `compile_error!` in release builds).
- **One constant-time comparison.** Two hand-rolled XOR-accumulate `secure_eq`
  copies were replaced by a single `subtle::ConstantTimeEq`-backed
  `core::constant_time_eq`. A hand-rolled loop has no defence against the
  optimiser turning it back into an early-exit compare; `subtle` does.

### Wire / crypto — participant discovery

- **Peppol discovery was broken in four independent ways at once, and the only
  test asserted that an MD5 hex string is 32 characters long.** `SmpClient`
  built `https://B-<hash>.<sml_zone>/` and issued a `GET` at it. Every input was
  wrong: the hash covered `"{scheme}::{value}"` where the specification hashes
  the **identifier value alone**; the mandatory `<scheme>` DNS label was absent;
  and both SML zone constants (`edelivery.tech.ec.europa.eu`,
  `acc.edelivery.tech.ec.europa.eu`) were decommissioned on 31 August 2026 when
  OpenPeppol took the SML in-house. Peppol had also already migrated from CNAME
  to **NAPTR**, so the `B-…` name resolves to nothing even in the zone that
  still answers.

  Discovery is now BDXL as specified — `strip-trailing(base32(sha256(lowercase(
  ID-VALUE))), "=") + "." + ID-SCHEME + "." + ZONE`, resolved as a `Meta:SMP`
  U-NAPTR — against `participant.sml.prod.tech.peppol.org` and
  `participant.sml.test.tech.peppol.org`. The DNS name computation is pinned to
  the specification's own worked example and to the record the live production
  SML returns.

  **This is not backward compatible and is not meant to be**: the old behaviour
  found nothing. `SmpClient` now needs a `BdxlResolver` for NAPTR discovery and
  says so, rather than silently falling back to a scheme the network withdrew.

- **A U-NAPTR replacement is now constrained.** The SMP URL is read out of a DNS
  record, so the record decides where a message goes. Backreferences are
  refused (RFC 4848 §2.2 forbids them; one would splice part of the queried name
  into the address), and a non-`https` replacement is refused rather than used,
  so a DNS answer cannot downgrade the metadata fetch.

- **SMP 2.0 support was a namespace constant and a comment.** The endpoint's
  transport profile was read only from the SMP 1.0 `transportProfile`
  *attribute*, but SMP 2.0 carries it in a `TransportProfileID` *element* — and
  renames the address to `AddressURI`, the process id to `Process/ID`, and nests
  the certificate. No 2.0 endpoint could ever match. Both generations are now
  detected and parsed by their own rules, and an SMP offering two endpoints for
  one process and transport profile is **refused** rather than resolved by
  document order.

### Wire / crypto — ordered delivery

- **Ordered AS4 delivery ordered nothing.** `receive_push_ordered` is documented
  as serializing concurrent receives that share an `eb:ConversationId`
  (ebMS3 §5.1.5). It did the entire receive — parse, verify, decrypt, dedup —
  and *then* acquired the conversation turn, so the queue recorded **completion**
  order rather than arrival order: a small message that arrived second overtook
  a large one that arrived first. It then **released the turn before returning**,
  so the application delivered with no turn held at all and nothing about
  delivery was serialized.

  The gate already had the right shape. `reserve_turn` / `wait_turn` is a
  two-phase ticket API whose own documentation calls early reservation "the
  optimization of early reservation (before full parse)" — and nothing outside
  the gate module called it. Early reservation is not an optimization; it is the
  property. `extract_conversation_id_for_gate`, the bounded byte scan written to
  get the key before parsing, was orphaned behind `#[cfg(test)]` with ten tests
  exercising a function production did not compile.

  Now: the turn is reserved from the raw bytes on arrival, the expensive work
  runs while holding only a ticket, and `receive_push_ordered` returns
  **`As4Ordered<As4ReceiveOutcome>`** — a guard that holds the turn until the
  caller drops it. The scanned id is compared against the verified
  `eb:ConversationId` afterwards, so an unauthenticated scan can only mis-order
  or reject the sender's own traffic.

- **A repeated `eb:ConversationId` was accepted, first-wins.** It is
  `maxOccurs="1"` in ebMS3 Core and it is the key the ordering gate queues on, so
  document order was deciding which conversation a message belonged to. Now
  rejected, like the `eb:MessageInfo` children already were.

- **The test guarding all of this exercised none of it.** It discarded the
  receive result with `let _ =`, failed on the first event emission because the
  bus had no durable audit sink, declared `application/soap+xml` for a multipart
  body, and satisfied its ordering assertion from the 10 ms `sleep` between two
  spawns — in 0.07 s, with the 120 ms verify it was built around never running.
  Made real, it failed immediately. `SECURITY.md` says `let _ = verify(...)` is
  not a shape that exists in this codebase; it was in the test guarding ordered
  delivery.

### Wire / crypto — AS2 MDN

- **A signed MDN could be made to report the wrong delivery outcome.** The
  machine-readable part of a `multipart/report` was located positionally: if no
  `message/disposition-notification` part existed, the code took whatever sat at
  index 1. A counterparty placing `Disposition: … processed` in a human-readable
  `text/plain` part therefore got that read as the verdict. Signed content of any
  media type at all — `text/html`, anything — was likewise returned as the
  notification part. Both were accepted in `InteropMode::Strict`: the signed
  path, which carries non-repudiation of receipt, had none of the guards the
  unsigned path had.

  The part is now selected by media type, the signed content must itself be a
  disposition notification or a report, and a report carrying two disposition
  notifications is refused rather than resolved by document order. Relaxed mode
  widens only the absent case: no machine-readable part means no verdict.

### Wire / crypto — HTTP ingress

- **A repeated HTTP header was resolved first-wins.** `AS2-From` names the
  partner a session is bound to, `Message-ID` is the dedup key,
  `Disposition-Notification-To` is where a receipt gets sent, and `Content-Type`
  decides how the body is parsed — and the ingress layer took the first
  occurrence of each and ignored the rest. `axum`'s `HeaderMap::iter` yields one
  entry per duplicate value, so a peer sending two `AS2-From` headers bound the
  session to one partner while a proxy or the partner's own gateway could read
  the other. Now an `InvalidInput` error. The crate applied this rule
  meticulously to repeated `eb:MessageId` and `eb:Messaging` elements (D5) and
  not at all to the headers carrying the same identities.

### Wire / crypto — canonicalization and key derivation

- **Inclusive C14N of a document subset dropped the ancestors' `xml:*`
  attributes.** Canonical XML 1.0 §2.3 gives the apex element of a subset every
  in-scope `xml:*` attribute from ancestors outside the node-set; Exclusive
  C14N deliberately does not, and the crate had generalised the exclusive
  behaviour to both. A conformant peer signing an element nested under an
  `xml:lang` or `xml:space` had its signature reported as a forgery.

- **A reference declaring no transform was canonicalized exclusively.** XMLDSig
  §4.3.3.2 makes **inclusive** Canonical XML the default when converting a
  node-set to octets. The signing path already knew this — it *states* the
  exclusive algorithm precisely because the default is not exclusive — and the
  verify path did not. Same fail-closed, undiagnosable outcome.

- **Processing-instruction data was trimmed.** C14N 1.0 §2.3 emits it verbatim;
  `<?t d  ?>` canonicalized to `<?t d?>`, a digest nothing else computes.

- **ConcatKDF ignored `SuppPubInfo` and `SuppPrivInfo`.** SP 800-56A §5.8.1.2
  concatenates all five `ConcatKDFParams` fields. Two were parsed by nobody, so
  an ECDH-ES peer supplying either derived a key-encryption key this crate could
  not reproduce — surfacing as "AES Key Unwrap integrity check failed", which
  names the KEK rather than the dropped parameter.

### Wire / crypto — AS4 envelope determinism

- **About one signed AS4 message in a thousand shipped a signature nothing
  could verify.** `eb:MessageInfo/eb:Timestamp` lives inside the signed
  `eb:Messaging` block, and the send path builds the envelope **twice** for one
  message — once unsigned to compute that block's `ds:Reference` digest, once
  again with the `wsse:Security` header. `SoapEnvelopeBuilder::build()` read
  `SystemTime::now()` on each call, so whenever the two builds straddled a
  whole-second boundary the envelope that went on the wire was not the one that
  had been digested. The receiver computed a different digest for
  `#as4-messaging` and rejected the message with
  `SecurityVerificationFailed` — indistinguishable from a flaky partner.

  `SoapEnvelopeBuilder::with_message_timestamp` is now **required**: `build()`
  returns `InvalidInput` without it, naming the setter. A caller that would
  have raced gets a deterministic error at its first build instead of a bad
  message on the wire once in a thousand. Found by a single failing run of the
  test suite that had passed a dozen times before it.

  The send path no longer builds the envelope twice at all: it reserves the
  `wsse:Security` slot with a placeholder and splices the finished header in
  after signing. The placeholder is outside both signed subtrees, so it cannot
  move a digest, and `splice_ws_security_header` refuses unless it finds
  exactly one — which is the safety the rebuild had been chosen for, without
  the race the rebuild introduced.

### Wire / crypto — base64 in XML

- **Line-wrapped base64 is accepted.** XML Signature §6.1 and XML Encryption
  define their base64 content by reference to RFC 2045, which line-wraps, and
  any XML pretty-printer folds a long `ds:DigestValue` or `ds:SignatureValue`
  anyway. The `base64` crate's standard engine rejects embedded whitespace, so
  a conformant counterparty was rejected: an inbound signature failed to parse,
  and — worse — an `eb:Receipt` whose NRR digests were line-wrapped was reported
  as `SecurityVerificationFailed` with "the acknowledgement refers to different
  bytes than were sent". Every base64 value that arrives inside an XML document
  now goes through `core::decode_xml_base64`, which strips ASCII whitespace
  first. `xenc:CipherValue` already did this; nothing else did.
- **NRR digests are compared as decoded bytes, in constant time**, rather than
  as base64 strings. Same root cause as above, plus consistency with the
  reference-digest check, which already used a constant-time comparison.
- **AS2: a folded `Received-Content-MIC` header no longer reports a mismatch.**
  RFC 5322 §2.2.3 lets a MIME header fold across lines, so a conformant
  partner's digest can arrive with a CRLF and a space inside the base64. Strict
  decoding failed on that and the comparison fell back to raw string equality —
  declaring a delivered message undelivered. Whitespace is now stripped before
  decoding and the digests are compared in constant time.

### Removed — scope

- **`incident_channels` is gone** (~2,900 lines). The module shipped a webhook
  HTTP client with retry, a circuit breaker, bounded queues and metrics, a
  file-spool writer, and a sizing advisor — plus **its own process-global
  multi-threaded Tokio runtime**, built inside a library. No protocol path
  depended on any of it. (The `…IncidentChannel` traits and incident structs it
  left behind are gone too — see **The alerting engine is gone**, below.) This is
  the same boundary the 0.13.0 removal of the built-in KMS/HSM client drew,
  applied consistently.
- **`recommend_event_bus_capacity`** and `EventBusCapacitySizingInput` removed:
  a multiplication with a hard-coded 25 % headroom constant is not something a
  protocol library should assert about someone else's workload. The alerting
  thresholds removed below are the same mistake in a different file.
- **`As2StrictProductionPreset` / `As4StrictProductionPreset`** removed. They
  wrapped `As2SendPolicy::regulated()` and friends and had no users.

### API — hard cuts

- **The alerting engine is gone** (~1,200 lines). `asx_rs::alerting` and the
  `EventBus` alert methods carried 22 public types in two parallel families that
  differed only in the noun — `As4ReceiptTaxonomyAlert{,Category,Severity,Policy,
  DispatchPolicy,Incident}`, `As2ProviderHealth…`, both `…IncidentChannel`
  traits, both `…SchedulerRequest`s — plus a threshold evaluator with hard-coded
  percentages, `runbook_hint` strings about a deployment this crate has never
  seen, a dedup-cooldown map, and `run_…_alert_scheduler` polling loops with
  their own shutdown channels, inside a library. No protocol path referenced any
  of it, and the two `AsxEvent` alert variants it defined were emitted **only by
  itself**, so the metric counting alerts counted this module exporting them.

  What remains is what only the crate can supply: `EventBusMetrics::
  as4_receipt_taxonomy_snapshot()` and `as2_provider_health_snapshot()`, the
  exhaustive event taxonomy, and the durable audit trail. A failure-rate
  threshold is a partner-SLA question; the monitoring stack already scraping
  these counters is where it belongs. Same boundary as the KMS/HSM client (D14)
  and `incident_channels` (D38), drawn a third time.
- **`receive_push_ordered` and `receive_push_ordered_fragment_aware` return
  `As4Ordered<T>`** instead of the bare outcome — see the ordered-delivery
  section above. `ConversationOrderGate` gains `reserve_ordered_turn` returning
  a `ConversationTurnHandle`; `acquire_ordered_turn` remains as a provided
  method for callers with nothing to overlap with the wait. A distributed gate
  implementation must split its lock acquisition into the two phases.
- **Test-only shadows of production code deleted**: a single-pass marker scanner
  documented as avoiding scans the precheck still performs, and a linear `cid:`
  reference resolver superseded by a hash index. Their assertions now run against
  the code that executes.
- **Unused public types removed**: `crypto::CryptoPolicy` (a confusing duplicate
  of `interop::SecurityPolicy`), `crypto::CertificateRef`, `http::HttpResponse`,
  `http::ClientRuntime`.
- **MSRV raised to 1.88** — required by the `dns` feature's DNS client, and a
  split MSRV per feature is a worse promise than one honest number.
- **`EventBus` has one builder instead of six constructors.**
  `EventBus::builder()` replaces `new_with_config_and_mode` and
  `new_with_config_and_mode_and_metrics` (four and five positional arguments);
  `new_strict_with_audit_fallback` is expressible as
  `.emission_mode(EventEmissionMode::StrictWithAuditFallback)`. `new`,
  `new_regulated` and `new_for_testing` stay as named presets.
- **`presets` collapsed to one entry point.** `StrictRuntimeBootstrap` (a
  builder) replaces `issue_strict_runtime_bootstrap_token`,
  `issue_strict_runtime_bootstrap_token_with_as4_topology`,
  `validate_strict_production_startup_readiness`,
  `validate_strict_production_as4_topology_readiness`,
  `require_strict_runtime_bootstrap_token`,
  `session_with_strict_runtime_bootstrap_token`,
  `strict_production_event_bus`, `require_durable_dedup_backend` and
  `require_durable_reconciliation_backend`. Bind a session with
  `token.bind(&session)`.
- **`AsxError::context` is now `Box<ErrorContext>`.** `AsxError` was 120 bytes,
  so *every* `Result` in the crate — including `Result<()>` — was 120 bytes
  wide on the success path too. It is now 40. Field access
  (`err.context.session_id`) is unchanged through `Deref`.
- **`DedupStorage`, `ReconciliationStorage`, `DurableAuditSink`,
  `OcspResponseCache`, `ConversationOrderGate` and `As2TrustVerifier` now
  require `Debug`.** Implementors add `#[derive(Debug)]`. This is what makes
  the request and policy types that hold them printable.
- Every public type implements `Debug`; `missing_debug_implementations` is a
  lint the crate now passes.

### Fixed

- **The strict startup gate rejected the mode its own documentation
  recommends.** `StrictWithAuditFallback` cannot be constructed without a
  production-durable audit sink and persists every event to it when no
  subscriber is live — it is a strict mode. The readiness check demanded
  `StrictTransactional` exactly, so a regulated deployment that followed the
  advice in `EventBus::new_strict_with_audit_fallback` could not start. The gate
  now rejects only `BestEffort`.
- **The performance gate ran four of its six benchmarks and said nothing.**
  `as2_verify_decrypt_mdn` and `as4_verify_decrypt` are behind `testing`, and
  `testing` is a `compile_error!` in release builds — which is exactly why the
  gate is invoked without it. Both baseline lines therefore checked nothing, for
  as long as they existed, while the file read as though six benchmarks were
  gated. `--check-baseline` now **fails** on a baseline entry with no matching
  measurement, and the baseline lists only what that configuration compiles.

  Underneath, all four of the receive-path benchmarks were broken and had been
  masked by the same gap: they built an `EventBus` with no durable audit sink
  while running fail-closed receive policies (every call returned
  `ReliabilityFailure`), held an event subscription nothing drained (emission
  failed once the channel filled), passed `multipart/related` with no `boundary`
  parameter (rejected before any protocol work), and omitted the ebMS3 routing
  properties strict interop requires. Fixed; the benchmarked paths are the ones
  production takes again.
- **Four broken intra-doc links**, shipping to docs.rs as dead references: one
  pointed at `lifecycle::InsecureBypassTrustVerifier`, which is in `as2::trust`
  and not exported at all; one at a `pub(super)` MIME builder; one at a field
  renamed to `signature_policy`; and `EventBus::builder()` documented a return
  type that had lost its `pub use`, so the builder was unnameable by callers.
  `cargo doc` with `-D warnings` is now a CI job and a `just doc-links` gate.
- **Two feature combinations did not build or test.** `transport::egress` was
  gated on `client`, but the OCSP fetcher calls into it for the validate-and-pin
  helper under `async-ocsp`, so `as2,async-ocsp` failed to compile. And the
  ordered-receive tests disabled `fail_closed_audit_events`, which the policy
  builder refuses outside `testing` builds, so they failed on every combination
  without that feature. Both were invisible to `--all-features`, where `testing`
  is always on; `just ci` now mirrors the CI matrix exactly and runs the feature
  powerset, which is the gate that sees them.
- **A test that could not fail.** `handler_outcome_constructors_build_expected_variants`
  wrote `matches!(..)` as a bare statement four times. `matches!` returns a
  `bool`, and a discarded `bool` is not `#[must_use]`, so the test passed
  whatever the constructors returned. Now wrapped in `assert!`.
- **`just hygiene` scanned a directory that does not exist.** The gate globbed
  `docs`, which became `site/content`, so every pattern it enforces was checked
  against the source tree minus the documentation for however long.
- **Dead code behind feature gates was invisible.** `-D warnings` ran only at
  `--all-features`, which is precisely the build where a stale `#[cfg]` cannot
  show up. The CI feature matrix now denies warnings too, and the four functions
  that were dead in narrower feature sets are gated correctly.
- **MSRV was declared but never checked.** Three `usize::is_multiple_of` calls
  (stable 1.87) meant the crate did not build on the edition-2024 floor, and
  `concepts/` claimed CI verified the declared version while no such job
  existed. `rust-version` is now `1.88` and a CI job builds on that exact
  toolchain. (The `is_multiple_of` workaround is reverted: it is below the new
  floor.) The doctest ratchet the justfile defines is likewise now a CI job
  rather than a recipe someone had to remember to run.
- **The mandatory ebMS3 Test Service was unreachable in production.**
  `asx_rs::as4::test_service` was gated behind the `testing` feature — which
  raises a `compile_error!` in release builds — so no production deployment
  could implement a protocol feature ebMS3 Core §5.2.2 requires of a conformant
  MSH, and which the eDelivery conformance suite exercises as `PING`. It is
  protocol, not scaffolding; the gate is removed.
- **docs.rs would have published an almost empty crate.** `as2` and `as4` are
  not default features and there was no `[package.metadata.docs.rs]`, so the
  published documentation covered only the shared infrastructure. Now
  `all-features = true`.

### Quality

- `#![forbid(unsafe_code)]` on the library (it already contained none).
- `keywords`, `categories` and `rust-version` added for crates.io.
- Working directories excluded from the published package.
- `clippy::todo`, `unimplemented` and `dbg_macro` denied; the crate is clippy
  clean at `--all-features --all-targets`.
- `DedupStorage`'s implementation example is a compiling doctest instead of a
  `rust,ignore` sketch, and the stale `asx-rs = "=0.5.0"` pin in the
  `ReconciliationStorage` docs is corrected.
- **A ratchet on uncompiled doctests** (`just doctest-ratchet`, in the release
  gate). A ```` ```ignore ```` block is never compiled, so it renders as checked
  Rust while being free to rot. The gate does not demand zero; it demands the
  count never grows. Converting the two receipt-generation examples immediately
  surfaced a wrong type in one of them — which is the point.
- The perf gate and the AS2 golden tests now mint a **real** bootstrap token
  through `StrictRuntimeBootstrap` instead of setting the marker directly, so
  they measure and exercise the path production takes.

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

## [0.13.0] — 2026-08-11

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
