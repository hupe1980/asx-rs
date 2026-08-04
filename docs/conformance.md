# eDelivery AS4 Conformance & Interop Testing

Two separate things, often conflated:

| | **Official conformance** | **Self-hosted e2e** |
|---|---|---|
| Gives you | A signed certificate + a public listing on the EC's conformant-solutions page | Continuous regression evidence in CI |
| Cost | **Free** (see below) | Free |
| Runs | On request, against DIGIT-hosted infrastructure | On every PR |
| Needs | A **publicly reachable** SUT + a SUT Controller + registration | Docker only |
| Proves | Point-in-time conformance of a specific version | That today's commit still interoperates |

They are complementary, and the second is a prerequisite for passing the first
without burning support cycles. Do the self-hosted loop first.

---

## Is the official service free?

**Yes.**

- The Interoperability Test Bed (ITB/GITB) that the service runs on is
  **open-source, EUPL-licensed**, and the EC states *"All Test Bed software is
  free to use (also when used as a service)"*. It is explicitly not restricted
  to public administrations — *"used by Public Administrations, International
  Organisations, Industry and Academia across the world"*.
- The eDelivery Conformance Testing Service exists to verify *"a software
  package either commercial or **Open Source***". DIGIT owns, hosts and
  operates the infrastructure.
- Neither the service pages, the Service Offering Description, nor the 46-page
  AS4 User Guide mention a fee, price, or charge anywhere.

The cost is **engineering time, not money** — and the engineering cost is the
part worth planning for (see [What ASX still needs](#what-asx-still-needs)).

> Caveat worth stating plainly: "no fee is documented anywhere" is strong
> evidence but is not the same as a published "this service is free of charge"
> sentence, which we did not find. Confirm in the registration email; it costs
> one line.

---

## The official process

Source: *eDelivery Conformance Testing Service — User Guide for AS4 testing*
v1.20, © European Union 2024.

### Actors

| Actor | Hosts |
|---|---|
| **DIGIT** | GITB (the test bed) and the **Test Driver** — an AS4-conformant access point (Domibus) that plays the counterparty |
| **You (SUT Owner)** | The **SUT** (your AS4 access point) and the **SUT Controller** |
| **eDelivery SO** | Support office, single point of contact, guides you through |

### Steps

1. **Registration** — email `EC-EDELIVERY-SUPPORT@ec.europa.eu` with:
   name and version of the product, specifications to test (AS4 Profile and/or
   SMP Profile), optional Profile Enhancements, **external public URL of the
   SUT**, planned start date, single point of contact. The SO creates your
   test-bed account.
2. **Preparation** — integrate the SUT with the platform, implement the SUT
   Controller, run basic connectivity tests.
3. **Execution** — run the suites from the GITB UI, resolve failures (with SO
   support).
4. **Closing** — receive the signed test report; the SO publishes it and adds
   your solution to the conformant list.

### The SUT Controller

This is the part people underestimate. It is **not** part of AS4 — it is a
test-harness protocol carried *over* AS4, using ordinary user messages whose
`eb:CollaborationInfo/Action` names a command and whose parameters travel as
`eb:MessageProperties`.

| Command | Direction | Meaning |
|---|---|---|
| `Submit` | Test Driver → SUT | "Send this user message." Payloads and `eb:PayloadInfo` metadata from the Submit must be reproduced in the message the SUT sends. |
| `Deliver` | SUT → Test Driver | "I received and processed a user message" — with the extracted metadata and the received attachments. |
| `Notify` | SUT → Test Driver | "I received a signal" — `SignalType` = `Receipt` or `Error`, plus `RefToMessageId`, and `ErrorCode`/`ShortDescription`/`Description` for errors. |

`Submit`/`Deliver` properties: `MessageId`, `ConversationId`, `RefToMessageId`,
`FromPartyId`, `FromPartyRole`, `ToPartyId`, `ToPartyRole`, `Service`,
`ServiceType`, `Action`, and `originalSender`/`finalRecipient` for the
Four-Corner Model enhancement.

### PMode profiles under test

All of them require **compression, signing and encryption**.

| Profile | MEP | Service / Action |
|---|---|---|
| `SIMPLE_ONEWAY` | One-way push | `http://www.edelivery.eu/as4/conformancetest/oneway` / `DEFAULT` |
| `SIMPLE_TWOWAY` | Two-way push-and-push | `…/conformancetest/twoway` / `DEFAULT` |
| `ONEWAY_RETRY` | One-way push, 5 retries, interval < 3 min | `…/conformancetest/oneway` / `RETRY` |
| `PING` | One-way push | ebMS3 core `…/200704/service` / `…/200704/test` |

### Payload profiles

Four parts, exercising **multi-payload** messages:

| Content-ID | MIME type | Required |
|---|---|---|
| `xmlpayload@gitb` | `application/xml` | yes |
| `xmlpayload2@gitb` | `application/xml` | no |
| `custompayload@gitb` | `application/octet-stream` | no |
| `custompayload2@gitb` | `application/octet-stream` | no |

---

## What ASX still needs

ASX is a **library**; the conformance service tests an **access point**. The
gap is deployment scaffolding, not protocol work.

| Requirement | Status |
|---|---|
| AS4 signing (RSA + ECDSA), XML encryption, compression | ✅ shipped |
| One-way push send + receive | ✅ shipped |
| Verified receipts / NRR | ✅ shipped (`verify_sync_response`) |
| **Multi-payload messages** (4 payload profiles) | ✅ shipped in 0.12.0 — receive resolves every `xop:Include`, verifies each attachment's signature coverage, and surfaces them via `As4ReceivePushOutput::payloads()`. **Send is still single-payload** ⬜ |
| Retry with bounded interval | ✅ `reliability::RetryScheduler` |
| Two-way push-and-push | ⬜ expressible as two correlated one-ways via `RefToMessageId`; not modelled as a MEP |
| ebMS3 `PING` service/action | ⬜ not special-cased |
| **A runnable access point** (public URL) | ⬜ not shipped — `server` + `client` features provide the pieces; no binary |
| **SUT Controller** | ⬜ not shipped |

The two ⬜ *deployment* blockers are the access point binary and the SUT
Controller. Everything else is either done or a small increment.

> ✅ **The protocol blocker found here is fixed.** The oracle initially showed
> xmlsec1 rejecting ASX signatures (0/3 reference digests). Root cause: the
> canonicalizer stripped whitespace-only text nodes, which no W3C
> canonicalization does. Removed, plus the missing per-`ds:Reference`
> exc-c14n `ds:Transform`. Now 3/3.

---

## Independent oracle — shipped

`tests/interop_xmlsec_oracle.rs` verifies ASX-generated WS-Security signatures
with **xmlsec1**, the W3C XMLDSig reference implementation, in a container:

```bash
cargo test --all-features --test interop_xmlsec_oracle -- --ignored --nocapture
```

Two tests: a positive one, and a negative one that flips a payload byte and
requires the oracle to reject it — without that, a harness bug that verified
nothing would look like a pass.

Managed with **testcontainers** (`blocking` runner, `WaitFor::Exit`), so the
container is removed even if an assertion panics.

This is the cheapest possible independent check (no gateway, no PModes, no
keystores, ~2 s) and it targets the exact defect class this codebase keeps
producing: canonicalization and digest disagreements that our own verifier
cannot see because it shares the signer's assumptions. **It found a real defect on
its first run** — a whitespace-stripping bug that made every ASX signature
non-interoperable, invisible to 998 other tests.

Two harness transformations are applied, neither touching signed content: the
`cid:` reference is retargeted to a local file with identical octets (xmlsec1
cannot resolve `cid:`), and `--id-attr` is given per referenced element
(`ebms:Messaging`, `soap:Body`) because `wsu:Id` is not a schema-declared ID.

---

## Self-hosted end-to-end testing (do this first)

Since ITB is EUPL and Docker-distributed, and Domibus — the very access point
DIGIT uses as Test Driver — is also freely available, **the whole loop can run
locally and in CI without registering for anything.**

### Option A — real counterparty, via testcontainers

Exchange real AS4 traffic with an independent implementation. This is the
third-party interop evidence the project still lacks, and unlike the official run it executes on
every commit.

**On testcontainers-rs.** The crate is `testcontainers` (0.27.x as of
2026-04), the official Rust fork of testcontainers.org. `GenericImage` plus a
`WaitFor` strategy covers a gateway container:

```rust
let container = GenericImage::new("holodeck", "7")
    .with_exposed_port(8080.tcp())
    .with_wait_for(WaitFor::message_on_stdout("Server startup"))
    .start()
    .await?;
let port = container.get_host_port_ipv4(8080).await?;
```

`WaitFor::Exit(ExitWaitStrategy::new())` also covers **run-to-completion**
containers, which is how the xmlsec1 oracle uses it — no ports, just a
bind-mount, a command, and the exit code plus captured stdout/stderr. That is
why the oracle uses testcontainers rather than shelling out to `docker run`:
the container is torn down when the handle drops, including when an assertion
panics, and a missing daemon produces a typed error instead of a silently
skipped test.

`testcontainers` is a **dev-dependency only** (`features = ["blocking"]`), and
every test that uses it is `#[ignore]`d, so a normal `cargo test` never starts
a container.

Candidate counterparties, in rough order of value:

| Counterparty | Why | Notes |
|---|---|---|
| **Domibus** | It *is* the conformance Test Driver — passing against it strongly predicts passing officially | Heaviest to start; needs a DB container |
| **phase4** | Closest analogue (embeddable Java AS4 library), Peppol/CEF profiles built in | Lighter than Domibus |
| **Holodeck B2B** | Long-standing independent implementation | Good third data point |

Shape of the harness:

```
#[tokio::test]
#[ignore = "requires docker"]           // opt-in: `cargo test -- --ignored`
async fn as4_push_is_accepted_by_domibus() {
    let gateway = Domibus::default().start().await?;   // testcontainers
    // ASX sends a signed+encrypted push to the container's AS4 endpoint
    // and verifies the returned receipt with `verify_sync_response`.
}
```

Both directions matter: **ASX → counterparty** proves our send path produces
conformant wire bytes; **counterparty → ASX** proves our receive path accepts
what real implementations emit. The second direction is where the defects found
in this codebase have clustered (attachment coverage, single-quoted `href`,
`ds:CanonicalizationMethod`) — precisely because in-crate fixtures are written
by the same hands as the parser.

Gate it behind `#[ignore]` plus a `docker` CI job so the default `cargo test`
stays hermetic and fast.

### Option B — self-hosted ITB with the real test suite

Stand up GITB from the `ISAITB` Docker images and run the actual eDelivery test
cases locally. This gets you the *same assertions* the official run uses,
without registration or a public URL.

The catch: the published messaging adapter, `isaitb/asx-messaging-v4`, drives
**Domibus** via its Default WebService Plugin. To point the suite at ASX you
implement the GITB messaging-service API (a small SOAP service: send, check
acknowledgement, receive by message id) on top of ASX — which is most of the
SUT Controller work anyway, so it is not wasted effort.

### Recommended order

1. **Option A** with one counterparty, wired into CI. Cheapest, immediate, and
   catches the class of bug that internal fixtures structurally cannot.
2. **Option B** once the messaging adapter exists — the official assertions,
   run locally.
3. **Official registration** for the certificate, once 1 and 2 are green. By
   then the SUT Controller exists and the run is a formality.

---

## References

- [eDelivery conformance testing](https://ec.europa.eu/digital-building-blocks/sites/spaces/DIGITAL/pages/467118600/eDelivery+conformance+testing)
- [Using the conformance testing service](https://ec.europa.eu/digital-building-blocks/sites/spaces/DIGITAL/pages/883824449/Using+conformance+testing+service)
- [AS4 User Guide v1.20 (PDF)](https://ec.europa.eu/digital-building-blocks/sites/download/attachments/467118600/(eDelivery).(Conformance%20Testing%20Service).(User%20Guide).(v1.20).pdf)
- [Interoperability Test Bed](https://interoperable-europe.ec.europa.eu/collection/interoperability-test-bed-repository/solution/interoperability-test-bed) · [ISAITB on GitHub](https://github.com/ISAITB/gitb)
- [phase4](https://github.com/phax/phase4)
- Contact: `EC-EDELIVERY-SUPPORT@ec.europa.eu`
