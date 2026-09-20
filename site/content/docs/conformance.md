+++
title = "Conformance"
description = "What asx-rs implements against the eDelivery AS4 conformance profile, what a deployment must add, and which interop oracles check it."
+++

Two separate things, often conflated:

| | **Official conformance** | **Self-hosted e2e** |
|---|---|---|
| Gives you | A signed certificate + a public listing on the EC's conformant-solutions page | Continuous regression evidence in CI |
| Cost | **Free** (see below) | Free |
| Runs | On request, against DIGIT-hosted infrastructure | On every PR |
| Needs | A **publicly reachable** SUT + a SUT Controller + registration | Docker, for most of it |
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

The cost is **engineering time, not money**; [Coverage](#coverage) has what a
deployment must add on top of this library.

> No fee is documented anywhere, which is not the same as a published "free of
> charge" statement. Confirm it in the registration email.

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

Not part of AS4 — a test-harness protocol carried *over* AS4, using ordinary user messages whose
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

## Coverage

`asx-rs` is a **library**; the conformance service tests a deployed **access
point**. What the profile requires of the protocol is implemented; what it
requires of a deployment is not shipped, because this crate never owns a
listener or a process.

| Conformance requirement | In `asx-rs` |
|---|---|
| AS4 signing (RSA + ECDSA), XML encryption | Yes |
| AS4 compression (gzip + `CompressionType` part property, both directions) | Yes |
| One-way push send + receive | Yes |
| Verified receipts / NRR | Yes — `verify_sync_response` |
| Multi-payload messages (all four payload profiles) | Yes, both directions. Send attaches parts via `As4AdditionalPayload` with pinned Content-IDs; receive resolves every signed `eb:PartInfo` reference and verifies each attachment's coverage |
| Retry with bounded interval | Yes — `reliability::RetryScheduler` |
| `PING` profile (ebMS3 core §5.2.2 Test Service) | Yes — `as4::test_service`; a ping is acknowledged and reported as one, never delivered as a business document |
| Two-way push-and-push | Expressible as two correlated one-ways via `RefToMessageId`; not modelled as a single MEP |
| A runnable access point at a public URL | Not shipped. The `server` and `client` features provide the pieces; there is no binary |
| SUT Controller | Not shipped |

The last two are deployment scaffolding you build around the library, not
protocol gaps. Rows above them are implemented and unit-tested; the one-way
push + NRR flow additionally has third-party evidence on every run, below.

---

## Interop oracles

Each one checks this crate against an implementation that does not share its
assumptions — the defect class our own verifier structurally cannot reach.

| Oracle | Counterparty | Needs | Runs |
|---|---|---|---|
| `interop_peppol_smp_oracle` | A signature from the live Peppol production network | nothing | every `cargo test` |
| `interop_openssl_smime_oracle` | `openssl smime` CLI | `openssl` binary | every PR, blocking |
| `interop_xmlsec_oracle` | xmlsec1, the W3C XMLDSig reference implementation | Docker | every PR, advisory |
| `interop_redis_storage_conformance` | A real Redis server | Docker | every PR, advisory |
| `interop_holodeck_counterparty` | Holodeck B2B 6.1.1 (WSS4J) | Docker on **arm64** | every PR, advisory |

`cosmo83/holodeckb2b` publishes a `linux/arm64` image only, so that oracle runs
on an arm64 runner; on amd64 the container fails with `exec format error`.

The Docker-backed jobs are `continue-on-error`, so a registry outage cannot block
a merge — which also means a genuine interop regression there shows up as a red
job, not a blocked PR. Read it, do not assume it.

### Live AS4 counterparty — Holodeck B2B

`tests/interop_holodeck_counterparty.rs` exchanges a **signed AS4 push with
Non-Repudiation of Receipt** against **Holodeck B2B 6.1.1** — an independent,
WSS4J-based ebMS3/AS4 implementation — in a container:

```bash
cargo test --all-features --test interop_holodeck_counterparty -- --ignored --nocapture
```

Per run, the harness generates fresh RSA identities, converts party B's to
PKCS#12 with the local `openssl`, assembles the three JKS keystores with the
container's own `keytool`, installs a One-Way/Push NRR P-Mode by bind mount,
and then:

1. asx signs and pushes a UserMessage;
2. Holodeck verifies the signature (WSS4J), resolves its P-Mode, delivers the
   payload, and answers with a signed receipt carrying
   `NonRepudiationInformation`;
3. asx verifies the receipt — signature, `X509v3` BST signer resolution, and
   the NRR digest echo against the sent message.

This exchange is the strongest interop evidence in the suite: it exercises
P-Mode resolution, WSS4J signature verification of asx output, and asx
verification of WSS4J output — failure classes that neither self-tests nor a
bare XMLDSig oracle can reach.

---

### Peppol SMP signature — live production capture

`tests/interop_peppol_smp_oracle.rs` verifies a `SignedServiceMetadata`
captured from the **live Peppol production network** against the real Peppol
PKI (`PEPPOL Root CA - G3` and the issuing SMP CA), plus tamper cases that must
fail. It needs no container and no network, so it runs in the ordinary test
suite.

The specimen differs from everything this crate generates in ways that exercise
real paths: a default `xmlns` rather than a `ds:` prefix, inclusive C14N, and a
reference with no explicit canonicalization transform.

### AS2 S/MIME — openssl CLI

`tests/interop_openssl_smime_oracle.rs` validates AS2 in both directions
against the `openssl smime` CLI — no container required:

```bash
cargo test --all-features --test interop_openssl_smime_oracle -- --ignored
```

openssl verifies and decrypts asx-signed/encrypted messages; asx verifies and
decrypts openssl-produced ones, which differ from asx output in ways that
matter (MIME preambles, legacy `application/x-pkcs7-*` media types, media type
carried only in the HTTP header).

---

### XMLDSig — xmlsec1

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

The cheapest independent check in the suite (no gateway, no PModes, no
keystores, ~2 s). It targets the defect class our own verifier structurally
cannot see, because it shares the signer's assumptions: canonicalization and
digest disagreements.

Three harness transformations are applied, none changing any digest input: the
`cid:` reference is retargeted to a local file with identical octets (xmlsec1
cannot resolve `cid:`), the WSS SwA `Attachment-Content-Signature-Transform` is
stripped from that reference (xmlsec1 has no SwA support; for binary content
the transform's digest input *is* the raw octets), and `--id-attr` is given per
referenced element (`ebms:Messaging`, `soap:Body`) because `wsu:Id` is not a
schema-declared ID. The first two edit `ds:SignedInfo`, so the tests assert the
per-reference digest tally rather than the overall `SignatureValue` verdict —
recomputing every reference digest under an independent C14N implementation is
the interoperability question the oracle exists to answer.

---

## Running the oracles locally

All oracle tests are `#[ignore]`d and Docker-backed where a container is
needed; CI runs them in a dedicated `interop-docker-oracles` job.

```bash
cargo test --all-features -- --ignored
```

`testcontainers` is a dev-dependency only. The container is torn down when the
handle drops — including when an assertion panics — and a missing Docker daemon
surfaces as a typed error rather than a silently skipped test.

## Toward official certification

Two things the library deliberately does not provide stand between it and a
registration, both listed under [Coverage](#coverage): a publicly reachable
access point binary, and a SUT Controller. Both are deployment code you write
around `asx-rs` using the `server` and `client` features.

The ITB is EUPL-licensed and Docker-distributed, so the official assertions can
be run locally before registering for anything: stand up GITB from the `ISAITB`
images and run the eDelivery AS4 test cases against your access point. The
published messaging adapter (`isaitb/asx-messaging-v4`) drives **Domibus** via
its Default WebService Plugin, so pointing the suite at your own SUT means
implementing the GITB messaging-service API — a small SOAP service (send, check
acknowledgement, receive by message id). That is most of the SUT Controller
work, so it is not spent twice.

## References

- [eDelivery conformance testing](https://ec.europa.eu/digital-building-blocks/sites/spaces/DIGITAL/pages/467118600/eDelivery+conformance+testing)
- [Using the conformance testing service](https://ec.europa.eu/digital-building-blocks/sites/spaces/DIGITAL/pages/883824449/Using+conformance+testing+service)
- [AS4 User Guide v1.20 (PDF)](https://ec.europa.eu/digital-building-blocks/sites/download/attachments/467118600/(eDelivery).(Conformance%20Testing%20Service).(User%20Guide).(v1.20).pdf)
- [Interoperability Test Bed](https://interoperable-europe.ec.europa.eu/collection/interoperability-test-bed-repository/solution/interoperability-test-bed) · [ISAITB on GitHub](https://github.com/ISAITB/gitb)
- [phase4](https://github.com/phax/phase4)
- Contact: `EC-EDELIVERY-SUPPORT@ec.europa.eu`
