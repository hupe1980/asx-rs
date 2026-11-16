+++
title = "Conformance"
description = "Which independent implementation witnesses which part of asx, and what official eDelivery conformance testing needs."
+++

These checks run asx against implementations written by other people. The
[gate table in RELEASING.md](https://github.com/hupe1980/asx-rs/blob/main/RELEASING.md#ci-workflows)
says which block a merge or a release.

## Which oracle witnesses what

| Oracle | Witnesses | Test | Gate |
|---|---|---|---|
| **phase4 4.8.1** (Java, WSS4J; `Phase4BDEWSender` and its BDEW P-Mode) | BDEW AS4 both ways: signed, encrypted (ECDH-ES/ConcatKDF) and compressed messages carrying the RzÜ AS4 2.6 Kap. 6 part properties, SM-PKI-shaped certificate triples (OU and URI subjectAltName), NRR receipts, tampered signatures and ciphertexts refused, unencrypted push refused (`EBMS:0103`), path switch | `tests/interop_phase4_counterparty.rs`, `interop_phase4_encryption.rs`, `interop_phase4_path_switch.rs` (12 cases) | blocking (CI `interop`, peer built from `tests/fixtures/phase4`) |
| **Holodeck B2B 6.1.1** (WSS4J) | an encrypted, signed two-part push from asx is decrypted, verified and delivered, and its signed NRR receipt verifies in `As4::send` | `tests/interop_holodeck_counterparty.rs` | manual (third-party arm64-only image; not in CI) |
| **xmlsec1 1.3.11** (W3C XMLDSig reference implementation) | C14N, reference digests and signatures of asx output; ECDSA `r ‖ s` on P-256, P-384, P-521 and BrainpoolP256r1 in both directions; the payload-less path-switch signature | `tests/interop_xmlsec_oracle.rs`, `tests/wssec_ecdsa_signature_value.rs` | blocking (CI `interop`) |
| **openssl CLI** (`openssl smime`/`cms`) | AS2 S/MIME and MDNs both ways, including openssl's own MIME shapes | `tests/interop_openssl_smime_oracle.rs` | blocking (CI `interop`) |
| **openssl CLI** (`openssl s_server`/`s_client`) | BDEW mutual TLS on BrainpoolP256r1 (BSI TR-03116-3): `s_server -Verify 1` accepts the built-in client's TLS identity and ends a handshake with an untrusted one; `s_client` verifies the testkit `TlsMsh` and its client-certificate demand | `tests/interop_openssl_tls_oracle.rs` | blocking (CI `interop`) |
| **A production Peppol SMP signature** | enveloped-signature verification of a `SignedServiceMetadata` captured from the live network against the real Peppol PKI, with tamper cases | `tests/interop_peppol_smp_oracle.rs` | blocking (CI `check`, no container) |
| **Redis** | the `DedupStore` conformance suite against a real server | `tests/interop_redis_storage_conformance.rs` | blocking (CI `interop`) |

Run them locally with `just interop` (Docker); each test file's module
documentation lists its needs. The ECDSA fixtures and the pinned xmlsec1 image
are described in `tests/fixtures/wssec/ecdsa/README.md`.

Not witnessed by a foreign implementation: duplicate receipts and the 503 for
an in-flight message.

## Official eDelivery conformance testing

The European Commission's eDelivery Conformance Testing Service (on the
Interoperability Test Bed) tests a deployed **access point**, not a library: a
public system under test plus a *SUT Controller* (`Submit`, `Deliver`,
`Notify` over AS4 user messages).

| Conformance requirement | asx |
|---|---|
| Signing, encryption, compression (eDelivery AS4 1.15) | yes, `Profile::edelivery_1_15()` |
| One-Way/Push send and receive with signed NRR receipts | yes |
| Multi-payload messages | yes, but Content-IDs are derived from the message id; the test bed's fixed Content-IDs (`xmlpayload@gitb`, …) cannot be reproduced |
| `PING` (ebMS3 test service) | yes, `Message::ping`; inbound pings are receipted and never delivered |
| `ONEWAY_RETRY` | the application's outbox, resending the same message (see [retrying](@/docs/getting-started.md#retrying)) |
| `SIMPLE_TWOWAY` | not modelled as one MEP |
| A runnable access point at a public URL, and a SUT Controller | not shipped: built around the library by the deployer |

asx holds no official conformance certificate.
