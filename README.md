# asx-rs

**AS2 and AS4 B2B messaging for Rust: async, memory-safe, and strict by default.**

[![Crates.io](https://img.shields.io/crates/v/asx-rs.svg)](https://crates.io/crates/asx-rs)
[![Docs.rs](https://docs.rs/asx-rs/badge.svg)](https://docs.rs/asx-rs)
[![License](https://img.shields.io/crates/l/asx-rs.svg)](#license)

`asx-rs` implements [AS2 (RFC 4130)](https://www.rfc-editor.org/rfc/rfc4130) and
[AS4 (OASIS ebMS3 / eDelivery)](https://docs.oasis-open.org/ebxml-msg/ebms/v3.0/profiles/AS4-profile/v1.0/)
for the networks that use them: the German energy market (BDEW AS4-Profil 1.2),
Peppol, eDelivery AS4 1.15, ENTSOG 3.6, and classic AS2 trading partners.

It is an **embeddable library**, not a gateway: no container, no database, no
JVM. You get the protocol and the cryptography; storage, keys and deployment
stay yours.

📖 **[Documentation](https://hupe1980.github.io/asx-rs)** ·
🦀 **[API reference](https://docs.rs/asx-rs)** ·
📋 **[Changelog](CHANGELOG.md)** ·
🔀 **[Migrating](https://hupe1980.github.io/asx-rs/docs/migration/)**

---

## Install

```toml
[dependencies]
asx-rs = "0.17"
```

The package is `asx-rs`; the library is `asx`. Features are additive and
none changes security behaviour:

| Flag | Enables | Default |
|------|---------|---------|
| `as2` | AS2 (RFC 4130): `asx::as2` | ✅ |
| `as4` | AS4 (ebMS3, eDelivery, BDEW, Peppol, ENTSOG): `asx::as4` | ✅ |
| `http-client` | The built-in HTTPS client (OpenSSL, pooled; HTTPS only, SNI, private addresses refused unless pinned, mTLS identity; BSI TR-03116-3 with Brainpool under BDEW) | ✅ |
| `peppol` | SMP lookup through BDXL (`asx::peppol::Smp`); implies `as4` | ❌ |
| `metrics` | Counters and histograms through the `metrics` facade (spans via `tracing` are always on) | ❌ |
| `test-util` | `asx::testkit`: test PKI, loopback partner, a TLS MSH on 127.0.0.1, store suites; `[dev-dependencies]` only | ❌ |

## Golden paths

Pick a network profile, say who you are and who your partners are; the client
signs, encrypts, compresses and verifies as that network requires.

**Send a BDEW AS4 message and keep the verified receipt**
([`examples/as4_send.rs`](examples/as4_send.rs)):

```rust,no_run
//! Golden path 1: send a BDEW AS4 message and keep the verified receipt.
//! (Formatted by hand: the README includes this file verbatim.)
#[rustfmt::skip]
use asx::{as4::{As4, Message}, Certificate, KeyPair, LocalParty, Partner, Payload, Profile};
use std::fs::read;

#[rustfmt::skip]
#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // The endpoint is the URI the partner's encryption certificate names (RzÜ AS4 2.6 Kap. 2).
    let partner = Partner::new("9900000000002").party_type("urn:oasis:names:tc:ebcore:partyid-type:unregistered:BDEW")
        .signing_cert(Certificate::from_pem(&read("partner-sig.crt")?)?)
        .encryption_cert(Certificate::from_pem(&read("partner-enc.crt")?)?);
    let as4 = As4::builder(Profile::bdew())
        .local(LocalParty::new("9900000000001").party_type("urn:oasis:names:tc:ebcore:partyid-type:unregistered:BDEW")
            .signer(KeyPair::from_pem(&read("sig.crt")?, &read("sig.key")?)?)
            .decrypter(KeyPair::from_pem(&read("enc.crt")?, &read("enc.key")?)?)
            .tls_identity(KeyPair::from_pem(&read("tls.crt")?, &read("tls.key")?)?)) // BrainpoolP256r1 mutual TLS
        .trust_anchor(Certificate::from_pem(&read("sm-pki-root.crt")?)?)
        .partner(partner.clone())
        .build()?;
    let receipt = as4.send(Message::to(&partner).service("https://www.bdew.de/as4/communication/services/MP")
        .payload(Payload::new(read("UTILMD.edi")?, "application/octet-stream").named("UTILMD.txt")
            .property("BDEWDocumentType", "UTILMD").property("BDEWDocumentDate", "2026-11-16") // RzÜ AS4 2.6 Kap. 6
            .property("BDEWDocumentNo", "ABC123"))).await?;
    std::fs::write("receipt.json", serde_json::to_vec(receipt.evidence())?)?; // the audit record as JSON
    Ok(())
}
```

On `Err`, `kind()` and `is_retryable()` say what happened and whether
resending the same message is safe.

**Receive AS4 messages in axum**
([`examples/as4_receive_axum.rs`](examples/as4_receive_axum.rs)):

```rust,no_run
//! Golden path 2: receive BDEW AS4 messages in an axum router.
//! (Formatted by hand: the README includes this file verbatim.)
#[rustfmt::skip]
use asx::{as4::{As4, UserMessage}, Certificate, KeyPair, LocalParty, MemoryDedup, Partner, Profile, Reject, Verified};
use std::fs::read;

#[rustfmt::skip]
async fn deliver(msg: Verified<UserMessage>) -> Result<(), Reject> {
    for (i, p) in msg.payloads().iter().enumerate() { tokio::fs::write(format!("inbox/{}-{i}", msg.message_id()), p.bytes()).await?; }
    Ok(()) // -> signed receipt; Err -> EBMS:0202; duplicates are answered without calling this
}

#[rustfmt::skip]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let as4 = As4::builder(Profile::bdew())
        .local(LocalParty::new("9900000000001").party_type("urn:oasis:names:tc:ebcore:partyid-type:unregistered:BDEW")
            .signer(KeyPair::from_pem(&read("sig.crt")?, &read("sig.key")?)?)
            .decrypter(KeyPair::from_pem(&read("enc.crt")?, &read("enc.key")?)?)
            .tls_identity(KeyPair::from_pem(&read("tls.crt")?, &read("tls.key")?)?)) // the SM-PKI triple (RzÜ AS4 2.6 Kap. 1.3)
        .trust_anchor(Certificate::from_pem(&read("sm-pki-root.crt")?)?)
        .partner(Partner::new("9900000000002").party_type("urn:oasis:names:tc:ebcore:partyid-type:unregistered:BDEW")
            .signing_cert(Certificate::from_pem(&read("partner-sig.crt")?)?)
            .encryption_cert(Certificate::from_pem(&read("partner-enc.crt")?)?))
        .build()?;
    let app = axum::Router::new().route_service("/as4", as4.inbound(MemoryDedup::default(), deliver));
    axum::serve(tokio::net::TcpListener::bind("0.0.0.0:8443").await?, app).await?; // terminate TLS in front
    Ok(())
}
```

`Inbound` is a tower `Service`: it verifies, claims the message in the
`DedupStore`, calls your handler and answers with a signed receipt, an ebMS
error or 503.

**Send AS2 and keep the verified MDN**
([`examples/as2_send_mdn.rs`](examples/as2_send_mdn.rs)):

```rust,no_run
//! Golden path 3: send an AS2 message and keep the verified MDN.
//! (Formatted by hand: the README includes this file verbatim.)
#[rustfmt::skip]
use asx::{as2::{As2, Message}, Certificate, KeyPair, LocalParty, Partner, Payload, Profile};
use std::fs::read;

#[rustfmt::skip]
#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cert = Certificate::from_pem(&read("partner.crt")?)?;
    let partner = Partner::new("THEIRAS2ID").endpoint("https://partner.example/as2")
        .signing_cert(cert.clone()).encryption_cert(cert);
    let key = KeyPair::from_pem(&read("me.crt")?, &read("me.key")?)?;
    let as2 = As2::builder(Profile::as2())
        .local(LocalParty::new("OURAS2ID").signer(key.clone()).decrypter(key))
        .trust_anchor(Certificate::from_pem(&read("ca.crt")?)?)
        .partner(partner.clone()).build()?;
    let mdn = as2.send(Message::to(&partner, Payload::new(read("po.x12")?, "application/edi-x12"))).await?;
    std::fs::write("mdn.json", serde_json::to_vec(mdn.evidence())?)?; // signature, MIC and Original-Message-ID verified, or Err
    Ok(())
}
```

Key material to try them: `cargo run -p xtask -- example-pki examples/pki`
(run the examples from that directory).

## What is verified for you

`send` returns `Ok(Verified<Receipt>)`, and `inbound` calls your handler with
`Verified<UserMessage>` (AS2: `Verified<Received>`), only after these checks,
in order: the signer chains to a trust anchor and is authorized for the
claimed sender, the signature value, the digest of every signed part, the
addressee, revocation, the timestamp, decryption and the replay store. A
receipt's non-repudiation digests must equal what you signed; an MDN's MIC and
`Original-Message-ID` must match. `Verified<T>` has no public constructor and
carries its audit record (`evidence()`).

## Design

- **A profile, not knobs.** `Profile::bdew()`, `peppol()`, `edelivery_1_15()`,
  `entsog()` and `as2()` fix algorithms, token references, packaging,
  compression, party-id rules and receipt requirements. Nothing loosens a
  profile; misconfiguration is refused at `build()`.
- **A verified signature is not an identity.** BDEW senders must carry their
  MP-ID as the certificate subject's OU, Peppol access points their party id
  as CN; other profiles accept configured partners only. Pinned partner
  certificates always apply.
- **BDEW end to end.** `build()` checks the SM-PKI certificate triple (MP-ID
  in the OU, exactly one URI subjectAltName, the partner endpoint taken from
  it: RzÜ AS4 2.6 Kap. 2, 5.2); the built-in client speaks BSI TR-03116-3
  mutual TLS (details under Status).
- **Keys can live in an HSM or KMS.** `Signer` and `Decrypter` are async traits
  for the private-key operation; `KeyPair` is the in-memory implementation.
- **Integration points are traits.** `DedupStore`, `AuditSink` and
  `HttpClient` are yours to implement; `asx::testkit` has the conformance
  suites. No retry scheduler, storage backend or listener is built in.

See the **[security model](https://hupe1980.github.io/asx-rs/docs/security/)**
for trust boundaries and what the library does *not* protect against, and the
**[threat model](THREAT_MODEL.md)** (also on docs.rs as `asx::threat_model`)
for every known threat class with its status and evidence.

## Status

**Beta.** No `unsafe` (`#![forbid(unsafe_code)]`); MSRV Rust 1.88.

- Presets: BDEW AS4-Profil 1.2, Peppol AS4 2.0.3, eDelivery AS4 1.15,
  ENTSOG 3.6, AS2 (RFC 4130).
- AS4 One-Way/Push: sign, then encrypt (WSS SwA 1.1), gzip; signed NRR
  receipts; duplicates, the test service and the BDEW path switch handled;
  part properties (`Payload::property`) under every profile.
- AS2: signed and encrypted, signed MDN with the MIC verified, asynchronous
  MDNs (`PendingMdn`), duplicate detection.
- WS-Security: RSA-SHA256, ECDSA-SHA256 (`r ‖ s`, brainpoolP256r1 for BDEW),
  RSA-OAEP, ECDH-ES + ConcatKDF + AES-KW, AES-GCM.
- Revocation from CRL distribution points (and OCSP outside BDEW), for
  message signers and, under BDEW, the TLS server chain.
- TLS: OpenSSL with connection pooling and SNI; under BDEW mutual TLS on
  BrainpoolP256r1 (BSI TR-03116-3), the SM-PKI root as the only TLS trust,
  the server chain CRL-checked before a request is written; TLS 1.3 from
  OpenSSL 3.2, TLS 1.2 before.
- Peppol SMP lookup returning a `Partner`.

Independent witnesses (phase4, Holodeck B2B, xmlsec1, the openssl CLI, a
production Peppol SMP signature, Redis) are listed on the
**[conformance page](https://hupe1980.github.io/asx-rs/docs/conformance/)**.

Not supported: AS4 pull, split/join, Two-Way MEPs, sending asynchronous AS2
MDNs, streaming AS2, LDAP CRL distribution points, a revocation cache shared
between processes. There is no official conformance certificate.

## Contributing

`just ci` runs the CI checks locally; [`RELEASING.md`](RELEASING.md) lists
the workflows. The site is built with [Zola](https://www.getzola.org) from
`site/`.

## Versioning

Pre-1.0: breaking changes ship in minor versions. The
[changelog](CHANGELOG.md) separates **wire/crypto** changes, which can break
interop even when your code compiles, from **API** changes.

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your option.
