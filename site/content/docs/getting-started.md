+++
title = "Getting started"
description = "Install asx-rs, send and receive AS4 and AS2 messages, and handle errors."
aliases = ["/docs/reliability/"]
+++

## Install and features

```toml
[dependencies]
asx-rs = "0.16"
```

The package is `asx-rs`; the library is `asx`. Features are additive and none
changes what is checked:

| Feature | Enables | Default |
|---|---|---|
| `as2` | AS2 (RFC 4130): `asx::as2` | yes |
| `as4` | AS4 (ebMS3, eDelivery, BDEW, Peppol, ENTSOG): `asx::as4` | yes |
| `http-client` | built-in HTTPS client (HTTPS only, resolved addresses pinned, mTLS identity from `LocalParty::tls_identity`) | yes |
| `peppol` | `asx::peppol::Smp`: SMP lookup through BDXL; implies `as4` | no |
| `metrics` | counters and histograms through the [`metrics`](https://docs.rs/metrics) facade | no |
| `test-util` | `asx::testkit` (see [Testing](@/docs/testing.md)); `[dev-dependencies]` only | no |

Without `http-client`, pass your own [`HttpClient`](https://docs.rs/asx-rs/latest/asx/trait.HttpClient.html)
to `Builder::http_client`. For tests, enable `test-util` in
`[dev-dependencies]` (see [Testing](@/docs/testing.md)).

## Runtime

Clients are `Clone` (an `Arc` inside) and run on any Tokio runtime, including
current-thread. Private-key operations and XML security run on the blocking
pool. Build one client per local party at startup and share it.

## The four values you supply

- a **[`Profile`](@/docs/profiles.md)**: the network preset (`Profile::bdew()`,
  `peppol()`, `edelivery_1_15()`, `entsog()`, `as2()`), the only source of
  security settings;
- the **`LocalParty`**: your party id, a `Signer`, one or more `Decrypter`s
  and, for the built-in client, a TLS identity;
- the **`Partner`s**: party id, HTTPS endpoint, pinned signing certificates,
  encryption certificate;
- at least one **trust anchor**: every signer, yours included, must chain to one.

`build()` validates everything against the profile once and returns
`ErrorKind::Config` naming the setting and profile section. See
[what `build()` refuses](@/docs/profiles.md#what-build-refuses).

## Send an AS4 message

The README's first golden path (`examples/as4_send.rs`) as a function:

```rust
use asx::{as4::{As4, Message}, Certificate, KeyPair, LocalParty, Partner, Payload, Profile};

async fn send(partner: Partner, sig: KeyPair, enc: KeyPair, root: Certificate, edi: Vec<u8>) -> asx::Result<()> {
    let as4 = As4::builder(Profile::bdew())
        .local(LocalParty::new("9900000000001")
            .party_type("urn:oasis:names:tc:ebcore:partyid-type:unregistered:BDEW")
            .signer(sig)
            .decrypter(enc))
        .trust_anchor(root)
        .partner(partner.clone())
        .build()?;
    let receipt = as4
        .send(Message::to(&partner)
            .service("https://www.bdew.de/as4/communication/services/MP")
            .payload(Payload::new(edi, "application/octet-stream")))
        .await?;
    println!("delivered, receipt record {}", receipt.evidence().record_id());
    Ok(())
}
```

`send` compresses, signs, encrypts, posts and verifies the answer. It returns
`Ok(Verified<Receipt>)` only for a receipt signed by a pinned partner
certificate that refers to your message id and echoes the digests you signed
([details](@/docs/as4.md#receipts-are-evidence)). Store `receipt.evidence()`:
it is the audit record ([stored form](@/docs/observability.md#the-stored-form)).

The partner is a plain value:

```rust
use asx::{Certificate, Partner};

fn bdew_partner(sig_pem: &[u8], enc_pem: &[u8]) -> asx::Result<Partner> {
    Ok(Partner::new("9900000000002")
        .party_type("urn:oasis:names:tc:ebcore:partyid-type:unregistered:BDEW")
        .endpoint("https://as4.partner.example/msh")
        .signing_cert(Certificate::from_pem(sig_pem)?)
        .encryption_cert(Certificate::from_pem(enc_pem)?))
}
```

## Receive in axum

`As4::inbound(dedup, handler)` returns an [`Inbound`](https://docs.rs/asx-rs/latest/asx/struct.Inbound.html)
tower `Service`; mount it with `route_service`:

```rust
use asx::{as4::{As4, UserMessage}, MemoryDedup, Reject, Verified};

async fn deliver(msg: Verified<UserMessage>) -> Result<(), Reject> {
    for p in msg.payloads() {
        store(msg.message_id(), p.bytes()).await?;
    }
    Ok(())
}

async fn store(_id: &str, _bytes: &[u8]) -> std::io::Result<()> {
    Ok(())
}

fn router(as4: &As4) -> axum::Router {
    axum::Router::new().route_service("/as4", as4.inbound(MemoryDedup::default(), deliver))
}
```

The endpoint verifies the message, claims it in the `DedupStore`, calls your
handler and answers: `Ok` gets a signed receipt, `Err(Reject::new(..))` an
`EBMS:0202` delivery failure the sender may retry, `Err(Reject::permanent(..))`
an `EBMS:0004` it does not retry (use it after dead-lettering), a duplicate a
fresh receipt without calling the handler. The full
table is on the [AS4 page](@/docs/as4.md#what-the-sender-is-told); the complete
program is `examples/as4_receive_axum.rs`.

`MemoryDedup` forgets everything on restart; in production implement
[`DedupStore`](@/docs/persistence.md) over your database.

## Send AS2 and verify the MDN

```rust
use asx::{as2::{As2, Message}, Certificate, KeyPair, LocalParty, Partner, Payload, Profile};

async fn send_po(partner: Partner, key: KeyPair, ca: Certificate, x12: Vec<u8>) -> asx::Result<()> {
    let as2 = As2::builder(Profile::as2())
        .local(LocalParty::new("OURAS2ID").signer(key.clone()).decrypter(key))
        .trust_anchor(ca)
        .partner(partner.clone())
        .build()?;
    let mdn = as2.send(Message::to(&partner, Payload::new(x12, "application/edi-x12"))).await?;
    println!("MDN verified, record {}", mdn.evidence().record_id());
    Ok(())
}
```

`send` returns only an MDN signed by a pinned partner certificate whose
`Original-Message-ID` and MIC match. See also
[asynchronous MDNs](@/docs/as2.md#asynchronous-mdns).

## Errors

There is one [`Error`](https://docs.rs/asx-rs/latest/asx/struct.Error.html):

| Method | Answers |
|---|---|
| `kind()` | `Config` (nothing sent), `Rejected` (we refused an inbound message, receipt or MDN), `PartnerError` (the partner refused ours), `Transport` (definitely not delivered), `Indeterminate` (possibly delivered: timeout after writing, no or unverifiable receipt), `Backend` (your `DedupStore`, `AuditSink`, `Signer` or `Decrypter` failed) |
| `is_retryable()` | whether resending the **same** message is safe and may succeed: `Transport`, `Indeterminate`, partner `EBMS:0202` or AS2 `unexpected-processing-error`, a partner error with HTTP 5xx, and `Backend` unless the evidence shows delivery |
| `ebms_code()` / `mdn_disposition()` | the AS4 error code or AS2 disposition |
| `evidence()` | the audit record that exists despite the error (unverifiable receipt bytes, the partner's `eb:Error` or negative MDN) |

### Retrying

The library never retries. Your outbox resends the **same** message: same
message id and, for AS4, same timestamp. The receiver's duplicate detection
then makes the resend safe and the signed digests match the first attempt
(AS4 Profile 1.0 §3.2).

```rust
use asx::{as4::{As4, Message}, ErrorKind, Partner, Payload};
use std::time::SystemTime;

/// One attempt of an outbox entry. `id` and `first_attempt` are persisted
/// with the entry, so every attempt sends the same message.
async fn attempt(as4: &As4, partner: &Partner, id: &str, first_attempt: SystemTime, edi: Vec<u8>) -> Result<(), bool> {
    let msg = Message::to(partner)
        .service("https://www.bdew.de/as4/communication/services/MP")
        .message_id(id)
        .timestamp(first_attempt)
        .payload(Payload::new(edi, "application/octet-stream"));
    match as4.send(msg).await {
        Ok(_receipt) => Ok(()),
        Err(e) if e.kind() == ErrorKind::Config => Err(false), // fix the message or configuration
        Err(e) => Err(e.is_retryable()),                       // true: schedule another attempt
    }
}
```

An asx receiver accepts an `eb:Timestamp` up to 300 s ahead and 7 days behind,
so a retry within that time (BDEW: 72 h) is answered as a duplicate with a fresh
receipt.
Message ids must be RFC 2822 `id-left@id-right` (`"{outbox_id}@{your-domain}"`);
`send` refuses anything else with `Config`.
