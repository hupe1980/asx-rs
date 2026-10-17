+++
title = "AS4"
description = "Send and receive AS4 messages, verify receipts, the BDEW path switch and Peppol SMP lookup."
aliases = ["/docs/transport/"]
+++

What you do with `asx::as4` (OASIS ebMS 3.0 with the AS4 profile). What the
preset fixes is on the [profiles page](@/docs/profiles.md).

## Sending

A [`Message`](https://docs.rs/asx-rs/latest/asx/as4/struct.Message.html) is
the partner plus, depending on the profile, service, action and payloads.

```rust
use asx::{as4::{As4, Message}, Partner, Payload};

async fn send_invoice(as4: &As4, partner: &Partner, invoice: Vec<u8>, attachment: Vec<u8>) -> asx::Result<()> {
    let receipt = as4
        .send(Message::to(partner)
            .service("urn:example:services:invoicing")
            .action("urn:example:actions:submit")
            .conversation_id("order-4711")
            .payload(Payload::new(invoice, "application/xml"))
            .payload(Payload::new(attachment, "application/pdf").named("invoice.pdf")))
        .await?;
    println!("signed by {:?}", receipt.signer());
    Ok(())
}
```

- **Payloads.** One MIME part (SwA) each, with Content-IDs derived from the
  message id and part index, so a resend produces the same parts. `named` sets
  a file name (`Content-Disposition`); Peppol refuses it.
- **Action.** Unless the profile fixes it or you set one, the ebMS3 default
  `http://docs.oasis-open.org/ebxml-msg/as4/200902/action`.
- **Message id and timestamp.** Fresh by default; set both from your outbox
  for [retries](@/docs/getting-started.md#retrying).
- **Ping.** `Message::ping(&partner)` sends a test-service message
  (eDelivery 1.15 §3.2.4, BDEW §2.3.6): receipted, never delivered. It still
  needs a payload.

```rust
use asx::{as4::{As4, Message}, Partner, Payload};

async fn ping(as4: &As4, partner: &Partner) -> asx::Result<()> {
    as4.send(Message::ping(partner).payload(Payload::new(b"ping".to_vec(), "text/plain"))).await?;
    Ok(())
}
```

### The BDEW path switch

Mandatory under BDEW (§2.2.8). `Message::path_switch(&partner, PathSwitch::Request)`
sends a payload-less user message (pathSwitch service, requestSwitch action);
the partner answers with a new message carrying `PathSwitch::Confirm`. It is
signed but not encrypted (no payload part, AS4 §5.1.6), so the partner needs no
encryption certificate. `send` refuses it under other profiles and with a
payload, service, action or conversation id.

```rust
use asx::{as4::{As4, Message, PathSwitch, UserMessage}, Partner, Reject, Verified};

async fn handle(msg: Verified<UserMessage>) -> Result<(), Reject> {
    if let Some(PathSwitch::Request) = msg.path_switch() {
        // Record it; confirm from a task spawned after returning Ok, because
        // the handler holds the duplicate-detection claim until it returns.
        return Ok(());
    }
    Ok(())
}

async fn confirm(as4: &As4, requester: &Partner) -> asx::Result<()> {
    as4.send(Message::path_switch(requester, PathSwitch::Confirm)).await?;
    Ok(())
}
```

Correlating confirmations with requests and recording the active path are up
to the application.

## Receipts are evidence

`send` returns `Ok(Verified<Receipt>)` only when the receipt:

1. is signed (a receipt without a signature is never accepted) by a
   certificate pinned for the partner (`Partner::signing_cert`, repeatable for
   rollover) that chains to a trust anchor;
2. refers to the message id that was sent (`eb:RefToMessageId`);
3. carries `ebbp:NonRepudiationInformation` whose digests equal the
   `ds:Reference` digests of the message you signed, every one of them (only
   `Quirk::ReceiptWithoutNonRepudiation` tolerates an absent NRI block);
4. has a fresh `eb:Timestamp` (300 s).

Any failure is `ErrorKind::Indeterminate` (possibly delivered; resend the
same message). An `eb:Error` signal is `ErrorKind::PartnerError` with
`ebms_code()`. `receipt.evidence()` holds the receipt bytes as received, their
SHA-256 and the NRR digest list.

## Receiving

[`As4::inbound(dedup, handler)`](https://docs.rs/asx-rs/latest/asx/as4/struct.As4.html#method.inbound)
returns an `Inbound`: a tower `Service<http::Request<B>>` with error type
`Infallible` (axum: `Router::route_service(path, inbound)`).

The handler is any `Fn(Verified<UserMessage>) -> impl Future<Output = Result<(), Reject>>`
(or a `Handler<UserMessage>`). It runs only for a message that verified,
decrypted and was claimed in the `DedupStore`. Make it idempotent on the
message id: delivery is at least once (a crashed holder's claim is released
when its lease expires). `?` converts any error into a `Reject`.

Each payload's `mime_type()` is the `MimeType` part property of its signed
`eb:PartInfo`, else `application/octet-stream`. A part property named twice
in one `eb:PartInfo` is refused with `EBMS:0004`.

```rust
use asx::{as4::{As4, UserMessage}, DedupStore, Inbound, Reject, Verified};

async fn deliver(msg: Verified<UserMessage>) -> Result<(), Reject> {
    println!(
        "{} from {} ({} / {}), signer {:?}, {} part(s)",
        msg.message_id(), msg.from(), msg.service(), msg.action(), msg.signer(), msg.payloads().len()
    );
    Ok(())
}

fn endpoint(as4: &As4, store: impl DedupStore) -> Inbound {
    as4.inbound(store, deliver)
}
```

### What the sender is told

| Situation | Response | Handler | Dedup |
|---|---|---|---|
| Body above `max_message_bytes` | HTTP 413 | no | — |
| Unparseable, ambiguous, or not SwA | HTTP 400 + `EBMS:0004` | no | — |
| Signature invalid, or signer not authorized for the claimed sender | HTTP 400 + `EBMS:0101` | no | — |
| `eb:To` is not the local party | HTTP 400 + `EBMS:0004` | no | — |
| Unsigned or unencrypted where the profile requires it | HTTP 400 + `EBMS:0103` | no | — |
| Decryption failed (any cause, one indistinguishable answer) | HTTP 400 + `EBMS:0102` | no | — |
| Attachment digest mismatch | HTTP 400 + `EBMS:0101` | no | — |
| Decompression failed | HTTP 400 + `EBMS:0303` | no | — |
| Test-service message | HTTP 200 + signed receipt | no | — |
| Duplicate (`Claim::Duplicate`) | HTTP 200 + a fresh signed receipt | no | unchanged |
| In flight (`Claim::InFlight`) | HTTP 503 | no | unchanged |
| `claim` failed | HTTP 500 + `EBMS:0004` | no | — |
| Handler `Ok`, audit record and `accept` succeed | HTTP 200 + signed NRR receipt | yes | accepted |
| Handler `Err(Reject::new(..))`, or a panic | HTTP 200 + `EBMS:0202` DeliveryFailure (the sender may retry) | yes | abandoned |
| Handler `Err(Reject::permanent(..))` | HTTP 200 + `EBMS:0004` Other (the sender does not retry) | yes | abandoned |
| Handler returns `peppol::not_serviced()` | HTTP 200 + `EBMS:0004` with `PEPPOL:NOT_SERVICED` | yes | abandoned |
| Handler `Ok`, then the audit record or `accept` fails | HTTP 500, no receipt | yes | abandoned |

An unauthenticated sender never causes a private-key operation, dedup write
or audit record. The order of checks is on the
[security page](@/docs/security.md#verification-order).

### Who may send

`bdew()` and `peppol()` accept unconfigured senders whose certificate
matches the claimed party id; eDelivery and ENTSOG accept configured partners
only (see the [profiles table](@/docs/profiles.md#what-each-preset-fixes)). A
configured partner's pinned certificates always apply. To refuse unconfigured
senders, check `msg.from()` in the handler and return `Err`.

## The wire

For comparing captures with a partner's:

- **Signature.** `ds:Signature` inside the `wsse:Security` header targeted at
  the receiver, covering `eb:Messaging` (`wsu:Id="as4-messaging"`), the SOAP
  Body and every attachment (`cid:` references with the
  Attachment-Content-Signature transform). Reference digests are SHA-256.
  ECDSA signature values are XMLDSig 1.1 `r ‖ s` (64 octets on
  BrainpoolP256r1), never ASN.1 DER. `eb:MessageId` carries no `wsu:Id`.
- **Signing token.** BDEW: a `#X509PKIPathv1` BinarySecurityToken, chain
  issuer first, with `wsse11:TokenType="…#X509PKIPathv1"` (WS-I BSP R5215).
  Others: `#X509v3`.
- **Encryption (WSS SwA 1.1 §5.5).** Signed first, then encrypted. The
  `wsse:Security` header holds `xenc:EncryptedKey` (one fresh 128-bit content
  key per message, its `ReferenceList` naming every `EncryptedData`), one
  `xenc:EncryptedData` per part (`Type="…#Attachment-Content-Only"`,
  `MimeType` = the pre-encryption type, `aes128-gcm`, a `CipherReference` to
  the part's `cid:`), the signer token and the signature. Each part travels as
  `application/octet-stream`: IV, ciphertext, tag. Key transport and
  recipient reference are per preset ([profiles](@/docs/profiles.md#as4-presets)).
  Inbound, an `xenc:ReferenceList` directly in `wsse:Security` (phase4's
  shape) is accepted too.
- **Properties.** `eb:Property` values are element text; `CompressionType` and
  `MimeType` are read from the signed `eb:PartProperties` only.

## Peppol: finding a partner

With the `peppol` feature, `peppol::Smp` finds a receiver through BDXL on the
OpenPeppol SML, verifies the SMP signature against your trust anchor, and
returns a `Partner` (endpoint, AP certificate, party id from its CN).

```rust
use asx::{as4::{As4, Message}, peppol::Smp, Payload};

async fn send_to_participant(smp: &Smp, as4: &As4, ubl: Vec<u8>) -> asx::Result<()> {
    let doc_type = "urn:oasis:names:specification:ubl:schema:xsd:Invoice-2::Invoice##urn:cen.eu:en16931:2017#compliant#urn:fdc:peppol.eu:2017:poacc:billing:3.0::2.1";
    let process = "urn:fdc:peppol.eu:2017:poacc:billing:01:1.0";
    let partner = smp
        .lookup(
            "iso6523-actorid-upis::0088:5790002590993",
            &format!("busdox-docid-qns::{doc_type}"),
            &format!("cenbii-procid-ubl::{process}"),
        )
        .await?;
    as4.send(Message::to(&partner)
        .service(process)
        .action(doc_type)
        .payload(Payload::new(ubl, "application/xml")))
        .await?;
    Ok(())
}
```

`Smp::production(http, anchor)` and `Smp::test(http, anchor)` take an
[`HttpClient`](https://docs.rs/asx-rs/latest/asx/trait.HttpClient.html). A
looked-up partner is not registered with the client; it is validated against
the profile at send. A receiver that does not serve a document type returns
`Err(asx::peppol::not_serviced())` from its handler. The SBDH envelope is not
built: put the complete document in the `Payload`.

## Not supported

One-Way/Pull, split/join of large messages, Two-Way MEPs, ordered delivery.
See the [migration page](@/docs/migration.md) for 0.15 users.
