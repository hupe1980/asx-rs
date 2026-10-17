+++
title = "AS2"
description = "Send AS2 with a verified synchronous or asynchronous MDN, and receive with MDN dispositions."
+++

AS2 (RFC 4130) is S/MIME over HTTP with a Message Disposition Notification
(MDN) as receipt. `Profile::as2()` fixes the security settings
([profiles](@/docs/profiles.md#as2)).

## Sending with a synchronous MDN

An AS2 [`Message`](https://docs.rs/asx-rs/latest/asx/as2/struct.Message.html)
is one payload to one partner.

```rust
use asx::{as2::{As2, Message}, ErrorKind, Partner, Payload};

async fn send_x12(as2: &As2, partner: &Partner, outbox_id: &str, x12: Vec<u8>) -> asx::Result<()> {
    let msg = Message::to(partner, Payload::new(x12, "application/edi-x12"))
        .message_id(format!("{outbox_id}@sender.example"));
    match as2.send(msg).await {
        Ok(mdn) => {
            println!("processed; MDN record {}", mdn.evidence().record_id());
            Ok(())
        }
        Err(e) if e.kind() == ErrorKind::PartnerError => {
            println!("partner refused: {:?}", e.mdn_disposition());
            Err(e)
        }
        Err(e) => Err(e),
    }
}
```

`send` returns `Ok(Verified<Receipt>)` only for an MDN that is signed by a
pinned partner certificate (unsigned only with `Quirk::UnsignedMdn`), names
the sent id in `Original-Message-ID`, echoes the MIC over the signed entity
(RFC 4130 §7.3.1) and reports `processed` (warnings allowed). A
`processed/error` or `failed` MDN is `ErrorKind::PartnerError` with
`mdn_disposition()`. An MDN that fails any check is `ErrorKind::Indeterminate`:
resend with the same message id.

`message_id` takes an RFC 2822 `id-left@id-right` value (sent as `<id>`);
without it a fresh one is generated. `Payload::named` is refused.

## Asynchronous MDNs

`send_async_mdn(msg, receipt_url)` sends with
`Receipt-Delivery-Option: receipt_url` and returns a
[`PendingMdn`](https://docs.rs/asx-rs/latest/asx/as2/struct.PendingMdn.html),
which holds no secret; persist its `serde` form (versioned JSON) with the
outbox entry. When the MDN arrives on your receipt URL, look it up and verify:

```rust
use asx::{as2::{As2, PendingMdn}, ErrorKind};
use bytes::Bytes;

async fn on_mdn(as2: &As2, request: http::Request<Bytes>, load: impl Fn(&str) -> Option<PendingMdn>) -> asx::Result<bool> {
    // Unauthenticated: only a lookup key. verify_async_mdn checks it.
    let Some(key) = PendingMdn::lookup_key(&request) else { return Ok(false) };
    let Some(pending) = load(&key) else { return Ok(false) };
    match as2.verify_async_mdn(request, &pending).await {
        Ok(_mdn) => Ok(true),
        Err(e) if e.kind() == ErrorKind::Rejected => Ok(false), // not an MDN for this message
        Err(e) => Err(e),
    }
}
```

A request that is not an MDN for `pending` is `ErrorKind::Rejected`; one that
fails verification is `ErrorKind::Indeterminate`. The audit record is written
when the MDN is verified.

## Receiving

`As2::inbound(dedup, handler)` returns the same `Inbound` tower `Service` as
[AS4](@/docs/as4.md#receiving), with a handler over [`Received`](https://docs.rs/asx-rs/latest/asx/as2/struct.Received.html).

```rust
use asx::{as2::{As2, Received}, MemoryDedup, Reject, Verified};

async fn deliver(msg: Verified<Received>) -> Result<(), Reject> {
    let p = msg.payload();
    println!("{} from {}: {} bytes of {}", msg.message_id(), msg.from(), p.bytes().len(), p.mime_type());
    Ok(())
}

fn router(as2: &As2) -> axum::Router {
    axum::Router::new().route_service("/as2", as2.inbound(MemoryDedup::default(), deliver))
}
```

The payload is decrypted, verified and, if compressed (RFC 5402),
decompressed. `mime_type()` is the signed entity's `Content-Type`; for a
compressed entity, that of the MIME entity inside the CompressedData.
`AS2-From` must be a configured partner whose pinned certificate signed.

### MDN dispositions

| Situation | Answer | Handler | Dedup |
|---|---|---|---|
| Body above `max_message_bytes` | HTTP 413 | no | — |
| Unparseable | HTTP 400, with an MDN `processed/error: unexpected-processing-error` when one can be addressed | no | — |
| Unknown sender, bad signature or unpinned signer | MDN `processed/error: authentication-failed` | no | — |
| `AS2-To` is not the local party | MDN `processed/error: unexpected-processing-error` | no | — |
| Unsigned or unencrypted | MDN `processed/error: insufficient-message-security` | no | — |
| Decryption failed (one answer for every cause) | MDN `processed/error: decryption-failed` | no | — |
| Decompression failed, or the compressed content is not a MIME entity | MDN `processed/error: decompression-failed` | no | — |
| Duplicate `(AS2-From, Message-ID)` | MDN `processed/warning: duplicate-document` | no | unchanged |
| In flight | HTTP 503 | no | unchanged |
| `claim` failed | HTTP 500, no MDN | no | — |
| Handler `Ok`, audit record and `accept` succeed | signed MDN `processed` with the MIC | yes | accepted |
| Handler `Err`, or a panic | MDN `processed/error: unexpected-processing-error` | yes | abandoned |
| Handler `Ok`, then the audit record or `accept` fails | HTTP 500, no MDN | yes | abandoned |

Every MDN is signed and returned synchronously, even when the sender asked
for an asynchronous one. An unknown sender never causes a private-key
operation.

## Not supported

Sending asynchronous MDNs as receiver, streaming receive, outbound
compression. See the [migration page](@/docs/migration.md) for 0.15 users.
