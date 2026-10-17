+++
title = "Testing"
description = "Testing an asx integration with asx-rs-testkit: test PKI, loopback partner, counting keys, store suites and trace capture."
+++

`asx-rs-testkit` is built only on the public `asx` API and weakens no check:
tests run the production security policy with throw-away keys. There is no
test-only feature in `asx`.

```toml
[dev-dependencies]
asx-rs-testkit = "0.16"
tokio = { version = "1", features = ["macros", "rt-multi-thread", "test-util"] }
```

Import it as `asx_testkit`.

## A test PKI per profile

`asx_testkit::pki::TestCa` is a throw-away CA whose party constructors issue
exactly what each profile's `build()` accepts:

| Constructor | Issues |
|---|---|
| `TestCa::sm_pki().bdew_party(mp_id)` | separate BrainpoolP256r1 signing, encryption and TLS key pairs, each with the MP-ID as the subject's OU (BDEW 1.2 §2.3.4.4, RzÜ AS4 2.6 §5.2), party type `…:unregistered:BDEW` |
| `ca.peppol_party(cn)` | one RSA AP certificate for signing and encryption, `cn` as the CN (the party id) |
| `ca.rsa_party(name)` | separate RSA 2048 pairs (eDelivery, ENTSOG) |
| `ca.as2_party(as2_id)` | one RSA 2048 pair for signing and decryption |

A `TestParty` gives `local()` (`LocalParty` with signer, decrypter and TLS
identity), `partner(endpoint)` (`Partner` with pinned certificates) and
`anchor()`. For revocation tests, `TestCa::issue_with` takes a validity window;
`TestCa::crl` and `TestCa::ocsp` produce signed DER responses.

## A loopback partner

`asx_testkit::loopback::Loopback` is an `HttpClient` that hands a request for a
mounted URL to that URL's `Inbound`, without socket or TLS. Clones share their
routes:

```rust
use asx::{as4::{As4, Message, UserMessage}, MemoryDedup, Payload, Profile, Reject, Verified};
use asx_testkit::{loopback::Loopback, pki::TestCa};

async fn deliver(msg: Verified<UserMessage>) -> Result<(), Reject> {
    assert_eq!(msg.payloads()[0].bytes().as_ref(), b"UNA:+.? '");
    Ok(())
}

#[tokio::main]
async fn main() -> asx::Result<()> {
    let ca = TestCa::sm_pki();
    let (a, b) = (ca.bdew_party("9900000000001"), ca.bdew_party("9900000000002"));
    let (a_url, b_url) = ("https://a.example/as4", "https://b.example/as4");
    let net = Loopback::new();

    let receiver = As4::builder(Profile::bdew())
        .local(b.local())
        .trust_anchor(b.anchor())
        .partner(a.partner(a_url))
        .http_client(net.clone())
        .build()?;
    net.mount(b_url, receiver.inbound(MemoryDedup::default(), deliver));

    let sender = As4::builder(Profile::bdew())
        .local(a.local())
        .trust_anchor(a.anchor())
        .partner(b.partner(b_url))
        .http_client(net.clone())
        .build()?;
    let receipt = sender
        .send(Message::to(&b.partner(b_url))
            .service("https://www.bdew.de/as4/communication/services/MP")
            .payload(Payload::new(b"UNA:+.? '".to_vec(), "application/octet-stream")))
        .await?;
    assert_eq!(receipt.signer(), &b.signing.certificate());
    assert_eq!(net.requests(), 1);
    Ok(())
}
```

`Loopback::intercept` rewrites responses before the sender sees them (e.g. a
tampered receipt must be `Indeterminate`); `last_request` returns the request
as sent.

## Testing your handler

`Verified` has no public constructor, so test a handler through the loopback:
mount your `inbound` and send from a second client, as above. Keep business
logic in a function of plain values (`message_id`, `from`, payload bytes) and
unit-test that directly. Payloads carry their media type: on AS4 the `eb:PartInfo`
`MimeType`, on AS2 the Content-Type of the signed entity (of the inner MIME
entity when compressed).

## External keys

`asx_testkit::keys::CountingKeys` wraps a test key pair behind `Signer` and
`Decrypter`, counts private-key operations (`signs()`, `decrypts()`) and can
simulate an outage (`fail()`).

## Conformance suites for your stores

- `asx_testkit::dedup::conformance` checks a `DedupStore`
  ([persistence](@/docs/persistence.md#check-your-store-before-production)).
- `asx_testkit::audit::conformance` checks an `AuditSink`
  ([observability](@/docs/observability.md#check-your-sink-before-production)).
- `asx_testkit::audit::MemoryAuditSink` is a durable in-memory sink whose clones
  share one store; `records()` returns what was written.

## Asserting on telemetry

`asx_testkit::trace::TraceCapture` collects spans and events while it is the
default subscriber; names and fields are on the
[observability page](@/docs/observability.md#spans):

```rust
use asx_testkit::trace::TraceCapture;

fn capture_spans() {
    let capture = TraceCapture::new();
    let _guard = capture.set_default();
    // ... run an exchange on a current-thread runtime ...
    for span in capture.spans_named("asx.send") {
        println!("{span:?}");
    }
}
```

## The crate's own evidence

How this crate itself is tested against foreign implementations is on the
[conformance page](@/docs/conformance.md).
