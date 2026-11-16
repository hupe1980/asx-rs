+++
title = "Testing"
description = "Testing an asx integration with the test-util feature: test PKI, loopback partner, a TLS MSH for mutual TLS end to end, counting keys, store suites and trace capture."
+++

The `test-util` feature adds `asx::testkit`: helpers built on the public API.
It changes nothing else, so tests run the production security policy with
throw-away keys.

```toml
[dev-dependencies]
asx-rs = { version = "0.18", features = ["test-util"] }
tokio = { version = "1", features = ["macros", "rt-multi-thread", "test-util"] }
```

## A test PKI per profile

`asx::testkit::pki::TestCa` is a throw-away CA whose party constructors issue
exactly what each profile's `build()` accepts:

| Constructor | Issues |
|---|---|
| `TestCa::sm_pki().bdew_party_at(mp_id, url)` | the SM-PKI certificate triple: separate BrainpoolP256r1 signing, encryption and TLS key pairs, each with the MP-ID as the subject's OU and `url` as its one URI subjectAltName (BDEW 1.2 Kap. 2.3.4.4, RzÜ AS4 2.6 Kap. 5.2); the TLS certificate also carries the URL's host as DNS name and `serverAuth` + `clientAuth`; party type `…:unregistered:BDEW` |
| `TestCa::sm_pki().bdew_party(mp_id)` | the same at `https://mp<mp_id>.testkit.example/as4` |
| `ca.peppol_party(cn)` | one RSA AP certificate for signing and encryption, `cn` as the CN (the party id) |
| `ca.rsa_party(name)` | separate RSA 2048 pairs (eDelivery, ENTSOG) |
| `ca.as2_party(as2_id)` | one RSA 2048 pair for signing and decryption |

A `TestParty` gives `local()` (`LocalParty` with signer, decrypter and TLS
identity), `partner(endpoint)` (`Partner` with pinned certificates),
`endpoint` (a BDEW party's URI subjectAltName: under `Profile::bdew()` the
partner endpoint must be that address) and `anchor()`. For revocation tests,
`TestCa::issue_with` takes a validity window; `TestCa::crl` and `TestCa::ocsp`
produce signed DER responses. `TestCa::issue_with_options` takes
`pki::IssueOptions` (subject attributes, `uri_sans`, `dns_sans`, `eku` as
`pki::Eku`, CRL/OCSP locations, and `key_pem` to certify an existing key
pair) to issue a leaf with one defect for a refusal test. A second certificate
over a party's signing key, used as its TLS or decryption certificate, is how
to test the BDEW key-pair separation (Kap. 2.3.4.4): `build()` compares keys,
not certificates.

## A loopback partner

`asx::testkit::loopback::Loopback` is an `HttpClient` that hands a request for a
mounted URL to that URL's `Inbound`, without socket or TLS. Clones share their
routes:

```rust
use asx::{as4::{As4, Message, UserMessage}, MemoryDedup, Payload, Profile, Reject, Verified};
use asx::testkit::{loopback::Loopback, pki::TestCa};

async fn deliver(msg: Verified<UserMessage>) -> Result<(), Reject> {
    assert_eq!(msg.payloads()[0].bytes().as_ref(), b"UNA:+.? '");
    Ok(())
}

#[tokio::main]
async fn main() -> asx::Result<()> {
    let ca = TestCa::sm_pki();
    // Each party's certificates name its AS4 endpoint (RzÜ AS4 2.6 Kap. 5.2).
    let (a_url, b_url) = ("https://a.example/as4", "https://b.example/as4");
    let (a, b) = (ca.bdew_party_at("9900000000001", a_url), ca.bdew_party_at("9900000000002", b_url));
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
            .payload(Payload::new(b"UNA:+.? '".to_vec(), "application/octet-stream")
                // RzÜ AS4 2.6 Kap. 6: the interchange's metadata.
                .property("BDEWDocumentType", "UTILMD")
                .property("BDEWDocumentDate", "2026-11-16")
                .property("BDEWDocumentNo", "ABC123")))
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

## Mutual TLS end to end

`asx::testkit::tls::TlsMsh` is a real MSH on 127.0.0.1: it serves an `Inbound`
over TLS with the server party's TLS certificate, **requires** a client
certificate issued under the CA you name, and records every client chain, the
SNI name and the handshake count. A second, plain-HTTP listener serves the
CRLs every `TestCa` publishes (host `pki::CRL_HOST`), so the built-in client's
revocation checks — the receipt signer's and, under BDEW, the TLS server
chain's — run over the network too.

The built-in client refuses loopback addresses; pin the MSH and the CRL host
with `Builder::resolve(host, addr)` (the same pin production code uses for a
private interconnect):

```rust,no_run
use asx::{as4::{As4, Message, UserMessage}, MemoryDedup, Payload, Profile, Reject, Verified};
use asx::testkit::{pki::{TestCa, CRL_HOST}, revocation::RevocationHttp, tls::TlsMsh};

async fn accept(_msg: Verified<UserMessage>) -> Result<(), Reject> {
    Ok(())
}

#[tokio::main]
async fn main() -> asx::Result<()> {
    let ca = TestCa::sm_pki();
    let us = ca.bdew_party("9900000000001");
    let them = ca.bdew_party_at("9900000000002", "https://msh.test/as4");
    let receiver = As4::builder(Profile::bdew())
        .local(them.local())
        .trust_anchor(ca.anchor())
        .http_client(RevocationHttp::new())
        .build()?;
    let msh = TlsMsh::start(&them, &ca, receiver.inbound(MemoryDedup::default(), accept)).await;

    let partner = them.partner(msh.url());
    let sender = As4::builder(Profile::bdew())
        .local(us.local())
        .trust_anchor(ca.anchor())
        .partner(partner.clone())
        .resolve(msh.host(), msh.addr())
        .resolve(CRL_HOST, msh.crl_addr())
        .build()?;
    sender
        .send(Message::to(&partner)
            .service("https://www.bdew.de/as4/communication/services/MP")
            .payload(Payload::new(b"UNA:+.? '".to_vec(), "application/edifact")
                .property("BDEWDocumentType", "UTILMD")
                .property("BDEWDocumentDate", "2026-11-16")
                .property("BDEWDocumentNo", "ABC123")))
        .await?;
    // The TLS identity you configured reached the wire.
    assert_eq!(msh.client_certificates()[0][0], us.tls.certificate());
    assert_eq!(msh.server_names(), [Some("msh.test".to_string())]);
    Ok(())
}
```

`TlsMsh::start_tls12` caps the MSH at TLS 1.2, as a peer on OpenSSL before 3.2
negotiates with Brainpool certificates.

## External keys

`asx::testkit::keys::CountingKeys` wraps a test key pair behind `Signer` and
`Decrypter`, counts private-key operations (`signs()`, `decrypts()`) and can
simulate an outage (`fail()`).

## Conformance suites for your stores

- `asx::testkit::dedup::conformance` checks a `DedupStore`
  ([persistence](@/docs/persistence.md#check-your-store-before-production)).
- `asx::testkit::audit::conformance` checks an `AuditSink`
  ([observability](@/docs/observability.md#check-your-sink-before-production)).
- `asx::testkit::audit::MemoryAuditSink` is a durable in-memory sink whose clones
  share one store; `records()` returns what was written.

## Asserting on telemetry

`asx::testkit::trace::TraceCapture` collects spans and events while it is the
default subscriber; names and fields are on the
[observability page](@/docs/observability.md#spans):

```rust
use asx::testkit::trace::TraceCapture;

fn capture_spans() {
    let capture = TraceCapture::new();
    let _guard = capture.set_default();
    // ... run an exchange on a current-thread runtime ...
    for span in capture.spans_named("asx.send") {
        println!("{span:?}");
    }
}
```
