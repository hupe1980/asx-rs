# asx-rs-testkit

Test support for `asx-rs`. Dev-dependency only.

| Module | What it gives you |
|---|---|
| `pki` | Test CAs, key pairs and parties (BDEW, Peppol, AS2); CRLs and OCSP responses dated relative to now |
| `loopback` | An in-process `HttpClient` that routes to a partner's `Inbound` |
| `keys` | `CountingKeys`: a `Signer`/`Decrypter` that counts private-key operations |
| `revocation` | An `HttpClient` that serves CRLs and OCSP responses by URL |
| `dedup` | Conformance suite for `DedupStore` backends |
| `audit` | `MemoryAuditSink` and the conformance suite for `AuditSink` backends |
| `trace` | Capture `tracing` spans and events for assertions |

Everything is built on the public `asx-rs` API. The crate contains no verifier
and nothing that weakens a check, so tests that use it run the production
security policy.
