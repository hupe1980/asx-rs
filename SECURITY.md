# Security Policy

`asx-rs` verifies signatures, decrypts payloads and accepts messages from
counterparties it does not control, so a flaw in it can be a flaw in an access
point. Please report one privately.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting:
<https://github.com/hupe1980/asx-rs/security/advisories/new>.
Do not open a public issue or pull request for a suspected vulnerability.

Please include the affected version, the feature flags and profile in use, and
a reproducer — ideally the inbound message or the sequence of calls. Reports
are handled on a best-effort basis by the maintainer; you will get an
acknowledgement, and a fix is released as a new version with a GitHub security
advisory (and a RustSec advisory where it applies) crediting you unless you ask
otherwise.

In scope, for example:

- a signature, encryption, receipt or certificate check that can be bypassed or
  that accepts what the active profile says to reject;
- memory exhaustion, a panic or unbounded work reachable from inbound
  network input;
- secret material (keys, passwords, session secrets) exposed through `Debug`,
  logs, errors or metrics.

Not a vulnerability: behaviour of the `testing` feature, which disables
WS-Security enforcement on purpose and refuses to compile in a release build;
and a profile or `interop-relaxed` exception that an embedder enables
explicitly, as long as it does what its documentation says.

## Supported versions

The crate is pre-1.0. Fixes go into the latest published minor version only;
upgrade to receive them. The [SemVer policy](CHANGELOG.md#semver-policy)
describes what a minor version may change.

## Dependencies and releases

Dependencies are checked against the RustSec advisory database and a licence
and source policy (`deny.toml`) on every push and pull request. From 0.16.0,
releases are published only by the CI-gated release workflow with crates.io
trusted publishing; see [RELEASING.md](RELEASING.md).
