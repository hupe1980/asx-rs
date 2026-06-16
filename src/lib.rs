/*!
# asx — AS2/AS4 EDI protocol library

`asx` is an async-native, memory-safe Rust library for the AS2 (RFC 4130) and
AS4 (OASIS ebMS3 + eDelivery) EDI transport protocols.

## Feature flags

 The crate uses Cargo feature flags to limit the compiled surface and dependency
 tree.  The **default** feature set is `["interop-strict", "async-ocsp", "compression"]`.

| Feature | Enables | Required by |
|---|---|---|
| `as2` | AS2 send/receive free functions (`as2::send_sync`, `as2::receive_sync`) and async wrappers (`as2::send_async`, `as2::receive_async`) | anything using AS2 |
| `as4` | AS4 send/receive free functions (`as4::send_sync`, `as4::receive_push_with_dedup_sync`), `As4PullStore`, and protocol configuration (`pmode`, `types`) | anything using AS4 |
| `compression` | Zlib/GZIP payload compression via `flate2` | AS2/AS4 `policy.compress = true` (default) |
| `async-ocsp` | Async OCSP responder fetching via `reqwest` | production OCSP validation |
| `interop-strict` | **(default)** Strict interop mode as the default | All profiles |
| `interop-relaxed` | Relaxed mode helpers available alongside strict | Legacy partner interop |
| `trace` | Experimental `tracing` instrumentation for selected protocol paths | Observability |
| `prometheus` | Built-in Prometheus/OpenMetrics text `MetricsSink` adapter (`observability::PrometheusMetricsSink`) | Native metrics export |
| `testing` | Exposes `fixtures` and `matrix` test-scaffold modules | Integration test harness |
| `server` | Axum router integration (`as2_router`, `as4_router`, `As2AxumHandler`, `As4AxumHandler`) | HTTP receive |
| `client` | Async HTTP egress transport via `reqwest` (`As2HttpTransport`, `As4HttpTransport`) | HTTP send |

`reqwest` dependency note:
- Enabling `async-ocsp` pulls `reqwest` for OCSP HTTP fetches.
- Enabling `client` also pulls `reqwest` for protocol egress transports.
- Enabling both features reuses the same crate dependency; there is no second HTTP stack.

### Minimal feature combinations

```toml
# AS2 only (sign, encrypt, OCSP; compression is enabled by default):
asx = { version = "0.2", features = ["as2", "async-ocsp"] }

# AS4 only (sign, encrypt; compression is enabled by default):
asx = { version = "0.2", features = ["as4", "async-ocsp"] }

# Both protocols with compression:
asx = { version = "0.2", features = ["as2", "as4", "compression", "async-ocsp"] }

# Both protocols, relaxed interop for legacy partners:
asx = { version = "0.2", features = ["as2", "as4", "interop-relaxed", "async-ocsp"] }

```

> **Note:** `as2` and `as4` are **not** in the default feature set.
> Adding `asx` without explicit features compiles only the shared
> infrastructure (`core`, `crypto`, `reliability`, `observability`).

## Security notes

- AS2 trust-verifier traits are intentionally open so applications and tests can
  supply their own verification backends. Prefer local deterministic test
  verifiers over crate-exported bypass helpers.
- PKIX chain validation requires at least one trust-anchor PEM in
  `CertHandle::trust_anchor_pems` (fail-closed when empty).
- OCSP freshness checking (thisUpdate/nextUpdate) is enforced automatically
  when `OcspMode` is not `Disabled`.
- HTTP egress transports are HTTPS-only.
*/

pub mod alerting;
pub mod core;
#[cfg(any(feature = "as2", feature = "as4"))]
pub mod credentials;
pub mod crypto;
pub mod http;
pub mod interop;
pub mod lifecycle;
pub mod observability;
pub mod presets;

// Compile-time guards for invalid feature combinations.
#[cfg(all(feature = "server", not(any(feature = "as2", feature = "as4"))))]
compile_error!(
    "the `server` feature requires at least one of `as2` or `as4` to be enabled alongside it; \
     e.g. features = [\"server\", \"as2\"] or features = [\"server\", \"as4\"]"
);

// Block `testing` in release profile.  The guard uses the `cargo_release_profile`
// cfg flag emitted by build.rs (derived from the `PROFILE` env var) rather than
// `not(debug_assertions)`, which can be defeated by
// `[profile.release] debug-assertions = true` in an embedder's Cargo.toml.
#[cfg(all(feature = "testing", cargo_release_profile))]
compile_error!(
    "the `testing` feature must not be enabled in release builds; \
     remove `testing` from your feature list for production or release workflows"
);

#[cfg(feature = "testing")]
pub mod fixtures;
#[cfg(feature = "testing")]
pub mod matrix;
pub mod reliability;
#[cfg(feature = "as4")]
pub mod sbdh;
#[cfg(any(feature = "as2", feature = "as4"))]
pub(crate) mod send_pipeline;
pub mod storage;
pub mod transport;
#[cfg(any(feature = "as2", feature = "as4"))]
pub mod wire;

#[cfg(feature = "as2")]
pub mod as2;

#[cfg(feature = "as4")]
pub mod as4;

#[cfg(feature = "client")]
#[cfg(feature = "as4")]
pub mod smp;

#[cfg(feature = "client")]
pub mod incident_channels;

pub use core::{AsxError, CryptoAdmissionControl, ErrorCode, ErrorContext, Result};
#[cfg(any(feature = "as2", feature = "as4"))]
pub use credentials::PartnerCredentials;

#[cfg(test)]
mod tests {
    use crate::core::InteropMode;

    #[test]
    fn default_interop_mode_is_strict() {
        assert_eq!(InteropMode::default(), InteropMode::Strict);
    }
}
