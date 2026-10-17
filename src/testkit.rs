//! Test support: test PKI, an in-process loopback partner, counting keys,
//! store conformance suites and trace capture.
//!
//! Enabled by the `test-util` feature; use it from `[dev-dependencies]` only.
//! Everything here is built on the public API: nothing in this module weakens
//! a check, so tests that use it run the production security policy.

pub mod audit;
pub mod dedup;
mod der;
pub mod keys;
pub mod loopback;
pub mod pki;
pub mod revocation;
pub mod trace;
