//! Test support for [`asx-rs`](https://docs.rs/asx-rs).
//!
//! **Dev-dependency only.** Add it under `[dev-dependencies]`; never ship it in
//! a production build.
//!
//! Everything here is built on the public `asx-rs` API. The crate contains no
//! verifier, implements no sealed `asx-rs` trait and has nothing that weakens a
//! check: tests that use it run the production security policy, with test key
//! material and in-memory stand-ins that pass the same validation production
//! configurations pass.

#![forbid(unsafe_code)]
#![warn(missing_debug_implementations, unreachable_pub)]

pub mod audit;
pub mod dedup;
mod der;
pub mod keys;
pub mod loopback;
pub mod pki;
pub mod revocation;
pub mod trace;
