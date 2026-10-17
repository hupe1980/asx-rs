//! AS2 and AS4 messaging. Start at [`as4::As4::builder`] or
//! [`as2::As2::builder`].
//!
//! `asx-rs` is an async, memory-safe library for the AS2 (RFC 4130) and AS4
//! (OASIS ebMS3 + eDelivery) EDI transport protocols. The crate is published
//! as `asx-rs`; the library is imported as `asx`.
//!
//! A client is built once from a [`Profile`] (every security and wire setting
//! of a network, cited), the [`LocalParty`], the [`Partner`]s and the trust
//! anchors. It sends a message and returns the partner's receipt or MDN only
//! as a [`Verified`] value, and its `inbound` endpoint verifies, deduplicates
//! ([`DedupStore`]) and answers before calling a [`Handler`].
//!
//! ## Feature flags
//!
//! | Feature | Enables |
//! |---|---|
//! | `as2` (default) | [`as2`] |
//! | `as4` (default) | [`as4`] |
//! | `http-client` (default) | the built-in HTTPS [`HttpClient`] |
//! | `peppol` | [`peppol`]: SMP lookup through BDXL with the bundled DNS resolver; implies `as4` |
//! | `metrics` | counters and histograms through the [`metrics`](https://docs.rs/metrics) facade |
//!
//! Without `http-client`, pass an [`HttpClient`] to [`Builder::http_client`].
//!
//! ## Observability
//!
//! Every send, receive, verification and audit write runs inside a `tracing`
//! span under target `asx` (`RUST_LOG=asx=info`); the library never installs a
//! subscriber or a metrics recorder, and nothing an observer does changes a
//! protocol outcome. Evidence of each exchange leg goes to an [`AuditSink`].
//! Span, field and metric names are a documented contract.

// The crate parses MIME, SOAP, XML and CMS straight off the network. Memory
// safety there is the entire point, so `unsafe` is not merely absent — it
// cannot be added.
#![forbid(unsafe_code)]
// A build with one protocol (or none), or without the built-in HTTP client,
// compiles shared building blocks only the missing feature calls. Dead code is
// checked where every block has a caller: the default build.
#![cfg_attr(
    not(all(feature = "as2", feature = "as4", feature = "http-client")),
    allow(dead_code, unused_imports)
)]

mod audit;
mod clock;
#[allow(unreachable_pub)]
pub(crate) mod core;
#[allow(unreachable_pub)]
pub(crate) mod crypto;
// The AS4 timestamp helpers and the audit record's `recorded_at` share it.
#[cfg_attr(not(feature = "as4"), allow(dead_code))]
pub(crate) mod time_utils;

#[cfg(any(feature = "as2", feature = "as4"))]
pub(crate) mod runtime;
#[cfg(feature = "as4")]
#[allow(unreachable_pub)]
pub(crate) mod sbdh;
#[cfg(any(feature = "as2", feature = "as4"))]
pub(crate) mod send_pipeline;
mod telemetry;
#[cfg(test)]
pub(crate) mod test_support;
// The README and the site pages, compiled as doctests (`src/docs.rs`).
#[cfg(all(
    doctest,
    feature = "as2",
    feature = "as4",
    feature = "http-client",
    feature = "peppol",
    feature = "metrics"
))]
mod docs;
#[allow(unreachable_pub)]
pub(crate) mod transport;
#[cfg(any(feature = "as2", feature = "as4"))]
#[allow(unreachable_pub)]
pub(crate) mod wire;
/// One XML parser, one writer, one namespace table.
#[cfg(feature = "as4")]
pub(crate) mod xml;

#[cfg(feature = "as2")]
pub mod as2;

#[cfg(feature = "as4")]
pub mod as4;

#[cfg(feature = "peppol")]
#[allow(unreachable_pub)]
pub(crate) mod smp;

/// Peppol network rules that sit above a single protocol.
#[cfg(feature = "peppol")]
pub mod peppol;

// ── The client API ────────────────────────────────────────────────────────────
#[cfg(any(feature = "as2", feature = "as4"))]
mod builder;
mod dedup;
mod error;
#[cfg(any(feature = "as2", feature = "as4"))]
mod http_client;
#[cfg(any(feature = "as2", feature = "as4"))]
mod inbound;
#[cfg(any(feature = "as2", feature = "as4"))]
mod keys;
#[cfg(any(feature = "as2", feature = "as4"))]
mod party;
#[cfg(any(feature = "as2", feature = "as4"))]
mod profile;
/// The one revocation validator.
#[cfg(any(feature = "as2", feature = "as4"))]
pub(crate) mod revocation;
#[cfg(any(feature = "as2", feature = "as4"))]
mod verified;

pub use audit::{AuditDurability, AuditRecord, AuditSink};
#[cfg(any(feature = "as2", feature = "as4"))]
pub use builder::Builder;
#[doc(hidden)]
pub use dedup::__dedup_key;
pub use dedup::{Claim, ClaimToken, DedupStore, MemoryDedup};
#[doc(hidden)]
pub use error::__mapping;
pub use error::{BoxFuture, Error, ErrorKind, Result};
#[cfg(any(feature = "as2", feature = "as4"))]
pub use http_client::HttpClient;
#[cfg(any(feature = "as2", feature = "as4"))]
pub use inbound::{Handler, Inbound, Reject};
#[cfg(any(feature = "as2", feature = "as4"))]
pub use keys::{Certificate, Decrypter, KeyOp, KeyPair, SignatureAlgorithm, Signer};
#[cfg(any(feature = "as2", feature = "as4"))]
pub use party::{LocalParty, Partner};
#[cfg(any(feature = "as2", feature = "as4"))]
#[doc(hidden)]
pub use profile::probe as __profile_probe;
#[cfg(any(feature = "as2", feature = "as4"))]
pub use profile::{Profile, Quirk};
#[cfg(any(feature = "as2", feature = "as4"))]
pub use verified::{Payload, Receipt, Verified};

/// Entry points of the vector, oracle, property and fuzz suites: the
/// crate-private XML-security and SMP building blocks those suites drive
/// directly. **Not part of the API**: hidden from the
/// documentation, excluded from the public-API snapshot, and changed without
/// notice. Applications use the clients.
#[doc(hidden)]
pub mod __fuzz {
    pub use crate::core::{
        AsxError, ErrorCode, ErrorContext, Result, SessionContext, SessionContextBuilder,
    };
    #[cfg(any(feature = "as2", feature = "as4"))]
    pub use crate::crypto::CertFingerprint;
    #[cfg(feature = "as4")]
    pub use crate::crypto::{soap_builder, wssec};
    /// The revocation module's decision on static material.
    #[cfg(any(feature = "as2", feature = "as4"))]
    pub use crate::revocation::vectors as revocation;
    #[cfg(feature = "peppol")]
    pub mod smp {
        pub use crate::smp::*;
    }
    // Crate-private generators the vector and property suites drive to craft
    // inputs the clients never produce (a receipt without NRI, odd MDNs).
    #[cfg(feature = "as2")]
    pub use crate::as2::mdn::{generate_mdn, generate_signed_mdn};
    #[cfg(feature = "as2")]
    pub use crate::as2::send_path::raw_message as as2_raw_message;
    #[cfg(feature = "as2")]
    pub use crate::as2::types::As2MdnSigningCredentials;
    #[cfg(feature = "as4")]
    pub use crate::as4::signals::{
        generate_error_signal, generate_receipt, generate_receipt_with_nri,
        generate_signed_receipt_with_nri,
    };
    #[cfg(feature = "as4")]
    pub use crate::as4::types::{
        As4ErrorCode, As4ErrorSeverity, As4NriReference, As4ReceiptCredentials,
    };
    #[cfg(feature = "as2")]
    pub use crate::crypto::as2_smime::sign_smime_message;
    #[cfg(feature = "as2")]
    pub use crate::crypto::compression::{AS2_COMPRESSED_CONTENT_TYPE, compress_cms_zlib};
    #[cfg(feature = "as4")]
    pub mod sbdh {
        pub use crate::sbdh::*;
    }
}
