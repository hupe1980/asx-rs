//! The phase4 counterparty harness: a digest-pinned phase4 peer in a
//! container and the helpers that drive AS4 exchanges with it in both
//! directions, through the public `asx` API only.
//!
//! Include it from a test file with
//!
//! ```text
//! #[path = "common/phase4/mod.rs"]
//! mod phase4;
//! ```
//!
//! # Extension points for other items' cases
//!
//! - **Variants** ([`variant::ProfileVariant`]): a phase4 profile paired with
//!   an `asx` preset and the collaboration values both accept.
//! - **Identities** ([`pki::RunPki`]): one test CA per run; per-variant
//!   leaves for both sides (BDEW: separate signing, encryption and TLS
//!   BrainpoolP256r1 pairs, the MP-ID as the subject OU, `EMT.MAK` in the CN
//!   as phase4's BDEW validator requires).
//! - **Exchanges** ([`exchange`]): `crate_to_phase4`, `phase4_to_crate` and
//!   their tampered twins, each asserting the evidence on both sides.
//! - **Tampering** ([`http::Tamper`]): one flipped byte in the signed
//!   `eb:Messaging`, in the first ciphertext part, or at an offset.
//! - **Known gaps** ([`exchange::Expectation::KnownGap`]): a case known to
//!   fail; it prints `known gap <item>: …` while it
//!   fails for a case reason and fails the run the moment it passes.
//!
//! The harness implements only public extension points: `asx::HttpClient`
//! ([`http::PeerHttp`], a transport adapter) and `asx::Handler` (a recording
//! closure). It never implements or replaces a verifier, policy or check.
#![allow(dead_code, unreachable_pub, clippy::type_complexity)]

pub mod exchange;
pub mod http;
pub mod image;
pub mod inbound;
pub mod peer;
pub mod pki;
pub mod variant;

use std::fmt;

/// Why a case failed: the exchange itself (an assertion about the protocol
/// or the evidence did not hold).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaseFailure(pub String);

impl fmt::Display for CaseFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A harness failure: infrastructure (Docker, image, readiness) or a case.
///
/// `Infra` never counts as a pass and never satisfies a known gap.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HarnessError {
    Infra(String),
    Case(CaseFailure),
}

impl HarnessError {
    pub fn infra(msg: impl Into<String>) -> HarnessError {
        HarnessError::Infra(msg.into())
    }

    pub fn case(msg: impl Into<String>) -> HarnessError {
        HarnessError::Case(CaseFailure(msg.into()))
    }
}

impl fmt::Display for HarnessError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HarnessError::Infra(msg) => write!(f, "INFRA: {msg}"),
            HarnessError::Case(failure) => write!(f, "{failure}"),
        }
    }
}

impl std::error::Error for HarnessError {}

impl From<CaseFailure> for HarnessError {
    fn from(failure: CaseFailure) -> Self {
        HarnessError::Case(failure)
    }
}

/// Lower-case hex SHA-256.
pub fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
