//! AS4 inbound verification, called by `As4::inbound` (`super::inbound`).
//!
//! The order is fixed: [`authenticate_inbound`] (bounded parse, sender
//! authorization, `SignatureValue` and same-document digests, `eb:To`), then
//! the caller's revocation check of the signer path, then [`open_inbound`]
//! (freshness, payload set = `eb:PartInfo`, envelope, decryption, `cid:`
//! digests over the decrypted bytes, decompression). No key is used before
//! the signature verified; the dedup claim is taken by the caller afterwards.
//!
//! | Module | Role |
//! |--------|------|
//! | `metadata` | Parse the envelope and verify its WS-Security header |
//! | `processing` | `authenticate_inbound` and `open_inbound` |
//! | `payload` | Declared parts, part properties, restored types, decompression |
//! | `verifier` | `As4Verifier`, `As4WsSecVerifier`, attachment-coverage checks |
//!
//! ebMS3 Part 2 split/join and conversation ordering are not supported.

mod metadata;
mod payload;
mod processing;
mod verifier;
use crate::core::Result;

pub(crate) use processing::{TO_PARTY_STAGE, VerifiedInbound, authenticate_inbound, open_inbound};
pub(super) use verifier::{As4Verifier, As4WsSecVerifier};

/// Who may sign as the claimed sender.
pub(crate) struct SenderAuthorization {
    /// Pinned signer certificates; empty when the rule alone decides.
    pub(crate) pins: Vec<crate::crypto::CertFingerprint>,
    /// The profile rule over the signer certificate (DER).
    pub(crate) check: Option<Box<crate::crypto::wssec::verify::SignerCheck>>,
}

/// Resolves the claimed sender (unauthenticated `eb:From`) to the rule its
/// signature must satisfy. Refusing here refuses before any signature work.
pub(crate) trait SenderAuthorizer: Send + Sync {
    fn authorize(&self, parsed: &super::ParsedAs4UserMessage) -> Result<SenderAuthorization>;
}

#[cfg(test)]
mod tests;
