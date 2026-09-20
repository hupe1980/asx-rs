//! Which signing certificate is permitted for which claimed sender.
//!
//! An AS4 receiver verifies that a message's signature is cryptographically
//! valid and chains to a trust anchor. Neither fact says the message came from
//! the party it *claims* to come from: every access point on a network shares
//! the network's PKI, so any of them can produce a signature that verifies
//! against the same anchors.
//!
//! Pinning closes that. The receiver states, per partner, which certificate
//! that partner signs with; the verifier then refuses a message whose signer is
//! not the pinned one. Because the pin is looked up by the **claimed**
//! `eb:From` party id and checked against the **verified** signer, a match
//! proves the claim.

use crate::core::{AsxError, ErrorCode, ErrorContext, Result};
use crate::crypto::CertFingerprint;
use std::collections::HashMap;
use std::fmt;

/// Resolves the signing certificates a claimed sender is allowed to use.
///
/// Implement this against whatever already knows your partners — a config
/// file, a partner table, an SMP cache. [`As4SignerPinMap`] is the in-memory
/// implementation for a static partner list.
pub trait As4SignerPins: Send + Sync + fmt::Debug {
    /// Fingerprints permitted for `from_party_id`, the primary
    /// `<eb:From>/<eb:PartyId>` of the inbound message.
    ///
    /// Returning an **empty slice refuses the message**: an unknown party has
    /// no permitted signer, and guessing is the failure this type prevents.
    /// Returning several permits any of them, which is what a certificate
    /// rollover needs — pin both the outgoing and incoming certificate for the
    /// overlap, then drop the old one.
    ///
    /// This is called on the receive path for every signed message, after the
    /// envelope is parsed and before the signature is checked. Keep it cheap;
    /// it is not async, so a database lookup belongs behind a cache.
    fn pins_for(&self, from_party_id: &str) -> &[CertFingerprint];
}

/// A static partner → permitted-signers map.
///
/// ```
/// use asx_rs::as4::As4SignerPinMap;
/// use asx_rs::crypto::CertFingerprint;
///
/// # fn main() -> asx_rs::Result<()> {
/// let pins = As4SignerPinMap::new()
///     .pin(
///         "9900000000001",
///         CertFingerprint::parse(
///             "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
///         )?,
///     );
/// # Ok(())
/// # }
/// ```
///
/// During a partner's certificate rollover, pin both:
///
/// ```
/// # use asx_rs::as4::As4SignerPinMap;
/// # use asx_rs::crypto::CertFingerprint;
/// # fn main() -> asx_rs::Result<()> {
/// # let outgoing = CertFingerprint::parse(&"ab".repeat(32))?;
/// # let incoming = CertFingerprint::parse(&"cd".repeat(32))?;
/// let pins = As4SignerPinMap::new()
///     .pin("9900000000001", outgoing)
///     .pin("9900000000001", incoming); // both valid during the overlap
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Default, Clone)]
pub struct As4SignerPinMap {
    by_party: HashMap<String, Vec<CertFingerprint>>,
}

impl As4SignerPinMap {
    /// An empty map. Every party is unknown, so every signed message is
    /// refused until something is pinned.
    pub fn new() -> Self {
        Self::default()
    }

    /// Permit `fingerprint` for `party_id`, keeping any already pinned for it.
    #[must_use]
    pub fn pin(mut self, party_id: impl Into<String>, fingerprint: CertFingerprint) -> Self {
        self.insert(party_id, fingerprint);
        self
    }

    /// [`pin`](Self::pin), by `&mut`.
    pub fn insert(&mut self, party_id: impl Into<String>, fingerprint: CertFingerprint) {
        let entry = self.by_party.entry(party_id.into()).or_default();
        if !entry.contains(&fingerprint) {
            entry.push(fingerprint);
        }
    }

    /// Permit the signer of `cert_pem` for `party_id`.
    ///
    /// The common case: you have the partner's certificate, not its hash.
    ///
    /// # Errors
    /// Whatever [`CertFingerprint::from_cert_pem`] rejects.
    pub fn pin_cert_pem(mut self, party_id: impl Into<String>, cert_pem: &[u8]) -> Result<Self> {
        self.insert(party_id, CertFingerprint::from_cert_pem(cert_pem)?);
        Ok(self)
    }

    /// Number of parties with at least one pin.
    pub fn len(&self) -> usize {
        self.by_party.len()
    }

    /// Whether nothing is pinned — in which case every signed message is
    /// refused.
    pub fn is_empty(&self) -> bool {
        self.by_party.is_empty()
    }
}

impl As4SignerPins for As4SignerPinMap {
    fn pins_for(&self, from_party_id: &str) -> &[CertFingerprint] {
        self.by_party
            .get(from_party_id)
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }
}

/// The error a receive returns when the claimed sender has no pinned signer.
pub(crate) fn unpinned_sender_error(
    stage: &'static str,
    session: &crate::core::SessionContext,
    from_party_id: &str,
) -> AsxError {
    AsxError::new(
        ErrorCode::PolicyViolation,
        format!(
            "no signing certificate is pinned for the claimed sender '{from_party_id}', \
             so a valid signature could not be attributed to it. Supply \
             As4ReceivePush::signer_pins covering this party, or pin a single \
             partner with SessionContextBuilder::with_fingerprint_sha256"
        ),
        ErrorContext::for_session(stage, session),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fp(seed: &str) -> CertFingerprint {
        CertFingerprint::parse(&seed.repeat(32)).expect("fingerprint")
    }

    #[test]
    fn an_unknown_party_has_no_pins() {
        let pins = As4SignerPinMap::new().pin("known", fp("ab"));
        assert!(pins.pins_for("stranger").is_empty());
        assert_eq!(pins.pins_for("known"), &[fp("ab")]);
    }

    #[test]
    fn rollover_permits_both_certificates() {
        let pins = As4SignerPinMap::new()
            .pin("p1", fp("ab"))
            .pin("p1", fp("cd"));
        assert_eq!(pins.pins_for("p1").len(), 2);
    }

    #[test]
    fn pinning_the_same_value_twice_is_idempotent() {
        let pins = As4SignerPinMap::new()
            .pin("p1", fp("ab"))
            .pin("p1", fp("ab"));
        assert_eq!(pins.pins_for("p1").len(), 1);
    }

    /// One partner's certificate must not authenticate another partner.
    #[test]
    fn pins_do_not_leak_between_parties() {
        let pins = As4SignerPinMap::new()
            .pin("p1", fp("ab"))
            .pin("p2", fp("cd"));
        assert_eq!(pins.pins_for("p1"), &[fp("ab")]);
        assert_eq!(pins.pins_for("p2"), &[fp("cd")]);
    }
}
