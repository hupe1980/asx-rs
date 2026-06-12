#[cfg(feature = "as2")]
use asx::as2::{As2TrustVerifier, TrustResult, TrustVerifierSeal};
use asx::core::SessionContext;
#[cfg(feature = "as2")]
use asx::core::{ReceivedBodyHandle, Result};
#[cfg(feature = "as2")]
use asx::lifecycle::TrustEvidence;

#[cfg(feature = "as2")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeterministicTrustVerifier {
    trust: TrustEvidence,
}

#[cfg(feature = "as2")]
impl DeterministicTrustVerifier {
    pub fn new(trust: TrustEvidence) -> Self {
        Self { trust }
    }
}

#[cfg(feature = "as2")]
impl TrustVerifierSeal for DeterministicTrustVerifier {}

#[cfg(feature = "as2")]
impl As2TrustVerifier for DeterministicTrustVerifier {
    fn verify_and_decrypt(
        &self,
        _session: &SessionContext,
        _body: &ReceivedBodyHandle,
    ) -> Result<TrustResult> {
        Ok(TrustResult {
            signature: self.trust.signature,
            decryption: self.trust.decryption,
            decrypted_payload: None,
        })
    }
}

#[inline]
pub fn fixture(name: &str) -> Vec<u8> {
    let path = format!("tests/fixtures/{name}");
    std::fs::read(&path).unwrap_or_else(|_| panic!("failed to read fixture: {path}"))
}
