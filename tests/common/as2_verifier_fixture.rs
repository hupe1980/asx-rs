#[cfg(all(feature = "as2", feature = "testing"))]
use asx::as2::{As2TrustVerifier, TrustResult, TrustVerifierSeal};
use asx::core::SessionContext;
#[cfg(all(feature = "as2", feature = "testing"))]
use asx::core::{ReceivedBodyHandle, Result};
#[cfg(all(feature = "as2", feature = "testing"))]
use asx::lifecycle::TrustEvidence;

#[cfg(all(feature = "as2", feature = "testing"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeterministicTrustVerifier {
    trust: TrustEvidence,
}

#[cfg(all(feature = "as2", feature = "testing"))]
impl DeterministicTrustVerifier {
    pub fn new(trust: TrustEvidence) -> Self {
        Self { trust }
    }
}

#[cfg(all(feature = "as2", feature = "testing"))]
impl TrustVerifierSeal for DeterministicTrustVerifier {}

#[cfg(all(feature = "as2", feature = "testing"))]
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
