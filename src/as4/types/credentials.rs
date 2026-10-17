//! Key material carriers for send and receipt signing.

use super::*;

/// Credentials required to generate a signed AS4 `eb:Receipt` signal.
///
/// Per eDelivery AS4 v1.15 §5.1.8 and profile derivatives (e.g. BDEW
/// AS4-Profil §2.2.4), receipts must carry a WS-Security XML Signature so
/// that Non-Repudiation of Receipt (NRR) holds.  Pass these credentials to
/// [`crate::as4::signals::generate_signed_receipt_with_nri`].
#[derive(Clone)]
pub struct As4ReceiptCredentials {
    /// PEM-encoded private key used to sign the receipt signal.
    pub signing_key_pem: Vec<u8>,
    /// PEM-encoded X.509 certificate corresponding to `signing_key_pem`.
    pub signing_cert_pem: Vec<u8>,
    /// Key-info profile controlling how the signing certificate appears in
    /// the `<ds:KeyInfo>` element of the generated XML signature.
    pub key_info_profile: WsSecOutboundKeyInfoProfile,
}

impl std::fmt::Debug for As4ReceiptCredentials {
    /// Never prints `signing_key_pem`.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("As4ReceiptCredentials")
            .field(
                "signing_key_pem",
                &crate::core::redact_present(!self.signing_key_pem.is_empty()),
            )
            .field("signing_cert_pem", &self.signing_cert_pem)
            .field("key_info_profile", &self.key_info_profile)
            .finish()
    }
}

impl Drop for As4ReceiptCredentials {
    fn drop(&mut self) {
        self.signing_key_pem.zeroize();
    }
}
