//! AS2 policy configuration, message type definitions, and version validation.
//!
//! The internal types the AS2 send and receive paths are configured with and
//! report through. No crypto or I/O is performed here.

use std::sync::Arc;
use zeroize::Zeroize;

#[cfg(feature = "as2")]
use crate::crypto::as2_smime::SmimeCipher;

/// Raw MIME envelope returned from the AS2 send path, ready for HTTP transport.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MimeEnvelope {
    pub content_type: String,
    pub body: Arc<[u8]>,
}

/// Algorithm used to compute the RFC 4130 §7.3.1 Message Integrity Check (MIC).
///
/// `Sha256` is the default; `Sha384` and `Sha512` are stronger alternatives.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub(crate) enum As2MicAlgorithm {
    /// SHA-256 (RFC 5754). Default.
    #[default]
    Sha256,
    /// SHA-384 (RFC 5754). Stronger alternative; supported by phase2-lib and
    /// pyas2-lib.
    Sha384,
    /// SHA-512 (RFC 5754). Strongest standard MIC algorithm; supported by
    /// phase2-lib and pyas2-lib.
    Sha512,
}

/// Policy governing an outbound AS2 message send.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct As2SendPolicy {
    pub sign: bool,
    pub encrypt: bool,
    pub compress: bool,
    /// MIME Content-Type of the raw payload for RFC 4130 §7.3.1 MIC
    /// computation.  Defaults to `"application/octet-stream"` when `None`.
    pub payload_content_type: Option<&'static str>,
    /// Algorithm used to compute the RFC 4130 §7.3.1 MIC.
    /// Defaults to [`As2MicAlgorithm::Sha256`].
    pub mic_algorithm: As2MicAlgorithm,
    /// Symmetric cipher used for S/MIME (CMS EnvelopedData) encryption when
    /// `encrypt` is `true`.  Defaults to [`SmimeCipher::Aes256Cbc`].
    #[cfg(feature = "as2")]
    pub encryption_cipher: SmimeCipher,
    /// AS2-From header value (this party's AS2 identifier per RFC 4130 §6).
    /// Defaults to `session.session_id()` when empty.
    pub as2_from_id: String,
}

/// Parsed MDN (RFC 4130 §7.4 Disposition Notification).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ParsedMdn {
    pub final_recipient: Option<String>,
    pub original_message_id: Option<String>,
    pub disposition: String,
    pub received_content_mic: Option<String>,
    pub is_signed: bool,
}

/// Signing credentials for MDN generation.
#[derive(Clone, PartialEq, Eq)]
pub struct As2MdnSigningCredentials {
    pub signing_cert_pem: Vec<u8>,
    pub signing_key_pem: Vec<u8>,
}

impl std::fmt::Debug for As2MdnSigningCredentials {
    /// Never prints `signing_key_pem`.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("As2MdnSigningCredentials")
            .field("signing_cert_pem", &self.signing_cert_pem)
            .field(
                "signing_key_pem",
                &crate::core::redact_present(!self.signing_key_pem.is_empty()),
            )
            .finish()
    }
}

impl Drop for As2MdnSigningCredentials {
    fn drop(&mut self) {
        self.signing_key_pem.zeroize();
    }
}
