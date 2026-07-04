//! Unified cross-protocol credential container for AS2/AS4 send paths.
//!
//! `PartnerCredentials` provides one zeroizing PEM bundle that can be projected
//! into protocol-specific credential structs (`As2SendCredentials` /
//! `As4SendCredentials`) or prepared directly against protocol policies.

use crate::core::{ErrorCode, Result};
use std::sync::Arc;
use zeroize::Zeroize;

#[cfg(feature = "as2")]
use crate::as2::{As2PreparedSendCredentials, As2SendCredentials, As2SendPolicy};
#[cfg(feature = "as4")]
use crate::as4::{As4PreparedSendCredentials, As4SendCredentials, As4SendPolicy};

/// Unified partner credential bundle for AS2/AS4 outbound messaging.
///
/// This type centralizes signing and encryption PEM material so one caller
/// object can drive either protocol's send path.
#[derive(Debug, Clone, Default)]
pub struct PartnerCredentials {
    /// PEM-encoded signing certificate.
    pub signing_cert_pem: Option<Arc<[u8]>>,
    /// PEM-encoded signing private key.
    pub signing_key_pem: Option<Vec<u8>>,
    /// PEM-encoded recipient certificate used for encryption.
    pub recipient_cert_pem: Option<Arc<[u8]>>,
}

impl Drop for PartnerCredentials {
    fn drop(&mut self) {
        if let Some(key) = self.signing_key_pem.as_mut() {
            key.zeroize();
        }
    }
}

impl PartnerCredentials {
    /// Project unified credentials into AS2 send credentials.
    #[cfg(feature = "as2")]
    pub fn to_as2_send_credentials(&self) -> As2SendCredentials {
        As2SendCredentials {
            signing_cert_pem: self.signing_cert_pem.clone(),
            signing_key_pem: self.signing_key_pem.clone(),
            recipient_cert_pem: self.recipient_cert_pem.clone(),
        }
    }

    /// Project unified credentials into AS4 send credentials.
    #[cfg(feature = "as4")]
    pub fn to_as4_send_credentials(&self) -> As4SendCredentials {
        As4SendCredentials {
            signing_cert_pem: self.signing_cert_pem.clone(),
            signing_key_pem: self.signing_key_pem.clone(),
            recipient_cert_pem: self.recipient_cert_pem.clone(),
        }
    }

    /// Prepare AS2 credentials once for repeated send operations.
    #[cfg(feature = "as2")]
    pub fn prepare_as2_for_policy(
        &self,
        policy: &As2SendPolicy,
        stage: &'static str,
        error_code: ErrorCode,
    ) -> Result<As2PreparedSendCredentials> {
        self.to_as2_send_credentials()
            .prepare_for_policy(policy, stage, error_code)
    }

    /// Prepare AS4 credentials once for repeated send operations.
    #[cfg(feature = "as4")]
    pub fn prepare_as4_for_policy(
        &self,
        policy: &As4SendPolicy,
        stage: &'static str,
        error_code: ErrorCode,
    ) -> Result<As4PreparedSendCredentials> {
        self.to_as4_send_credentials()
            .prepare_for_policy(policy, stage, error_code)
    }

    /// Import a `PartnerCredentials` bundle from a PKCS#12 (`.p12` / `.pfx`) file.
    ///
    /// Most enterprise PKI systems and many trading-partner onboarding portals
    /// distribute key material as PKCS#12 bundles.  This constructor parses the
    /// DER-encoded bundle, extracts the signing certificate and private key as
    /// PEM, and stores them in the returned credential object.
    ///
    /// If the bundle contains a `safebag` of additional certificates they are
    /// silently ignored — only the primary end-entity certificate and its
    /// associated private key are extracted.  The `recipient_cert_pem` field is
    /// left `None` and can be set by the caller afterwards via direct field
    /// assignment.
    ///
    /// # Security
    ///
    /// The passphrase is accepted as a `&str` slice and is **not zeroized**
    /// after use because OpenSSL copies it internally.  If passphrase hygiene
    /// is critical, zero the source buffer after this call returns.
    ///
    /// # Errors
    ///
    /// Returns `ErrorCode::InvalidInput` if the DER bytes are not a valid
    /// PKCS#12 bundle, or if the passphrase is incorrect.
    #[cfg(any(feature = "as2", feature = "as4"))]
    pub fn from_pkcs12(der: &[u8], passphrase: &str) -> crate::core::Result<Self> {
        use crate::core::{AsxError, ErrorContext};
        use openssl::pkcs12::Pkcs12;

        let pkcs12 = Pkcs12::from_der(der).map_err(|e| {
            AsxError::new(
                ErrorCode::InvalidInput,
                format!("PKCS#12 DER parsing failed: {e}"),
                ErrorContext::new("credentials_from_pkcs12"),
            )
        })?;

        let parsed = pkcs12.parse2(passphrase).map_err(|e| {
            AsxError::new(
                ErrorCode::InvalidInput,
                format!("PKCS#12 passphrase or structure error: {e}"),
                ErrorContext::new("credentials_from_pkcs12"),
            )
        })?;

        let signing_cert_pem = parsed
            .cert
            .as_ref()
            .map(|cert| {
                cert.to_pem()
                    .map_err(|e| {
                        AsxError::new(
                            ErrorCode::InvalidInput,
                            format!("PKCS#12 certificate to PEM conversion failed: {e}"),
                            ErrorContext::new("credentials_from_pkcs12"),
                        )
                    })
                    .map(Arc::from)
            })
            .transpose()?;

        let signing_key_pem = parsed
            .pkey
            .as_ref()
            .map(|key| {
                key.private_key_to_pem_pkcs8().map_err(|e| {
                    AsxError::new(
                        ErrorCode::InvalidInput,
                        format!("PKCS#12 private key to PEM conversion failed: {e}"),
                        ErrorContext::new("credentials_from_pkcs12"),
                    )
                })
            })
            .transpose()?;

        Ok(Self {
            signing_cert_pem,
            signing_key_pem,
            recipient_cert_pem: None,
        })
    }
}

#[cfg(feature = "as2")]
impl From<As2SendCredentials> for PartnerCredentials {
    fn from(mut value: As2SendCredentials) -> Self {
        let result = Self {
            signing_cert_pem: value.signing_cert_pem.take(),
            signing_key_pem: value.signing_key_pem.take(),
            recipient_cert_pem: value.recipient_cert_pem.take(),
        };
        // All fields have been moved out; skip As2SendCredentials::drop so the
        // zeroize-on-drop does not run over already-None fields (no-op but wastes
        // cycles).  The transferred bytes are exclusively owned by `result`
        // (PartnerCredentials), which zeroizes them on its own Drop.
        std::mem::forget(value);
        result
    }
}

#[cfg(feature = "as2")]
impl From<PartnerCredentials> for As2SendCredentials {
    fn from(value: PartnerCredentials) -> Self {
        let mut value = value;
        Self {
            signing_cert_pem: value.signing_cert_pem.take(),
            signing_key_pem: value.signing_key_pem.take(),
            recipient_cert_pem: value.recipient_cert_pem.take(),
        }
    }
}

#[cfg(feature = "as4")]
impl From<As4SendCredentials> for PartnerCredentials {
    fn from(mut value: As4SendCredentials) -> Self {
        let result = Self {
            signing_cert_pem: value.signing_cert_pem.take(),
            signing_key_pem: value.signing_key_pem.take(),
            recipient_cert_pem: value.recipient_cert_pem.take(),
        };
        // Same rationale as From<As2SendCredentials>: skip the no-op zeroize
        // on already-None fields; PartnerCredentials is the canonical zeroizer.
        std::mem::forget(value);
        result
    }
}

#[cfg(feature = "as4")]
impl From<PartnerCredentials> for As4SendCredentials {
    fn from(value: PartnerCredentials) -> Self {
        let mut value = value;
        Self {
            signing_cert_pem: value.signing_cert_pem.take(),
            signing_key_pem: value.signing_key_pem.take(),
            recipient_cert_pem: value.recipient_cert_pem.take(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::PartnerCredentials;
    use std::sync::Arc;

    #[cfg(feature = "as2")]
    #[test]
    fn partner_credentials_roundtrip_as2_projection() {
        let src = PartnerCredentials {
            signing_cert_pem: Some(Arc::from(b"cert" as &[u8])),
            signing_key_pem: Some(b"key".to_vec()),
            recipient_cert_pem: Some(Arc::from(b"recipient" as &[u8])),
        };

        let as2 = src.to_as2_send_credentials();
        assert_eq!(as2.signing_cert_pem.as_deref(), Some(b"cert".as_slice()));
        assert_eq!(as2.signing_key_pem.as_deref(), Some(b"key".as_slice()));
        assert_eq!(
            as2.recipient_cert_pem.as_deref(),
            Some(b"recipient".as_slice())
        );
    }

    #[cfg(feature = "as4")]
    #[test]
    fn partner_credentials_roundtrip_as4_projection() {
        let src = PartnerCredentials {
            signing_cert_pem: Some(Arc::from(b"cert" as &[u8])),
            signing_key_pem: Some(b"key".to_vec()),
            recipient_cert_pem: Some(Arc::from(b"recipient" as &[u8])),
        };

        let as4 = src.to_as4_send_credentials();
        assert_eq!(as4.signing_cert_pem.as_deref(), Some(b"cert".as_slice()));
        assert_eq!(as4.signing_key_pem.as_deref(), Some(b"key".as_slice()));
        assert_eq!(
            as4.recipient_cert_pem.as_deref(),
            Some(b"recipient".as_slice())
        );
    }
}
