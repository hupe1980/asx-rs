use crate::core::{AsxError, ErrorCode, ErrorContext, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureVerification {
    Verified,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecryptionMaterial {
    Available,
    Missing,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrustEvidence {
    pub signature: SignatureVerification,
    pub decryption: DecryptionMaterial,
}

impl TrustEvidence {
    pub fn verified_and_decryptable() -> Self {
        Self {
            signature: SignatureVerification::Verified,
            decryption: DecryptionMaterial::Available,
        }
    }

    pub fn signature_failed() -> Self {
        Self {
            signature: SignatureVerification::Failed,
            decryption: DecryptionMaterial::Available,
        }
    }

    pub fn missing_decryption_material() -> Self {
        Self {
            signature: SignatureVerification::Verified,
            decryption: DecryptionMaterial::Missing,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UntrustedBytes<T> {
    payload: T,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StructurallyParsed<T> {
    payload: T,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CryptographicallyVerified<T> {
    payload: T,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContentDecrypted<T> {
    payload: T,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainReady<T> {
    payload: T,
}

impl<T> UntrustedBytes<T> {
    pub fn new(payload: T) -> Self {
        Self { payload }
    }

    pub fn into_inner(self) -> T {
        self.payload
    }

    /// Structurally validate the payload using a caller-supplied validator, then
    /// advance to [`StructurallyParsed<U>`].
    ///
    /// The validator receives a shared reference to the raw payload and must
    /// return `Ok(U)` (the parsed form) or an `AsxError` on failure. Using a
    /// typed `U` allows the parsed form to differ from the raw type `T` — for
    /// example, `T = Arc<[u8]>` and `U = ParsedSoapEnvelope`.
    ///
    /// ## Example
    ///
    /// ```rust,ignore
    /// let parsed = UntrustedBytes::new(raw_bytes)
    ///     .parse_with(|bytes| {
    ///         enforce_payload_limit("stage", bytes.len(), MAX_BYTES)?;
    ///         if bytes.is_empty() {
    ///             return Err(AsxError::new(ErrorCode::ParseFailed, "empty payload", ctx));
    ///         }
    ///         Ok(bytes.clone())
    ///     })?;
    /// ```
    pub fn parse_with<U, E>(
        self,
        validator: impl FnOnce(T) -> std::result::Result<U, E>,
    ) -> Result<StructurallyParsed<U>>
    where
        E: Into<AsxError>,
    {
        validator(self.payload)
            .map(|parsed| StructurallyParsed { payload: parsed })
            .map_err(Into::into)
    }

    /// Advance directly to [`StructurallyParsed<T>`] **without any structural
    /// validation**.
    ///
    /// Use this **only** when structural validation was already performed by an
    /// external code path before the payload was wrapped in `UntrustedBytes` —
    /// for example, after a cryptographic verifier that also enforces payload
    /// size and encoding constraints.
    ///
    /// Prefer [`parse_with`](Self::parse_with) when the caller can express the
    /// structural invariant as a closure.  Using `into_parsed_unchecked`
    /// bypasses all structural guarantees and should be auditable at every
    /// call site.
    pub fn into_parsed_unchecked(self) -> StructurallyParsed<T> {
        StructurallyParsed {
            payload: self.payload,
        }
    }
}

impl<T> AsRef<T> for UntrustedBytes<T> {
    fn as_ref(&self) -> &T {
        &self.payload
    }
}

impl<T> StructurallyParsed<T> {
    pub fn into_inner(self) -> T {
        self.payload
    }

    pub fn verify(
        self,
        verification: SignatureVerification,
    ) -> Result<CryptographicallyVerified<T>> {
        if verification != SignatureVerification::Verified {
            return Err(AsxError::new(
                ErrorCode::SecurityVerificationFailed,
                "cryptographic verification failed",
                ErrorContext::new("trust_state_verify"),
            ));
        }

        Ok(CryptographicallyVerified {
            payload: self.payload,
        })
    }
}

impl<T> AsRef<T> for StructurallyParsed<T> {
    fn as_ref(&self) -> &T {
        &self.payload
    }
}

impl<T> CryptographicallyVerified<T> {
    pub fn into_inner(self) -> T {
        self.payload
    }

    pub fn decrypt(self, material: DecryptionMaterial) -> Result<ContentDecrypted<T>> {
        if material != DecryptionMaterial::Available {
            return Err(AsxError::new(
                ErrorCode::DecryptionFailed,
                "decryption key unavailable",
                ErrorContext::new("trust_state_decrypt"),
            ));
        }

        Ok(ContentDecrypted {
            payload: self.payload,
        })
    }
}

impl<T> AsRef<T> for CryptographicallyVerified<T> {
    fn as_ref(&self) -> &T {
        &self.payload
    }
}

impl<T> ContentDecrypted<T> {
    pub fn into_inner(self) -> T {
        self.payload
    }

    pub fn into_domain_ready(self) -> DomainReady<T> {
        DomainReady {
            payload: self.payload,
        }
    }
}

impl<T> AsRef<T> for ContentDecrypted<T> {
    fn as_ref(&self) -> &T {
        &self.payload
    }
}

impl<T> DomainReady<T> {
    pub fn into_inner(self) -> T {
        self.payload
    }
}

impl<T> AsRef<T> for DomainReady<T> {
    fn as_ref(&self) -> &T {
        &self.payload
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forward_only_flow_succeeds() {
        let trust = TrustEvidence::verified_and_decryptable();
        let ready = UntrustedBytes::new(vec![1, 2, 3])
            .into_parsed_unchecked()
            .verify(trust.signature)
            .expect("verify")
            .decrypt(trust.decryption)
            .expect("decrypt")
            .into_domain_ready();

        assert_eq!(ready.as_ref(), &vec![1, 2, 3]);
    }

    #[test]
    fn failed_verify_and_decrypt_use_stage_codes() {
        let verify_fail = TrustEvidence::signature_failed();
        let verify_err = UntrustedBytes::new("x")
            .into_parsed_unchecked()
            .verify(verify_fail.signature)
            .expect_err("verify fails");
        assert_eq!(verify_err.code, ErrorCode::SecurityVerificationFailed);

        let missing_key = TrustEvidence::missing_decryption_material();
        let decrypt_err = UntrustedBytes::new("x")
            .into_parsed_unchecked()
            .verify(missing_key.signature)
            .expect("verify ok")
            .decrypt(missing_key.decryption)
            .expect_err("decrypt fails");
        assert_eq!(decrypt_err.code, ErrorCode::DecryptionFailed);
    }
}
