//! Spool-at-rest encryption keys.
//!
//! Regulated profiles spool large inbound payloads to disk rather than holding
//! them in memory, and those spool files are encrypted. This module defines
//! where the key comes from.
//!
//! # Bring your own key manager
//!
//! [`SpoolEncryptionKeyProvider`] is the integration point. A real deployment
//! resolves the key from AWS KMS, HashiCorp Vault, an HSM, or a Kubernetes
//! secret — each with its own SDK, authentication model and error semantics.
//! This crate does not try to speak those protocols for you; it asks for 32
//! bytes and stays out of the way:
//!
//! ```rust,ignore
//! #[derive(Debug)]
//! struct VaultSpoolKey { client: vault::Client, path: String }
//!
//! impl SpoolEncryptionKeyProvider for VaultSpoolKey {
//!     fn label(&self) -> &'static str { "vault" }
//!
//!     fn resolve_key(&self, _session: &SessionContext) -> Result<Arc<[u8; 32]>> {
//!         let secret = self.client.read(&self.path)?;
//!         Ok(Arc::new(secret.try_into()?))
//!     }
//! }
//! ```
//!
//! For development, a fixed key from the environment or a file is enough — see
//! [`StaticSpoolKey`].

use std::fmt;
use std::path::Path;
use std::sync::Arc;

use crate::core::{AsxError, ErrorCode, ErrorContext, Result, SessionContext};

/// Supplies the AES-256 key used to encrypt spooled payload bytes at rest.
///
/// Implementations are consulted when a receive path decides to spool, so
/// `resolve_key` sits on the hot path: cache inside the implementation rather
/// than calling a remote key manager per message.
///
/// The key is returned behind an `Arc` so it can be shared without copying;
/// implementations that hold long-lived key material should zeroize it on drop.
pub trait SpoolEncryptionKeyProvider: Send + Sync + fmt::Debug {
    /// Resolve the 32-byte spool encryption key for this session.
    ///
    /// `session` is supplied so a provider can scope keys per partner or
    /// tenant; implementations that use one key everywhere may ignore it.
    fn resolve_key(&self, session: &SessionContext) -> Result<Arc<[u8; 32]>>;

    /// Short, stable label identifying the backing key manager.
    ///
    /// Appears in audit events, so keep it constant across releases:
    /// `"aws-kms"`, `"vault"`, `"static"`.
    fn label(&self) -> &'static str {
        "custom"
    }
}

/// A spool key held in memory, resolved once at construction.
///
/// Every constructor fails immediately on a missing or malformed key, so a
/// misconfiguration surfaces at startup rather than on the first large inbound
/// message.
///
/// Suitable for development and for deployments that inject the key through an
/// orchestrator secret. Production deployments with a key manager should
/// implement [`SpoolEncryptionKeyProvider`] directly.
pub struct StaticSpoolKey {
    key: Arc<[u8; 32]>,
    label: &'static str,
}

impl fmt::Debug for StaticSpoolKey {
    /// Never prints the key.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StaticSpoolKey")
            .field("label", &self.label)
            .finish_non_exhaustive()
    }
}

impl StaticSpoolKey {
    /// Use `key` directly.
    pub fn from_bytes(key: [u8; 32]) -> Result<Self> {
        reject_unusable_key(&key)?;
        Ok(Self {
            key: Arc::new(key),
            label: "static",
        })
    }

    /// Parse a 64-character hex string.
    pub fn from_hex(hex: &str) -> Result<Self> {
        Self::from_bytes(*parse_spool_key_hex(hex)?)
    }

    /// Read a 64-character hex string from the named environment variable.
    ///
    /// The variable name is a parameter rather than a crate constant: the name
    /// belongs to your deployment, and a library that reads hardcoded
    /// environment variables is configured by invisible global state.
    pub fn from_env(var: &str) -> Result<Self> {
        let raw = std::env::var(var).map_err(|_| {
            AsxError::new(
                ErrorCode::PolicyViolation,
                format!("spool encryption key environment variable {var} is not set"),
                ErrorContext::new("as2_spool_key_from_env"),
            )
        })?;
        Self::from_hex(&raw)
    }

    /// Read a 64-character hex string from a file.
    ///
    /// Trailing whitespace and a trailing newline are tolerated so the file can
    /// be written by ordinary tooling.
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let raw = std::fs::read_to_string(path).map_err(|err| {
            AsxError::new(
                ErrorCode::PolicyViolation,
                format!(
                    "failed to read spool encryption key from {}: {err}",
                    path.display()
                ),
                ErrorContext::new("as2_spool_key_from_file"),
            )
        })?;
        Self::from_hex(&raw)
    }

    /// Override the audit label (default `"static"`).
    #[must_use]
    pub fn with_label(mut self, label: &'static str) -> Self {
        self.label = label;
        self
    }
}

impl SpoolEncryptionKeyProvider for StaticSpoolKey {
    fn resolve_key(&self, _session: &SessionContext) -> Result<Arc<[u8; 32]>> {
        Ok(Arc::clone(&self.key))
    }

    fn label(&self) -> &'static str {
        self.label
    }
}

/// Reject keys that indicate a configuration mistake rather than a real secret.
///
/// An all-zero key is what an uninitialised buffer, a truncated secret mount, or
/// a placeholder value looks like. Encrypting a regulated spool under it would
/// satisfy every type check and protect nothing.
pub(crate) fn reject_unusable_key(key: &[u8; 32]) -> Result<()> {
    if key.iter().all(|b| *b == 0) {
        return Err(AsxError::new(
            ErrorCode::PolicyViolation,
            "spool encryption key is all zeros; this is an unset or truncated \
             secret, not a key",
            ErrorContext::new("as2_spool_key_validate"),
        ));
    }
    Ok(())
}

/// Parse exactly 64 hex characters into a 32-byte key.
pub(crate) fn parse_spool_key_hex(hex_key: &str) -> Result<Arc<[u8; 32]>> {
    let hex_key = hex_key.trim();
    if hex_key.len() != 64 {
        return Err(AsxError::new(
            ErrorCode::InvalidInput,
            format!(
                "spool encryption key must contain exactly 64 hex characters \
                 (got {})",
                hex_key.len()
            ),
            ErrorContext::new("as2_spool_encryption_key_parse"),
        ));
    }

    let mut out = [0u8; 32];
    for (idx, chunk) in hex_key.as_bytes().chunks_exact(2).enumerate() {
        let hi = (chunk[0] as char).to_digit(16);
        let lo = (chunk[1] as char).to_digit(16);
        let (Some(hi), Some(lo)) = (hi, lo) else {
            return Err(AsxError::new(
                ErrorCode::InvalidInput,
                "spool encryption key contains non-hex characters",
                ErrorContext::new("as2_spool_encryption_key_parse"),
            ));
        };
        out[idx] = ((hi << 4) | lo) as u8;
    }

    Ok(Arc::new(out))
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_HEX: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn session() -> SessionContext {
        SessionContext::new("s-spool", "p1", "strict").expect("session")
    }

    #[test]
    fn hex_key_round_trips() {
        let provider = StaticSpoolKey::from_hex(VALID_HEX).expect("parse");
        let key = provider.resolve_key(&session()).expect("resolve");
        assert_eq!(key[0], 0x01);
        assert_eq!(key[31], 0xef);
        assert_eq!(provider.label(), "static");
    }

    #[test]
    fn hex_key_rejects_wrong_length_and_non_hex() {
        assert_eq!(
            StaticSpoolKey::from_hex("abcd").expect_err("short").code,
            ErrorCode::InvalidInput
        );
        let non_hex = "z".repeat(64);
        assert_eq!(
            StaticSpoolKey::from_hex(&non_hex)
                .expect_err("non-hex")
                .code,
            ErrorCode::InvalidInput
        );
    }

    /// An all-zero key is indistinguishable from an unset secret, and would
    /// "encrypt" a regulated spool while protecting nothing.
    #[test]
    fn all_zero_key_is_rejected() {
        let err = StaticSpoolKey::from_bytes([0u8; 32]).expect_err("all-zero key");
        assert_eq!(err.code, ErrorCode::PolicyViolation);

        let zero_hex = "0".repeat(64);
        assert_eq!(
            StaticSpoolKey::from_hex(&zero_hex)
                .expect_err("all-zero hex")
                .code,
            ErrorCode::PolicyViolation
        );
    }

    #[test]
    fn missing_env_var_names_itself() {
        let err = StaticSpoolKey::from_env("ASX_TEST_DEFINITELY_UNSET_KEY").expect_err("unset");
        assert_eq!(err.code, ErrorCode::PolicyViolation);
        assert!(err.message.contains("ASX_TEST_DEFINITELY_UNSET_KEY"));
    }

    #[test]
    fn file_key_tolerates_trailing_newline() {
        let dir = std::env::temp_dir().join("asx-spool-key-test");
        std::fs::create_dir_all(&dir).expect("mkdir");
        let path = dir.join("key.hex");
        std::fs::write(&path, format!("{VALID_HEX}\n")).expect("write");

        let provider = StaticSpoolKey::from_file(&path).expect("read");
        assert_eq!(provider.resolve_key(&session()).expect("resolve")[0], 0x01);

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn label_is_overridable_and_debug_hides_the_key() {
        let provider = StaticSpoolKey::from_hex(VALID_HEX)
            .expect("parse")
            .with_label("aws-kms");
        assert_eq!(provider.label(), "aws-kms");

        let rendered = format!("{provider:?}");
        assert!(rendered.contains("aws-kms"));
        assert!(
            !rendered.contains("0123456789abcdef"),
            "Debug must never print key material: {rendered}"
        );
    }
}
