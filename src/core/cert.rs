//! `CertHandle`, OCSP modes and the trust-anchor caches.

#[cfg_attr(not(any(feature = "as2", feature = "as4")), allow(unused_imports))]
use super::*;

/// Lazy cache of trust-anchor X.509 certificates parsed from
/// [`CertHandle::trust_anchor_pems`].  Shared across clones of the same
/// [`CertHandle`] via an `Arc` so that clones see the same populated cache
/// rather than re-parsing independently.
///
/// Equality is always `true` — the cache is an implementation detail derived
/// from the authoritative `trust_anchor_pems` field; it does not contribute to
/// the identity of a [`CertHandle`].
#[derive(Debug, Default, Clone)]
#[cfg(any(feature = "as2", feature = "as4"))]
pub(crate) struct TrustAnchorCache(pub(super) Arc<OnceLock<Vec<openssl::x509::X509>>>);

#[cfg(any(feature = "as2", feature = "as4"))]
impl PartialEq for TrustAnchorCache {
    fn eq(&self, _: &Self) -> bool {
        true // cache state is not part of CertHandle identity
    }
}
#[cfg(any(feature = "as2", feature = "as4"))]
impl Eq for TrustAnchorCache {}

/// Lazy cache of the `X509Store` built from [`CertHandle::trust_anchor_pems`].
///
/// Caching avoids rebuilding an `X509Store` (O(n_anchors) OpenSSL allocations)
/// on every inbound message verification.  Shared across clones via `Arc`;
/// the store is built at most once per `CertHandle` lineage regardless of how
/// many clones exist.  Equality is always `true` (derived from `trust_anchor_pems`).
#[derive(Default, Clone)]
#[cfg(any(feature = "as2", feature = "as4"))]
pub(crate) struct X509StoreCache(pub(super) Arc<OnceLock<Arc<openssl::x509::store::X509Store>>>);

#[cfg(any(feature = "as2", feature = "as4"))]
impl std::fmt::Debug for X509StoreCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("X509StoreCache")
            .field(&self.0.get().is_some())
            .finish()
    }
}

#[cfg(any(feature = "as2", feature = "as4"))]
impl PartialEq for X509StoreCache {
    fn eq(&self, _: &Self) -> bool {
        true
    }
}
#[cfg(any(feature = "as2", feature = "as4"))]
impl Eq for X509StoreCache {}

#[derive(Clone, PartialEq, Eq)]
pub struct CertHandle {
    pub key_id: String,
    pub fingerprint_sha256: String,
    pub trust_anchor_pems: Vec<String>,
    /// Additional certificates (PEM) made available for chain building during
    /// signature verification.
    ///
    /// AS2 verification runs OpenSSL with `PKCS7_NOINTERN`, so certificates
    /// **embedded in the inbound message are not used for path building** —
    /// otherwise a sender could influence its own chain. The practical
    /// consequence is that this list must contain every certificate needed to
    /// reach a trust anchor, including the partner's **leaf signing
    /// certificate** when it is not itself a configured anchor.
    ///
    /// Populate it with [`SessionContextBuilder::with_intermediate_ca_pem`].
    pub intermediate_ca_pems: Vec<String>,
    /// PEM-encoded X.509 certificate used to sign **outbound** messages to
    /// this partner (set via
    /// [`SessionContextBuilder::with_signing_cert_pem`]).
    ///
    /// Must be paired with [`signing_key_pem`](Self::signing_key_pem).
    /// [`SessionContextBuilder::build`] validates the pair and checks that
    /// the key matches the certificate.
    pub signing_cert_pem: Option<String>,
    /// PEM-encoded private key matching
    /// [`signing_cert_pem`](Self::signing_cert_pem).
    ///
    /// # Security
    ///
    /// The key bytes are **zeroized on drop** via the `Zeroizing` wrapper.
    /// Do not log or persist a `CertHandle` that contains live key material.
    pub signing_key_pem: Option<zeroize::Zeroizing<String>>,
    /// PEM-encoded X.509 certificate belonging to this partner, used to
    /// encrypt outbound AS4 / AS2 messages when the send policy has
    /// `encrypt = true`.
    pub recipient_cert_pem: Option<String>,
}

// Hand-written `Debug` that never renders private key material. The derived
// `Debug` would forward through `Zeroizing<String>` and print the raw PEM (see
// the `# Security` note on `signing_key_pem`), so any `?cert_handle`/`?session`
// in a log line or panic message would leak the key. Presence is reported as a
// redacted marker so debugging stays useful without exposing secrets.
impl std::fmt::Debug for CertHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CertHandle")
            .field("key_id", &self.key_id)
            .field("fingerprint_sha256", &self.fingerprint_sha256)
            .field("trust_anchor_pems", &self.trust_anchor_pems)
            .field("intermediate_ca_pems", &self.intermediate_ca_pems)
            .field("signing_cert_pem", &self.signing_cert_pem)
            .field(
                "signing_key_pem",
                &self.signing_key_pem.as_ref().map(|_| "<redacted>"),
            )
            .field("recipient_cert_pem", &self.recipient_cert_pem)
            .finish()
    }
}

impl CertHandle {
    /// Construct a `CertHandle` with sensible defaults for the given key ID.
    ///
    /// All PEM fields default to empty (`Vec::new()`). Override any field
    /// with struct update syntax before passing to
    /// [`SessionContext::with_cert_handle`] or
    /// [`SessionContext::rotate_cert_handle`]:
    ///
    /// ```text
    /// let handle = CertHandle {
    ///     trust_anchor_pems: vec![root_pem],
    ///     ..CertHandle::new("partner-cert")
    /// };
    /// ```
    pub fn new(key_id: impl Into<String>) -> Self {
        Self {
            key_id: key_id.into(),
            fingerprint_sha256: String::new(),
            trust_anchor_pems: Vec::new(),
            intermediate_ca_pems: Vec::new(),
            signing_cert_pem: None,
            signing_key_pem: None,
            recipient_cert_pem: None,
        }
    }

    /// Set the PEM-encoded private key for outbound signing without requiring
    /// callers to depend on the `zeroize` crate directly.
    ///
    /// The key bytes are automatically wrapped in [`zeroize::Zeroizing`] and
    /// will be zeroized on drop.
    pub fn set_signing_key_pem(&mut self, key_pem: impl Into<String>) {
        self.signing_key_pem = Some(zeroize::Zeroizing::new(key_pem.into()));
    }
}
