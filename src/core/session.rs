//! `SessionContext`, its builder and metadata.

use super::*;

/// The internal per-partner context every send and receive runs under:
/// identity, the partner's certificate and trust material, the signer pins
/// and the clock. A client builds one per partner from its resolved policy.
///
/// `Clone` is O(1): certificates and trust anchors sit behind `Arc`, and
/// clones share one `CertHandle` until [`rotate_cert_handle`] is called on
/// one of them.
///
/// [`rotate_cert_handle`]: SessionContext::rotate_cert_handle
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionContext {
    pub(super) session_id: String,
    pub(super) partner_id: String,
    pub(super) profile_name: String,
    pub(super) metadata: SessionMetadata,
    /// The certificate/trust configuration for this session.
    ///
    /// Behind an `Arc` so that cloning is cheap, in-flight verifications keep
    /// the snapshot they started with, and [`rotate_cert_handle`] can swap the
    /// handle without rebuilding the session.
    ///
    /// [`rotate_cert_handle`]: SessionContext::rotate_cert_handle
    pub(super) cert_handle: Arc<CertHandle>,
    pub(super) correlation_scope: CorrelationScope,
    /// Lazy-parsed trust-anchor cache.  Invalidated whenever `cert_handle` is
    /// replaced via [`with_cert_handle`] or [`rotate_cert_handle`].
    ///
    /// [`with_cert_handle`]: SessionContext::with_cert_handle
    /// [`rotate_cert_handle`]: SessionContext::rotate_cert_handle
    #[cfg(any(feature = "as2", feature = "as4"))]
    pub(super) trust_anchors_cache: TrustAnchorCache,
    /// Lazy-built X.509 store derived from `trust_anchor_pems`.
    /// Invalidated whenever `cert_handle` is replaced.
    #[cfg(any(feature = "as2", feature = "as4"))]
    pub(super) x509_store_cache: X509StoreCache,
}

/// Session-scoped metadata that is derived rather than configured.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct SessionMetadata {
    /// Built by a client from a resolved `PartnerPolicy`.
    pub(crate) profile_built: bool,
    /// Every pinned signer of the partner (a rollover pins several).
    /// Non-empty only for profile-built sessions; otherwise the single pin is
    /// `CertHandle::fingerprint_sha256`.
    pub(crate) signer_pins: Vec<crate::crypto::CertFingerprint>,
    /// The wall clock every time decision under this session reads: the
    /// building client's clock, else the system clock.
    pub(crate) clock: crate::clock::SharedClock,
}

/// Equal when derived alike and reading the same clock object.
impl PartialEq for SessionMetadata {
    fn eq(&self, other: &Self) -> bool {
        self.profile_built == other.profile_built
            && self.signer_pins == other.signer_pins
            && std::sync::Arc::ptr_eq(&self.clock, &other.clock)
    }
}
impl Eq for SessionMetadata {}

impl Default for SessionMetadata {
    fn default() -> Self {
        Self {
            profile_built: false,
            signer_pins: Vec::new(),
            clock: crate::clock::system(),
        }
    }
}

/// Builder for ergonomic incremental construction of [`SessionContext`].
#[derive(Debug, Clone)]
pub struct SessionContextBuilder {
    pub(super) session_id: String,
    pub(super) partner_id: String,
    pub(super) profile_name: String,
    pub(super) cert_handle: Option<CertHandle>,
    pub(super) correlation_scope: Option<CorrelationScope>,
}

impl SessionContextBuilder {
    /// Create a new builder with required identity fields.
    ///
    /// `profile_name` defaults to `"strict"` and can be overridden with
    /// [`profile_name`][Self::profile_name].
    pub fn new(session_id: impl Into<String>, partner_id: impl Into<String>) -> Self {
        Self {
            session_id: session_id.into(),
            partner_id: partner_id.into(),
            profile_name: "strict".to_string(),
            cert_handle: None,
            correlation_scope: None,
        }
    }

    /// Override the profile name (defaults to `"strict"`).
    pub fn profile_name(mut self, profile_name: impl Into<String>) -> Self {
        self.profile_name = profile_name.into();
        self
    }

    /// Set explicit certificate/trust material for the session.
    pub fn cert_handle(mut self, cert_handle: CertHandle) -> Self {
        self.cert_handle = Some(cert_handle);
        self
    }

    /// Return a key_id string derived from the partner_id, matching the
    /// pattern used by [`SessionContext::new`] for the default `CertHandle`.
    fn default_cert_handle_key_id(&self) -> String {
        format!("cert:{}", self.partner_id)
    }

    /// Get or lazily create the builder's CertHandle with a sensible key_id.
    fn cert_handle_or_init(&mut self) -> &mut CertHandle {
        let key_id = self.default_cert_handle_key_id();
        self.cert_handle
            .get_or_insert_with(|| CertHandle::new(key_id))
    }

    /// Append a single PEM-encoded trust anchor to the session's certificate store.
    ///
    /// This is a convenience alternative to constructing a [`CertHandle`] manually.
    /// Can be called multiple times to build up a set of trusted root/intermediate CAs.
    ///
    /// # Example
    /// ```text
    /// let session = SessionContextBuilder::new("s1", "partner-a")
    ///     .with_trust_anchor_pem(root_ca_pem)
    ///     .build()?;
    /// ```
    pub fn with_trust_anchor_pem(mut self, pem: impl Into<String>) -> Self {
        self.cert_handle_or_init()
            .trust_anchor_pems
            .push(pem.into());
        self
    }

    /// Append a certificate that signature verification may use for chain
    /// building — an intermediate CA, or the partner's leaf signing
    /// certificate.
    ///
    /// See [`CertHandle::intermediate_ca_pems`] for why the leaf usually has to
    /// be supplied here rather than being taken from the message.
    pub fn with_intermediate_ca_pem(mut self, pem: impl Into<String>) -> Self {
        self.cert_handle_or_init()
            .intermediate_ca_pems
            .push(pem.into());
        self
    }

    /// Set the PEM-encoded X.509 certificate used to sign **outbound** messages.
    ///
    /// Must be called together with [`with_signing_key_pem`](Self::with_signing_key_pem).
    /// [`build`](Self::build) will return an error when only one of the signing
    /// pair is provided, or when the key does not match the certificate.
    pub fn with_signing_cert_pem(mut self, pem: impl Into<String>) -> Self {
        self.cert_handle_or_init().signing_cert_pem = Some(pem.into());
        self
    }

    /// Set the PEM-encoded private key used to sign **outbound** messages.
    ///
    /// Must match the certificate supplied via
    /// [`with_signing_cert_pem`](Self::with_signing_cert_pem).  The raw key
    /// bytes are **zeroized on drop** via the `CertHandle` destructor.
    pub fn with_signing_key_pem(mut self, pem: impl Into<String>) -> Self {
        self.cert_handle_or_init().signing_key_pem = Some(zeroize::Zeroizing::new(pem.into()));
        self
    }

    /// Set the PEM-encoded X.509 certificate belonging to **this partner**,
    /// used to encrypt outbound messages when the send policy has
    /// `encrypt = true`.
    pub fn with_recipient_cert_pem(mut self, pem: impl Into<String>) -> Self {
        self.cert_handle_or_init().recipient_cert_pem = Some(pem.into());
        self
    }

    /// Set both signing certificate and key in one call.
    ///
    /// Equivalent to chaining [`with_signing_cert_pem`](Self::with_signing_cert_pem)
    /// and [`with_signing_key_pem`](Self::with_signing_key_pem), but eliminates the
    /// intermediate half-configured state where one of the pair is set and the other
    /// is not.  [`build`](Self::build) validates that the cert and key match.
    pub fn with_signing_material(
        mut self,
        cert_pem: impl Into<String>,
        key_pem: impl Into<String>,
    ) -> Self {
        let ch = self.cert_handle_or_init();
        ch.signing_cert_pem = Some(cert_pem.into());
        ch.signing_key_pem = Some(zeroize::Zeroizing::new(key_pem.into()));
        self
    }

    /// Pin the expected SHA-256 fingerprint of the partner's signing
    /// certificate — **required** to receive signed AS4 messages.
    ///
    /// A signed message whose sender resolves to no pin is refused: a
    /// signature that verifies against the network's shared trust anchors
    /// proves membership of the network, not the sender's identity. The value
    /// is compared against the signer of each inbound message; a mistyped or
    /// truncated pin is rejected here rather than surfacing later as
    /// "signature does not match".
    pub fn with_fingerprint_sha256(mut self, fingerprint: impl Into<String>) -> Self {
        self.cert_handle_or_init().fingerprint_sha256 = fingerprint.into();
        self
    }

    /// Override the default correlation scope.
    pub fn correlation_scope(
        mut self,
        root_id: impl Into<String>,
        parent_message_id: Option<String>,
    ) -> Self {
        self.correlation_scope = Some(CorrelationScope {
            root_id: root_id.into(),
            parent_message_id,
        });
        self
    }

    /// Build a validated [`SessionContext`].
    pub fn build(self) -> Result<SessionContext> {
        let mut session = SessionContext::new(self.session_id, self.partner_id, self.profile_name)?;

        if let Some(cert_handle) = self.cert_handle {
            // Validate that signing_key_pem and signing_cert_pem are both
            // present or both absent.
            match (&cert_handle.signing_key_pem, &cert_handle.signing_cert_pem) {
                (Some(_), None) | (None, Some(_)) => {
                    return Err(AsxError::new(
                        ErrorCode::InvalidInput,
                        "signing_key_pem and signing_cert_pem must both be set or both absent",
                        ErrorContext::new("session_context_builder"),
                    ));
                }
                _ => {}
            }
            // Eagerly parse and validate PEM material when crypto features are
            // available.  This surfaces key/cert mismatches at session
            // construction time rather than deep inside the send pipeline.
            #[cfg(any(feature = "as2", feature = "as4"))]
            validate_cert_handle_outbound_pem(&cert_handle)?;
            session = session.with_cert_handle(cert_handle)?;
        }

        if let Some(correlation_scope) = self.correlation_scope {
            if correlation_scope.root_id.trim().is_empty() {
                return Err(AsxError::new(
                    ErrorCode::InvalidInput,
                    "correlation root_id must not be empty",
                    ErrorContext::for_session("session_context_builder", &session),
                ));
            }
            session.correlation_scope = correlation_scope;
        }

        Ok(session)
    }
}

/// Validate PEM-encoded outbound signing material stored in a `CertHandle`.
///
/// Called from `SessionContextBuilder::build` when `as2` or `as4` features
/// are active.  Parses the signing cert + key, verifies the key matches the
/// cert, and optionally parses the recipient cert if present.  All errors are
/// surfaced at session construction time rather than deep in the send pipeline.
#[cfg(any(feature = "as2", feature = "as4"))]
fn validate_cert_handle_outbound_pem(cert_handle: &CertHandle) -> Result<()> {
    if let (Some(key_pem), Some(cert_pem)) =
        (&cert_handle.signing_key_pem, &cert_handle.signing_cert_pem)
    {
        let cert = openssl::x509::X509::from_pem(cert_pem.as_bytes()).map_err(|_| {
            AsxError::new(
                ErrorCode::InvalidInput,
                "signing_cert_pem is not a valid PEM X.509 certificate",
                ErrorContext::new("session_context_builder_validate"),
            )
        })?;

        let key = openssl::pkey::PKey::private_key_from_pem(key_pem.as_bytes()).map_err(|_| {
            AsxError::new(
                ErrorCode::InvalidInput,
                "signing_key_pem is not a valid PEM private key",
                ErrorContext::new("session_context_builder_validate"),
            )
        })?;

        let cert_pub = cert.public_key().map_err(|_| {
            AsxError::new(
                ErrorCode::InvalidInput,
                "signing_cert_pem does not contain a usable public key",
                ErrorContext::new("session_context_builder_validate"),
            )
        })?;

        if !key.public_eq(&cert_pub) {
            return Err(AsxError::new(
                ErrorCode::InvalidInput,
                "signing_key_pem does not match signing_cert_pem",
                ErrorContext::new("session_context_builder_validate"),
            ));
        }
    }

    if let Some(pem) = &cert_handle.recipient_cert_pem {
        openssl::x509::X509::from_pem(pem.as_bytes()).map_err(|_| {
            AsxError::new(
                ErrorCode::InvalidInput,
                "recipient_cert_pem is not a valid PEM X.509 certificate",
                ErrorContext::new("session_context_builder_validate"),
            )
        })?;
    }

    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CorrelationScope {
    pub root_id: String,
    pub parent_message_id: Option<String>,
}

impl SessionContext {
    /// Start building a [`SessionContext`] incrementally.
    pub fn builder(
        session_id: impl Into<String>,
        partner_id: impl Into<String>,
    ) -> SessionContextBuilder {
        SessionContextBuilder::new(session_id, partner_id)
    }

    pub fn new(
        session_id: impl Into<String>,
        partner_id: impl Into<String>,
        profile_name: impl Into<String>,
    ) -> Result<Self> {
        let session_id = session_id.into();
        let partner_id = partner_id.into();
        let profile_name = profile_name.into();

        if session_id.trim().is_empty() {
            return Err(AsxError::new(
                ErrorCode::InvalidInput,
                "session_id must not be empty",
                ErrorContext::new("session_context_init"),
            ));
        }
        if partner_id.trim().is_empty() {
            return Err(AsxError::new(
                ErrorCode::InvalidInput,
                "partner_id must not be empty",
                ErrorContext::new("session_context_init").with_session_id(&session_id),
            ));
        }
        if profile_name.trim().is_empty() {
            return Err(AsxError::new(
                ErrorCode::InvalidInput,
                "profile_name must not be empty",
                ErrorContext::new("session_context_init")
                    .with_session_and_partner(&session_id, &partner_id),
            ));
        }

        Ok(Self {
            metadata: SessionMetadata::default(),
            cert_handle: Arc::new(CertHandle::new(format!("cert:{partner_id}"))),
            correlation_scope: CorrelationScope {
                root_id: format!("corr:{session_id}"),
                parent_message_id: None,
            },
            session_id,
            partner_id,
            profile_name,
            #[cfg(any(feature = "as2", feature = "as4"))]
            trust_anchors_cache: TrustAnchorCache::default(),
            #[cfg(any(feature = "as2", feature = "as4"))]
            x509_store_cache: X509StoreCache::default(),
        })
    }

    /// Validate and set the session's certificate/trust configuration (builder method).
    ///
    /// This is the primary way to attach certificate material when constructing a
    /// session.  For rotation on an already-live session, prefer
    /// [`rotate_cert_handle`] which takes `&mut self`.
    ///
    /// Both the trust-anchor parse cache and the X.509 store cache are reset so
    /// that the new handle's anchors are parsed fresh on first use.
    ///
    /// [`rotate_cert_handle`]: Self::rotate_cert_handle
    pub fn with_cert_handle(mut self, cert_handle: CertHandle) -> Result<Self> {
        Self::validate_cert_handle_fields(&cert_handle, "session_context_cert_update", &self)?;
        self.cert_handle = Arc::new(cert_handle);
        #[cfg(any(feature = "as2", feature = "as4"))]
        {
            self.trust_anchors_cache = TrustAnchorCache::default();
            self.x509_store_cache = X509StoreCache::default();
        }
        Ok(self)
    }

    /// Atomically rotate the certificate/trust configuration on a live session.
    ///
    /// Unlike [`with_cert_handle`], this takes `&mut self` and therefore works
    /// on an already-constructed session without rebuilding it. The `session_id`,
    /// `partner_id` and profile are preserved.
    ///
    /// Any in-flight verification calls that were already dispatched continue
    /// using the previous `Arc<CertHandle>` snapshot until they complete; newly
    /// accepted messages see the updated configuration immediately.
    ///
    /// # Errors
    ///
    /// Returns `InvalidInput` if `cert_handle` fails the same validation as
    /// [`with_cert_handle`].
    ///
    /// [`with_cert_handle`]: Self::with_cert_handle
    pub fn rotate_cert_handle(&mut self, cert_handle: CertHandle) -> Result<()> {
        Self::validate_cert_handle_fields(&cert_handle, "session_context_cert_rotate", self)?;
        self.cert_handle = Arc::new(cert_handle);
        #[cfg(any(feature = "as2", feature = "as4"))]
        {
            self.trust_anchors_cache = TrustAnchorCache::default();
            self.x509_store_cache = X509StoreCache::default();
        }
        Ok(())
    }

    fn validate_cert_handle_fields(
        cert_handle: &CertHandle,
        stage: &'static str,
        session: &SessionContext,
    ) -> Result<()> {
        if cert_handle.key_id.trim().is_empty() {
            return Err(AsxError::new(
                ErrorCode::InvalidInput,
                "cert handle key_id must not be empty",
                ErrorContext::for_session(stage, session),
            ));
        }
        if cert_handle
            .trust_anchor_pems
            .iter()
            .any(|pem| pem.trim().is_empty())
        {
            return Err(AsxError::new(
                ErrorCode::InvalidInput,
                "cert handle PKIX material must not contain empty entries",
                ErrorContext::for_session(stage, session),
            ));
        }
        // A malformed pin fails closed here; it is never read as "no pin".
        if !cert_handle.fingerprint_sha256.trim().is_empty()
            && let Err(err) = crate::crypto::CertFingerprint::parse(&cert_handle.fingerprint_sha256)
        {
            return Err(AsxError::new(
                ErrorCode::InvalidInput,
                format!(
                    "cert handle fingerprint_sha256 is a malformed signer pin: {}",
                    err.message
                ),
                ErrorContext::for_session(stage, session),
            ));
        }
        Ok(())
    }

    pub(crate) fn metadata(&self) -> &SessionMetadata {
        &self.metadata
    }

    /// Mark a session built from a resolved `PartnerPolicy`.
    pub(crate) fn with_profile_metadata(
        mut self,
        signer_pins: Vec<crate::crypto::CertFingerprint>,
        clock: crate::clock::SharedClock,
    ) -> Self {
        self.metadata.clock = clock;
        self.metadata.profile_built = true;
        self.metadata.signer_pins = signer_pins;
        self
    }

    /// The session's wall clock.
    pub(crate) fn clock(&self) -> &crate::clock::SharedClock {
        &self.metadata.clock
    }

    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    pub fn partner_id(&self) -> &str {
        &self.partner_id
    }

    pub fn profile_name(&self) -> &str {
        &self.profile_name
    }

    pub fn cert_handle(&self) -> &CertHandle {
        self.cert_handle.as_ref()
    }

    /// Return the parsed trust-anchor X.509 certificates, parsing from
    /// `cert_handle.trust_anchor_pems` on first call and caching the result.
    ///
    /// Thread-safe: multiple concurrent callers share one parse via `OnceLock`.
    /// The cache is invalidated automatically when `with_cert_handle` or
    /// `rotate_cert_handle` is called on this session.
    #[cfg(any(feature = "as2", feature = "as4"))]
    pub(crate) fn trust_anchors_x509(&self) -> Result<Vec<openssl::x509::X509>> {
        if let Some(anchors) = self.trust_anchors_cache.0.get() {
            return Ok(anchors.clone());
        }
        let mut anchors = Vec::new();
        for pem in &self.cert_handle.trust_anchor_pems {
            let certs = openssl::x509::X509::stack_from_pem(pem.as_bytes()).map_err(|e| {
                AsxError::new(
                    ErrorCode::InvalidInput,
                    format!("invalid trust-anchor PEM in CertHandle: {e}"),
                    ErrorContext::new("session_parse_trust_anchors"),
                )
            })?;
            anchors.extend(certs);
        }
        let _ = self.trust_anchors_cache.0.set(anchors.clone());
        Ok(anchors)
    }

    /// Return an `Arc`-wrapped `X509Store` built from the trust-anchor PEMs.
    ///
    /// Built at most once per `(session, cert_handle)` pair and shared across
    /// clones.  The cache is invalidated automatically when `with_cert_handle`
    /// or `rotate_cert_handle` is called.
    #[cfg(any(feature = "as2", feature = "as4"))]
    pub(crate) fn trust_anchor_x509_store(&self) -> Result<Arc<openssl::x509::store::X509Store>> {
        if let Some(store) = self.x509_store_cache.0.get() {
            return Ok(Arc::clone(store));
        }
        let anchors = self.trust_anchors_x509()?;
        let mut builder = openssl::x509::store::X509StoreBuilder::new().map_err(|e| {
            AsxError::new(
                ErrorCode::InvalidInput,
                format!("failed to build X.509 trust store: {e}"),
                ErrorContext::new("session_build_x509_store"),
            )
        })?;
        for cert in &anchors {
            builder.add_cert(cert.clone()).map_err(|e| {
                AsxError::new(
                    ErrorCode::InvalidInput,
                    format!("failed to add trust anchor to X.509 store: {e}"),
                    ErrorContext::new("session_build_x509_store"),
                )
            })?;
        }
        let store = Arc::new(builder.build());
        let _ = self.x509_store_cache.0.set(Arc::clone(&store));
        Ok(store)
    }

    pub fn correlation_scope(&self) -> &CorrelationScope {
        &self.correlation_scope
    }
}
