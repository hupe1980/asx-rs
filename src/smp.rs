//! PEPPOL / CEF Service Metadata Publisher (SMP) client.
//!
//! Implements [OASIS BDX SMP 1.0 / PEPPOL BIS] dynamic discovery: resolves the
//! AS4 endpoint URL and signing certificate for a participant from the PEPPOL
//! Participant Identifier + Document Type Identifier + Process Identifier triple.
//!
//! # Finding the SMP (BDXL)
//!
//! Before any metadata can be fetched, the SMP that holds it has to be found.
//! Peppol and CEF eDelivery publish that in DNS as a U-NAPTR record keyed by a
//! hash of the participant identifier — see [`bdxl`] for the construction, the
//! record format, and the [`BdxlResolver`] seam that performs the query.
//!
//! ```text
//! name = strip-trailing(base32(sha256(lowercase(ID-VALUE))), "=") + "." + ID-SCHEME + "." + ZONE
//! name. IN NAPTR 100 10 "U" "Meta:SMP" "!.*!https://smp.example.org!" .
//! ```
//!
//! The ServiceMetadata is then retrieved from the SMP the record named:
//!
//! ```text
//! GET {smp_base}/{url_encoded_canonical_id}/services/{url_encoded_document_type_id}
//! ```
//!
//! # Verify the SMP signature
//!
//! An SMP lookup decides *where a message is sent* and *which public key it is
//! encrypted to*. TLS authenticates the SMP host, not the metadata it serves, so
//! a rogue or compromised SMP can redirect traffic and substitute its own
//! recipient certificate. PEPPOL and CEF eDelivery both require the consumer to
//! verify the enveloped XMLDSig and chain the signing certificate to the
//! network's SMP CA.
//!
//! ASX does this for you. Supply the network's SMP CA:
//!
//! ```rust,ignore
//! let config = SmpConfig {
//!     signature_policy: SmpSignaturePolicy::verify_with_trust_anchors(vec![smp_ca_pem]),
//!     ..SmpConfig::peppol_production()
//! };
//! ```
//!
//! [`SmpSignaturePolicy`] defaults to [`SmpSignaturePolicy::Deny`]: a lookup
//! whose authenticity was never established does not silently become a routing
//! decision. The weaker settings exist for closed and test networks and must be
//! chosen explicitly.
//!
//! # SSRF protection
//!
//! The SMP URL is validated **and pinned** before the HTTP request is issued,
//! so a host that passed the check cannot be swapped for a private address on
//! the connection. The `sml_zone` in [`SmpConfig`] names the DNS zone that is
//! allowed to answer for participants — treat it as configuration, not user
//! data — and a NAPTR record may only name an `https` SMP.
//!
//! # Example
//!
//! ```rust,no_run
//! # #[cfg(feature = "dns")]
//! # mod example {
//! use asx_rs::smp::{HickoryBdxlResolver, SmpClient, SmpConfig, SmpLookupRequest, SmpSignaturePolicy};
//! use std::sync::Arc;
//!
//! async fn example(smp_ca_pem: String) -> asx_rs::core::Result<()> {
//!     let client = SmpClient::with_config(SmpConfig {
//!         signature_policy: SmpSignaturePolicy::verify_with_trust_anchors(vec![smp_ca_pem]),
//!         ..SmpConfig::peppol_production()
//!     })
//!     .with_resolver(Arc::new(HickoryBdxlResolver::from_system_config()?));
//!
//!     let endpoint = client
//!         .lookup_endpoint(SmpLookupRequest {
//!             participant_id: "0088:1234567890123".to_string(),
//!             document_type_id: "urn:oasis:names:specification:ubl:schema:xsd:Invoice-2::Invoice##\
//!                                urn:cen.eu:en16931:2017#compliant#\
//!                                urn:fdc:peppol.eu:2017:poacc:billing:3.0::2.1"
//!                 .to_string(),
//!             process_id: "urn:fdc:peppol.eu:2017:poacc:billing:01:1.0".to_string(),
//!             transport_profile: None,
//!         })
//!         .await?;
//!
//!     println!("AS4 endpoint: {}", endpoint.url);
//!     Ok(())
//! }
//! # }
//! ```
//!
//! [OASIS BDX SMP 1.0 / PEPPOL BIS]: https://docs.peppol.eu/edelivery/smp/

use std::sync::Arc;

use crate::core::{AsxError, ErrorCode, ErrorContext, Result};
use crate::transport::egress::{TransportConfig, validated_pinned_client};
use roxmltree::Document;

pub mod bdxl;

#[cfg(feature = "dns")]
pub use bdxl::HickoryBdxlResolver;
pub use bdxl::{
    BdxlResolver, NaptrRecord, SmlDiscovery, StaticBdxlResolver, bdxl_dns_name, legacy_cname_host,
    select_smp_base_url,
};

// ── Well-known constants ──────────────────────────────────────────────────

/// PEPPOL AS4 transport profile identifier used in SMP ServiceMetadata.
pub const PEPPOL_AS4_TRANSPORT_PROFILE: &str = "peppol-transport-as4-v2_0";

/// Default PEPPOL participant identifier scheme.
///
/// Re-exported from [`crate::peppol`], which is where the network's own
/// constants live — the scheme is not a discovery concern, it just happens to
/// be needed here.
pub use crate::peppol::PEPPOL_PARTICIPANT_SCHEME;

/// SML zone answering for the **Peppol production** network.
///
/// OpenPeppol took the SML in-house during 2026; the European Commission zone
/// this replaced (`edelivery.tech.ec.europa.eu`) stopped answering participant
/// lookups on 31 August 2026.
pub const PEPPOL_PRODUCTION_SML_ZONE: &str = "participant.sml.prod.tech.peppol.org";

/// SML zone answering for the **Peppol test** network (SMK).
pub const PEPPOL_TEST_SML_ZONE: &str = "participant.sml.test.tech.peppol.org";

// ── Types ─────────────────────────────────────────────────────────────────

/// Configuration for an [`SmpClient`].
#[derive(Debug, Clone)]
pub struct SmpConfig {
    /// SML DNS zone that answers participant lookups.
    ///
    /// | Network | Value |
    /// |---------|-------|
    /// | Peppol production | [`PEPPOL_PRODUCTION_SML_ZONE`] |
    /// | Peppol test (SMK) | [`PEPPOL_TEST_SML_ZONE`] |
    ///
    /// Unused when [`discovery`](Self::discovery) is [`SmlDiscovery::Static`].
    pub sml_zone: String,

    /// How the SMP holding a participant's metadata is located.
    ///
    /// Defaults to [`SmlDiscovery::Naptr`] — what Peppol and CEF eDelivery
    /// publish. Requires a resolver; see [`SmpClient::with_resolver`].
    pub discovery: SmlDiscovery,

    /// Participant identifier scheme prepended to the participant ID before
    /// hashing.  Default: [`PEPPOL_PARTICIPANT_SCHEME`].
    pub participant_scheme: String,

    /// Default transport profile used when [`SmpLookupRequest::transport_profile`]
    /// is `None`.  Default: [`PEPPOL_AS4_TRANSPORT_PROFILE`].
    pub transport_profile: String,

    /// Whether an unsigned `ServiceMetadata` response is accepted.
    ///
    /// How the response is authenticated before its contents are trusted.
    ///
    /// Defaults to [`SmpSignaturePolicy::Deny`]; set
    /// [`SmpSignaturePolicy::verify_with_trust_anchors`] with the network's SMP
    /// CA for any public network.
    pub signature_policy: SmpSignaturePolicy,
}

impl SmpConfig {
    /// Config for the **PEPPOL test** network.
    ///
    /// Carries the network's identity, not its trust anchors — those belong to
    /// your deployment. Set
    /// [`signature_policy`](Self::signature_policy) before using the result for
    /// routing.
    pub fn peppol_test() -> Self {
        Self {
            sml_zone: PEPPOL_TEST_SML_ZONE.to_string(),
            discovery: SmlDiscovery::Naptr,
            participant_scheme: PEPPOL_PARTICIPANT_SCHEME.to_string(),
            transport_profile: PEPPOL_AS4_TRANSPORT_PROFILE.to_string(),
            signature_policy: SmpSignaturePolicy::Deny,
        }
    }

    /// Config for the **PEPPOL production** network.
    ///
    /// Carries the network's identity, not its trust anchors — those belong to
    /// your deployment. Supply the PEPPOL SMP CA via
    /// [`SmpSignaturePolicy::verify_with_trust_anchors`] before using the result
    /// for routing.
    pub fn peppol_production() -> Self {
        Self {
            sml_zone: PEPPOL_PRODUCTION_SML_ZONE.to_string(),
            discovery: SmlDiscovery::Naptr,
            participant_scheme: PEPPOL_PARTICIPANT_SCHEME.to_string(),
            transport_profile: PEPPOL_AS4_TRANSPORT_PROFILE.to_string(),
            signature_policy: SmpSignaturePolicy::Deny,
        }
    }

    /// Config for a known SMP, skipping DNS discovery.
    ///
    /// For a bilateral agreement or a test SMP whose URL is configuration
    /// rather than something to be looked up. No resolver is needed.
    pub fn with_static_smp(smp_base_url: impl Into<String>) -> Self {
        Self {
            sml_zone: String::new(),
            discovery: SmlDiscovery::Static {
                smp_base_url: smp_base_url.into(),
            },
            participant_scheme: PEPPOL_PARTICIPANT_SCHEME.to_string(),
            transport_profile: PEPPOL_AS4_TRANSPORT_PROFILE.to_string(),
            signature_policy: SmpSignaturePolicy::Deny,
        }
    }
}

/// How an SMP `ServiceMetadata` response is authenticated before its contents
/// are used for routing.
///
/// The lookup result determines where a message is sent and which key it is
/// encrypted to, so treating an unauthenticated response as fact hands those
/// decisions to whoever answered the request.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub enum SmpSignaturePolicy {
    /// Refuse to use the lookup result. **The default.**
    ///
    /// An SMP response whose authenticity was never established must not
    /// silently become a routing decision, so there is no "unverified" setting
    /// reachable by leaving this field alone — only by choosing one below.
    #[default]
    Deny,

    /// **Verify** the enveloped `ds:Signature` and chain the SMP signing
    /// certificate to the supplied trust anchors.
    ///
    /// This is the only setting that makes an SMP lookup trustworthy: it proves
    /// the endpoint URL and recipient certificate really came from the network's
    /// SMP and were not substituted in transit. Use it on any public network.
    ///
    /// Supply the network's SMP CA (PEPPOL / CEF publish these); construct it
    /// with [`verify_with_trust_anchors`](Self::verify_with_trust_anchors). An
    /// empty anchor set with `require_chain_validation` fails closed.
    Verify(Box<crate::crypto::wssec::OwnedRevocationPolicy>),

    /// Require a `ds:Signature` to be present but do not verify it.
    ///
    /// A stepping stone, not a destination: it catches an outright unsigned or
    /// misconfigured SMP and nothing else — a forged response with any
    /// signature-shaped element passes. Prefer [`Self::Verify`].
    RequireSignaturePresent,

    /// Accept an unsigned `ServiceMetadata` response.
    ///
    /// For closed networks and test SMPs that do not sign. Do not use against
    /// a public network.
    AllowUnsigned,
}

impl SmpSignaturePolicy {
    /// Verify signatures against the given SMP CA trust anchors.
    pub fn verify_with_trust_anchors(trust_anchor_pems: Vec<String>) -> Self {
        Self::Verify(Box::new(
            crate::crypto::wssec::OwnedRevocationPolicy::production(trust_anchor_pems),
        ))
    }
}

/// A single AS4 endpoint extracted from SMP `ServiceMetadata`.
#[derive(Debug, Clone)]
pub struct SmpEndpoint {
    /// URL the sender should POST AS4 messages to.
    pub url: String,

    /// SHA-256 fingerprint (lowercase hex) of the SMP certificate whose
    /// signature over this response was **verified**.
    ///
    /// `Some` only under [`SmpSignaturePolicy::Verify`]. `None` means the
    /// signature was not checked, so [`Self::url`] and
    /// [`Self::certificate_der_b64`] are unauthenticated.
    pub verified_signer_fingerprint_sha256: Option<String>,

    /// The exact `ServiceMetadata` bytes the SMP returned.
    ///
    /// Retained so a caller can re-check the enveloped XMLDSig itself, archive
    /// the response for audit, or verify it against a second trust store.
    ///
    /// Under [`SmpSignaturePolicy::Verify`] these bytes have already been
    /// verified and [`Self::verified_signer_fingerprint_sha256`] names the
    /// signer. Under the weaker policies they are unauthenticated, and so are
    /// [`Self::url`] and [`Self::certificate_der_b64`].
    pub signed_document: std::sync::Arc<[u8]>,

    /// Base64-encoded DER X.509 certificate of the receiving party's signing
    /// key.  Validate this against your trust store before pinning it.
    ///
    /// `None` when the SMP entry does not include a `<Certificate>` element.
    pub certificate_der_b64: Option<String>,

    /// Transport profile identifier, e.g. `peppol-transport-as4-v2_0`.
    pub transport_profile: String,

    /// Human-readable description of the service.
    pub service_description: Option<String>,

    /// Service activation date in ISO-8601 format (`YYYY-MM-DD`).
    pub service_activation_date: Option<String>,

    /// Service expiration date in ISO-8601 format (`YYYY-MM-DD`).
    pub service_expiration_date: Option<String>,
}

/// Parameters for a single SMP endpoint lookup.
#[derive(Debug, Clone)]
pub struct SmpLookupRequest {
    /// Participant identifier **without** the scheme prefix
    /// (e.g. `0088:1234567890123`).  The scheme is read from [`SmpConfig`].
    pub participant_id: String,

    /// Full document type identifier
    /// (e.g. `urn:oasis:names:specification:ubl:schema:xsd:Invoice-2::Invoice##…`).
    pub document_type_id: String,

    /// Process identifier
    /// (e.g. `urn:fdc:peppol.eu:2017:poacc:billing:01:1.0`).
    pub process_id: String,

    /// Override the default transport profile from [`SmpConfig`].
    /// Typically `None` — use the config default.
    pub transport_profile: Option<String>,
}

impl SmpLookupRequest {
    /// A lookup using the config's default transport profile.
    ///
    /// The three identifiers are the ones a Peppol AP already has to hand: the
    /// recipient participant, the document type it is sending, and the process
    /// that document belongs to.
    ///
    /// ```
    /// # use asx_rs::smp::SmpLookupRequest;
    /// let request = SmpLookupRequest::new(
    ///     "0088:1234567890123",
    ///     "urn:cen.eu:en16931:2017#compliant#urn:fdc:peppol.eu:2017:poacc:billing:3.0::2.1",
    ///     "urn:fdc:peppol.eu:2017:poacc:billing:01:1.0",
    /// );
    /// assert!(request.transport_profile.is_none());
    /// ```
    pub fn new(
        participant_id: impl Into<String>,
        document_type_id: impl Into<String>,
        process_id: impl Into<String>,
    ) -> Self {
        Self {
            participant_id: participant_id.into(),
            document_type_id: document_type_id.into(),
            process_id: process_id.into(),
            transport_profile: None,
        }
    }

    /// Request a specific transport profile instead of the config's default.
    #[must_use]
    pub fn with_transport_profile(mut self, transport_profile: impl Into<String>) -> Self {
        self.transport_profile = Some(transport_profile.into());
        self
    }
}

// ── Client ────────────────────────────────────────────────────────────────

/// Async PEPPOL SMP client for dynamic AS4 endpoint discovery.
///
/// Construct with [`SmpClient::new`] (convenience) or
/// [`SmpClient::with_config`] (full control).
#[derive(Clone, Debug)]
pub struct SmpClient {
    config: SmpConfig,
    /// Timeouts and pool settings for the per-lookup pinned client.
    ///
    /// The client itself is built **per request** so it can be pinned to the
    /// addresses that URL validation actually checked; a long-lived client
    /// would re-resolve DNS and reopen the rebinding hole.
    transport: TransportConfig,
    /// Performs the BDXL NAPTR query. `None` until one is supplied, which is
    /// why [`SmlDiscovery::Naptr`] reports a configuration error rather than
    /// silently falling back to a scheme the network no longer publishes.
    resolver: Option<Arc<dyn BdxlResolver>>,
}

impl SmpClient {
    /// Create a client that targets the given SML zone with Peppol defaults
    /// and BDXL NAPTR discovery.
    ///
    /// Supply a resolver with [`with_resolver`](Self::with_resolver) before
    /// looking anything up.
    pub fn new(sml_zone: impl Into<String>) -> Self {
        Self::with_config(SmpConfig {
            sml_zone: sml_zone.into(),
            discovery: SmlDiscovery::Naptr,
            participant_scheme: PEPPOL_PARTICIPANT_SCHEME.to_string(),
            transport_profile: PEPPOL_AS4_TRANSPORT_PROFILE.to_string(),
            signature_policy: SmpSignaturePolicy::Deny,
        })
    }

    /// Create a client with explicit [`SmpConfig`].
    pub fn with_config(config: SmpConfig) -> Self {
        Self {
            config,
            transport: TransportConfig {
                request_timeout: std::time::Duration::from_secs(10),
                ..TransportConfig::default()
            },
            resolver: None,
        }
    }

    /// Attach the resolver that performs BDXL NAPTR queries.
    ///
    /// Required for [`SmlDiscovery::Naptr`]; ignored by the other modes.
    #[must_use]
    pub fn with_resolver(mut self, resolver: Arc<dyn BdxlResolver>) -> Self {
        self.resolver = Some(resolver);
        self
    }

    /// Return the `SmpConfig` this client was created with.
    pub fn config(&self) -> &SmpConfig {
        &self.config
    }

    /// Look up the AS4 endpoint for the given participant + document type +
    /// process combination.
    ///
    /// Performs one HTTP GET against the PEPPOL SMP and parses the returned
    /// `ServiceMetadata` XML.
    ///
    /// # Errors
    ///
    /// - [`ErrorCode::InvalidInput`] — URL validation failed (bad SML zone or
    ///   private-range host after DNS resolution).
    /// - [`ErrorCode::TransportFailure`] — HTTP request failed.
    /// - [`ErrorCode::NotFound`] — SMP returned a non-2xx status.
    /// - [`ErrorCode::ParseFailed`] — XML parsing or endpoint extraction failed.
    pub async fn lookup_endpoint(&self, req: SmpLookupRequest) -> Result<SmpEndpoint> {
        let smp_base = self.resolve_smp_base_url(&req.participant_id).await?;
        let url = self.build_lookup_url_at(&smp_base, &req);

        // Validate **and pin** in one step. Validating the URL and then letting
        // a separately-built client resolve DNS again is a
        // time-of-check/time-of-use hole: the attacker answers the check with a
        // public address and the connection with a private one. An SMP lookup
        // decides where a message goes and which key it is encrypted to, so it
        // is the last place to leave that open.
        let http = validated_pinned_client(&url, &self.transport, "smp_lookup").await?;

        let response = http.get(&url).send().await.map_err(|e| {
            AsxError::new(
                ErrorCode::TransportFailure,
                format!("SMP HTTP request failed for '{url}': {e}"),
                ErrorContext::new("smp_lookup"),
            )
        })?;

        let status = response.status();
        if !status.is_success() {
            return Err(AsxError::new(
                ErrorCode::NotFound,
                format!(
                    "SMP returned HTTP {status} for participant '{}' / doc-type '{}'",
                    req.participant_id, req.document_type_id
                ),
                ErrorContext::new("smp_lookup"),
            ));
        }

        let body = response.bytes().await.map_err(|e| {
            AsxError::new(
                ErrorCode::TransportFailure,
                format!("SMP response body read failed: {e}"),
                ErrorContext::new("smp_lookup_body"),
            )
        })?;

        let transport_profile = req
            .transport_profile
            .as_deref()
            .unwrap_or(&self.config.transport_profile);

        parse_service_metadata(
            &body,
            &req.process_id,
            transport_profile,
            &self.config.signature_policy,
        )
    }

    /// The DNS name a [`SmlDiscovery::Naptr`] or [`SmlDiscovery::LegacyCname`]
    /// lookup queries for `participant_id`.
    ///
    /// Exposed so a deployment can check what a lookup will ask for — a name
    /// that resolves to nothing and an unregistered participant are otherwise
    /// the same observation.
    pub fn discovery_dns_name(&self, participant_id: &str) -> Option<String> {
        match &self.config.discovery {
            SmlDiscovery::Naptr => Some(bdxl_dns_name(
                &self.config.participant_scheme,
                participant_id,
                &self.config.sml_zone,
            )),
            SmlDiscovery::LegacyCname => Some(legacy_cname_host(
                &self.config.participant_scheme,
                participant_id,
                &self.config.sml_zone,
            )),
            SmlDiscovery::Static { .. } => None,
        }
    }

    /// Locate the SMP that holds `participant_id`'s metadata.
    async fn resolve_smp_base_url(&self, participant_id: &str) -> Result<String> {
        match &self.config.discovery {
            SmlDiscovery::Static { smp_base_url } => {
                Ok(smp_base_url.trim_end_matches('/').to_string())
            }
            SmlDiscovery::LegacyCname => Ok(format!(
                "https://{}",
                legacy_cname_host(
                    &self.config.participant_scheme,
                    participant_id,
                    &self.config.sml_zone,
                )
            )),
            SmlDiscovery::Naptr => {
                let Some(resolver) = self.resolver.as_ref() else {
                    return Err(AsxError::new(
                        ErrorCode::InvalidInput,
                        "SmlDiscovery::Naptr needs a DNS resolver: call \
                         SmpClient::with_resolver(..) — with HickoryBdxlResolver under the \
                         `dns` feature, or your own BdxlResolver. Use \
                         SmpConfig::with_static_smp(..) if the SMP URL is known in advance",
                        ErrorContext::new("smp_discovery"),
                    ));
                };
                let name = bdxl_dns_name(
                    &self.config.participant_scheme,
                    participant_id,
                    &self.config.sml_zone,
                );
                let records = resolver.lookup_naptr(&name).await?;
                if records.is_empty() {
                    return Err(AsxError::new(
                        ErrorCode::NotFound,
                        format!(
                            "participant '{participant_id}' is not registered in SML zone \
                             '{}': no NAPTR records at '{name}'",
                            self.config.sml_zone
                        ),
                        ErrorContext::new("smp_discovery"),
                    ));
                }
                select_smp_base_url(&records)
            }
        }
    }

    /// Compute the full SMP ServiceMetadata lookup URL against a known SMP base.
    ///
    /// Exposed primarily for testing and logging purposes; [`lookup_endpoint`]
    /// finds the base itself.
    ///
    /// [`lookup_endpoint`]: Self::lookup_endpoint
    pub fn build_lookup_url_at(&self, smp_base_url: &str, req: &SmpLookupRequest) -> String {
        let canonical = format!("{}::{}", self.config.participant_scheme, req.participant_id);
        format!(
            "{}/{}/services/{}",
            smp_base_url.trim_end_matches('/'),
            percent_encode(&canonical),
            percent_encode(&req.document_type_id),
        )
    }
}

// ── XML parsing ───────────────────────────────────────────────────────────

/// OASIS BDX SMP 1.0 (`busdox`) — the shape Peppol and CEF eDelivery publish.
const SMP_NS: &str = "http://busdox.org/serviceMetadata/publishing/1.0/";
/// OASIS SMP 2.0 document namespace.
const SMP2_NS_SERVICE_METADATA: &str = "http://docs.oasis-open.org/bdxr/ns/SMP/2/ServiceMetadata";
/// OASIS SMP 2.0 basic components — where every leaf element in a 2.0
/// `ServiceMetadata` actually lives.
const SMP2_NS_BASIC: &str = "http://docs.oasis-open.org/bdxr/ns/SMP/2/BasicComponents";
/// OASIS SMP 2.0 aggregate components — `ProcessMetadata`, `Process`,
/// `Endpoint`, `Certificate`.
const SMP2_NS_AGGREGATE: &str = "http://docs.oasis-open.org/bdxr/ns/SMP/2/AggregateComponents";

/// Parse `ServiceMetadata` XML bytes and extract the first matching endpoint.
///
/// Matches on both SMP 1.0 and SMP 2.0 namespaces.
fn parse_service_metadata(
    xml: &[u8],
    process_id: &str,
    transport_profile: &str,
    signature_policy: &SmpSignaturePolicy,
) -> Result<SmpEndpoint> {
    let text = std::str::from_utf8(xml).map_err(|_| {
        AsxError::new(
            ErrorCode::ParseFailed,
            "SMP ServiceMetadata response is not valid UTF-8",
            ErrorContext::new("smp_parse"),
        )
    })?;

    let doc = Document::parse(text).map_err(|e| {
        AsxError::new(
            ErrorCode::ParseFailed,
            format!("SMP ServiceMetadata XML parse failed: {e}"),
            ErrorContext::new("smp_parse"),
        )
    })?;

    let signer = enforce_smp_signature_policy(text, &doc, signature_policy)?;
    let version = SmpVersion::detect(&doc)?;

    let mut endpoint =
        extract_endpoint(&doc, version, process_id, transport_profile)?.ok_or_else(|| {
            AsxError::new(
                ErrorCode::NotFound,
                format!(
                    "no matching AS4 endpoint found in SMP for process '{process_id}' \
                     with transport profile '{transport_profile}'"
                ),
                ErrorContext::new("smp_parse"),
            )
        })?;

    endpoint.signed_document = std::sync::Arc::from(xml);
    endpoint.verified_signer_fingerprint_sha256 = signer;
    Ok(endpoint)
}

/// Apply [`SmpSignaturePolicy`], returning the verified signer fingerprint when
/// the signature was actually checked.
fn enforce_smp_signature_policy(
    text: &str,
    doc: &Document<'_>,
    policy: &SmpSignaturePolicy,
) -> Result<Option<String>> {
    match policy {
        SmpSignaturePolicy::Deny => Err(AsxError::new(
            ErrorCode::PolicyViolation,
            "SMP lookup results are not authorized for use: SmpConfig::signature_policy is \
             SmpSignaturePolicy::Deny (the default). Set \
             SmpSignaturePolicy::verify_with_trust_anchors(smp_ca_pems) to verify the \
             response against the network's SMP CA, or one of the weaker variants for a \
             closed or test network",
            ErrorContext::new("smp_signature_policy"),
        )),
        SmpSignaturePolicy::Verify(revocation) => {
            let verified = crate::crypto::wssec::verify_enveloped_document_signature(
                text,
                // SMP responses are pinned by the network's SMP CA (the
                // revocation policy's anchors), not by a per-signer fingerprint.
                &[],
                &crate::crypto::wssec::RevocationPolicy::from(revocation.as_ref()),
            )
            .map_err(|err| {
                AsxError::new(
                    ErrorCode::SecurityVerificationFailed,
                    format!(
                        "SMP ServiceMetadata signature verification failed: {}. The endpoint \
                         URL and recipient certificate in this response cannot be trusted",
                        err.message
                    ),
                    ErrorContext::new("smp_verify_signature"),
                )
            })?;
            Ok(Some(verified.signer_fingerprint_sha256))
        }
        SmpSignaturePolicy::RequireSignaturePresent => {
            if !has_enveloped_signature(doc) {
                return Err(AsxError::new(
                    ErrorCode::SecurityVerificationFailed,
                    "SMP ServiceMetadata response carries no ds:Signature; PEPPOL and CEF \
                     eDelivery require the SMP to sign its metadata. Set \
                     SmpConfig::signature_policy = AllowUnsigned only for a closed or test \
                     network",
                    ErrorContext::new("smp_parse_signature"),
                ));
            }
            Ok(None)
        }
        SmpSignaturePolicy::AllowUnsigned => Ok(None),
    }
}

/// XML Signature namespace.
const XMLDSIG_NS: &str = "http://www.w3.org/2000/09/xmldsig#";

/// Whether the document contains a `ds:Signature` element.
///
/// Presence only. [`SmpSignaturePolicy::Verify`] is what actually checks the
/// enveloped signature; this backs the weaker
/// [`SmpSignaturePolicy::RequireSignaturePresent`], which catches an outright
/// unsigned SMP and nothing more.
fn has_enveloped_signature(doc: &Document<'_>) -> bool {
    doc.descendants().any(|n| {
        n.is_element()
            && n.tag_name().namespace() == Some(XMLDSIG_NS)
            && n.tag_name().name() == "Signature"
    })
}

/// Which OASIS SMP generation a `ServiceMetadata` document is written in.
///
/// The two are not dialects of one grammar: 2.0 moved the transport profile
/// from an attribute to an element, renamed the address and the process
/// identifier, and nested the certificate. Detecting the version and then
/// parsing with that version's rules is the alternative to a name-matching
/// walk that accepts a mixture neither specification defines (D5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SmpVersion {
    /// OASIS BDX SMP 1.0 (`busdox`).
    V1,
    /// OASIS SMP 2.0.
    V2,
}

impl SmpVersion {
    /// Determine the version from the document element's namespace.
    fn detect(doc: &Document<'_>) -> Result<Self> {
        let root = doc.root_element();
        match root.tag_name().namespace() {
            Some(SMP_NS) => Ok(Self::V1),
            Some(SMP2_NS_SERVICE_METADATA) => Ok(Self::V2),
            other => Err(AsxError::new(
                ErrorCode::ParseFailed,
                format!(
                    "SMP response document element is {{{}}}{}; expected an OASIS SMP 1.0 \
                     ({SMP_NS}) or SMP 2.0 ({SMP2_NS_SERVICE_METADATA}) ServiceMetadata",
                    other.unwrap_or("no namespace"),
                    root.tag_name().name(),
                ),
                ErrorContext::new("smp_parse"),
            )),
        }
    }
}

/// Find the endpoint for `process_id` + `transport_profile`.
///
/// Ambiguity is refused rather than resolved by document order: a response
/// offering the same process and transport profile twice would otherwise let
/// whichever entry came first decide where a message goes.
fn extract_endpoint(
    doc: &Document<'_>,
    version: SmpVersion,
    process_id: &str,
    transport_profile: &str,
) -> Result<Option<SmpEndpoint>> {
    let mut found: Option<SmpEndpoint> = None;

    for endpoint in doc.descendants().filter(|n| is_endpoint(*n, version)) {
        let Some(profile) = endpoint_transport_profile(endpoint, version) else {
            continue;
        };
        if !profile.trim().eq_ignore_ascii_case(transport_profile) {
            continue;
        }
        let Some(declared_process) = ancestor_process_id(endpoint, version) else {
            continue;
        };
        if !declared_process.trim().eq_ignore_ascii_case(process_id) {
            continue;
        }
        let Some(url) = endpoint_address(endpoint, version) else {
            continue;
        };

        if found.is_some() {
            return Err(AsxError::new(
                ErrorCode::ParseFailed,
                format!(
                    "SMP response offers more than one endpoint for process '{process_id}' \
                     with transport profile '{transport_profile}'; refusing to resolve the \
                     ambiguity by document order"
                ),
                ErrorContext::new("smp_parse"),
            ));
        }

        found = Some(SmpEndpoint {
            // Both replaced by `parse_service_metadata` once the policy has run.
            signed_document: std::sync::Arc::from(&[][..]),
            verified_signer_fingerprint_sha256: None,
            url: url.trim().to_string(),
            certificate_der_b64: endpoint_certificate(endpoint, version)
                .map(|s| s.split_whitespace().collect()),
            transport_profile: profile.trim().to_string(),
            service_description: child_text(endpoint, version, "ServiceDescription", "Description")
                .map(|s| s.trim().to_string()),
            service_activation_date: child_text(
                endpoint,
                version,
                "ServiceActivationDate",
                "ActivationDate",
            )
            .map(|s| s.trim().to_string()),
            service_expiration_date: child_text(
                endpoint,
                version,
                "ServiceExpirationDate",
                "ExpirationDate",
            )
            .map(|s| s.trim().to_string()),
        });
    }

    Ok(found)
}

/// Whether `node` is an `Endpoint` element of the given SMP generation.
fn is_endpoint(node: roxmltree::Node<'_, '_>, version: SmpVersion) -> bool {
    match version {
        SmpVersion::V1 => is_named(node, SMP_NS, "Endpoint"),
        SmpVersion::V2 => is_named(node, SMP2_NS_AGGREGATE, "Endpoint"),
    }
}

/// The endpoint's transport profile.
///
/// SMP 1.0 carries it as the `transportProfile` attribute; SMP 2.0 moved it
/// into a `TransportProfileID` child element. Reading only the attribute — as
/// this crate did — matches no SMP 2.0 endpoint at all.
fn endpoint_transport_profile<'a>(
    endpoint: roxmltree::Node<'a, '_>,
    version: SmpVersion,
) -> Option<&'a str> {
    match version {
        SmpVersion::V1 => endpoint.attribute("transportProfile"),
        SmpVersion::V2 => child_in(endpoint, SMP2_NS_BASIC, "TransportProfileID")?.text(),
    }
}

/// The URL an AS4 message is POSTed to.
fn endpoint_address<'a>(endpoint: roxmltree::Node<'a, '_>, version: SmpVersion) -> Option<&'a str> {
    match version {
        SmpVersion::V1 => child_in(endpoint, SMP_NS, "EndpointReference")
            .and_then(|reference| child_in(reference, WSA_NS, "Address"))
            .or_else(|| child_in(endpoint, SMP_NS, "EndpointURI"))?
            .text(),
        SmpVersion::V2 => child_in(endpoint, SMP2_NS_BASIC, "AddressURI")?.text(),
    }
}

/// The receiving party's base64 DER certificate.
fn endpoint_certificate<'a>(
    endpoint: roxmltree::Node<'a, '_>,
    version: SmpVersion,
) -> Option<&'a str> {
    match version {
        SmpVersion::V1 => child_in(endpoint, SMP_NS, "Certificate")?.text(),
        // SMP 2.0 nests the bytes one level deeper, in a typed wrapper.
        SmpVersion::V2 => child_in(endpoint, SMP2_NS_AGGREGATE, "Certificate")
            .and_then(|cert| child_in(cert, SMP2_NS_BASIC, "ContentBinaryObject"))?
            .text(),
    }
}

/// Text of the first matching child, named per generation.
fn child_text<'a>(
    endpoint: roxmltree::Node<'a, '_>,
    version: SmpVersion,
    v1_name: &str,
    v2_name: &str,
) -> Option<&'a str> {
    match version {
        SmpVersion::V1 => child_in(endpoint, SMP_NS, v1_name)?.text(),
        SmpVersion::V2 => child_in(endpoint, SMP2_NS_BASIC, v2_name)?.text(),
    }
}

/// The process identifier governing this endpoint.
///
/// SMP 1.0 nests `Endpoint` under `ServiceEndpointList` under `Process`, whose
/// `ProcessIdentifier` names it. SMP 2.0 places `Endpoint` and `Process`
/// side by side inside `ProcessMetadata`, and the identifier is `Process/ID`.
fn ancestor_process_id<'a>(
    endpoint: roxmltree::Node<'a, '_>,
    version: SmpVersion,
) -> Option<&'a str> {
    match version {
        SmpVersion::V1 => {
            let process = endpoint.parent()?.parent()?;
            child_in(process, SMP_NS, "ProcessIdentifier")?.text()
        }
        SmpVersion::V2 => {
            let process_metadata = endpoint.parent()?;
            let process = child_in(process_metadata, SMP2_NS_AGGREGATE, "Process")?;
            child_in(process, SMP2_NS_BASIC, "ID")?.text()
        }
    }
}

/// WS-Addressing namespace — SMP 1.0 wraps the endpoint URL in an
/// `EndpointReference/Address`.
const WSA_NS: &str = "http://www.w3.org/2005/08/addressing";

/// Whether `node` is an element `{namespace}local`.
fn is_named(node: roxmltree::Node<'_, '_>, namespace: &str, local: &str) -> bool {
    node.is_element()
        && node.tag_name().name() == local
        && node.tag_name().namespace() == Some(namespace)
}

/// The first child element `{namespace}local` of `node`.
fn child_in<'a, 'i>(
    node: roxmltree::Node<'a, 'i>,
    namespace: &str,
    local: &str,
) -> Option<roxmltree::Node<'a, 'i>> {
    node.children().find(|c| is_named(*c, namespace, local))
}

// ── URL helpers ───────────────────────────────────────────────────────────

/// Percent-encode a string for use in a URL path segment.
///
/// Encodes all bytes except `ALPHA / DIGIT / "-" / "." / "_" / "~"` (RFC 3986
/// §2.3 unreserved characters).  Colons, slashes, and other characters that
/// would normally appear in PEPPOL identifiers are all encoded.
fn percent_encode(s: &str) -> String {
    let mut encoded = String::with_capacity(s.len() * 3);
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            encoded.push(b as char);
        } else {
            use std::fmt::Write;
            let _ = write!(encoded, "%{b:02X}");
        }
    }
    encoded
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percent_encode_peppol_doc_type() {
        let raw = "urn:oasis:names:specification:ubl:schema:xsd:Invoice-2::Invoice##test";
        let encoded = percent_encode(raw);
        assert!(!encoded.contains(':'), "colons must be encoded");
        assert!(!encoded.contains('#'), "hash must be encoded");
        assert!(encoded.contains("urn%3Aoasis"), "colon should be %3A");
    }

    #[test]
    fn lookup_url_appends_the_smp_rest_binding_to_the_discovered_base() {
        let client = SmpClient::with_config(SmpConfig::with_static_smp("https://smp.example.org/"));
        let req = SmpLookupRequest {
            participant_id: "0088:5798009883995".to_string(),
            document_type_id: "urn:test:doc".to_string(),
            process_id: "urn:test:process".to_string(),
            transport_profile: None,
        };
        assert_eq!(
            client.build_lookup_url_at("https://smp.example.org/", &req),
            "https://smp.example.org\
             /iso6523-actorid-upis%3A%3A0088%3A5798009883995\
             /services/urn%3Atest%3Adoc"
        );
    }

    /// The Peppol presets must name the OpenPeppol zones. The European
    /// Commission zones they replaced stopped answering on 31 August 2026, so a
    /// stale constant here is a lookup that silently finds nothing.
    #[test]
    fn peppol_presets_name_the_openpeppol_sml_zones() {
        assert_eq!(
            SmpConfig::peppol_production().sml_zone,
            "participant.sml.prod.tech.peppol.org"
        );
        assert_eq!(
            SmpConfig::peppol_test().sml_zone,
            "participant.sml.test.tech.peppol.org"
        );
        assert!(matches!(
            SmpConfig::peppol_production().discovery,
            SmlDiscovery::Naptr
        ));
    }

    #[test]
    fn discovery_dns_name_matches_the_bdxl_construction() {
        let client = SmpClient::with_config(SmpConfig::peppol_production());
        assert_eq!(
            client
                .discovery_dns_name("0088:5790002590993")
                .expect("NAPTR discovery names a host"),
            "2M2UFGZNGSS25JOOMOV2S4VGG7PW64KIVYNONDSVZSRT4EAZVCLQ\
             .iso6523-actorid-upis.participant.sml.prod.tech.peppol.org"
        );
        assert_eq!(
            SmpClient::with_config(SmpConfig::with_static_smp("https://smp.example.org"))
                .discovery_dns_name("0088:5790002590993"),
            None,
            "a statically configured SMP is not looked up"
        );
    }

    /// NAPTR discovery without a resolver is a configuration error that names
    /// the fix, not a silent fall-back to a scheme the network withdrew.
    #[tokio::test]
    async fn naptr_discovery_without_a_resolver_reports_the_missing_seam() {
        let client = SmpClient::with_config(SmpConfig::peppol_production());
        let err = client
            .resolve_smp_base_url("0088:5790002590993")
            .await
            .expect_err("NAPTR discovery needs a resolver");
        assert_eq!(err.code, crate::core::ErrorCode::InvalidInput);
        assert!(err.message.contains("with_resolver"), "{}", err.message);
    }

    #[tokio::test]
    async fn naptr_discovery_resolves_the_smp_base_url() {
        let name = bdxl_dns_name(
            "iso6523-actorid-upis",
            "0088:5790002590993",
            "participant.sml.prod.tech.peppol.org",
        );
        let client = SmpClient::with_config(SmpConfig::peppol_production()).with_resolver(
            Arc::new(StaticBdxlResolver::new().with_smp(name, "https://smp.example.org")),
        );
        assert_eq!(
            client
                .resolve_smp_base_url("0088:5790002590993")
                .await
                .expect("the participant is registered"),
            "https://smp.example.org"
        );
    }

    /// An unregistered participant is `NotFound`, and the message names the
    /// zone and the name that was queried — otherwise a wrong zone and a
    /// genuinely absent participant are the same observation.
    #[tokio::test]
    async fn unregistered_participant_reports_not_found_with_the_queried_name() {
        let client = SmpClient::with_config(SmpConfig::peppol_production())
            .with_resolver(Arc::new(StaticBdxlResolver::new()));
        let err = client
            .resolve_smp_base_url("0088:0000000000000")
            .await
            .expect_err("nothing is registered");
        assert_eq!(err.code, crate::core::ErrorCode::NotFound);
        assert!(
            err.message.contains("participant.sml.prod.tech.peppol.org"),
            "{}",
            err.message
        );
    }

    #[tokio::test]
    async fn legacy_cname_discovery_builds_the_historical_host() {
        let client = SmpClient::with_config(SmpConfig {
            discovery: SmlDiscovery::LegacyCname,
            sml_zone: "edelivery.tech.ec.europa.eu".to_string(),
            ..SmpConfig::peppol_production()
        });
        assert_eq!(
            client
                .resolve_smp_base_url("0088:123abc")
                .await
                .expect("the construction is pure"),
            "https://B-f5e78500450d37de5aabe6648ac3bb70\
             .iso6523-actorid-upis.edelivery.tech.ec.europa.eu"
        );
    }

    #[test]
    fn parse_service_metadata_smp1_roundtrip() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<ServiceMetadata xmlns="http://busdox.org/serviceMetadata/publishing/1.0/">
  <ServiceInformation>
    <ParticipantIdentifier scheme="iso6523-actorid-upis">0088:1234567890123</ParticipantIdentifier>
    <DocumentIdentifier scheme="busdox-docid-qns">urn:test:doc</DocumentIdentifier>
    <ProcessList>
      <Process>
        <ProcessIdentifier scheme="cenbii-procid-ubl">urn:test:process</ProcessIdentifier>
        <ServiceEndpointList>
          <Endpoint transportProfile="peppol-transport-as4-v2_0">
            <EndpointURI>https://ap.example.com/as4/receive</EndpointURI>
            <Certificate>MIIB…</Certificate>
            <ServiceDescription>Test AP</ServiceDescription>
            <ServiceActivationDate>2024-01-01</ServiceActivationDate>
            <ServiceExpirationDate>2025-12-31</ServiceExpirationDate>
          </Endpoint>
        </ServiceEndpointList>
      </Process>
    </ProcessList>
  </ServiceInformation>
</ServiceMetadata>"#;
        let ep = parse_service_metadata(
            xml.as_bytes(),
            "urn:test:process",
            "peppol-transport-as4-v2_0",
            &SmpSignaturePolicy::AllowUnsigned,
        )
        .expect("should parse");
        assert_eq!(ep.url, "https://ap.example.com/as4/receive");
        assert_eq!(ep.transport_profile, "peppol-transport-as4-v2_0");
        assert_eq!(ep.service_description.as_deref(), Some("Test AP"));
        assert_eq!(ep.service_activation_date.as_deref(), Some("2024-01-01"));
    }

    /// OASIS SMP 2.0 moved the transport profile from an attribute to an
    /// element, renamed the address and the process identifier, and nested the
    /// certificate. The crate advertised 2.0 support while reading only the 1.0
    /// attribute, so no 2.0 endpoint could ever match.
    #[test]
    fn parse_service_metadata_smp2_roundtrip() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<smp:ServiceMetadata
    xmlns:smp="http://docs.oasis-open.org/bdxr/ns/SMP/2/ServiceMetadata"
    xmlns:sma="http://docs.oasis-open.org/bdxr/ns/SMP/2/AggregateComponents"
    xmlns:smb="http://docs.oasis-open.org/bdxr/ns/SMP/2/BasicComponents">
  <smb:ID>urn:test:doc</smb:ID>
  <smb:ParticipantID>0088:1234567890123</smb:ParticipantID>
  <sma:ProcessMetadata>
    <sma:Process>
      <smb:ID>urn:test:process</smb:ID>
    </sma:Process>
    <sma:Endpoint>
      <smb:TransportProfileID>peppol-transport-as4-v2_0</smb:TransportProfileID>
      <smb:Description>Test AP</smb:Description>
      <smb:AddressURI>https://ap.example.com/as4/receive</smb:AddressURI>
      <smb:ActivationDate>2024-01-01</smb:ActivationDate>
      <smb:ExpirationDate>2025-12-31</smb:ExpirationDate>
      <sma:Certificate>
        <smb:ContentBinaryObject>MIIB</smb:ContentBinaryObject>
      </sma:Certificate>
    </sma:Endpoint>
  </sma:ProcessMetadata>
</smp:ServiceMetadata>"#;
        let ep = parse_service_metadata(
            xml.as_bytes(),
            "urn:test:process",
            "peppol-transport-as4-v2_0",
            &SmpSignaturePolicy::AllowUnsigned,
        )
        .expect("an SMP 2.0 response must parse");
        assert_eq!(ep.url, "https://ap.example.com/as4/receive");
        assert_eq!(ep.certificate_der_b64.as_deref(), Some("MIIB"));
        assert_eq!(ep.service_description.as_deref(), Some("Test AP"));
        assert_eq!(ep.service_activation_date.as_deref(), Some("2024-01-01"));
        assert_eq!(ep.service_expiration_date.as_deref(), Some("2025-12-31"));
    }

    /// SMP 1.0 may wrap the address in a WS-Addressing `EndpointReference`.
    #[test]
    fn parse_service_metadata_smp1_endpoint_reference_address() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<ServiceMetadata xmlns="http://busdox.org/serviceMetadata/publishing/1.0/"
                 xmlns:wsa="http://www.w3.org/2005/08/addressing">
  <ServiceInformation>
    <ProcessList>
      <Process>
        <ProcessIdentifier>urn:test:process</ProcessIdentifier>
        <ServiceEndpointList>
          <Endpoint transportProfile="peppol-transport-as4-v2_0">
            <EndpointReference><wsa:Address>https://ap.example.com/as4</wsa:Address></EndpointReference>
          </Endpoint>
        </ServiceEndpointList>
      </Process>
    </ProcessList>
  </ServiceInformation>
</ServiceMetadata>"#;
        let ep = parse_service_metadata(
            xml.as_bytes(),
            "urn:test:process",
            "peppol-transport-as4-v2_0",
            &SmpSignaturePolicy::AllowUnsigned,
        )
        .expect("the WS-Addressing shape must parse");
        assert_eq!(ep.url, "https://ap.example.com/as4");
    }

    /// Two endpoints for one process and transport profile are ambiguous. The
    /// answer decides where a message goes, so document order must not settle
    /// it (D5).
    #[test]
    fn duplicate_endpoints_for_one_process_are_rejected() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<ServiceMetadata xmlns="http://busdox.org/serviceMetadata/publishing/1.0/">
  <ServiceInformation>
    <ProcessList>
      <Process>
        <ProcessIdentifier>urn:test:process</ProcessIdentifier>
        <ServiceEndpointList>
          <Endpoint transportProfile="peppol-transport-as4-v2_0">
            <EndpointURI>https://first.example/as4</EndpointURI>
          </Endpoint>
          <Endpoint transportProfile="peppol-transport-as4-v2_0">
            <EndpointURI>https://second.example/as4</EndpointURI>
          </Endpoint>
        </ServiceEndpointList>
      </Process>
    </ProcessList>
  </ServiceInformation>
</ServiceMetadata>"#;
        let err = parse_service_metadata(
            xml.as_bytes(),
            "urn:test:process",
            "peppol-transport-as4-v2_0",
            &SmpSignaturePolicy::AllowUnsigned,
        )
        .expect_err("an ambiguous response must be refused");
        assert_eq!(err.code, crate::core::ErrorCode::ParseFailed);
        assert!(err.message.contains("more than one"), "{}", err.message);
    }

    /// A document in neither SMP namespace is refused by name rather than
    /// walked with lenient element matching.
    #[test]
    fn unknown_document_namespace_is_refused() {
        let xml = r#"<ServiceMetadata xmlns="urn:not-an-smp"><Endpoint/></ServiceMetadata>"#;
        let err = parse_service_metadata(
            xml.as_bytes(),
            "urn:test:process",
            "peppol-transport-as4-v2_0",
            &SmpSignaturePolicy::AllowUnsigned,
        )
        .expect_err("an unknown namespace must be refused");
        assert_eq!(err.code, crate::core::ErrorCode::ParseFailed);
    }

    #[test]
    fn parse_service_metadata_no_match_returns_not_found() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<ServiceMetadata xmlns="http://busdox.org/serviceMetadata/publishing/1.0/">
  <ServiceInformation>
    <ProcessList>
      <Process>
        <ProcessIdentifier scheme="x">urn:other:process</ProcessIdentifier>
        <ServiceEndpointList>
          <Endpoint transportProfile="peppol-transport-as4-v2_0">
            <EndpointURI>https://ap.example.com/as4/receive</EndpointURI>
          </Endpoint>
        </ServiceEndpointList>
      </Process>
    </ProcessList>
  </ServiceInformation>
</ServiceMetadata>"#;
        let err = parse_service_metadata(
            xml.as_bytes(),
            "urn:test:process", // does not match "urn:other:process"
            "peppol-transport-as4-v2_0",
            &SmpSignaturePolicy::AllowUnsigned,
        )
        .unwrap_err();
        assert_eq!(err.code, crate::core::ErrorCode::NotFound);
    }

    /// An unsigned `ServiceMetadata` is never valid on a public network, so the
    /// default policy rejects it rather than silently trusting the endpoint and
    /// certificate it advertises.
    #[test]
    fn unsigned_service_metadata_is_rejected_by_the_presence_gate() {
        let xml = SIGNED_FIXTURE_TEMPLATE.replace("{signature}", "");
        let err = parse_service_metadata(
            xml.as_bytes(),
            "urn:test:process",
            "peppol-transport-as4-v2_0",
            &SmpSignaturePolicy::RequireSignaturePresent,
        )
        .expect_err("unsigned response must be rejected by the presence gate");
        assert_eq!(err.code, crate::core::ErrorCode::SecurityVerificationFailed);
        assert!(err.message.contains("ds:Signature"), "{}", err.message);
    }

    /// A lookup whose authenticity was never established must not become a
    /// routing decision by default.
    #[test]
    fn lookup_results_are_denied_until_a_policy_is_chosen() {
        let signature = r#"<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignatureValue>AAAA</ds:SignatureValue></ds:Signature>"#;
        let xml = SIGNED_FIXTURE_TEMPLATE.replace("{signature}", signature);
        let err = parse_service_metadata(
            xml.as_bytes(),
            "urn:test:process",
            "peppol-transport-as4-v2_0",
            &SmpSignaturePolicy::default(),
        )
        .expect_err("the default policy must refuse to hand back a routing decision");
        assert_eq!(err.code, crate::core::ErrorCode::PolicyViolation);
        assert!(
            err.message.contains("SmpSignaturePolicy"),
            "the error must name the knob to set: {}",
            err.message
        );

        // The PEPPOL presets carry network identity, not trust anchors.
        assert!(matches!(
            SmpConfig::peppol_production().signature_policy,
            SmpSignaturePolicy::Deny
        ));
    }

    #[test]
    fn signed_service_metadata_is_accepted_and_bytes_are_retained() {
        let signature = r#"<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignatureValue>AAAA</ds:SignatureValue></ds:Signature>"#;
        let xml = SIGNED_FIXTURE_TEMPLATE.replace("{signature}", signature);
        let ep = parse_service_metadata(
            xml.as_bytes(),
            "urn:test:process",
            "peppol-transport-as4-v2_0",
            &SmpSignaturePolicy::RequireSignaturePresent,
        )
        .expect("a signed response passes the presence gate");

        // The caller needs the exact bytes to verify the signature itself —
        // ASX only checked that one is present.
        assert_eq!(ep.signed_document.as_ref(), xml.as_bytes());
    }

    #[test]
    fn signature_presence_gate_can_be_disabled_for_closed_networks() {
        let xml = SIGNED_FIXTURE_TEMPLATE.replace("{signature}", "");
        parse_service_metadata(
            xml.as_bytes(),
            "urn:test:process",
            "peppol-transport-as4-v2_0",
            &SmpSignaturePolicy::AllowUnsigned,
        )
        .expect("closed networks may opt out");
    }

    const SIGNED_FIXTURE_TEMPLATE: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<ServiceMetadata xmlns="http://busdox.org/serviceMetadata/publishing/1.0/">
  <ServiceInformation>
    <ProcessList>
      <Process>
        <ProcessIdentifier scheme="cenbii-procid-ubl">urn:test:process</ProcessIdentifier>
        <ServiceEndpointList>
          <Endpoint transportProfile="peppol-transport-as4-v2_0">
            <EndpointURI>https://ap.example.com/as4/receive</EndpointURI>
          </Endpoint>
        </ServiceEndpointList>
      </Process>
    </ProcessList>
  </ServiceInformation>
  {signature}
</ServiceMetadata>"#;
}
