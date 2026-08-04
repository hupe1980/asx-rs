//! PEPPOL / CEF Service Metadata Publisher (SMP) client.
//!
//! Implements [OASIS BDX SMP 1.0 / PEPPOL BIS] dynamic discovery: resolves the
//! AS4 endpoint URL and signing certificate for a participant from the PEPPOL
//! Participant Identifier + Document Type Identifier + Process Identifier triple.
//!
//! # DNS Discovery (BDXL / SML)
//!
//! The SMP hostname is computed by hashing the canonical participant identifier:
//!
//! ```text
//! canonical  = "{scheme}::{participant_id}"            (e.g. "iso6523-actorid-upis::0088:1234567890123")
//! dns_label  = "B-" + lowercase_hex(md5(lowercase(canonical)))
//! smp_host   = "{dns_label}.{sml_zone}"                (e.g. "B-abc123….acc.edelivery.tech.ec.europa.eu")
//! smp_base   = "https://{smp_host}/"
//! ```
//!
//! The ServiceMetadata is retrieved with:
//! ```text
//! GET {smp_base}{url_encoded_canonical}/services/{url_encoded_document_type_id}
//! ```
//!
//! # ⚠ The SMP response is not cryptographically verified
//!
//! This client parses `ServiceMetadata` but does **not** verify its enveloped
//! XMLDSig signature. The lookup result decides *where a message is sent* and
//! *which public key it is encrypted to*, and TLS authenticates the SMP host,
//! not the metadata it serves — so a rogue or compromised SMP can redirect
//! traffic and substitute its own recipient certificate.
//!
//! PEPPOL and CEF eDelivery both require the consumer to verify the signature
//! and chain the SMP signing certificate to the network's SMP CA. Until ASX
//! implements this (it needs whole-document `URI=""` reference support that the
//! WS-Security verifier lacks), the embedder must do it, using the response
//! bytes returned in [`SmpEndpoint::signed_document`].
//!
//! [`SmpConfig::signature_policy`] defaults to rejecting a response that
//! carries no `ds:Signature` at all — presence, not validity.
//!
//! # SSRF protection
//!
//! The constructed SMP URL is validated before the HTTP request is issued.
//! The `sml_zone` value in [`SmpConfig`] **must** be a trusted PEPPOL SML
//! hostname supplied by the operator — treat it like a service URL, not user
//! data.
//!
//! # Example
//!
//! ```rust,no_run
//! use asx_rs::smp::{SmpClient, SmpLookupRequest};
//!
//! async fn example() -> asx_rs::core::Result<()> {
//!     let client = SmpClient::new("acc.edelivery.tech.ec.europa.eu");
//!     let endpoint = client.lookup_endpoint(SmpLookupRequest {
//!         participant_id:   "0088:1234567890123".to_string(),
//!         document_type_id: "urn:oasis:names:specification:ubl:schema:xsd:Invoice-2::Invoice##\
//!                            urn:cen.eu:en16931:2017#compliant#\
//!                            urn:fdc:peppol.eu:2017:poacc:billing:3.0::2.1".to_string(),
//!         process_id:       "urn:fdc:peppol.eu:2017:poacc:billing:01:1.0".to_string(),
//!         transport_profile: None,
//!     }).await?;
//!     println!("AS4 endpoint: {}", endpoint.url);
//!     Ok(())
//! }
//! ```
//!
//! [OASIS BDX SMP 1.0 / PEPPOL BIS]: https://docs.peppol.eu/edelivery/smp/

use crate::core::{AsxError, ErrorCode, ErrorContext, Result};
use crate::transport::egress::validate_egress_url;
use roxmltree::Document;

// ── Well-known constants ──────────────────────────────────────────────────

/// PEPPOL AS4 transport profile identifier used in SMP ServiceMetadata.
pub const PEPPOL_AS4_TRANSPORT_PROFILE: &str = "peppol-transport-as4-v2_0";

/// Default PEPPOL participant identifier scheme.
pub const PEPPOL_PARTICIPANT_SCHEME: &str = "iso6523-actorid-upis";

// ── Types ─────────────────────────────────────────────────────────────────

/// Configuration for an [`SmpClient`].
#[derive(Debug, Clone)]
pub struct SmpConfig {
    /// SML DNS zone used to construct SMP hostnames.
    ///
    /// | Network | Value |
    /// |---------|-------|
    /// | PEPPOL test | `acc.edelivery.tech.ec.europa.eu` |
    /// | PEPPOL production | `edelivery.tech.ec.europa.eu` |
    pub sml_zone: String,

    /// Participant identifier scheme prepended to the participant ID before
    /// hashing.  Default: [`PEPPOL_PARTICIPANT_SCHEME`].
    pub participant_scheme: String,

    /// Default transport profile used when [`SmpLookupRequest::transport_profile`]
    /// is `None`.  Default: [`PEPPOL_AS4_TRANSPORT_PROFILE`].
    pub transport_profile: String,

    /// Whether an unsigned `ServiceMetadata` response is accepted.
    ///
    /// Defaults to [`SmpSignaturePolicy::RequireSignaturePresent`]. See
    /// [`SmpEndpoint::signed_document`] — the signature is checked for
    /// *presence* only; verifying it remains the embedder's job.
    pub signature_policy: SmpSignaturePolicy,
}

impl SmpConfig {
    /// Config for the **PEPPOL test** network.
    pub fn peppol_test() -> Self {
        Self {
            sml_zone: "acc.edelivery.tech.ec.europa.eu".to_string(),
            participant_scheme: PEPPOL_PARTICIPANT_SCHEME.to_string(),
            transport_profile: PEPPOL_AS4_TRANSPORT_PROFILE.to_string(),
            signature_policy: SmpSignaturePolicy::RequireSignaturePresent,
        }
    }

    /// Config for the **PEPPOL production** network.
    pub fn peppol_production() -> Self {
        Self {
            sml_zone: "edelivery.tech.ec.europa.eu".to_string(),
            participant_scheme: PEPPOL_PARTICIPANT_SCHEME.to_string(),
            transport_profile: PEPPOL_AS4_TRANSPORT_PROFILE.to_string(),
            signature_policy: SmpSignaturePolicy::RequireSignaturePresent,
        }
    }
}

/// Whether a lookup requires the SMP response to carry an XMLDSig signature.
///
/// ASX does **not** cryptographically verify the SMP signature — see
/// [`SmpEndpoint::signed_document`] for why that matters and what to do about
/// it. This policy controls only whether a response with *no* signature at all
/// is accepted, which is the one part of the check the library can make
/// unambiguously.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub enum SmpSignaturePolicy {
    /// **Verify** the enveloped `ds:Signature` and chain the SMP signing
    /// certificate to the supplied trust anchors.
    ///
    /// This is the only setting that makes an SMP lookup trustworthy: it is
    /// what proves the endpoint URL and recipient certificate really came from
    /// the network's SMP and were not substituted in transit.
    ///
    /// Supply the network's SMP CA (PEPPOL / CEF publish these). An empty
    /// anchor set with `require_chain_validation` fails closed.
    Verify(Box<crate::crypto::wssec::OwnedRevocationPolicy>),
    /// Require a `ds:Signature` to be present but do not verify it.
    ///
    /// A stepping stone, not a destination: it catches an outright unsigned or
    /// misconfigured SMP but nothing else. Prefer [`Self::Verify`].
    #[default]
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

    /// The exact `ServiceMetadata` bytes the SMP returned, retained so the
    /// caller can verify the enveloped XMLDSig itself if it prefers.
    ///
    /// # This response is not cryptographically verified by ASX
    ///
    /// [`Self::url`] and [`Self::certificate_der_b64`] come straight from this
    /// document. Everything downstream — where the message is sent, and which
    /// public key it is encrypted to — is therefore only as trustworthy as the
    /// SMP response, and TLS authenticates *the SMP host*, not the metadata it
    /// serves. A rogue or compromised SMP can redirect traffic and substitute
    /// its own recipient certificate.
    ///
    /// PEPPOL and CEF eDelivery both require the consumer to verify the
    /// enveloped signature and chain the signing certificate to the network's
    /// SMP CA. ASX does not do this yet (the WS-Security verifier cannot
    /// process the whole-document `URI=""` reference with an enveloped-signature
    /// transform that SMP responses use), so **the embedder must**. These bytes
    /// are the input to that check.
    ///
    /// [`SmpSignaturePolicy::RequireSignaturePresent`] guarantees only that a
    /// `ds:Signature` element exists — not that it verifies.
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

// ── Client ────────────────────────────────────────────────────────────────

/// Async PEPPOL SMP client for dynamic AS4 endpoint discovery.
///
/// Construct with [`SmpClient::new`] (convenience) or
/// [`SmpClient::with_config`] (full control).
#[derive(Clone)]
pub struct SmpClient {
    config: SmpConfig,
    http: reqwest::Client,
}

impl SmpClient {
    /// Create a client that targets the given SML zone with PEPPOL defaults.
    ///
    /// # Panics
    /// Panics if the HTTP client cannot be built (system TLS configuration
    /// error).
    pub fn new(sml_zone: impl Into<String>) -> Self {
        Self::with_config(SmpConfig {
            sml_zone: sml_zone.into(),
            participant_scheme: PEPPOL_PARTICIPANT_SCHEME.to_string(),
            transport_profile: PEPPOL_AS4_TRANSPORT_PROFILE.to_string(),
            signature_policy: SmpSignaturePolicy::RequireSignaturePresent,
        })
    }

    /// Create a client with explicit [`SmpConfig`].
    ///
    /// # Panics
    /// Panics if the HTTP client cannot be built.
    pub fn with_config(config: SmpConfig) -> Self {
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            // Do not follow redirects: the SMP lookup URL is SSRF-validated
            // before the request, but a `3xx Location` from a compromised or
            // spoofed SMP would be followed to an unchecked (possibly internal)
            // host. SMP endpoints are fixed and never legitimately redirect.
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("failed to build SMP reqwest client");
        Self { config, http }
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
        let url = self.build_lookup_url(&req);
        validate_egress_url(&url, "smp_lookup").await?;

        let response = self.http.get(&url).send().await.map_err(|e| {
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

    /// Compute the full SMP ServiceMetadata lookup URL for a request.
    ///
    /// Exposed primarily for testing and logging purposes.
    pub fn build_lookup_url(&self, req: &SmpLookupRequest) -> String {
        let smp_base = self.build_smp_base_url(&req.participant_id);
        let canonical = format!("{}::{}", self.config.participant_scheme, req.participant_id);
        format!(
            "{}{}/services/{}",
            smp_base,
            percent_encode(&canonical),
            percent_encode(&req.document_type_id),
        )
    }

    /// Construct the SMP base URL for a participant using the PEPPOL BDXL
    /// MD5-based DNS formula.
    fn build_smp_base_url(&self, participant_id: &str) -> String {
        let canonical = format!(
            "{}::{}",
            self.config.participant_scheme,
            participant_id.to_lowercase()
        );
        let hash = md5_hex(canonical.as_bytes());
        format!("https://B-{}.{}/", hash, self.config.sml_zone)
    }
}

// ── XML parsing ───────────────────────────────────────────────────────────

/// OASIS BDX SMP / PEPPOL SMP 1.0 namespace.
const SMP_NS: &str = "http://busdox.org/serviceMetadata/publishing/1.0/";
/// OASIS BDX SMP 2.0 namespace (used by some CEF deployments).
const SMP_NS_V2: &str = "http://docs.oasis-open.org/bdxr/ns/SMP/2/ServiceMetadata";

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

    let mut endpoint = extract_endpoint(&doc, process_id, transport_profile).ok_or_else(|| {
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
        SmpSignaturePolicy::Verify(revocation) => {
            let verified = crate::crypto::wssec::verify_enveloped_document_signature(
                text,
                None,
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
/// Presence only — verifying it requires whole-document (`URI=""`) reference
/// support that the WS-Security verifier does not implement. See
/// [`SmpEndpoint::signed_document`].
fn has_enveloped_signature(doc: &Document<'_>) -> bool {
    doc.descendants().any(|n| {
        n.is_element()
            && n.tag_name().namespace() == Some(XMLDSIG_NS)
            && n.tag_name().name() == "Signature"
    })
}

/// Walk the roxmltree document and find the first `<Endpoint>` whose
/// `<ProcessIdentifier>` matches `process_id` and whose `transportProfile`
/// attribute matches `transport_profile`.
fn extract_endpoint(
    doc: &Document<'_>,
    process_id: &str,
    transport_profile: &str,
) -> Option<SmpEndpoint> {
    // Both SMP 1.0 (busdox) and SMP 2.0 (OASIS) share the same element
    // structure; we match on local name and accept either namespace.
    for node in doc.descendants() {
        if !matches_smp_element(&node, "Endpoint") {
            continue;
        }

        // Check transportProfile attribute.
        let profile = node.attribute("transportProfile")?;
        if !profile.eq_ignore_ascii_case(transport_profile) {
            continue;
        }

        // Walk up to find <Process> → <ProcessIdentifier>.
        let process_node = find_ancestor_process_id(doc, &node)?;
        if !process_node.eq_ignore_ascii_case(process_id) {
            continue;
        }

        // Extract child elements.
        let url =
            find_child_text(&node, "EndpointURI").or_else(|| find_child_text(&node, "Address"))?; // SMP 2.0 uses <Address>

        let certificate_der_b64 = find_child_text(&node, "Certificate");
        let service_description = find_child_text(&node, "ServiceDescription");
        let service_activation_date = find_child_text(&node, "ServiceActivationDate");
        let service_expiration_date = find_child_text(&node, "ServiceExpirationDate");

        return Some(SmpEndpoint {
            // Both replaced by `parse_service_metadata` once the policy has run.
            signed_document: std::sync::Arc::from(&[][..]),
            verified_signer_fingerprint_sha256: None,
            url: url.trim().to_string(),
            certificate_der_b64: certificate_der_b64.map(|s| s.trim().to_string()),
            transport_profile: profile.to_string(),
            service_description: service_description.map(|s| s.trim().to_string()),
            service_activation_date: service_activation_date.map(|s| s.trim().to_string()),
            service_expiration_date: service_expiration_date.map(|s| s.trim().to_string()),
        });
    }
    None
}

/// Returns `true` when `node` is an element with local name `local` in either
/// the SMP 1.0 or SMP 2.0 namespace (or no namespace at all, for lenient parsing).
fn matches_smp_element(node: &roxmltree::Node<'_, '_>, local: &str) -> bool {
    if !node.is_element() {
        return false;
    }
    if node.tag_name().name() != local {
        return false;
    }
    let ns = node.tag_name().namespace().unwrap_or("");
    ns.is_empty() || ns == SMP_NS || ns == SMP_NS_V2
}

/// Find the `<ProcessIdentifier>` text value in the ancestor `<Process>` node.
fn find_ancestor_process_id<'a>(
    _doc: &'a Document<'a>,
    endpoint: &roxmltree::Node<'a, '_>,
) -> Option<&'a str> {
    // Walk up: Endpoint → ServiceEndpointList → Process → ProcessIdentifier
    let service_endpoint_list = endpoint.parent()?;
    let process = service_endpoint_list.parent()?;
    for child in process.children() {
        if matches_smp_element(&child, "ProcessIdentifier") {
            return child.text();
        }
    }
    None
}

/// Return the trimmed text of the first child element with local name `name`.
fn find_child_text<'a>(node: &roxmltree::Node<'a, '_>, name: &str) -> Option<&'a str> {
    for child in node.children() {
        if matches_smp_element(&child, name) {
            return child.text();
        }
    }
    None
}

// ── Crypto helpers ────────────────────────────────────────────────────────

/// Compute the lowercase hex-encoded MD5 of `input`.
///
/// MD5 is used here **solely** for PEPPOL DNS name construction per the BDXL
/// specification — it provides no security property and is not used for
/// content integrity.
fn md5_hex(input: &[u8]) -> String {
    use openssl::hash::{MessageDigest, hash};
    // MD5 failure would require an OpenSSL build without MD5 support, which
    // PEPPOL deployments will never encounter.
    let digest = hash(MessageDigest::md5(), input).expect("MD5 unavailable");
    let mut hex = String::with_capacity(32);
    for b in &*digest {
        use std::fmt::Write;
        let _ = write!(hex, "{b:02x}");
    }
    hex
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
    fn md5_hex_known_value() {
        // Pre-computed: echo -n "iso6523-actorid-upis::0088:5798009883995" | md5sum
        let result = md5_hex("iso6523-actorid-upis::0088:5798009883995".as_bytes());
        assert_eq!(result.len(), 32, "MD5 hex should be 32 chars");
        assert!(result.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn percent_encode_peppol_doc_type() {
        let raw = "urn:oasis:names:specification:ubl:schema:xsd:Invoice-2::Invoice##test";
        let encoded = percent_encode(raw);
        assert!(!encoded.contains(':'), "colons must be encoded");
        assert!(!encoded.contains('#'), "hash must be encoded");
        assert!(encoded.contains("urn%3Aoasis"), "colon should be %3A");
    }

    #[test]
    fn build_lookup_url_structure() {
        let client = SmpClient::new("acc.edelivery.tech.ec.europa.eu");
        let req = SmpLookupRequest {
            participant_id: "0088:5798009883995".to_string(),
            document_type_id: "urn:test:doc".to_string(),
            process_id: "urn:test:process".to_string(),
            transport_profile: None,
        };
        let url = client.build_lookup_url(&req);
        assert!(
            url.starts_with("https://B-"),
            "must start with SMP DNS scheme"
        );
        assert!(
            url.contains(".acc.edelivery.tech.ec.europa.eu/"),
            "must embed SML zone"
        );
        assert!(url.contains("/services/"), "must have /services/ path");
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
    fn unsigned_service_metadata_is_rejected_by_default() {
        let xml = SIGNED_FIXTURE_TEMPLATE.replace("{signature}", "");
        let err = parse_service_metadata(
            xml.as_bytes(),
            "urn:test:process",
            "peppol-transport-as4-v2_0",
            &SmpSignaturePolicy::default(),
        )
        .expect_err("unsigned response must be rejected under the default policy");
        assert_eq!(err.code, crate::core::ErrorCode::SecurityVerificationFailed);
        assert!(err.message.contains("ds:Signature"), "{}", err.message);
    }

    #[test]
    fn signed_service_metadata_is_accepted_and_bytes_are_retained() {
        let signature = r#"<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignatureValue>AAAA</ds:SignatureValue></ds:Signature>"#;
        let xml = SIGNED_FIXTURE_TEMPLATE.replace("{signature}", signature);
        let ep = parse_service_metadata(
            xml.as_bytes(),
            "urn:test:process",
            "peppol-transport-as4-v2_0",
            &SmpSignaturePolicy::default(),
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
