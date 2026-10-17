// WS-Security module — thin re-export hub.
//
// Implementation is split across focused sub-modules:
//   canonicalize  — Exclusive XML Canonicalization (Exc-C14N) + DOM serializer
//   sign          — XMLDSig signature generation
//   verify        — Signature + reference verification
//   x509          — X.509 certificate validation + PKIX chain
//   xmlenc        — XML Encryption (AES-128/256-GCM + RSA-OAEP)

// These sub-modules depend on roxmltree, an as4-only dep.
#[cfg(feature = "as4")]
pub(crate) mod canonicalize;
#[cfg(feature = "as4")]
pub(crate) use canonicalize::swa_attachment_digest_input;
#[cfg(feature = "as4")]
pub(crate) mod sign;
#[cfg(feature = "as4")]
pub(crate) mod verify;
pub(crate) mod x509;

#[cfg(feature = "as4")]
pub mod xmlenc;

// ---------------------------------------------------------------------------
// Namespace URI constants (used across all sub-modules)
// ---------------------------------------------------------------------------

#[cfg(feature = "as4")]
pub(crate) const DS_NS: &str = crate::xml::ns::DS;
#[cfg(feature = "as4")]
pub(crate) const XML_NS: &str = crate::xml::ns::XML;
// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

use serde::{Deserialize, Serialize};

/// The trust material a signature's certification path is validated
/// against (offline PKIX: no CRL, no OCSP, nothing fetched). Revocation is
/// the caller's, after the signature and the sender rule
/// (`crate::revocation`).
#[derive(Clone, Default)]
pub struct ChainPolicy<'a> {
    pub trust_anchor_pems: &'a [String],
    /// When `true`, PKIX chain validation is always performed and fails if
    /// `trust_anchor_pems` is empty (fail-closed). When `false`, chain
    /// validation is skipped entirely (vector suites only).
    pub require_chain_validation: bool,
    /// Pre-parsed trust-anchor X.509 certificates; when `Some`, used instead
    /// of re-parsing `trust_anchor_pems` on every call.
    pub pre_parsed_trust_anchors: Option<Vec<openssl::x509::X509>>,
    /// A pre-built `X509Store` of the anchors (cached per session).
    pub pre_built_x509_store: Option<std::sync::Arc<openssl::x509::store::X509Store>>,
}

impl std::fmt::Debug for ChainPolicy<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChainPolicy")
            .field("require_chain_validation", &self.require_chain_validation)
            .field("trust_anchors", &self.trust_anchor_pems.len())
            .field(
                "pre_parsed_trust_anchors",
                &self.pre_parsed_trust_anchors.as_ref().map(|v| v.len()),
            )
            .field("pre_built_x509_store", &self.pre_built_x509_store.is_some())
            .finish()
    }
}

/// Owned counterpart to [`ChainPolicy`]; borrow it with `From`.
#[derive(Debug, Clone)]
pub struct OwnedChainPolicy {
    pub trust_anchor_pems: Vec<String>,
    pub require_chain_validation: bool,
}

impl OwnedChainPolicy {
    /// The supplied anchors, PKIX chain validation required.
    pub fn production(trust_anchor_pems: Vec<String>) -> Self {
        Self {
            trust_anchor_pems,
            require_chain_validation: true,
        }
    }
}

impl<'a> From<&'a OwnedChainPolicy> for ChainPolicy<'a> {
    fn from(owned: &'a OwnedChainPolicy) -> Self {
        Self {
            trust_anchor_pems: &owned.trust_anchor_pems,
            require_chain_validation: owned.require_chain_validation,
            pre_parsed_trust_anchors: None,
            pre_built_x509_store: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[non_exhaustive]
pub enum WsSecOutboundKeyInfoProfile {
    /// WS-Security X.509 v3 token (`wsse:BinarySecurityToken` with
    /// `ValueType="...#X509v3"`), referenced from `ds:KeyInfo` via
    /// `wsse:SecurityTokenReference`. **The default**, and the shape WSS 1.1.1
    /// §7.7 requires — `ds:KeyInfo` in a WS-Security header MUST contain a
    /// `SecurityTokenReference`. WSS4J-based receivers (Holodeck B2B, phase4,
    /// Domibus) reject a bare `ds:X509Data` KeyInfo with
    /// `UNSUPPORTED_SECURITY_TOKEN`.
    #[default]
    BinarySecurityTokenX509v3,
    /// Bare `ds:X509Data` + `ds:RSAKeyValue` KeyInfo. Not WSS-conformant —
    /// use only for consumers that verify with plain XMLDSig tooling.
    X509DataAndRsaKeyValue,
    /// Bare `ds:X509Data` KeyInfo. Not WSS-conformant — see
    /// [`Self::X509DataAndRsaKeyValue`].
    X509DataOnly,
    /// WS-Security X.509 PKI path token (`wsse:BinarySecurityToken` with
    /// `ValueType="...#X509PKIPathv1"`).  The `ds:KeyInfo` inside the signature
    /// element contains a `<wsse:SecurityTokenReference>` pointing to the BST
    /// by `wsu:Id` instead of an inline `ds:X509Certificate`.
    ///
    /// Required by BDEW AS4-Profil §2.2.6.2.1 and some German energy market
    /// profiles.  When this profile is selected, the caller must also use
    /// [`WsSecurityHeaderBuilder::with_signing_cert_pkipath_der`](crate::crypto::soap_builder::WsSecurityHeaderBuilder::with_signing_cert_pkipath_der) so that the
    /// BST element and `ds:KeyInfo` reference are consistent.
    X509PKIPathv1,
}

/// Defined in the algorithm registry (`crypto::alg`).
pub use crate::crypto::alg::{WsSecCanonicalizationKind, WsSecDigestMethod};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WsSecCanonicalizationProfile {
    pub kind: WsSecCanonicalizationKind,
    pub include_comments: bool,
    /// Prefixes from `exc-c14n:InclusiveNamespaces/@PrefixList`.
    ///
    /// Per W3C Exc-C14N §2.1: when a namespace prefix appears in this list and
    /// the binding is in-scope at the element being serialized, the namespace
    /// declaration MUST be rendered even if the prefix is not "visibly utilized"
    /// by the element or its attributes.  This is required for interoperability
    /// with signers that declare visually-unused prefixes in the SignedInfo scope.
    pub inclusive_ns_prefixes: Vec<String>,
}

impl Default for WsSecCanonicalizationProfile {
    fn default() -> Self {
        Self {
            kind: WsSecCanonicalizationKind::Exclusive,
            include_comments: false,
            inclusive_ns_prefixes: Vec::new(),
        }
    }
}

impl WsSecCanonicalizationProfile {
    /// Returns the W3C transform algorithm URI for this profile's C14N kind.
    pub fn algorithm_uri(&self) -> &'static str {
        self.kind.uri()
    }

    /// Construct a profile for Inclusive C14N.
    pub fn inclusive() -> Self {
        Self {
            kind: WsSecCanonicalizationKind::Inclusive,
            include_comments: false,
            inclusive_ns_prefixes: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WsSecSignatureReference {
    pub uri: String,
    pub digest_method: WsSecDigestMethod,
    pub digest_value_base64: String,
    /// C14N algorithm used for this reference's `<ds:Transform>`.
    /// Defaults to `Exclusive`; set to `Inclusive` when the transform URI is
    /// `http://www.w3.org/TR/2001/REC-xml-c14n-20010315`.
    pub c14n_kind: WsSecCanonicalizationKind,
    /// Inclusive namespace prefixes parsed from `exc-c14n:InclusiveNamespaces/@PrefixList`
    /// inside the `<ds:Transforms>` element for this reference.
    /// Only meaningful when `c14n_kind == Exclusive`.
    pub inclusive_ns_prefixes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WsSecCanonicalizedReference {
    pub uri: String,
    pub canonical_bytes: Vec<u8>,
    pub digest_value_base64: String,
}

/// Internal-only material extracted from a `<ds:Signature>` element.
///
/// Gated to match its only consumer, the `as4` test module below — a `test`
/// build without `as4` would otherwise define it and never construct it.
#[cfg(all(test, feature = "as4"))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WsSecSignatureMaterial {
    pub(crate) signed_info_c14n: Vec<u8>,
    pub(crate) signature_value: Vec<u8>,
    pub(crate) signature_method_algorithm: String,
    pub(crate) rsa_modulus: Option<Vec<u8>>,
    pub(crate) rsa_exponent: Option<Vec<u8>>,
    pub(crate) x509_certificates_der: Vec<Vec<u8>>,
}

// ---------------------------------------------------------------------------
// Public API re-exports
// ---------------------------------------------------------------------------

#[cfg(feature = "as4")]
pub use xmlenc::{XmlEncPayloadAlgorithm, decrypt_swa, encrypt_swa};

#[cfg(feature = "as4")]
pub use canonicalize::{
    SameDocumentReferenceIndex, canonical_vector_diff, canonicalize_enveloped_document,
    canonicalize_reference, canonicalize_reference_digest_from_doc_with_inclusive_ns_and_index,
    canonicalize_reference_from_doc, canonicalize_reference_from_doc_with_inclusive_ns,
};
#[cfg(feature = "as4")]
pub use sign::{
    generate_xmlsig_signature, generate_xmlsig_signature_with_external_references,
    generate_xmlsig_signature_with_external_references_preparsed,
};
#[cfg(feature = "as4")]
pub use verify::{
    ENVELOPED_SIGNATURE_URI, VerifiedEnvelopedSignature, WsSecVerifyOptions,
    parse_signature_references, verify_enveloped_document_signature, verify_enveloped_signature,
    verify_signature_references_strict,
};
pub use x509::validate_certificate_chain;

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(all(test, feature = "as4"))]
mod tests {
    use super::*;
    use crate::crypto::signing::SignatureAlgorithm;
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
    use openssl::asn1::Asn1Time;
    use openssl::hash::MessageDigest;
    use openssl::pkey::PKey;
    use openssl::sign::Signer;
    use openssl::x509::X509;
    use verify::parse_signature_material;
    use x509::validate_x509_certificate;

    // Valid DER-encoded self-signed RSA CA certificate generated for tests.
    const TEST_CA_CERT_B64: &str = concat!(
        "MIIDBzCCAe+gAwIBAgIUK+LZMsfX026W1bjcNh7Itso/uIowDQYJKoZIhvcNAQELBQAwEzERMA8GA1UEAwwIYXN4LXRlc3QwHhcNMjYwNTE3MTA0ND",
        "U3WhcNMjcwNTE3MTA0NDU3WjATMREwDwYDVQQDDAhhc3gtdGVzdDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAJ5HIVNm97sqbUIurm2p",
        "fhcvhXyKxRY/eGr8Ohs4h5UvpOtFjlMDoQZEqihyeq8dzFU51FpTuwU+xprCLNwYkBTT7M9J2t6VQZdK2+CobUzk56rRAH1J3io+v3abpYro3bYexU",
        "Zh4aow7Oy5T7rouEdAqes6ozt9v6WouyHcY0LxSIR2WYjaGDZRbJCdySdGWgsznjNOkYjKaRUySvtSHAHXFM544ZR0xIJf94OqnFYjWPx3RYM0ttIi",
        "lcZgem9T+K8MMb6BNWBWM5n+KXSjph+6PlO0txjLMW2GO8xcjeHplM0j/0B7NbtF1NGJpNTXS8XY8OjNpVy6QQj5DAVG1HUCAwEAAaNTMFEwHQYDVR",
        "0OBBYEFAsog+EedA+IQsJhrXUwEP2ltMJHMB8GA1UdIwQYMBaAFAsog+EedA+IQsJhrXUwEP2ltMJHMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcN",
        "AQELBQADggEBACm6hPG6kdwcNEHBMccjW0elgdjhBcygn4FTnMTR3Vfxyr69grzhtiyo7IoSm6KPpx88D33PH3s8w2ZCRg8js7wRRZkugHZUNl1lcI",
        "pjJcelhZim9oKnklpnjgH4YE14mIFlEN5OhOZMuLSjA//iw+fQ3U+Xqnv+TnaSPbop0JqPZGQW4a8tGOfK55wPU9JSRQ5OrBgP+tMM8TYSNDler4Xs",
        "Dk4+exqNprjVO1457CfiDPAYWnkfByAoTgw9ffdSxdiZRKBgJcWrJyp/AWxeqO6rP8x9xo3WRwe0X+GynUet3hSskSfyQX45vXqoGL+uv+9m9pfWAe",
        "Rmb40yqB4UT/g="
    );

    /// Generate a 2048-bit RSA key pair (openssl) and return the PKey,
    /// base64-encoded modulus, and base64-encoded public exponent.
    fn make_test_rsa_key() -> (openssl::pkey::PKey<openssl::pkey::Private>, String, String) {
        let rsa = openssl::rsa::Rsa::generate(2048).expect("rsa key generation");
        let modulus_b64 = BASE64_STANDARD.encode(rsa.n().to_vec());
        let exponent_b64 = BASE64_STANDARD.encode(rsa.e().to_vec());
        let pkey = openssl::pkey::PKey::from_rsa(rsa).expect("pkey from rsa");
        (pkey, modulus_b64, exponent_b64)
    }

    /// An RSA key plus a self-signed certificate that carries it.
    ///
    /// Verification requires an X.509 signer token — a bare `ds:RSAKeyValue`
    /// authenticates nobody — so positive tests need a certificate whose public
    /// key really is the signing key.
    fn make_test_rsa_key_and_cert() -> (
        openssl::pkey::PKey<openssl::pkey::Private>,
        String,
        String,
        String,
    ) {
        let (pkey, modulus_b64, exponent_b64) = make_test_rsa_key();

        let mut name = openssl::x509::X509NameBuilder::new().expect("name builder");
        name.append_entry_by_nid(openssl::nid::Nid::COMMONNAME, "asx-wssec-test")
            .expect("cn");
        let name = name.build();

        let mut builder = openssl::x509::X509::builder().expect("x509 builder");
        builder.set_version(2).expect("version");
        let mut serial = openssl::bn::BigNum::new().expect("serial");
        serial
            .pseudo_rand(64, openssl::bn::MsbOption::MAYBE_ZERO, false)
            .expect("serial rand");
        builder
            .set_serial_number(&serial.to_asn1_integer().expect("serial asn1"))
            .expect("serial");
        builder.set_subject_name(&name).expect("subject");
        builder.set_issuer_name(&name).expect("issuer");
        builder.set_pubkey(&pkey).expect("pubkey");
        builder
            .set_not_before(&openssl::asn1::Asn1Time::days_from_now(0).expect("nb"))
            .expect("nb");
        builder
            .set_not_after(&openssl::asn1::Asn1Time::days_from_now(365).expect("na"))
            .expect("na");
        builder
            .sign(&pkey, openssl::hash::MessageDigest::sha256())
            .expect("sign cert");
        let cert_b64 = BASE64_STANDARD.encode(builder.build().to_der().expect("cert der"));

        (pkey, modulus_b64, exponent_b64, cert_b64)
    }

    /// Sign `data` with the given PKey using RSA-SHA256; return base64 signature.
    fn rsa_sha256_sign(pkey: &openssl::pkey::PKey<openssl::pkey::Private>, data: &[u8]) -> String {
        let mut signer = openssl::sign::Signer::new(openssl::hash::MessageDigest::sha256(), pkey)
            .expect("signer");
        signer.update(data).expect("signer update");
        BASE64_STANDARD.encode(signer.sign_to_vec().expect("sign"))
    }

    /// The `<ds:Transforms>` a real signer writes for this reference.
    ///
    /// A same-document reference must state the exclusive algorithm, because
    /// XMLDSig §4.3.3.2 makes *inclusive* C14N the default for one that states
    /// nothing. A `cid:` reference dereferences to an octet stream and
    /// correctly carries no C14N transform at all.
    fn reference_transforms(reference_uri: &str) -> &'static str {
        if reference_uri.starts_with("cid:") {
            ""
        } else {
            "\n                    <ds:Transforms>\
             \n                        <ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\
             \n                    </ds:Transforms>"
        }
    }

    fn signed_xml_with_rsa_keyvalue(
        reference_uri: &str,
        payload_xml: &str,
        digest_base64: &str,
        signature_value_base64: &str,
        modulus_base64: &str,
        exponent_base64: &str,
    ) -> String {
        let rsa_sha256_uri = SignatureAlgorithm::RsaSha256.algorithm_uri();
        let sha256_uri = WsSecDigestMethod::Sha256.algorithm_uri();
        let transforms = reference_transforms(reference_uri);
        format!(
            r#"<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"
        xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"
        xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
        xmlns:eb="urn:example:eb">
    <soap:Header>
        <wsse:Security xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
        <ds:Signature>
            <ds:SignedInfo>
                <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
                <ds:SignatureMethod Algorithm="{rsa_sha256_uri}"/>
                <ds:Reference URI="{reference_uri}">{transforms}
                    <ds:DigestMethod Algorithm="{sha256_uri}"/>
                    <ds:DigestValue>{digest_base64}</ds:DigestValue>
                </ds:Reference>
            </ds:SignedInfo>
            <ds:SignatureValue>{signature_value_base64}</ds:SignatureValue>
            <ds:KeyInfo>
                <ds:KeyValue>
                    <ds:RSAKeyValue>
                        <ds:Modulus>{modulus_base64}</ds:Modulus>
                        <ds:Exponent>{exponent_base64}</ds:Exponent>
                    </ds:RSAKeyValue>
                </ds:KeyValue>
            </ds:KeyInfo>
        </ds:Signature>
        </wsse:Security>
    </soap:Header>
    <soap:Body>
{payload_xml}
    </soap:Body>
</soap:Envelope>"#
        )
    }

    fn signed_xml_with_rsa_keyvalue_and_x509(
        reference_uri: &str,
        payload_xml: &str,
        digest_base64: &str,
        signature_value_base64: &str,
        modulus_base64: &str,
        exponent_base64: &str,
        x509_certificate_base64: &str,
    ) -> String {
        let rsa_sha256_uri = SignatureAlgorithm::RsaSha256.algorithm_uri();
        let sha256_uri = WsSecDigestMethod::Sha256.algorithm_uri();
        let transforms = reference_transforms(reference_uri);
        format!(
            r#"<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"
        xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"
        xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
        xmlns:eb="urn:example:eb">
    <soap:Header>
        <wsse:Security xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
        <ds:Signature>
            <ds:SignedInfo>
                <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
                <ds:SignatureMethod Algorithm="{rsa_sha256_uri}"/>
                <ds:Reference URI="{reference_uri}">{transforms}
                    <ds:DigestMethod Algorithm="{sha256_uri}"/>
                    <ds:DigestValue>{digest_base64}</ds:DigestValue>
                </ds:Reference>
            </ds:SignedInfo>
            <ds:SignatureValue>{signature_value_base64}</ds:SignatureValue>
            <ds:KeyInfo>
                <ds:KeyValue>
                    <ds:RSAKeyValue>
                        <ds:Modulus>{modulus_base64}</ds:Modulus>
                        <ds:Exponent>{exponent_base64}</ds:Exponent>
                    </ds:RSAKeyValue>
                </ds:KeyValue>
                <ds:X509Data>
                    <ds:X509Certificate>{x509_certificate_base64}</ds:X509Certificate>
                </ds:X509Data>
            </ds:KeyInfo>
        </ds:Signature>
        </wsse:Security>
    </soap:Header>
    <soap:Body>
{payload_xml}
    </soap:Body>
</soap:Envelope>"#
        )
    }

    fn signed_xml_with_x509_only(
        reference_uri: &str,
        payload_xml: &str,
        digest_base64: &str,
        signature_value_base64: &str,
        x509_certificate_base64: &str,
    ) -> String {
        let rsa_sha256_uri = SignatureAlgorithm::RsaSha256.algorithm_uri();
        let sha256_uri = WsSecDigestMethod::Sha256.algorithm_uri();
        let transforms = reference_transforms(reference_uri);
        format!(
            r#"<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"
        xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"
        xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
        xmlns:eb="urn:example:eb">
    <soap:Header>
        <wsse:Security xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
        <ds:Signature>
            <ds:SignedInfo>
                <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
                <ds:SignatureMethod Algorithm="{rsa_sha256_uri}"/>
                <ds:Reference URI="{reference_uri}">{transforms}
                    <ds:DigestMethod Algorithm="{sha256_uri}"/>
                    <ds:DigestValue>{digest_base64}</ds:DigestValue>
                </ds:Reference>
            </ds:SignedInfo>
            <ds:SignatureValue>{signature_value_base64}</ds:SignatureValue>
            <ds:KeyInfo>
                <ds:X509Data>
                    <ds:X509Certificate>{x509_certificate_base64}</ds:X509Certificate>
                </ds:X509Data>
            </ds:KeyInfo>
        </ds:Signature>
        </wsse:Security>
    </soap:Header>
    <soap:Body>
{payload_xml}
    </soap:Body>
</soap:Envelope>"#
        )
    }

    /// XMLDSig §4.3.3.2: a same-document reference that declares no transform
    /// is digested over **inclusive** Canonical XML. Defaulting to exclusive
    /// rejects a conformant peer's signature as a forgery whenever an ancestor
    /// declares a namespace the signed subtree does not use — the ordinary
    /// shape of a SOAP envelope.
    #[test]
    fn transformless_same_document_reference_digests_over_inclusive_c14n() {
        let payload = "    <eb:Payload wsu:Id=\"payload-1\">ABC</eb:Payload>";
        let skeleton = signed_xml_with_x509_only("#payload-1", payload, "placeholder", "AA==", "");
        // Strip the transform the fixture writes, leaving a bare reference.
        let bare = skeleton
            .replace(
                "\n                    <ds:Transforms>\
                 \n                        <ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\
                 \n                    </ds:Transforms>",
                "",
            );
        assert!(!bare.contains("ds:Transforms"), "the fixture must be bare");

        let inclusive = canonicalize_reference(
            &bare,
            "#payload-1",
            WsSecCanonicalizationProfile {
                kind: WsSecCanonicalizationKind::Inclusive,
                include_comments: false,
                inclusive_ns_prefixes: Vec::new(),
            },
        )
        .expect("inclusive digest")
        .digest_value_base64;

        let exclusive =
            canonicalize_reference(&bare, "#payload-1", WsSecCanonicalizationProfile::default())
                .expect("exclusive digest")
                .digest_value_base64;

        assert_ne!(
            inclusive, exclusive,
            "the fixture must be one where the two algorithms disagree, or it \
             proves nothing"
        );

        // What the reference parser resolves the bare reference to is what
        // decides which of the two digests the verifier will compute.
        let references = parse_signature_references(&bare).expect("references parse");
        let reference = references
            .iter()
            .find(|r| r.uri == "#payload-1")
            .expect("the reference is present");
        assert_eq!(
            reference.c14n_kind,
            WsSecCanonicalizationKind::Inclusive,
            "a transform-less same-document reference defaults to inclusive C14N"
        );
    }

    #[test]
    fn parser_rejects_missing_references() {
        let xml = "<Envelope xmlns=\"urn:example\"></Envelope>";
        let err = parse_signature_references(xml).expect_err("missing refs should fail");
        assert_eq!(err.code, crate::core::ErrorCode::ParseFailed);
    }

    #[test]
    fn parser_accepts_digest_value_with_padding_whitespace() {
        let xml = r##"
<d:Envelope xmlns:d="urn:example" xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
  <ds:Signature>
    <ds:SignedInfo>
        <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
      <ds:Reference URI="#x">
        <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
        <ds:DigestValue>
          abcd==
        </ds:DigestValue>
      </ds:Reference>
    </ds:SignedInfo>
    <ds:SignatureValue>stub-signature</ds:SignatureValue>
  </ds:Signature>
</d:Envelope>
"##;

        let refs = parse_signature_references(xml).expect("reference parse should pass");
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].digest_value_base64, "abcd==");
    }

    #[test]
    fn parser_rejects_missing_signature_value() {
        let xml = r##"
<d:Envelope xmlns:d="urn:example" xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
  <ds:Signature>
    <ds:SignedInfo>
        <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
      <ds:Reference URI="#x">
        <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
        <ds:DigestValue>abcd==</ds:DigestValue>
      </ds:Reference>
    </ds:SignedInfo>
  </ds:Signature>
</d:Envelope>
"##;

        let err = parse_signature_references(xml).expect_err("missing signature value should fail");
        assert_eq!(err.code, crate::core::ErrorCode::SecurityVerificationFailed);
    }

    #[test]
    fn parser_rejects_duplicate_reference_uris() {
        let xml = r##"
<d:Envelope xmlns:d="urn:example" xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
    <ds:Signature>
        <ds:SignedInfo>
            <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
            <ds:Reference URI="#x">
                <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                <ds:DigestValue>abcd==</ds:DigestValue>
            </ds:Reference>
            <ds:Reference URI="#x">
                <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                <ds:DigestValue>abcd==</ds:DigestValue>
            </ds:Reference>
        </ds:SignedInfo>
        <ds:SignatureValue>stub-signature</ds:SignatureValue>
    </ds:Signature>
</d:Envelope>
"##;

        let err = parse_signature_references(xml).expect_err("duplicate references should fail");
        assert_eq!(err.code, crate::core::ErrorCode::InteropViolation);
    }

    #[test]
    fn parser_rejects_transforms_in_reference() {
        let xml = r##"
<d:Envelope xmlns:d="urn:example" xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
    <ds:Signature>
        <ds:SignedInfo>
            <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
            <ds:Reference URI="#x">
                <ds:Transforms>
                    <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
                </ds:Transforms>
                <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                <ds:DigestValue>abcd==</ds:DigestValue>
            </ds:Reference>
        </ds:SignedInfo>
        <ds:SignatureValue>stub-signature</ds:SignatureValue>
    </ds:Signature>
</d:Envelope>
"##;

        let err = parse_signature_references(xml).expect_err("transforms should fail");
        assert_eq!(err.code, crate::core::ErrorCode::InteropViolation);
    }

    #[test]
    fn verify_enveloped_signature_strict_accepts_valid_rsa_signature_value() {
        let (test_pkey, modulus_base64, exponent_base64, cert_base64) =
            make_test_rsa_key_and_cert();

        let payload = "    <eb:Payload wsu:Id=\"payload-1\">ABC</eb:Payload>";
        let unsigned = signed_xml_with_rsa_keyvalue_and_x509(
            "#payload-1",
            payload,
            "placeholder",
            "AA==",
            &modulus_base64,
            &exponent_base64,
            &cert_base64,
        );

        let digest = canonicalize_reference(
            &unsigned,
            "#payload-1",
            WsSecCanonicalizationProfile::default(),
        )
        .expect("digest")
        .digest_value_base64;

        let material = parse_signature_material(
            &signed_xml_with_rsa_keyvalue_and_x509(
                "#payload-1",
                payload,
                &digest,
                "AA==",
                &modulus_base64,
                &exponent_base64,
                &cert_base64,
            ),
            WsSecCanonicalizationProfile::default(),
        )
        .expect("signature material");

        let mut signer = Signer::new(MessageDigest::sha256(), &test_pkey).expect("signer");
        signer
            .update(&material.signed_info_c14n)
            .expect("signer update");
        let signature_bytes = signer.sign_to_vec().expect("sign");
        let signature_base64 = BASE64_STANDARD.encode(&signature_bytes);

        let signed = signed_xml_with_rsa_keyvalue_and_x509(
            "#payload-1",
            payload,
            &digest,
            &signature_base64,
            &modulus_base64,
            &exponent_base64,
            &cert_base64,
        );

        verify_enveloped_signature(&signed, WsSecVerifyOptions::new())
            .expect("strict verification");
    }

    #[test]
    fn verify_enveloped_signature_accepts_x509data_without_rsa_keyvalue() {
        let rsa = openssl::rsa::Rsa::generate(2048).expect("rsa");
        let pkey = PKey::from_rsa(rsa).expect("pkey");

        let mut name = openssl::x509::X509NameBuilder::new().expect("name builder");
        name.append_entry_by_nid(openssl::nid::Nid::COMMONNAME, "asx-wssec-test")
            .expect("cn");
        let name = name.build();

        let mut serial = openssl::bn::BigNum::new().expect("serial");
        serial
            .pseudo_rand(64, openssl::bn::MsbOption::MAYBE_ZERO, false)
            .expect("serial rand");
        let serial = serial.to_asn1_integer().expect("serial asn1");

        let mut cert_builder = X509::builder().expect("x509 builder");
        cert_builder.set_version(2).expect("version");
        cert_builder.set_serial_number(&serial).expect("serial");
        cert_builder.set_subject_name(&name).expect("subject");
        cert_builder.set_issuer_name(&name).expect("issuer");
        cert_builder.set_pubkey(&pkey).expect("pubkey");
        let not_before = Asn1Time::days_from_now(0).expect("not_before");
        let not_after = Asn1Time::days_from_now(365).expect("not_after");
        cert_builder.set_not_before(&not_before).expect("nb");
        cert_builder.set_not_after(&not_after).expect("na");
        cert_builder
            .sign(&pkey, MessageDigest::sha256())
            .expect("cert sign");
        let cert = cert_builder.build();
        let cert_der_b64 = BASE64_STANDARD.encode(cert.to_der().expect("cert der"));

        let payload = "    <eb:Payload wsu:Id=\"payload-1\">ABC</eb:Payload>";
        let unsigned =
            signed_xml_with_x509_only("#payload-1", payload, "placeholder", "AA==", &cert_der_b64);

        let digest = canonicalize_reference(
            &unsigned,
            "#payload-1",
            WsSecCanonicalizationProfile::default(),
        )
        .expect("digest")
        .digest_value_base64;

        let material = parse_signature_material(
            &signed_xml_with_x509_only("#payload-1", payload, &digest, "AA==", &cert_der_b64),
            WsSecCanonicalizationProfile::default(),
        )
        .expect("signature material");

        let mut signer =
            openssl::sign::Signer::new(MessageDigest::sha256(), &pkey).expect("signer");
        signer
            .update(&material.signed_info_c14n)
            .expect("signer update");
        let signature = signer.sign_to_vec().expect("signature");
        let signature_base64 = BASE64_STANDARD.encode(signature);

        let signed = signed_xml_with_x509_only(
            "#payload-1",
            payload,
            &digest,
            &signature_base64,
            &cert_der_b64,
        );

        verify_enveloped_signature(
            &signed,
            WsSecVerifyOptions::new().with_expected_fingerprints(&[]),
        )
        .expect("verification should pass");
    }

    #[test]
    fn verify_enveloped_signature_rejects_tampered_external_reference_bytes() {
        let (test_pkey, modulus_base64, exponent_base64, cert_base64) =
            make_test_rsa_key_and_cert();

        let payload = b"payload-attachment";
        let payload_digest = openssl::hash::hash(MessageDigest::sha256(), payload).expect("digest");
        let payload_digest_b64 = BASE64_STANDARD.encode(payload_digest);

        let unsigned = signed_xml_with_rsa_keyvalue_and_x509(
            "cid:payload-1@example.com",
            "    <eb:Payload>Attachment</eb:Payload>",
            &payload_digest_b64,
            "AA==",
            &modulus_base64,
            &exponent_base64,
            &cert_base64,
        );

        let material = parse_signature_material(&unsigned, WsSecCanonicalizationProfile::default())
            .expect("signature material");

        let mut signer = Signer::new(MessageDigest::sha256(), &test_pkey).expect("signer");
        signer
            .update(&material.signed_info_c14n)
            .expect("signer update");
        let signature_base64 = BASE64_STANDARD.encode(signer.sign_to_vec().expect("sign"));

        let signed = signed_xml_with_rsa_keyvalue_and_x509(
            "cid:payload-1@example.com",
            "    <eb:Payload>Attachment</eb:Payload>",
            &payload_digest_b64,
            &signature_base64,
            &modulus_base64,
            &exponent_base64,
            &cert_base64,
        );

        let good_refs: [(&str, &[u8]); 1] = [("cid:payload-1@example.com", payload.as_slice())];
        verify_enveloped_signature(
            &signed,
            WsSecVerifyOptions::new().with_external_references(&good_refs),
        )
        .expect("valid external reference bytes should pass");

        let bad_refs: [(&str, &[u8]); 1] = [("cid:payload-1@example.com", b"payload-tampered")];
        let err = verify_enveloped_signature(
            &signed,
            WsSecVerifyOptions::new().with_external_references(&bad_refs),
        )
        .expect_err("tampered external reference bytes must fail");

        assert_eq!(err.code, crate::core::ErrorCode::SecurityVerificationFailed);
        assert!(
            err.message
                .contains("digest mismatch for reference cid:payload-1@example.com")
        );
    }

    /// A signature that verifies against a key the message itself supplied
    /// proves nothing: an attacker can generate a key pair, sign the envelope,
    /// and inline the public half. Verification must demand an X.509 signer
    /// token regardless of what the caller's policy asks for.
    #[test]
    fn bare_rsa_keyvalue_without_a_certificate_is_rejected() {
        let (test_pkey, modulus_base64, exponent_base64) = make_test_rsa_key();

        let payload = "    <eb:Payload wsu:Id=\"payload-1\">ABC</eb:Payload>";
        let unsigned = signed_xml_with_rsa_keyvalue(
            "#payload-1",
            payload,
            "placeholder",
            "AA==",
            &modulus_base64,
            &exponent_base64,
        );
        let digest = canonicalize_reference(
            &unsigned,
            "#payload-1",
            WsSecCanonicalizationProfile::default(),
        )
        .expect("digest")
        .digest_value_base64;

        let material = parse_signature_material(
            &signed_xml_with_rsa_keyvalue(
                "#payload-1",
                payload,
                &digest,
                "AA==",
                &modulus_base64,
                &exponent_base64,
            ),
            WsSecCanonicalizationProfile::default(),
        )
        .expect("signature material");
        let signature_base64 = rsa_sha256_sign(&test_pkey, &material.signed_info_c14n);

        // Cryptographically this signature is perfectly valid over SignedInfo.
        let signed = signed_xml_with_rsa_keyvalue(
            "#payload-1",
            payload,
            &digest,
            &signature_base64,
            &modulus_base64,
            &exponent_base64,
        );

        let err = verify_enveloped_signature(&signed, WsSecVerifyOptions::new())
            .expect_err("a self-asserted RSAKeyValue must never satisfy verification");
        assert_eq!(err.code, crate::core::ErrorCode::SecurityVerificationFailed);
        assert!(
            err.message.contains("no X.509 certificate"),
            "error must name the cause: {}",
            err.message
        );
    }

    #[test]
    fn verify_enveloped_signature_strict_rejects_tampered_signature_value() {
        let (pkey, modulus_base64, exponent_base64) = make_test_rsa_key();

        let payload = "    <eb:Payload wsu:Id=\"payload-1\">ABC</eb:Payload>";
        let unsigned = signed_xml_with_rsa_keyvalue(
            "#payload-1",
            payload,
            "placeholder",
            "AA==",
            &modulus_base64,
            &exponent_base64,
        );

        let digest = canonicalize_reference(
            &unsigned,
            "#payload-1",
            WsSecCanonicalizationProfile::default(),
        )
        .expect("digest")
        .digest_value_base64;

        let material = parse_signature_material(
            &signed_xml_with_rsa_keyvalue(
                "#payload-1",
                payload,
                &digest,
                "AA==",
                &modulus_base64,
                &exponent_base64,
            ),
            WsSecCanonicalizationProfile::default(),
        )
        .expect("signature material");

        let mut signature = BASE64_STANDARD
            .decode(rsa_sha256_sign(&pkey, &material.signed_info_c14n))
            .expect("decode sig");
        signature[0] ^= 0x01;
        let signature_base64 = BASE64_STANDARD.encode(signature);

        let signed = signed_xml_with_rsa_keyvalue(
            "#payload-1",
            payload,
            &digest,
            &signature_base64,
            &modulus_base64,
            &exponent_base64,
        );

        let err = verify_enveloped_signature(&signed, WsSecVerifyOptions::new())
            .expect_err("tampered signature should fail");
        assert_eq!(err.code, crate::core::ErrorCode::SecurityVerificationFailed);
    }

    #[test]
    fn trust_binding_requires_x509_certificate_when_fingerprint_is_configured() {
        let (pkey, modulus_base64, exponent_base64) = make_test_rsa_key();

        let payload = "    <eb:Payload wsu:Id=\"payload-1\">ABC</eb:Payload>";
        let unsigned = signed_xml_with_rsa_keyvalue(
            "#payload-1",
            payload,
            "placeholder",
            "AA==",
            &modulus_base64,
            &exponent_base64,
        );

        let digest = canonicalize_reference(
            &unsigned,
            "#payload-1",
            WsSecCanonicalizationProfile::default(),
        )
        .expect("digest")
        .digest_value_base64;

        let material = parse_signature_material(
            &signed_xml_with_rsa_keyvalue(
                "#payload-1",
                payload,
                &digest,
                "AA==",
                &modulus_base64,
                &exponent_base64,
            ),
            WsSecCanonicalizationProfile::default(),
        )
        .expect("signature material");

        let signature_base64 = rsa_sha256_sign(&pkey, &material.signed_info_c14n);

        let signed = signed_xml_with_rsa_keyvalue(
            "#payload-1",
            payload,
            &digest,
            &signature_base64,
            &modulus_base64,
            &exponent_base64,
        );

        let err = verify_enveloped_signature(
            &signed,
            WsSecVerifyOptions::new().with_expected_fingerprints(std::slice::from_ref(
                // Any well-formed pin: the point is that a message with no
                // X.509 certificate cannot satisfy one.
                &crate::crypto::CertFingerprint::parse(&"ab".repeat(32)).unwrap(),
            )),
        )
        .expect_err("missing x509 certificate should fail trust binding");
        assert_eq!(err.code, crate::core::ErrorCode::SecurityVerificationFailed);
    }

    #[test]
    fn malformed_x509_certificate_is_rejected() {
        let (pkey, modulus_base64, exponent_base64) = make_test_rsa_key();

        let payload = "    <eb:Payload wsu:Id=\"payload-1\">ABC</eb:Payload>";
        let unsigned = signed_xml_with_rsa_keyvalue_and_x509(
            "#payload-1",
            payload,
            "placeholder",
            "AA==",
            &modulus_base64,
            &exponent_base64,
            "AQID",
        );

        let digest = canonicalize_reference(
            &unsigned,
            "#payload-1",
            WsSecCanonicalizationProfile::default(),
        )
        .expect("digest")
        .digest_value_base64;

        let material = parse_signature_material(
            &signed_xml_with_rsa_keyvalue_and_x509(
                "#payload-1",
                payload,
                &digest,
                "AA==",
                &modulus_base64,
                &exponent_base64,
                "AQID",
            ),
            WsSecCanonicalizationProfile::default(),
        )
        .expect("signature material");

        let signature_base64 = rsa_sha256_sign(&pkey, &material.signed_info_c14n);

        let signed = signed_xml_with_rsa_keyvalue_and_x509(
            "#payload-1",
            payload,
            &digest,
            &signature_base64,
            &modulus_base64,
            &exponent_base64,
            "AQID",
        );

        let err = verify_enveloped_signature(
            &signed,
            WsSecVerifyOptions::new().with_expected_fingerprints(&[]),
        )
        .expect_err("malformed x509 certificate must fail");
        assert_eq!(err.code, crate::core::ErrorCode::SecurityVerificationFailed);
    }

    #[test]
    fn mismatched_x509_and_keyvalue_are_rejected() {
        let (pkey, modulus_base64, exponent_base64) = make_test_rsa_key();

        let payload = "    <eb:Payload wsu:Id=\"payload-1\">ABC</eb:Payload>";
        let unsigned = signed_xml_with_rsa_keyvalue_and_x509(
            "#payload-1",
            payload,
            "placeholder",
            "AA==",
            &modulus_base64,
            &exponent_base64,
            TEST_CA_CERT_B64,
        );

        let digest = canonicalize_reference(
            &unsigned,
            "#payload-1",
            WsSecCanonicalizationProfile::default(),
        )
        .expect("digest")
        .digest_value_base64;

        let material = parse_signature_material(
            &signed_xml_with_rsa_keyvalue_and_x509(
                "#payload-1",
                payload,
                &digest,
                "AA==",
                &modulus_base64,
                &exponent_base64,
                TEST_CA_CERT_B64,
            ),
            WsSecCanonicalizationProfile::default(),
        )
        .expect("signature material");

        let signature_base64 = rsa_sha256_sign(&pkey, &material.signed_info_c14n);

        let signed = signed_xml_with_rsa_keyvalue_and_x509(
            "#payload-1",
            payload,
            &digest,
            &signature_base64,
            &modulus_base64,
            &exponent_base64,
            TEST_CA_CERT_B64,
        );

        let err = verify_enveloped_signature(
            &signed,
            WsSecVerifyOptions::new().with_expected_fingerprints(&[]),
        )
        .expect_err("key mismatch must fail");
        assert_eq!(err.code, crate::core::ErrorCode::SecurityVerificationFailed);
    }

    #[test]
    fn ca_certificate_is_rejected_for_message_signing() {
        let cert_der = BASE64_STANDARD
            .decode(TEST_CA_CERT_B64)
            .expect("decode test certificate");

        let err = validate_x509_certificate(&cert_der)
            .expect_err("CA certificate must be rejected for end-entity signing");
        assert_eq!(err.code, crate::core::ErrorCode::SecurityVerificationFailed);
    }

    #[test]
    fn signer_policy_rejects_cert_without_compatible_eku() {
        let (pkey, modulus_base64, exponent_base64) = make_test_rsa_key();

        let payload = "    <eb:Payload wsu:Id=\"payload-1\">ABC</eb:Payload>";
        let unsigned = signed_xml_with_rsa_keyvalue_and_x509(
            "#payload-1",
            payload,
            "placeholder",
            "AA==",
            &modulus_base64,
            &exponent_base64,
            TEST_CA_CERT_B64,
        );

        let digest = canonicalize_reference(
            &unsigned,
            "#payload-1",
            WsSecCanonicalizationProfile::default(),
        )
        .expect("digest")
        .digest_value_base64;

        let material = parse_signature_material(
            &signed_xml_with_rsa_keyvalue_and_x509(
                "#payload-1",
                payload,
                &digest,
                "AA==",
                &modulus_base64,
                &exponent_base64,
                TEST_CA_CERT_B64,
            ),
            WsSecCanonicalizationProfile::default(),
        )
        .expect("signature material");

        let signature_base64 = rsa_sha256_sign(&pkey, &material.signed_info_c14n);

        let signed = signed_xml_with_rsa_keyvalue_and_x509(
            "#payload-1",
            payload,
            &digest,
            &signature_base64,
            &modulus_base64,
            &exponent_base64,
            TEST_CA_CERT_B64,
        );

        let err = verify_enveloped_signature(
            &signed,
            WsSecVerifyOptions::new().with_expected_fingerprints(&[]),
        )
        .expect_err("certificate with incompatible EKU must fail signer policy");
        assert_eq!(err.code, crate::core::ErrorCode::SecurityVerificationFailed);
    }

    // -----------------------------------------------------------------------
    // W3C Exclusive XML Canonicalization 1.0 test vectors
    // -----------------------------------------------------------------------

    fn c14n_element(envelope: &str, id: &str) -> String {
        let result = canonicalize_reference(
            envelope,
            id,
            WsSecCanonicalizationProfile {
                kind: WsSecCanonicalizationKind::Exclusive,
                include_comments: false,
                inclusive_ns_prefixes: Vec::new(),
            },
        )
        .expect("canonicalize_reference");
        String::from_utf8(result.canonical_bytes).expect("valid UTF-8")
    }

    #[test]
    fn w3c_exc_c14n_simple_namespace_propagation() {
        let envelope = r#"<root xmlns:n1="http://www.w3.org">
  <elem wsu:Id="e1"
        xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"
        xmlns:n1="http://www.w3.org"
        n1:attr="v">text</elem>
</root>"#;

        let c14n = c14n_element(envelope, "#e1");
        assert!(
            c14n.contains(r#"xmlns:n1="http://www.w3.org""#),
            "n1 ns missing: {c14n}"
        );
        assert!(c14n.contains(r#"n1:attr="v""#), "attr missing: {c14n}");
        assert!(c14n.contains("text"), "text missing: {c14n}");
    }

    #[test]
    fn w3c_exc_c14n_attribute_ordering() {
        let envelope = r#"<r xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"
      xmlns:ns="urn:test">
  <e wsu:Id="e1" ns:z="last" ns:a="first" plain="plain"/>
</r>"#;

        let c14n = c14n_element(envelope, "#e1");
        let a_pos = c14n.find(r#"ns:a="first""#).expect("ns:a missing");
        let z_pos = c14n.find(r#"ns:z="last""#).expect("ns:z missing");
        assert!(
            a_pos < z_pos,
            "ns:a must precede ns:z in C14N output:\n{c14n}"
        );
    }

    #[test]
    fn w3c_c14n_text_and_attr_escaping() {
        let envelope = r#"<r xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
  <e wsu:Id="e1" a="&quot;&amp;&#x9;&#xA;&#xD;">text &lt;&amp;&gt;</e>
</r>"#;

        let c14n = c14n_element(envelope, "#e1");
        assert!(
            c14n.contains(r#"&quot;&amp;&#x9;&#xA;&#xD;"#),
            "attr escaping wrong: {c14n}"
        );
        assert!(
            c14n.contains("text &lt;&amp;&gt;"),
            "text escaping wrong: {c14n}"
        );
    }

    #[test]
    fn c14n_preserves_processing_instructions() {
        let envelope = r#"<r xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
  <e wsu:Id="e1"><?xml-stylesheet type="text/xsl" href="style.xsl"?>body</e>
</r>"#;

        let c14n = c14n_element(envelope, "#e1");
        assert!(
            c14n.contains(r#"<?xml-stylesheet type="text/xsl" href="style.xsl"?>"#),
            "PI missing from C14N output: {c14n}"
        );
    }

    #[test]
    fn c14n_strips_comments_by_default() {
        let envelope = r#"<r xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
  <e wsu:Id="e1"><!-- secret -->visible</e>
</r>"#;

        let c14n = c14n_element(envelope, "#e1");
        assert!(!c14n.contains("secret"), "comment not stripped: {c14n}");
        assert!(c14n.contains("visible"), "text missing: {c14n}");
    }

    #[test]
    fn c14n_preserves_comments_when_requested() {
        let envelope = r#"<r xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
  <e wsu:Id="e1"><!-- keep-me -->text</e>
</r>"#;

        let result = canonicalize_reference(
            envelope,
            "#e1",
            WsSecCanonicalizationProfile {
                kind: WsSecCanonicalizationKind::Exclusive,
                include_comments: true,
                inclusive_ns_prefixes: Vec::new(),
            },
        )
        .expect("canonicalize");
        let c14n = String::from_utf8(result.canonical_bytes).unwrap();
        assert!(c14n.contains("<!-- keep-me -->"), "comment missing: {c14n}");
    }

    #[test]
    fn c14n_inclusive_ns_prefixes_renders_ancestor_binding() {
        let envelope = r#"<root xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"
    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <bar wsu:Id="e1"/>
</root>"#;

        let result = canonicalize_reference(
            envelope,
            "#e1",
            WsSecCanonicalizationProfile {
                kind: WsSecCanonicalizationKind::Exclusive,
                include_comments: false,
                inclusive_ns_prefixes: vec!["xsi".to_string()],
            },
        )
        .expect("canonicalize");
        let c14n = String::from_utf8(result.canonical_bytes).unwrap();
        assert!(
            c14n.contains(r#"xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance""#),
            "xsi declaration missing from inclusive-prefix output:\n{c14n}"
        );
    }

    #[test]
    fn c14n_inclusive_ns_prefix_not_in_scope_is_not_emitted() {
        let envelope = r#"<root xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
  <bar wsu:Id="e1"/>
</root>"#;

        let result = canonicalize_reference(
            envelope,
            "#e1",
            WsSecCanonicalizationProfile {
                kind: WsSecCanonicalizationKind::Exclusive,
                include_comments: false,
                inclusive_ns_prefixes: vec!["xsi".to_string()],
            },
        )
        .expect("canonicalize");
        let c14n = String::from_utf8(result.canonical_bytes).unwrap();
        assert!(
            !c14n.contains("xmlns:xsi"),
            "xsi declaration must not appear when prefix is not in scope:\n{c14n}"
        );
    }
}
