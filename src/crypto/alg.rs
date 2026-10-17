//! The algorithm registry: the **only** table in the crate that maps an
//! algorithm identifier (URI) to the algorithm it names, for every role the
//! XML-security layer emits or accepts.
//!
//! A declared identifier *is* the description of the bytes: the URI a peer
//! reads in `ds:SignatureMethod`, `ds:DigestMethod`, `xenc:EncryptionMethod`
//! or `dsig11:NamedCurve` must be the one that produced them. With one row
//! table, emit and accept cannot disagree, and per-algorithm behaviour (digest
//! length, key family, curve width, key length) is an exhaustive `match` on a
//! closed enum, so a new variant is a compile error everywhere it matters.
//!
//! # Adding an algorithm
//!
//! One enum variant, one [`REGISTRY`] row, and the exhaustive `match`es the
//! compiler then lists. For example, the eDelivery 2.0 algorithms would take:
//!
//! | Role | Variant | URI |
//! |---|---|---|
//! | `Signature` | `SignatureAlgorithm::Ed25519` (`key_family = Ed25519`, `to_wire` identity) | `http://www.w3.org/2021/04/xmldsig-more#eddsa-ed25519` |
//! | `KeyAgreement` | `AgreementAlg::X25519` (+ `KeyOp::X25519`) | `http://www.w3.org/2021/04/xmldsig-more#x25519` |
//! | `Kdf` | `KdfAlg::Hkdf` (+ `HKDFParams` in `xmlenc/parse.rs`) | `http://www.w3.org/2021/04/xmldsig-more#hkdf` |
//!
//! The registry tests fail when a variant has no row or a `(role, URI)` pair
//! has two. Identifiers with no row (SHA-1, `WithComments` C14N, `rsa-1_5`,
//! `rsa-oaep-mgf1p`, CBC ciphers, `mgf1sha1`, PBKDF2, …) are rejected by name.

// The XML-security consumers are `as4`-only; `as2` uses the signature role.
#![cfg_attr(not(feature = "as4"), allow(dead_code, unreachable_pub))]

pub(crate) mod ecdsa;

use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::x509::X509Ref;
use serde::{Deserialize, Serialize};

use crate::core::{AsxError, ErrorCode, ErrorContext, Result};

// ── URIs (the registry rows reference these; nothing else may) ─────────────

const SHA256: &str = "http://www.w3.org/2001/04/xmlenc#sha256";
const SHA384: &str = "http://www.w3.org/2001/04/xmldsig-more#sha384";
const SHA512: &str = "http://www.w3.org/2001/04/xmlenc#sha512";
const RSA_SHA256: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
const RSA_SHA384: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384";
const RSA_SHA512: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512";
const ECDSA_SHA256: &str = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256";
const ECDSA_SHA384: &str = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384";
const ECDSA_SHA512: &str = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512";
const EXC_C14N: &str = "http://www.w3.org/2001/10/xml-exc-c14n#";
const INC_C14N: &str = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";
const SWA_ATTACHMENT_CONTENT: &str = "http://docs.oasis-open.org/wss/oasis-wss-SwAProfile-1.1#Attachment-Content-Signature-Transform";
/// XMLDSig enveloped-signature transform (re-exported publicly as
/// `crypto::wssec::ENVELOPED_SIGNATURE_URI`).
pub(crate) const ENVELOPED_SIGNATURE: &str =
    "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
const RSA_OAEP: &str = "http://www.w3.org/2009/xmlenc11#rsa-oaep";
const ECDH_ES: &str = "http://www.w3.org/2009/xmlenc11#ECDH-ES";
const CONCAT_KDF: &str = "http://www.w3.org/2009/xmlenc11#ConcatKDF";
const KW_AES128: &str = "http://www.w3.org/2001/04/xmlenc#kw-aes128";
const KW_AES192: &str = "http://www.w3.org/2001/04/xmlenc#kw-aes192";
const KW_AES256: &str = "http://www.w3.org/2001/04/xmlenc#kw-aes256";
const AES128_GCM: &str = "http://www.w3.org/2009/xmlenc11#aes128-gcm";
const AES256_GCM: &str = "http://www.w3.org/2009/xmlenc11#aes256-gcm";
const MGF1_SHA256: &str = "http://www.w3.org/2009/xmlenc11#mgf1sha256";
const CURVE_P256: &str = "urn:oid:1.2.840.10045.3.1.7";
const CURVE_P384: &str = "urn:oid:1.3.132.0.34";
const CURVE_P521: &str = "urn:oid:1.3.132.0.35";
const CURVE_BP256R1: &str = "urn:oid:1.3.36.3.3.2.8.1.1.7";
const CURVE_BP384R1: &str = "urn:oid:1.3.36.3.3.2.8.1.1.11";
const CURVE_BP512R1: &str = "urn:oid:1.3.36.3.3.2.8.1.1.13";

// ── Public role enums (existing public types, re-exported at their paths) ──

/// Signature algorithm for outbound XMLDSig / WS-Security operations.
///
/// The variants mirror the W3C XML Signature / IETF RFC 9231 algorithm URIs.
/// The library supports RSA-PKCS1-v1.5 and ECDSA; RSA-PSS is not wired because
/// it is absent from the normative AS4 profiles.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SignatureAlgorithm {
    /// RSA with SHA-256 — the PEPPOL AS4 / CEF eDelivery baseline.
    RsaSha256,
    /// RSA with SHA-384 — available for higher-assurance configurations.
    RsaSha384,
    /// RSA with SHA-512 — available for higher-assurance configurations.
    RsaSha512,
    /// ECDSA with SHA-256 — BDEW (brainpoolP256r1) and newer PEPPOL Access Points.
    EcdsaSha256,
    /// ECDSA with SHA-384.
    EcdsaSha384,
    /// ECDSA with SHA-512.
    EcdsaSha512,
}

/// Digest algorithm of a `ds:Reference` (`ds:DigestMethod`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum WsSecDigestMethod {
    Sha256,
    /// SHA-384 reference digest — rare but accepted by some regulated-sector
    /// gateways (e.g. BDEW, financial-sector AS4 variants).  Not required by
    /// PEPPOL or CEF eDelivery; supported for broad inbound interoperability.
    Sha384,
    /// SHA-512 reference digest — uncommon but present in some IBM DataPower
    /// and Axway configurations.  Supported for inbound decryption/verification.
    Sha512,
}

/// XML canonicalization algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[non_exhaustive]
pub enum WsSecCanonicalizationKind {
    /// W3C Exclusive XML Canonicalization (Exc-C14N, RFC 3741).
    /// Only visibly-utilized namespace declarations are rendered.
    /// Required by WS-Security 1.0 and all modern AS4 profiles.
    #[default]
    Exclusive,
    /// W3C Canonical XML 1.0 (Inclusive C14N).
    /// ALL in-scope namespace declarations are rendered, regardless of
    /// whether they are visibly utilized at the element.  Used by some
    /// legacy AS4 gateways (IBM DataPower ≤ v7.5, SAP PI/PO ≤ 7.31).
    Inclusive,
}

/// XML Encryption content cipher (`xenc:EncryptedData/xenc:EncryptionMethod`).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Default)]
#[non_exhaustive]
pub enum XmlEncPayloadAlgorithm {
    /// eDelivery AS4 v1.15 Common Profile default.
    #[default]
    Aes128Gcm,
    /// Stronger key size, but not eDelivery v1.15 Common Profile default.
    Aes256Gcm,
}

// ── Crate-private role enums ────────────────────────────────────────────────

/// What an identifier is used for. A URI is looked up *for a role*: the same
/// string may legitimately name a C14N method and a transform.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Role {
    Digest,
    Signature,
    C14n,
    Transform,
    KeyTransport,
    KeyAgreement,
    Kdf,
    KeyWrap,
    ContentCipher,
    Mgf,
    Curve,
}

impl Role {
    fn label(self) -> &'static str {
        match self {
            Self::Digest => "digest",
            Self::Signature => "signature",
            Self::C14n => "canonicalization",
            Self::Transform => "transform",
            Self::KeyTransport => "key transport",
            Self::KeyAgreement => "key agreement",
            Self::Kdf => "key derivation",
            Self::KeyWrap => "key wrap",
            Self::ContentCipher => "content encryption",
            Self::Mgf => "mask generation function",
            Self::Curve => "named curve",
        }
    }
}

/// A `ds:Reference` transform.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TransformAlg {
    C14n(WsSecCanonicalizationKind),
    /// WSS SwA 1.1 `Attachment-Content-Signature-Transform`.
    AttachmentContent,
    /// XMLDSig `enveloped-signature`.
    EnvelopedSignature,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum KeyTransportAlg {
    RsaOaep,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AgreementAlg {
    EcdhEs,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum KdfAlg {
    ConcatKdf,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum KeyWrapAlg {
    Aes128,
    Aes192,
    Aes256,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MgfAlg {
    Mgf1Sha256,
}

/// Named elliptic curves (`dsig11:NamedCurve/@URI`, RFC 5480 OIDs).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NamedCurve {
    P256,
    P384,
    P521,
    BrainpoolP256r1,
    BrainpoolP384r1,
    BrainpoolP512r1,
}

/// The public-key family a signature method requires.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum KeyFamily {
    Rsa,
    Ec,
}

/// One algorithm of one role.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Alg {
    Digest(WsSecDigestMethod),
    Signature(SignatureAlgorithm),
    C14n(WsSecCanonicalizationKind),
    Transform(TransformAlg),
    KeyTransport(KeyTransportAlg),
    KeyAgreement(AgreementAlg),
    Kdf(KdfAlg),
    KeyWrap(KeyWrapAlg),
    ContentCipher(XmlEncPayloadAlgorithm),
    Mgf(MgfAlg),
    Curve(NamedCurve),
}

/// The registry: `(role, URI, algorithm)`. The only URI table in `src/`.
pub(crate) static REGISTRY: &[(Role, &str, Alg)] = &[
    (Role::Digest, SHA256, Alg::Digest(WsSecDigestMethod::Sha256)),
    (Role::Digest, SHA384, Alg::Digest(WsSecDigestMethod::Sha384)),
    (Role::Digest, SHA512, Alg::Digest(WsSecDigestMethod::Sha512)),
    (
        Role::Signature,
        RSA_SHA256,
        Alg::Signature(SignatureAlgorithm::RsaSha256),
    ),
    (
        Role::Signature,
        RSA_SHA384,
        Alg::Signature(SignatureAlgorithm::RsaSha384),
    ),
    (
        Role::Signature,
        RSA_SHA512,
        Alg::Signature(SignatureAlgorithm::RsaSha512),
    ),
    (
        Role::Signature,
        ECDSA_SHA256,
        Alg::Signature(SignatureAlgorithm::EcdsaSha256),
    ),
    (
        Role::Signature,
        ECDSA_SHA384,
        Alg::Signature(SignatureAlgorithm::EcdsaSha384),
    ),
    (
        Role::Signature,
        ECDSA_SHA512,
        Alg::Signature(SignatureAlgorithm::EcdsaSha512),
    ),
    (
        Role::C14n,
        EXC_C14N,
        Alg::C14n(WsSecCanonicalizationKind::Exclusive),
    ),
    (
        Role::C14n,
        INC_C14N,
        Alg::C14n(WsSecCanonicalizationKind::Inclusive),
    ),
    (
        Role::Transform,
        EXC_C14N,
        Alg::Transform(TransformAlg::C14n(WsSecCanonicalizationKind::Exclusive)),
    ),
    (
        Role::Transform,
        INC_C14N,
        Alg::Transform(TransformAlg::C14n(WsSecCanonicalizationKind::Inclusive)),
    ),
    (
        Role::Transform,
        SWA_ATTACHMENT_CONTENT,
        Alg::Transform(TransformAlg::AttachmentContent),
    ),
    (
        Role::Transform,
        ENVELOPED_SIGNATURE,
        Alg::Transform(TransformAlg::EnvelopedSignature),
    ),
    (
        Role::KeyTransport,
        RSA_OAEP,
        Alg::KeyTransport(KeyTransportAlg::RsaOaep),
    ),
    (
        Role::KeyAgreement,
        ECDH_ES,
        Alg::KeyAgreement(AgreementAlg::EcdhEs),
    ),
    (Role::Kdf, CONCAT_KDF, Alg::Kdf(KdfAlg::ConcatKdf)),
    (Role::KeyWrap, KW_AES128, Alg::KeyWrap(KeyWrapAlg::Aes128)),
    (Role::KeyWrap, KW_AES192, Alg::KeyWrap(KeyWrapAlg::Aes192)),
    (Role::KeyWrap, KW_AES256, Alg::KeyWrap(KeyWrapAlg::Aes256)),
    (
        Role::ContentCipher,
        AES128_GCM,
        Alg::ContentCipher(XmlEncPayloadAlgorithm::Aes128Gcm),
    ),
    (
        Role::ContentCipher,
        AES256_GCM,
        Alg::ContentCipher(XmlEncPayloadAlgorithm::Aes256Gcm),
    ),
    (Role::Mgf, MGF1_SHA256, Alg::Mgf(MgfAlg::Mgf1Sha256)),
    (Role::Curve, CURVE_P256, Alg::Curve(NamedCurve::P256)),
    (Role::Curve, CURVE_P384, Alg::Curve(NamedCurve::P384)),
    (Role::Curve, CURVE_P521, Alg::Curve(NamedCurve::P521)),
    (
        Role::Curve,
        CURVE_BP256R1,
        Alg::Curve(NamedCurve::BrainpoolP256r1),
    ),
    (
        Role::Curve,
        CURVE_BP384R1,
        Alg::Curve(NamedCurve::BrainpoolP384r1),
    ),
    (
        Role::Curve,
        CURVE_BP512R1,
        Alg::Curve(NamedCurve::BrainpoolP512r1),
    ),
];

/// The algorithm `uri` names in `role`, or an `InteropViolation` naming both.
pub(crate) fn lookup(role: Role, uri: &str) -> Result<Alg> {
    REGISTRY
        .iter()
        .find(|(r, u, _)| *r == role && *u == uri)
        .map(|(_, _, alg)| *alg)
        .ok_or_else(|| unsupported(role, uri))
}

fn unsupported(role: Role, uri: &str) -> AsxError {
    AsxError::new(
        ErrorCode::InteropViolation,
        format!("unsupported {} algorithm: {uri}", role.label()),
        ErrorContext::new("xmlsec_algorithm_registry").with_message_id(uri.to_string()),
    )
}

impl Alg {
    /// The URI of this algorithm (its registry row).
    pub(crate) fn uri(self) -> &'static str {
        REGISTRY
            .iter()
            .find(|(_, _, alg)| *alg == self)
            .map(|(_, uri, _)| *uri)
            // Every variant has a row; the registry tests enforce it.
            .unwrap_or("")
    }
}

/// `lookup` narrowed to one role's enum.
macro_rules! typed_lookup {
    ($role:ident, $variant:ident, $uri:expr) => {
        match lookup(Role::$role, $uri)? {
            Alg::$variant(value) => Ok(value),
            _ => Err(unsupported(Role::$role, $uri)),
        }
    };
}

// ── Per-algorithm behaviour ─────────────────────────────────────────────────

impl SignatureAlgorithm {
    /// Returns the canonical W3C algorithm URI for embedding in
    /// `<ds:SignatureMethod Algorithm="..."/>`.
    pub fn algorithm_uri(self) -> &'static str {
        Alg::Signature(self).uri()
    }

    /// The algorithm a `ds:SignatureMethod/@Algorithm` names.
    pub(crate) fn from_uri(uri: &str) -> Result<Self> {
        typed_lookup!(Signature, Signature, uri)
    }

    /// The OpenSSL digest of the hash component of this algorithm.
    pub(crate) fn message_digest(self) -> MessageDigest {
        match self {
            Self::RsaSha256 | Self::EcdsaSha256 => MessageDigest::sha256(),
            Self::RsaSha384 | Self::EcdsaSha384 => MessageDigest::sha384(),
            Self::RsaSha512 | Self::EcdsaSha512 => MessageDigest::sha512(),
        }
    }

    /// The public-key family this method requires.
    pub(crate) fn key_family(self) -> KeyFamily {
        match self {
            Self::RsaSha256 | Self::RsaSha384 | Self::RsaSha512 => KeyFamily::Rsa,
            Self::EcdsaSha256 | Self::EcdsaSha384 | Self::EcdsaSha512 => KeyFamily::Ec,
        }
    }

    /// Key-seam output → `ds:SignatureValue` octets. RSA: identity (PKCS #1
    /// v1.5). ECDSA: DER → `r ‖ s`, `l` from the signer certificate's curve
    /// order (XMLDSig 1.1 §6.4.3).
    pub(crate) fn to_wire(self, raw: Vec<u8>, signer_cert: &X509Ref) -> Result<Vec<u8>> {
        match self.key_family() {
            KeyFamily::Rsa => Ok(raw),
            KeyFamily::Ec => ecdsa::der_to_wire(&raw, ec_order_len(self, signer_cert)?),
        }
    }

    /// `ds:SignatureValue` octets → what OpenSSL's verifier takes. RSA:
    /// identity. ECDSA: exactly `2·l` octets for the signer certificate's
    /// curve, else refused naming the received and the required length.
    // `from_wire` pairs with `to_wire`; both read the method (`self`).
    #[allow(clippy::wrong_self_convention)]
    pub(crate) fn from_wire(self, value: &[u8], signer_cert: &X509Ref) -> Result<Vec<u8>> {
        match self.key_family() {
            KeyFamily::Rsa => Ok(value.to_vec()),
            KeyFamily::Ec => {
                let l = ec_order_len(self, signer_cert)?;
                ecdsa::wire_to_der(value, l).map_err(|err| {
                    let curve = signer_cert
                        .public_key()
                        .ok()
                        .and_then(|k| k.ec_key().ok())
                        .and_then(|k| NamedCurve::from_group(k.group()).ok())
                        .map(|c| format!("{c:?}"))
                        .unwrap_or_else(|| "the signer's curve".to_string());
                    if value.len() == 2 * l {
                        err
                    } else {
                        AsxError::new(
                            ErrorCode::SecurityVerificationFailed,
                            format!(
                                "ECDSA SignatureValue is {} octets; {curve} requires {} \
                                 (r ‖ s, XMLDSig 1.1 §6.4.3)",
                                value.len(),
                                2 * l
                            ),
                            ErrorContext::new("xmldsig_ecdsa_signature_value"),
                        )
                    }
                })
            }
        }
    }
}

/// `l` for an ECDSA method: the order length of the certificate's EC key.
fn ec_order_len(algorithm: SignatureAlgorithm, cert: &X509Ref) -> Result<usize> {
    let key = cert
        .public_key()
        .ok()
        .and_then(|k| k.ec_key().ok())
        .ok_or_else(|| {
            AsxError::new(
                ErrorCode::SecurityVerificationFailed,
                format!(
                    "{} requires an EC certificate key",
                    algorithm.algorithm_uri()
                ),
                ErrorContext::new("xmldsig_ecdsa_signature_value"),
            )
        })?;
    Ok(ecdsa::order_len(key.group()))
}

impl WsSecDigestMethod {
    /// The digest method a `ds:DigestMethod/@Algorithm` names.
    pub fn from_algorithm_uri(uri: &str) -> Result<Self> {
        typed_lookup!(Digest, Digest, uri)
    }

    /// Returns the canonical algorithm URI for this digest method.
    pub fn algorithm_uri(self) -> &'static str {
        Alg::Digest(self).uri()
    }

    /// The OpenSSL digest for this method.
    pub(crate) fn message_digest(self) -> MessageDigest {
        match self {
            Self::Sha256 => MessageDigest::sha256(),
            Self::Sha384 => MessageDigest::sha384(),
            Self::Sha512 => MessageDigest::sha512(),
        }
    }

    /// Output byte length for this digest method.
    pub(crate) fn output_len(self) -> usize {
        match self {
            Self::Sha256 => 32,
            Self::Sha384 => 48,
            Self::Sha512 => 64,
        }
    }
}

impl WsSecCanonicalizationKind {
    /// The canonicalization method a `ds:CanonicalizationMethod/@Algorithm`
    /// names.
    pub(crate) fn from_uri(uri: &str) -> Result<Self> {
        typed_lookup!(C14n, C14n, uri)
    }

    /// The URI of this canonicalization method.
    pub(crate) fn uri(self) -> &'static str {
        Alg::C14n(self).uri()
    }
}

impl TransformAlg {
    /// The transform a `ds:Transform/@Algorithm` names.
    pub(crate) fn from_uri(uri: &str) -> Result<Self> {
        typed_lookup!(Transform, Transform, uri)
    }

    pub(crate) fn uri(self) -> &'static str {
        Alg::Transform(self).uri()
    }
}

impl XmlEncPayloadAlgorithm {
    /// The content cipher an `xenc:EncryptionMethod/@Algorithm` names.
    pub(crate) fn from_uri(uri: &str) -> Result<Self> {
        typed_lookup!(ContentCipher, ContentCipher, uri)
    }

    pub(crate) fn uri(self) -> &'static str {
        Alg::ContentCipher(self).uri()
    }

    /// CEK length in octets: the declared cipher decides it.
    pub(crate) fn key_len(self) -> usize {
        match self {
            Self::Aes128Gcm => 16,
            Self::Aes256Gcm => 32,
        }
    }

    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Aes128Gcm => "AES-128-GCM",
            Self::Aes256Gcm => "AES-256-GCM",
        }
    }
}

impl KeyTransportAlg {
    pub(crate) fn from_uri(uri: &str) -> Result<Self> {
        typed_lookup!(KeyTransport, KeyTransport, uri)
    }

    pub(crate) fn uri(self) -> &'static str {
        Alg::KeyTransport(self).uri()
    }
}

impl AgreementAlg {
    pub(crate) fn from_uri(uri: &str) -> Result<Self> {
        typed_lookup!(KeyAgreement, KeyAgreement, uri)
    }

    pub(crate) fn uri(self) -> &'static str {
        Alg::KeyAgreement(self).uri()
    }
}

impl KdfAlg {
    pub(crate) fn from_uri(uri: &str) -> Result<Self> {
        typed_lookup!(Kdf, Kdf, uri)
    }

    pub(crate) fn uri(self) -> &'static str {
        Alg::Kdf(self).uri()
    }
}

impl KeyWrapAlg {
    pub(crate) fn from_uri(uri: &str) -> Result<Self> {
        typed_lookup!(KeyWrap, KeyWrap, uri)
    }

    pub(crate) fn uri(self) -> &'static str {
        Alg::KeyWrap(self).uri()
    }

    /// KEK length in octets.
    pub(crate) fn kek_len(self) -> usize {
        match self {
            Self::Aes128 => 16,
            Self::Aes192 => 24,
            Self::Aes256 => 32,
        }
    }

    /// The wrap algorithm for a KEK of `len` octets.
    pub(crate) fn for_kek_len(len: usize) -> Result<Self> {
        match len {
            16 => Ok(Self::Aes128),
            24 => Ok(Self::Aes192),
            32 => Ok(Self::Aes256),
            other => Err(AsxError::new(
                ErrorCode::InvalidInput,
                format!("no AES key wrap algorithm for a {other}-octet KEK"),
                ErrorContext::new("xmlsec_algorithm_registry"),
            )),
        }
    }
}

impl MgfAlg {
    pub(crate) fn from_uri(uri: &str) -> Result<Self> {
        typed_lookup!(Mgf, Mgf, uri)
    }

    pub(crate) fn uri(self) -> &'static str {
        Alg::Mgf(self).uri()
    }
}

impl NamedCurve {
    pub(crate) fn from_uri(uri: &str) -> Result<Self> {
        typed_lookup!(Curve, Curve, uri)
    }

    pub(crate) fn uri(self) -> &'static str {
        Alg::Curve(self).uri()
    }

    /// The OpenSSL curve NID.
    pub(crate) fn nid(self) -> Nid {
        match self {
            Self::P256 => Nid::X9_62_PRIME256V1,
            Self::P384 => Nid::SECP384R1,
            Self::P521 => Nid::SECP521R1,
            Self::BrainpoolP256r1 => Nid::BRAINPOOL_P256R1,
            Self::BrainpoolP384r1 => Nid::BRAINPOOL_P384R1,
            Self::BrainpoolP512r1 => Nid::BRAINPOOL_P512R1,
        }
    }

    /// The curve of an OpenSSL group, or `InteropViolation` for a curve with
    /// no registry row.
    pub(crate) fn from_group(group: &openssl::ec::EcGroupRef) -> Result<Self> {
        let nid = group.curve_name();
        [
            Self::P256,
            Self::P384,
            Self::P521,
            Self::BrainpoolP256r1,
            Self::BrainpoolP384r1,
            Self::BrainpoolP512r1,
        ]
        .into_iter()
        .find(|curve| Some(curve.nid()) == nid)
        .ok_or_else(|| {
            AsxError::new(
                ErrorCode::InteropViolation,
                format!(
                    "unsupported EC curve {nid:?} (supported: P-256, P-384, P-521, \
                     brainpoolP256r1/P384r1/P512r1)"
                ),
                ErrorContext::new("xmlsec_algorithm_registry"),
            )
        })
    }

    /// Octet length of a field element (an uncompressed point is
    /// `1 + 2·field_len` octets).
    pub(crate) fn field_len(self) -> usize {
        match self {
            Self::P256 | Self::BrainpoolP256r1 => 32,
            Self::P384 | Self::BrainpoolP384r1 => 48,
            Self::BrainpoolP512r1 => 64,
            Self::P521 => 66,
        }
    }

    /// Octet length of the base-point order — the ECDSA `l` of XMLDSig 1.1
    /// §6.4.3. Test oracle for `ecdsa::order_len`, which reads the group.
    #[cfg(test)]
    pub(crate) fn order_len(self) -> usize {
        match self {
            Self::P256 | Self::BrainpoolP256r1 => 32,
            Self::P384 | Self::BrainpoolP384r1 => 48,
            Self::BrainpoolP512r1 => 64,
            Self::P521 => 66,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn all_variants() -> Vec<Alg> {
        use SignatureAlgorithm as S;
        let mut all = vec![
            Alg::Digest(WsSecDigestMethod::Sha256),
            Alg::Digest(WsSecDigestMethod::Sha384),
            Alg::Digest(WsSecDigestMethod::Sha512),
            Alg::C14n(WsSecCanonicalizationKind::Exclusive),
            Alg::C14n(WsSecCanonicalizationKind::Inclusive),
            Alg::Transform(TransformAlg::C14n(WsSecCanonicalizationKind::Exclusive)),
            Alg::Transform(TransformAlg::C14n(WsSecCanonicalizationKind::Inclusive)),
            Alg::Transform(TransformAlg::AttachmentContent),
            Alg::Transform(TransformAlg::EnvelopedSignature),
            Alg::KeyTransport(KeyTransportAlg::RsaOaep),
            Alg::KeyAgreement(AgreementAlg::EcdhEs),
            Alg::Kdf(KdfAlg::ConcatKdf),
            Alg::KeyWrap(KeyWrapAlg::Aes128),
            Alg::KeyWrap(KeyWrapAlg::Aes192),
            Alg::KeyWrap(KeyWrapAlg::Aes256),
            Alg::ContentCipher(XmlEncPayloadAlgorithm::Aes128Gcm),
            Alg::ContentCipher(XmlEncPayloadAlgorithm::Aes256Gcm),
            Alg::Mgf(MgfAlg::Mgf1Sha256),
        ];
        for s in [
            S::RsaSha256,
            S::RsaSha384,
            S::RsaSha512,
            S::EcdsaSha256,
            S::EcdsaSha384,
            S::EcdsaSha512,
        ] {
            all.push(Alg::Signature(s));
        }
        for c in [
            NamedCurve::P256,
            NamedCurve::P384,
            NamedCurve::P521,
            NamedCurve::BrainpoolP256r1,
            NamedCurve::BrainpoolP384r1,
            NamedCurve::BrainpoolP512r1,
        ] {
            all.push(Alg::Curve(c));
        }
        all
    }

    /// Exhaustiveness guard: adding a variant without listing it here is a
    /// compile error, so `all_variants` cannot silently fall behind.
    #[allow(dead_code)]
    fn exhaustive(alg: Alg) {
        match alg {
            Alg::Digest(
                WsSecDigestMethod::Sha256 | WsSecDigestMethod::Sha384 | WsSecDigestMethod::Sha512,
            )
            | Alg::Signature(
                SignatureAlgorithm::RsaSha256
                | SignatureAlgorithm::RsaSha384
                | SignatureAlgorithm::RsaSha512
                | SignatureAlgorithm::EcdsaSha256
                | SignatureAlgorithm::EcdsaSha384
                | SignatureAlgorithm::EcdsaSha512,
            )
            | Alg::C14n(
                WsSecCanonicalizationKind::Exclusive | WsSecCanonicalizationKind::Inclusive,
            )
            | Alg::Transform(
                TransformAlg::C14n(
                    WsSecCanonicalizationKind::Exclusive | WsSecCanonicalizationKind::Inclusive,
                )
                | TransformAlg::AttachmentContent
                | TransformAlg::EnvelopedSignature,
            )
            | Alg::KeyTransport(KeyTransportAlg::RsaOaep)
            | Alg::KeyAgreement(AgreementAlg::EcdhEs)
            | Alg::Kdf(KdfAlg::ConcatKdf)
            | Alg::KeyWrap(KeyWrapAlg::Aes128 | KeyWrapAlg::Aes192 | KeyWrapAlg::Aes256)
            | Alg::ContentCipher(
                XmlEncPayloadAlgorithm::Aes128Gcm | XmlEncPayloadAlgorithm::Aes256Gcm,
            )
            | Alg::Mgf(MgfAlg::Mgf1Sha256)
            | Alg::Curve(
                NamedCurve::P256
                | NamedCurve::P384
                | NamedCurve::P521
                | NamedCurve::BrainpoolP256r1
                | NamedCurve::BrainpoolP384r1
                | NamedCurve::BrainpoolP512r1,
            ) => {}
        }
    }

    fn role_of(alg: Alg) -> Role {
        match alg {
            Alg::Digest(_) => Role::Digest,
            Alg::Signature(_) => Role::Signature,
            Alg::C14n(_) => Role::C14n,
            Alg::Transform(_) => Role::Transform,
            Alg::KeyTransport(_) => Role::KeyTransport,
            Alg::KeyAgreement(_) => Role::KeyAgreement,
            Alg::Kdf(_) => Role::Kdf,
            Alg::KeyWrap(_) => Role::KeyWrap,
            Alg::ContentCipher(_) => Role::ContentCipher,
            Alg::Mgf(_) => Role::Mgf,
            Alg::Curve(_) => Role::Curve,
        }
    }

    #[test]
    fn every_role_uri_pair_is_unique() {
        for (i, (role, uri, _)) in REGISTRY.iter().enumerate() {
            for (other_role, other_uri, _) in &REGISTRY[i + 1..] {
                assert!(
                    !(role == other_role && uri == other_uri),
                    "({role:?}, {uri}) has two rows"
                );
            }
        }
    }

    #[test]
    fn every_variant_has_exactly_one_row_in_its_role() {
        let all = all_variants();
        assert_eq!(all.len(), REGISTRY.len(), "a row has no listed variant");
        for alg in all {
            let rows: Vec<_> = REGISTRY.iter().filter(|(_, _, a)| *a == alg).collect();
            assert_eq!(rows.len(), 1, "{alg:?} must have exactly one row");
            assert_eq!(
                rows[0].0,
                role_of(alg),
                "{alg:?} is filed under the wrong role"
            );
        }
    }

    #[test]
    fn lookup_round_trips_every_row() {
        for alg in all_variants() {
            assert_eq!(lookup(role_of(alg), alg.uri()).unwrap(), alg);
        }
        assert_eq!(
            SignatureAlgorithm::from_uri(SignatureAlgorithm::EcdsaSha256.algorithm_uri()).unwrap(),
            SignatureAlgorithm::EcdsaSha256
        );
        assert_eq!(
            NamedCurve::from_uri(NamedCurve::BrainpoolP256r1.uri()).unwrap(),
            NamedCurve::BrainpoolP256r1
        );
    }

    #[test]
    fn unknown_uri_is_rejected_naming_role_and_uri() {
        let sha1 = "http://www.w3.org/2000/09/xmldsig#sha1";
        let err = lookup(Role::Digest, sha1).unwrap_err();
        assert_eq!(err.code, ErrorCode::InteropViolation);
        assert!(err.message.contains("digest"), "{}", err.message);
        assert!(err.message.contains(sha1), "{}", err.message);

        // A URI of another role is unknown in this one.
        let err =
            SignatureAlgorithm::from_uri(WsSecDigestMethod::Sha256.algorithm_uri()).unwrap_err();
        assert!(err.message.contains("signature"), "{}", err.message);
    }

    #[test]
    fn curves_match_openssl_groups() {
        for curve in [
            NamedCurve::P256,
            NamedCurve::P384,
            NamedCurve::P521,
            NamedCurve::BrainpoolP256r1,
            NamedCurve::BrainpoolP384r1,
            NamedCurve::BrainpoolP512r1,
        ] {
            let group = openssl::ec::EcGroup::from_curve_name(curve.nid()).unwrap();
            assert_eq!(NamedCurve::from_group(&group).unwrap(), curve);
            assert_eq!(
                (group.order_bits() as usize).div_ceil(8),
                curve.order_len(),
                "{curve:?}"
            );
            assert_eq!(
                (group.degree() as usize).div_ceil(8),
                curve.field_len(),
                "{curve:?}"
            );
        }
    }
}
