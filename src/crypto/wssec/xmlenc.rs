//! AS4/WS-Security XML Encryption — encrypt and decrypt payloads.
//!
//! ## Key transport algorithms
//!
//! | Recipient key type | Algorithm | Standard |
//! |---|---|---|
//! | RSA | RSA-OAEP (SHA-256/MGF1-SHA-256) | eDelivery AS4 v1.15 / PEPPOL |
//! | EC  | ECDH-ES + ConcatKDF + AES-128-KW | BSI TR-03116-3 §9.2 / BDEW AS4-Profil |
//!
//! The key transport algorithm is selected **automatically** based on the
//! recipient certificate’s public key type.  RSA certificates use RSA-OAEP;
//! EC certificates (including BrainpoolP256r1) use ECDH-ES with ephemeral
//! key generation, ConcatKDF (NIST SP 800-56A) key derivation, and
//! AES-128 Key Wrap (RFC 3394).
//!
//! ## Payload encryption
//!
//! eDelivery AS4 v1.15 Common Profile mandates AES-128-GCM for outbound
//! XML-Enc payload encryption.  Some partner networks accept AES-256-GCM.
//! AES-CBC is explicitly rejected: not required by eDelivery AS4 v1.15 and
//! opens padding-oracle attack surface.

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use openssl::derive::Deriver;
use openssl::ec::{EcKey, EcPoint, PointConversionForm};
use openssl::encrypt::{Decrypter, Encrypter};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::PKey;
use openssl::rsa::Padding;
use openssl::symm::{Cipher, Crypter, Mode};
use openssl::x509::{X509, X509Ref};
use quick_xml::events::{BytesStart, Event};
use quick_xml::name::ResolveResult;
use quick_xml::reader::NsReader;

// Pure-Rust symmetric crypto: AES-GCM (aes-gcm crate).
// OpenSSL is retained only for asymmetric operations (RSA-OAEP key wrap/unwrap).
use aes_gcm::{Aes128Gcm, Aes256Gcm, KeyInit, aead::Aead};

use crate::core::{AsxError, ErrorCode, ErrorContext, Result};

use super::DS_NS;

const XENC_NS: &str = "http://www.w3.org/2001/04/xmlenc#";
const XENC11_NS: &str = "http://www.w3.org/2009/xmlenc11#";
const DSIG11_NS: &str = "http://www.w3.org/2009/xmldsig11#";
const XENC11_RSA_OAEP_URI: &str = "http://www.w3.org/2009/xmlenc11#rsa-oaep";
/// AES-128 Key Wrap algorithm URI (RFC 3394).
const KW_AES128_URI: &str = "http://www.w3.org/2001/04/xmlenc#kw-aes128";
/// ECDH Ephemeral-Static key agreement (XMLenc 1.1).
const ECDH_ES_URI: &str = "http://www.w3.org/2009/xmlenc11#ECDH-ES";
/// ConcatKDF key derivation (XMLenc 1.1 / NIST SP 800-56A).
const CONCAT_KDF_URI: &str = "http://www.w3.org/2009/xmlenc11#ConcatKDF";
/// SHA-256 digest algorithm URI used in ConcatKDF parameters.
const SHA256_DIGEST_URI: &str = "http://www.w3.org/2001/04/xmlenc#sha256";
const XENC11_CONTENT_URI: &str = "http://www.w3.org/2001/04/xmlenc#Content";
const XENC11_ELEMENT_URI: &str = "http://www.w3.org/2001/04/xmlenc#Element";
const XENC11_AES128_GCM_URI: &str = "http://www.w3.org/2009/xmlenc11#aes128-gcm";
const XENC11_AES256_GCM_URI: &str = "http://www.w3.org/2009/xmlenc11#aes256-gcm";

/// Inbound decryption mode derived from the `xenc:EncryptionMethod` algorithm URI.
/// AES-CBC is intentionally excluded: not required by eDelivery AS4 v1.15 and
/// susceptible to padding-oracle attacks (POODLE/BEAST variants).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum InboundDataAlgorithm {
    Aes128Gcm,
    Aes256Gcm,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Default)]
#[non_exhaustive]
pub enum XmlEncPayloadAlgorithm {
    /// eDelivery AS4 v1.15 Common Profile default.
    #[default]
    Aes128Gcm,
    /// Stronger key size, but not eDelivery v1.15 Common Profile default.
    Aes256Gcm,
}

impl XmlEncPayloadAlgorithm {
    fn key_len(self) -> usize {
        match self {
            Self::Aes128Gcm => 16,
            Self::Aes256Gcm => 32,
        }
    }

    fn xmlenc_uri(self) -> &'static str {
        match self {
            Self::Aes128Gcm => XENC11_AES128_GCM_URI,
            Self::Aes256Gcm => XENC11_AES256_GCM_URI,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Aes128Gcm => "AES-128-GCM",
            Self::Aes256Gcm => "AES-256-GCM",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum XmlEncTag {
    EncryptedData,
    EncryptedKey,
    EncryptionMethod,
    CipherData,
    CipherValue,
    /// `xenc:AgreementMethod` or `xenc11:AgreementMethod` — ECDH-ES key agreement.
    AgreementMethod,
    /// `dsig11:PublicKey` — carries the originator’s ephemeral EC public key bytes.
    PublicKeyElement,
    Other,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CipherTarget {
    WrappedKey,
    Payload,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum XmlEncEncapsulation {
    Payload,
    SoapHeader {
        soap_namespace: &'static str,
        must_understand_token: &'static str,
    },
}

pub fn encrypt_payload_xmlenc(
    payload: &[u8],
    recipient_cert_pem: &[u8],
    payload_algorithm: XmlEncPayloadAlgorithm,
) -> Result<Vec<u8>> {
    let cert = X509::from_pem(recipient_cert_pem).map_err(|err| {
        AsxError::new(
            ErrorCode::SecurityVerificationFailed,
            format!("failed to parse XML Encryption recipient cert PEM: {err}"),
            ErrorContext::new("wssec_encrypt_payload"),
        )
    })?;
    encrypt_payload_xmlenc_preparsed(payload, &cert, payload_algorithm)
}

pub fn encrypt_payload_xmlenc_preparsed(
    payload: &[u8],
    recipient_cert: &X509Ref,
    payload_algorithm: XmlEncPayloadAlgorithm,
) -> Result<Vec<u8>> {
    encrypt_xmlenc_preparsed(
        payload,
        recipient_cert,
        payload_algorithm,
        XmlEncEncapsulation::Payload,
    )
}

/// Encrypt a SOAP header block and wrap the result in `xenc:EncryptedHeader`.
pub fn encrypt_soap_header_xmlenc_preparsed(
    header_xml: &[u8],
    recipient_cert: &X509Ref,
    payload_algorithm: XmlEncPayloadAlgorithm,
    soap_namespace: &'static str,
    must_understand_token: &'static str,
) -> Result<Vec<u8>> {
    encrypt_xmlenc_preparsed(
        header_xml,
        recipient_cert,
        payload_algorithm,
        XmlEncEncapsulation::SoapHeader {
            soap_namespace,
            must_understand_token,
        },
    )
}

fn encrypt_xmlenc_preparsed(
    payload: &[u8],
    recipient_cert: &X509Ref,
    payload_algorithm: XmlEncPayloadAlgorithm,
    encapsulation: XmlEncEncapsulation,
) -> Result<Vec<u8>> {
    let pkey = recipient_cert.public_key().map_err(|err| {
        AsxError::new(
            ErrorCode::SecurityVerificationFailed,
            format!("recipient certificate does not contain a usable public key: {err}"),
            ErrorContext::new("wssec_encrypt_payload"),
        )
    })?;

    // Generate the AES-GCM content-encryption key (CEK) and encrypt the payload.
    let mut aes_key = vec![0u8; payload_algorithm.key_len()];
    getrandom::fill(&mut aes_key).map_err(|err| {
        AsxError::new(
            ErrorCode::SecurityVerificationFailed,
            format!("failed to generate XML Encryption AES key: {err}"),
            ErrorContext::new("wssec_encrypt_payload"),
        )
    })?;
    let mut nonce_bytes = [0u8; 12];
    getrandom::fill(&mut nonce_bytes).map_err(|err| {
        AsxError::new(
            ErrorCode::SecurityVerificationFailed,
            format!("failed to generate XML Encryption GCM nonce: {err}"),
            ErrorContext::new("wssec_encrypt_payload"),
        )
    })?;
    let nonce = aes_gcm::Nonce::from(nonce_bytes);
    let gcm_output = match aes_key.len() {
        16 => aes_gcm::Aes128Gcm::new_from_slice(&aes_key)
            .expect("key length validated above")
            .encrypt(&nonce, payload.as_ref()),
        32 => aes_gcm::Aes256Gcm::new_from_slice(&aes_key)
            .expect("key length validated above")
            .encrypt(&nonce, payload.as_ref()),
        _ => unreachable!("XmlEncPayloadAlgorithm::key_len() returns 16 or 32"),
    }
    .map_err(|_| {
        AsxError::new(
            ErrorCode::SecurityVerificationFailed,
            format!(
                "failed to {}-encrypt outbound payload",
                payload_algorithm.label()
            ),
            ErrorContext::new("wssec_encrypt_payload"),
        )
    })?;
    // XMLenc11 GCM wire format: nonce (12) || ciphertext || auth_tag (16).
    let mut gcm_blob = Vec::with_capacity(12 + gcm_output.len());
    gcm_blob.extend_from_slice(&nonce_bytes);
    gcm_blob.extend_from_slice(&gcm_output);
    let gcm_blob_b64 = BASE64_STANDARD.encode(&gcm_blob);

    // Wrap the CEK using the algorithm matching the recipient's key type.
    let xmlenc_type = match encapsulation {
        XmlEncEncapsulation::Payload => XENC11_CONTENT_URI,
        XmlEncEncapsulation::SoapHeader { .. } => XENC11_ELEMENT_URI,
    };
    let aes_gcm_uri = payload_algorithm.xmlenc_uri();

    let encrypted_data_xml = match pkey.id() {
        openssl::pkey::Id::RSA | openssl::pkey::Id::RSA_PSS => {
            // RSA-OAEP key transport (PEPPOL / CEF eDelivery AS4 profile).
            const RSA_OAEP_URI: &str = "http://www.w3.org/2009/xmlenc11#rsa-oaep";
            const MGF1SHA256_URI: &str = "http://www.w3.org/2009/xmlenc11#mgf1sha256";

            let mut encrypter = Encrypter::new(&pkey).map_err(|err| {
                AsxError::new(
                    ErrorCode::SecurityVerificationFailed,
                    format!("failed to create RSA encrypter: {err}"),
                    ErrorContext::new("wssec_encrypt_payload"),
                )
            })?;
            encrypter
                .set_rsa_padding(Padding::PKCS1_OAEP)
                .map_err(|err| {
                    AsxError::new(
                        ErrorCode::SecurityVerificationFailed,
                        format!("failed to set RSA-OAEP padding: {err}"),
                        ErrorContext::new("wssec_encrypt_payload"),
                    )
                })?;
            encrypter
                .set_rsa_oaep_md(MessageDigest::sha256())
                .map_err(|err| {
                    AsxError::new(
                        ErrorCode::SecurityVerificationFailed,
                        format!("failed to set RSA-OAEP SHA-256 digest: {err}"),
                        ErrorContext::new("wssec_encrypt_payload"),
                    )
                })?;
            encrypter
                .set_rsa_mgf1_md(MessageDigest::sha256())
                .map_err(|err| {
                    AsxError::new(
                        ErrorCode::SecurityVerificationFailed,
                        format!("failed to set RSA MGF1-SHA-256 digest: {err}"),
                        ErrorContext::new("wssec_encrypt_payload"),
                    )
                })?;
            let buf_len = encrypter.encrypt_len(&aes_key).map_err(|err| {
                AsxError::new(
                    ErrorCode::SecurityVerificationFailed,
                    format!("failed to compute encrypted key buffer length: {err}"),
                    ErrorContext::new("wssec_encrypt_payload"),
                )
            })?;
            let mut encrypted_key = vec![0u8; buf_len];
            let encrypted_key_len = encrypter.encrypt(&aes_key, &mut encrypted_key).map_err(|err| {
                AsxError::new(
                    ErrorCode::SecurityVerificationFailed,
                    format!("failed to wrap AES key with recipient RSA key (OAEP/MGF1-SHA256): {err}"),
                    ErrorContext::new("wssec_encrypt_payload"),
                )
            })?;
            encrypted_key.truncate(encrypted_key_len);
            let encrypted_key_b64 = BASE64_STANDARD.encode(&encrypted_key);

            format!(
                "<xenc:EncryptedData xmlns:xenc=\"{XENC_NS}\" xmlns:xenc11=\"{XENC11_NS}\" Type=\"{xmlenc_type}\">\
<xenc:EncryptionMethod Algorithm=\"{aes_gcm_uri}\"/>\
<ds:KeyInfo xmlns:ds=\"{DS_NS}\">\
<xenc:EncryptedKey>\
<xenc:EncryptionMethod Algorithm=\"{RSA_OAEP_URI}\">\
<ds:DigestMethod Algorithm=\"{SHA256_DIGEST_URI}\"/>\
<xenc11:MGF Algorithm=\"{MGF1SHA256_URI}\"/>\
</xenc:EncryptionMethod>\
<xenc:CipherData><xenc:CipherValue>{encrypted_key_b64}</xenc:CipherValue></xenc:CipherData>\
</xenc:EncryptedKey>\
</ds:KeyInfo>\
<xenc:CipherData><xenc:CipherValue>{gcm_blob_b64}</xenc:CipherValue></xenc:CipherData>\
</xenc:EncryptedData>"
            )
        }
        openssl::pkey::Id::EC => {
            // ECDH-ES key agreement + AES-128 Key Wrap (BSI TR-03116-3 §9.2).
            let ec_key = pkey.ec_key().map_err(|err| {
                AsxError::new(
                    ErrorCode::SecurityVerificationFailed,
                    format!("failed to extract EC key from recipient certificate: {err}"),
                    ErrorContext::new("wssec_encrypt_payload"),
                )
            })?;
            let group = ec_key.group();
            let curve_oid_urn = ec_group_oid_urn(group)?;

            // Generate ephemeral EC key on the recipient's curve.
            let ephemeral_ec = EcKey::generate(group).map_err(|err| {
                AsxError::new(
                    ErrorCode::SecurityVerificationFailed,
                    format!("failed to generate ephemeral EC key: {err}"),
                    ErrorContext::new("wssec_encrypt_payload"),
                )
            })?;
            let ephemeral_pkey = PKey::from_ec_key(ephemeral_ec.clone()).map_err(|err| {
                AsxError::new(
                    ErrorCode::SecurityVerificationFailed,
                    format!("failed to wrap ephemeral EC key: {err}"),
                    ErrorContext::new("wssec_encrypt_payload"),
                )
            })?;

            // Encode ephemeral public key as uncompressed point (04 || X || Y).
            let mut bn_ctx = openssl::bn::BigNumContext::new().map_err(|err| {
                AsxError::new(
                    ErrorCode::SecurityVerificationFailed,
                    format!("BN context allocation failed: {err}"),
                    ErrorContext::new("wssec_encrypt_payload"),
                )
            })?;
            let ephemeral_pubkey_bytes = ephemeral_ec
                .public_key()
                .to_bytes(group, PointConversionForm::UNCOMPRESSED, &mut bn_ctx)
                .map_err(|err| {
                    AsxError::new(
                        ErrorCode::SecurityVerificationFailed,
                        format!("failed to encode ephemeral EC public key: {err}"),
                        ErrorContext::new("wssec_encrypt_payload"),
                    )
                })?;
            let ephemeral_pubkey_b64 = BASE64_STANDARD.encode(&ephemeral_pubkey_bytes);

            // Compute ECDH shared secret: ephemeral private × recipient public.
            let recipient_pkey_pub = PKey::from_ec_key(ec_key).map_err(|err| {
                AsxError::new(
                    ErrorCode::SecurityVerificationFailed,
                    format!("failed to wrap recipient EC key: {err}"),
                    ErrorContext::new("wssec_encrypt_payload"),
                )
            })?;
            // Deriver requires a private key; use ephemeral private + recipient public.
            let z = {
                let mut deriver = Deriver::new(&ephemeral_pkey).map_err(|err| {
                    AsxError::new(
                        ErrorCode::SecurityVerificationFailed,
                        format!("ECDH deriver init failed: {err}"),
                        ErrorContext::new("wssec_encrypt_payload"),
                    )
                })?;
                deriver.set_peer(&recipient_pkey_pub).map_err(|err| {
                    AsxError::new(
                        ErrorCode::SecurityVerificationFailed,
                        format!("ECDH set_peer failed: {err}"),
                        ErrorContext::new("wssec_encrypt_payload"),
                    )
                })?;
                deriver.derive_to_vec().map_err(|err| {
                    AsxError::new(
                        ErrorCode::SecurityVerificationFailed,
                        format!("ECDH shared secret derivation failed: {err}"),
                        ErrorContext::new("wssec_encrypt_payload"),
                    )
                })?
            };

            // Derive 16-byte key-encryption key via ConcatKDF (SHA-256).
            // BDEW profile: AlgorithmID = "", PartyUInfo = "", PartyVInfo = "" (all empty).
            let kdf_output = concat_kdf_sha256(&z, 128, &[], &[], &[]);
            let kek: [u8; 16] = kdf_output[..16].try_into().expect("16-byte slice");
            // Zeroize the shared secret immediately after use.
            let mut z_zeroize = z;
            use zeroize::Zeroize as _;
            z_zeroize.zeroize();

            // Wrap CEK with AES-128 Key Wrap (RFC 3394).
            let wrapped_cek = aes_128_key_wrap(&kek, &aes_key)?;
            let wrapped_cek_b64 = BASE64_STANDARD.encode(&wrapped_cek);

            // Subject Key Identifier for recipient key reference.
            let ski_bytes = cert_subject_key_id(recipient_cert)?;
            let ski_b64 = BASE64_STANDARD.encode(&ski_bytes);

            format!(
                "<xenc:EncryptedData xmlns:xenc=\"{XENC_NS}\" xmlns:xenc11=\"{XENC11_NS}\" \
xmlns:ds=\"{DS_NS}\" xmlns:dsig11=\"{DSIG11_NS}\" Type=\"{xmlenc_type}\">\
<xenc:EncryptionMethod Algorithm=\"{aes_gcm_uri}\"/>\
<ds:KeyInfo>\
<xenc:EncryptedKey>\
<xenc:EncryptionMethod Algorithm=\"{KW_AES128_URI}\"/>\
<ds:KeyInfo>\
<xenc:AgreementMethod Algorithm=\"{ECDH_ES_URI}\">\
<xenc11:KeyDerivationMethod Algorithm=\"{CONCAT_KDF_URI}\">\
<xenc11:ConcatKDFParams AlgorithmID=\"\" PartyUInfo=\"\" PartyVInfo=\"\">\
<ds:DigestMethod Algorithm=\"{SHA256_DIGEST_URI}\"/>\
</xenc11:ConcatKDFParams>\
</xenc11:KeyDerivationMethod>\
<xenc:OriginatorKeyInfo>\
<ds:KeyValue>\
<dsig11:ECKeyValue>\
<dsig11:NamedCurve URI=\"{curve_oid_urn}\"/>\
<dsig11:PublicKey>{ephemeral_pubkey_b64}</dsig11:PublicKey>\
</dsig11:ECKeyValue>\
</ds:KeyValue>\
</xenc:OriginatorKeyInfo>\
<xenc:RecipientKeyInfo>\
<ds:X509Data><ds:X509SKI>{ski_b64}</ds:X509SKI></ds:X509Data>\
</xenc:RecipientKeyInfo>\
</xenc:AgreementMethod>\
</ds:KeyInfo>\
<xenc:CipherData><xenc:CipherValue>{wrapped_cek_b64}</xenc:CipherValue></xenc:CipherData>\
</xenc:EncryptedKey>\
</ds:KeyInfo>\
<xenc:CipherData><xenc:CipherValue>{gcm_blob_b64}</xenc:CipherValue></xenc:CipherData>\
</xenc:EncryptedData>"
            )
        }
        other => {
            return Err(AsxError::new(
                ErrorCode::SecurityVerificationFailed,
                format!(
                    "recipient certificate key type {:?} is not supported for XML Encryption; \
                     use an RSA or EC certificate",
                    other
                ),
                ErrorContext::new("wssec_encrypt_payload"),
            ));
        }
    };

    match encapsulation {
        XmlEncEncapsulation::Payload => Ok(encrypted_data_xml.into_bytes()),
        XmlEncEncapsulation::SoapHeader {
            soap_namespace,
            must_understand_token,
        } => Ok(format!(
            "<xenc:EncryptedHeader xmlns:xenc=\"{XENC_NS}\" xmlns:soap=\"{soap_namespace}\" \
             soap:mustUnderstand=\"{must_understand_token}\">{encrypted_data_xml}</xenc:EncryptedHeader>"
        )
        .into_bytes()),
    }
}

fn namespace_is_xenc_or_xenc11(ns: &ResolveResult<'_>) -> bool {
    matches!(ns, ResolveResult::Bound(namespace)
        if namespace.as_ref() == XENC_NS.as_bytes()
        || namespace.as_ref() == XENC11_NS.as_bytes())
}

fn namespace_is_dsig11(ns: &ResolveResult<'_>) -> bool {
    matches!(ns, ResolveResult::Bound(namespace) if namespace.as_ref() == DSIG11_NS.as_bytes())
}

fn tag_kind(ns: &ResolveResult<'_>, local_name: &[u8]) -> XmlEncTag {
    if namespace_is_xenc_or_xenc11(ns) {
        return match local_name {
            b"EncryptedData" => XmlEncTag::EncryptedData,
            b"EncryptedKey" => XmlEncTag::EncryptedKey,
            b"EncryptionMethod" => XmlEncTag::EncryptionMethod,
            b"CipherData" => XmlEncTag::CipherData,
            b"CipherValue" => XmlEncTag::CipherValue,
            b"AgreementMethod" => XmlEncTag::AgreementMethod,
            _ => XmlEncTag::Other,
        };
    }
    if namespace_is_dsig11(ns) && local_name == b"PublicKey" {
        return XmlEncTag::PublicKeyElement;
    }
    XmlEncTag::Other
}

fn element_attribute_value(
    element: &BytesStart<'_>,
    attribute_name: &[u8],
) -> Result<Option<Vec<u8>>> {
    for attribute in element.attributes() {
        let attribute = attribute.map_err(|err| {
            AsxError::new(
                ErrorCode::ParseFailed,
                format!("failed to parse XML Encryption attribute: {err}"),
                ErrorContext::new("wssec_decrypt_payload"),
            )
        })?;
        if attribute.key.as_ref() == attribute_name {
            return Ok(Some(attribute.value.as_ref().to_vec()));
        }
    }
    Ok(None)
}

fn extract_encryption_method_algorithm(element: &BytesStart<'_>) -> Result<Option<Vec<u8>>> {
    element_attribute_value(element, b"Algorithm")
}

fn append_cipher_text(buffer: &mut String, text: &[u8]) -> Result<()> {
    let text = std::str::from_utf8(text).map_err(|_| {
        AsxError::new(
            ErrorCode::ParseFailed,
            "XML Encryption cipher text is not valid UTF-8",
            ErrorContext::new("wssec_decrypt_payload"),
        )
    })?;
    buffer.push_str(text);
    Ok(())
}

fn decode_cipher_value(label: &str, text: &str) -> Result<Vec<u8>> {
    let normalized: String = text
        .chars()
        .filter(|ch| !ch.is_ascii_whitespace())
        .collect();
    if normalized.is_empty() {
        return Err(AsxError::new(
            ErrorCode::ParseFailed,
            format!("XML Encryption payload is missing {label}"),
            ErrorContext::new("wssec_decrypt_payload"),
        ));
    }

    BASE64_STANDARD.decode(normalized).map_err(|err| {
        AsxError::new(
            ErrorCode::ParseFailed,
            format!("failed to decode {label}: {err}"),
            ErrorContext::new("wssec_decrypt_payload"),
        )
    })
}

fn current_cipher_target(stack: &[XmlEncTag]) -> Option<CipherTarget> {
    if stack.contains(&XmlEncTag::EncryptedKey) {
        Some(CipherTarget::WrappedKey)
    } else if stack.contains(&XmlEncTag::EncryptedData) {
        Some(CipherTarget::Payload)
    } else {
        None
    }
}

// ── ECDH-ES helpers ────────────────────────────────────────────────────────

/// Returns the W3C XMLDSig11 `urn:oid:...` curve URI for an EC group's named curve.
/// Supports NIST P-256/P-384/P-521 and BSI Brainpool curves.
fn ec_group_oid_urn(group: &openssl::ec::EcGroupRef) -> Result<&'static str> {
    let nid = group.curve_name().ok_or_else(|| {
        AsxError::new(
            ErrorCode::SecurityVerificationFailed,
            "recipient EC certificate uses an unnamed curve; \
             only named curves are supported for ECDH-ES",
            ErrorContext::new("wssec_encrypt_payload"),
        )
    })?;
    match nid {
        Nid::X9_62_PRIME256V1 => Ok("urn:oid:1.2.840.10045.3.1.7"),
        Nid::SECP384R1 => Ok("urn:oid:1.3.132.0.34"),
        Nid::SECP521R1 => Ok("urn:oid:1.3.132.0.35"),
        _ => match nid.as_raw() {
            // BrainpoolP256r1: NID 927 in OpenSSL 1.1+
            927 => Ok("urn:oid:1.3.36.3.3.2.8.1.1.7"),
            // BrainpoolP384r1
            931 => Ok("urn:oid:1.3.36.3.3.2.8.1.1.11"),
            // BrainpoolP512r1
            933 => Ok("urn:oid:1.3.36.3.3.2.8.1.1.13"),
            raw => Err(AsxError::new(
                ErrorCode::SecurityVerificationFailed,
                format!(
                    "EC curve NID {raw} is not supported for ECDH-ES; \
                     use P-256, P-384, P-521, or BrainpoolP256r1/P384r1/P512r1"
                ),
                ErrorContext::new("wssec_encrypt_payload"),
            )),
        },
    }
}

/// Extract the Subject Key Identifier bytes for the recipient certificate.
/// Uses the SKI extension if present, otherwise computes SHA-1 of the
/// uncompressed EC public key point (RFC 5280 method #1).
fn cert_subject_key_id(cert: &X509Ref) -> Result<Vec<u8>> {
    if let Some(ski) = cert.subject_key_id() {
        return Ok(ski.as_slice().to_vec());
    }
    // Fallback: SHA-1 of the uncompressed EC public key bytes
    let pkey = cert.public_key().map_err(|e| {
        AsxError::new(
            ErrorCode::SecurityVerificationFailed,
            format!("failed to extract public key from recipient cert for SKI: {e}"),
            ErrorContext::new("wssec_encrypt_payload"),
        )
    })?;
    let ec_key = pkey.ec_key().map_err(|e| {
        AsxError::new(
            ErrorCode::SecurityVerificationFailed,
            format!("recipient cert for ECDH-ES must have an EC public key: {e}"),
            ErrorContext::new("wssec_encrypt_payload"),
        )
    })?;
    let group = ec_key.group();
    let mut ctx = openssl::bn::BigNumContext::new().map_err(|e| {
        AsxError::new(
            ErrorCode::SecurityVerificationFailed,
            format!("BN context allocation failed: {e}"),
            ErrorContext::new("wssec_encrypt_payload"),
        )
    })?;
    let pubkey_bytes = ec_key
        .public_key()
        .to_bytes(group, PointConversionForm::UNCOMPRESSED, &mut ctx)
        .map_err(|e| {
            AsxError::new(
                ErrorCode::SecurityVerificationFailed,
                format!("failed to encode EC public key for SKI computation: {e}"),
                ErrorContext::new("wssec_encrypt_payload"),
            )
        })?;
    openssl::hash::hash(MessageDigest::sha1(), &pubkey_bytes)
        .map(|d| d.to_vec())
        .map_err(|e| {
            AsxError::new(
                ErrorCode::SecurityVerificationFailed,
                format!("SHA-1 digest for SKI computation failed: {e}"),
                ErrorContext::new("wssec_encrypt_payload"),
            )
        })
}

/// AES-128 ECB single-block encrypt (no padding).  Used internally by AES Key Wrap.
fn aes_128_ecb_encrypt_block(key: &[u8; 16], block: &[u8; 16]) -> Result<[u8; 16]> {
    let mut c = Crypter::new(Cipher::aes_128_ecb(), Mode::Encrypt, key, None).map_err(|e| {
        AsxError::new(
            ErrorCode::SecurityVerificationFailed,
            format!("AES-KW block encrypt init: {e}"),
            ErrorContext::new("wssec_aes_kw"),
        )
    })?;
    c.pad(false);
    let mut out = [0u8; 32];
    let n1 = c.update(block, &mut out).map_err(|e| {
        AsxError::new(
            ErrorCode::SecurityVerificationFailed,
            format!("AES-KW block encrypt update: {e}"),
            ErrorContext::new("wssec_aes_kw"),
        )
    })?;
    let n2 = c.finalize(&mut out[n1..]).map_err(|e| {
        AsxError::new(
            ErrorCode::SecurityVerificationFailed,
            format!("AES-KW block encrypt finalize: {e}"),
            ErrorContext::new("wssec_aes_kw"),
        )
    })?;
    Ok(out[..n1 + n2][..16]
        .try_into()
        .expect("AES block is 16 bytes"))
}

/// AES-128 ECB single-block decrypt (no padding).  Used internally by AES Key Unwrap.
fn aes_128_ecb_decrypt_block(key: &[u8; 16], block: &[u8; 16]) -> Result<[u8; 16]> {
    let mut c = Crypter::new(Cipher::aes_128_ecb(), Mode::Decrypt, key, None).map_err(|e| {
        AsxError::new(
            ErrorCode::DecryptionFailed,
            format!("AES-KW block decrypt init: {e}"),
            ErrorContext::new("wssec_aes_kw"),
        )
    })?;
    c.pad(false);
    let mut out = [0u8; 32];
    let n1 = c.update(block, &mut out).map_err(|e| {
        AsxError::new(
            ErrorCode::DecryptionFailed,
            format!("AES-KW block decrypt update: {e}"),
            ErrorContext::new("wssec_aes_kw"),
        )
    })?;
    let n2 = c.finalize(&mut out[n1..]).map_err(|e| {
        AsxError::new(
            ErrorCode::DecryptionFailed,
            format!("AES-KW block decrypt finalize: {e}"),
            ErrorContext::new("wssec_aes_kw"),
        )
    })?;
    Ok(out[..n1 + n2][..16]
        .try_into()
        .expect("AES block is 16 bytes"))
}

/// AES-128 Key Wrap (RFC 3394) — wraps `plaintext` (must be a multiple of 8 bytes,
/// minimum 16 bytes) with `kek` (16-byte key-encryption key).
/// Output is `plaintext.len() + 8` bytes.
fn aes_128_key_wrap(kek: &[u8; 16], plaintext: &[u8]) -> Result<Vec<u8>> {
    debug_assert!(plaintext.len() >= 16 && plaintext.len().is_multiple_of(8));
    let n = plaintext.len() / 8;
    // RFC 3394 default IV
    let mut a: [u8; 8] = [0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6];
    let mut r: Vec<[u8; 8]> = plaintext
        .chunks(8)
        .map(|c| c.try_into().expect("8-byte chunk"))
        .collect();

    for j in 0u64..6 {
        for (i, r_block) in r.iter_mut().enumerate() {
            let mut b_in = [0u8; 16];
            b_in[..8].copy_from_slice(&a);
            b_in[8..].copy_from_slice(r_block);
            let b_out = aes_128_ecb_encrypt_block(kek, &b_in)?;
            let t = (n as u64) * j + (i as u64 + 1);
            // A = MSB(64, B) XOR t  (t in big-endian)
            let t_be = t.to_be_bytes();
            a.copy_from_slice(&b_out[..8]);
            for k in 0..8 {
                a[k] ^= t_be[k];
            }
            r_block.copy_from_slice(&b_out[8..]);
        }
    }

    let mut result = Vec::with_capacity(8 + plaintext.len());
    result.extend_from_slice(&a);
    for block in &r {
        result.extend_from_slice(block);
    }
    Ok(result)
}

/// AES-128 Key Unwrap (RFC 3394) — inverse of [`aes_128_key_wrap`].
/// Returns `DecryptionFailed` if the integrity check value does not match.
fn aes_128_key_unwrap(kek: &[u8; 16], ciphertext: &[u8]) -> Result<Vec<u8>> {
    if ciphertext.len() < 24 || !ciphertext.len().is_multiple_of(8) {
        return Err(AsxError::new(
            ErrorCode::DecryptionFailed,
            "AES Key Unwrap: ciphertext too short or not a multiple of 8 bytes",
            ErrorContext::new("wssec_aes_kw"),
        ));
    }
    let n = ciphertext.len() / 8 - 1;
    let mut a: [u8; 8] = ciphertext[..8].try_into().expect("8-byte slice");
    let mut r: Vec<[u8; 8]> = ciphertext[8..]
        .chunks(8)
        .map(|c| c.try_into().expect("8-byte chunk"))
        .collect();

    for j in (0u64..6).rev() {
        for i in (0..n).rev() {
            let t = (n as u64) * j + (i as u64 + 1);
            let t_be = t.to_be_bytes();
            let mut a_xored = a;
            for k in 0..8 {
                a_xored[k] ^= t_be[k];
            }
            let mut b_in = [0u8; 16];
            b_in[..8].copy_from_slice(&a_xored);
            b_in[8..].copy_from_slice(&r[i]);
            let b_out = aes_128_ecb_decrypt_block(kek, &b_in)?;
            a.copy_from_slice(&b_out[..8]);
            r[i].copy_from_slice(&b_out[8..]);
        }
    }

    const RFC3394_IV: [u8; 8] = [0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6];
    if a != RFC3394_IV {
        return Err(AsxError::new(
            ErrorCode::DecryptionFailed,
            "AES Key Unwrap integrity check failed: wrong KEK or corrupt wrapped key",
            ErrorContext::new("wssec_decrypt_payload"),
        ));
    }

    let mut result = Vec::with_capacity(n * 8);
    for block in &r {
        result.extend_from_slice(block);
    }
    Ok(result)
}

/// ConcatKDF (NIST SP 800-56A, one-pass DH, single iteration for \u2264256-bit output).
///
/// Hash input: `counter(4B BE=1) || Z || keydatalen(4B BE, bits)
///             || len(AlgorithmID)(4B BE) || AlgorithmID
///             || len(PartyUInfo)(4B BE)  || PartyUInfo
///             || len(PartyVInfo)(4B BE)  || PartyVInfo`
///
/// Returns a 32-byte (256-bit) SHA-256 digest; the caller takes `[..keydatalen_bits/8]`.
fn concat_kdf_sha256(
    z: &[u8],
    keydatalen_bits: u32,
    algorithm_id: &[u8],
    party_u_info: &[u8],
    party_v_info: &[u8],
) -> [u8; 32] {
    let mut input: Vec<u8> = Vec::with_capacity(
        4 + z.len() + 4 + 4 + algorithm_id.len() + 4 + party_u_info.len() + 4 + party_v_info.len(),
    );
    input.extend_from_slice(&1u32.to_be_bytes()); // counter = 1
    input.extend_from_slice(z);
    input.extend_from_slice(&keydatalen_bits.to_be_bytes());
    input.extend_from_slice(&(algorithm_id.len() as u32).to_be_bytes());
    input.extend_from_slice(algorithm_id);
    input.extend_from_slice(&(party_u_info.len() as u32).to_be_bytes());
    input.extend_from_slice(party_u_info);
    input.extend_from_slice(&(party_v_info.len() as u32).to_be_bytes());
    input.extend_from_slice(party_v_info);

    let digest =
        openssl::hash::hash(MessageDigest::sha256(), &input).expect("SHA-256 is always available");
    digest.as_ref().try_into().expect("SHA-256 is 32 bytes")
}

/// Compute the ECDH shared secret between `private_key` and `peer_public_key`.
fn ecdh_shared_secret(
    private_key: &openssl::pkey::PKeyRef<openssl::pkey::Private>,
    peer_public_key: &openssl::pkey::PKeyRef<openssl::pkey::Public>,
) -> Result<Vec<u8>> {
    let mut deriver = Deriver::new(private_key).map_err(|e| {
        AsxError::new(
            ErrorCode::SecurityVerificationFailed,
            format!("ECDH deriver init failed: {e}"),
            ErrorContext::new("wssec_encrypt_payload"),
        )
    })?;
    deriver.set_peer(peer_public_key).map_err(|e| {
        AsxError::new(
            ErrorCode::SecurityVerificationFailed,
            format!("ECDH set_peer failed: {e}"),
            ErrorContext::new("wssec_encrypt_payload"),
        )
    })?;
    deriver.derive_to_vec().map_err(|e| {
        AsxError::new(
            ErrorCode::SecurityVerificationFailed,
            format!("ECDH shared secret derivation failed: {e}"),
            ErrorContext::new("wssec_encrypt_payload"),
        )
    })
}

/// Decrypt an XML Encryption payload (`<xenc:EncryptedData>`) using the
/// recipient's private RSA key.
///
/// # Cancel Safety
///
/// This function is **synchronous** and not cancel-safe.  When invoked from a
/// `tokio::task::spawn_blocking` closure, cancelling the outer Tokio task does
/// **not** interrupt the blocking thread — RSA key-unwrap and AES payload
/// decryption run to completion regardless of task cancellation.
///
/// Do not call this function directly from an async context; always dispatch via
/// `tokio::task::spawn_blocking` or an equivalent executor thread.
/// Decrypt AES-GCM ciphertext (shared by RSA-OAEP and ECDH-ES paths).
fn decrypt_aes_gcm_payload(
    inbound_algo: InboundDataAlgorithm,
    aes_key: &[u8],
    cipher_blob: &[u8],
) -> Result<Vec<u8>> {
    if cipher_blob.len() < 28 {
        return Err(AsxError::new(
            ErrorCode::DecryptionFailed,
            "AES-GCM ciphertext blob is too short (need nonce + tag)",
            ErrorContext::new("wssec_decrypt_payload"),
        ));
    }
    let _ = inbound_algo; // algorithm already validated before calling
    let nonce_bytes: [u8; 12] = cipher_blob[..12].try_into().expect("12 bytes");
    let nonce = aes_gcm::Nonce::from(nonce_bytes);
    let aead_err = |_| {
        AsxError::new(
            ErrorCode::DecryptionFailed,
            "failed to decrypt AES-GCM ciphertext: authentication tag mismatch or corrupt data",
            ErrorContext::new("wssec_decrypt_payload"),
        )
    };
    match aes_key.len() {
        16 => Aes128Gcm::new_from_slice(aes_key)
            .expect("key length pre-validated")
            .decrypt(&nonce, &cipher_blob[12..])
            .map_err(aead_err),
        32 => Aes256Gcm::new_from_slice(aes_key)
            .expect("key length pre-validated")
            .decrypt(&nonce, &cipher_blob[12..])
            .map_err(aead_err),
        other => Err(AsxError::new(
            ErrorCode::DecryptionFailed,
            format!("unsupported XML Encryption content key length: {other} (expected 16 or 32)"),
            ErrorContext::new("wssec_decrypt_payload"),
        )),
    }
}

/// Decode a `ConcatKDFParams` attribute value (base64-encoded octet string or
/// empty string) into raw bytes.  Empty string maps to empty `Vec<u8>`.
fn decode_concat_kdf_param_bytes(raw: &[u8]) -> Vec<u8> {
    let trimmed: Vec<u8> = raw
        .iter()
        .copied()
        .filter(|b| !b.is_ascii_whitespace())
        .collect();
    if trimmed.is_empty() {
        return Vec::new();
    }
    BASE64_STANDARD.decode(&trimmed).unwrap_or(trimmed)
}

pub fn decrypt_payload_xmlenc(
    encrypted_payload_xml: &[u8],
    recipient_key_pem: &[u8],
) -> Result<Vec<u8>> {
    let mut reader = NsReader::from_reader(encrypted_payload_xml);
    reader.config_mut().trim_text(true);

    let mut started = false;
    let mut stack: Vec<XmlEncTag> = Vec::new();
    let mut data_algorithm: Option<Vec<u8>> = None;
    let mut key_algorithm: Option<Vec<u8>> = None;
    let mut wrapped_key_text = String::new();
    let mut payload_cipher_text = String::new();
    let mut active_cipher_target: Option<CipherTarget> = None;
    // ECDH-ES state
    let mut agreement_algorithm: Option<Vec<u8>> = None;
    let mut originator_pubkey_text = String::new();
    let mut active_reading_originator_pubkey = false;
    let mut originator_curve_oid_urn: Option<String> = None;
    let mut concat_kdf_algid: Vec<u8> = Vec::new();
    let mut concat_kdf_party_u: Vec<u8> = Vec::new();
    let mut concat_kdf_party_v: Vec<u8> = Vec::new();

    loop {
        let (ns, event) = reader.read_resolved_event().map_err(|err| {
            AsxError::new(
                ErrorCode::ParseFailed,
                format!("failed to stream XML Encryption payload: {err}"),
                ErrorContext::new("wssec_decrypt_payload"),
            )
        })?;

        match event {
            Event::Start(element) => {
                let kind = tag_kind(&ns, element.local_name().as_ref());
                if !started {
                    if kind != XmlEncTag::EncryptedData {
                        continue;
                    }
                    started = true;
                }

                if kind == XmlEncTag::EncryptionMethod {
                    match stack.last().copied() {
                        Some(XmlEncTag::EncryptedData) => {
                            data_algorithm = extract_encryption_method_algorithm(&element)?;
                        }
                        _ if stack.contains(&XmlEncTag::EncryptedKey)
                            && !stack.contains(&XmlEncTag::AgreementMethod) =>
                        {
                            key_algorithm = extract_encryption_method_algorithm(&element)?;
                        }
                        _ => {}
                    }
                }

                if kind == XmlEncTag::AgreementMethod {
                    agreement_algorithm = element_attribute_value(&element, b"Algorithm")?;
                }

                if kind == XmlEncTag::PublicKeyElement {
                    active_reading_originator_pubkey = true;
                }

                // Parse ConcatKDFParams attributes (xenc11 namespace, local name ConcatKDFParams).
                if namespace_is_xenc_or_xenc11(&ns)
                    && element.local_name().as_ref() == b"ConcatKDFParams"
                {
                    if let Some(v) = element_attribute_value(&element, b"AlgorithmID")? {
                        concat_kdf_algid = decode_concat_kdf_param_bytes(&v);
                    }
                    if let Some(v) = element_attribute_value(&element, b"PartyUInfo")? {
                        concat_kdf_party_u = decode_concat_kdf_param_bytes(&v);
                    }
                    if let Some(v) = element_attribute_value(&element, b"PartyVInfo")? {
                        concat_kdf_party_v = decode_concat_kdf_param_bytes(&v);
                    }
                }

                if kind == XmlEncTag::CipherValue {
                    active_cipher_target = current_cipher_target(&stack);
                    if active_cipher_target.is_none() {
                        return Err(AsxError::new(
                            ErrorCode::ParseFailed,
                            "XML Encryption CipherValue is not nested under EncryptedData or EncryptedKey",
                            ErrorContext::new("wssec_decrypt_payload"),
                        ));
                    }
                }

                stack.push(kind);
            }
            Event::Empty(element) => {
                let kind = tag_kind(&ns, element.local_name().as_ref());
                if !started {
                    if kind != XmlEncTag::EncryptedData {
                        continue;
                    }
                    started = true;
                }

                if kind == XmlEncTag::EncryptionMethod {
                    match stack.last().copied() {
                        Some(XmlEncTag::EncryptedData) => {
                            data_algorithm = extract_encryption_method_algorithm(&element)?;
                        }
                        _ if stack.contains(&XmlEncTag::EncryptedKey)
                            && !stack.contains(&XmlEncTag::AgreementMethod) =>
                        {
                            key_algorithm = extract_encryption_method_algorithm(&element)?;
                        }
                        _ => {}
                    }
                }

                if kind == XmlEncTag::AgreementMethod {
                    agreement_algorithm = element_attribute_value(&element, b"Algorithm")?;
                }

                if kind == XmlEncTag::CipherValue {
                    return Err(AsxError::new(
                        ErrorCode::ParseFailed,
                        "XML Encryption CipherValue cannot be empty",
                        ErrorContext::new("wssec_decrypt_payload"),
                    ));
                }

                // dsig11:NamedCurve — carries the originator curve OID URN.
                if namespace_is_dsig11(&ns)
                    && element.local_name().as_ref() == b"NamedCurve"
                    && let Some(uri) = element_attribute_value(&element, b"URI")?
                {
                    originator_curve_oid_urn = Some(String::from_utf8_lossy(&uri).into_owned());
                }

                // ConcatKDFParams (self-closing variant).
                if namespace_is_xenc_or_xenc11(&ns)
                    && element.local_name().as_ref() == b"ConcatKDFParams"
                {
                    if let Some(v) = element_attribute_value(&element, b"AlgorithmID")? {
                        concat_kdf_algid = decode_concat_kdf_param_bytes(&v);
                    }
                    if let Some(v) = element_attribute_value(&element, b"PartyUInfo")? {
                        concat_kdf_party_u = decode_concat_kdf_param_bytes(&v);
                    }
                    if let Some(v) = element_attribute_value(&element, b"PartyVInfo")? {
                        concat_kdf_party_v = decode_concat_kdf_param_bytes(&v);
                    }
                }

                stack.push(kind);
                stack.pop();
            }
            Event::Text(text) => {
                if active_reading_originator_pubkey {
                    append_cipher_text(&mut originator_pubkey_text, text.as_ref())?;
                } else if let Some(target) = active_cipher_target {
                    match target {
                        CipherTarget::WrappedKey => {
                            append_cipher_text(&mut wrapped_key_text, text.as_ref())?
                        }
                        CipherTarget::Payload => {
                            append_cipher_text(&mut payload_cipher_text, text.as_ref())?
                        }
                    }
                }
            }
            Event::CData(text) => {
                if active_reading_originator_pubkey {
                    append_cipher_text(&mut originator_pubkey_text, text.as_ref())?;
                } else if let Some(target) = active_cipher_target {
                    match target {
                        CipherTarget::WrappedKey => {
                            append_cipher_text(&mut wrapped_key_text, text.as_ref())?
                        }
                        CipherTarget::Payload => {
                            append_cipher_text(&mut payload_cipher_text, text.as_ref())?
                        }
                    }
                }
            }
            Event::End(_) => {
                if !started {
                    continue;
                }

                let kind = stack.pop().unwrap_or(XmlEncTag::Other);
                if kind == XmlEncTag::PublicKeyElement {
                    active_reading_originator_pubkey = false;
                }
                if kind == XmlEncTag::CipherValue {
                    active_cipher_target = None;
                }
                if kind == XmlEncTag::EncryptedData {
                    break;
                }
            }
            Event::Comment(_)
            | Event::Decl(_)
            | Event::PI(_)
            | Event::DocType(_)
            | Event::GeneralRef(_) => {}
            Event::Eof => break,
        }
    }

    let data_algorithm = data_algorithm.ok_or_else(|| {
        AsxError::new(
            ErrorCode::ParseFailed,
            "XML Encryption payload is missing xenc:EncryptedData/xenc:EncryptionMethod",
            ErrorContext::new("wssec_decrypt_payload"),
        )
    })?;
    let data_algorithm = std::str::from_utf8(&data_algorithm).map_err(|_| {
        AsxError::new(
            ErrorCode::ParseFailed,
            "XML Encryption payload contains a non-UTF8 data encryption algorithm URI",
            ErrorContext::new("wssec_decrypt_payload"),
        )
    })?;
    let inbound_algo = match data_algorithm {
        XENC11_AES128_GCM_URI => InboundDataAlgorithm::Aes128Gcm,
        XENC11_AES256_GCM_URI => InboundDataAlgorithm::Aes256Gcm,
        other => {
            return Err(AsxError::new(
                ErrorCode::DecryptionFailed,
                format!(
                    "unsupported XML Encryption data algorithm: {other} \
                     (supported: AES-128-GCM, AES-256-GCM)"
                ),
                ErrorContext::new("wssec_decrypt_payload"),
            ));
        }
    };

    let key_algorithm = key_algorithm.ok_or_else(|| {
        AsxError::new(
            ErrorCode::ParseFailed,
            "XML Encryption payload is missing xenc:EncryptedKey/xenc:EncryptionMethod",
            ErrorContext::new("wssec_decrypt_payload"),
        )
    })?;
    let key_algorithm = std::str::from_utf8(&key_algorithm).map_err(|_| {
        AsxError::new(
            ErrorCode::ParseFailed,
            "XML Encryption payload contains a non-UTF8 key transport algorithm URI",
            ErrorContext::new("wssec_decrypt_payload"),
        )
    })?;

    match key_algorithm {
        XENC11_RSA_OAEP_URI => {
            // RSA-OAEP key transport (PEPPOL / CEF eDelivery AS4 profile).
            let wrapped_key = decode_cipher_value("wrapped XML Encryption key", &wrapped_key_text)?;
            let cipher_blob =
                decode_cipher_value("XML Encryption ciphertext", &payload_cipher_text)?;

            let pkey = PKey::private_key_from_pem(recipient_key_pem).map_err(|err| {
                AsxError::new(
                    ErrorCode::DecryptionFailed,
                    format!("failed to parse XML Encryption recipient private key: {err}"),
                    ErrorContext::new("wssec_decrypt_payload"),
                )
            })?;
            let mut decrypter = Decrypter::new(&pkey).map_err(|err| {
                AsxError::new(
                    ErrorCode::DecryptionFailed,
                    format!("failed to create RSA decrypter: {err}"),
                    ErrorContext::new("wssec_decrypt_payload"),
                )
            })?;
            decrypter
                .set_rsa_padding(Padding::PKCS1_OAEP)
                .map_err(|err| {
                    AsxError::new(
                        ErrorCode::DecryptionFailed,
                        format!("failed to set RSA-OAEP padding: {err}"),
                        ErrorContext::new("wssec_decrypt_payload"),
                    )
                })?;
            decrypter
                .set_rsa_oaep_md(MessageDigest::sha256())
                .map_err(|err| {
                    AsxError::new(
                        ErrorCode::DecryptionFailed,
                        format!("failed to set RSA-OAEP SHA-256 digest: {err}"),
                        ErrorContext::new("wssec_decrypt_payload"),
                    )
                })?;
            decrypter
                .set_rsa_mgf1_md(MessageDigest::sha256())
                .map_err(|err| {
                    AsxError::new(
                        ErrorCode::DecryptionFailed,
                        format!("failed to set RSA MGF1-SHA-256 digest: {err}"),
                        ErrorContext::new("wssec_decrypt_payload"),
                    )
                })?;
            let buf_len = decrypter.decrypt_len(&wrapped_key).map_err(|err| {
                AsxError::new(
                    ErrorCode::DecryptionFailed,
                    format!("failed to compute decrypted key buffer length: {err}"),
                    ErrorContext::new("wssec_decrypt_payload"),
                )
            })?;
            let mut aes_key = vec![0u8; buf_len];
            let key_len = decrypter
                .decrypt(&wrapped_key, &mut aes_key)
                .map_err(|err| {
                    AsxError::new(
                        ErrorCode::DecryptionFailed,
                        format!(
                            "failed to unwrap XML Encryption content key (OAEP/MGF1-SHA256): {err}"
                        ),
                        ErrorContext::new("wssec_decrypt_payload"),
                    )
                })?;
            aes_key.truncate(key_len);

            decrypt_aes_gcm_payload(inbound_algo, &aes_key, &cipher_blob)
        }

        KW_AES128_URI => {
            // ECDH-ES key agreement + AES-128 Key Wrap (BSI TR-03116-3 §9.2).
            let agreement_alg = agreement_algorithm
                .as_deref()
                .and_then(|b| std::str::from_utf8(b).ok())
                .unwrap_or("");
            if agreement_alg != ECDH_ES_URI {
                return Err(AsxError::new(
                    ErrorCode::DecryptionFailed,
                    format!(
                        "kw-aes128 key transport requires ECDH-ES key agreement \
                         (xenc:AgreementMethod Algorithm=\"{ECDH_ES_URI}\") but got \"{agreement_alg}\""
                    ),
                    ErrorContext::new("wssec_decrypt_payload"),
                ));
            }
            let _ = originator_curve_oid_urn; // informational only, not needed for decryption

            let originator_pubkey_b64 = originator_pubkey_text.trim().to_string();
            if originator_pubkey_b64.is_empty() {
                return Err(AsxError::new(
                    ErrorCode::ParseFailed,
                    "ECDH-ES XML Encryption is missing the originator ephemeral public key \
                     (dsig11:PublicKey)",
                    ErrorContext::new("wssec_decrypt_payload"),
                ));
            }
            let originator_pubkey_bytes =
                decode_cipher_value("originator EC public key", &originator_pubkey_b64)?;

            // Load recipient private key.
            let pkey = PKey::private_key_from_pem(recipient_key_pem).map_err(|err| {
                AsxError::new(
                    ErrorCode::DecryptionFailed,
                    format!("failed to parse ECDH-ES recipient private key: {err}"),
                    ErrorContext::new("wssec_decrypt_payload"),
                )
            })?;
            if pkey.id() != openssl::pkey::Id::EC {
                return Err(AsxError::new(
                    ErrorCode::DecryptionFailed,
                    "ECDH-ES decryption requires an EC private key; \
                     the configured inbound_decryption_key_pem is not an EC key",
                    ErrorContext::new("wssec_decrypt_payload"),
                ));
            }
            let recipient_ec = pkey.ec_key().map_err(|err| {
                AsxError::new(
                    ErrorCode::DecryptionFailed,
                    format!("failed to extract EC key from recipient private key: {err}"),
                    ErrorContext::new("wssec_decrypt_payload"),
                )
            })?;
            let group = recipient_ec.group();

            // Parse originator ephemeral EC public key.
            let mut bn_ctx = openssl::bn::BigNumContext::new().map_err(|err| {
                AsxError::new(
                    ErrorCode::DecryptionFailed,
                    format!("BN context allocation failed: {err}"),
                    ErrorContext::new("wssec_decrypt_payload"),
                )
            })?;
            let originator_point =
                EcPoint::from_bytes(group, &originator_pubkey_bytes, &mut bn_ctx).map_err(
                    |err| {
                        AsxError::new(
                            ErrorCode::DecryptionFailed,
                            format!("failed to parse originator ephemeral EC public key: {err}"),
                            ErrorContext::new("wssec_decrypt_payload"),
                        )
                    },
                )?;
            let originator_ec_key =
                EcKey::from_public_key(group, &originator_point).map_err(|err| {
                    AsxError::new(
                        ErrorCode::DecryptionFailed,
                        format!("failed to construct originator EC public key: {err}"),
                        ErrorContext::new("wssec_decrypt_payload"),
                    )
                })?;
            let originator_pkey = PKey::from_ec_key(originator_ec_key).map_err(|err| {
                AsxError::new(
                    ErrorCode::DecryptionFailed,
                    format!("failed to wrap originator EC key: {err}"),
                    ErrorContext::new("wssec_decrypt_payload"),
                )
            })?;

            // Compute ECDH shared secret: recipient private × originator public.
            let mut z = ecdh_shared_secret(&pkey, &originator_pkey)?;

            // ConcatKDF (NIST SP 800-56A) → 128-bit key-encryption key.
            let kdf_output = concat_kdf_sha256(
                &z,
                128,
                &concat_kdf_algid,
                &concat_kdf_party_u,
                &concat_kdf_party_v,
            );
            let kek: [u8; 16] = kdf_output[..16].try_into().expect("16-byte slice");
            // Zeroize shared secret immediately after KDF.
            use zeroize::Zeroize as _;
            z.zeroize();

            // Unwrap the content-encryption key.
            let wrapped_key_bytes = decode_cipher_value("wrapped AES key", &wrapped_key_text)?;
            let aes_key = aes_128_key_unwrap(&kek, &wrapped_key_bytes)?;

            let cipher_blob =
                decode_cipher_value("XML Encryption ciphertext", &payload_cipher_text)?;
            decrypt_aes_gcm_payload(inbound_algo, &aes_key, &cipher_blob)
        }

        other => Err(AsxError::new(
            ErrorCode::DecryptionFailed,
            format!(
                "unsupported XML Encryption key transport algorithm: {other} \
                 (accepted: {XENC11_RSA_OAEP_URI}, {KW_AES128_URI})"
            ),
            ErrorContext::new("wssec_decrypt_payload"),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decrypt_payload_xmlenc_skips_comments_and_processing_instructions() {
        let cert_pem = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/pki/receipt_signing.cert.pem"
        ));
        let key_pem = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/pki/receipt_signing.key.pem"
        ));

        let ciphertext =
            encrypt_payload_xmlenc(b"payload", cert_pem, XmlEncPayloadAlgorithm::Aes256Gcm)
                .expect("encrypt");
        let ciphertext = String::from_utf8(ciphertext).expect("utf8");
        let wrapped = format!("<?xml version=\"1.0\"?>\n<!--noise-->{ciphertext}<!--more-noise-->");

        let plaintext = decrypt_payload_xmlenc(wrapped.as_bytes(), key_pem).expect("decrypt");
        assert_eq!(plaintext, b"payload");
    }

    #[test]
    fn decrypt_payload_xmlenc_is_prefix_agnostic() {
        let cert_pem = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/pki/receipt_signing.cert.pem"
        ));
        let key_pem = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/pki/receipt_signing.key.pem"
        ));

        let ciphertext =
            encrypt_payload_xmlenc(b"payload", cert_pem, XmlEncPayloadAlgorithm::Aes128Gcm)
                .expect("encrypt");
        let ciphertext = String::from_utf8(ciphertext).expect("utf8");
        let renamed = ciphertext
            .replace(
                "xmlns:xenc=\"http://www.w3.org/2001/04/xmlenc#\"",
                "xmlns:e=\"http://www.w3.org/2001/04/xmlenc#\"",
            )
            .replace(
                "xmlns:xenc11=\"http://www.w3.org/2009/xmlenc11#\"",
                "xmlns:e11=\"http://www.w3.org/2009/xmlenc11#\"",
            )
            .replace(
                "xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"",
                "xmlns:s=\"http://www.w3.org/2000/09/xmldsig#\"",
            )
            .replace("xenc11:", "e11:")
            .replace("xenc:", "e:")
            .replace("ds:", "s:");

        let plaintext = decrypt_payload_xmlenc(renamed.as_bytes(), key_pem).expect("decrypt");
        assert_eq!(plaintext, b"payload");
    }

    #[test]
    fn decrypt_payload_xmlenc_rejects_legacy_key_transport_algorithm() {
        let cert_pem = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/pki/receipt_signing.cert.pem"
        ));
        let key_pem = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/pki/receipt_signing.key.pem"
        ));

        let ciphertext =
            encrypt_payload_xmlenc(b"payload", cert_pem, XmlEncPayloadAlgorithm::Aes128Gcm)
                .expect("encrypt");
        let tampered = String::from_utf8(ciphertext).expect("utf8").replace(
            "http://www.w3.org/2009/xmlenc11#rsa-oaep",
            "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p",
        );

        let err = decrypt_payload_xmlenc(tampered.as_bytes(), key_pem)
            .expect_err("legacy key transport must be rejected");
        assert_eq!(err.code, ErrorCode::DecryptionFailed);
        assert!(
            err.message
                .contains("unsupported XML Encryption key transport algorithm"),
            "unexpected error: {}",
            err.message
        );
    }

    #[test]
    fn decrypt_payload_xmlenc_rejects_legacy_data_encryption_algorithm() {
        let cert_pem = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/pki/receipt_signing.cert.pem"
        ));
        let key_pem = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/pki/receipt_signing.key.pem"
        ));

        let ciphertext =
            encrypt_payload_xmlenc(b"payload", cert_pem, XmlEncPayloadAlgorithm::Aes128Gcm)
                .expect("encrypt");
        let tampered = String::from_utf8(ciphertext).expect("utf8").replace(
            "http://www.w3.org/2009/xmlenc11#aes128-gcm",
            "http://www.w3.org/2001/04/xmlenc#aes256-cbc",
        );

        let err = decrypt_payload_xmlenc(tampered.as_bytes(), key_pem)
            .expect_err("legacy data encryption algorithm must be rejected");
        assert_eq!(err.code, ErrorCode::DecryptionFailed);
        assert!(
            err.message
                .contains("unsupported XML Encryption data algorithm"),
            "unexpected error: {}",
            err.message
        );
    }

    #[test]
    fn ecdh_es_aes128gcm_roundtrip_p256() {
        // Generate an ephemeral P-256 EC keypair for the recipient.
        let group = openssl::ec::EcGroup::from_curve_name(openssl::nid::Nid::X9_62_PRIME256V1)
            .expect("P-256 group");
        let ec_key = openssl::ec::EcKey::generate(&group).expect("ec key");
        let pkey = openssl::pkey::PKey::from_ec_key(ec_key).expect("pkey");

        // Self-sign into a minimal cert so we can use it as recipient_cert.
        let cert = build_test_ec_cert(&pkey);
        let cert_pem = cert.to_pem().expect("cert pem");
        let key_pem = pkey.private_key_to_pem_pkcs8().expect("key pem");

        let plaintext = b"ECDH-ES AES-128-GCM test payload";

        // Encrypt using the EC recipient cert — should auto-dispatch to ECDH-ES.
        let ciphertext =
            encrypt_payload_xmlenc(plaintext, &cert_pem, XmlEncPayloadAlgorithm::Aes128Gcm)
                .expect("encrypt");

        let xml = String::from_utf8(ciphertext.clone()).expect("utf8");
        assert!(xml.contains("ECDH-ES"), "must use ECDH-ES key agreement");
        assert!(
            xml.contains("ConcatKDF"),
            "must use ConcatKDF key derivation"
        );
        assert!(xml.contains("kw-aes128"), "must use AES-128 Key Wrap");
        assert!(
            xml.contains("aes128-gcm"),
            "must use AES-128-GCM payload enc"
        );
        assert!(xml.contains("X509SKI"), "must reference recipient by SKI");

        // Decrypt and verify round-trip.
        let decrypted = decrypt_payload_xmlenc(&ciphertext, &key_pem).expect("decrypt");
        assert_eq!(
            decrypted, plaintext,
            "ECDH-ES roundtrip must recover plaintext"
        );
    }

    #[test]
    fn ecdh_es_aes256gcm_roundtrip_p256() {
        let group = openssl::ec::EcGroup::from_curve_name(openssl::nid::Nid::X9_62_PRIME256V1)
            .expect("P-256 group");
        let ec_key = openssl::ec::EcKey::generate(&group).expect("ec key");
        let pkey = openssl::pkey::PKey::from_ec_key(ec_key).expect("pkey");
        let cert = build_test_ec_cert(&pkey);
        let cert_pem = cert.to_pem().expect("cert pem");
        let key_pem = pkey.private_key_to_pem_pkcs8().expect("key pem");

        let plaintext = b"AES-256-GCM with ECDH-ES";
        let ciphertext =
            encrypt_payload_xmlenc(plaintext, &cert_pem, XmlEncPayloadAlgorithm::Aes256Gcm)
                .expect("encrypt");

        // AES-256-GCM payload encryption, but still ECDH-ES + kw-aes128 key agreement.
        let xml = String::from_utf8(ciphertext.clone()).expect("utf8");
        assert!(
            xml.contains("aes256-gcm"),
            "payload algo must be AES-256-GCM"
        );
        assert!(
            xml.contains("kw-aes128"),
            "key wrap stays AES-128 regardless of payload algo"
        );

        let decrypted = decrypt_payload_xmlenc(&ciphertext, &key_pem).expect("decrypt");
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn ecdh_es_prefix_agnostic_roundtrip() {
        let group = openssl::ec::EcGroup::from_curve_name(openssl::nid::Nid::X9_62_PRIME256V1)
            .expect("P-256 group");
        let ec_key = openssl::ec::EcKey::generate(&group).expect("ec key");
        let pkey = openssl::pkey::PKey::from_ec_key(ec_key).expect("pkey");
        let cert = build_test_ec_cert(&pkey);
        let cert_pem = cert.to_pem().expect("cert pem");
        let key_pem = pkey.private_key_to_pem_pkcs8().expect("key pem");

        let plaintext = b"prefix-agnostic ECDH-ES";
        let ciphertext =
            encrypt_payload_xmlenc(plaintext, &cert_pem, XmlEncPayloadAlgorithm::Aes128Gcm)
                .expect("encrypt");

        // Rename XML namespace prefixes — the parser must still decode correctly.
        let renamed = String::from_utf8(ciphertext)
            .expect("utf8")
            .replace(
                "xmlns:xenc=\"http://www.w3.org/2001/04/xmlenc#\"",
                "xmlns:e=\"http://www.w3.org/2001/04/xmlenc#\"",
            )
            .replace(
                "xmlns:xenc11=\"http://www.w3.org/2009/xmlenc11#\"",
                "xmlns:e11=\"http://www.w3.org/2009/xmlenc11#\"",
            )
            .replace(
                "xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"",
                "xmlns:s=\"http://www.w3.org/2000/09/xmldsig#\"",
            )
            .replace(
                "xmlns:dsig11=\"http://www.w3.org/2009/xmldsig11#\"",
                "xmlns:d11=\"http://www.w3.org/2009/xmldsig11#\"",
            )
            .replace("xenc11:", "e11:")
            .replace("xenc:", "e:")
            .replace("dsig11:", "d11:")
            .replace("ds:", "s:");

        let decrypted = decrypt_payload_xmlenc(renamed.as_bytes(), &key_pem)
            .expect("prefix-renamed ECDH-ES must still decrypt");
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn rsa_recipient_still_uses_rsa_oaep() {
        // RSA recipient cert must continue using the existing RSA-OAEP path.
        let cert_pem = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/pki/receipt_signing.cert.pem"
        ));
        let key_pem = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/pki/receipt_signing.key.pem"
        ));

        let plaintext = b"RSA recipient must still use RSA-OAEP";
        let ciphertext =
            encrypt_payload_xmlenc(plaintext, cert_pem, XmlEncPayloadAlgorithm::Aes128Gcm)
                .expect("encrypt");

        let xml = String::from_utf8(ciphertext.clone()).expect("utf8");
        assert!(xml.contains("rsa-oaep"), "RSA cert must use RSA-OAEP");
        assert!(!xml.contains("ECDH-ES"), "RSA cert must NOT use ECDH-ES");

        let decrypted = decrypt_payload_xmlenc(&ciphertext, key_pem).expect("decrypt");
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn aes_128_key_wrap_roundtrip() {
        let kek = [0x42u8; 16];
        let cek = [0x13u8; 16]; // 128-bit CEK

        let wrapped = aes_128_key_wrap(&kek, &cek).expect("wrap");
        assert_eq!(
            wrapped.len(),
            24,
            "wrapped 128-bit key must be 24 bytes (RFC 3394)"
        );

        let unwrapped = aes_128_key_unwrap(&kek, &wrapped).expect("unwrap");
        assert_eq!(
            unwrapped,
            cek.as_slice(),
            "unwrap must recover original CEK"
        );
    }

    #[test]
    fn aes_128_key_wrap_wrong_kek_fails() {
        let kek = [0x42u8; 16];
        let wrong_kek = [0xFFu8; 16];
        let cek = [0x13u8; 16];

        let wrapped = aes_128_key_wrap(&kek, &cek).expect("wrap");
        let err = aes_128_key_unwrap(&wrong_kek, &wrapped)
            .expect_err("wrong KEK must fail integrity check");
        assert_eq!(err.code, ErrorCode::DecryptionFailed);
        assert!(
            err.message.contains("integrity check failed"),
            "{}",
            err.message
        );
    }

    /// Build a minimal self-signed EC certificate for testing key wrap/ECDH-ES.
    fn build_test_ec_cert(
        pkey: &openssl::pkey::PKeyRef<openssl::pkey::Private>,
    ) -> openssl::x509::X509 {
        use openssl::asn1::Asn1Time;
        use openssl::hash::MessageDigest;
        use openssl::x509::{X509, X509NameBuilder, extension::BasicConstraints};

        let mut name = X509NameBuilder::new().expect("name builder");
        name.append_entry_by_text("CN", "xmlenc-test").expect("CN");
        let name = name.build();

        let mut builder = X509::builder().expect("X509 builder");
        builder.set_version(2).expect("version");
        builder.set_subject_name(&name).expect("subject");
        builder.set_issuer_name(&name).expect("issuer");
        builder
            .set_not_before(&Asn1Time::days_from_now(0).expect("nb"))
            .expect("set_not_before");
        builder
            .set_not_after(&Asn1Time::days_from_now(365).expect("na"))
            .expect("set_not_after");
        builder.set_pubkey(pkey).expect("pubkey");
        let bc = BasicConstraints::new().critical().build().expect("bc");
        builder.append_extension(bc).expect("bc ext");
        builder.sign(pkey, MessageDigest::sha256()).expect("sign");
        builder.build()
    }

    /// BDEW mandatory curve — BrainpoolP256r1 (NID 927).
    #[test]
    fn ecdh_es_roundtrip_brainpool_p256r1() {
        // BrainpoolP256r1 NID is 927 in OpenSSL 1.1+.
        let nid = openssl::nid::Nid::from_raw(927);
        let group = openssl::ec::EcGroup::from_curve_name(nid).expect("BrainpoolP256r1 group");
        let ec_key = openssl::ec::EcKey::generate(&group).expect("ec key");
        let pkey = openssl::pkey::PKey::from_ec_key(ec_key).expect("pkey");
        let cert = build_test_ec_cert(&pkey);
        let cert_pem = cert.to_pem().expect("cert pem");
        let key_pem = pkey.private_key_to_pem_pkcs8().expect("key pem");

        let plaintext = b"BDEW BrainpoolP256r1 ECDH-ES roundtrip";
        let ciphertext =
            encrypt_payload_xmlenc(plaintext, &cert_pem, XmlEncPayloadAlgorithm::Aes128Gcm)
                .expect("encrypt with BrainpoolP256r1");

        let xml = String::from_utf8(ciphertext.clone()).expect("utf8");
        // Verify the correct OID is emitted in the NamedCurve element.
        assert!(
            xml.contains("1.3.36.3.3.2.8.1.1.7"),
            "BrainpoolP256r1 OID must appear in NamedCurve URI"
        );
        assert!(xml.contains("ECDH-ES"), "must use ECDH-ES");
        assert!(xml.contains("kw-aes128"), "must use AES-128 Key Wrap");

        let decrypted =
            decrypt_payload_xmlenc(&ciphertext, &key_pem).expect("decrypt with BrainpoolP256r1");
        assert_eq!(
            decrypted, plaintext,
            "BrainpoolP256r1 ECDH-ES roundtrip must recover plaintext"
        );
    }

    #[test]
    fn aes_128_key_wrap_roundtrip_brainpool_sanity() {
        // Duplicate-free alias used for context — the real AES-KW tests are above.
        let kek = [0xBBu8; 16];
        let cek = [0xCCu8; 16];
        let wrapped = aes_128_key_wrap(&kek, &cek).expect("wrap");
        let unwrapped = aes_128_key_unwrap(&kek, &wrapped).expect("unwrap");
        assert_eq!(unwrapped, cek.as_slice());
    }
}
