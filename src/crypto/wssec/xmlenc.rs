//! AS4/WS-Security XML Encryption — encrypt and decrypt payloads via
//! AES-GCM + RSA-OAEP (SHA-256/MGF1-SHA-256).
//!
//! eDelivery AS4 v1.15 Common Profile mandates AES-128-GCM for outbound
//! XML-Enc payload encryption. Some partner networks accept AES-256-GCM.
//! This module supports both GCM variants outbound (via `XmlEncPayloadAlgorithm`)
//! and accepts AES-128/256-GCM inbound. AES-CBC is explicitly rejected: it is
//! not required by eDelivery AS4 v1.15 and opens padding-oracle attack surface.

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use openssl::encrypt::{Decrypter, Encrypter};
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::rsa::Padding;
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
const XENC11_RSA_OAEP_URI: &str = "http://www.w3.org/2009/xmlenc11#rsa-oaep";
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
    const XENC11_NS: &str = "http://www.w3.org/2009/xmlenc11#";
    const RSA_OAEP_URI: &str = "http://www.w3.org/2009/xmlenc11#rsa-oaep";
    const MGF1SHA256_URI: &str = "http://www.w3.org/2009/xmlenc11#mgf1sha256";
    const SHA256_DIGEST_URI: &str = "http://www.w3.org/2001/04/xmlenc#sha256";

    let pkey = recipient_cert.public_key().map_err(|err| {
        AsxError::new(
            ErrorCode::SecurityVerificationFailed,
            format!("recipient certificate does not contain a usable public key: {err}"),
            ErrorContext::new("wssec_encrypt_payload"),
        )
    })?;

    // AES-GCM key length is selected by outbound policy.
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

    // Pure-Rust AES-GCM encryption (aes-gcm crate).
    // encrypt() returns ciphertext || 16-byte tag concatenated.
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
    // gcm_output already contains ciphertext||tag from aes-gcm::encrypt.
    let mut gcm_blob = Vec::with_capacity(12 + gcm_output.len());
    gcm_blob.extend_from_slice(&nonce_bytes);
    gcm_blob.extend_from_slice(&gcm_output);
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
    let encrypted_key_len = encrypter
        .encrypt(&aes_key, &mut encrypted_key)
        .map_err(|err| {
            AsxError::new(
                ErrorCode::SecurityVerificationFailed,
                format!("failed to wrap AES key with recipient RSA key (OAEP/MGF1-SHA256): {err}"),
                ErrorContext::new("wssec_encrypt_payload"),
            )
        })?;
    encrypted_key.truncate(encrypted_key_len);

    let encrypted_data_xml = format!(
        "<xenc:EncryptedData xmlns:xenc=\"{XENC_NS}\" xmlns:xenc11=\"{XENC11_NS}\" Type=\"{xmlenc_type}\">\
  <xenc:EncryptionMethod Algorithm=\"{AES_GCM_URI}\"/>\
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
</xenc:EncryptedData>",
        xmlenc_type = match encapsulation {
            XmlEncEncapsulation::Payload => XENC11_CONTENT_URI,
            XmlEncEncapsulation::SoapHeader { .. } => XENC11_ELEMENT_URI,
        },
        AES_GCM_URI = payload_algorithm.xmlenc_uri(),
        encrypted_key_b64 = BASE64_STANDARD.encode(&encrypted_key),
        gcm_blob_b64 = BASE64_STANDARD.encode(&gcm_blob),
    );

    match encapsulation {
        XmlEncEncapsulation::Payload => Ok(encrypted_data_xml.into_bytes()),
        XmlEncEncapsulation::SoapHeader {
            soap_namespace,
            must_understand_token,
        } => Ok(format!(
            "<xenc:EncryptedHeader xmlns:xenc=\"{XENC_NS}\" xmlns:soap=\"{soap_namespace}\" soap:mustUnderstand=\"{must_understand_token}\">{encrypted_data_xml}</xenc:EncryptedHeader>"
        )
        .into_bytes()),
    }
}

fn namespace_is_xmlenc(ns: &ResolveResult<'_>) -> bool {
    matches!(ns, ResolveResult::Bound(namespace) if namespace.as_ref() == XENC_NS.as_bytes())
}

fn tag_kind(ns: &ResolveResult<'_>, local_name: &[u8]) -> XmlEncTag {
    if !namespace_is_xmlenc(ns) {
        return XmlEncTag::Other;
    }

    match local_name {
        b"EncryptedData" => XmlEncTag::EncryptedData,
        b"EncryptedKey" => XmlEncTag::EncryptedKey,
        b"EncryptionMethod" => XmlEncTag::EncryptionMethod,
        b"CipherData" => XmlEncTag::CipherData,
        b"CipherValue" => XmlEncTag::CipherValue,
        _ => XmlEncTag::Other,
    }
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
                        _ if stack.contains(&XmlEncTag::EncryptedKey) => {
                            key_algorithm = extract_encryption_method_algorithm(&element)?;
                        }
                        _ => {}
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
                        _ if stack.contains(&XmlEncTag::EncryptedKey) => {
                            key_algorithm = extract_encryption_method_algorithm(&element)?;
                        }
                        _ => {}
                    }
                }

                if kind == XmlEncTag::CipherValue {
                    return Err(AsxError::new(
                        ErrorCode::ParseFailed,
                        "XML Encryption CipherValue cannot be empty",
                        ErrorContext::new("wssec_decrypt_payload"),
                    ));
                }

                stack.push(kind);
                stack.pop();
            }
            Event::Text(text) => {
                if let Some(target) = active_cipher_target {
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
                if let Some(target) = active_cipher_target {
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
    if key_algorithm != XENC11_RSA_OAEP_URI {
        return Err(AsxError::new(
            ErrorCode::DecryptionFailed,
            format!(
                "unsupported XML Encryption key transport algorithm: {key_algorithm} (only xmlenc11 RSA-OAEP is accepted)"
            ),
            ErrorContext::new("wssec_decrypt_payload"),
        ));
    }

    let wrapped_key = decode_cipher_value("wrapped XML Encryption key", &wrapped_key_text)?;
    let cipher_blob = decode_cipher_value("XML Encryption ciphertext", &payload_cipher_text)?;

    let pkey = PKey::private_key_from_pem(recipient_key_pem).map_err(|err| {
        AsxError::new(
            ErrorCode::DecryptionFailed,
            format!("failed to parse XML Encryption recipient private key: {err}"),
            ErrorContext::new("wssec_decrypt_payload"),
        )
    })?;

    // Unwrap the content-encryption key via RSA-OAEP with SHA-256/MGF1-SHA-256.
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
                format!("failed to unwrap XML Encryption content key (OAEP/MGF1-SHA256): {err}"),
                ErrorContext::new("wssec_decrypt_payload"),
            )
        })?;
    // Truncate in-place: avoids the redundant aes_key[..key_len].to_vec() allocation.
    aes_key.truncate(key_len);

    // Decrypt the payload based on the negotiated algorithm.
    match inbound_algo {
        InboundDataAlgorithm::Aes128Gcm | InboundDataAlgorithm::Aes256Gcm => {
            // GCM wire format: nonce (12) || ciphertext || auth_tag (16).
            // Minimum: 12-byte nonce + 0-byte ciphertext + 16-byte tag = 28 bytes.
            if cipher_blob.len() < 28 {
                return Err(AsxError::new(
                    ErrorCode::DecryptionFailed,
                    "AES-GCM ciphertext blob is too short (need nonce + tag)",
                    ErrorContext::new("wssec_decrypt_payload"),
                ));
            }

            // Extract the 12-byte nonce; cipher_blob[12..] = ciphertext || tag,
            // which is exactly the format Aead::decrypt expects.
            let nonce_bytes: [u8; 12] = cipher_blob[..12].try_into().expect("12 bytes");
            let nonce = aes_gcm::Nonce::from(nonce_bytes);

            let aead_err = |_| {
                AsxError::new(
                    ErrorCode::DecryptionFailed,
                    "failed to decrypt AES-GCM ciphertext: authentication tag mismatch or corrupt data",
                    ErrorContext::new("wssec_decrypt_payload"),
                )
            };
            let plaintext = match aes_key.len() {
                16 => Aes128Gcm::new_from_slice(&aes_key)
                    .expect("key length pre-validated")
                    .decrypt(&nonce, &cipher_blob[12..]),
                32 => Aes256Gcm::new_from_slice(&aes_key)
                    .expect("key length pre-validated")
                    .decrypt(&nonce, &cipher_blob[12..]),
                other => {
                    return Err(AsxError::new(
                        ErrorCode::DecryptionFailed,
                        format!(
                            "unsupported XML Encryption content key length: {other} (expected 16 or 32)"
                        ),
                        ErrorContext::new("wssec_decrypt_payload"),
                    ));
                }
            }
            .map_err(aead_err)?;
            Ok(plaintext)
        }
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
}
