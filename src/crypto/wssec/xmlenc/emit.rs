//! Outbound XML Encryption in the WSS SwA 1.1 §5.5 shape of the eDelivery
//! AS4 1.15 §5 example, written with `XmlOut`: one `xenc:EncryptedKey` whose
//! `ReferenceList` names one `xenc:EncryptedData` per attachment; each `EncryptedData` points at its
//! MIME part through `CipherReference URI="cid:…"` with the
//! `Attachment-Ciphertext-Transform`; each part body is `IV ‖ ct ‖ tag`.
//!
//! Key transport: ECDH-ES with `xenc11:KeyDerivationMethod` ConcatKDF,
//! `ConcatKDFParams AlgorithmID="" PartyUInfo="" PartyVInfo=""`, a SHA-256
//! `ds:DigestMethod` and the recipient's `dsig11:NamedCurve`; RSA-OAEP with a
//! SHA-256 `ds:DigestMethod` and `mgf1sha256`; `kw-aes*`; AES-GCM.

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use openssl::encrypt::Encrypter;
use openssl::rsa::Padding;
use openssl::x509::X509Ref;
use zeroize::Zeroizing;

use super::kdf::{ConcatKdfParams, concat_kdf};
use super::{KeyTransport, RecipientForm, agreement, gcm, keywrap, randomness};
use crate::core::{AsxError, ErrorCode, ErrorContext, Result};
use crate::crypto::alg::{
    AgreementAlg, KdfAlg, KeyTransportAlg, KeyWrapAlg, MgfAlg, NamedCurve, XmlEncPayloadAlgorithm,
};
use crate::crypto::wssec::WsSecDigestMethod;
use crate::xml::{XmlFragment, XmlOut, ns};

const STAGE: &str = "wssec_encrypt_payload";

fn failure(detail: String) -> AsxError {
    AsxError::new(
        ErrorCode::SecurityVerificationFailed,
        detail,
        ErrorContext::new(STAGE),
    )
}

/// The content key wrapped for the recipient, with what `ds:KeyInfo` says
/// about it.
pub(crate) enum WrappedKey {
    RsaOaep {
        wrapped: Vec<u8>,
    },
    EcdhEs {
        curve: NamedCurve,
        originator_point: Vec<u8>,
        wrap: KeyWrapAlg,
        wrapped: Vec<u8>,
    },
}

impl KeyTransport {
    /// The transport the recipient certificate's key admits: RSA-OAEP for an
    /// RSA key, ECDH-ES + ConcatKDF for an EC key.
    pub(crate) fn for_recipient(recipient: &X509Ref) -> Result<KeyTransport> {
        let public = recipient.public_key().map_err(|err| {
            failure(format!(
                "recipient certificate does not contain a usable public key: {err}"
            ))
        })?;
        match public.id() {
            openssl::pkey::Id::RSA | openssl::pkey::Id::RSA_PSS => Ok(KeyTransport::RsaOaep),
            openssl::pkey::Id::EC => Ok(KeyTransport::EcdhEs {
                kdf: KdfAlg::ConcatKdf,
            }),
            other => Err(failure(format!(
                "recipient certificate key type {other:?} is not supported for XML \
                 Encryption; use an RSA or EC certificate"
            ))),
        }
    }

    /// Wrap `cek` for `recipient`.
    pub(crate) fn wrap(&self, cek: &[u8], recipient: &X509Ref) -> Result<WrappedKey> {
        let public = recipient.public_key().map_err(|err| {
            failure(format!(
                "recipient certificate does not contain a usable public key: {err}"
            ))
        })?;
        match self {
            KeyTransport::RsaOaep => {
                let mut encrypter = Encrypter::new(&public)
                    .map_err(|err| failure(format!("failed to create RSA encrypter: {err}")))?;
                encrypter
                    .set_rsa_padding(Padding::PKCS1_OAEP)
                    .and_then(|()| {
                        encrypter.set_rsa_oaep_md(WsSecDigestMethod::Sha256.message_digest())
                    })
                    .and_then(|()| {
                        encrypter.set_rsa_mgf1_md(WsSecDigestMethod::Sha256.message_digest())
                    })
                    .map_err(|err| failure(format!("failed to configure RSA-OAEP: {err}")))?;
                let mut wrapped = vec![
                    0u8;
                    encrypter.encrypt_len(cek).map_err(|err| {
                        failure(format!("failed to size the RSA-OAEP output: {err}"))
                    })?
                ];
                let len = encrypter.encrypt(cek, &mut wrapped).map_err(|err| {
                    failure(format!(
                        "failed to wrap the content key with RSA-OAEP (SHA-256/MGF1-SHA-256): {err}"
                    ))
                })?;
                wrapped.truncate(len);
                Ok(WrappedKey::RsaOaep { wrapped })
            }
            KeyTransport::EcdhEs { kdf } => {
                let KdfAlg::ConcatKdf = kdf;
                let ec = public
                    .ec_key()
                    .map_err(|err| failure(format!("recipient EC key unreadable: {err}")))?;
                let group = ec.group();
                let curve = NamedCurve::from_group(group)?;
                let (ephemeral, originator_point) = randomness::ephemeral(group)?;
                let z = agreement::shared_secret(&ephemeral, group, ec.public_key())
                    .map_err(|_| failure("ECDH key agreement failed".to_string()))?;
                // A KEK as strong as the CEK: wrapping a 256-bit CEK under a
                // 128-bit KEK would cap the construction at 128-bit security.
                let wrap = KeyWrapAlg::for_kek_len(cek.len())?;
                let kek = concat_kdf(
                    WsSecDigestMethod::Sha256,
                    &z,
                    (wrap.kek_len() * 8) as u32,
                    &ConcatKdfParams::default(),
                );
                let wrapped = keywrap::wrap(wrap, &kek, cek)?;
                Ok(WrappedKey::EcdhEs {
                    curve,
                    originator_point,
                    wrap,
                    wrapped,
                })
            }
        }
    }
}

/// One attachment to encrypt.
pub(crate) struct OutboundPart<'a> {
    /// Bare Content-ID (no `cid:`, no angle brackets).
    pub(crate) content_id: &'a str,
    /// The pre-encryption type (`EncryptedData/@MimeType`).
    pub(crate) mime_type: &'a str,
    /// The pre-encryption bytes (what the `cid:` reference digests).
    pub(crate) plaintext: &'a [u8],
}

/// The encryption half of `wsse:Security` (the recipient BST if any, the `EncryptedKey`, the `EncryptedData`s) and the
/// encrypted part bodies, in part order.
pub(crate) struct OutboundEnvelope {
    pub(crate) header: XmlFragment,
    pub(crate) bodies: Vec<Vec<u8>>,
}

impl std::fmt::Debug for OutboundEnvelope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OutboundEnvelope")
            .field("parts", &self.bodies.len())
            .finish_non_exhaustive()
    }
}

/// Encrypt `parts` under one fresh content key for `recipient`,
/// referenced by `form`. `id_seed` makes the `EK-`/`ED-`/`X509-`
/// identifiers (NCName characters only). No parts: `None` — no
/// `EncryptedKey` is written.
pub(crate) fn encrypt_attachments(
    parts: &[OutboundPart<'_>],
    recipient: &X509Ref,
    form: RecipientForm,
    cipher: XmlEncPayloadAlgorithm,
    id_seed: &str,
) -> Result<Option<OutboundEnvelope>> {
    if parts.is_empty() {
        return Ok(None);
    }
    let transport = KeyTransport::for_recipient(recipient)?;
    let cek: Zeroizing<Vec<u8>> = randomness::cek(cipher.key_len())?;
    let mut bodies = Vec::with_capacity(parts.len());
    for part in parts {
        let nonce = randomness::nonce()?;
        bodies.push(
            gcm::encrypt(cipher, &cek, nonce, part.plaintext).map_err(|_| {
                failure(format!("failed to {}-encrypt the payload", cipher.label()))
            })?,
        );
    }
    let wrapped = transport.wrap(&cek, recipient)?;
    drop(cek);

    let key_id = format!("EK-{id_seed}");
    let bst_id = format!("X509-{id_seed}");
    let data_ids: Vec<String> = (0..parts.len())
        .map(|i| format!("ED-{id_seed}-{i}"))
        .collect();

    let mut out = XmlOut::new();
    if form == RecipientForm::Bst {
        let der = recipient
            .to_der()
            .map_err(|err| failure(format!("recipient certificate DER: {err}")))?;
        out.start("wsse:BinarySecurityToken")?
            .ns("wsse", ns::WSSE)?
            .ns("wsu", ns::WSU)?
            .attr("wsu:Id", &bst_id, "wsu:Id")?
            .attr("EncodingType", ns::WSSE_BASE64_ENCODING, "EncodingType")?
            .attr("ValueType", ns::WSSE_X509V3_VALUE_TYPE, "ValueType")?
            .text(&BASE64_STANDARD.encode(der), "BinarySecurityToken")?
            .end()?;
    }
    write_encrypted_key(
        &mut out, &key_id, &wrapped, form, &bst_id, recipient, &data_ids,
    )?;
    for (part, data_id) in parts.iter().zip(&data_ids) {
        write_encrypted_data(&mut out, data_id, &key_id, part, cipher)?;
    }
    Ok(Some(OutboundEnvelope {
        header: out.finish()?.into_fragment()?,
        bodies,
    }))
}

fn write_encrypted_key(
    out: &mut XmlOut,
    key_id: &str,
    key: &WrappedKey,
    form: RecipientForm,
    bst_id: &str,
    recipient: &X509Ref,
    data_ids: &[String],
) -> Result<()> {
    out.start("xenc:EncryptedKey")?
        .ns("xenc", ns::XENC)?
        .ns("ds", ns::DS)?
        .ns("wsse", ns::WSSE)?;
    if matches!(key, WrappedKey::EcdhEs { .. }) {
        out.ns("xenc11", ns::XENC11)?.ns("dsig11", ns::DSIG11)?;
    } else {
        out.ns("xenc11", ns::XENC11)?;
    }
    out.attr("Id", key_id, "EncryptedKey/@Id")?;
    let wrapped = match key {
        WrappedKey::RsaOaep { wrapped } => {
            out.start("xenc:EncryptionMethod")?.attr(
                "Algorithm",
                KeyTransportAlg::RsaOaep.uri(),
                "EncryptionMethod/@Algorithm",
            )?;
            out.start("ds:DigestMethod")?
                .attr(
                    "Algorithm",
                    WsSecDigestMethod::Sha256.algorithm_uri(),
                    "DigestMethod/@Algorithm",
                )?
                .end()?;
            out.start("xenc11:MGF")?
                .attr("Algorithm", MgfAlg::Mgf1Sha256.uri(), "MGF/@Algorithm")?
                .end()?;
            out.end()?;
            out.start("ds:KeyInfo")?;
            write_recipient_reference(out, form, bst_id, recipient)?;
            out.end()?;
            wrapped
        }
        WrappedKey::EcdhEs {
            curve,
            originator_point,
            wrap,
            wrapped,
        } => {
            out.start("xenc:EncryptionMethod")?
                .attr("Algorithm", wrap.uri(), "EncryptionMethod/@Algorithm")?
                .end()?;
            out.start("ds:KeyInfo")?;
            out.start("xenc:AgreementMethod")?.attr(
                "Algorithm",
                AgreementAlg::EcdhEs.uri(),
                "AgreementMethod/@Algorithm",
            )?;
            out.start("xenc11:KeyDerivationMethod")?.attr(
                "Algorithm",
                KdfAlg::ConcatKdf.uri(),
                "KeyDerivationMethod/@Algorithm",
            )?;
            out.start("xenc11:ConcatKDFParams")?
                .attr("AlgorithmID", "", "AlgorithmID")?
                .attr("PartyUInfo", "", "PartyUInfo")?
                .attr("PartyVInfo", "", "PartyVInfo")?;
            out.start("ds:DigestMethod")?
                .attr(
                    "Algorithm",
                    WsSecDigestMethod::Sha256.algorithm_uri(),
                    "DigestMethod/@Algorithm",
                )?
                .end()?;
            out.end()?.end()?;
            out.start("xenc:OriginatorKeyInfo")?
                .start("ds:KeyValue")?
                .start("dsig11:ECKeyValue")?;
            out.start("dsig11:NamedCurve")?
                .attr("URI", curve.uri(), "NamedCurve/@URI")?
                .end()?;
            out.leaf(
                "dsig11:PublicKey",
                &BASE64_STANDARD.encode(originator_point),
                "PublicKey",
            )?;
            out.end()?.end()?.end()?;
            out.start("xenc:RecipientKeyInfo")?;
            write_recipient_reference(out, form, bst_id, recipient)?;
            out.end()?; // RecipientKeyInfo
            out.end()?; // AgreementMethod
            out.end()?; // ds:KeyInfo
            wrapped
        }
    };
    out.start("xenc:CipherData")?;
    out.leaf(
        "xenc:CipherValue",
        &BASE64_STANDARD.encode(wrapped),
        "CipherValue",
    )?;
    out.end()?;
    out.start("xenc:ReferenceList")?;
    for id in data_ids {
        out.start("xenc:DataReference")?
            .attr("URI", &format!("#{id}"), "DataReference/@URI")?
            .end()?;
    }
    out.end()?;
    out.end()?; // EncryptedKey
    Ok(())
}

/// The recipient's `wsse:SecurityTokenReference`: a direct
/// reference to the recipient BST, or its Subject Key Identifier.
fn write_recipient_reference(
    out: &mut XmlOut,
    form: RecipientForm,
    bst_id: &str,
    recipient: &X509Ref,
) -> Result<()> {
    out.start("wsse:SecurityTokenReference")?;
    match form {
        RecipientForm::Bst => {
            out.start("wsse:Reference")?
                .attr("URI", &format!("#{bst_id}"), "Reference/@URI")?
                .attr("ValueType", ns::WSSE_X509V3_VALUE_TYPE, "ValueType")?
                .end()?;
        }
        RecipientForm::Ski => {
            out.start("wsse:KeyIdentifier")?
                .attr("EncodingType", ns::WSSE_BASE64_ENCODING, "EncodingType")?
                .attr("ValueType", ns::WSSE_SKI_VALUE_TYPE, "ValueType")?
                .text(
                    &BASE64_STANDARD.encode(subject_key_id(recipient)?),
                    "KeyIdentifier",
                )?
                .end()?;
        }
    }
    out.end()?;
    Ok(())
}

fn write_encrypted_data(
    out: &mut XmlOut,
    data_id: &str,
    key_id: &str,
    part: &OutboundPart<'_>,
    cipher: XmlEncPayloadAlgorithm,
) -> Result<()> {
    out.start("xenc:EncryptedData")?
        .ns("xenc", ns::XENC)?
        .ns("ds", ns::DS)?
        .ns("wsse", ns::WSSE)?
        .ns("wsse11", ns::WSSE11)?
        .attr("Id", data_id, "EncryptedData/@Id")?
        .attr("MimeType", part.mime_type, "EncryptedData/@MimeType")?
        .attr("Type", ns::SWA_CONTENT_ONLY, "EncryptedData/@Type")?;
    out.start("xenc:EncryptionMethod")?
        .attr("Algorithm", cipher.uri(), "EncryptionMethod/@Algorithm")?
        .end()?;
    out.start("ds:KeyInfo")?
        .start("wsse:SecurityTokenReference")?
        .attr(
            "wsse11:TokenType",
            ns::WSSE11_ENCRYPTED_KEY_TOKEN,
            "wsse11:TokenType",
        )?;
    out.start("wsse:Reference")?
        .attr("URI", &format!("#{key_id}"), "Reference/@URI")?
        .end()?;
    out.end()?.end()?;
    out.start("xenc:CipherData")?
        .start("xenc:CipherReference")?
        .attr(
            "URI",
            &format!("cid:{}", part.content_id),
            "CipherReference/@URI",
        )?;
    out.start("xenc:Transforms")?
        .start("ds:Transform")?
        .attr(
            "Algorithm",
            ns::SWA_CIPHERTEXT_TRANSFORM,
            "Transform/@Algorithm",
        )?
        .end()?
        .end()?;
    out.end()?.end()?;
    out.end()?; // EncryptedData
    Ok(())
}

/// The recipient certificate's Subject Key Identifier, or SHA-1 of its
/// `subjectPublicKey` bits (RFC 5280 §4.2.1.2 method 1, what WSS4J computes)
/// when it has none.
fn subject_key_id(cert: &X509Ref) -> Result<Vec<u8>> {
    if let Some(ski) = cert.subject_key_id() {
        return Ok(ski.as_slice().to_vec());
    }
    let der = cert
        .to_der()
        .map_err(|err| failure(format!("recipient certificate DER: {err}")))?;
    let (_, parsed) = x509_parser::parse_x509_certificate(&der)
        .map_err(|err| failure(format!("recipient certificate unreadable for SKI: {err}")))?;
    openssl::hash::hash(
        openssl::hash::MessageDigest::sha1(),
        &parsed.public_key().subject_public_key.data,
    )
    .map(|d| d.to_vec())
    .map_err(|err| failure(format!("SHA-1 for the SKI failed: {err}")))
}
