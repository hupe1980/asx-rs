//! AS4/WS-Security XML Encryption — encrypt and decrypt payloads.
//!
//! ## Key transport
//!
//! | Recipient key | Algorithm | Standard |
//! |---|---|---|
//! | RSA | RSA-OAEP (SHA-256 / MGF1-SHA-256, no label) | eDelivery AS4 v1.15 / PEPPOL |
//! | EC  | ECDH-ES + ConcatKDF (SHA-256) + AES Key Wrap | BSI TR-03116-3 §9.2 / BDEW AS4-Profil 1.2 §2.2.6.2.2 |
//!
//! Content is AES-128-GCM (eDelivery default) or AES-256-GCM; CBC is never
//! accepted.
//!
//! ## Structure
//!
//! - `parse` turns the DOM (`xml::parse` with the payload limits) into closed
//!   values and refuses every unsupported identifier **by name, before any key
//!   is used** (`InteropViolation`);
//! - `bind` checks what needs the recipient key's *public* side (curve match,
//!   originator point validation) — still before the private key is used;
//! - the private-key step is exactly one call into a `PrivateKeyStep` with a
//!   closed `KeyOp`: RSA-OAEP with the parsed parameters, or ECDH with the
//!   validated originator point. Key derivation, key unwrap and content
//!   decryption stay in the library;
//! - `unlock_cek` cannot fail: on any OAEP, unwrap or CEK-length failure it
//!   substitutes a random CEK of the declared cipher's length (RFC 3218
//!   §2.3.2), and `decrypt_content` maps every failure to one
//!   `DecryptionFailed` with one fixed message (XMLenc11 §6.1). Detail goes only
//!   to the local `tracing` debug event `xmlenc_decrypt_failure_detail`.
//!
//! ## Extending
//!
//! Adding an algorithm is one variant and one row in `crypto::alg`, plus the
//! exhaustive matches the compiler lists here.
//!
//! ## The SwA envelope
//!
//! Attachments are encrypted in the WSS SwA 1.1 §5.5 shape: one
//! `EncryptedKey` with a `ReferenceList`, one `EncryptedData` per part with a
//! `CipherReference` to the part (`emit`); inbound, `resolve_envelope` checks
//! the structure and the profile suite without a key, and
//! `decrypt_attachments` selects the decrypter by reference and decrypts the
//! part bodies.

mod agreement;
mod emit;
mod gcm;
mod kdf;
mod keywrap;
mod parse;

use openssl::ec::{EcGroup, EcPoint};
use openssl::pkey::{PKey, Private};
use openssl::x509::{X509, X509Ref};
use zeroize::Zeroizing;

pub(crate) use emit::{OutboundEnvelope, OutboundPart};
pub(crate) use parse::{
    EncryptedKeySpec, RecipientRef, ResolvedEnvelope, RsaOaepParams, Suite, normalize_cid,
};

use crate::core::{AsxError, ErrorCode, ErrorContext, Result};
use crate::crypto::alg::{KdfAlg, KeyWrapAlg, NamedCurve};
use crate::crypto::wssec::WsSecDigestMethod;
use crate::xml::{XmlLimits, ns};

/// Defined in the algorithm registry (`crypto::alg`).
pub use crate::crypto::alg::XmlEncPayloadAlgorithm;

const STAGE: &str = "wssec_decrypt_payload";

/// The one message every failure after the private key is used carries.
const DECRYPTION_FAILED: &str = "XML Encryption decryption failed";

/// How the content key travels: a closed, crate-private set. Envelope, part
/// encryption and resolver are written against it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum KeyTransport {
    /// RSA-OAEP, SHA-256 / MGF1-SHA-256 (eDelivery AS4 1.15 §3.2.6).
    RsaOaep,
    /// ECDH-ES + `kdf` + AES key wrap (BDEW AS4-Profil 1.2 §2.2.6.2.2).
    EcdhEs { kdf: KdfAlg },
}

/// How the outbound `EncryptedKey` names the recipient: profile
/// data, never a setting.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RecipientForm {
    /// A `wsse:Reference` to a `#X509v3` BinarySecurityToken in the header
    /// (Peppol, eDelivery 1.15, ENTSOG).
    Bst,
    /// `wsse:KeyIdentifier #X509SubjectKeyIdentifier` (BDEW 1.2 §2.2.6.2.2
    /// "x509SKI"; phase4 `Phase4BDEWSender` `X509_SKI_KEY_IDENTIFIER`).
    Ski,
}

/// Encrypt `parts` for `recipient` in the WSS SwA shape; `None` for no parts.
pub(crate) fn encrypt_attachments(
    parts: &[OutboundPart<'_>],
    recipient: &X509Ref,
    form: RecipientForm,
    cipher: XmlEncPayloadAlgorithm,
    id_seed: &str,
) -> Result<Option<OutboundEnvelope>> {
    encrypt_span(recipient, cipher)
        .in_scope(|| emit::encrypt_attachments(parts, recipient, form, cipher, id_seed))
}

/// The `asx.encrypt` span: the content algorithm and how its key travels.
fn encrypt_span(recipient_cert: &X509Ref, algorithm: XmlEncPayloadAlgorithm) -> tracing::Span {
    let key_transport = match recipient_cert.public_key().map(|k| k.id()) {
        Ok(openssl::pkey::Id::RSA) => "rsa-oaep",
        Ok(_) => "ecdh-es",
        Err(_) => "unknown",
    };
    tracing::debug_span!(
        target: "asx",
        "asx.encrypt",
        algorithm = algorithm.uri(),
        key_transport,
    )
}

/// Resolve the encryption envelope of `security` (no key used): the envelope
/// structure, then `suite`, then the key identifiers.
pub(crate) fn resolve_envelope(
    doc: &roxmltree::Document<'_>,
    security: roxmltree::Node<'_, '_>,
    declared: &[String],
    suite: Option<&Suite>,
    max_parts: usize,
) -> Result<Option<ResolvedEnvelope>> {
    parse::resolve_envelope(doc, security, declared, suite, max_parts)
}

fn uniform_failure() -> AsxError {
    AsxError::new(
        ErrorCode::DecryptionFailed,
        DECRYPTION_FAILED,
        ErrorContext::new(STAGE),
    )
}

/// Decrypt every part of `envelope`; `bodies[i]` is the MIME body
/// (`IV ‖ ct ‖ tag`) of `envelope.data[i]`. The decrypter is selected by the
/// `EncryptedKey`'s reference; a key matching no decrypter or
/// several, and every failure from the key operation to the last GCM tag,
/// is one `DecryptionFailed` with one text. Each part allocates one
/// plaintext buffer.
pub(crate) fn decrypt_attachments(
    envelope: &ResolvedEnvelope,
    bodies: &[&[u8]],
    keys: &dyn RecipientKeys,
) -> Result<Vec<Vec<u8>>> {
    let Some(cipher) = envelope.data.first().map(|d| d.cipher) else {
        return Ok(Vec::new());
    };
    if envelope.data.iter().any(|d| d.cipher != cipher) || bodies.len() != envelope.data.len() {
        return Err(AsxError::new(
            ErrorCode::InteropViolation,
            "the encrypted parts declare different content ciphers",
            ErrorContext::new(STAGE),
        ));
    }
    let Some((recipient, decrypter)) = keys.select(&envelope.key) else {
        failure_detail("key_selection");
        return Err(uniform_failure());
    };
    let bound = bind(&envelope.key, Some(recipient))?;
    let cek = unlock_cek(&bound, cipher, decrypter);
    bodies
        .iter()
        .map(|body| decrypt_content(cipher, &cek, body))
        .collect()
}

/// The client's decryption keys: exactly one key is
/// selected by the `EncryptedKey`'s reference, never by trial decryption.
pub(crate) trait RecipientKeys: Send + Sync {
    /// The key `spec` names, or `None` (no match, or more than one) — which
    /// fails as every other decryption failure does.
    fn select(&self, spec: &EncryptedKeySpec) -> Option<(RecipientKey, &dyn PrivateKeyStep)>;
}

/// The randomness of one outbound envelope: the content key, one nonce per
/// part, the ECDH-ES ephemeral key. Tests pin it ([`randomness::fixed`]) for
/// byte-pinned vectors.
pub(crate) mod randomness {
    use super::*;

    #[cfg(test)]
    pub(crate) struct Fixed {
        pub(crate) cek: Vec<u8>,
        pub(crate) nonces: Vec<[u8; 12]>,
        pub(crate) ephemeral_pem: Option<Vec<u8>>,
    }

    #[cfg(test)]
    thread_local! {
        static FIXED: std::cell::RefCell<Option<Fixed>> = const { std::cell::RefCell::new(None) };
    }

    /// Run `f` with `fixed` randomness on this thread.
    #[cfg(test)]
    pub(crate) fn fixed<T>(fixed: Fixed, f: impl FnOnce() -> T) -> T {
        FIXED.with(|c| *c.borrow_mut() = Some(fixed));
        let out = f();
        FIXED.with(|c| *c.borrow_mut() = None);
        out
    }

    pub(crate) fn cek(len: usize) -> Result<Zeroizing<Vec<u8>>> {
        #[cfg(test)]
        if let Some(cek) = FIXED.with(|c| c.borrow().as_ref().map(|f| f.cek.clone())) {
            return Ok(Zeroizing::new(cek));
        }
        let mut cek = Zeroizing::new(vec![0u8; len]);
        getrandom::fill(&mut cek).map_err(|err| {
            AsxError::new(
                ErrorCode::SecurityVerificationFailed,
                format!("failed to generate the content key: {err}"),
                ErrorContext::new("wssec_encrypt_payload"),
            )
        })?;
        Ok(cek)
    }

    pub(crate) fn nonce() -> Result<[u8; gcm::NONCE_LEN]> {
        #[cfg(test)]
        if let Some(nonce) = FIXED.with(|c| {
            c.borrow_mut()
                .as_mut()
                .filter(|f| !f.nonces.is_empty())
                .map(|f| f.nonces.remove(0))
        }) {
            return Ok(nonce);
        }
        gcm::fresh_nonce()
    }

    pub(crate) fn ephemeral(group: &openssl::ec::EcGroupRef) -> Result<(PKey<Private>, Vec<u8>)> {
        #[cfg(test)]
        if let Some(pem) = FIXED.with(|c| c.borrow().as_ref().and_then(|f| f.ephemeral_pem.clone()))
        {
            let key = PKey::private_key_from_pem(&pem).expect("fixed ephemeral key");
            let ec = key.ec_key().expect("EC key");
            let mut ctx = openssl::bn::BigNumContext::new().expect("BN context");
            let point = ec
                .public_key()
                .to_bytes(
                    group,
                    openssl::ec::PointConversionForm::UNCOMPRESSED,
                    &mut ctx,
                )
                .expect("point");
            return Ok((key, point));
        }
        agreement::ephemeral(group)
    }
}

// ── The fuzz/test seam (doc-hidden `__fuzz::wssec`) ─────────────────────────

/// Encrypt `parts` (`(content id, pre-encryption type, bytes)`) for the
/// certificate in `recipient_cert_pem` — SKI reference for an EC key, BST
/// for RSA — and return a standalone `wsse:Security` element holding the
/// envelope, with the part bodies. Not API: the doc-hidden fuzz seam.
pub fn encrypt_swa(
    parts: &[(&str, &str, &[u8])],
    recipient_cert_pem: &[u8],
    cipher: XmlEncPayloadAlgorithm,
) -> Result<(String, Vec<Vec<u8>>)> {
    let cert = X509::from_pem(recipient_cert_pem).map_err(|err| {
        AsxError::new(
            ErrorCode::SecurityVerificationFailed,
            format!("failed to parse XML Encryption recipient cert PEM: {err}"),
            ErrorContext::new("wssec_encrypt_payload"),
        )
    })?;
    let form = match KeyTransport::for_recipient(&cert)? {
        KeyTransport::RsaOaep => RecipientForm::Bst,
        KeyTransport::EcdhEs { .. } => RecipientForm::Ski,
    };
    let outbound: Vec<OutboundPart<'_>> = parts
        .iter()
        .map(|(content_id, mime_type, plaintext)| OutboundPart {
            content_id,
            mime_type,
            plaintext,
        })
        .collect();
    let Some(envelope) = encrypt_attachments(&outbound, &cert, form, cipher, "fuzz")? else {
        return Ok((String::new(), Vec::new()));
    };
    let mut out = crate::xml::XmlOut::new();
    out.start("wsse:Security")?.ns("wsse", ns::WSSE)?;
    out.fragment(&envelope.header)?;
    out.end()?;
    Ok((out.finish()?.into_string()?, envelope.bodies))
}

/// Resolve and decrypt the envelope of a standalone `wsse:Security` element
/// (`security_xml`) with the private key in `recipient_key_pem`; `parts` are
/// `(content id, body)`. Registry acceptance only (no profile suite). Not
/// API: the doc-hidden fuzz seam.
pub fn decrypt_swa(
    security_xml: &[u8],
    parts: &[(&str, &[u8])],
    recipient_key_pem: &[u8],
) -> Result<Vec<Vec<u8>>> {
    let doc = crate::xml::parse_bytes(security_xml, XmlLimits::ENVELOPE, STAGE)?;
    let security = doc.root_element();
    let declared: Vec<String> = parts.iter().map(|(cid, _)| cid.to_string()).collect();
    let Some(envelope) = resolve_envelope(&doc, security, &declared, None, 16)? else {
        return Err(AsxError::new(
            ErrorCode::ParseFailed,
            "the header carries no xenc:EncryptedKey",
            ErrorContext::new(STAGE),
        ));
    };
    let bodies: Vec<&[u8]> = envelope
        .data
        .iter()
        .map(|d| {
            parts
                .iter()
                .find(|(cid, _)| normalize_cid(cid) == d.cid)
                .map(|(_, body)| *body)
                .unwrap_or_default()
        })
        .collect();
    let decrypter = PemDecrypter::from_pem(recipient_key_pem)?;
    let one = OneKey(decrypter);
    decrypt_attachments(&envelope, &bodies, &one)
}

/// The fuzz seam's key: the one key, whatever the reference says.
struct OneKey(PemDecrypter);

impl RecipientKeys for OneKey {
    fn select(&self, _: &EncryptedKeySpec) -> Option<(RecipientKey, &dyn PrivateKeyStep)> {
        Some((self.0.recipient()?, &self.0))
    }
}

// ── The key seam ────────────────────────────────────────────────────────────

/// The private-key step of decryption, behind one call; the in-memory PEM key
/// is its only implementation here.
pub(crate) trait PrivateKeyStep: Send + Sync {
    /// Perform `op` with the private key. RSA-OAEP returns the CEK; ECDH
    /// returns the shared secret `Z`.
    fn decrypt(&self, op: KeyOp<'_>) -> Result<Zeroizing<Vec<u8>>>;
}

/// The closed set of private-key operations decryption needs.
pub(crate) enum KeyOp<'a> {
    /// RSA-OAEP decode of `wrapped` with the parsed parameters.
    RsaOaep {
        wrapped: &'a [u8],
        params: RsaOaepParams,
    },
    /// ECDH with a validated originator point on `group`.
    Ecdh {
        peer: &'a openssl::ec::EcPointRef,
        group: &'a openssl::ec::EcGroupRef,
    },
}

impl std::fmt::Debug for KeyOp<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RsaOaep { params, .. } => f
                .debug_struct("RsaOaep")
                .field("params", params)
                .finish_non_exhaustive(),
            Self::Ecdh { group, .. } => f
                .debug_struct("Ecdh")
                .field("curve", &NamedCurve::from_group(group).ok())
                .finish_non_exhaustive(),
        }
    }
}

/// The recipient key's public side, as far as the parse needs it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RecipientKey {
    Rsa,
    Ec(NamedCurve),
}

/// An in-memory PEM private key. `Debug` prints no key material; OpenSSL
/// frees the key and the PEM bytes are not kept.
pub(crate) struct PemDecrypter {
    key: PKey<Private>,
}

impl std::fmt::Debug for PemDecrypter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PemDecrypter")
            .field("key", &self.key.id())
            .finish_non_exhaustive()
    }
}

impl PemDecrypter {
    pub(crate) fn from_pem(key_pem: &[u8]) -> Result<Self> {
        let key = PKey::private_key_from_pem(key_pem).map_err(|_| {
            AsxError::new(
                ErrorCode::DecryptionFailed,
                "the XML Encryption recipient private key is not a valid PEM key",
                ErrorContext::new(STAGE),
            )
        })?;
        Ok(Self { key })
    }

    /// The key's family and curve (no private-key operation).
    pub(crate) fn recipient(&self) -> Option<RecipientKey> {
        match self.key.id() {
            openssl::pkey::Id::RSA | openssl::pkey::Id::RSA_PSS => Some(RecipientKey::Rsa),
            openssl::pkey::Id::EC => self
                .key
                .ec_key()
                .ok()
                .and_then(|k| NamedCurve::from_group(k.group()).ok())
                .map(RecipientKey::Ec),
            _ => None,
        }
    }
}

impl PrivateKeyStep for PemDecrypter {
    fn decrypt(&self, op: KeyOp<'_>) -> Result<Zeroizing<Vec<u8>>> {
        let fail = || {
            AsxError::new(
                ErrorCode::DecryptionFailed,
                DECRYPTION_FAILED,
                ErrorContext::new(STAGE),
            )
        };
        match op {
            KeyOp::RsaOaep { wrapped, params } => {
                let md = params.digest.message_digest();
                let mgf = match params.mgf {
                    crate::crypto::alg::MgfAlg::Mgf1Sha256 => {
                        WsSecDigestMethod::Sha256.message_digest()
                    }
                };
                let mut decrypter =
                    openssl::encrypt::Decrypter::new(&self.key).map_err(|_| fail())?;
                decrypter
                    .set_rsa_padding(openssl::rsa::Padding::PKCS1_OAEP)
                    .and_then(|()| decrypter.set_rsa_oaep_md(md))
                    .and_then(|()| decrypter.set_rsa_mgf1_md(mgf))
                    .map_err(|_| fail())?;
                let mut out =
                    Zeroizing::new(vec![
                        0u8;
                        decrypter.decrypt_len(wrapped).map_err(|_| fail())?
                    ]);
                let len = decrypter.decrypt(wrapped, &mut out).map_err(|_| fail())?;
                out.truncate(len);
                Ok(out)
            }
            KeyOp::Ecdh { peer, group } => agreement::shared_secret(&self.key, group, peer),
        }
    }
}

// ── The pipeline ────────────────────────────────────────────────────────────

/// An `EncryptedKey` checked against the recipient's public side and ready
/// for the one private-key operation.
pub(crate) enum BoundKey<'a> {
    RsaOaep {
        params: RsaOaepParams,
        wrapped: &'a [u8],
    },
    Ecdh {
        group: EcGroup,
        point: EcPoint,
        kdf_digest: WsSecDigestMethod,
        kdf_params: &'a kdf::ConcatKdfParams,
        wrap: KeyWrapAlg,
        wrapped: &'a [u8],
    },
}

/// Check what needs the recipient's public key — still before its private
/// half is used: the originator curve is the recipient's, the
/// originator point is valid on it, and the transport fits the key type.
pub(crate) fn bind<'a>(
    spec: &'a EncryptedKeySpec,
    recipient: Option<RecipientKey>,
) -> Result<BoundKey<'a>> {
    let refused = |message: String| {
        AsxError::new(
            ErrorCode::InteropViolation,
            message,
            ErrorContext::new(STAGE),
        )
    };
    match &spec.transport {
        parse::KeyTransportSpec::RsaOaep(params) => match recipient {
            Some(RecipientKey::Rsa) => Ok(BoundKey::RsaOaep {
                params: *params,
                wrapped: &spec.wrapped_key,
            }),
            other => Err(refused(format!(
                "RSA-OAEP key transport to a recipient key that is not RSA ({other:?})"
            ))),
        },
        parse::KeyTransportSpec::Agreement(agreement) => {
            let Some(RecipientKey::Ec(curve)) = recipient else {
                return Err(refused(format!(
                    "ECDH-ES key agreement to a recipient key that is not EC ({recipient:?})"
                )));
            };
            if agreement.originator_curve != curve {
                return Err(refused(format!(
                    "dsig11:NamedCurve {} does not match the recipient key's curve {curve:?}",
                    agreement.originator_curve.uri()
                )));
            }
            let (group, point) =
                agreement::validate_originator_point(curve, &agreement.originator_point)?;
            let parse::KeyDerivation::ConcatKdf { digest, params } = &agreement.kdf;
            Ok(BoundKey::Ecdh {
                group,
                point,
                kdf_digest: *digest,
                kdf_params: params,
                wrap: agreement.wrap,
                wrapped: &spec.wrapped_key,
            })
        }
    }
}

fn failure_detail(step: &str) {
    tracing::debug!(target: "asx", step, "XML Encryption decryption failed");
}

/// The CEK for `cipher`. **Never fails**: on an OAEP decode, ECDH, unwrap or
/// CEK-length failure a random CEK of the declared length is returned, so the
/// caller cannot branch on the unwrap outcome and content decryption runs in
/// every case (RFC 3218 §2.3.2).
pub(crate) fn unlock_cek(
    bound: &BoundKey<'_>,
    cipher: XmlEncPayloadAlgorithm,
    decrypter: &dyn PrivateKeyStep,
) -> Zeroizing<Vec<u8>> {
    let unlocked: Result<Zeroizing<Vec<u8>>> = match bound {
        BoundKey::RsaOaep { params, wrapped } => decrypter
            .decrypt(KeyOp::RsaOaep {
                wrapped,
                params: *params,
            })
            .inspect_err(|_| failure_detail("rsa_oaep")),
        BoundKey::Ecdh {
            group,
            point,
            kdf_digest,
            kdf_params,
            wrap,
            wrapped,
        } => decrypter
            .decrypt(KeyOp::Ecdh { peer: point, group })
            .inspect_err(|_| failure_detail("ecdh"))
            .and_then(|z| {
                let kek = kdf::concat_kdf(*kdf_digest, &z, (wrap.kek_len() * 8) as u32, kdf_params);
                keywrap::unwrap(*wrap, &kek, wrapped).inspect_err(|_| failure_detail("key_unwrap"))
            }),
    };
    match unlocked {
        Ok(cek) if cek.len() == cipher.key_len() => cek,
        Ok(_) => {
            failure_detail("cek_length");
            random_cek(cipher)
        }
        Err(_) => random_cek(cipher),
    }
}

fn random_cek(cipher: XmlEncPayloadAlgorithm) -> Zeroizing<Vec<u8>> {
    let mut cek = Zeroizing::new(vec![0u8; cipher.key_len()]);
    // A zero key only if the OS has no randomness — the tag check still fails.
    let _ = getrandom::fill(&mut cek);
    cek
}

/// Content decryption: every failure is one `DecryptionFailed` with one fixed
/// message.
pub(crate) fn decrypt_content(
    cipher: XmlEncPayloadAlgorithm,
    cek: &[u8],
    blob: &[u8],
) -> Result<Vec<u8>> {
    let span = tracing::debug_span!(
        target: "asx",
        "asx.decrypt",
        algorithm = cipher.uri(),
        outcome = tracing::field::Empty,
    );
    let result = span.in_scope(|| {
        gcm::decrypt(cipher, cek, blob).map_err(|_| {
            failure_detail("aes_gcm");
            AsxError::new(
                ErrorCode::DecryptionFailed,
                DECRYPTION_FAILED,
                ErrorContext::new(STAGE),
            )
        })
    });
    crate::telemetry::child_outcome(&span, &result);
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD as B64;

    fn rsa_pair() -> (Vec<u8>, Vec<u8>) {
        crate::test_support::self_signed_rsa("asx-xmlenc-unit")
    }

    fn ec_pair(nid: openssl::nid::Nid) -> (Vec<u8>, Vec<u8>) {
        let group = EcGroup::from_curve_name(nid).unwrap();
        let key = PKey::from_ec_key(openssl::ec::EcKey::generate(&group).unwrap()).unwrap();
        let mut name = openssl::x509::X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", "asx-xmlenc-ec").unwrap();
        let name = name.build();
        let mut b = X509::builder().unwrap();
        b.set_version(2).unwrap();
        b.set_subject_name(&name).unwrap();
        b.set_issuer_name(&name).unwrap();
        b.set_pubkey(&key).unwrap();
        b.set_not_before(&openssl::asn1::Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        b.set_not_after(&openssl::asn1::Asn1Time::days_from_now(30).unwrap())
            .unwrap();
        b.sign(&key, openssl::hash::MessageDigest::sha256())
            .unwrap();
        (
            b.build().to_pem().unwrap(),
            key.private_key_to_pem_pkcs8().unwrap(),
        )
    }

    const CID: &str = "part0.unit@asx";

    fn encrypt_one(
        payload: &[u8],
        cert: &[u8],
        cipher: XmlEncPayloadAlgorithm,
    ) -> (String, Vec<u8>) {
        let (xml, mut bodies) =
            encrypt_swa(&[(CID, "application/gzip", payload)], cert, cipher).unwrap();
        (xml, bodies.remove(0))
    }

    fn decrypt_one(xml: &str, body: &[u8], key: &[u8]) -> Result<Vec<u8>> {
        decrypt_swa(xml.as_bytes(), &[(CID, body)], key).map(|mut v| v.remove(0))
    }

    fn replace_cipher_value(xml: &str, f: impl Fn(Vec<u8>) -> Vec<u8>) -> String {
        let open = "<xenc:CipherValue>";
        let at = xml.find(open).unwrap() + open.len();
        let end = at + xml[at..].find('<').unwrap();
        let bytes = B64.decode(&xml[at..end]).unwrap();
        format!("{}{}{}", &xml[..at], B64.encode(f(bytes)), &xml[end..])
    }

    fn flip(mut b: Vec<u8>) -> Vec<u8> {
        let i = b.len() - 1;
        b[i] ^= 1;
        b
    }

    /// On the SwA envelope, OAEP decode,
    /// key unwrap, CEK length and GCM tag failures carry one code and one
    /// message, and content decryption is reached in 4 of 4.
    #[test]
    fn decryption_failures_are_indistinguishable() {
        let (rsa_cert, rsa_key) = rsa_pair();
        let (ec_cert, ec_key) = ec_pair(openssl::nid::Nid::BRAINPOOL_P256R1);
        let (rsa, rsa_body) = encrypt_one(b"p", &rsa_cert, XmlEncPayloadAlgorithm::Aes128Gcm);
        let (ec, ec_body) = encrypt_one(b"p", &ec_cert, XmlEncPayloadAlgorithm::Aes128Gcm);
        let oversized_cek = {
            let cert = X509::from_pem(&rsa_cert).unwrap();
            let public = cert.public_key().unwrap();
            let mut enc = openssl::encrypt::Encrypter::new(&public).unwrap();
            enc.set_rsa_padding(openssl::rsa::Padding::PKCS1_OAEP)
                .unwrap();
            enc.set_rsa_oaep_md(openssl::hash::MessageDigest::sha256())
                .unwrap();
            enc.set_rsa_mgf1_md(openssl::hash::MessageDigest::sha256())
                .unwrap();
            let cek = [7u8; 32];
            let mut out = vec![0u8; enc.encrypt_len(&cek).unwrap()];
            let n = enc.encrypt(&cek, &mut out).unwrap();
            out.truncate(n);
            out
        };
        let cases = [
            (
                "D1 OAEP",
                replace_cipher_value(&rsa, flip),
                rsa_body.clone(),
                &rsa_key,
            ),
            (
                "D2 unwrap",
                replace_cipher_value(&ec, flip),
                ec_body.clone(),
                &ec_key,
            ),
            (
                "D3 CEK length",
                replace_cipher_value(&rsa, |_| oversized_cek.clone()),
                rsa_body.clone(),
                &rsa_key,
            ),
            ("D4 tag", rsa.clone(), flip(rsa_body.clone()), &rsa_key),
        ];
        let _ = gcm::probe::take();
        let mut messages = Vec::new();
        for (name, xml, body, key) in cases {
            let err = decrypt_one(&xml, &body, key).expect_err(name);
            assert_eq!(err.code, ErrorCode::DecryptionFailed, "{name}");
            messages.push(err.message);
        }
        assert!(
            messages.iter().all(|m| m == DECRYPTION_FAILED),
            "{messages:?}"
        );
        assert_eq!(
            gcm::probe::take(),
            4,
            "content decryption reached in 4 of 4"
        );
        // A body shorter than nonce and tag fails the same way.
        let err = decrypt_one(&rsa, &[0u8; 27], &rsa_key).unwrap_err();
        assert_eq!(
            (err.code, err.message.as_str()),
            (ErrorCode::DecryptionFailed, DECRYPTION_FAILED)
        );
    }

    /// A counting `PrivateKeyStep`: the private-key step is one call with the
    /// declared operation, whatever the part count.
    #[derive(Debug)]
    struct Counting {
        inner: PemDecrypter,
        calls: std::sync::Mutex<Vec<String>>,
    }

    impl PrivateKeyStep for Counting {
        fn decrypt(&self, op: KeyOp<'_>) -> Result<Zeroizing<Vec<u8>>> {
            let label = match &op {
                KeyOp::RsaOaep { params, .. } => format!("rsa-oaep {params:?}"),
                KeyOp::Ecdh { group, .. } => {
                    format!("ecdh {:?}", NamedCurve::from_group(group).ok())
                }
            };
            self.calls.lock().unwrap().push(label);
            self.inner.decrypt(op)
        }
    }

    impl RecipientKeys for Counting {
        fn select(&self, _: &EncryptedKeySpec) -> Option<(RecipientKey, &dyn PrivateKeyStep)> {
            Some((self.inner.recipient()?, self))
        }
    }

    fn decrypt_with(xml: &str, bodies: &[Vec<u8>], decrypter: &Counting) -> Result<Vec<Vec<u8>>> {
        let doc = crate::xml::parse(xml, XmlLimits::ENVELOPE, STAGE).expect("parse");
        let declared = ["a@asx".to_string(), "b@asx".to_string()];
        let envelope =
            resolve_envelope(&doc, doc.root_element(), &declared, None, 16)?.expect("envelope");
        let bodies: Vec<&[u8]> = bodies.iter().map(Vec::as_slice).collect();
        decrypt_attachments(&envelope, &bodies, decrypter)
    }

    #[test]
    fn decrypter_called_once_with_declared_key_op() {
        let parts: [(&str, &str, &[u8]); 2] = [
            ("a@asx", "application/gzip", b"seam-a"),
            ("b@asx", "application/gzip", b"seam-b"),
        ];
        let (rsa_cert, rsa_key) = rsa_pair();
        let (xml, bodies) =
            encrypt_swa(&parts, &rsa_cert, XmlEncPayloadAlgorithm::Aes256Gcm).unwrap();
        let counting = Counting {
            inner: PemDecrypter::from_pem(&rsa_key).unwrap(),
            calls: std::sync::Mutex::new(Vec::new()),
        };
        assert_eq!(
            decrypt_with(&xml, &bodies, &counting).unwrap(),
            vec![b"seam-a".to_vec(), b"seam-b".to_vec()]
        );
        assert_eq!(
            *counting.calls.lock().unwrap(),
            vec!["rsa-oaep RsaOaepParams { digest: Sha256, mgf: Mgf1Sha256 }".to_string()]
        );

        let (ec_cert, ec_key) = ec_pair(openssl::nid::Nid::BRAINPOOL_P256R1);
        let (xml, bodies) =
            encrypt_swa(&parts, &ec_cert, XmlEncPayloadAlgorithm::Aes128Gcm).unwrap();
        let counting = Counting {
            inner: PemDecrypter::from_pem(&ec_key).unwrap(),
            calls: std::sync::Mutex::new(Vec::new()),
        };
        assert_eq!(decrypt_with(&xml, &bodies, &counting).unwrap().len(), 2);
        assert_eq!(
            *counting.calls.lock().unwrap(),
            vec!["ecdh Some(BrainpoolP256r1)".to_string()]
        );
    }

    #[test]
    fn rsa_and_ec_round_trips_on_every_supported_curve() {
        let (rsa_cert, rsa_key) = rsa_pair();
        for cipher in [
            XmlEncPayloadAlgorithm::Aes128Gcm,
            XmlEncPayloadAlgorithm::Aes256Gcm,
        ] {
            let (xml, body) = encrypt_one(b"rsa", &rsa_cert, cipher);
            assert!(xml.contains("BinarySecurityToken"), "BST form for RSA");
            assert_eq!(decrypt_one(&xml, &body, &rsa_key).unwrap(), b"rsa");
        }
        for nid in [
            openssl::nid::Nid::X9_62_PRIME256V1,
            openssl::nid::Nid::SECP384R1,
            openssl::nid::Nid::SECP521R1,
            openssl::nid::Nid::BRAINPOOL_P256R1,
            openssl::nid::Nid::BRAINPOOL_P384R1,
            openssl::nid::Nid::BRAINPOOL_P512R1,
        ] {
            let (cert, key) = ec_pair(nid);
            for cipher in [
                XmlEncPayloadAlgorithm::Aes128Gcm,
                XmlEncPayloadAlgorithm::Aes256Gcm,
            ] {
                let (xml, body) = encrypt_one(b"ec", &cert, cipher);
                assert!(xml.contains("ECDH-ES") && xml.contains("ConcatKDF"));
                assert!(xml.contains("X509SubjectKeyIdentifier"), "SKI form for EC");
                let wrap = if cipher == XmlEncPayloadAlgorithm::Aes128Gcm {
                    "kw-aes128"
                } else {
                    "kw-aes256"
                };
                assert!(xml.contains(wrap), "{nid:?} {cipher:?}: {xml}");
                assert_eq!(decrypt_one(&xml, &body, &key).unwrap(), b"ec", "{nid:?}");
            }
        }
    }

    #[test]
    fn decrypt_is_prefix_agnostic_and_skips_comments() {
        let (cert, key) = ec_pair(openssl::nid::Nid::X9_62_PRIME256V1);
        let (xml, body) = encrypt_one(b"prefix", &cert, XmlEncPayloadAlgorithm::Aes128Gcm);
        let renamed = xml
            .replace("xmlns:xenc11=", "xmlns:e11=")
            .replace("xmlns:xenc=", "xmlns:e=")
            .replace("xmlns:dsig11=", "xmlns:d11=")
            .replace("xmlns:ds=", "xmlns:s=")
            .replace("xenc11:", "e11:")
            .replace("xenc:", "e:")
            .replace("dsig11:", "d11:")
            .replace("ds:", "s:");
        let wrapped = format!("<?xml version=\"1.0\"?>\n<!--noise-->{renamed}<!--more-->");
        assert_eq!(decrypt_one(&wrapped, &body, &key).unwrap(), b"prefix");
    }

    /// A message without payload parts carries no `EncryptedKey`, and
    /// none is required.
    #[test]
    fn zero_parts_need_no_encrypted_key() {
        let (cert, _) = rsa_pair();
        let cert = X509::from_pem(&cert).unwrap();
        assert!(
            encrypt_attachments(
                &[],
                &cert,
                RecipientForm::Bst,
                XmlEncPayloadAlgorithm::Aes128Gcm,
                "x"
            )
            .unwrap()
            .is_none()
        );
        let xml = format!("<wsse:Security xmlns:wsse=\"{}\"/>", ns::WSSE);
        let doc = crate::xml::parse(&xml, XmlLimits::ENVELOPE, STAGE).unwrap();
        assert!(
            resolve_envelope(&doc, doc.root_element(), &[], None, 16)
                .unwrap()
                .is_none()
        );
    }

    /// The BDEW envelope under fixed randomness (recipient key,
    /// ephemeral key, CEK, nonces from `tests/fixtures/wssec/swa-enc/`) is
    /// byte-pinned in `swa-enc-bdew-fixed.mime`.
    #[test]
    fn bdew_fixed_randomness_vector_is_byte_pinned() {
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/wssec/swa-enc/");
        let read = |name: &str| std::fs::read(format!("{dir}{name}")).unwrap();
        let cert = X509::from_pem(&read("recipient-bp256.cert.pem")).unwrap();
        let fixed = randomness::Fixed {
            cek: (0u8..16).collect(),
            nonces: vec![[0x11; 12], [0x22; 12]],
            ephemeral_pem: Some(read("ephemeral-bp256.key.pem")),
        };
        let envelope = randomness::fixed(fixed, || {
            encrypt_attachments(
                &[
                    OutboundPart {
                        content_id: "part0.fixed@asx",
                        mime_type: "application/gzip",
                        plaintext: b"first part",
                    },
                    OutboundPart {
                        content_id: "part1.fixed@asx",
                        mime_type: "application/gzip",
                        plaintext: b"second part",
                    },
                ],
                &cert,
                RecipientForm::Ski,
                XmlEncPayloadAlgorithm::Aes128Gcm,
                "fixed",
            )
        })
        .unwrap()
        .unwrap();
        let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
        let rendered = format!(
            "{}\n--part0.fixed@asx\n{}\n--part1.fixed@asx\n{}\n",
            envelope.header.as_str(),
            hex(&envelope.bodies[0]),
            hex(&envelope.bodies[1])
        );
        let golden_path = format!("{dir}../swa-enc-bdew-fixed.mime");
        if std::env::var_os("ASX_RECORD_GOLDEN").is_some() {
            std::fs::write(&golden_path, &rendered).unwrap();
        }
        assert_eq!(
            rendered,
            std::fs::read_to_string(&golden_path).expect("golden recorded"),
            "the BDEW SwA envelope changed"
        );
        // And it decrypts with the recipient key.
        let xml = format!(
            "<wsse:Security xmlns:wsse=\"{}\">{}</wsse:Security>",
            ns::WSSE,
            envelope.header.as_str()
        );
        let parts = [
            ("part0.fixed@asx", envelope.bodies[0].as_slice()),
            ("part1.fixed@asx", envelope.bodies[1].as_slice()),
        ];
        assert_eq!(
            decrypt_swa(xml.as_bytes(), &parts, &read("recipient-bp256.key.pem")).unwrap(),
            vec![b"first part".to_vec(), b"second part".to_vec()]
        );
    }
}
