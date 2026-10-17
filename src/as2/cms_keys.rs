//! AS2 CMS through the key seams.
//!
//! OpenSSL's `CMS_sign`/`CMS_decrypt` need the private key in process, so the
//! two private-key steps of AS2 are done here around the public traits:
//!
//! - **Signing**: the `SignedData` is assembled with the RustCrypto `cms`/`der`
//!   types. The signed attributes (content-type, message-digest, signing-time)
//!   are DER-encoded as a `SET OF` and handed to one [`Signer::sign`]; the
//!   result is emitted as the detached `multipart/signed` entity, laid out
//!   as OpenSSL writes it.
//! - **Decryption**: the `EnvelopedData` is parsed, the one
//!   `KeyTransRecipientInfo` naming a configured decrypter's certificate (by
//!   issuer-serial or SKI) is selected — never trial decryption — and one
//!   [`Decrypter::decrypt`] unwraps the CEK. A failed unwrap continues with a
//!   random CEK, and every cause ends in the same [`DecryptionFailed`] after
//!   the content step (RFC 3218 §2.3.2).
//!
//! Outbound encryption and inbound signature verification stay on OpenSSL:
//! neither needs a private key.

use crate::keys::{Certificate, Decrypter, KeyKind, KeyOp, SignatureAlgorithm, Signer};
use cms::cert::x509::Certificate as X509Certificate;
use cms::cert::x509::attr::Attribute;
use cms::cert::x509::spki::AlgorithmIdentifierOwned;
use cms::cert::x509::time::Time;
use cms::cert::{CertificateChoices, IssuerAndSerialNumber};
use cms::content_info::{CmsVersion, ContentInfo};
use cms::enveloped_data::{EnvelopedData, RecipientIdentifier, RecipientInfo};
use cms::signed_data::{
    CertificateSet, EncapsulatedContentInfo, SignedData, SignerIdentifier, SignerInfo, SignerInfos,
};
use der::asn1::{ObjectIdentifier as Oid, OctetString, SetOfVec, UtcTime};
use der::{Any, Decode, Encode};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;

const ID_DATA: Oid = Oid::new_unwrap("1.2.840.113549.1.7.1");
const ID_SIGNED_DATA: Oid = Oid::new_unwrap("1.2.840.113549.1.7.2");
const ID_ENVELOPED_DATA: Oid = Oid::new_unwrap("1.2.840.113549.1.7.3");
const ID_CONTENT_TYPE: Oid = Oid::new_unwrap("1.2.840.113549.1.9.3");
const ID_MESSAGE_DIGEST: Oid = Oid::new_unwrap("1.2.840.113549.1.9.4");
const ID_SIGNING_TIME: Oid = Oid::new_unwrap("1.2.840.113549.1.9.5");
const ID_SHA256: Oid = Oid::new_unwrap("2.16.840.1.101.3.4.2.1");
const SHA256_WITH_RSA: Oid = Oid::new_unwrap("1.2.840.113549.1.1.11");
const ECDSA_WITH_SHA256: Oid = Oid::new_unwrap("1.2.840.10045.4.3.2");
const RSA_ENCRYPTION: Oid = Oid::new_unwrap("1.2.840.113549.1.1.1");
const RSAES_OAEP: Oid = Oid::new_unwrap("1.2.840.113549.1.1.7");
const ID_MGF1: Oid = Oid::new_unwrap("1.2.840.113549.1.1.8");
const ID_P_SPECIFIED: Oid = Oid::new_unwrap("1.2.840.113549.1.1.9");
const AES128_CBC: Oid = Oid::new_unwrap("2.16.840.1.101.3.4.1.2");
const AES192_CBC: Oid = Oid::new_unwrap("2.16.840.1.101.3.4.1.22");
const AES256_CBC: Oid = Oid::new_unwrap("2.16.840.1.101.3.4.1.42");

// ── Signing ─────────────────────────────────────────────────────────────────

/// Why a `SignedData` could not be produced.
#[derive(Debug)]
pub(crate) enum SignError {
    /// The [`Signer`] failed (an HSM/KMS outage): `ErrorKind::Backend`.
    Signer(crate::error::BoxError),
    /// The structure around the signature could not be built (an unusable
    /// certificate or key type).
    Build(String),
}

impl std::fmt::Display for SignError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SignError::Signer(err) => write!(f, "the signer failed: {err}"),
            SignError::Build(detail) => write!(f, "the CMS signature could not be built: {detail}"),
        }
    }
}

impl SignError {
    /// The public error: a signer failure is `Backend` (retryable), anything
    /// else is the configured key's fault.
    pub(crate) fn into_error(self) -> crate::error::Error {
        match self {
            SignError::Signer(err) => crate::error::Error::backend("the signer failed", err),
            SignError::Build(detail) => crate::error::Error::config(format!(
                "LocalParty::signer: the CMS signature could not be built: {detail}"
            )),
        }
    }
}

fn build_err(detail: impl std::fmt::Display) -> SignError {
    SignError::Build(detail.to_string())
}

/// Everything of a `SignerInfo` except the signature.
struct Unsigned {
    algorithm: SignatureAlgorithm,
    signature_algorithm: AlgorithmIdentifierOwned,
    sid: SignerIdentifier,
    attrs: SetOfVec<Attribute>,
    attrs_der: Vec<u8>,
    certificates: Vec<X509Certificate>,
}

fn attribute(oid: Oid, value: Any) -> Result<Attribute, SignError> {
    Ok(Attribute {
        oid,
        values: SetOfVec::try_from(vec![value]).map_err(build_err)?,
    })
}

fn prepare(signer: &dyn Signer, entity: &[u8], now: SystemTime) -> Result<Unsigned, SignError> {
    let chain = signer.certificate_chain();
    let leaf = chain
        .first()
        .ok_or_else(|| build_err("the signer has no certificate"))?;
    let (algorithm, signature_algorithm) = match leaf.key_kind() {
        KeyKind::Rsa { .. } => (
            SignatureAlgorithm::RsaSha256,
            AlgorithmIdentifierOwned {
                oid: SHA256_WITH_RSA,
                parameters: Some(Any::null()),
            },
        ),
        KeyKind::Ec { .. } => (
            SignatureAlgorithm::EcdsaSha256,
            AlgorithmIdentifierOwned {
                oid: ECDSA_WITH_SHA256,
                parameters: None,
            },
        ),
        other => {
            return Err(build_err(format!(
                "a {} key cannot sign AS2 messages",
                other.describe()
            )));
        }
    };
    let certificates = chain
        .iter()
        .map(|c| X509Certificate::from_der(c.der()).map_err(build_err))
        .collect::<Result<Vec<_>, _>>()?;
    let tbs = &certificates[0].tbs_certificate;
    let sid = SignerIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber {
        issuer: tbs.issuer.clone(),
        serial_number: tbs.serial_number.clone(),
    });
    let digest = openssl::sha::sha256(entity);
    let seconds = now.duration_since(UNIX_EPOCH).map_err(build_err)?.as_secs();
    let signing_time = Time::UtcTime(
        UtcTime::from_unix_duration(Duration::from_secs(seconds)).map_err(build_err)?,
    );
    let attrs = SetOfVec::try_from(vec![
        attribute(
            ID_CONTENT_TYPE,
            Any::encode_from(&ID_DATA).map_err(build_err)?,
        )?,
        attribute(
            ID_SIGNING_TIME,
            Any::encode_from(&signing_time).map_err(build_err)?,
        )?,
        attribute(
            ID_MESSAGE_DIGEST,
            Any::encode_from(&OctetString::new(digest.to_vec()).map_err(build_err)?)
                .map_err(build_err)?,
        )?,
    ])
    .map_err(build_err)?;
    // RFC 5652 §5.4: the signature covers the DER `SET OF`, not the
    // `[0] IMPLICIT` form that travels in the SignerInfo.
    let attrs_der = attrs.to_der().map_err(build_err)?;
    Ok(Unsigned {
        algorithm,
        signature_algorithm,
        sid,
        attrs,
        attrs_der,
        certificates,
    })
}

fn assemble(unsigned: Unsigned, signature: Vec<u8>) -> Result<Vec<u8>, SignError> {
    let digest_alg = AlgorithmIdentifierOwned {
        oid: ID_SHA256,
        parameters: None,
    };
    let signer_info = SignerInfo {
        version: CmsVersion::V1,
        sid: unsigned.sid,
        digest_alg: digest_alg.clone(),
        signed_attrs: Some(unsigned.attrs),
        signature_algorithm: unsigned.signature_algorithm,
        signature: OctetString::new(signature).map_err(build_err)?,
        unsigned_attrs: None,
    };
    let certificates = SetOfVec::try_from(
        unsigned
            .certificates
            .into_iter()
            .map(CertificateChoices::Certificate)
            .collect::<Vec<_>>(),
    )
    .map_err(build_err)?;
    let signed_data = SignedData {
        version: CmsVersion::V1,
        digest_algorithms: SetOfVec::try_from(vec![digest_alg]).map_err(build_err)?,
        encap_content_info: EncapsulatedContentInfo {
            econtent_type: ID_DATA,
            econtent: None,
        },
        certificates: Some(CertificateSet(certificates)),
        crls: None,
        signer_infos: SignerInfos(SetOfVec::try_from(vec![signer_info]).map_err(build_err)?),
    };
    ContentInfo {
        content_type: ID_SIGNED_DATA,
        content: Any::encode_from(&signed_data).map_err(build_err)?,
    }
    .to_der()
    .map_err(build_err)
}

/// The detached S/MIME entity, laid out octet for octet as OpenSSL's
/// `SMIME_write_PKCS7(DETACHED | BINARY)` writes it: LF line ends around the
/// parts, the entity verbatim.
fn multipart_signed(entity: &[u8], signature_der: &[u8]) -> Result<Vec<u8>, SignError> {
    use base64::Engine as _;
    let mut random = [0u8; 16];
    getrandom::fill(&mut random).map_err(build_err)?;
    let boundary: String = random.iter().map(|b| format!("{b:02X}")).collect();
    let mut out = format!(
        "MIME-Version: 1.0\nContent-Type: multipart/signed; \
         protocol=\"application/x-pkcs7-signature\"; micalg=\"sha-256\"; \
         boundary=\"----{boundary}\"\n\nThis is an S/MIME signed message\n\n------{boundary}\n"
    )
    .into_bytes();
    out.extend_from_slice(entity);
    out.extend_from_slice(
        format!(
            "\n------{boundary}\nContent-Type: application/x-pkcs7-signature; \
             name=\"smime.p7s\"\nContent-Transfer-Encoding: base64\n\
             Content-Disposition: attachment; filename=\"smime.p7s\"\n\n"
        )
        .as_bytes(),
    );
    let encoded = base64::engine::general_purpose::STANDARD.encode(signature_der);
    for line in encoded.as_bytes().chunks(64) {
        out.extend_from_slice(line);
        out.push(b'\n');
    }
    out.extend_from_slice(format!("\n------{boundary}--\n\n").as_bytes());
    Ok(out)
}

/// Sign `entity` (the complete MIME entity) with one `Signer::sign` and
/// return the `multipart/signed` S/MIME entity.
/// `now` is the CMS `signingTime` (the client's clock).
pub(crate) async fn sign_detached(
    signer: &dyn Signer,
    entity: &[u8],
    now: SystemTime,
) -> Result<Vec<u8>, SignError> {
    let span = tracing::debug_span!(
        target: "asx",
        "asx.sign",
        algorithm = "cms-signed-data",
        reference_count = 1usize,
    );
    let unsigned = span.in_scope(|| prepare(signer, entity, now))?;
    let signature = tracing::Instrument::instrument(
        signer.sign(unsigned.algorithm, &unsigned.attrs_der),
        span.clone(),
    )
    .await
    .map_err(SignError::Signer)?;
    let der = span.in_scope(|| assemble(unsigned, signature))?;
    multipart_signed(entity, &der)
}

/// [`sign_detached`] for a signer whose future is ready at once (the
/// in-memory `KeyPair` of the crafting hooks); anything else is refused.
pub(crate) fn sign_detached_ready(
    signer: &dyn Signer,
    entity: &[u8],
    now: SystemTime,
) -> Result<Vec<u8>, SignError> {
    use std::future::Future as _;
    let future = sign_detached(signer, entity, now);
    let mut future = std::pin::pin!(future);
    let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
    match future.as_mut().poll(&mut cx) {
        std::task::Poll::Ready(result) => result,
        std::task::Poll::Pending => Err(build_err("the signer did not complete synchronously")),
    }
}

// ── Decryption ──────────────────────────────────────────────────────────────

/// The one decryption outcome. Carries no cause by design.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DecryptionFailed;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Transport {
    Pkcs1v15,
    Oaep,
}

/// A parsed `EnvelopedData` with the recipient selected.
pub(crate) struct Envelope {
    decrypter: usize,
    transport: Transport,
    wrapped: Vec<u8>,
    cipher: openssl::symm::Cipher,
    iv: Vec<u8>,
    ciphertext: Vec<u8>,
}

/// `RSAES-OAEP-params` (RFC 4055 §4.1).
#[derive(der::Sequence)]
struct RsaesOaepParams {
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional = "true")]
    hash: Option<AlgorithmIdentifierOwned>,
    #[asn1(context_specific = "1", tag_mode = "EXPLICIT", optional = "true")]
    mask_gen: Option<AlgorithmIdentifierOwned>,
    #[asn1(context_specific = "2", tag_mode = "EXPLICIT", optional = "true")]
    p_source: Option<AlgorithmIdentifierOwned>,
}

/// The key transport, when it is one [`KeyOp`] can express: RSAES-PKCS1-v1_5,
/// or RSA-OAEP with SHA-256, MGF1-SHA-256 and an empty label.
fn transport(alg: &AlgorithmIdentifierOwned) -> Option<Transport> {
    if alg.oid == RSA_ENCRYPTION {
        return Some(Transport::Pkcs1v15);
    }
    if alg.oid != RSAES_OAEP {
        return None;
    }
    let params: RsaesOaepParams = alg.parameters.as_ref()?.decode_as().ok()?;
    let sha256 = |a: &AlgorithmIdentifierOwned| a.oid == ID_SHA256;
    let mgf_ok = params.mask_gen.as_ref().is_some_and(|mgf| {
        mgf.oid == ID_MGF1
            && mgf
                .parameters
                .as_ref()
                .and_then(|p| p.decode_as::<AlgorithmIdentifierOwned>().ok())
                .is_some_and(|h| sha256(&h))
    });
    let label_ok = match &params.p_source {
        None => true,
        Some(p) => {
            p.oid == ID_P_SPECIFIED
                && p.parameters
                    .as_ref()
                    .and_then(|v| v.decode_as::<OctetString>().ok())
                    .is_some_and(|label| label.as_bytes().is_empty())
        }
    };
    (params.hash.as_ref().is_some_and(sha256) && mgf_ok && label_ok).then_some(Transport::Oaep)
}

fn content_cipher(alg: &AlgorithmIdentifierOwned) -> Option<(openssl::symm::Cipher, Vec<u8>)> {
    let cipher = match alg.oid {
        oid if oid == AES128_CBC => openssl::symm::Cipher::aes_128_cbc(),
        oid if oid == AES192_CBC => openssl::symm::Cipher::aes_192_cbc(),
        oid if oid == AES256_CBC => openssl::symm::Cipher::aes_256_cbc(),
        _ => return None,
    };
    let iv = alg.parameters.as_ref()?.decode_as::<OctetString>().ok()?;
    (Some(iv.as_bytes().len()) == cipher.iv_len()).then(|| (cipher, iv.as_bytes().to_vec()))
}

/// Whether `rid` names `cert` (issuer-serial or SKI).
fn names(rid: &RecipientIdentifier, cert: &Certificate, parsed: &X509Certificate) -> bool {
    match rid {
        RecipientIdentifier::IssuerAndSerialNumber(ias) => {
            let tbs = &parsed.tbs_certificate;
            ias.issuer == tbs.issuer && ias.serial_number == tbs.serial_number
        }
        RecipientIdentifier::SubjectKeyIdentifier(ski) => cert
            .ski_candidates()
            .iter()
            .any(|c| c.as_slice() == ski.0.as_bytes()),
    }
}

/// The DER `ContentInfo` carried by the S/MIME entity `smime`: the body with
/// its transfer encoding removed, re-encoded through OpenSSL so a BER
/// (indefinite-length) encoding from a streaming sender becomes DER.
fn content_info_der(smime: &[u8]) -> Option<Vec<u8>> {
    use base64::Engine as _;
    let raw = mailparse::parse_mail(smime).ok()?.get_body_raw().ok()?;
    // DER (a SEQUENCE) as it is, otherwise base64 — what an S/MIME reader
    // assumes for `application/pkcs7-mime` without a transfer encoding.
    let raw = if raw.first() == Some(&0x30) {
        raw
    } else {
        let text: Vec<u8> = raw
            .into_iter()
            .filter(|b| !b.is_ascii_whitespace())
            .collect();
        base64::engine::general_purpose::STANDARD
            .decode(text)
            .ok()?
    };
    // The `openssl` crate panics on an error string that is not UTF-8;
    // hostile input must end in the uniform failure instead.
    std::panic::catch_unwind(|| {
        openssl::cms::CmsContentInfo::from_der(&raw)
            .and_then(|cms| cms.to_der())
            .ok()
    })
    .ok()
    .flatten()
}

/// Parse the S/MIME `EnvelopedData` in `smime` and select the one
/// `KeyTransRecipientInfo` that names one of `recipients` (RSA keys only).
/// No match, or more than one, is [`DecryptionFailed`]; no key is tried.
pub(crate) fn parse_envelope(
    smime: &[u8],
    recipients: &[Certificate],
) -> Result<Envelope, DecryptionFailed> {
    let der = content_info_der(smime).ok_or(DecryptionFailed)?;
    let info = ContentInfo::from_der(&der).map_err(|_| DecryptionFailed)?;
    if info.content_type != ID_ENVELOPED_DATA {
        return Err(DecryptionFailed);
    }
    let enveloped: EnvelopedData = info.content.decode_as().map_err(|_| DecryptionFailed)?;
    let content = enveloped.encrypted_content;
    if content.content_type != ID_DATA {
        return Err(DecryptionFailed);
    }
    let (cipher, iv) = content_cipher(&content.content_enc_alg).ok_or(DecryptionFailed)?;
    let ciphertext = content
        .encrypted_content
        .ok_or(DecryptionFailed)?
        .as_bytes()
        .to_vec();
    let parsed: Vec<Option<X509Certificate>> = recipients
        .iter()
        .map(|c| {
            matches!(c.key_kind(), KeyKind::Rsa { .. })
                .then(|| X509Certificate::from_der(c.der()).ok())
                .flatten()
        })
        .collect();
    let mut selected = Vec::new();
    for info in enveloped.recip_infos.0.iter() {
        let RecipientInfo::Ktri(ktri) = info else {
            continue;
        };
        for (index, cert) in recipients.iter().enumerate() {
            if let Some(parsed) = &parsed[index]
                && names(&ktri.rid, cert, parsed)
            {
                selected.push((index, ktri));
            }
        }
    }
    let [(decrypter, ktri)] = selected.as_slice() else {
        return Err(DecryptionFailed);
    };
    Ok(Envelope {
        decrypter: *decrypter,
        transport: transport(&ktri.key_enc_alg).ok_or(DecryptionFailed)?,
        wrapped: ktri.enc_key.as_bytes().to_vec(),
        cipher,
        iv,
        ciphertext,
    })
}

/// Unwrap the CEK with the selected decrypter: one key operation. Never
/// fails: a failed or malformed unwrap yields a random CEK, so the outcome is
/// decided only by the content step.
pub(crate) async fn unwrap_cek(
    envelope: &Envelope,
    decrypters: &[Arc<dyn Decrypter>],
) -> Zeroizing<Vec<u8>> {
    let key_len = envelope.cipher.key_len();
    let op = match envelope.transport {
        Transport::Pkcs1v15 => KeyOp::RsaPkcs1v15(&envelope.wrapped),
        Transport::Oaep => KeyOp::RsaOaep(&envelope.wrapped),
    };
    let unwrapped = match decrypters.get(envelope.decrypter) {
        Some(decrypter) => decrypter.decrypt(op).await.ok(),
        None => None,
    };
    match unwrapped {
        Some(cek) if cek.len() == key_len => cek,
        _ => {
            let mut random = Zeroizing::new(vec![0u8; key_len]);
            // Without randomness the zero key still fails uniformly.
            let _ = getrandom::fill(&mut random);
            random
        }
    }
}

/// Decrypt the content with `cek`. The plaintext must be a MIME entity: the
/// octets a random CEK yields are refused here too, with the same outcome.
pub(crate) fn decrypt_content(
    envelope: &Envelope,
    cek: &[u8],
) -> Result<Vec<u8>, DecryptionFailed> {
    let plain = openssl::symm::decrypt(
        envelope.cipher,
        cek,
        Some(&envelope.iv),
        &envelope.ciphertext,
    )
    .map_err(|_| DecryptionFailed)?;
    if super::body_starts_with_mime_header(&plain) {
        Ok(plain)
    } else {
        Err(DecryptionFailed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::KeyPair;

    fn pair(
        rsa: bool,
    ) -> (
        KeyPair,
        openssl::x509::X509,
        openssl::pkey::PKey<openssl::pkey::Private>,
    ) {
        let (cert, key) = if rsa {
            crate::test_support::self_signed_rsa("cms-keys")
        } else {
            let group =
                openssl::ec::EcGroup::from_curve_name(openssl::nid::Nid::X9_62_PRIME256V1).unwrap();
            let key =
                openssl::pkey::PKey::from_ec_key(openssl::ec::EcKey::generate(&group).unwrap())
                    .unwrap();
            let mut name = openssl::x509::X509NameBuilder::new().unwrap();
            name.append_entry_by_nid(openssl::nid::Nid::COMMONNAME, "cms-ec")
                .unwrap();
            let name = name.build();
            let mut b = openssl::x509::X509::builder().unwrap();
            b.set_version(2).unwrap();
            b.set_subject_name(&name).unwrap();
            b.set_issuer_name(&name).unwrap();
            b.set_pubkey(&key).unwrap();
            b.set_not_before(&openssl::asn1::Asn1Time::days_from_now(0).unwrap())
                .unwrap();
            b.set_not_after(&openssl::asn1::Asn1Time::days_from_now(2).unwrap())
                .unwrap();
            b.sign(&key, openssl::hash::MessageDigest::sha256())
                .unwrap();
            (
                b.build().to_pem().unwrap(),
                key.private_key_to_pem_pkcs8().unwrap(),
            )
        };
        (
            KeyPair::from_pem(&cert, &key).unwrap(),
            openssl::x509::X509::from_pem(&cert).unwrap(),
            openssl::pkey::PKey::private_key_from_pem(&key).unwrap(),
        )
    }

    const ENTITY: &[u8] = b"Content-Type: text/plain\r\n\r\nhello";

    #[test]
    fn signed_entity_verifies_with_openssl_for_rsa_and_ec() {
        for rsa in [true, false] {
            let (keys, cert, _) = pair(rsa);
            let signed = sign_detached_ready(&keys, ENTITY, crate::clock::system().now()).unwrap();
            let (pkcs7, content) = openssl::pkcs7::Pkcs7::from_smime(&signed).unwrap();
            let content = content.expect("detached content");
            assert_eq!(content, ENTITY);
            let mut certs = openssl::stack::Stack::new().unwrap();
            certs.push(cert.clone()).unwrap();
            let mut store = openssl::x509::store::X509StoreBuilder::new().unwrap();
            store.add_cert(cert).unwrap();
            let store = store.build();
            let mut out = Vec::new();
            pkcs7
                .verify(
                    &certs,
                    &store,
                    Some(&content),
                    Some(&mut out),
                    openssl::pkcs7::Pkcs7Flags::BINARY | openssl::pkcs7::Pkcs7Flags::NOVERIFY,
                )
                .unwrap_or_else(|e| panic!("rsa={rsa}: {e}"));
            assert_eq!(out, ENTITY);
            let text = String::from_utf8_lossy(&signed);
            assert!(text.contains("micalg=\"sha-256\""));
        }
    }

    fn encrypt(cert: &openssl::x509::X509, cipher: openssl::symm::Cipher) -> Vec<u8> {
        let mut certs = openssl::stack::Stack::new().unwrap();
        certs.push(cert.clone()).unwrap();
        let p7 = openssl::pkcs7::Pkcs7::encrypt(
            &certs,
            ENTITY,
            cipher,
            openssl::pkcs7::Pkcs7Flags::BINARY,
        )
        .unwrap();
        p7.to_smime(ENTITY, openssl::pkcs7::Pkcs7Flags::BINARY)
            .unwrap()
    }

    async fn open(smime: &[u8], keys: &KeyPair) -> Result<Vec<u8>, DecryptionFailed> {
        let certs = [Decrypter::certificate(keys).clone()];
        let envelope = parse_envelope(smime, &certs)?;
        let decrypters: Vec<Arc<dyn Decrypter>> = vec![Arc::new(keys.clone())];
        let cek = unwrap_cek(&envelope, &decrypters).await;
        decrypt_content(&envelope, &cek)
    }

    #[tokio::test]
    async fn aes_cbc_envelopes_open_through_the_decrypter() {
        let (keys, cert, _) = pair(true);
        for cipher in [
            openssl::symm::Cipher::aes_128_cbc(),
            openssl::symm::Cipher::aes_192_cbc(),
            openssl::symm::Cipher::aes_256_cbc(),
        ] {
            let smime = encrypt(&cert, cipher);
            assert_eq!(open(&smime, &keys).await.unwrap(), ENTITY);
        }
    }

    #[tokio::test]
    async fn ski_and_oaep_recipients_open() {
        // `openssl cms -keyid -keyopt rsa_padding_mode:oaep -keyopt
        // rsa_oaep_md:sha256` shape: the KTRI re-keyed by SKI and the CEK
        // re-wrapped with RSA-OAEP-SHA-256.
        let (keys, cert, pkey) = pair(true);
        let mut certs = openssl::stack::Stack::new().unwrap();
        certs.push(cert.clone()).unwrap();
        let cms = openssl::cms::CmsContentInfo::encrypt(
            &certs,
            ENTITY,
            openssl::symm::Cipher::aes_256_cbc(),
            openssl::cms::CMSOptions::BINARY,
        )
        .unwrap();
        let der = cms.to_der().unwrap();
        // Re-key the KTRI by SKI.
        let info = ContentInfo::from_der(&der).unwrap();
        let mut enveloped: EnvelopedData = info.content.decode_as().unwrap();
        let mut ris: Vec<RecipientInfo> = enveloped.recip_infos.0.into();
        let RecipientInfo::Ktri(ktri) = &mut ris[0] else {
            panic!("ktri")
        };
        let ski = Decrypter::certificate(&keys).ski_candidates()[0].clone();
        let mut dec = openssl::encrypt::Decrypter::new(&pkey).unwrap();
        dec.set_rsa_padding(openssl::rsa::Padding::PKCS1).unwrap();
        let mut cek = vec![0u8; dec.decrypt_len(ktri.enc_key.as_bytes()).unwrap()];
        let n = dec.decrypt(ktri.enc_key.as_bytes(), &mut cek).unwrap();
        cek.truncate(n);
        let public = cert.public_key().unwrap();
        let mut enc = openssl::encrypt::Encrypter::new(&public).unwrap();
        enc.set_rsa_padding(openssl::rsa::Padding::PKCS1_OAEP)
            .unwrap();
        enc.set_rsa_oaep_md(openssl::hash::MessageDigest::sha256())
            .unwrap();
        enc.set_rsa_mgf1_md(openssl::hash::MessageDigest::sha256())
            .unwrap();
        let mut wrapped = vec![0u8; enc.encrypt_len(&cek).unwrap()];
        let n = enc.encrypt(&cek, &mut wrapped).unwrap();
        wrapped.truncate(n);
        let sha256 = AlgorithmIdentifierOwned {
            oid: ID_SHA256,
            parameters: None,
        };
        let params = RsaesOaepParams {
            hash: Some(sha256.clone()),
            mask_gen: Some(AlgorithmIdentifierOwned {
                oid: ID_MGF1,
                parameters: Some(Any::encode_from(&sha256).unwrap()),
            }),
            p_source: None,
        };
        ktri.key_enc_alg = AlgorithmIdentifierOwned {
            oid: RSAES_OAEP,
            parameters: Some(Any::encode_from(&params).unwrap()),
        };
        ktri.enc_key = OctetString::new(wrapped).unwrap();
        ktri.version = CmsVersion::V2;
        ktri.rid = RecipientIdentifier::SubjectKeyIdentifier(
            cms::cert::x509::ext::pkix::SubjectKeyIdentifier(OctetString::new(ski).unwrap()),
        );
        enveloped.recip_infos =
            cms::enveloped_data::RecipientInfos(SetOfVec::try_from(ris).unwrap());
        let der = ContentInfo {
            content_type: ID_ENVELOPED_DATA,
            content: Any::encode_from(&enveloped).unwrap(),
        }
        .to_der()
        .unwrap();
        use base64::Engine as _;
        let smime = format!(
            "MIME-Version: 1.0\nContent-Type: application/pkcs7-mime; smime-type=enveloped-data\nContent-Transfer-Encoding: base64\n\n{}\n",
            base64::engine::general_purpose::STANDARD.encode(&der)
        );
        assert_eq!(open(smime.as_bytes(), &keys).await.unwrap(), ENTITY);
    }

    #[tokio::test]
    async fn an_unknown_recipient_is_the_uniform_failure_without_a_key_operation() {
        let (keys, _, _) = pair(true);
        let (_, other, _) = pair(true);
        let smime = encrypt(&other, openssl::symm::Cipher::aes_256_cbc());
        assert!(parse_envelope(&smime, &[Decrypter::certificate(&keys).clone()]).is_err());
        // Two configured decrypters naming the same certificate are ambiguous.
        let smime = encrypt(
            &openssl::x509::X509::from_der(Decrypter::certificate(&keys).der()).unwrap(),
            openssl::symm::Cipher::aes_256_cbc(),
        );
        let cert = Decrypter::certificate(&keys).clone();
        assert!(parse_envelope(&smime, &[cert.clone(), cert]).is_err());
    }

    #[tokio::test]
    async fn a_corrupted_key_and_corrupted_content_fail_alike() {
        let (keys, cert, _) = pair(true);
        let smime = encrypt(&cert, openssl::symm::Cipher::aes_256_cbc());
        let certs = [Decrypter::certificate(&keys).clone()];
        let decrypters: Vec<Arc<dyn Decrypter>> = vec![Arc::new(keys.clone())];
        let mut bad_key = parse_envelope(&smime, &certs).unwrap();
        bad_key.wrapped[10] ^= 0xff;
        let cek = unwrap_cek(&bad_key, &decrypters).await;
        assert_eq!(decrypt_content(&bad_key, &cek), Err(DecryptionFailed));
        let mut bad_content = parse_envelope(&smime, &certs).unwrap();
        bad_content.ciphertext.pop();
        let cek = unwrap_cek(&bad_content, &decrypters).await;
        assert_eq!(decrypt_content(&bad_content, &cek), Err(DecryptionFailed));
    }
}
