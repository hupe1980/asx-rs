//! Keys and certificates: the [`Signer`] and [`Decrypter`] seams,
//! the in-memory [`KeyPair`] and the parsed [`Certificate`].
//!
//! The library performs every step around the private-key operation — the
//! XMLDSig/CMS structure, ConcatKDF, key unwrap and content decryption — so a
//! key in an HSM or KMS only ever sees one [`SignatureAlgorithm`] sign or one
//! [`KeyOp`].

use crate::error::{BoxError, BoxFuture, Error, Result};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{Id, PKey, Private};
use openssl::x509::X509;
use std::fmt;
use std::sync::Arc;
use zeroize::{Zeroize, Zeroizing};

// ── Certificate ─────────────────────────────────────────────────────────────

/// A parsed X.509 certificate. `Debug` prints subject, issuer, serial and
/// SHA-256 fingerprint. `Eq` and `Hash` compare the DER encoding.
#[derive(Clone)]
pub struct Certificate(Arc<CertInner>);

struct CertInner {
    der: Vec<u8>,
    x509: X509,
    fingerprint: crate::crypto::CertFingerprint,
}

/// The key family and size of a certificate's or key pair's public key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KeyKind {
    Rsa { bits: u32 },
    Ec { curve: Option<Nid> },
    Other,
}

impl KeyKind {
    pub(crate) fn of_public<T: openssl::pkey::HasPublic>(key: &openssl::pkey::PKeyRef<T>) -> Self {
        match key.id() {
            Id::RSA | Id::RSA_PSS => KeyKind::Rsa { bits: key.bits() },
            Id::EC => KeyKind::Ec {
                curve: key.ec_key().ok().and_then(|ec| ec.group().curve_name()),
            },
            _ => KeyKind::Other,
        }
    }

    pub(crate) fn describe(self) -> String {
        match self {
            KeyKind::Rsa { bits } => format!("RSA {bits}"),
            KeyKind::Ec { curve: Some(nid) } => {
                format!("EC {}", nid.short_name().unwrap_or("unknown curve"))
            }
            KeyKind::Ec { curve: None } => "EC (unnamed curve)".to_string(),
            KeyKind::Other => "an unsupported key type".to_string(),
        }
    }
}

impl Certificate {
    /// Exactly one PEM certificate; zero or several is an error (ambiguity is
    /// refused).
    pub fn from_pem(pem: &[u8]) -> Result<Certificate> {
        let certs = X509::stack_from_pem(pem)
            .map_err(|err| Error::config(format!("certificate PEM is not parseable: {err}")))?;
        match certs.len() {
            1 => Self::from_x509(certs.into_iter().next().expect("one certificate")),
            0 => Err(Error::config("certificate PEM contains no certificate")),
            n => Err(Error::config(format!(
                "certificate PEM contains {n} certificates; exactly one is required"
            ))),
        }
    }

    /// The DER encoding.
    pub fn der(&self) -> &[u8] {
        &self.0.der
    }

    pub(crate) fn from_x509(x509: X509) -> Result<Certificate> {
        let der = x509
            .to_der()
            .map_err(|err| Error::config(format!("certificate is not DER-encodable: {err}")))?;
        let fingerprint = crate::crypto::CertFingerprint::from_cert_der(&der);
        Ok(Certificate(Arc::new(CertInner {
            der,
            x509,
            fingerprint,
        })))
    }

    pub(crate) fn from_der(der: &[u8]) -> Result<Certificate> {
        let x509 = X509::from_der(der)
            .map_err(|err| Error::config(format!("certificate DER is not parseable: {err}")))?;
        Self::from_x509(x509)
    }

    pub(crate) fn x509(&self) -> &X509 {
        &self.0.x509
    }

    pub(crate) fn fingerprint(&self) -> &crate::crypto::CertFingerprint {
        &self.0.fingerprint
    }

    pub(crate) fn pem(&self) -> String {
        let pem = self.0.x509.to_pem().unwrap_or_default();
        String::from_utf8(pem).unwrap_or_default()
    }

    pub(crate) fn key_kind(&self) -> KeyKind {
        self.0
            .x509
            .public_key()
            .map(|key| KeyKind::of_public(&key))
            .unwrap_or(KeyKind::Other)
    }

    /// Every value of every subject attribute, in order.
    pub(crate) fn subject_values(&self) -> Vec<(Nid, String)> {
        self.0
            .x509
            .subject_name()
            .entries()
            .map(|entry| {
                let value = String::from_utf8_lossy(entry.data().as_slice()).into_owned();
                (entry.object().nid(), value)
            })
            .collect()
    }

    /// The subject common name, if there is exactly one.
    pub(crate) fn subject_cn(&self) -> Option<String> {
        let mut cns = self
            .subject_values()
            .into_iter()
            .filter(|(nid, _)| *nid == Nid::COMMONNAME);
        let first = cns.next()?;
        if cns.next().is_some() {
            return None;
        }
        Some(first.1)
    }

    /// Whether the keyUsage extension is present and asserts `cRLSign`.
    pub(crate) fn has_crl_sign(&self) -> bool {
        use x509_parser::prelude::FromDer;
        let Ok(der) = self.0.x509.to_der() else {
            return false;
        };
        x509_parser::certificate::X509Certificate::from_der(&der)
            .ok()
            .and_then(|(_, cert)| {
                cert.key_usage()
                    .ok()
                    .flatten()
                    .map(|ku| ku.value.crl_sign())
            })
            .unwrap_or(false)
    }

    pub(crate) fn is_valid_at(&self, now: std::time::SystemTime) -> bool {
        let Ok(now) = openssl::asn1::Asn1Time::from_unix(crate::time_utils::unix_secs(now)) else {
            return false;
        };
        let x509 = &self.0.x509;
        let started = x509
            .not_before()
            .compare(&now)
            .map(|o| o != std::cmp::Ordering::Greater)
            .unwrap_or(false);
        let not_expired = x509
            .not_after()
            .compare(&now)
            .map(|o| o != std::cmp::Ordering::Less)
            .unwrap_or(false);
        started && not_expired
    }

    /// The subject key identifiers this certificate answers to: the SKI
    /// extension, and the RFC 5280 §4.2.1.2 method (1) SHA-1 of the public key
    /// bits, which is what senders compute when the extension is absent.
    pub(crate) fn ski_candidates(&self) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        if let Some(ski) = self.0.x509.subject_key_id() {
            out.push(ski.as_slice().to_vec());
        }
        if let Some(bits) = public_key_bits(&self.0.x509)
            && let Ok(digest) = openssl::hash::hash(MessageDigest::sha1(), &bits)
        {
            let digest = digest.to_vec();
            if !out.contains(&digest) {
                out.push(digest);
            }
        }
        out
    }
}

/// The `subjectPublicKey` BIT STRING contents of `cert`.
fn public_key_bits(cert: &X509) -> Option<Vec<u8>> {
    let der = cert.to_der().ok()?;
    let (_, parsed) = x509_parser::parse_x509_certificate(&der).ok()?;
    Some(parsed.public_key().subject_public_key.data.to_vec())
}

impl PartialEq for Certificate {
    fn eq(&self, other: &Self) -> bool {
        self.0.der == other.0.der
    }
}

impl Eq for Certificate {}

impl std::hash::Hash for Certificate {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.der.hash(state);
    }
}

impl fmt::Debug for Certificate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = |n: &openssl::x509::X509NameRef| {
            n.entries()
                .map(|e| {
                    format!(
                        "{}={}",
                        e.object().nid().short_name().unwrap_or("?"),
                        String::from_utf8_lossy(e.data().as_slice())
                    )
                })
                .collect::<Vec<_>>()
                .join(", ")
        };
        let x509 = &self.0.x509;
        let serial = x509
            .serial_number()
            .to_bn()
            .ok()
            .and_then(|bn| bn.to_hex_str().ok().map(|s| s.to_string()))
            .unwrap_or_default();
        f.debug_struct("Certificate")
            .field("subject", &name(x509.subject_name()))
            .field("issuer", &name(x509.issuer_name()))
            .field("serial", &serial)
            .field("sha256", &self.0.fingerprint.as_str())
            .finish()
    }
}

// ── Signer / Decrypter ──────────────────────────────────────────────────────

/// A signing key, in memory or in an HSM/KMS. Object-safe.
pub trait Signer: Send + Sync + fmt::Debug + 'static {
    /// Leaf first. The chain is emitted where the profile requires it (BDEW
    /// `X509PKIPathv1`, BDEW AS4-Profil §2.2.6.2.1).
    fn certificate_chain(&self) -> &[Certificate];

    /// Sign `message` (unhashed) with `algorithm`. RSA: PKCS#1 v1.5 signature
    /// octets. ECDSA: ASN.1 DER `ECDSA-Sig-Value`; the library converts to
    /// XMLDSig `r‖s` where needed. An error fails the operation with
    /// [`ErrorKind::Backend`](crate::ErrorKind::Backend).
    fn sign<'a>(
        &'a self,
        algorithm: SignatureAlgorithm,
        message: &'a [u8],
    ) -> BoxFuture<'a, std::result::Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>>>;
}

/// A decryption key, in memory or in an HSM/KMS. Performs only the
/// private-key step; the library does KDF, key unwrap and content decryption.
/// Object-safe.
pub trait Decrypter: Send + Sync + fmt::Debug + 'static {
    /// Identifies the key for inbound key-reference matching (SKI, BST,
    /// issuer-serial).
    fn certificate(&self) -> &Certificate;

    /// Perform `operation` with the private key.
    fn decrypt<'a>(
        &'a self,
        operation: KeyOp<'a>,
    ) -> BoxFuture<'a, std::result::Result<Zeroizing<Vec<u8>>, BoxError>>;
}

/// A signature algorithm a profile selects (never negotiated from inbound
/// data).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SignatureAlgorithm {
    /// RSASSA-PKCS1-v1_5 with SHA-256 (`xmldsig-more#rsa-sha256`; CMS
    /// sha256WithRSAEncryption).
    RsaSha256,
    /// ECDSA with SHA-256 (`xmldsig-more#ecdsa-sha256`; CMS
    /// ecdsa-with-SHA256).
    EcdsaSha256,
}

impl SignatureAlgorithm {
    #[cfg_attr(not(feature = "as4"), allow(dead_code))]
    pub(crate) fn internal(self) -> crate::crypto::alg::SignatureAlgorithm {
        match self {
            Self::RsaSha256 => crate::crypto::alg::SignatureAlgorithm::RsaSha256,
            Self::EcdsaSha256 => crate::crypto::alg::SignatureAlgorithm::EcdsaSha256,
        }
    }
}

/// One private-key operation.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub enum KeyOp<'a> {
    /// RSA-OAEP, MGF1-SHA-256, SHA-256, empty label (eDelivery AS4 1.15
    /// §3.2.6). Returns the content-encryption key.
    RsaOaep(&'a [u8]),
    /// RSAES-PKCS1-v1_5 key transport (CMS `rsaEncryption`, AS2). Returns the
    /// CEK. Implementations should not distinguish padding failures; the
    /// library continues with a random CEK on failure.
    RsaPkcs1v15(&'a [u8]),
    /// ECDH with the originator's ephemeral public key (SubjectPublicKeyInfo
    /// DER). Returns the shared secret Z.
    Ecdh(&'a [u8]),
}

// ── KeyPair ─────────────────────────────────────────────────────────────────

/// An in-memory private key with its certificate chain. Implements [`Signer`]
/// and [`Decrypter`]. Zeroized on drop; `Debug` prints the certificate only.
#[derive(Clone)]
pub struct KeyPair(Arc<KeyPairInner>);

struct KeyPairInner {
    chain: Vec<Certificate>,
    secret: SecretKey,
}

/// The private key. `Debug` prints `[redacted]`; the PEM is zeroized on drop.
struct SecretKey {
    pkey: PKey<Private>,
    pem: Zeroizing<Vec<u8>>,
}

#[cfg(test)]
pub(crate) static SECRETS_ZEROIZED: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

impl Drop for SecretKey {
    fn drop(&mut self) {
        self.pem.zeroize();
        #[cfg(test)]
        SECRETS_ZEROIZED.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[redacted]")
    }
}

impl fmt::Debug for KeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyPair")
            .field("certificate", &self.0.chain.first())
            .field("key", &self.0.secret)
            .finish()
    }
}

impl KeyPair {
    /// `chain_pem`: leaf first, then intermediates. `key_pem`: PKCS#8 or
    /// SEC1/PKCS#1. The key must match the leaf.
    pub fn from_pem(chain_pem: &[u8], key_pem: &[u8]) -> Result<KeyPair> {
        let chain = X509::stack_from_pem(chain_pem)
            .map_err(|err| Error::config(format!("certificate chain PEM is not parseable: {err}")))?
            .into_iter()
            .map(Certificate::from_x509)
            .collect::<Result<Vec<_>>>()?;
        let Some(leaf) = chain.first() else {
            return Err(Error::config(
                "certificate chain PEM contains no certificate",
            ));
        };
        let pkey = PKey::private_key_from_pem(key_pem)
            .map_err(|_| Error::config("private key PEM is not parseable"))?;
        let leaf_key = leaf
            .x509()
            .public_key()
            .map_err(|_| Error::config("leaf certificate has no usable public key"))?;
        if !pkey.public_eq(&leaf_key) {
            return Err(Error::config(
                "private key does not match the leaf certificate's public key",
            ));
        }
        Ok(KeyPair(Arc::new(KeyPairInner {
            chain,
            secret: SecretKey {
                pkey,
                pem: Zeroizing::new(key_pem.to_vec()),
            },
        })))
    }

    pub(crate) fn leaf(&self) -> &Certificate {
        &self.0.chain[0]
    }

    pub(crate) fn key_kind(&self) -> KeyKind {
        KeyKind::of_public(&self.0.secret.pkey)
    }

    /// The private key as PEM, for the TLS identity of the built-in HTTP
    /// client only: AS2 and AS4 reach keys through [`Signer`] and
    /// [`Decrypter`]. Never logged.
    #[cfg_attr(not(feature = "http-client"), allow(dead_code))]
    pub(crate) fn key_pem(&self) -> &[u8] {
        &self.0.secret.pem
    }

    #[cfg_attr(not(feature = "http-client"), allow(dead_code))]
    pub(crate) fn chain_pem(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for cert in &self.0.chain {
            out.extend_from_slice(cert.pem().as_bytes());
        }
        out
    }

    fn sign_now(&self, algorithm: SignatureAlgorithm, message: &[u8]) -> Result<Vec<u8>> {
        let pkey = &self.0.secret.pkey;
        match (algorithm, self.key_kind()) {
            (SignatureAlgorithm::RsaSha256, KeyKind::Rsa { .. })
            | (SignatureAlgorithm::EcdsaSha256, KeyKind::Ec { .. }) => {}
            (alg, kind) => {
                return Err(Error::config(format!(
                    "a {} key cannot produce {alg:?} signatures",
                    kind.describe()
                )));
            }
        }
        let mut signer = openssl::sign::Signer::new(MessageDigest::sha256(), pkey)
            .map_err(|err| Error::config(format!("signing failed: {err}")))?;
        signer
            .sign_oneshot_to_vec(message)
            .map_err(|err| Error::config(format!("signing failed: {err}")))
    }

    pub(crate) fn decrypt_now(&self, operation: KeyOp<'_>) -> Result<Zeroizing<Vec<u8>>> {
        let pkey = &self.0.secret.pkey;
        let fail = || Error::new(crate::ErrorKind::Rejected, "decryption failed");
        match operation {
            KeyOp::RsaOaep(wrapped) => {
                let mut dec = openssl::encrypt::Decrypter::new(pkey).map_err(|_| fail())?;
                dec.set_rsa_padding(openssl::rsa::Padding::PKCS1_OAEP)
                    .and_then(|()| dec.set_rsa_oaep_md(MessageDigest::sha256()))
                    .and_then(|()| dec.set_rsa_mgf1_md(MessageDigest::sha256()))
                    .map_err(|_| fail())?;
                let mut out =
                    Zeroizing::new(vec![0u8; dec.decrypt_len(wrapped).map_err(|_| fail())?]);
                let len = dec.decrypt(wrapped, &mut out).map_err(|_| fail())?;
                out.truncate(len);
                Ok(out)
            }
            KeyOp::RsaPkcs1v15(wrapped) => {
                // Implicit rejection: a padding failure is never
                // reported; the caller continues with unpredictable octets and
                // fails only at content decryption, like any other cause.
                let attempt = || -> Option<Zeroizing<Vec<u8>>> {
                    let mut dec = openssl::encrypt::Decrypter::new(pkey).ok()?;
                    dec.set_rsa_padding(openssl::rsa::Padding::PKCS1).ok()?;
                    let mut out = Zeroizing::new(vec![0u8; dec.decrypt_len(wrapped).ok()?]);
                    let len = dec.decrypt(wrapped, &mut out).ok()?;
                    out.truncate(len);
                    Some(out)
                };
                Ok(attempt().unwrap_or_else(|| {
                    let mut random = Zeroizing::new(vec![0u8; 32]);
                    let _ = getrandom::fill(&mut random);
                    random
                }))
            }
            KeyOp::Ecdh(peer_spki) => {
                let peer = PKey::public_key_from_der(peer_spki).map_err(|_| fail())?;
                let (KeyKind::Ec { curve: ours }, KeyKind::Ec { curve: theirs }) =
                    (self.key_kind(), KeyKind::of_public(&peer))
                else {
                    return Err(fail());
                };
                if ours.is_none() || ours != theirs {
                    return Err(fail());
                }
                let mut deriver = openssl::derive::Deriver::new(pkey).map_err(|_| fail())?;
                deriver.set_peer(&peer).map_err(|_| fail())?;
                deriver
                    .derive_to_vec()
                    .map(Zeroizing::new)
                    .map_err(|_| fail())
            }
        }
    }
}

impl Signer for KeyPair {
    fn certificate_chain(&self) -> &[Certificate] {
        &self.0.chain
    }

    fn sign<'a>(
        &'a self,
        algorithm: SignatureAlgorithm,
        message: &'a [u8],
    ) -> BoxFuture<'a, std::result::Result<Vec<u8>, BoxError>> {
        let result = self.sign_now(algorithm, message).map_err(BoxError::from);
        Box::pin(std::future::ready(result))
    }
}

impl Decrypter for KeyPair {
    fn certificate(&self) -> &Certificate {
        self.leaf()
    }

    fn decrypt<'a>(
        &'a self,
        operation: KeyOp<'a>,
    ) -> BoxFuture<'a, std::result::Result<Zeroizing<Vec<u8>>, BoxError>> {
        let result = self.decrypt_now(operation).map_err(BoxError::from);
        Box::pin(std::future::ready(result))
    }
}

/// The value as a [`KeyPair`] when it is one: the in-memory key takes the
/// synchronous path, which saves a second verification pass on receive.
pub(crate) fn as_key_pair<T: 'static>(value: &T) -> Option<KeyPair> {
    (value as &dyn std::any::Any)
        .downcast_ref::<KeyPair>()
        .cloned()
}

/// The key seam's operation in the public form: OAEP parameters other
/// than SHA-256/MGF1-SHA-256 do not occur (the parser refuses them), and the
/// ECDH peer becomes its SubjectPublicKeyInfo.
#[cfg(feature = "as4")]
pub(crate) fn public_op(op: &crate::crypto::wssec::xmlenc::KeyOp<'_>) -> Option<OwnedKeyOp> {
    use crate::crypto::wssec::xmlenc::KeyOp as Internal;
    match op {
        Internal::RsaOaep { wrapped, params } => (params.digest
            == crate::crypto::wssec::WsSecDigestMethod::Sha256)
            .then(|| OwnedKeyOp::RsaOaep(wrapped.to_vec())),
        Internal::Ecdh { peer, group } => {
            let key = openssl::ec::EcKey::from_public_key(group, peer).ok()?;
            let spki = PKey::from_ec_key(key).ok()?.public_key_to_der().ok()?;
            Some(OwnedKeyOp::Ecdh(spki))
        }
    }
}

/// A [`KeyOp`] that owns its input.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(not(feature = "as4"), allow(dead_code))]
pub(crate) enum OwnedKeyOp {
    RsaOaep(Vec<u8>),
    Ecdh(Vec<u8>),
}

#[cfg_attr(not(feature = "as4"), allow(dead_code))]
impl OwnedKeyOp {
    pub(crate) fn as_public(&self) -> KeyOp<'_> {
        match self {
            OwnedKeyOp::RsaOaep(b) => KeyOp::RsaOaep(b),
            OwnedKeyOp::Ecdh(b) => KeyOp::Ecdh(b),
        }
    }
}

/// The in-memory key on the synchronous key seam: no second pass needed.
#[cfg(feature = "as4")]
impl crate::crypto::wssec::xmlenc::PrivateKeyStep for KeyPair {
    fn decrypt(
        &self,
        op: crate::crypto::wssec::xmlenc::KeyOp<'_>,
    ) -> crate::core::Result<Zeroizing<Vec<u8>>> {
        let fail = || {
            crate::core::AsxError::new(
                crate::core::ErrorCode::DecryptionFailed,
                "XML Encryption decryption failed",
                crate::core::ErrorContext::new("wssec_xmlenc"),
            )
        };
        let owned = public_op(&op).ok_or_else(fail)?;
        self.decrypt_now(owned.as_public()).map_err(|_| fail())
    }
}

/// The recipient-key description the parser needs for a certificate.
#[cfg(feature = "as4")]
pub(crate) fn recipient_key(
    cert: &Certificate,
) -> Option<crate::crypto::wssec::xmlenc::RecipientKey> {
    use crate::crypto::wssec::xmlenc::RecipientKey;
    let public = cert.x509().public_key().ok()?;
    match public.id() {
        Id::RSA | Id::RSA_PSS => Some(RecipientKey::Rsa),
        Id::EC => public
            .ec_key()
            .ok()
            .and_then(|k| crate::crypto::alg::NamedCurve::from_group(k.group()).ok())
            .map(RecipientKey::Ec),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl::ec::{EcGroup, EcKey};
    use openssl::rsa::Rsa;

    fn self_signed(key: &PKey<Private>, cn: &str) -> Vec<u8> {
        let mut name = openssl::x509::X509NameBuilder::new().unwrap();
        name.append_entry_by_nid(Nid::COMMONNAME, cn).unwrap();
        let name = name.build();
        let mut b = X509::builder().unwrap();
        b.set_version(2).unwrap();
        b.set_subject_name(&name).unwrap();
        b.set_issuer_name(&name).unwrap();
        b.set_pubkey(key).unwrap();
        b.set_not_before(&openssl::asn1::Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        b.set_not_after(&openssl::asn1::Asn1Time::days_from_now(30).unwrap())
            .unwrap();
        b.sign(key, MessageDigest::sha256()).unwrap();
        b.build().to_pem().unwrap()
    }

    fn rsa() -> (Vec<u8>, Vec<u8>) {
        let key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
        (
            self_signed(&key, "rsa"),
            key.private_key_to_pem_pkcs8().unwrap(),
        )
    }

    fn ec(nid: Nid) -> (Vec<u8>, Vec<u8>) {
        let group = EcGroup::from_curve_name(nid).unwrap();
        let key = PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap();
        (
            self_signed(&key, "ec"),
            key.private_key_to_pem_pkcs8().unwrap(),
        )
    }

    #[test]
    fn certificate_from_pem_requires_exactly_one() {
        let (a, _) = rsa();
        let (b, _) = rsa();
        assert!(Certificate::from_pem(&a).is_ok());
        assert!(Certificate::from_pem(b"").is_err());
        let both = [a, b].concat();
        let err = Certificate::from_pem(&both).unwrap_err();
        assert_eq!(err.kind(), crate::ErrorKind::Config);
    }

    #[test]
    fn mismatched_key_is_refused() {
        let (cert, _) = rsa();
        let (_, other_key) = rsa();
        let err = KeyPair::from_pem(&cert, &other_key).unwrap_err();
        assert_eq!(err.kind(), crate::ErrorKind::Config);
        assert!(err.to_string().contains("does not match"));
    }

    #[test]
    fn debug_prints_no_key_material() {
        let (cert, key) = rsa();
        let pair = KeyPair::from_pem(&cert, &key).unwrap();
        let debug = format!("{pair:?}");
        assert!(debug.contains("[redacted]"));
        let body: String = String::from_utf8(key.clone())
            .unwrap()
            .lines()
            .filter(|l| !l.starts_with("-----"))
            .collect();
        assert!(!debug.contains(&body[..40]));
        assert!(!debug.contains("PRIVATE KEY"));
    }

    #[test]
    fn secret_is_zeroized_on_drop() {
        let (cert, key) = rsa();
        let before = SECRETS_ZEROIZED.load(std::sync::atomic::Ordering::SeqCst);
        drop(KeyPair::from_pem(&cert, &key).unwrap());
        assert!(SECRETS_ZEROIZED.load(std::sync::atomic::Ordering::SeqCst) > before);
    }

    #[tokio::test]
    async fn rsa_and_ecdsa_signatures_verify_with_openssl() {
        for (cert, key, alg) in [
            {
                let (c, k) = rsa();
                (c, k, SignatureAlgorithm::RsaSha256)
            },
            {
                let (c, k) = ec(Nid::BRAINPOOL_P256R1);
                (c, k, SignatureAlgorithm::EcdsaSha256)
            },
        ] {
            let pair = KeyPair::from_pem(&cert, &key).unwrap();
            let sig = Signer::sign(&pair, alg, b"message").await.unwrap();
            let public = X509::from_pem(&cert).unwrap().public_key().unwrap();
            let mut verifier =
                openssl::sign::Verifier::new(MessageDigest::sha256(), &public).unwrap();
            assert!(
                verifier.verify_oneshot(&sig, b"message").unwrap(),
                "{alg:?}"
            );
            if alg == SignatureAlgorithm::EcdsaSha256 {
                // DER ECDSA-Sig-Value: a SEQUENCE.
                assert_eq!(sig[0], 0x30);
            }
        }
    }

    #[tokio::test]
    async fn wrong_algorithm_for_key_fails() {
        let (cert, key) = rsa();
        let pair = KeyPair::from_pem(&cert, &key).unwrap();
        assert!(
            Signer::sign(&pair, SignatureAlgorithm::EcdsaSha256, b"m")
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn oaep_round_trip() {
        let (cert, key) = rsa();
        let pair = KeyPair::from_pem(&cert, &key).unwrap();
        let public = X509::from_pem(&cert).unwrap().public_key().unwrap();
        let mut enc = openssl::encrypt::Encrypter::new(&public).unwrap();
        enc.set_rsa_padding(openssl::rsa::Padding::PKCS1_OAEP)
            .unwrap();
        enc.set_rsa_oaep_md(MessageDigest::sha256()).unwrap();
        enc.set_rsa_mgf1_md(MessageDigest::sha256()).unwrap();
        let mut wrapped = vec![0u8; enc.encrypt_len(b"0123456789abcdef").unwrap()];
        let n = enc.encrypt(b"0123456789abcdef", &mut wrapped).unwrap();
        wrapped.truncate(n);
        let cek = Decrypter::decrypt(&pair, KeyOp::RsaOaep(&wrapped))
            .await
            .unwrap();
        assert_eq!(&cek[..], b"0123456789abcdef");
    }

    #[tokio::test]
    async fn pkcs1v15_implicit_rejection_never_errors_and_varies() {
        let (cert, key) = rsa();
        let pair = KeyPair::from_pem(&cert, &key).unwrap();
        let a = Decrypter::decrypt(&pair, KeyOp::RsaPkcs1v15(&[1u8; 256]))
            .await
            .unwrap();
        let b = Decrypter::decrypt(&pair, KeyOp::RsaPkcs1v15(&[2u8; 256]))
            .await
            .unwrap();
        assert_ne!(&a[..], &b[..]);
        // A genuine wrap still opens.
        let public = X509::from_pem(&cert).unwrap().public_key().unwrap();
        let mut enc = openssl::encrypt::Encrypter::new(&public).unwrap();
        enc.set_rsa_padding(openssl::rsa::Padding::PKCS1).unwrap();
        let mut wrapped = vec![0u8; enc.encrypt_len(b"k").unwrap()];
        let n = enc.encrypt(b"k", &mut wrapped).unwrap();
        wrapped.truncate(n);
        let cek = Decrypter::decrypt(&pair, KeyOp::RsaPkcs1v15(&wrapped))
            .await
            .unwrap();
        assert_eq!(&cek[..], b"k");
    }

    #[tokio::test]
    async fn ecdh_checks_the_curve() {
        let (cert, key) = ec(Nid::BRAINPOOL_P256R1);
        let pair = KeyPair::from_pem(&cert, &key).unwrap();
        let same = PKey::from_ec_key(
            EcKey::generate(&EcGroup::from_curve_name(Nid::BRAINPOOL_P256R1).unwrap()).unwrap(),
        )
        .unwrap();
        let other = PKey::from_ec_key(
            EcKey::generate(&EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap()).unwrap(),
        )
        .unwrap();
        let z = Decrypter::decrypt(&pair, KeyOp::Ecdh(&same.public_key_to_der().unwrap()))
            .await
            .unwrap();
        assert_eq!(z.len(), 32);
        assert!(
            Decrypter::decrypt(&pair, KeyOp::Ecdh(&other.public_key_to_der().unwrap()))
                .await
                .is_err()
        );
    }
}
