//! Test key material: self-signed pairs, a throw-away CA, and the parties
//! (`TestParty`) the clients are built from; certificates, CRLs and OCSP
//! responses dated relative to now, so a test produces stale or
//! expired material on purpose instead of waiting for a fixture to age.

use asx::__fuzz::CertFingerprint;
use openssl::asn1::Asn1Time;
use openssl::bn::{BigNum, MsbOption};
use openssl::ec::{EcGroup, EcKey};
use openssl::hash::MessageDigest;
pub use openssl::nid::Nid;
use openssl::pkey::{PKey, Private};
use openssl::rsa::Rsa;
use openssl::x509::extension::{
    AuthorityKeyIdentifier, BasicConstraints, KeyUsage, SubjectKeyIdentifier,
};
use openssl::x509::{X509, X509Extension, X509Name, X509NameBuilder, X509Ref};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use super::der;

/// Validity window of an issued certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Validity {
    /// `notBefore`.
    pub not_before: SystemTime,
    /// `notAfter`.
    pub not_after: SystemTime,
}

impl Default for Validity {
    /// One hour back to thirty days ahead of now.
    fn default() -> Validity {
        let now = SystemTime::now();
        Validity {
            not_before: now - Duration::from_secs(3600),
            not_after: now + Duration::from_secs(30 * 86_400),
        }
    }
}

impl Validity {
    /// One hour back to ten years ahead: the window of [`TestCa::issue`] and
    /// [`KeyPair::self_signed`].
    fn ten_years() -> Validity {
        let now = SystemTime::now();
        Validity {
            not_before: now - Duration::from_secs(3600),
            not_after: now + Duration::from_secs(3650 * 86_400),
        }
    }
}

fn asn1_time(t: SystemTime) -> Asn1Time {
    let secs = match t.duration_since(UNIX_EPOCH) {
        Ok(d) => d.as_secs() as i64,
        Err(e) => -(e.duration().as_secs() as i64),
    };
    Asn1Time::from_unix(secs).expect("certificate time")
}

/// Key algorithm of a generated key pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyAlg {
    /// RSA 2048 (PEPPOL / eDelivery tests).
    Rsa2048,
    /// RSA 3072.
    Rsa3072,
    /// NIST P-256.
    EcP256,
    /// BSI brainpoolP256r1 (BDEW AS4-Profil).
    EcBrainpoolP256r1,
    /// NIST P-384.
    EcP384,
    /// NIST P-521 (curve order 66 octets: the widest XMLDSig ECDSA value).
    EcP521,
}

impl KeyAlg {
    fn generate(self) -> PKey<Private> {
        match self {
            Self::Rsa2048 => PKey::from_rsa(Rsa::generate(2048).expect("rsa 2048")).expect("pkey"),
            Self::Rsa3072 => PKey::from_rsa(Rsa::generate(3072).expect("rsa 3072")).expect("pkey"),
            Self::EcP256 => ec_key(Nid::X9_62_PRIME256V1),
            Self::EcBrainpoolP256r1 => ec_key(Nid::BRAINPOOL_P256R1),
            Self::EcP384 => ec_key(Nid::SECP384R1),
            Self::EcP521 => ec_key(Nid::SECP521R1),
        }
    }

    fn is_ec(self) -> bool {
        matches!(
            self,
            Self::EcP256 | Self::EcBrainpoolP256r1 | Self::EcP384 | Self::EcP521
        )
    }
}

fn ec_key(curve: Nid) -> PKey<Private> {
    let group = EcGroup::from_curve_name(curve).expect("ec group");
    PKey::from_ec_key(EcKey::generate(&group).expect("ec key")).expect("pkey")
}

/// A PEM certificate and its PKCS#8 private key.
///
/// `Debug` prints the certificate subject only: the key is a secret.
#[derive(Clone)]
pub struct KeyPair {
    /// PEM-encoded X.509 certificate.
    pub cert_pem: Vec<u8>,
    /// PEM-encoded PKCS#8 private key.
    pub key_pem: Vec<u8>,
}

impl std::fmt::Debug for KeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let subject = X509::from_pem(&self.cert_pem)
            .ok()
            .and_then(|cert| {
                cert.subject_name()
                    .entries_by_nid(Nid::COMMONNAME)
                    .next()
                    .map(|cn| String::from_utf8_lossy(cn.data().as_slice()).into_owned())
            })
            .unwrap_or_else(|| "<unparseable>".to_string());
        f.debug_struct("KeyPair")
            .field("subject_cn", &subject)
            .field("key_pem", &"<redacted>")
            .finish()
    }
}

impl KeyPair {
    /// A self-signed leaf: `digitalSignature` plus `keyEncipherment` (RSA) or
    /// `keyAgreement` (EC), valid from an hour ago for ten years.
    pub fn self_signed(subject_cn: &str, alg: KeyAlg) -> KeyPair {
        let key = alg.generate();
        let name = cn(subject_cn);
        let cert = build_cert(
            &name,
            &name,
            &key,
            &key,
            None,
            alg,
            Role::Leaf,
            Validity::ten_years(),
            &[],
        );
        KeyPair {
            cert_pem: cert.to_pem().expect("cert pem"),
            key_pem: key.private_key_to_pem_pkcs8().expect("key pem"),
        }
    }

    /// The pair as the library's in-memory key.
    pub fn key_pair(&self) -> asx::KeyPair {
        asx::KeyPair::from_pem(&self.cert_pem, &self.key_pem).expect("test key pair")
    }

    /// The certificate as the library parses it.
    pub fn certificate(&self) -> asx::Certificate {
        asx::Certificate::from_pem(&self.cert_pem).expect("test certificate")
    }

    /// The SHA-256 certificate fingerprint in the form sessions pin.
    pub fn fingerprint(&self) -> String {
        CertFingerprint::from_cert_pem(&self.cert_pem)
            .expect("fingerprint")
            .to_string()
    }
}

/// A throw-away certification authority.
///
/// Every CA publishes a CRL at its own CRL distribution point
/// ([`TestCa::crl_url`], `http://crl.testkit.example/<random>.crl`), and
/// every certificate it issues names that point (RFC 5280 §4.2.1.13), so a
/// client checking revocation finds a current CRL through
/// [`super::loopback::Loopback`] or [`super::revocation::RevocationHttp`]
/// without configuration. [`TestCa::revoke`] lists a certificate in it.
/// Clones share the CA.
#[derive(Clone)]
pub struct TestCa {
    inner: Arc<CaInner>,
}

pub(crate) struct CaInner {
    name: X509Name,
    key: PKey<Private>,
    cert: X509,
    cert_pem: Vec<u8>,
    /// The certificates above this CA, nearest first (empty for a root).
    chain: Vec<X509>,
    crl_url: String,
    /// Every revoked certificate.
    revoked: Mutex<Vec<Entry>>,
}

/// One CRL entry: the serial and, for an indirect CRL, the issuer name DER.
type Entry = (Vec<u8>, Option<Vec<u8>>);

/// The CRLs every [`TestCa`] publishes, by distribution point URL.
fn published() -> &'static Mutex<HashMap<String, Arc<CaInner>>> {
    static PUBLISHED: OnceLock<Mutex<HashMap<String, Arc<CaInner>>>> = OnceLock::new();
    PUBLISHED.get_or_init(Mutex::default)
}

/// A current CRL (`thisUpdate` an hour ago, `nextUpdate` in seven days) of
/// the CA publishing at `url`, listing what [`TestCa::revoke`] revoked; `None`
/// when no CA publishes there.
pub fn published_crl(url: &str) -> Option<Vec<u8>> {
    let inner = published().lock().expect("published").get(url).cloned()?;
    let now = SystemTime::now();
    let ca = TestCa { inner };
    let entries = ca.inner.revoked.lock().expect("revoked").clone();
    let mut builder = ca
        .crl_builder()
        .this_update(now - Duration::from_secs(3600))
        .next_update(Some(now + Duration::from_secs(7 * 86_400)));
    builder.entries = entries;
    Some(builder.build())
}

impl std::fmt::Debug for TestCa {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TestCa")
            .field("cert_pem", &String::from_utf8_lossy(&self.inner.cert_pem))
            .field("crl_url", &self.inner.crl_url)
            .finish_non_exhaustive()
    }
}

/// Where an issued certificate says its CRL is (RFC 5280 §4.2.1.13).
#[derive(Debug, Clone, Default)]
pub enum Cdp {
    /// The issuing CA's own distribution point ([`TestCa::crl_url`]).
    #[default]
    Issuer,
    /// No `cRLDistributionPoints` extension.
    None,
    /// One distribution point per entry, each with these URIs, in order.
    Points(Vec<Vec<String>>),
    /// An indirect CRL (RFC 5280 §5.3.3): the URIs and the `cRLIssuer`, the
    /// subject of a [`TestCa::crl_signer`].
    Indirect {
        /// Where the indirect CRL is published.
        uris: Vec<String>,
        /// The CRL signer named as `cRLIssuer`.
        crl_issuer: TestCa,
    },
}

/// How [`TestCa::issue_with_options`] issues a certificate.
#[derive(Debug, Clone, Default)]
pub struct IssueOptions {
    /// The validity window; ten years from an hour ago when `None`.
    pub validity: Option<Validity>,
    /// The CRL distribution point.
    pub cdp: Cdp,
    /// `id-ad-ocsp` URIs for the Authority Information Access extension.
    pub ocsp: Vec<String>,
    /// Subject attributes; the CN argument alone when empty.
    pub subject: Vec<(Nid, String)>,
}

impl TestCa {
    /// A self-signed CA (`CA:TRUE`, `keyCertSign`, `cRLSign`).
    pub fn new(subject_cn: &str, alg: KeyAlg) -> TestCa {
        let key = alg.generate();
        let name = cn(subject_cn);
        let now = SystemTime::now();
        // Valid well before anything it issues or signs.
        let validity = Validity {
            not_before: now - Duration::from_secs(400 * 86_400),
            not_after: now + Duration::from_secs(3650 * 86_400),
        };
        let cert = build_cert(&name, &name, &key, &key, None, alg, Role::Ca, validity, &[]);
        TestCa::publish(name, key, cert, Vec::new())
    }

    fn publish(name: X509Name, key: PKey<Private>, cert: X509, chain: Vec<X509>) -> TestCa {
        let mut id = [0u8; 8];
        openssl::rand::rand_bytes(&mut id).expect("random");
        let crl_url = format!(
            "http://crl.testkit.example/{}.crl",
            id.iter().map(|b| format!("{b:02x}")).collect::<String>()
        );
        let inner = Arc::new(CaInner {
            cert_pem: cert.to_pem().expect("ca pem"),
            name,
            key,
            cert,
            chain,
            crl_url: crl_url.clone(),
            revoked: Mutex::default(),
        });
        published()
            .lock()
            .expect("published")
            .insert(crl_url, inner.clone());
        TestCa { inner }
    }

    /// The CA certificate, PEM-encoded: the trust anchor for its leaves.
    pub fn cert_pem(&self) -> &[u8] {
        &self.inner.cert_pem
    }

    /// The CA certificate as a trust anchor.
    pub fn anchor(&self) -> asx::Certificate {
        asx::Certificate::from_pem(&self.inner.cert_pem).expect("CA certificate")
    }

    /// The CA certificate (for a sub-CA: an intermediate, not an anchor).
    pub fn certificate(&self) -> asx::Certificate {
        self.anchor()
    }

    /// The certificate as DER.
    pub fn cert_der(&self) -> Vec<u8> {
        self.inner.cert.to_der().expect("ca der")
    }

    /// The subject name as DER (what a `cRLIssuer` or `CertificateIssuer`
    /// names).
    pub fn name_der(&self) -> Vec<u8> {
        self.inner.name.to_der().expect("name der")
    }

    /// Where this CA publishes its CRL.
    pub fn crl_url(&self) -> &str {
        &self.inner.crl_url
    }

    /// List `pair` in this CA's published CRL.
    pub fn revoke(&self, pair: &KeyPair) {
        self.inner
            .revoked
            .lock()
            .expect("revoked")
            .push((serial_of(pair), None));
    }

    /// List the sub-CA `ca` (issued by this CA) in this CA's published CRL.
    pub fn revoke_ca(&self, ca: &TestCa) {
        self.inner
            .revoked
            .lock()
            .expect("revoked")
            .push((serial_of_x509(&ca.inner.cert), None));
    }

    /// A sub-CA issued by this CA, naming this CA's distribution point.
    pub fn sub_ca(&self, subject_cn: &str, alg: KeyAlg) -> TestCa {
        self.sub_ca_with_options(subject_cn, alg, IssueOptions::default())
    }

    /// A sub-CA issued by this CA with `options` (e.g. an indirect CDP).
    pub fn sub_ca_with_options(
        &self,
        subject_cn: &str,
        alg: KeyAlg,
        options: IssueOptions,
    ) -> TestCa {
        let key = alg.generate();
        let name = cn(subject_cn);
        let now = SystemTime::now();
        let validity = options.validity.unwrap_or(Validity {
            not_before: now - Duration::from_secs(200 * 86_400),
            not_after: now + Duration::from_secs(3000 * 86_400),
        });
        let extensions = self.locator_extensions(&options);
        let cert = build_cert(
            &name,
            &self.inner.name,
            &key,
            &self.inner.key,
            Some(&self.inner.cert),
            alg,
            Role::Ca,
            validity,
            &extensions,
        );
        let mut chain = vec![self.inner.cert.clone()];
        chain.extend(self.inner.chain.iter().cloned());
        TestCa::publish(name, key, cert, chain)
    }

    /// A CRL signer for indirect CRLs (RFC 5280 §5.3.3; the SM-PKI
    /// CCRL-S(Root), BSI TR-03109-4 §4.2.1): an end-entity certificate with
    /// `keyUsage cRLSign` only, issued by this CA. Sign with
    /// [`TestCa::crl_builder`] on the returned value.
    pub fn crl_signer(&self, subject_cn: &str, alg: KeyAlg) -> TestCa {
        let key = alg.generate();
        let name = cn(subject_cn);
        let now = SystemTime::now();
        let validity = Validity {
            not_before: now - Duration::from_secs(200 * 86_400),
            not_after: now + Duration::from_secs(3000 * 86_400),
        };
        let cert = build_cert(
            &name,
            &self.inner.name,
            &key,
            &self.inner.key,
            Some(&self.inner.cert),
            alg,
            Role::CrlSigner,
            validity,
            &[],
        );
        let mut chain = vec![self.inner.cert.clone()];
        chain.extend(self.inner.chain.iter().cloned());
        TestCa::publish(name, key, cert, chain)
    }

    /// `leaf` (issued by this CA) with the certificates above it, as the
    /// library's key: the signer then presents the whole path.
    pub fn chain_key_pair(&self, leaf: &KeyPair) -> asx::KeyPair {
        let mut pem = leaf.cert_pem.clone();
        if !self.inner.chain.is_empty() {
            pem.extend_from_slice(&self.inner.cert_pem);
            for cert in self.inner.chain.iter().take(self.inner.chain.len() - 1) {
                pem.extend(cert.to_pem().expect("pem"));
            }
        }
        asx::KeyPair::from_pem(&pem, &leaf.key_pem).expect("chain key pair")
    }

    /// An SM-PKI-like root (BrainpoolP256r1) for [`TestCa::bdew_party`].
    pub fn sm_pki() -> TestCa {
        TestCa::new("asx-testkit SM-PKI root", KeyAlg::EcBrainpoolP256r1)
    }

    /// A BDEW market participant (BDEW AS4-Profil 1.2 §2.3.4.4, RzÜ AS4 2.6
    /// §5.2): separate BrainpoolP256r1 key pairs for signing, encryption and
    /// TLS, each with the MP-ID as the subject's OU.
    pub fn bdew_party(&self, mp_id: &str) -> TestParty {
        let issue = |role: &str| {
            self.issue_named(
                &[
                    (Nid::COMMONNAME, &format!("Test MP {mp_id} {role}")),
                    (Nid::ORGANIZATIONALUNITNAME, mp_id),
                    (Nid::ORGANIZATIONNAME, "asx testkit"),
                ],
                KeyAlg::EcBrainpoolP256r1,
            )
        };
        TestParty {
            id: mp_id.to_string(),
            party_type: Some(BDEW_PARTY_TYPE.to_string()),
            signing: issue("sig"),
            encryption: issue("enc"),
            tls: issue("tls"),
            anchor_pem: self.root_pem(),
        }
    }

    /// A Peppol access point (Peppol AS4 2.0.3 §4.5, §4.7): one RSA AP
    /// certificate for signing and encryption, `cn` as the CN (the party id).
    pub fn peppol_party(&self, cn: &str) -> TestParty {
        let ap = self.issue(cn, KeyAlg::Rsa2048);
        TestParty {
            id: cn.to_string(),
            party_type: None,
            signing: ap.clone(),
            encryption: ap,
            tls: self.issue(&format!("{cn} tls"), KeyAlg::Rsa2048),
            anchor_pem: self.root_pem(),
        }
    }

    /// An RSA party (eDelivery 1.15, ENTSOG): separate RSA 2048 pairs.
    pub fn rsa_party(&self, name: &str) -> TestParty {
        TestParty {
            id: name.to_string(),
            party_type: Some(UNREGISTERED_PARTY_TYPE.to_string()),
            signing: self.issue(&format!("{name} sig"), KeyAlg::Rsa2048),
            encryption: self.issue(&format!("{name} enc"), KeyAlg::Rsa2048),
            tls: self.issue(&format!("{name} tls"), KeyAlg::Rsa2048),
            anchor_pem: self.root_pem(),
        }
    }

    /// An AS2 party: one RSA 2048 pair for signing and decryption.
    pub fn as2_party(&self, as2_id: &str) -> TestParty {
        let pair = self.issue(as2_id, KeyAlg::Rsa2048);
        TestParty {
            id: as2_id.to_string(),
            party_type: None,
            signing: pair.clone(),
            encryption: pair,
            tls: self.issue(&format!("{as2_id} tls"), KeyAlg::Rsa2048),
            anchor_pem: self.root_pem(),
        }
    }

    /// The root of this CA's path (itself for a root), PEM.
    fn root_pem(&self) -> Vec<u8> {
        match self.inner.chain.last() {
            Some(root) => root.to_pem().expect("root pem"),
            None => self.inner.cert_pem.clone(),
        }
    }

    /// Issue a leaf with the given subject attributes.
    pub fn issue_named(&self, subject: &[(Nid, &str)], alg: KeyAlg) -> KeyPair {
        let mut name = X509NameBuilder::new().expect("name builder");
        for (nid, value) in subject {
            name.append_entry_by_nid(*nid, value)
                .expect("subject entry");
        }
        self.issue_leaf(name.build(), alg, IssueOptions::default())
    }

    /// Issue a leaf certificate for `subject_cn` (key usages as for
    /// [`KeyPair::self_signed`]), valid from an hour ago for ten years.
    pub fn issue(&self, subject_cn: &str, alg: KeyAlg) -> KeyPair {
        self.issue_leaf(cn(subject_cn), alg, IssueOptions::default())
    }

    /// Issue a leaf certificate for `subject_cn` valid exactly for `validity`:
    /// expired, not yet valid or about to expire, on purpose.
    pub fn issue_with(&self, subject_cn: &str, alg: KeyAlg, validity: Validity) -> KeyPair {
        self.issue_leaf(
            cn(subject_cn),
            alg,
            IssueOptions {
                validity: Some(validity),
                ..IssueOptions::default()
            },
        )
    }

    /// Issue a leaf certificate for `subject_cn` with `options` (no CDP,
    /// other CDPs, an indirect CDP, AIA OCSP URIs).
    pub fn issue_with_options(
        &self,
        subject_cn: &str,
        alg: KeyAlg,
        options: IssueOptions,
    ) -> KeyPair {
        let subject = if options.subject.is_empty() {
            cn(subject_cn)
        } else {
            let mut name = X509NameBuilder::new().expect("name builder");
            for (nid, value) in &options.subject {
                name.append_entry_by_nid(*nid, value)
                    .expect("subject entry");
            }
            name.build()
        };
        self.issue_leaf(subject, alg, options)
    }

    fn issue_leaf(&self, subject: X509Name, alg: KeyAlg, options: IssueOptions) -> KeyPair {
        let key = alg.generate();
        let extensions = self.locator_extensions(&options);
        let cert = build_cert(
            &subject,
            &self.inner.name,
            &key,
            &self.inner.key,
            Some(&self.inner.cert),
            alg,
            Role::Leaf,
            options.validity.unwrap_or_else(Validity::ten_years),
            &extensions,
        );
        KeyPair {
            cert_pem: cert.to_pem().expect("leaf pem"),
            key_pem: key.private_key_to_pem_pkcs8().expect("leaf key pem"),
        }
    }

    /// The CDP and AIA extensions `options` asks for.
    fn locator_extensions(&self, options: &IssueOptions) -> Vec<X509Extension> {
        let mut out = Vec::new();
        let points = match &options.cdp {
            Cdp::Issuer => Some(vec![(vec![self.inner.crl_url.clone()], None)]),
            Cdp::None => None,
            Cdp::Points(points) => Some(points.iter().map(|uris| (uris.clone(), None)).collect()),
            Cdp::Indirect { uris, crl_issuer } => {
                Some(vec![(uris.clone(), Some(crl_issuer.name_der()))])
            }
        };
        if let Some(points) = points {
            out.push(raw_extension(
                "2.5.29.31",
                false,
                &der::crl_distribution_points(&points),
            ));
        }
        if !options.ocsp.is_empty() {
            out.push(raw_extension(
                "1.3.6.1.5.5.7.1.1",
                false,
                &der::authority_info_access(&options.ocsp),
            ));
        }
        out
    }

    /// A DER CRL (RFC 5280 §5, v2) signed by this CA with the given
    /// `thisUpdate`/`nextUpdate`, listing each of `revoked` with reason
    /// `keyCompromise` and revocation date `this_update`.
    pub fn crl(
        &self,
        revoked: &[&KeyPair],
        this_update: SystemTime,
        next_update: SystemTime,
    ) -> Vec<u8> {
        let mut builder = self
            .crl_builder()
            .this_update(this_update)
            .next_update(Some(next_update));
        for pair in revoked {
            builder = builder.revoke(pair);
        }
        builder.build()
    }

    /// A CRL signed by this CA, shaped by the builder's setters: entries of
    /// another issuer (indirect CRLs), an `IssuingDistributionPoint`, a
    /// missing `nextUpdate`, a delta indicator, an unknown critical
    /// extension.
    pub fn crl_builder(&self) -> CrlBuilder<'_> {
        let now = SystemTime::now();
        CrlBuilder {
            ca: self,
            entries: Vec::new(),
            this_update: now - Duration::from_secs(3600),
            next_update: Some(now + Duration::from_secs(7 * 86_400)),
            idp: None,
            delta: false,
            unknown_critical: false,
            unknown_critical_entry: false,
        }
    }

    /// A DER OCSP response (RFC 6960 §4.2) for `leaf`, signed by this CA
    /// (which also issued `leaf`): `good`, or `revoked` (reason
    /// `keyCompromise`, revoked at `this_update`), with the given
    /// `thisUpdate`/`nextUpdate` (`producedAt` = `this_update`).
    pub fn ocsp(
        &self,
        leaf: &KeyPair,
        revoked: bool,
        this_update: SystemTime,
        next_update: SystemTime,
    ) -> Vec<u8> {
        let sha1 = |data: &[u8]| {
            openssl::hash::hash(MessageDigest::sha1(), data)
                .expect("sha1")
                .to_vec()
        };
        let issuer_name = self.inner.name.to_der().expect("issuer name");
        let spki = self.inner.key.public_key_to_der().expect("issuer key");
        let cert_id = der::seq(&[
            &der::seq(&[&der::oid(der::SHA1), &der::NULL]),
            &der::octets(&sha1(&issuer_name)),
            &der::octets(&sha1(der::spki_key_bits(&spki))),
            &der::integer(&serial_of(leaf)),
        ]);
        let status = if revoked {
            // revoked [1] IMPLICIT RevokedInfo { revocationTime, revocationReason [0] }
            der::tlv(
                0xa1,
                &[
                    der::generalized_time(this_update),
                    der::explicit(0, &der::enumerated(1)),
                ]
                .concat(),
            )
        } else {
            // good [0] IMPLICIT NULL
            vec![0x80, 0x00]
        };
        let single = der::seq(&[
            &cert_id,
            &status,
            &der::generalized_time(this_update),
            &der::explicit(0, &der::generalized_time(next_update)),
        ]);
        let response_data = der::seq(&[
            // responderID byName [1] EXPLICIT Name
            &der::explicit(1, &issuer_name),
            &der::generalized_time(this_update),
            &der::seq(&[&single]),
        ]);
        let algorithm = self.signature_algorithm();
        let signature = self.sign(&response_data);
        let basic = der::seq(&[
            &response_data,
            &algorithm,
            &der::bits(&signature),
            &der::explicit(0, &der::seq(&[&self.inner.cert.to_der().expect("ca der")])),
        ]);
        let response_bytes = der::seq(&[&der::oid(der::OCSP_BASIC), &der::octets(&basic)]);
        der::seq(&[&der::enumerated(0), &der::explicit(0, &response_bytes)])
    }

    fn signature_algorithm(&self) -> Vec<u8> {
        if self.inner.key.ec_key().is_ok() {
            der::seq(&[&der::oid(der::ECDSA_WITH_SHA256)])
        } else {
            der::seq(&[&der::oid(der::SHA256_WITH_RSA), &der::NULL])
        }
    }

    /// SHA-256 with the CA key (PKCS#1 v1.5 or DER ECDSA), as X.509 signs.
    fn sign(&self, tbs: &[u8]) -> Vec<u8> {
        let mut signer =
            openssl::sign::Signer::new(MessageDigest::sha256(), &self.inner.key).expect("signer");
        signer.sign_oneshot_to_vec(tbs).expect("sign")
    }
}

/// The `IssuingDistributionPoint` of a [`CrlBuilder`] CRL (RFC 5280 §5.2.5).
#[derive(Debug, Clone, Default)]
pub struct Idp {
    /// `distributionPoint` `fullName` URIs (empty: absent).
    pub uris: Vec<String>,
    /// `onlyContainsUserCerts`.
    pub only_user_certs: bool,
    /// `onlyContainsCACerts`.
    pub only_ca_certs: bool,
    /// `onlySomeReasons` (`keyCompromise` only).
    pub only_some_reasons: bool,
    /// `indirectCRL`.
    pub indirect: bool,
}

/// Builds one CRL signed by a [`TestCa`]; see [`TestCa::crl_builder`].
#[derive(Debug)]
pub struct CrlBuilder<'a> {
    ca: &'a TestCa,
    entries: Vec<Entry>,
    this_update: SystemTime,
    next_update: Option<SystemTime>,
    idp: Option<Idp>,
    delta: bool,
    unknown_critical: bool,
    unknown_critical_entry: bool,
}

impl CrlBuilder<'_> {
    /// List `pair` (issued by the signing CA).
    pub fn revoke(mut self, pair: &KeyPair) -> Self {
        self.entries.push((serial_of(pair), None));
        self
    }

    /// List the CA certificate of `ca` (issued by the signing CA).
    pub fn revoke_ca(mut self, ca: &TestCa) -> Self {
        self.entries.push((serial_of_x509(&ca.inner.cert), None));
        self
    }

    /// List `pair`, issued by `issuer`, with a `CertificateIssuer` entry
    /// extension (an indirect CRL, RFC 5280 §5.3.3).
    pub fn revoke_issued_by(mut self, pair: &KeyPair, issuer: &TestCa) -> Self {
        self.entries
            .push((serial_of(pair), Some(issuer.name_der())));
        self
    }

    /// List the CA certificate of `ca`, issued by `issuer`, with a
    /// `CertificateIssuer` entry extension (the SM-PKI Root-CA CRL listing a
    /// Sub-CA, TR-03109-4 §4.2.1).
    pub fn revoke_ca_issued_by(mut self, ca: &TestCa, issuer: &TestCa) -> Self {
        self.entries
            .push((serial_of_x509(&ca.inner.cert), Some(issuer.name_der())));
        self
    }

    /// `thisUpdate`.
    pub fn this_update(mut self, at: SystemTime) -> Self {
        self.this_update = at;
        self
    }

    /// `nextUpdate`; `None` leaves it out.
    pub fn next_update(mut self, at: Option<SystemTime>) -> Self {
        self.next_update = at;
        self
    }

    /// Add an `IssuingDistributionPoint` (critical).
    pub fn idp(mut self, idp: Idp) -> Self {
        self.idp = Some(idp);
        self
    }

    /// Mark the CRL a delta CRL (`DeltaCRLIndicator`, critical).
    pub fn delta(mut self) -> Self {
        self.delta = true;
        self
    }

    /// Add a critical CRL extension no implementation knows.
    pub fn unknown_critical_extension(mut self) -> Self {
        self.unknown_critical = true;
        self
    }

    /// Add a critical entry extension no implementation knows (needs one
    /// entry).
    pub fn unknown_critical_entry_extension(mut self) -> Self {
        self.unknown_critical_entry = true;
        self
    }

    /// The DER CRL.
    pub fn build(self) -> Vec<u8> {
        let ca = self.ca;
        let issuer = ca.name_der();
        let indirect_entries = self.entries.iter().any(|(_, i)| i.is_some());
        let mut entries = Vec::new();
        for (index, (serial, entry_issuer)) in self.entries.iter().enumerate() {
            let reason = der::extension(der::CRL_REASON, false, &der::enumerated(1));
            let mut extensions = vec![reason];
            if indirect_entries {
                let name = entry_issuer.clone().unwrap_or_else(|| issuer.clone());
                extensions.push(der::extension(
                    der::CERTIFICATE_ISSUER,
                    true,
                    &der::directory_names(&name),
                ));
            }
            if self.unknown_critical_entry && index == 0 {
                extensions.push(der::extension(der::UNKNOWN_EXTENSION, true, &der::NULL));
            }
            entries.extend(der::seq(&[
                &der::integer(serial),
                &der::time(self.this_update),
                &der::tlv(0x30, &extensions.concat()),
            ]));
        }
        let mut extensions = vec![der::extension(der::CRL_NUMBER, false, &der::small_int(1))];
        if let Some(ski) = ca.inner.cert.subject_key_id() {
            // AuthorityKeyIdentifier { keyIdentifier [0] IMPLICIT }
            let aki = der::seq(&[&der::tlv(0x80, ski.as_slice())]);
            extensions.push(der::extension(der::AUTHORITY_KEY_ID, false, &aki));
        }
        if let Some(idp) = &self.idp {
            extensions.push(der::extension(
                der::ISSUING_DISTRIBUTION_POINT,
                true,
                &der::issuing_distribution_point(
                    &idp.uris,
                    idp.only_user_certs,
                    idp.only_ca_certs,
                    idp.only_some_reasons,
                    idp.indirect,
                ),
            ));
        }
        if self.delta {
            extensions.push(der::extension(
                der::DELTA_CRL_INDICATOR,
                true,
                &der::small_int(1),
            ));
        }
        if self.unknown_critical {
            extensions.push(der::extension(der::UNKNOWN_EXTENSION, true, &der::NULL));
        }
        let algorithm = ca.signature_algorithm();
        let mut tbs_parts: Vec<Vec<u8>> = vec![
            der::small_int(1),
            algorithm.clone(),
            issuer,
            der::time(self.this_update),
        ];
        if let Some(next) = self.next_update {
            tbs_parts.push(der::time(next));
        }
        if !self.entries.is_empty() {
            tbs_parts.push(der::tlv(0x30, &entries));
        }
        tbs_parts.push(der::explicit(0, &der::tlv(0x30, &extensions.concat())));
        let tbs = der::tlv(0x30, &tbs_parts.concat());
        let signature = ca.sign(&tbs);
        der::seq(&[&tbs, &algorithm, &der::bits(&signature)])
    }
}

fn raw_extension(oid: &str, critical: bool, value: &[u8]) -> X509Extension {
    X509Extension::new_from_der(
        &openssl::asn1::Asn1Object::from_str(oid).expect("extension oid"),
        critical,
        &openssl::asn1::Asn1OctetString::new_from_bytes(value).expect("extension value"),
    )
    .expect("extension")
}

fn serial_of_x509(cert: &X509Ref) -> Vec<u8> {
    cert.serial_number().to_bn().expect("serial").to_vec()
}

fn serial_of(pair: &KeyPair) -> Vec<u8> {
    serial_of_x509(&X509::from_pem(&pair.cert_pem).expect("certificate"))
}

/// `urn:oasis:names:tc:ebcore:partyid-type:unregistered:BDEW`.
pub const BDEW_PARTY_TYPE: &str = "urn:oasis:names:tc:ebcore:partyid-type:unregistered:BDEW";
/// `urn:oasis:names:tc:ebcore:partyid-type:unregistered`.
pub const UNREGISTERED_PARTY_TYPE: &str = "urn:oasis:names:tc:ebcore:partyid-type:unregistered";

/// One party's key material for a profile, issued by a [`TestCa`].
#[derive(Debug, Clone)]
pub struct TestParty {
    /// The party id (MP-ID, AP CN, AS2 id).
    pub id: String,
    /// The party-id type the profile expects, if the caller sets one.
    pub party_type: Option<String>,
    /// Signs messages, receipts and MDNs.
    pub signing: KeyPair,
    /// Decrypts inbound messages.
    pub encryption: KeyPair,
    /// The TLS client identity.
    pub tls: KeyPair,
    /// The issuing CA certificate (PEM).
    pub anchor_pem: Vec<u8>,
}

impl TestParty {
    /// The issuing CA as a trust anchor.
    pub fn anchor(&self) -> asx::Certificate {
        asx::Certificate::from_pem(&self.anchor_pem).expect("CA certificate")
    }

    /// This party as the local party of a client.
    pub fn local(&self) -> asx::LocalParty {
        let mut local = asx::LocalParty::new(&self.id)
            .signer(self.signing.key_pair())
            .decrypter(self.encryption.key_pair())
            .tls_identity(self.tls.key_pair());
        if let Some(t) = &self.party_type {
            local = local.party_type(t);
        }
        local
    }

    /// This party as a partner reachable at `endpoint`.
    pub fn partner(&self, endpoint: &str) -> asx::Partner {
        let mut partner = asx::Partner::new(&self.id)
            .endpoint(endpoint)
            .signing_cert(self.signing.certificate())
            .encryption_cert(self.encryption.certificate());
        if let Some(t) = &self.party_type {
            partner = partner.party_type(t);
        }
        partner
    }
}

fn cn(subject_cn: &str) -> X509Name {
    let mut name = X509NameBuilder::new().expect("name builder");
    name.append_entry_by_nid(Nid::COMMONNAME, subject_cn)
        .expect("cn");
    name.build()
}

/// What a built certificate is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Role {
    Ca,
    Leaf,
    CrlSigner,
}

#[allow(clippy::too_many_arguments)]
fn build_cert(
    subject: &X509Name,
    issuer: &X509Name,
    key: &PKey<Private>,
    issuer_key: &PKey<Private>,
    issuer_cert: Option<&X509Ref>,
    alg: KeyAlg,
    role: Role,
    validity: Validity,
    extra: &[X509Extension],
) -> X509 {
    let mut serial = BigNum::new().expect("serial");
    serial
        .rand(64, MsbOption::MAYBE_ZERO, false)
        .expect("serial rand");

    let mut builder = X509::builder().expect("x509 builder");
    builder.set_version(2).expect("version");
    builder
        .set_serial_number(&serial.to_asn1_integer().expect("serial asn1"))
        .expect("serial");
    builder.set_subject_name(subject).expect("subject");
    builder.set_issuer_name(issuer).expect("issuer");
    builder.set_pubkey(key).expect("pubkey");
    builder
        .set_not_before(&asn1_time(validity.not_before))
        .expect("not_before");
    builder
        .set_not_after(&asn1_time(validity.not_after))
        .expect("not_after");

    if role == Role::CrlSigner {
        builder
            .append_extension(BasicConstraints::new().critical().build().expect("bc"))
            .expect("bc");
        builder
            .append_extension(KeyUsage::new().critical().crl_sign().build().expect("ku"))
            .expect("ku");
    } else if role == Role::Ca {
        builder
            .append_extension(BasicConstraints::new().critical().ca().build().expect("bc"))
            .expect("bc");
        builder
            .append_extension(
                KeyUsage::new()
                    .critical()
                    .key_cert_sign()
                    .crl_sign()
                    .digital_signature()
                    .build()
                    .expect("ku"),
            )
            .expect("ku");
    } else {
        builder
            .append_extension(BasicConstraints::new().critical().build().expect("bc"))
            .expect("bc");
        let mut usage = KeyUsage::new();
        usage.critical().digital_signature();
        if alg.is_ec() {
            usage.key_agreement();
        } else {
            usage.key_encipherment();
        }
        builder
            .append_extension(usage.build().expect("ku"))
            .expect("ku");
    }

    let ski = SubjectKeyIdentifier::new()
        .build(&builder.x509v3_context(issuer_cert, None))
        .expect("ski");
    builder.append_extension(ski).expect("ski");
    if issuer_cert.is_some() {
        let aki = AuthorityKeyIdentifier::new()
            .keyid(true)
            .build(&builder.x509v3_context(issuer_cert, None))
            .expect("aki");
        builder.append_extension(aki).expect("aki");
    }

    for extension in extra {
        builder.append_extension2(extension).expect("extension");
    }

    builder
        .sign(issuer_key, MessageDigest::sha256())
        .expect("sign certificate");
    builder.build()
}
