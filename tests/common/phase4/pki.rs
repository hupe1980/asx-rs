//! Per-run identities for both sides of a variant, issued by one test CA.
//!
//! BDEW (AS4-Profil 1.2 §2.3.4.4, RzÜ AS4 2.6 §5.2): separate
//! BrainpoolP256r1 pairs for signing, encryption and TLS; the MP-ID is the
//! subject's OU. phase4's BDEW validator additionally requires `EMT.MAK` in
//! the signing certificate's CN (`BDEWCompatibilityValidator
//! .validateInitiatorIdentity`), as SM-PKI market-communication certificates
//! carry it; both sides' certificates follow that form.

use asx::testkit::pki::{KeyAlg, TestCa};
use asx::{Certificate, KeyPair, LocalParty, Partner};
use openssl::nid::Nid;
use openssl::x509::X509;
use serde_json::{Value, json};

use super::sha256_hex;
use super::variant::ProfileVariant;

/// The partner endpoint the crate is configured with for phase4. HTTPS (the
/// presets refuse anything else); `PeerHttp` maps this host to the container.
pub const PHASE4_HOST: &str = "phase4.peer.test";

/// Key suite of a variant's leaves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeySuite {
    Rsa2048,
    BrainpoolP256r1,
}

impl KeySuite {
    fn alg(self) -> KeyAlg {
        match self {
            KeySuite::Rsa2048 => KeyAlg::Rsa2048,
            KeySuite::BrainpoolP256r1 => KeyAlg::EcBrainpoolP256r1,
        }
    }
}

/// A certificate and its PKCS#8 key, PEM. `Debug` prints the subject and the
/// SHA-256 fingerprint only.
#[derive(Clone)]
pub struct PemPair {
    pub cert_pem: Vec<u8>,
    pub key_pem: Vec<u8>,
}

impl std::fmt::Debug for PemPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let subject = X509::from_pem(&self.cert_pem)
            .ok()
            .map(|cert| {
                cert.subject_name()
                    .entries()
                    .map(|e| {
                        format!(
                            "{}={}",
                            e.object().nid().short_name().unwrap_or("?"),
                            String::from_utf8_lossy(e.data().as_slice())
                        )
                    })
                    .collect::<Vec<_>>()
                    .join(",")
            })
            .unwrap_or_else(|| "<unparseable>".into());
        f.debug_struct("PemPair")
            .field("subject", &subject)
            .field("sha256", &self.fingerprint())
            .finish_non_exhaustive()
    }
}

impl PemPair {
    fn from_testkit(pair: asx::testkit::pki::KeyPair) -> PemPair {
        PemPair {
            cert_pem: pair.cert_pem,
            key_pem: pair.key_pem,
        }
    }

    pub fn key_pair(&self) -> KeyPair {
        KeyPair::from_pem(&self.cert_pem, &self.key_pem).expect("harness key pair")
    }

    pub fn certificate(&self) -> Certificate {
        Certificate::from_pem(&self.cert_pem).expect("harness certificate")
    }

    /// SHA-256 over the certificate DER, lower-case hex.
    pub fn fingerprint(&self) -> String {
        X509::from_pem(&self.cert_pem)
            .and_then(|c| c.to_der())
            .map(|der| sha256_hex(&der))
            .unwrap_or_default()
    }
}

/// One side's identities.
#[derive(Debug, Clone)]
pub struct PeerIdentity {
    pub suite: KeySuite,
    pub sign: PemPair,
    pub enc: PemPair,
    pub tls: Option<PemPair>,
    pub party_id: String,
    pub party_type: String,
}

/// The run's PKI: one CA, the crate's and phase4's identities for a variant.
#[derive(Debug)]
pub struct RunPki {
    pub ca: TestCa,
    pub crate_side: PeerIdentity,
    pub phase4_side: PeerIdentity,
}

fn identity(ca: &TestCa, suite: KeySuite, party: &(String, String), label: &str) -> PeerIdentity {
    let (party_id, party_type) = party;
    let issue = |role: &str| {
        let cn = match suite {
            KeySuite::BrainpoolP256r1 => format!("{label} {role} {party_id}.EMT.MAK"),
            KeySuite::Rsa2048 => format!("{label} {role} {party_id}"),
        };
        PemPair::from_testkit(ca.issue_named(
            &[
                (Nid::COMMONNAME, cn.as_str()),
                (Nid::ORGANIZATIONALUNITNAME, party_id.as_str()),
                (Nid::ORGANIZATIONNAME, "asx phase4 interop"),
            ],
            suite.alg(),
        ))
    };
    PeerIdentity {
        suite,
        sign: issue("sig"),
        enc: issue("enc"),
        tls: Some(issue("tls")),
        party_id: party_id.clone(),
        party_type: party_type.clone(),
    }
}

impl RunPki {
    /// One CA per run, leaves per side for the variant's suite.
    pub fn generate(variant: &ProfileVariant) -> RunPki {
        let collab = variant.collaboration();
        let (ca, suite) = match variant {
            ProfileVariant::Bdew => (TestCa::sm_pki(), KeySuite::BrainpoolP256r1),
            ProfileVariant::Cef => (
                TestCa::new("asx phase4 interop CA", KeyAlg::Rsa2048),
                KeySuite::Rsa2048,
            ),
        };
        let crate_side = identity(&ca, suite, &collab.crate_party, "asx");
        let phase4_side = identity(&ca, suite, &collab.phase4_party, "phase4");
        RunPki {
            ca,
            crate_side,
            phase4_side,
        }
    }

    pub fn anchor(&self) -> Certificate {
        self.ca.anchor()
    }

    /// The crate's `LocalParty`: signer, decrypter and TLS identity.
    pub fn local_party(&self, _variant: &ProfileVariant) -> LocalParty {
        let side = &self.crate_side;
        let mut local = LocalParty::new(&side.party_id)
            .party_type(&side.party_type)
            .signer(side.sign.key_pair())
            .decrypter(side.enc.key_pair());
        if let Some(tls) = &side.tls {
            local = local.tls_identity(tls.key_pair());
        }
        local
    }

    /// phase4 as an `asx::Partner`: `https://phase4.peer.test/as4/<id>`, its
    /// signing certificate pinned, its encryption certificate.
    pub fn phase4_partner(&self, variant: &ProfileVariant) -> Partner {
        let side = &self.phase4_side;
        Partner::new(&side.party_id)
            .party_type(&side.party_type)
            .endpoint(format!("https://{PHASE4_HOST}{}", variant.path()))
            .signing_cert(side.sign.certificate())
            .encryption_cert(side.enc.certificate())
    }

    /// phase4's key material and trust (the CA and the crate's certificates:
    /// direct trust), as files for the container's `/config/keys/`, and the
    /// variant's `peer.json` entry naming them.
    ///
    /// The keys are PEM, not PKCS#12: the peer builds BouncyCastle in-memory
    /// key stores from them (the JDK's SunEC no longer implements
    /// brainpoolP256r1, and BC's PKCS#12 reader is not needed for PEM).
    pub fn phase4_config_files(&self, variant: &ProfileVariant) -> (Vec<(String, Vec<u8>)>, Value) {
        let id = variant.id();
        let dir = "/config/keys";
        let p4 = &self.phase4_side;
        let cr = &self.crate_side;
        let files = vec![
            (format!("{dir}/{id}-sign.crt"), p4.sign.cert_pem.clone()),
            (format!("{dir}/{id}-sign.key"), p4.sign.key_pem.clone()),
            (format!("{dir}/{id}-enc.crt"), p4.enc.cert_pem.clone()),
            (format!("{dir}/{id}-enc.key"), p4.enc.key_pem.clone()),
            (format!("{dir}/{id}-ca.crt"), self.ca.cert_pem().to_vec()),
            (format!("{dir}/{id}-asx-sign.crt"), cr.sign.cert_pem.clone()),
            (format!("{dir}/{id}-asx-enc.crt"), cr.enc.cert_pem.clone()),
        ];
        let entry = json!({
            "id": id,
            "profile": variant.phase4_profile_id(),
            "partyId": p4.party_id,
            "partyIdType": p4.party_type,
            "signCert": format!("{dir}/{id}-sign.crt"),
            "signKey": format!("{dir}/{id}-sign.key"),
            "encCert": format!("{dir}/{id}-enc.crt"),
            "encKey": format!("{dir}/{id}-enc.key"),
            "trust": [
                format!("{dir}/{id}-ca.crt"),
                format!("{dir}/{id}-asx-sign.crt"),
                format!("{dir}/{id}-asx-enc.crt"),
            ],
            "partner": {
                "partyId": cr.party_id,
                "partyIdType": cr.party_type,
                "signCert": format!("{dir}/{id}-asx-sign.crt"),
                "encCert": format!("{dir}/{id}-asx-enc.crt"),
            }
        });
        (files, entry)
    }
}
