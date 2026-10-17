//! Who we are ([`LocalParty`]) and who they are ([`Partner`]).
//! Both are raw values: the profile validates them at `build()`.

use crate::keys::{Certificate, Decrypter, KeyPair, Signer};
use crate::profile::Quirk;
use std::sync::Arc;

/// Who we are.
#[derive(Debug, Clone)]
pub struct LocalParty {
    pub(crate) id: String,
    pub(crate) party_type: Option<String>,
    pub(crate) signers: Vec<LocalSigner>,
    pub(crate) decrypters: Vec<LocalDecrypter>,
    pub(crate) tls: Option<KeyPair>,
}

/// The signer: every signature goes through the asynchronous trait.
#[derive(Debug, Clone)]
pub(crate) struct LocalSigner {
    pub(crate) signer: Arc<dyn Signer>,
}

/// A decrypter, with its in-memory form when it is a [`KeyPair`].
#[derive(Debug, Clone)]
pub(crate) struct LocalDecrypter {
    pub(crate) decrypter: Arc<dyn Decrypter>,
    pub(crate) key_pair: Option<KeyPair>,
}

impl LocalParty {
    /// AS4 `PartyId` value / AS2 `AS2-From` identifier.
    pub fn new(id: impl Into<String>) -> LocalParty {
        LocalParty {
            id: id.into(),
            party_type: None,
            signers: Vec::new(),
            decrypters: Vec::new(),
            tls: None,
        }
    }

    /// AS4 `PartyId@type` (e.g.
    /// `urn:oasis:names:tc:ebcore:partyid-type:unregistered:BDEW`). Peppol
    /// fixes it.
    pub fn party_type(self, party_type: impl Into<String>) -> LocalParty {
        LocalParty {
            party_type: Some(party_type.into()),
            ..self
        }
    }

    /// The signing key. Exactly one (a second is refused at `build()`).
    pub fn signer(mut self, signer: impl Signer) -> LocalParty {
        self.signers.push(LocalSigner {
            signer: Arc::new(signer),
        });
        self
    }

    /// A decryption key. Repeat for key rollover; inbound selection is by key
    /// reference.
    pub fn decrypter(mut self, decrypter: impl Decrypter) -> LocalParty {
        let key_pair = crate::keys::as_key_pair(&decrypter);
        self.decrypters.push(LocalDecrypter {
            decrypter: Arc::new(decrypter),
            key_pair,
        });
        self
    }

    /// The TLS client certificate presented by the built-in HTTP client.
    /// Must differ from the signing and decryption keys under
    /// `Profile::bdew()` (BDEW AS4-Profil §2.3.4.4).
    pub fn tls_identity(self, key_pair: KeyPair) -> LocalParty {
        LocalParty {
            tls: Some(key_pair),
            ..self
        }
    }

    pub(crate) fn signer_ref(&self) -> &LocalSigner {
        &self.signers[0]
    }
}

/// A trading partner. Cheap to clone.
#[derive(Debug, Clone)]
pub struct Partner(Arc<PartnerInner>);

#[derive(Debug, Clone, Default)]
struct PartnerInner {
    id: String,
    party_type: Option<String>,
    endpoint: Option<String>,
    signing: Vec<Certificate>,
    encryption: Option<Certificate>,
    quirks: Vec<Quirk>,
}

impl Partner {
    /// The partner's AS4 `PartyId` / AS2 identifier.
    pub fn new(id: impl Into<String>) -> Partner {
        Partner(Arc::new(PartnerInner {
            id: id.into(),
            ..PartnerInner::default()
        }))
    }

    fn with(self, f: impl FnOnce(&mut PartnerInner)) -> Partner {
        let mut inner = Arc::try_unwrap(self.0).unwrap_or_else(|arc| (*arc).clone());
        f(&mut inner);
        Partner(Arc::new(inner))
    }

    /// The partner's `PartyId@type`.
    pub fn party_type(self, party_type: impl Into<String>) -> Partner {
        let party_type = party_type.into();
        self.with(|p| p.party_type = Some(party_type))
    }

    /// HTTPS only; validated at `build()` (or at `send` for an unregistered
    /// partner).
    pub fn endpoint(self, url: impl AsRef<str>) -> Partner {
        let url = url.as_ref().to_string();
        self.with(|p| p.endpoint = Some(url))
    }

    /// A certificate allowed to sign this partner's messages, receipts and
    /// MDNs (a pin). Repeat during a rollover.
    pub fn signing_cert(self, certificate: Certificate) -> Partner {
        self.with(|p| p.signing.push(certificate))
    }

    /// The certificate we encrypt to.
    pub fn encryption_cert(self, certificate: Certificate) -> Partner {
        self.with(|p| p.encryption = Some(certificate))
    }

    /// Tolerate one absent element from this partner.
    pub fn quirk(self, quirk: Quirk) -> Partner {
        self.with(|p| {
            if !p.quirks.contains(&quirk) {
                p.quirks.push(quirk);
            }
        })
    }

    // ── crate-private accessors ─────────────────────────────────────────────

    pub(crate) fn id(&self) -> &str {
        &self.0.id
    }

    pub(crate) fn type_ref(&self) -> Option<&str> {
        self.0.party_type.as_deref()
    }

    pub(crate) fn endpoint_url(&self) -> Option<&str> {
        self.0.endpoint.as_deref()
    }

    pub(crate) fn signing_certs(&self) -> &[Certificate] {
        &self.0.signing
    }

    pub(crate) fn encryption_certificate(&self) -> Option<&Certificate> {
        self.0.encryption.as_ref()
    }

    pub(crate) fn quirks(&self) -> &[Quirk] {
        &self.0.quirks
    }

    /// The (type, id) key partners are registered under.
    pub(crate) fn key(&self) -> (Option<String>, String) {
        (self.0.party_type.clone(), self.0.id.clone())
    }
}
