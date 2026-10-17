//! Clients wired for the revocation suites: parties issued by
//! test CAs that publish CRLs, `RevocationHttp` in front of a `Loopback`.
#![allow(dead_code, unreachable_pub)]

#[path = "peers.rs"]
pub mod peers;

use asx::as2::{self, As2, Received};
use asx::as4::{As4, UserMessage};
use asx::{Certificate, ErrorKind, LocalParty, MemoryDedup, Partner, Payload, Profile, Verified};
use asx_testkit::loopback::Loopback;
use asx_testkit::pki::{Cdp, IssueOptions, KeyAlg, KeyPair, Nid, TestCa};
use asx_testkit::revocation::RevocationHttp;
use peers::{A_URL, B_URL, Preset};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

pub const A: &str = "9900000000001";
pub const B: &str = "9900000000002";
pub const BDEW_TYPE: &str = asx_testkit::pki::BDEW_PARTY_TYPE;
pub const HOUR: Duration = Duration::from_secs(3600);

/// One party's key material, issued by `ca`, whose local signer presents
/// the whole path.
pub struct Party {
    pub id: String,
    pub party_type: Option<String>,
    pub ca: TestCa,
    pub signing: KeyPair,
    pub encryption: KeyPair,
}

impl Party {
    pub fn local(&self) -> LocalParty {
        let mut local = LocalParty::new(&self.id)
            .signer(self.ca.chain_key_pair(&self.signing))
            .decrypter(self.encryption.key_pair());
        if let Some(t) = &self.party_type {
            local = local.party_type(t);
        }
        local
    }

    pub fn partner(&self, url: &str) -> Partner {
        let mut partner = Partner::new(&self.id)
            .endpoint(url)
            .signing_cert(self.signing.certificate())
            .encryption_cert(self.encryption.certificate());
        if let Some(t) = &self.party_type {
            partner = partner.party_type(t);
        }
        partner
    }
}

/// A BDEW party (MP-ID in the OU) issued by `ca` with `cdp` on its signing
/// certificate; `ou` overrides the MP-ID in the subject.
pub fn bdew(ca: &TestCa, mp_id: &str, ou: &str, cdp: Cdp) -> Party {
    let issue = |role: &str, cdp: Cdp| {
        ca.issue_with_options(
            "",
            KeyAlg::EcBrainpoolP256r1,
            IssueOptions {
                cdp,
                subject: vec![
                    (Nid::COMMONNAME, format!("Test MP {mp_id} {role}")),
                    (Nid::ORGANIZATIONALUNITNAME, ou.to_string()),
                ],
                ..IssueOptions::default()
            },
        )
    };
    Party {
        id: mp_id.to_string(),
        party_type: Some(BDEW_TYPE.to_string()),
        ca: ca.clone(),
        signing: issue("sig", cdp),
        encryption: issue("enc", Cdp::Issuer),
    }
}

/// An RSA party (Peppol: `id` is the CN; eDelivery: any id) whose signing
/// certificate carries `options`.
pub fn rsa(ca: &TestCa, id: &str, preset: Preset, options: IssueOptions) -> Party {
    let signing = ca.issue_with_options(id, KeyAlg::Rsa2048, options);
    Party {
        id: id.to_string(),
        party_type: match preset {
            Preset::Peppol => None,
            _ => Some(asx_testkit::pki::UNREGISTERED_PARTY_TYPE.to_string()),
        },
        ca: ca.clone(),
        encryption: if preset == Preset::Peppol {
            signing.clone()
        } else {
            ca.issue(&format!("{id} enc"), KeyAlg::Rsa2048)
        },
        signing,
    }
}

pub struct As4Net {
    pub sender: As4,
    pub to_b: Partner,
    /// The receiver's revocation fetches.
    pub b_http: RevocationHttp,
    /// The sender's revocation fetches (the receipt signer).
    pub a_http: RevocationHttp,
    pub calls: Arc<AtomicUsize>,
    pub inbound: asx::Inbound,
}

/// `a` sends to `b` under `preset`; `anchors` and `crl_signers` are
/// configured on both.
pub fn as4_net(
    preset: Preset,
    a: &Party,
    b: &Party,
    anchors: &[Certificate],
    crl_signers: &[Certificate],
) -> As4Net {
    let loopback = Loopback::new();
    let a_http = RevocationHttp::new().with_fallback(loopback.clone());
    let b_http = RevocationHttp::new().with_fallback(loopback.clone());
    let to_b = b.partner(B_URL);
    let mut sender = As4::builder(preset.profile())
        .local(a.local())
        .partner(to_b.clone())
        .http_client(a_http.clone());
    let mut receiver = As4::builder(preset.profile())
        .local(b.local())
        .partner(a.partner(A_URL))
        .http_client(b_http.clone());
    for anchor in anchors {
        sender = sender.trust_anchor(anchor.clone());
        receiver = receiver.trust_anchor(anchor.clone());
    }
    for signer in crl_signers {
        sender = sender.crl_signer(signer.clone());
        receiver = receiver.crl_signer(signer.clone());
    }
    let sender = sender.build().expect("sender builds");
    let receiver = receiver.build().expect("receiver builds");
    let calls = Arc::new(AtomicUsize::new(0));
    let counted = calls.clone();
    let inbound = receiver.inbound(MemoryDedup::default(), move |_m: Verified<UserMessage>| {
        let counted = counted.clone();
        async move {
            counted.fetch_add(1, Ordering::SeqCst);
            Ok::<(), asx::Reject>(())
        }
    });
    loopback.mount(B_URL, inbound.clone());
    As4Net {
        sender,
        to_b,
        b_http,
        a_http,
        calls,
        inbound,
    }
}

impl As4Net {
    pub async fn send(&self, preset: Preset) -> asx::Result<Verified<asx::Receipt>> {
        self.sender
            .send(preset.message(&self.to_b, b"revocation test payload"))
            .await
    }
}

pub fn assert_refused_0101(result: asx::Result<Verified<asx::Receipt>>) {
    let err = result.expect_err("refused");
    assert_eq!(err.kind(), ErrorKind::PartnerError, "{err}");
    assert_eq!(err.ebms_code(), Some("EBMS:0101"), "{err}");
}

pub struct As2Net {
    pub sender: As2,
    pub to_b: Partner,
    pub b_http: RevocationHttp,
    pub calls: Arc<AtomicUsize>,
}

pub fn as2_party(ca: &TestCa, id: &str) -> Party {
    let pair = ca.issue(id, KeyAlg::Rsa2048);
    Party {
        id: id.to_string(),
        party_type: None,
        ca: ca.clone(),
        signing: pair.clone(),
        encryption: pair,
    }
}

pub fn as2_net(a: &Party, b: &Party, anchors: &[Certificate]) -> As2Net {
    let loopback = Loopback::new();
    let a_http = RevocationHttp::new().with_fallback(loopback.clone());
    let b_http = RevocationHttp::new().with_fallback(loopback.clone());
    let to_b = b.partner("https://b.example/as2");
    let mut sender = As2::builder(Profile::as2())
        .local(a.local())
        .partner(to_b.clone())
        .http_client(a_http);
    let mut receiver = As2::builder(Profile::as2())
        .local(b.local())
        .partner(a.partner("https://a.example/as2"))
        .http_client(b_http.clone());
    for anchor in anchors {
        sender = sender.trust_anchor(anchor.clone());
        receiver = receiver.trust_anchor(anchor.clone());
    }
    let (sender, receiver) = (sender.build().unwrap(), receiver.build().unwrap());
    let calls = Arc::new(AtomicUsize::new(0));
    let counted = calls.clone();
    loopback.mount(
        "https://b.example/as2",
        receiver.inbound(MemoryDedup::default(), move |_m: Verified<Received>| {
            let counted = counted.clone();
            async move {
                counted.fetch_add(1, Ordering::SeqCst);
                Ok::<(), asx::Reject>(())
            }
        }),
    );
    As2Net {
        sender,
        to_b,
        b_http,
        calls,
    }
}

impl As2Net {
    pub async fn send(&self) -> asx::Result<Verified<asx::Receipt>> {
        self.sender
            .send(as2::Message::to(
                &self.to_b,
                Payload::new(b"ISA*00*revocation~".to_vec(), "application/edi-x12"),
            ))
            .await
    }
}
