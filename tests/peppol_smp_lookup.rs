#![cfg(feature = "peppol")]
//! `peppol::Smp` returns a `Partner`, and the Peppol sender
//! rule (Peppol AS4 2.0.3 §4.5) authorizes unconfigured access points.

#[path = "common/peers.rs"]
mod peers;

use asx::as4::{As4, UserMessage};
use asx::peppol::Smp;
use asx::{Certificate, ErrorKind, MemoryDedup, Profile, Reject, Verified};
use peers::{B_URL, Preset, pair};
use std::sync::atomic::Ordering;

const METADATA: &[u8] =
    include_bytes!("fixtures/smp/peppol_production_signed_service_metadata.xml");
const ROOT_G3: &[u8] = include_bytes!("fixtures/smp/peppol_root_ca_g3.cert.pem");
const SMP_CA_G3: &[u8] = include_bytes!("fixtures/smp/peppol_smp_ca_g3.cert.pem");

/// An SMP answering every GET with the captured production document.
#[derive(Debug, Clone)]
struct CapturedSmp;

impl asx::HttpClient for CapturedSmp {
    fn send(
        &self,
        request: http::Request<bytes::Bytes>,
    ) -> asx::BoxFuture<
        '_,
        Result<http::Response<bytes::Bytes>, Box<dyn std::error::Error + Send + Sync>>,
    > {
        // The SMP answers its metadata; the SMP signer's CRL and OCSP URLs
        // are unreachable from here: 404, accepted with a WARN for the SMP
        // signer (soft-fail).
        let smp = request.uri().host() == Some("smp.example");
        if smp {
            assert_eq!(request.method(), http::Method::GET);
        }
        Box::pin(async move {
            Ok(http::Response::builder()
                .status(if smp { 200 } else { 404 })
                .body(if smp {
                    bytes::Bytes::from_static(METADATA)
                } else {
                    bytes::Bytes::new()
                })
                .unwrap())
        })
    }
}

const PARTICIPANT: &str = "iso6523-actorid-upis::0088:5790002590993";
const DOCUMENT: &str = "busdox-docid-qns::urn:oasis:names:specification:ubl:schema:xsd:Invoice-2::Invoice##urn:cen.eu:en16931:2017#compliant#urn:fdc:peppol.eu:2017:poacc:billing:3.0::2.1";
const PROCESS: &str = "cenbii-procid-ubl::urn:fdc:peppol.eu:2017:poacc:billing:01:1.0";

#[tokio::test(flavor = "multi_thread")]
async fn captured_smp_document_gives_a_partner() {
    let smp = Smp::production(CapturedSmp, Certificate::from_pem(ROOT_G3).unwrap())
        .__with_intermediate(Certificate::from_pem(SMP_CA_G3).unwrap())
        .__with_static_smp("https://smp.example");
    let partner = smp
        .lookup(PARTICIPANT, DOCUMENT, PROCESS)
        .await
        .expect("partner");
    let debug = format!("{partner:?}");
    assert!(debug.contains("https://"), "endpoint: {debug}");
    assert!(debug.contains("signing"), "{debug}");
}

#[tokio::test(flavor = "multi_thread")]
async fn smp_signature_not_chaining_to_the_anchor_is_rejected() {
    let foreign = asx::testkit::pki::TestCa::new("not peppol", asx::testkit::pki::KeyAlg::Rsa2048);
    let smp =
        Smp::production(CapturedSmp, foreign.anchor()).__with_static_smp("https://smp.example");
    let err = smp
        .lookup(PARTICIPANT, DOCUMENT, PROCESS)
        .await
        .expect_err("untrusted SMP");
    assert_eq!(err.kind(), ErrorKind::Rejected, "{err}");
}

fn stranger(p: &peers::Pair) -> asx::Inbound {
    // The receiver knows no partner: Peppol admits any AP whose CN is its
    // PartyId (P §4.5).
    let receiver = As4::builder(Profile::peppol())
        .local(p.b.local())
        .trust_anchor(p.ca.anchor())
        .http_client(p.loopback.clone())
        .build()
        .unwrap();
    let calls = p.calls.clone();
    receiver.inbound(MemoryDedup::default(), move |_m: Verified<UserMessage>| {
        let calls = calls.clone();
        async move {
            calls.fetch_add(1, Ordering::SeqCst);
            Ok::<(), Reject>(())
        }
    })
}

#[tokio::test]
async fn unconfigured_access_point_with_matching_cn_is_accepted() {
    let p = pair(Preset::Peppol);
    p.loopback.mount(B_URL, stranger(&p));
    p.sender
        .send(Preset::Peppol.message(&p.to_b, b"<Invoice/>"))
        .await
        .expect("accepted");
    assert_eq!(p.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn access_point_whose_cn_is_not_its_party_id_is_refused() {
    let p = pair(Preset::Peppol);
    p.loopback.mount(B_URL, stranger(&p));
    // The sender claims POP000009 but signs with the POP000001 certificate.
    let liar = asx::testkit::pki::TestParty {
        id: "POP000009".into(),
        ..p.a.clone()
    };
    let sender = As4::builder(Profile::peppol())
        .local(liar.local())
        .trust_anchor(p.ca.anchor())
        .partner(p.to_b.clone())
        .http_client(p.loopback.clone())
        .build()
        .unwrap();
    let err = sender
        .send(Preset::Peppol.message(&p.to_b, b"<Invoice/>"))
        .await
        .expect_err("CN mismatch");
    assert_eq!(err.ebms_code(), Some("EBMS:0101"), "{err}");
    assert_eq!(p.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn not_serviced_is_ebms_0004_with_peppol_detail() {
    let p = pair(Preset::Peppol);
    let receiver = As4::builder(Profile::peppol())
        .local(p.b.local())
        .trust_anchor(p.ca.anchor())
        .http_client(p.loopback.clone())
        .build()
        .unwrap();
    p.loopback.mount(
        B_URL,
        receiver.inbound(MemoryDedup::default(), |_m: Verified<UserMessage>| async {
            Err::<(), Reject>(asx::peppol::not_serviced())
        }),
    );
    let captured = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
    {
        let captured = captured.clone();
        p.loopback.intercept(move |r| {
            *captured.lock().unwrap() = String::from_utf8_lossy(r.body()).into_owned()
        });
    }
    let err = p
        .sender
        .send(Preset::Peppol.message(&p.to_b, b"<Invoice/>"))
        .await
        .expect_err("not serviced");
    assert_eq!(err.ebms_code(), Some("EBMS:0004"));
    assert!(captured.lock().unwrap().contains("PEPPOL:NOT_SERVICED"));
}
