#![cfg(feature = "as4")]
//! The header values each preset puts on the wire .

#[path = "common/peers.rs"]
mod peers;

use peers::{Preset, pair, soap_part};

async fn sent_wire(preset: Preset) -> (String, String) {
    let p = pair(preset);
    p.sender
        .send(preset.message(&p.to_b, b"payload"))
        .await
        .expect("delivered");
    let request = p.loopback.last_request().unwrap();
    let body = String::from_utf8_lossy(request.body()).into_owned();
    (soap_part(request.body()), body)
}

#[tokio::test]
async fn bdew_header_values() {
    let (soap, body) = sent_wire(Preset::Bdew).await;
    // B §2.3.1.2.1: the service.
    assert!(
        soap.contains(">https://www.bdew.de/as4/communication/services/MP</"),
        "{soap}"
    );
    // B §2.3.1.2.2: the fixed action.
    assert!(soap.contains(">http://docs.oasis-open.org/ebxml-msg/as4/200902/action</"));
    // B §2.3.1.2.3: roles.
    assert!(
        soap.contains(">http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/initiator</")
    );
    assert!(
        soap.contains(">http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/responder</")
    );
    // B §2.3.2: AgreementRef without pmode/type.
    assert!(
        soap.contains("AgreementRef>https://www.bdew.de/as4/communication/agreement</"),
        "{soap}"
    );
    assert!(!soap.contains("pmode="));
    // B §2.3.1.2.4: ConversationId always empty.
    assert!(
        soap.contains("ConversationId></") || soap.contains("ConversationId/>"),
        "{soap}"
    );
    // B §2.3.1.1: the party-id type.
    assert!(soap.contains("type=\"urn:oasis:names:tc:ebcore:partyid-type:unregistered:BDEW\""));
    // B §2.2.6.2.1: the signing token is a PKIPath.
    assert!(soap.contains("#X509PKIPathv1"), "{soap}");
    // B §2.2.3.3: gzip, always; B §2.2.3.2: octet-stream part type.
    assert!(soap.contains("application/gzip"));
    assert!(soap.contains(">application/octet-stream</"), "{soap}");
    // B §2.2.6.2.2: ECDH-ES key agreement, recipient by its Subject Key
    // Identifier (`wsse:KeyIdentifier #X509SubjectKeyIdentifier`).
    assert!(
        body.contains("ECDH-ES") || body.contains("ecdh-es"),
        "ECDH-ES expected"
    );
    assert!(body.contains("#X509SubjectKeyIdentifier"));
    // No four-corner properties under BDEW.
    assert!(!soap.contains("originalSender"));
}

#[tokio::test]
async fn peppol_no_filename() {
    let (soap, body) = sent_wire(Preset::Peppol).await;
    assert!(!body.contains("Content-Disposition"), "W4: P §4.10");
    assert!(soap.contains("AgreementRef>urn:fdc:peppol.eu:2017:agreements:tia:ap_provider</"));
    assert!(soap.contains("type=\"urn:fdc:peppol.eu:2017:identifiers:ap\""));
}

#[tokio::test]
async fn edelivery_and_entsog_use_x509v3_tokens() {
    for preset in [Preset::Edelivery, Preset::Entsog] {
        let (soap, body) = sent_wire(preset).await;
        assert!(soap.contains("#X509v3"), "{preset:?}");
        assert!(!soap.contains("#X509PKIPathv1"), "{preset:?}");
        assert!(
            body.contains("rsa-oaep"),
            "{preset:?}: RSA-OAEP key transport"
        );
        assert!(body.contains("filename=\"doc.bin\""), "{preset:?}");
    }
}
