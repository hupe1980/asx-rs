//! Golden path 1: send a BDEW AS4 message and keep the verified receipt.
//! (Formatted by hand: the README includes this file verbatim.)
#[rustfmt::skip]
use asx::{as4::{As4, Message}, Certificate, KeyPair, LocalParty, Partner, Payload, Profile};
use std::fs::read;

#[rustfmt::skip]
#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let partner = Partner::new("9900000000002").party_type("urn:oasis:names:tc:ebcore:partyid-type:unregistered:BDEW")
        .endpoint("https://as4.partner.example/msh")
        .signing_cert(Certificate::from_pem(&read("partner-sig.crt")?)?)
        .encryption_cert(Certificate::from_pem(&read("partner-enc.crt")?)?);
    let as4 = As4::builder(Profile::bdew())
        .local(LocalParty::new("9900000000001").party_type("urn:oasis:names:tc:ebcore:partyid-type:unregistered:BDEW")
            .signer(KeyPair::from_pem(&read("sig.crt")?, &read("sig.key")?)?)
            .decrypter(KeyPair::from_pem(&read("enc.crt")?, &read("enc.key")?)?))
        .trust_anchor(Certificate::from_pem(&read("sm-pki-root.crt")?)?)
        .partner(partner.clone())
        .build()?;
    let receipt = as4.send(Message::to(&partner).service("https://www.bdew.de/as4/communication/services/MP")
        .payload(Payload::new(read("UTILMD.edi")?, "application/octet-stream").named("UTILMD.txt"))).await?;
    std::fs::write("receipt.json", serde_json::to_vec(receipt.evidence())?)?; // the audit record as JSON
    Ok(())
}
