//! Golden path 3: send an AS2 message and keep the verified MDN.
//! (Formatted by hand: the README includes this file verbatim.)
#[rustfmt::skip]
use asx::{as2::{As2, Message}, Certificate, KeyPair, LocalParty, Partner, Payload, Profile};
use std::fs::read;

#[rustfmt::skip]
#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cert = Certificate::from_pem(&read("partner.crt")?)?;
    let partner = Partner::new("THEIRAS2ID").endpoint("https://partner.example/as2")
        .signing_cert(cert.clone()).encryption_cert(cert);
    let key = KeyPair::from_pem(&read("me.crt")?, &read("me.key")?)?;
    let as2 = As2::builder(Profile::as2())
        .local(LocalParty::new("OURAS2ID").signer(key.clone()).decrypter(key))
        .trust_anchor(Certificate::from_pem(&read("ca.crt")?)?)
        .partner(partner.clone()).build()?;
    let mdn = as2.send(Message::to(&partner, Payload::new(read("po.x12")?, "application/edi-x12"))).await?;
    std::fs::write("mdn.json", serde_json::to_vec(mdn.evidence())?)?; // signature, MIC and Original-Message-ID verified, or Err
    Ok(())
}
