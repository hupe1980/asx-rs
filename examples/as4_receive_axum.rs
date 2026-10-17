//! Golden path 2: receive BDEW AS4 messages in an axum router.
//! (Formatted by hand: the README includes this file verbatim.)
#[rustfmt::skip]
use asx::{as4::{As4, UserMessage}, Certificate, KeyPair, LocalParty, MemoryDedup, Partner, Profile, Reject, Verified};
use std::fs::read;

#[rustfmt::skip]
async fn deliver(msg: Verified<UserMessage>) -> Result<(), Reject> {
    for (i, p) in msg.payloads().iter().enumerate() { tokio::fs::write(format!("inbox/{}-{i}", msg.message_id()), p.bytes()).await?; }
    Ok(()) // -> signed receipt; Err -> EBMS:0202; duplicates are answered without calling this
}

#[rustfmt::skip]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let as4 = As4::builder(Profile::bdew())
        .local(LocalParty::new("9900000000001").party_type("urn:oasis:names:tc:ebcore:partyid-type:unregistered:BDEW")
            .signer(KeyPair::from_pem(&read("sig.crt")?, &read("sig.key")?)?)
            .decrypter(KeyPair::from_pem(&read("enc.crt")?, &read("enc.key")?)?))
        .trust_anchor(Certificate::from_pem(&read("sm-pki-root.crt")?)?)
        .partner(Partner::new("9900000000002").party_type("urn:oasis:names:tc:ebcore:partyid-type:unregistered:BDEW")
            .signing_cert(Certificate::from_pem(&read("partner-sig.crt")?)?)
            .encryption_cert(Certificate::from_pem(&read("partner-enc.crt")?)?))
        .build()?;
    let app = axum::Router::new().route_service("/as4", as4.inbound(MemoryDedup::default(), deliver));
    axum::serve(tokio::net::TcpListener::bind("0.0.0.0:8443").await?, app).await?; // terminate TLS in front
    Ok(())
}
