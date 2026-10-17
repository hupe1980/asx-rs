//! Crate-private helpers for the in-crate unit tests (the test PKI and the
//! loopback partner are in `crate::testkit`).
//!
//! The internal policy views are built only by the profile: the
//! helpers in [`views`] resolve a profile and a partner exactly as `build()`
//! does, and tests adjust the returned view's fields when they need an odd
//! policy.

/// The internal policy views, resolved from a profile.
#[allow(dead_code)]
pub(crate) mod views {
    use crate::party::Partner;
    use crate::profile::{PartnerPolicy, Profile, resolve};

    fn policy(profile: Profile) -> PartnerPolicy {
        resolve(&profile, &Partner::new("partner"), &crate::clock::system())
    }

    /// The AS4 send view under eDelivery 1.15, with the given action/service.
    #[cfg(feature = "as4")]
    pub(crate) fn as4_send() -> crate::as4::As4SendPolicy {
        policy(Profile::edelivery_1_15()).send_view(&crate::profile::SendHeader {
            from_party: "sender".into(),
            from_type: None,
            to_party: "receiver".into(),
            to_type: None,
            service: "http://example.org/example".into(),
            service_type: "example".into(),
            action: "urn:example:action".into(),
            conversation_id: None,
        })
    }

    /// The AS4 inbound (push) view.
    #[cfg(feature = "as4")]
    pub(crate) fn as4_push() -> crate::as4::As4PushPolicy {
        crate::profile::receive_view(&Profile::edelivery_1_15())
    }

    /// The AS4 receipt-verification view.
    #[cfg(feature = "as4")]
    pub(crate) fn as4_receipt() -> crate::as4::As4ReceiptPolicy {
        policy(Profile::edelivery_1_15()).receipt_view()
    }

    /// The AS2 send view.
    #[cfg(feature = "as2")]
    pub(crate) fn as2_send() -> crate::as2::As2SendPolicy {
        crate::as2::send_view(&policy(Profile::as2()), "sender")
    }
}

/// A fresh self-signed RSA-2048 certificate and its PKCS#8 key, as PEM.
pub(crate) fn self_signed_rsa(subject_cn: &str) -> (Vec<u8>, Vec<u8>) {
    use openssl::asn1::Asn1Time;
    use openssl::bn::{BigNum, MsbOption};
    use openssl::hash::MessageDigest;
    use openssl::nid::Nid;
    use openssl::pkey::PKey;
    use openssl::rsa::Rsa;
    use openssl::x509::{X509, X509NameBuilder};

    let pkey = PKey::from_rsa(Rsa::generate(2048).expect("rsa")).expect("pkey");
    let mut name = X509NameBuilder::new().expect("name builder");
    name.append_entry_by_nid(Nid::COMMONNAME, subject_cn)
        .expect("cn");
    let name = name.build();
    let mut serial = BigNum::new().expect("serial");
    serial
        .rand(64, MsbOption::MAYBE_ZERO, false)
        .expect("serial rand");
    let mut builder = X509::builder().expect("x509 builder");
    builder.set_version(2).expect("version");
    builder
        .set_serial_number(&serial.to_asn1_integer().expect("serial asn1"))
        .expect("serial");
    builder.set_subject_name(&name).expect("subject");
    builder.set_issuer_name(&name).expect("issuer");
    builder.set_pubkey(&pkey).expect("pubkey");
    builder
        .set_not_before(&Asn1Time::days_from_now(0).expect("not_before"))
        .expect("nb");
    builder
        .set_not_after(&Asn1Time::days_from_now(365).expect("not_after"))
        .expect("na");
    builder.sign(&pkey, MessageDigest::sha256()).expect("sign");
    (
        builder.build().to_pem().expect("cert pem"),
        pkey.private_key_to_pem_pkcs8().expect("key pem"),
    )
}
