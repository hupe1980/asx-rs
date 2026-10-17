#![cfg(feature = "as4")]
//! `Builder::build()` validation.
//!
//! Each test starts from a valid configuration, breaks exactly the one thing
//! its row describes, and asserts that `build()` refuses it with
//! `ErrorKind::Config`, naming the setting and, where the row cites one, the
//! profile section.

use asx::as4::As4;
use asx::{
    Certificate, ErrorKind, LocalParty, Partner, Profile, Quirk, SignatureAlgorithm, Signer,
};
use asx_testkit::loopback::Loopback;
use asx_testkit::pki::{BDEW_PARTY_TYPE, KeyAlg, Nid, TestCa, TestParty};

const A: &str = "9900000000001";
const B: &str = "9900000000002";
const B_URL: &str = "https://b.example/as4";
const BDEW: &str = "BDEW AS4-Profil 1.2";
const PEPPOL: &str = "Peppol AS4 Profile 2.0.3";

// ── helpers ─────────────────────────────────────────────────────────────────

/// Assert a `Config` refusal whose message contains every needle.
#[track_caller]
fn assert_refused<T: std::fmt::Debug>(result: Result<T, asx::Error>, needles: &[&str]) {
    let err = result.expect_err("build() must refuse this configuration");
    assert_eq!(err.kind(), ErrorKind::Config, "{err}");
    let text = err.to_string();
    for needle in needles {
        assert!(text.contains(needle), "{text:?} does not name {needle:?}");
    }
}

struct Bdew {
    ca: TestCa,
    a: TestParty,
    b: TestParty,
}

fn bdew() -> Bdew {
    let ca = TestCa::sm_pki();
    let a = ca.bdew_party(A);
    let b = ca.bdew_party(B);
    Bdew { ca, a, b }
}

impl Bdew {
    /// A valid BDEW builder without the local party.
    fn without_local(&self) -> asx::Builder<As4> {
        As4::builder(Profile::bdew())
            .trust_anchor(self.ca.anchor())
            .partner(self.b.partner(B_URL))
            .http_client(Loopback::new())
    }

    /// A valid BDEW builder without partners.
    fn without_partner(&self) -> asx::Builder<As4> {
        As4::builder(Profile::bdew())
            .local(self.a.local())
            .trust_anchor(self.ca.anchor())
            .http_client(Loopback::new())
    }

    fn valid(&self) -> asx::Builder<As4> {
        self.without_local().local(self.a.local())
    }

    /// `B` as a partner, built field by field.
    fn partner_b(&self) -> Partner {
        Partner::new(B).party_type(BDEW_PARTY_TYPE).endpoint(B_URL)
    }
}

/// An RSA party (eDelivery 1.15 / ENTSOG) builder with partner `b`.
fn rsa_builder(profile: Profile, ca: &TestCa, a: &TestParty) -> asx::Builder<As4> {
    As4::builder(profile)
        .local(a.local())
        .trust_anchor(ca.anchor())
        .http_client(Loopback::new())
}

fn rsa_ca() -> TestCa {
    TestCa::new("build-rejections RSA root", KeyAlg::Rsa2048)
}

/// A self-signed RSA 2048 certificate valid 2020-01-01 to 2021-01-01.
fn expired_certificate(cn: &str) -> Certificate {
    use openssl::asn1::Asn1Time;
    use openssl::hash::MessageDigest;
    use openssl::pkey::PKey;
    use openssl::rsa::Rsa;
    use openssl::x509::{X509, X509NameBuilder};

    let key = PKey::from_rsa(Rsa::generate(2048).expect("rsa")).expect("pkey");
    let mut name = X509NameBuilder::new().expect("name");
    name.append_entry_by_nid(Nid::COMMONNAME, cn).expect("cn");
    let name = name.build();
    let mut builder = X509::builder().expect("builder");
    builder.set_version(2).expect("version");
    builder.set_subject_name(&name).expect("subject");
    builder.set_issuer_name(&name).expect("issuer");
    builder.set_pubkey(&key).expect("pubkey");
    builder
        .set_not_before(&Asn1Time::from_str("20200101000000Z").expect("nb"))
        .expect("not_before");
    builder
        .set_not_after(&Asn1Time::from_str("20210101000000Z").expect("na"))
        .expect("not_after");
    builder.sign(&key, MessageDigest::sha256()).expect("sign");
    let pem = builder.build().to_pem().expect("pem");
    Certificate::from_pem(&pem).expect("expired certificate parses")
}

/// A signer with a fixed certificate chain that never signs.
#[derive(Debug)]
struct ChainSigner(Vec<Certificate>);

impl Signer for ChainSigner {
    fn certificate_chain(&self) -> &[Certificate] {
        &self.0
    }

    fn sign<'a>(
        &'a self,
        _algorithm: SignatureAlgorithm,
        _message: &'a [u8],
    ) -> asx::BoxFuture<'a, Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>>> {
        Box::pin(async { Err("not a signing key".into()) })
    }
}

// ── positive: every preset builds ───────────────────────────────────────────

#[test]
fn bdew_valid_configuration_builds() {
    bdew().valid().build().expect("valid bdew configuration");
}

#[test]
fn peppol_valid_configuration_builds() {
    let ca = rsa_ca();
    let a = ca.peppol_party("POP000001");
    let b = ca.peppol_party("POP000002");
    As4::builder(Profile::peppol())
        .local(a.local())
        .trust_anchor(ca.anchor())
        .partner(b.partner(B_URL))
        .http_client(Loopback::new())
        .build()
        .expect("valid peppol configuration");
}

#[test]
fn edelivery_valid_configuration_builds() {
    let ca = rsa_ca();
    let a = ca.rsa_party("party-a");
    let b = ca.rsa_party("party-b");
    rsa_builder(Profile::edelivery_1_15(), &ca, &a)
        .partner(b.partner(B_URL))
        .build()
        .expect("valid edelivery configuration");
}

#[test]
fn entsog_valid_configuration_builds() {
    let ca = rsa_ca();
    let a = ca.rsa_party("party-a");
    let b = ca.rsa_party("party-b");
    rsa_builder(Profile::entsog(), &ca, &a)
        .partner(b.partner(B_URL))
        .build()
        .expect("valid entsog configuration");
}

#[cfg(feature = "as2")]
#[test]
fn as2_valid_configuration_builds() {
    let ca = rsa_ca();
    let a = ca.as2_party("OURAS2ID");
    let b = ca.as2_party("THEIRAS2ID");
    asx::as2::As2::builder(Profile::as2())
        .local(a.local())
        .trust_anchor(ca.anchor())
        .partner(b.partner("https://b.example/as2"))
        .http_client(Loopback::new())
        .build()
        .expect("valid as2 configuration");
}

// ── Rejections ──────────────────────────────────────────────────────────────

#[test]
fn no_local_party() {
    assert_refused(bdew().without_local().build(), &["Builder::local"]);
}

#[test]
fn local_party_without_signer() {
    let pki = bdew();
    let local = LocalParty::new(A)
        .party_type(BDEW_PARTY_TYPE)
        .decrypter(pki.a.encryption.key_pair())
        .tls_identity(pki.a.tls.key_pair());
    assert_refused(
        pki.without_local().local(local).build(),
        &["LocalParty::signer"],
    );
}

#[test]
fn local_party_without_decrypter() {
    let pki = bdew();
    let local = LocalParty::new(A)
        .party_type(BDEW_PARTY_TYPE)
        .signer(pki.a.signing.key_pair())
        .tls_identity(pki.a.tls.key_pair());
    assert_refused(
        pki.without_local().local(local).build(),
        &["LocalParty::decrypter"],
    );
}

#[test]
fn signer_key_type_not_allowed() {
    // bdew: RSA instead of BrainpoolP256r1.
    let pki = bdew();
    let rsa = pki.ca.issue_named(
        &[
            (Nid::COMMONNAME, "rsa sig"),
            (Nid::ORGANIZATIONALUNITNAME, A),
        ],
        KeyAlg::Rsa2048,
    );
    let local = LocalParty::new(A)
        .party_type(BDEW_PARTY_TYPE)
        .signer(rsa.key_pair())
        .decrypter(pki.a.encryption.key_pair())
        .tls_identity(pki.a.tls.key_pair());
    assert_refused(
        pki.without_local().local(local).build(),
        &["LocalParty::signer", BDEW, "§2.2.6.2.1"],
    );

    // peppol: EC P-256 instead of RSA >= 2048.
    let ca = rsa_ca();
    let ec = ca.issue("POP000001", KeyAlg::EcP256);
    let rsa = ca.issue("POP000001", KeyAlg::Rsa2048);
    let local = LocalParty::new("POP000001")
        .signer(ec.key_pair())
        .decrypter(rsa.key_pair());
    assert_refused(
        As4::builder(Profile::peppol())
            .local(local)
            .trust_anchor(ca.anchor())
            .http_client(Loopback::new())
            .build(),
        &["LocalParty::signer", PEPPOL, "§3"],
    );
}

#[cfg(feature = "as2")]
#[test]
fn as2_signer_key_type_not_allowed() {
    // as2: RSA >= 2048 or EC P-256/P-384; BrainpoolP256r1 is not allowed.
    let ca = rsa_ca();
    let bp = ca.issue("OURAS2ID", KeyAlg::EcBrainpoolP256r1);
    let rsa = ca.issue("OURAS2ID", KeyAlg::Rsa2048);
    let local = LocalParty::new("OURAS2ID")
        .signer(bp.key_pair())
        .decrypter(rsa.key_pair());
    assert_refused(
        asx::as2::As2::builder(Profile::as2())
            .local(local)
            .trust_anchor(ca.anchor())
            .http_client(Loopback::new())
            .build(),
        &["LocalParty::signer", "RFC 4130", "§2.4"],
    );
}

#[test]
fn decrypter_key_type_not_allowed() {
    let pki = bdew();
    let rsa = pki.ca.issue_named(
        &[
            (Nid::COMMONNAME, "rsa enc"),
            (Nid::ORGANIZATIONALUNITNAME, A),
        ],
        KeyAlg::Rsa2048,
    );
    let local = LocalParty::new(A)
        .party_type(BDEW_PARTY_TYPE)
        .signer(pki.a.signing.key_pair())
        .decrypter(rsa.key_pair())
        .tls_identity(pki.a.tls.key_pair());
    assert_refused(
        pki.without_local().local(local).build(),
        &["LocalParty::decrypter", BDEW, "§2.2.6.2.2"],
    );
}

#[test]
fn signer_chain_empty() {
    let pki = bdew();
    let local = LocalParty::new(A)
        .party_type(BDEW_PARTY_TYPE)
        .signer(ChainSigner(Vec::new()))
        .decrypter(pki.a.encryption.key_pair())
        .tls_identity(pki.a.tls.key_pair());
    assert_refused(
        pki.without_local().local(local).build(),
        &["LocalParty::signer", "empty"],
    );
}

#[test]
fn signer_leaf_expired() {
    let pki = bdew();
    let local = LocalParty::new(A)
        .party_type(BDEW_PARTY_TYPE)
        .signer(ChainSigner(vec![expired_certificate("expired signer")]))
        .decrypter(pki.a.encryption.key_pair())
        .tls_identity(pki.a.tls.key_pair());
    assert_refused(
        pki.without_local().local(local).build(),
        &["LocalParty::signer", "expired"],
    );
}

#[test]
fn bdew_signer_equals_decrypter() {
    let pki = bdew();
    let local = LocalParty::new(A)
        .party_type(BDEW_PARTY_TYPE)
        .signer(pki.a.signing.key_pair())
        .decrypter(pki.a.signing.key_pair())
        .tls_identity(pki.a.tls.key_pair());
    assert_refused(
        pki.without_local().local(local).build(),
        &["LocalParty::signer", BDEW, "§2.3.4.4"],
    );
}

#[test]
fn bdew_tls_identity_equals_signer_or_decrypter() {
    let pki = bdew();
    for tls in [&pki.a.signing, &pki.a.encryption] {
        let local = LocalParty::new(A)
            .party_type(BDEW_PARTY_TYPE)
            .signer(pki.a.signing.key_pair())
            .decrypter(pki.a.encryption.key_pair())
            .tls_identity(tls.key_pair());
        assert_refused(
            pki.without_local().local(local).build(),
            &["LocalParty::tls_identity", BDEW, "§2.3.4.4"],
        );
    }
}

#[test]
fn bdew_local_id_not_mp_id() {
    let ca = TestCa::sm_pki();
    let a = ca.bdew_party("99000000001");
    let b = ca.bdew_party(B);
    let builder = As4::builder(Profile::bdew())
        .local(a.local())
        .trust_anchor(ca.anchor())
        .partner(b.partner(B_URL))
        .http_client(Loopback::new());
    assert_refused(builder.build(), &["LocalParty::new", BDEW, "§2.3.1.1"]);
}

#[test]
fn bdew_party_type_missing_or_unknown() {
    let pki = bdew();
    let base = || {
        LocalParty::new(A)
            .signer(pki.a.signing.key_pair())
            .decrypter(pki.a.encryption.key_pair())
            .tls_identity(pki.a.tls.key_pair())
    };
    assert_refused(
        pki.without_local().local(base()).build(),
        &["LocalParty::party_type", BDEW, "§2.3.1.1"],
    );
    assert_refused(
        pki.without_local()
            .local(base().party_type("urn:example:not-a-bdew-type"))
            .build(),
        &["LocalParty::party_type", BDEW, "§2.3.1.1"],
    );
}

#[test]
fn peppol_party_type_set() {
    let ca = rsa_ca();
    let a = ca.peppol_party("POP000001");
    let local = a
        .local()
        .party_type("urn:fdc:peppol.eu:2017:identifiers:ap");
    assert_refused(
        As4::builder(Profile::peppol())
            .local(local)
            .trust_anchor(ca.anchor())
            .http_client(Loopback::new())
            .build(),
        &["LocalParty::party_type", PEPPOL, "§4.5"],
    );
}

#[test]
fn no_trust_anchor() {
    let pki = bdew();
    let builder = As4::builder(Profile::bdew())
        .local(pki.a.local())
        .partner(pki.b.partner(B_URL))
        .http_client(Loopback::new());
    assert_refused(builder.build(), &["Builder::trust_anchor"]);
}

#[test]
fn signer_does_not_chain_to_anchor() {
    let pki = bdew();
    let builder = As4::builder(Profile::bdew())
        .local(pki.a.local())
        .trust_anchor(TestCa::sm_pki().anchor())
        .partner(pki.b.partner(B_URL))
        .http_client(Loopback::new());
    assert_refused(builder.build(), &["LocalParty::signer", "trust anchor"]);
}

#[test]
fn two_decrypters_same_certificate() {
    let pki = bdew();
    let local = pki.a.local().decrypter(pki.a.encryption.key_pair());
    assert_refused(
        pki.without_local().local(local).build(),
        &["LocalParty::decrypter", "same certificate"],
    );
}

#[test]
fn partner_endpoint_invalid() {
    let pki = bdew();
    for url in [
        "http://b.example/as4",
        "not a url",
        "https://user:secret@b.example/as4",
    ] {
        let partner = Partner::new(B)
            .party_type(BDEW_PARTY_TYPE)
            .endpoint(url)
            .signing_cert(pki.b.signing.certificate())
            .encryption_cert(pki.b.encryption.certificate());
        assert_refused(
            pki.without_partner().partner(partner).build(),
            &["Partner(9900000000002)::endpoint"],
        );
    }
}

#[test]
fn partner_endpoint_without_encryption_cert() {
    let ca = rsa_ca();
    let a = ca.rsa_party("party-a");
    let b = ca.rsa_party("party-b");
    for profile in [Profile::edelivery_1_15(), Profile::entsog()] {
        let partner = Partner::new("party-b")
            .endpoint(B_URL)
            .signing_cert(b.signing.certificate());
        assert_refused(
            rsa_builder(profile, &ca, &a).partner(partner).build(),
            &["Partner(party-b)::encryption_cert"],
        );
    }
}

/// Under BDEW a partner without an encryption certificate builds (it can be
/// sent a payload-less path switch); a business message to it is refused at
/// `send` — see tests/as4_path_switch.rs.
#[test]
fn bdew_partner_without_encryption_cert_builds_for_path_switch() {
    let pki = bdew();
    let partner = pki.partner_b().signing_cert(pki.b.signing.certificate());
    pki.without_partner()
        .partner(partner)
        .build()
        .expect("a path-switch-only BDEW partner builds");
}

#[test]
fn registered_partner_without_signing_cert() {
    let ca = rsa_ca();
    let a = ca.rsa_party("party-a");
    let b = ca.rsa_party("party-b");
    let partner = Partner::new("party-b")
        .party_type(b.party_type.clone().expect("rsa party type"))
        .endpoint(B_URL)
        .encryption_cert(b.encryption.certificate());
    for profile in [Profile::edelivery_1_15(), Profile::entsog()] {
        assert_refused(
            rsa_builder(profile, &ca, &a)
                .partner(partner.clone())
                .build(),
            &["Partner(party-b)::signing_cert"],
        );
    }
}

#[cfg(feature = "as2")]
#[test]
fn as2_registered_partner_without_signing_cert() {
    let ca = rsa_ca();
    let a = ca.as2_party("OURAS2ID");
    let b = ca.as2_party("THEIRAS2ID");
    let partner = Partner::new("THEIRAS2ID")
        .endpoint("https://b.example/as2")
        .encryption_cert(b.encryption.certificate());
    assert_refused(
        asx::as2::As2::builder(Profile::as2())
            .local(a.local())
            .trust_anchor(ca.anchor())
            .partner(partner)
            .http_client(Loopback::new())
            .build(),
        &["Partner(THEIRAS2ID)::signing_cert"],
    );
}

#[test]
fn partner_certificate_key_type_not_allowed() {
    let pki = bdew();
    let rsa = pki.ca.issue_named(
        &[(Nid::COMMONNAME, "rsa"), (Nid::ORGANIZATIONALUNITNAME, B)],
        KeyAlg::Rsa2048,
    );
    let signing = pki
        .partner_b()
        .signing_cert(rsa.certificate())
        .encryption_cert(pki.b.encryption.certificate());
    assert_refused(
        pki.without_partner().partner(signing).build(),
        &["Partner(9900000000002)::signing_cert", BDEW, "§2.2.6.2.1"],
    );
    let encryption = pki
        .partner_b()
        .signing_cert(pki.b.signing.certificate())
        .encryption_cert(rsa.certificate());
    assert_refused(
        pki.without_partner().partner(encryption).build(),
        &[
            "Partner(9900000000002)::encryption_cert",
            BDEW,
            "§2.2.6.2.2",
        ],
    );
}

#[test]
fn partner_certificate_expired() {
    let ca = rsa_ca();
    let a = ca.rsa_party("party-a");
    let b = ca.rsa_party("party-b");
    let party_type = b.party_type.clone().expect("rsa party type");
    let signing = Partner::new("party-b")
        .party_type(&party_type)
        .endpoint(B_URL)
        .signing_cert(expired_certificate("party-b sig"))
        .encryption_cert(b.encryption.certificate());
    assert_refused(
        rsa_builder(Profile::edelivery_1_15(), &ca, &a)
            .partner(signing)
            .build(),
        &["Partner(party-b)::signing_cert", "expired"],
    );
    let encryption = Partner::new("party-b")
        .party_type(&party_type)
        .endpoint(B_URL)
        .signing_cert(b.signing.certificate())
        .encryption_cert(expired_certificate("party-b enc"));
    assert_refused(
        rsa_builder(Profile::edelivery_1_15(), &ca, &a)
            .partner(encryption)
            .build(),
        &["Partner(party-b)::encryption_cert", "expired"],
    );
}

#[test]
fn bdew_partner_subject_lacks_mp_id() {
    let pki = bdew();
    // B's id with the certificates of another market participant.
    let other = pki.ca.bdew_party("9900000000003");
    let partner = pki
        .partner_b()
        .signing_cert(other.signing.certificate())
        .encryption_cert(other.encryption.certificate());
    assert_refused(
        pki.without_partner().partner(partner).build(),
        &[
            "Partner(9900000000002)::signing_cert",
            "MP-ID",
            BDEW,
            "§2.3.4.4",
        ],
    );
}

#[test]
fn peppol_partner_cn_not_party_id() {
    let ca = rsa_ca();
    let a = ca.peppol_party("POP000001");
    let b = ca.peppol_party("POP000002");
    let partner = Partner::new("POP000999")
        .endpoint(B_URL)
        .signing_cert(b.signing.certificate())
        .encryption_cert(b.encryption.certificate());
    assert_refused(
        As4::builder(Profile::peppol())
            .local(a.local())
            .trust_anchor(ca.anchor())
            .partner(partner)
            .http_client(Loopback::new())
            .build(),
        &["Partner(POP000999)::signing_cert", PEPPOL, "§4.5"],
    );
}

#[test]
fn duplicate_partner() {
    let pki = bdew();
    assert_refused(
        pki.valid()
            .partner(pki.b.partner("https://b2.example/as4"))
            .build(),
        &["Partner(9900000000002)", "twice"],
    );
}

#[test]
fn partner_id_equals_local_id() {
    let pki = bdew();
    assert_refused(
        pki.valid()
            .partner(pki.a.partner("https://a.example/as4"))
            .build(),
        &["Partner(9900000000001)", "local party"],
    );
}

#[test]
fn max_message_bytes_out_of_range() {
    let pki = bdew();
    for bytes in [0, u64::MAX] {
        let builder = As4::builder(Profile::bdew().max_message_bytes(bytes))
            .local(pki.a.local())
            .trust_anchor(pki.ca.anchor())
            .partner(pki.b.partner(B_URL))
            .http_client(Loopback::new());
        assert_refused(builder.build(), &["Profile::max_message_bytes"]);
    }
}

#[cfg(feature = "as2")]
#[test]
fn profile_protocol_differs_from_client() {
    let ca = rsa_ca();
    let a = ca.as2_party("OURAS2ID");
    assert_refused(
        As4::builder(Profile::as2())
            .local(a.local())
            .trust_anchor(ca.anchor())
            .http_client(Loopback::new())
            .build(),
        &["Profile", "as2"],
    );
    let pki = bdew();
    assert_refused(
        asx::as2::As2::builder(Profile::bdew())
            .local(pki.a.local())
            .trust_anchor(pki.ca.anchor())
            .http_client(Loopback::new())
            .build(),
        &["Profile", "bdew"],
    );
}

#[test]
fn quirk_of_other_protocol() {
    let pki = bdew();
    let partner = pki.b.partner(B_URL).quirk(Quirk::UnsignedMdn);
    assert_refused(
        pki.without_partner().partner(partner).build(),
        &["Partner(9900000000002)::quirk", "UnsignedMdn"],
    );
}

#[cfg(feature = "as2")]
#[test]
fn as2_quirk_of_other_protocol() {
    let ca = rsa_ca();
    let a = ca.as2_party("OURAS2ID");
    let b = ca.as2_party("THEIRAS2ID");
    let partner = b
        .partner("https://b.example/as2")
        .quirk(Quirk::ReceiptWithoutNonRepudiation);
    assert_refused(
        asx::as2::As2::builder(Profile::as2())
            .local(a.local())
            .trust_anchor(ca.anchor())
            .partner(partner)
            .http_client(Loopback::new())
            .build(),
        &["Partner(THEIRAS2ID)::quirk", "ReceiptWithoutNonRepudiation"],
    );
}

#[cfg(feature = "as2")]
#[test]
fn as2_id_not_printable_ascii() {
    let ca = rsa_ca();
    let a = ca.as2_party("OURAS2ID");
    let b = ca.as2_party("THEIRAS2ID");
    let builder = || {
        asx::as2::As2::builder(Profile::as2())
            .trust_anchor(ca.anchor())
            .http_client(Loopback::new())
    };
    for bad in ["", "bad\nid", &"x".repeat(129)] {
        let local = LocalParty::new(bad)
            .signer(a.signing.key_pair())
            .decrypter(a.encryption.key_pair());
        assert_refused(
            builder().local(local).build(),
            &["LocalParty::new", "RFC 4130", "§6.2"],
        );
    }
    let partner = Partner::new("bad\u{7f}id")
        .endpoint("https://b.example/as2")
        .signing_cert(b.signing.certificate())
        .encryption_cert(b.encryption.certificate());
    assert_refused(
        builder().local(a.local()).partner(partner).build(),
        &["::id", "RFC 4130", "§6.2"],
    );
}

#[cfg(not(feature = "http-client"))]
#[test]
fn no_http_client_without_feature() {
    let pki = bdew();
    let builder = As4::builder(Profile::bdew())
        .local(pki.a.local())
        .trust_anchor(pki.ca.anchor())
        .partner(pki.b.partner(B_URL));
    assert_refused(builder.build(), &["Builder::http_client"]);
}

/// An indirect-CRL signer must chain to a trust anchor, assert `cRLSign`, not
/// be an anchor itself and not be repeated.
#[test]
fn crl_signer_rules() {
    let pki = bdew();
    let signer = pki.ca.crl_signer("CCRL-S(Root)", KeyAlg::EcBrainpoolP256r1);
    pki.valid()
        .crl_signer(signer.certificate())
        .build()
        .expect("control: a CRL signer issued by the anchor builds");

    // Not chaining to a configured anchor.
    let foreign = TestCa::sm_pki().crl_signer("CCRL-S(foreign)", KeyAlg::EcBrainpoolP256r1);
    assert_refused(
        pki.valid().crl_signer(foreign.certificate()).build(),
        &["Builder::crl_signer", "chain"],
    );
    // Without cRLSign (an end-entity signing certificate).
    assert_refused(
        pki.valid().crl_signer(pki.b.signing.certificate()).build(),
        &["Builder::crl_signer", "cRLSign"],
    );
    // The anchor itself.
    assert_refused(
        pki.valid().crl_signer(pki.ca.anchor()).build(),
        &["Builder::crl_signer", "trust anchor"],
    );
    // Twice.
    assert_refused(
        pki.valid()
            .crl_signer(signer.certificate())
            .crl_signer(signer.certificate())
            .build(),
        &["Builder::crl_signer", "twice"],
    );
}
