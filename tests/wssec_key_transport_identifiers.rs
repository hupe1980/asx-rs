#![cfg(feature = "as4")]
//! Inbound XML Encryption reads every declared parameter and refuses what it
//! does not support **by name, before the private key is used**; every
//! failure after the key is used looks the same.
//!
//! Each test encrypts one attachment to a brainpoolP256r1 (ECDH-ES) or
//! RSA-2048 (RSA-OAEP) recipient in the WSS SwA shape (`encrypt_swa`), mutates one declared item of the `wsse:Security` header
//! and decrypts with `decrypt_swa`.

use asx::__fuzz::wssec::{XmlEncPayloadAlgorithm, decrypt_swa, encrypt_swa};
use asx::__fuzz::{AsxError, ErrorCode};
use asx::testkit::pki::{KeyAlg, KeyPair};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

const PLAINTEXT: &[u8] = b"BDEW payload: UNB+UNOC:3+9900000000001:500+9900000000002:500'";

const XENC: &str = "http://www.w3.org/2001/04/xmlenc#";
const XENC11: &str = "http://www.w3.org/2009/xmlenc11#";

struct Case {
    pair: KeyPair,
    xml: String,
}

/// The part bodies by Content-ID: a header names its part, so mutating the
/// header text keeps the body reachable.
static BODIES: Mutex<Option<HashMap<String, Vec<u8>>>> = Mutex::new(None);
static NEXT: AtomicUsize = AtomicUsize::new(0);

fn register(body: Vec<u8>) -> String {
    let cid = format!("part{}@asx.test", NEXT.fetch_add(1, Ordering::SeqCst));
    BODIES
        .lock()
        .unwrap()
        .get_or_insert_with(HashMap::new)
        .insert(cid.clone(), body);
    cid
}

fn body_of(cid: &str) -> Vec<u8> {
    BODIES.lock().unwrap().as_ref().unwrap()[cid].clone()
}

fn cid_in(xml: &str) -> String {
    let at = xml.find("URI=\"cid:").expect("CipherReference") + "URI=\"cid:".len();
    xml[at..at + xml[at..].find('"').unwrap()].to_string()
}

fn encrypted(alg: KeyAlg, cipher: XmlEncPayloadAlgorithm) -> Case {
    let pair = KeyPair::self_signed("asx-xmlenc-recipient", alg);
    let cid = format!("part{}@asx.test", NEXT.fetch_add(1, Ordering::SeqCst));
    let (xml, mut bodies) = encrypt_swa(
        &[(cid.as_str(), "application/gzip", PLAINTEXT)],
        &pair.cert_pem,
        cipher,
    )
    .unwrap();
    BODIES
        .lock()
        .unwrap()
        .get_or_insert_with(HashMap::new)
        .insert(cid, bodies.remove(0));
    Case { pair, xml }
}

/// `xml` with its part body replaced by `f(body)`.
fn with_body(xml: &str, f: impl Fn(Vec<u8>) -> Vec<u8>) -> String {
    let old = cid_in(xml);
    let new = register(f(body_of(&old)));
    xml.replace(&format!("cid:{old}"), &format!("cid:{new}"))
}

fn ec() -> Case {
    encrypted(KeyAlg::EcBrainpoolP256r1, XmlEncPayloadAlgorithm::Aes128Gcm)
}

fn rsa() -> Case {
    encrypted(KeyAlg::Rsa2048, XmlEncPayloadAlgorithm::Aes128Gcm)
}

fn decrypt(xml: &str, key_pem: &[u8]) -> Result<Vec<u8>, AsxError> {
    let cid = cid_in(xml);
    let body = body_of(&cid);
    decrypt_swa(xml.as_bytes(), &[(cid.as_str(), &body)], key_pem).map(|mut v| v.remove(0))
}

/// Byte range of the first element named `qname` (start tag through end tag,
/// or a self-closing tag).
fn element(xml: &str, qname: &str) -> std::ops::Range<usize> {
    let open = format!("<{qname}");
    let start = xml
        .match_indices(&open)
        .map(|(i, _)| i)
        .find(|&i| matches!(xml.as_bytes().get(i + open.len()), Some(b' ' | b'>' | b'/')))
        .unwrap_or_else(|| panic!("no <{qname}> in\n{xml}"));
    let tag_end = start + xml[start..].find('>').unwrap();
    if xml.as_bytes()[tag_end - 1] == b'/' {
        return start..tag_end + 1;
    }
    let close = format!("</{qname}>");
    let end = start + xml[start..].find(&close).unwrap() + close.len();
    start..end
}

fn remove(xml: &str, qname: &str) -> String {
    let r = element(xml, qname);
    format!("{}{}", &xml[..r.start], &xml[r.end..])
}

fn duplicate(xml: &str, qname: &str) -> String {
    let r = element(xml, qname);
    format!("{}{}{}", &xml[..r.end], &xml[r.clone()], &xml[r.end..])
}

fn replace_element(xml: &str, qname: &str, with: &str) -> String {
    let r = element(xml, qname);
    format!("{}{}{}", &xml[..r.start], with, &xml[r.end..])
}

/// Set `attr` on the first `qname` element.
fn set_attr(xml: &str, qname: &str, attr: &str, value: &str) -> String {
    let r = element(xml, qname);
    let tag_end = r.start + xml[r.start..].find('>').unwrap();
    let tag = &xml[r.start..tag_end];
    let needle = format!("{attr}=\"");
    let new_tag = match tag.find(&needle) {
        Some(at) => {
            let vstart = at + needle.len();
            let vend = vstart + tag[vstart..].find('"').unwrap();
            format!("{}{}{}", &tag[..vstart], value, &tag[vend..])
        }
        None => panic!("<{qname}> has no {attr}"),
    };
    format!("{}{}{}", &xml[..r.start], new_tag, &xml[tag_end..])
}

/// Insert `child` as the first child of the first `qname` element.
fn insert_child(xml: &str, qname: &str, child: &str) -> String {
    let r = element(xml, qname);
    let tag_end = r.start + xml[r.start..].find('>').unwrap();
    if xml.as_bytes()[tag_end - 1] == b'/' {
        let open = &xml[r.start..tag_end - 1];
        return format!(
            "{}{open}>{child}</{qname}>{}",
            &xml[..r.start],
            &xml[tag_end + 1..]
        );
    }
    format!("{}{}{}", &xml[..tag_end + 1], child, &xml[tag_end + 1..])
}

/// The RSA-OAEP `xenc:EncryptionMethod` of the `xenc:EncryptedKey`.
fn oaep_method(xml: &str) -> std::ops::Range<usize> {
    let key = element(xml, "xenc:EncryptedKey");
    let inner = &xml[key.clone()];
    let r = element(inner, "xenc:EncryptionMethod");
    key.start + r.start..key.start + r.end
}

fn edit_oaep(xml: &str, f: impl Fn(&str) -> String) -> String {
    let r = oaep_method(xml);
    format!("{}{}{}", &xml[..r.start], f(&xml[r.clone()]), &xml[r.end..])
}

fn assert_named(result: Result<Vec<u8>, AsxError>, needles: &[&str], case: &str) {
    let err = result.expect_err(case);
    assert_eq!(
        err.code,
        ErrorCode::InteropViolation,
        "{case}: {}",
        err.message
    );
    for needle in needles {
        assert!(
            err.message.contains(needle),
            "{case}: the error must name {needle:?}: {}",
            err.message
        );
    }
}

#[test]
fn unmutated_messages_decrypt() {
    for case in [
        ec(),
        rsa(),
        encrypted(KeyAlg::EcP256, XmlEncPayloadAlgorithm::Aes256Gcm),
        encrypted(KeyAlg::Rsa2048, XmlEncPayloadAlgorithm::Aes256Gcm),
    ] {
        assert_eq!(decrypt(&case.xml, &case.pair.key_pem).unwrap(), PLAINTEXT);
    }
}

#[test]
fn key_derivation_method_required_exactly_once() {
    let c = ec();
    assert_named(
        decrypt(
            &remove(&c.xml, "xenc11:KeyDerivationMethod"),
            &c.pair.key_pem,
        ),
        &["KeyDerivationMethod"],
        "K1 absent",
    );
    assert_named(
        decrypt(
            &duplicate(&c.xml, "xenc11:KeyDerivationMethod"),
            &c.pair.key_pem,
        ),
        &["KeyDerivationMethod"],
        "K1 twice",
    );
}

#[test]
fn only_concat_kdf_is_accepted() {
    let c = ec();
    for uri in [
        "http://www.w3.org/2021/04/xmldsig-more#hkdf",
        "http://www.w3.org/2009/xmlenc11#pbkdf2",
    ] {
        assert_named(
            decrypt(
                &set_attr(&c.xml, "xenc11:KeyDerivationMethod", "Algorithm", uri),
                &c.pair.key_pem,
            ),
            &["key derivation", uri],
            "K2",
        );
    }
}

#[test]
fn concat_kdf_params_required_exactly_once() {
    let c = ec();
    assert_named(
        decrypt(&remove(&c.xml, "xenc11:ConcatKDFParams"), &c.pair.key_pem),
        &["ConcatKDFParams"],
        "K3 absent",
    );
    assert_named(
        decrypt(
            &duplicate(&c.xml, "xenc11:ConcatKDFParams"),
            &c.pair.key_pem,
        ),
        &["ConcatKDFParams"],
        "K3 twice",
    );
}

#[test]
fn concat_kdf_digest_method_required_exactly_once() {
    let c = ec();
    let params = element(&c.xml, "xenc11:ConcatKDFParams");
    let inner = &c.xml[params.clone()];
    let without = format!(
        "{}{}{}",
        &c.xml[..params.start],
        remove(inner, "ds:DigestMethod"),
        &c.xml[params.end..]
    );
    assert_named(
        decrypt(&without, &c.pair.key_pem),
        &["ConcatKDFParams/DigestMethod"],
        "K4 absent",
    );
    let twice = format!(
        "{}{}{}",
        &c.xml[..params.start],
        duplicate(inner, "ds:DigestMethod"),
        &c.xml[params.end..]
    );
    assert_named(
        decrypt(&twice, &c.pair.key_pem),
        &["ConcatKDFParams/DigestMethod"],
        "K4 twice",
    );
}

#[test]
fn concat_kdf_digest_must_be_sha256() {
    let c = ec();
    let params = element(&c.xml, "xenc11:ConcatKDFParams");
    let sha512 = "http://www.w3.org/2001/04/xmlenc#sha512";
    let inner = set_attr(
        &c.xml[params.clone()],
        "ds:DigestMethod",
        "Algorithm",
        sha512,
    );
    let xml = format!(
        "{}{}{}",
        &c.xml[..params.start],
        inner,
        &c.xml[params.end..]
    );
    assert_named(decrypt(&xml, &c.pair.key_pem), &[sha512], "K5");
}

#[test]
fn xmlenc11_elements_in_the_xmlenc10_namespace_are_refused() {
    let c = ec();
    let kdm = c
        .xml
        .replace("xenc11:KeyDerivationMethod", "xenc:KeyDerivationMethod");
    assert_named(
        decrypt(&kdm, &c.pair.key_pem),
        &["KeyDerivationMethod", XENC],
        "K6 KeyDerivationMethod",
    );
    let params = c
        .xml
        .replace("xenc11:ConcatKDFParams", "xenc:ConcatKDFParams");
    assert_named(
        decrypt(&params, &c.pair.key_pem),
        &["ConcatKDFParams", XENC],
        "K6 ConcatKDFParams",
    );
    let r = rsa();
    let mgf = r.xml.replace("xenc11:MGF", "xenc:MGF");
    assert_named(decrypt(&mgf, &r.pair.key_pem), &["MGF", XENC], "K6 MGF");
}

#[test]
fn named_curve_must_be_the_recipient_curve() {
    let c = ec();
    let p384 = "urn:oid:1.3.132.0.34";
    assert_named(
        decrypt(
            &set_attr(&c.xml, "dsig11:NamedCurve", "URI", p384),
            &c.pair.key_pem,
        ),
        &[p384, "BrainpoolP256r1"],
        "K7",
    );
}

#[test]
fn named_curve_required_and_known() {
    let c = ec();
    assert_named(
        decrypt(
            &replace_element(&c.xml, "dsig11:NamedCurve", "<dsig11:ECParameters/>"),
            &c.pair.key_pem,
        ),
        &["ECParameters"],
        "K8 ECParameters",
    );
    assert_named(
        decrypt(&remove(&c.xml, "dsig11:NamedCurve"), &c.pair.key_pem),
        &["NamedCurve"],
        "K8 absent",
    );
    assert_named(
        decrypt(
            &set_attr(&c.xml, "dsig11:NamedCurve", "URI", "urn:oid:1.2.3.4"),
            &c.pair.key_pem,
        ),
        &["urn:oid:1.2.3.4"],
        "K8 unknown",
    );
}

#[test]
fn rsa_oaep_digest_must_be_declared_sha256() {
    let r = rsa();
    let absent = edit_oaep(&r.xml, |m| remove(m, "ds:DigestMethod"));
    assert_named(
        decrypt(&absent, &r.pair.key_pem),
        &["DigestMethod", "absent (SHA-1 default)"],
        "K10 absent",
    );
    let sha1 = "http://www.w3.org/2000/09/xmldsig#sha1";
    let other = edit_oaep(&r.xml, |m| {
        set_attr(m, "ds:DigestMethod", "Algorithm", sha1)
    });
    assert_named(
        decrypt(&other, &r.pair.key_pem),
        &["DigestMethod", sha1],
        "K10 sha1",
    );
}

#[test]
fn rsa_oaep_mgf_must_be_declared_mgf1_sha256() {
    let r = rsa();
    let absent = edit_oaep(&r.xml, |m| remove(m, "xenc11:MGF"));
    assert_named(
        decrypt(&absent, &r.pair.key_pem),
        &["MGF", "absent (MGF1-SHA-1 default)"],
        "K11 absent",
    );
    let mgf1sha1 = format!("{XENC11}mgf1sha1");
    let other = edit_oaep(&r.xml, |m| {
        set_attr(m, "xenc11:MGF", "Algorithm", &mgf1sha1)
    });
    assert_named(
        decrypt(&other, &r.pair.key_pem),
        &["MGF", &mgf1sha1],
        "K11 sha1",
    );
}

#[test]
fn non_empty_oaep_params_are_refused() {
    let r = rsa();
    let xml = edit_oaep(&r.xml, |m| {
        insert_child(
            m,
            "xenc:EncryptionMethod",
            "<xenc:OAEPparams>AAAA</xenc:OAEPparams>",
        )
    });
    assert_named(decrypt(&xml, &r.pair.key_pem), &["OAEPparams"], "K12");
    let empty = edit_oaep(&r.xml, |m| {
        insert_child(
            m,
            "xenc:EncryptionMethod",
            "<xenc:OAEPparams></xenc:OAEPparams>",
        )
    });
    assert_eq!(
        decrypt(&empty, &r.pair.key_pem).expect("an empty OAEPparams is the empty label"),
        PLAINTEXT
    );
}

#[test]
fn unknown_transport_wrap_and_cipher_are_refused_by_role() {
    let r = rsa();
    let rsa15 = format!("{XENC}rsa-1_5");
    let xml = edit_oaep(&r.xml, |m| {
        set_attr(m, "xenc:EncryptionMethod", "Algorithm", &rsa15)
    });
    assert_named(decrypt(&xml, &r.pair.key_pem), &[&rsa15], "K13 transport");

    let c = ec();
    let key = element(&c.xml, "xenc:EncryptedKey");
    let tdes = format!("{XENC}kw-tripledes");
    let inner = set_attr(
        &c.xml[key.clone()],
        "xenc:EncryptionMethod",
        "Algorithm",
        &tdes,
    );
    let xml = format!("{}{}{}", &c.xml[..key.start], inner, &c.xml[key.end..]);
    assert_named(decrypt(&xml, &c.pair.key_pem), &[&tdes], "K13 wrap");

    let cbc = format!("{XENC}aes256-cbc");
    let data = element(&r.xml, "xenc:EncryptedData");
    let inner = set_attr(
        &r.xml[data.clone()],
        "xenc:EncryptionMethod",
        "Algorithm",
        &cbc,
    );
    let xml = format!("{}{}{}", &r.xml[..data.start], inner, &r.xml[data.end..]);
    assert_named(
        decrypt(&xml, &r.pair.key_pem),
        &["content encryption", &cbc],
        "K13 cipher",
    );
}

/// The identifier checks precede any key use: with a key PEM that does not
/// parse, a bad identifier is still reported as the identifier.
#[test]
fn identifier_checks_precede_key_use() {
    let garbage = b"-----BEGIN PRIVATE KEY-----\nnot a key\n-----END PRIVATE KEY-----\n";
    let c = ec();
    let hkdf = "http://www.w3.org/2021/04/xmldsig-more#hkdf";
    assert_named(
        decrypt(
            &set_attr(&c.xml, "xenc11:KeyDerivationMethod", "Algorithm", hkdf),
            garbage,
        ),
        &[hkdf],
        "K2 with garbage key",
    );
    let r = rsa();
    let absent = edit_oaep(&r.xml, |m| remove(m, "ds:DigestMethod"));
    assert_named(
        decrypt(&absent, garbage),
        &["absent (SHA-1 default)"],
        "K10 with garbage key",
    );
}

// ── One failure after the key is used (D1–D4) ───────────────────────────────

fn cipher_values(xml: &str) -> Vec<std::ops::Range<usize>> {
    xml.match_indices("<xenc:CipherValue>")
        .map(|(i, m)| {
            let start = i + m.len();
            start..start + xml[start..].find("</xenc:CipherValue>").unwrap()
        })
        .collect()
}

/// Index 0 is the wrapped key (the one CipherValue); index 1 the content —
/// the MIME part body (SwA `CipherReference`).
fn with_cipher_value(xml: &str, index: usize, f: impl Fn(Vec<u8>) -> Vec<u8>) -> String {
    if index == 1 {
        return with_body(xml, f);
    }
    let ranges = cipher_values(xml);
    let r = ranges[0].clone();
    let decoded = B64
        .decode(xml[r.clone()].split_whitespace().collect::<String>())
        .unwrap();
    format!(
        "{}{}{}",
        &xml[..r.start],
        B64.encode(f(decoded)),
        &xml[r.end..]
    )
}

fn flip_last(mut bytes: Vec<u8>) -> Vec<u8> {
    let last = bytes.len() - 1;
    bytes[last] ^= 0x01;
    bytes
}

#[test]
fn decryption_failures_are_indistinguishable() {
    let r = rsa();
    let c = ec();

    // D1: OAEP decode fails.
    let d1 = decrypt(&with_cipher_value(&r.xml, 0, flip_last), &r.pair.key_pem);
    // D2: key-unwrap integrity fails.
    let d2 = decrypt(&with_cipher_value(&c.xml, 0, flip_last), &c.pair.key_pem);
    // D3: a 32-octet CEK under the declared aes128-gcm.
    let d3 = {
        let cert = openssl::x509::X509::from_pem(&r.pair.cert_pem).unwrap();
        let pkey = cert.public_key().unwrap();
        let mut enc = openssl::encrypt::Encrypter::new(&pkey).unwrap();
        enc.set_rsa_padding(openssl::rsa::Padding::PKCS1_OAEP)
            .unwrap();
        enc.set_rsa_oaep_md(openssl::hash::MessageDigest::sha256())
            .unwrap();
        enc.set_rsa_mgf1_md(openssl::hash::MessageDigest::sha256())
            .unwrap();
        let cek = [0x42u8; 32];
        let mut out = vec![0u8; enc.encrypt_len(&cek).unwrap()];
        let n = enc.encrypt(&cek, &mut out).unwrap();
        out.truncate(n);
        decrypt(
            &with_cipher_value(&r.xml, 0, |_| out.clone()),
            &r.pair.key_pem,
        )
    };
    // D4: GCM tag mismatch.
    let d4 = decrypt(&with_cipher_value(&r.xml, 1, flip_last), &r.pair.key_pem);

    let errors: Vec<AsxError> = [d1, d2, d3, d4]
        .into_iter()
        .map(|r| r.expect_err("must fail"))
        .collect();
    for (i, err) in errors.iter().enumerate() {
        assert_eq!(
            err.code,
            ErrorCode::DecryptionFailed,
            "D{}: {}",
            i + 1,
            err.message
        );
        assert_eq!(
            err.message,
            errors[0].message,
            "D{} must be indistinguishable from D1",
            i + 1
        );
        assert!(
            !err.message.to_ascii_lowercase().contains("openssl")
                && !err.message.contains("error:"),
            "D{}: no library detail: {}",
            i + 1,
            err.message
        );
    }
}
