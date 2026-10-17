#![cfg(feature = "as4")]
//! Outbound AS4 encryption in the WSS SwA shape, signed before encrypted.

#[path = "common/peers.rs"]
mod peers;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use peers::{Preset, pair};
use sha2::Digest;

const DS: &str = "http://www.w3.org/2000/09/xmldsig#";
const XENC: &str = "http://www.w3.org/2001/04/xmlenc#";
const XENC11: &str = "http://www.w3.org/2009/xmlenc11#";
const DSIG11: &str = "http://www.w3.org/2009/xmldsig11#";
const WSSE: &str =
    "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd";
const WSSE11: &str = "http://docs.oasis-open.org/wss/oasis-wss-wssecurity-secext-1.1.xsd";
const CONTENT_ONLY: &str =
    "http://docs.oasis-open.org/wss/oasis-wss-SwAProfile-1.1#Attachment-Content-Only";
const CIPHERTEXT_TRANSFORM: &str =
    "http://docs.oasis-open.org/wss/oasis-wss-SwAProfile-1.1#Attachment-Ciphertext-Transform";
const SKI_VALUE_TYPE: &str = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509SubjectKeyIdentifier";
const ENCRYPTED_KEY_TOKEN: &str =
    "http://docs.oasis-open.org/wss/oasis-wss-soap-message-security-1.1#EncryptedKey";

/// 2026-10-16T00:00:00Z.
fn fixed_time() -> std::time::SystemTime {
    std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_792_108_800)
}

/// One BDEW message with a fixed id and timestamp, sent through the loopback;
/// returns the captured request body (the receiver's answer is irrelevant).
async fn sent_bdew(payloads: &[&[u8]]) -> (peers::Pair, Vec<u8>) {
    let p = pair(Preset::Bdew);
    let mut message = asx::as4::Message::to(&p.to_b)
        .service(peers::MP)
        .message_id("golden-1@asx.test")
        .timestamp(fixed_time());
    for (i, body) in payloads.iter().enumerate() {
        message = message.payload(
            asx::Payload::new(body.to_vec(), "application/octet-stream")
                .named(format!("part{i}.txt")),
        );
    }
    let _ = p.sender.send(message).await;
    let body = p.loopback.last_request().expect("request").body().to_vec();
    (p, body)
}

/// The MIME parts of a captured multipart body: `(headers, body)`, root
/// first.
fn mime_parts(body: &[u8]) -> Vec<(String, Vec<u8>)> {
    let first_line = body
        .iter()
        .position(|b| *b == b'\r')
        .expect("boundary line");
    let delimiter = [b"\r\n".as_slice(), &body[..first_line]].concat();
    let mut parts = Vec::new();
    let mut rest = &body[first_line + 2..];
    loop {
        let split = rest
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .expect("header end");
        let headers = String::from_utf8_lossy(&rest[..split]).into_owned();
        let after = &rest[split + 4..];
        let end = after
            .windows(delimiter.len())
            .position(|w| w == delimiter.as_slice())
            .expect("next delimiter");
        parts.push((headers, after[..end].to_vec()));
        rest = &after[end + delimiter.len()..];
        if rest.starts_with(b"--") {
            return parts;
        }
        rest = &rest[2..];
    }
}

fn soap_text(body: &[u8]) -> String {
    String::from_utf8(mime_parts(body).remove(0).1).expect("UTF-8 SOAP part")
}

/// `(URI, DigestValue)` of every `ds:Reference` of the request's signature.
fn reference_digests(soap: &str) -> Vec<(String, String)> {
    let doc = roxmltree::Document::parse(soap).expect("SOAP part parses");
    doc.descendants()
        .filter(|n| n.has_tag_name((DS, "Reference")))
        .map(|r| {
            let value = r
                .descendants()
                .find(|n| n.has_tag_name((DS, "DigestValue")))
                .and_then(|n| n.text())
                .unwrap_or_default()
                .to_string();
            (r.attribute("URI").unwrap_or_default().to_string(), value)
        })
        .collect()
}

/// The `eb:Messaging` and Body digests of a fixed message are byte-identical
/// with or without encryption (the SwA envelope lives only in
/// `wsse:Security`, outside every signed subtree). The ConcatKDF golden is
/// `xmlenc::kdf::tests::concat_kdf_bdew_golden_is_unchanged`.
#[tokio::test]
async fn messaging_and_body_digests_golden_is_unchanged() {
    let (_, body) = sent_bdew(&[b"UNB+UNOC:3"]).await;
    let digests = reference_digests(&soap_text(&body));
    let same_document: Vec<_> = digests
        .iter()
        .filter(|(uri, _)| uri.starts_with('#'))
        .cloned()
        .collect();
    assert_eq!(
        same_document,
        vec![
            (
                "#as4-messaging".to_string(),
                "nMv/gKo1hahp5aCWA5MpfJ7p1HLC7t8UFQ/ezpJeFNU=".to_string()
            ),
            (
                "#as4-body".to_string(),
                "adfD/Vtscma87JFBMnukgCxNBiWnqTwZkQM7eUspkYQ=".to_string()
            ),
        ]
    );
}

fn child_elements<'a, 'i>(node: roxmltree::Node<'a, 'i>) -> Vec<roxmltree::Node<'a, 'i>> {
    node.children().filter(|n| n.is_element()).collect()
}

fn names(nodes: &[roxmltree::Node<'_, '_>]) -> Vec<(String, String)> {
    nodes
        .iter()
        .map(|n| {
            (
                n.tag_name().namespace().unwrap_or_default().to_string(),
                n.tag_name().name().to_string(),
            )
        })
        .collect()
}

fn ns_name(ns: &str, name: &str) -> (String, String) {
    (ns.to_string(), name.to_string())
}

fn header(headers: &str, name: &str) -> Option<String> {
    headers.lines().find_map(|line| {
        let (k, v) = line.split_once(':')?;
        k.trim()
            .eq_ignore_ascii_case(name)
            .then(|| v.trim().to_string())
    })
}

/// The recipient certificate's SKI as WSS4J computes it: the extension, else
/// SHA-1 of the `subjectPublicKey` bits.
fn ski(cert_pem: &[u8]) -> Vec<u8> {
    let cert = openssl::x509::X509::from_pem(cert_pem).unwrap();
    if let Some(ski) = cert.subject_key_id() {
        return ski.as_slice().to_vec();
    }
    let key = cert.public_key().unwrap().ec_key().unwrap();
    let mut ctx = openssl::bn::BigNumContext::new().unwrap();
    let point = key
        .public_key()
        .to_bytes(
            key.group(),
            openssl::ec::PointConversionForm::UNCOMPRESSED,
            &mut ctx,
        )
        .unwrap();
    openssl::sha::sha1(&point).to_vec()
}

/// BDEW: the `wsse:Security` header, the `EncryptedKey`, the
/// `EncryptedData` list and the MIME parts of an encrypted two-payload send.
#[tokio::test]
async fn bdew_outbound_shape() {
    let (p, body) = sent_bdew(&[b"UNB+UNOC:3+first", b"UNB+UNOC:3+second"]).await;
    let parts = mime_parts(&body);
    let soap = String::from_utf8(parts[0].1.clone()).unwrap();
    let doc = roxmltree::Document::parse(&soap).unwrap();

    // Children of wsse:Security, in order (a leading wsu:Timestamp is ours).
    let security = doc
        .descendants()
        .find(|n| n.has_tag_name((WSSE, "Security")))
        .expect("wsse:Security");
    let children = child_elements(security);
    let mut order = names(&children);
    if order.first().map(|(_, n)| n.as_str()) == Some("Timestamp") {
        order.remove(0);
    }
    assert_eq!(
        order,
        vec![
            ns_name(XENC, "EncryptedKey"),
            ns_name(XENC, "EncryptedData"),
            ns_name(XENC, "EncryptedData"),
            ns_name(WSSE, "BinarySecurityToken"),
            ns_name(DS, "Signature"),
        ],
        "wire-outbound §1 order"
    );
    // No xenc: element outside wsse:Security; Body empty.
    assert!(
        doc.descendants()
            .filter(|n| n.tag_name().namespace() == Some(XENC))
            .all(|n| n.ancestors().any(|a| a == security)),
        "xenc: element outside wsse:Security"
    );
    let body_el = doc
        .descendants()
        .find(|n| n.tag_name().name() == "Body")
        .unwrap();
    assert!(child_elements(body_el).is_empty(), "env:Body is empty");

    // The one EncryptedKey.
    let key = children
        .iter()
        .find(|n| n.has_tag_name((XENC, "EncryptedKey")))
        .unwrap();
    let key_id = key.attribute("Id").expect("EncryptedKey/@Id");
    assert!(key_id.starts_with("EK-"), "{key_id}");
    let key_children = child_elements(*key);
    assert_eq!(
        names(&key_children),
        vec![
            ns_name(XENC, "EncryptionMethod"),
            ns_name(DS, "KeyInfo"),
            ns_name(XENC, "CipherData"),
            ns_name(XENC, "ReferenceList"),
        ]
    );
    assert_eq!(
        key_children[0].attribute("Algorithm"),
        Some("http://www.w3.org/2001/04/xmlenc#kw-aes128")
    );
    let agreement = child_elements(key_children[1]);
    assert_eq!(names(&agreement), vec![ns_name(XENC, "AgreementMethod")]);
    assert_eq!(
        agreement[0].attribute("Algorithm"),
        Some("http://www.w3.org/2009/xmlenc11#ECDH-ES")
    );
    let am = child_elements(agreement[0]);
    assert_eq!(
        names(&am),
        vec![
            ns_name(XENC11, "KeyDerivationMethod"),
            ns_name(XENC, "OriginatorKeyInfo"),
            ns_name(XENC, "RecipientKeyInfo"),
        ]
    );
    assert_eq!(
        am[0].attribute("Algorithm"),
        Some("http://www.w3.org/2009/xmlenc11#ConcatKDF")
    );
    let params = child_elements(am[0])[0];
    for attr in ["AlgorithmID", "PartyUInfo", "PartyVInfo"] {
        assert_eq!(params.attribute(attr), Some(""), "{attr}");
    }
    assert_eq!(
        child_elements(params)[0].attribute("Algorithm"),
        Some("http://www.w3.org/2001/04/xmlenc#sha256")
    );
    let curve = am[1]
        .descendants()
        .find(|n| n.has_tag_name((DSIG11, "NamedCurve")))
        .unwrap();
    assert_eq!(curve.attribute("URI"), Some("urn:oid:1.3.36.3.3.2.8.1.1.7"));
    let recipient = child_elements(am[2]);
    assert_eq!(
        names(&recipient),
        vec![ns_name(WSSE, "SecurityTokenReference")]
    );
    let key_identifier = child_elements(recipient[0])[0];
    assert!(key_identifier.has_tag_name((WSSE, "KeyIdentifier")));
    assert_eq!(key_identifier.attribute("ValueType"), Some(SKI_VALUE_TYPE));
    assert_eq!(
        B64.decode(key_identifier.text().unwrap().trim()).unwrap(),
        ski(&p.b.encryption.cert_pem),
        "the SKI of the partner's encryption certificate"
    );
    assert!(
        key_children[2]
            .descendants()
            .any(|n| n.has_tag_name((XENC, "CipherValue")))
    );
    let references: Vec<String> = child_elements(key_children[3])
        .iter()
        .map(|r| r.attribute("URI").unwrap().to_string())
        .collect();

    // One EncryptedData per part, PartInfo order.
    let hrefs: Vec<String> = doc
        .descendants()
        .filter(|n| n.tag_name().name() == "PartInfo")
        .map(|n| n.attribute("href").unwrap().to_string())
        .collect();
    let data: Vec<_> = children
        .iter()
        .filter(|n| n.has_tag_name((XENC, "EncryptedData")))
        .collect();
    assert_eq!(data.len(), hrefs.len());
    assert_eq!(
        references,
        data.iter()
            .map(|d| format!("#{}", d.attribute("Id").unwrap()))
            .collect::<Vec<_>>(),
        "ReferenceList names every EncryptedData in header order"
    );
    for (d, href) in data.iter().zip(&hrefs) {
        assert!(d.attribute("Id").unwrap().starts_with("ED-"));
        assert_eq!(d.attribute("Type"), Some(CONTENT_ONLY));
        assert_eq!(d.attribute("MimeType"), Some("application/gzip"));
        assert_eq!(d.attribute("Encoding"), None);
        let c = child_elements(**d);
        assert_eq!(
            names(&c),
            vec![
                ns_name(XENC, "EncryptionMethod"),
                ns_name(DS, "KeyInfo"),
                ns_name(XENC, "CipherData"),
            ]
        );
        assert_eq!(
            c[0].attribute("Algorithm"),
            Some("http://www.w3.org/2009/xmlenc11#aes128-gcm")
        );
        let str_ = child_elements(c[1])[0];
        assert!(str_.has_tag_name((WSSE, "SecurityTokenReference")));
        assert_eq!(
            str_.attribute((WSSE11, "TokenType")),
            Some(ENCRYPTED_KEY_TOKEN)
        );
        assert_eq!(
            child_elements(str_)[0].attribute("URI"),
            Some(format!("#{key_id}").as_str())
        );
        let cipher = child_elements(c[2]);
        assert_eq!(names(&cipher), vec![ns_name(XENC, "CipherReference")]);
        assert_eq!(cipher[0].attribute("URI"), Some(href.as_str()));
        let transforms: Vec<_> = cipher[0]
            .descendants()
            .filter(|n| n.has_tag_name((DS, "Transform")))
            .collect();
        assert_eq!(transforms.len(), 1);
        assert_eq!(
            transforms[0].attribute("Algorithm"),
            Some(CIPHERTEXT_TRANSFORM)
        );
    }

    // The MIME parts.
    for (headers, part) in &parts[1..] {
        assert_eq!(
            header(headers, "Content-Type").as_deref(),
            Some("application/octet-stream"),
            "{headers}"
        );
        assert_eq!(
            header(headers, "Content-Transfer-Encoding").as_deref(),
            Some("binary")
        );
        let cid = header(headers, "Content-ID").unwrap();
        assert!(
            hrefs.contains(&format!("cid:{}", cid.trim_matches(['<', '>']))),
            "{cid}"
        );
        assert!(part.len() >= 28, "IV ‖ ct ‖ tag");
    }
}

/// ECDH-ES + ConcatKDF (SHA-256, empty OtherInfo) + AES-KW + AES-128-GCM,
/// written here against OpenSSL directly — not with the library's code.
fn bdew_decrypt(soap: &str, recipient_key_pem: &[u8], parts: &[(String, Vec<u8>)]) -> Vec<Vec<u8>> {
    let doc = roxmltree::Document::parse(soap).unwrap();
    let text = |ns: &str, name: &str| {
        doc.descendants()
            .find(|n| n.has_tag_name((ns, name)))
            .and_then(|n| n.text())
            .map(|t| {
                B64.decode(t.split_whitespace().collect::<String>())
                    .unwrap()
            })
            .unwrap()
    };
    let peer_point = text(DSIG11, "PublicKey");
    let wrapped = text(XENC, "CipherValue");
    let key = openssl::pkey::PKey::private_key_from_pem(recipient_key_pem).unwrap();
    let ec = key.ec_key().unwrap();
    let group = ec.group();
    let mut ctx = openssl::bn::BigNumContext::new().unwrap();
    let point = openssl::ec::EcPoint::from_bytes(group, &peer_point, &mut ctx).unwrap();
    let peer = openssl::pkey::PKey::from_ec_key(
        openssl::ec::EcKey::from_public_key(group, &point).unwrap(),
    )
    .unwrap();
    let mut deriver = openssl::derive::Deriver::new(&key).unwrap();
    deriver.set_peer(&peer).unwrap();
    let z = deriver.derive_to_vec().unwrap();
    let kek = sha2::Sha256::digest([&[0u8, 0, 0, 1][..], &z].concat());
    let aes = openssl::aes::AesKey::new_decrypt(&kek[..16]).unwrap();
    let mut cek = [0u8; 16];
    openssl::aes::unwrap_key(&aes, None, &mut cek, &wrapped).unwrap();
    parts[1..]
        .iter()
        .map(|(_, body)| {
            let (iv, rest) = body.split_at(12);
            let (ct, tag) = rest.split_at(rest.len() - 16);
            openssl::symm::decrypt_aead(
                openssl::symm::Cipher::aes_128_gcm(),
                &cek,
                Some(iv),
                &[],
                ct,
                tag,
            )
            .unwrap()
        })
        .collect()
}

/// Each `cid:` DigestValue is SHA-256 of the part's
/// pre-encryption (gzip) bytes — recovered here with an independent
/// decryption — and not of the ciphertext on the wire.
#[tokio::test]
async fn cid_digests_cover_pre_encryption_bytes() {
    let payloads: [&[u8]; 2] = [b"UNB+UNOC:3+first", b"UNB+UNOC:3+second"];
    let (p, body) = sent_bdew(&payloads).await;
    let parts = mime_parts(&body);
    let soap = String::from_utf8(parts[0].1.clone()).unwrap();
    let digests = reference_digests(&soap);
    let plaintexts = bdew_decrypt(&soap, &p.b.encryption.key_pem, &parts);
    for (i, ((headers, wire), gz)) in parts[1..].iter().zip(&plaintexts).enumerate() {
        let cid = header(headers, "Content-ID").unwrap();
        let uri = format!("cid:{}", cid.trim_matches(['<', '>']));
        let (_, value) = digests.iter().find(|(u, _)| *u == uri).expect(&uri);
        let value = B64.decode(value).unwrap();
        assert_eq!(value, sha2::Sha256::digest(gz).to_vec(), "part {i}");
        assert_ne!(value, sha2::Sha256::digest(wire).to_vec(), "part {i}");
        let mut plain = Vec::new();
        std::io::Read::read_to_end(&mut flate2::read::GzDecoder::new(gz.as_slice()), &mut plain)
            .unwrap();
        assert_eq!(plain, payloads[i]);
    }
}

/// A retry reproduces every digest, `cid:` included: the digest covers the
/// deterministic gzip bytes, not ciphertext.
#[tokio::test]
async fn cid_digest_is_stable_across_retries() {
    let (_, first) = sent_bdew(&[b"retry"]).await;
    let (_, second) = sent_bdew(&[b"retry"]).await;
    let a = reference_digests(&soap_text(&first));
    let b = reference_digests(&soap_text(&second));
    assert_eq!(a.len(), 3);
    assert_eq!(a, b);
}

/// RSA form: under `edelivery_1_15()` the recipient's
/// BST comes first, the `EncryptedKey` references it, and RSA-OAEP declares
/// SHA-256 and MGF1-SHA-256.
#[tokio::test]
async fn edelivery_outbound_uses_the_recipient_bst() {
    let p = pair(Preset::Edelivery);
    p.sender
        .send(Preset::Edelivery.message(&p.to_b, b"rsa recipient"))
        .await
        .expect("receipted");
    let body = p.loopback.last_request().unwrap().body().to_vec();
    let soap = soap_text(&body);
    let doc = roxmltree::Document::parse(&soap).unwrap();
    let security = doc
        .descendants()
        .find(|n| n.has_tag_name((WSSE, "Security")))
        .unwrap();
    let children: Vec<_> = child_elements(security)
        .into_iter()
        .filter(|n| n.tag_name().name() != "Timestamp")
        .collect();
    assert_eq!(
        names(&children),
        vec![
            ns_name(WSSE, "BinarySecurityToken"),
            ns_name(XENC, "EncryptedKey"),
            ns_name(XENC, "EncryptedData"),
            ns_name(WSSE, "BinarySecurityToken"),
            ns_name(DS, "Signature"),
        ]
    );
    let recipient_der = B64.decode(children[0].text().unwrap().trim()).unwrap();
    let expected = openssl::x509::X509::from_pem(&p.b.encryption.cert_pem)
        .unwrap()
        .to_der()
        .unwrap();
    assert_eq!(
        recipient_der, expected,
        "the partner's encryption certificate"
    );
    let bst_id = children[0]
        .attribute((
            "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd",
            "Id",
        ))
        .unwrap();
    let key = children[1];
    let method = child_elements(key)[0];
    assert_eq!(
        method.attribute("Algorithm"),
        Some("http://www.w3.org/2009/xmlenc11#rsa-oaep")
    );
    let params: Vec<_> = child_elements(method)
        .iter()
        .map(|n| n.attribute("Algorithm").unwrap().to_string())
        .collect();
    assert_eq!(
        params,
        vec![
            "http://www.w3.org/2001/04/xmlenc#sha256".to_string(),
            "http://www.w3.org/2009/xmlenc11#mgf1sha256".to_string(),
        ]
    );
    let reference = key
        .descendants()
        .find(|n| n.has_tag_name((WSSE, "Reference")))
        .unwrap();
    assert_eq!(
        reference.attribute("URI"),
        Some(format!("#{bst_id}").as_str())
    );
    assert_eq!(
        reference.attribute("ValueType"),
        Some(
            "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3"
        )
    );
}

const PKIPATH: &str =
    "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509PKIPathv1";

/// Every `wsse:SecurityTokenReference` to a
/// `#X509PKIPathv1` token carries `wsse11:TokenType` (WS-I BSP R5215; WSS4J
/// refuses it otherwise) — on the user message and on our receipt.
fn assert_pkipath_str_has_token_type(xml: &str, what: &str) {
    let doc = roxmltree::Document::parse(xml).unwrap();
    let strs: Vec<_> = doc
        .descendants()
        .filter(|n| n.has_tag_name((WSSE, "SecurityTokenReference")))
        .filter(|n| {
            child_elements(*n)
                .iter()
                .any(|r| r.attribute("ValueType") == Some(PKIPATH))
        })
        .collect();
    assert!(!strs.is_empty(), "{what}: a PKIPath STR");
    for s in strs {
        assert_eq!(s.attribute((WSSE11, "TokenType")), Some(PKIPATH), "{what}");
    }
}

#[tokio::test]
async fn pkipath_token_reference_carries_token_type() {
    let p = pair(Preset::Bdew);
    let captured = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    {
        let captured = captured.clone();
        p.loopback
            .intercept(move |resp| captured.lock().unwrap().push(resp.body().to_vec()));
    }
    p.sender
        .send(Preset::Bdew.message(&p.to_b, b"token type"))
        .await
        .expect("receipted");
    let request = p.loopback.last_request().unwrap().body().to_vec();
    assert_pkipath_str_has_token_type(&soap_text(&request), "user message");
    let receipt = String::from_utf8(captured.lock().unwrap().pop().unwrap()).unwrap();
    assert_pkipath_str_has_token_type(&receipt, "receipt");
}

/// The ebMS3 header schema gives `eb:MessageId` no
/// attributes — a `wsu:Id` there is answered EBMS:0009 by phase4.
#[tokio::test]
async fn message_id_carries_no_attribute() {
    let (_, body) = sent_bdew(&[b"x"]).await;
    let soap = soap_text(&body);
    let doc = roxmltree::Document::parse(&soap).unwrap();
    let id = doc
        .descendants()
        .find(|n| n.tag_name().name() == "MessageId")
        .unwrap();
    assert_eq!(id.attributes().count(), 0, "{soap}");
}
