#![cfg(feature = "as4")]
//! Inbound AS4 encryption in the WSS SwA shape: authenticate, then decrypt.
//!
//! Every row posts a genuine message from `a` — mutated where the row says —
//! to an `Inbound` of `b` whose decrypter is the testkit `CountingKeys`, and
//! asserts the answer and how many private-key operations ran. The
//! encryption envelope lives in `wsse:Security`, outside every signed
//! subtree, so header mutations keep the signature valid and reach the
//! envelope checks.

#[path = "common/inbound_harness.rs"]
mod inbound_harness;
#[path = "common/peers.rs"]
mod peers;

use asx::as4::{As4, UserMessage};
use asx::{LocalParty, MemoryDedup, Payload, Reject, Verified};
use asx_testkit::keys::CountingKeys;
use inbound_harness::{Answer, Genuine, Part, post};
use peers::{A_URL, Preset};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

/// An `Inbound` of `b` with external decrypters and a counting handler.
struct Counted {
    inbound: asx::Inbound,
    keys: Vec<CountingKeys>,
    calls: Arc<AtomicUsize>,
}

impl Counted {
    fn decrypts(&self) -> usize {
        self.keys.iter().map(CountingKeys::decrypts).sum()
    }

    async fn post(&self, request: http::Request<bytes::Bytes>) -> Answer {
        post(&self.inbound, request).await
    }

    /// Refused with `code`, before any key operation, never delivered.
    #[track_caller]
    fn assert_pre_key(&self, answer: &Answer, code: &str) {
        answer.assert_refused(code);
        assert_eq!(self.decrypts(), 0, "no key operation: {answer:?}");
        assert_eq!(self.calls.load(Ordering::SeqCst), 0, "not delivered");
    }
}

/// `b` with `decrypters` (each wrapping a key pair) instead of its key pair.
fn counted_with(g: &Genuine, decrypters: &[&asx_testkit::pki::KeyPair]) -> Counted {
    let b = &g.pair.b;
    let keys: Vec<CountingKeys> = decrypters.iter().map(|k| CountingKeys::new(k)).collect();
    let mut local = LocalParty::new(&b.id)
        .signer(b.signing.key_pair())
        .tls_identity(b.tls.key_pair());
    for key in &keys {
        local = local.decrypter(key.clone());
    }
    if let Some(t) = &b.party_type {
        local = local.party_type(t);
    }
    let receiver = As4::builder(g.pair.preset.profile())
        .local(local)
        .trust_anchor(g.pair.ca.anchor())
        .partner(g.pair.a.partner(A_URL))
        .http_client(g.pair.loopback.clone())
        .build()
        .expect("receiver builds");
    let calls = Arc::new(AtomicUsize::new(0));
    let inbound = {
        let calls = calls.clone();
        receiver.inbound(MemoryDedup::default(), move |_m: Verified<UserMessage>| {
            let calls = calls.clone();
            async move {
                calls.fetch_add(1, Ordering::SeqCst);
                Ok::<(), Reject>(())
            }
        })
    };
    Counted {
        inbound,
        keys,
        calls,
    }
}

fn counted(g: &Genuine) -> Counted {
    counted_with(g, &[&g.pair.b.encryption])
}

/// A genuine two-payload message under `preset`.
async fn genuine2(preset: Preset) -> Genuine {
    let pair = peers::pair(preset);
    let message = preset
        .message(&pair.to_b, b"first payload")
        .payload(Payload::new(
            b"second payload".to_vec(),
            "application/octet-stream",
        ));
    pair.sender
        .send(message)
        .await
        .expect("the genuine message is receipted");
    let request = pair.loopback.last_request().expect("captured request");
    Genuine { pair, request }
}

async fn bdew2() -> Genuine {
    genuine2(Preset::Bdew).await
}

/// The `Id` values of the `xenc:EncryptedData` elements, in header order.
fn data_ids(soap: &str) -> Vec<String> {
    soap.match_indices("<xenc:EncryptedData ")
        .map(|(i, _)| {
            let tag = &soap[i..i + soap[i..].find('>').unwrap()];
            let at = tag.find(" Id=\"").unwrap() + 5;
            tag[at..at + tag[at..].find('"').unwrap()].to_string()
        })
        .collect()
}

fn key_id(soap: &str) -> String {
    let at = soap.find("<xenc:EncryptedKey ").unwrap();
    let tag = &soap[at..at + soap[at..].find('>').unwrap()];
    let id = tag.find(" Id=\"").unwrap() + 5;
    tag[id..id + tag[id..].find('"').unwrap()].to_string()
}

/// The byte range of the `n`th `xenc:EncryptedData` element.
fn data_element(soap: &str, n: usize) -> std::ops::Range<usize> {
    let start = soap.match_indices("<xenc:EncryptedData ").nth(n).unwrap().0;
    let end = start + soap[start..].find("</xenc:EncryptedData>").unwrap() + 21;
    start..end
}

fn key_element(soap: &str) -> std::ops::Range<usize> {
    let start = soap.find("<xenc:EncryptedKey ").unwrap();
    let end = start + soap[start..].find("</xenc:EncryptedKey>").unwrap() + 20;
    start..end
}

/// Apply `f` to the `n`th `EncryptedData` element only.
fn in_data(soap: &str, n: usize, f: impl FnOnce(&str) -> String) -> String {
    let r = data_element(soap, n);
    format!(
        "{}{}{}",
        &soap[..r.start],
        f(&soap[r.clone()]),
        &soap[r.end..]
    )
}

fn in_key(soap: &str, f: impl FnOnce(&str) -> String) -> String {
    let r = key_element(soap);
    format!(
        "{}{}{}",
        &soap[..r.start],
        f(&soap[r.clone()]),
        &soap[r.end..]
    )
}

// ── The control ──────────────────────────────────────────────────────────────

#[tokio::test]
async fn genuine_message_decrypts_with_one_key_operation() {
    for preset in [Preset::Bdew, Preset::Edelivery] {
        let g = genuine2(preset).await;
        let r = counted(&g);
        let answer = r.post(g.with_parts(&g.parts())).await;
        assert!(answer.is_receipt(), "{preset:?}: {answer:?}");
        assert_eq!(r.decrypts(), 1, "{preset:?}: one key operation per message");
        assert_eq!(r.calls.load(Ordering::SeqCst), 1);
    }
}

// ── No key operation for a sender that cannot authenticate ─────────────────

#[tokio::test]
async fn unauthenticated_message_makes_no_key_operation() {
    let g = bdew2().await;
    let r = counted(&g);
    // A flipped SignatureValue byte.
    let answer = r
        .post(g.mutated(|s| {
            let at = s.find("<ds:SignatureValue>").unwrap() + "<ds:SignatureValue>".len();
            let mut bytes = s.into_bytes();
            bytes[at + 4] = if bytes[at + 4] == b'A' { b'B' } else { b'A' };
            String::from_utf8(bytes).unwrap()
        }))
        .await;
    r.assert_pre_key(&answer, "EBMS:0101");
    // The same envelope re-signed by a stranger's key.
    let stranger = g.pair.ca.bdew_party("9900000000009");
    let attachments = g.plaintext_attachments();
    let forged = inbound_harness::resign(&g.soap(), &attachments, &stranger.signing);
    let answer = r.post(g.with_soap(&forged)).await;
    r.assert_pre_key(&answer, "EBMS:0101");
}

/// A same-document digest failure (a changed `eb:Messaging`) is refused
/// before any key is used.
#[tokio::test]
async fn messaging_digest_failure_is_pre_key() {
    let g = bdew2().await;
    let r = counted(&g);
    let answer = r
        .post(g.mutated(|s| {
            s.replacen("<ebms:Service", "<ebms:Service ", 1).replacen(
                "communication/services/MP<",
                "communication/services/FP<",
                1,
            )
        }))
        .await;
    r.assert_pre_key(&answer, "EBMS:0101");
}

// ── The envelope structure ───────────────────────────────────────────────────

#[tokio::test]
async fn two_encrypted_data_for_one_cid() {
    let g = bdew2().await;
    let r = counted(&g);
    let soap = g.soap();
    let first_cid = {
        let d = &soap[data_element(&soap, 0)];
        let at = d.find("URI=\"cid:").unwrap() + 5;
        d[at..at + d[at..].find('"').unwrap()].to_string()
    };
    let answer = r
        .post(g.mutated(|s| {
            in_data(&s, 1, |d| {
                let at = d.find("URI=\"cid:").unwrap() + 5;
                let end = at + d[at..].find('"').unwrap();
                format!("{}{}{}", &d[..at], first_cid, &d[end..])
            })
        }))
        .await;
    r.assert_pre_key(&answer, "EBMS:0004");
}

#[tokio::test]
async fn dangling_data_reference() {
    let g = bdew2().await;
    let r = counted(&g);
    let id = data_ids(&g.soap())[0].clone();
    let answer = r
        .post(g.mutated(|s| s.replacen(&format!("URI=\"#{id}\""), "URI=\"#nowhere\"", 1)))
        .await;
    r.assert_pre_key(&answer, "EBMS:0004");
}

#[tokio::test]
async fn data_reference_to_a_duplicate_id() {
    let g = bdew2().await;
    let r = counted(&g);
    let id = data_ids(&g.soap())[0].clone();
    let answer = r
        .post(g.mutated(|s| s.replacen("wsu:Id=\"Timestamp\"", &format!("wsu:Id=\"{id}\""), 1)))
        .await;
    r.assert_pre_key(&answer, "EBMS:0004");
}

#[tokio::test]
async fn orphan_encrypted_data() {
    let g = bdew2().await;
    let r = counted(&g);
    let id = data_ids(&g.soap())[1].clone();
    let answer = r
        .post(g.mutated(|s| s.replacen(&format!("<xenc:DataReference URI=\"#{id}\"/>"), "", 1)))
        .await;
    r.assert_pre_key(&answer, "EBMS:0004");
}

#[tokio::test]
async fn encrypted_data_named_twice() {
    let g = bdew2().await;
    let r = counted(&g);
    let id = data_ids(&g.soap())[0].clone();
    let reference = format!("<xenc:DataReference URI=\"#{id}\"/>");
    let answer = r
        .post(g.mutated(|s| s.replacen(&reference, &format!("{reference}{reference}"), 1)))
        .await;
    r.assert_pre_key(&answer, "EBMS:0004");
}

#[tokio::test]
async fn key_info_naming_another_key() {
    let g = bdew2().await;
    let r = counted(&g);
    let key = key_id(&g.soap());
    let answer = r
        .post(g.mutated(|s| {
            in_data(&s, 0, |d| {
                d.replace(&format!("URI=\"#{key}\""), "URI=\"#EK-other\"")
            })
        }))
        .await;
    r.assert_pre_key(&answer, "EBMS:0004");
}

#[tokio::test]
async fn cipher_reference_not_a_declared_cid() {
    let g = bdew2().await;
    for replacement in [
        "URI=\"http://attacker.example/part\"",
        "URI=\"cid:undeclared@x\"",
    ] {
        let r = counted(&g);
        let answer = r
            .post(g.mutated(|s| {
                in_data(&s, 0, |d| {
                    let at = d.find("URI=\"cid:").unwrap();
                    let end = at + 5 + d[at + 5..].find('"').unwrap() + 1;
                    format!("{}{replacement}{}", &d[..at], &d[end..])
                })
            }))
            .await;
        r.assert_pre_key(&answer, "EBMS:0004");
    }
}

#[tokio::test]
async fn type_other_than_content_only() {
    let g = bdew2().await;
    let content_only = "#Attachment-Content-Only\"";
    for replacement in ["#Attachment-Complete\"", "#Element\"", "#Content\""] {
        let r = counted(&g);
        let answer = r
            .post(g.mutated(|s| in_data(&s, 0, |d| d.replace(content_only, replacement))))
            .await;
        r.assert_pre_key(&answer, "EBMS:0004");
    }
    // Absent.
    let r = counted(&g);
    let answer = r
        .post(g.mutated(|s| {
            in_data(&s, 0, |d| {
                let at = d.find(" Type=\"").unwrap();
                let end = at + 7 + d[at + 7..].find('"').unwrap() + 1;
                format!("{}{}", &d[..at], &d[end..])
            })
        }))
        .await;
    r.assert_pre_key(&answer, "EBMS:0004");
}

#[tokio::test]
async fn transform_list_not_exactly_the_ciphertext_transform() {
    let g = bdew2().await;
    let transform = "#Attachment-Ciphertext-Transform\"/>";
    for replacement in [
        "#Attachment-Content-Signature-Transform\"/>".to_string(),
        format!("{transform}<ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>"),
    ] {
        let r = counted(&g);
        let answer = r
            .post(g.mutated(|s| in_data(&s, 0, |d| d.replace(transform, &replacement))))
            .await;
        r.assert_pre_key(&answer, "EBMS:0004");
    }
}

#[tokio::test]
async fn inline_cipher_value_on_an_attachment() {
    let g = bdew2().await;
    let r = counted(&g);
    let answer = r
        .post(g.mutated(|s| {
            in_data(&s, 0, |d| {
                let at = d.find("<xenc:CipherReference").unwrap();
                let end = d.find("</xenc:CipherReference>").unwrap() + 23;
                format!(
                    "{}<xenc:CipherValue>AAAA</xenc:CipherValue>{}",
                    &d[..at],
                    &d[end..]
                )
            })
        }))
        .await;
    r.assert_pre_key(&answer, "EBMS:0004");
}

#[tokio::test]
async fn xenc_outside_the_security_header() {
    let g = bdew2().await;
    for stray in [
        "<wsse11:EncryptedHeader xmlns:wsse11=\"http://docs.oasis-open.org/wss/oasis-wss-wssecurity-secext-1.1.xsd\"/>",
        "<xenc:EncryptedData xmlns:xenc=\"http://www.w3.org/2001/04/xmlenc#\" Id=\"stray\"/>",
    ] {
        let r = counted(&g);
        let answer = r
            .post(g.mutated(|s| inbound_harness::header_last(&s, stray)))
            .await;
        r.assert_pre_key(&answer, "EBMS:0004");
    }
}

#[tokio::test]
async fn second_encrypted_key() {
    let g = bdew2().await;
    let r = counted(&g);
    let answer = r
        .post(g.mutated(|s| {
            let k = key_element(&s);
            let copy = s[k.clone()].replacen(" Id=\"", " Id=\"x", 1);
            format!("{}{}{}", &s[..k.end], copy, &s[k.end..])
        }))
        .await;
    r.assert_pre_key(&answer, "EBMS:0004");
}

#[tokio::test]
async fn encrypted_key_with_two_different_ids() {
    let g = bdew2().await;
    let r = counted(&g);
    let answer = r
        .post(g.mutated(|s| {
            in_key(&s, |k| {
                k.replacen(
                    " Id=\"",
                    " xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\" wsu:Id=\"other\" Id=\"",
                    1,
                )
            })
        }))
        .await;
    r.assert_pre_key(&answer, "EBMS:0004");
    assert!(answer.description().contains("wsu:Id"), "{answer:?}");
}

// ── The payload set is the signed eb:PartInfo set ───────────────────────────

#[tokio::test]
async fn undeclared_mime_part_is_refused() {
    let g = bdew2().await;
    let r = counted(&g);
    let mut parts = g.parts();
    parts.push(Part {
        headers: "Content-Type: application/octet-stream\r\nContent-ID: <extra@attacker>"
            .to_string(),
        body: b"smuggled".to_vec(),
    });
    let answer = r.post(g.with_parts(&parts)).await;
    r.assert_pre_key(&answer, "EBMS:0004");
}

#[tokio::test]
async fn declared_part_missing_is_refused() {
    let g = bdew2().await;
    let r = counted(&g);
    let mut parts = g.parts();
    parts.pop();
    let answer = r.post(g.with_parts(&parts)).await;
    r.assert_pre_key(&answer, "EBMS:0004");
}

// ── The partner's suite, before any unwrap ──────────────────────────────────

#[tokio::test]
async fn suite_outside_partner_set_is_rejected_before_unwrap() {
    // aes256-gcm under bdew().
    let g = bdew2().await;
    let r = counted(&g);
    let answer = r
        .post(g.mutated(|s| {
            in_data(&s, 0, |d| {
                d.replace("xmlenc11#aes128-gcm", "xmlenc11#aes256-gcm")
            })
        }))
        .await;
    r.assert_pre_key(&answer, "EBMS:0103");
    // rsa-oaep-mgf1p (XML Encryption 1.0) under edelivery_1_15().
    let g = genuine2(Preset::Edelivery).await;
    let r = counted(&g);
    let answer = r
        .post(g.mutated(|s| {
            in_key(&s, |k| {
                k.replace(
                    "http://www.w3.org/2009/xmlenc11#rsa-oaep",
                    "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p",
                )
            })
        }))
        .await;
    r.assert_pre_key(&answer, "EBMS:0103");
}

// ── Every declared part is encrypted ─────────────────────────────────────────

#[tokio::test]
async fn part_without_encrypted_data() {
    let g = bdew2().await;
    let r = counted(&g);
    let id = data_ids(&g.soap())[1].clone();
    let answer = r
        .post(g.mutated(|s| {
            let s = s.replacen(&format!("<xenc:DataReference URI=\"#{id}\"/>"), "", 1);
            let d = data_element(&s, 1);
            format!("{}{}", &s[..d.start], &s[d.end..])
        }))
        .await;
    r.assert_pre_key(&answer, "EBMS:0103");
}

/// A plaintext business document that mentions `<xenc:EncryptedData` is not
/// "decrypted": with no header envelope it is refused as unencrypted.
#[tokio::test]
async fn plaintext_xml_mentioning_encrypted_data_is_refused() {
    let g = bdew2().await;
    let r = counted(&g);
    let soap = g.soap();
    let k = key_element(&soap);
    let last = data_element(&soap, 1);
    let stripped = format!("{}{}", &soap[..k.start], &soap[last.end..]);
    let mut parts = g.parts();
    parts[0].body = format!("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n{stripped}").into_bytes();
    for part in &mut parts[1..] {
        part.body = b"<Invoice><xenc:EncryptedData xmlns:xenc=\"http://www.w3.org/2001/04/xmlenc#\"/></Invoice>".to_vec();
    }
    let answer = r.post(g.with_parts(&parts)).await;
    r.assert_pre_key(&answer, "EBMS:0103");
}

// ── The restored type agrees with CompressionType ───────────────────────────

#[tokio::test]
async fn mime_type_contradicting_compression() {
    let g = bdew2().await;
    let r = counted(&g);
    let answer = r
        .post(g.mutated(|s| {
            in_data(&s, 0, |d| {
                d.replace(
                    "MimeType=\"application/gzip\"",
                    "MimeType=\"application/xml\"",
                )
            })
        }))
        .await;
    r.assert_pre_key(&answer, "EBMS:0004");
}

// ── After the key: one uniform EBMS:0102 ─────────────────────────────────────

/// A reference matching no decrypter makes no key operation and is answered
/// exactly like a tag failure.
#[tokio::test]
async fn one_identical_decryption_failure() {
    let g = bdew2().await;
    let r = counted(&g);
    let no_match = r
        .post(g.mutated(|s| {
            in_key(&s, |k| {
                let at = k.find("X509SubjectKeyIdentifier\">").unwrap() + 26;
                let end = at + k[at..].find('<').unwrap();
                format!("{}AAAAAAAAAAAAAAAAAAAAAAAAAAA={}", &k[..at], &k[end..])
            })
        }))
        .await;
    no_match.assert_refused("EBMS:0102");
    assert_eq!(r.decrypts(), 0, "no decrypter matches: none is called");

    let r = counted(&g);
    let mut parts = g.parts();
    let last = parts.last_mut().unwrap();
    let n = last.body.len();
    last.body[n - 1] ^= 0x01;
    let tag = r.post(g.with_parts(&parts)).await;
    tag.assert_refused("EBMS:0102");
    assert_eq!(r.calls.load(Ordering::SeqCst), 0);
    assert_eq!(no_match.description(), tag.description(), "one fixed text");
    assert_eq!(tag.description(), "decryption failed");
}

/// A `cid:` digest that does not match the decrypted bytes.
#[tokio::test]
async fn cid_digest_mismatch_over_the_decrypted_bytes() {
    let g = bdew2().await;
    let r = counted(&g);
    let mut attachments = g.plaintext_attachments();
    attachments[0].1.push(0);
    let soap = inbound_harness::resign(&g.soap(), &attachments, &g.pair.a.signing);
    let answer = r.post(g.with_soap(&soap)).await;
    answer.assert_refused("EBMS:0101");
    assert_eq!(r.calls.load(Ordering::SeqCst), 0);
}

// ── Selection by reference among several decrypters ─────────────────────────

#[tokio::test]
async fn second_decrypter_selected_by_reference() {
    let g = bdew2().await;
    let older = g.pair.ca.bdew_party("9900000000002");
    let r = counted_with(&g, &[&older.encryption, &g.pair.b.encryption]);
    let answer = r.post(g.with_parts(&g.parts())).await;
    assert!(answer.is_receipt(), "{answer:?}");
    assert_eq!(r.keys[0].decrypts(), 0, "the first decrypter is not tried");
    assert_eq!(r.keys[1].decrypts(), 1);
}

/// Two decrypters a reference could both select are refused when the
/// client is built, so inbound selection is never ambiguous; a reference
/// matching none is answered like a tag failure.
#[tokio::test]
async fn ambiguous_reference_refused() {
    let g = bdew2().await;
    let b = &g.pair.b;
    let err = As4::builder(g.pair.preset.profile())
        .local(
            LocalParty::new(&b.id)
                .party_type(b.party_type.clone().unwrap())
                .signer(b.signing.key_pair())
                .decrypter(CountingKeys::new(&b.encryption))
                .decrypter(CountingKeys::new(&b.encryption)),
        )
        .trust_anchor(g.pair.ca.anchor())
        .partner(g.pair.a.partner(A_URL))
        .http_client(g.pair.loopback.clone())
        .build()
        .expect_err("an ambiguous key reference is refused at build()");
    assert!(err.to_string().contains("ambiguous"), "{err}");
}

// ── phase4 shape: a standalone ReferenceList (WSS 1.1 §9.3) ─────────────────

/// phase4/WSS4J (BDEW, ECDH-ES) puts the `xenc:ReferenceList` directly in
/// `wsse:Security` instead of inside the `EncryptedKey`: both are legal
/// (WSS SOAP Message Security 1.1 §9.3); accepted.
#[tokio::test]
async fn standalone_reference_list_is_accepted() {
    let g = bdew2().await;
    let r = counted(&g);
    let answer = r
        .post(g.mutated(|s| {
            let at = s.find("<xenc:ReferenceList>").unwrap();
            let end = s.find("</xenc:ReferenceList>").unwrap() + 21;
            let list = s[at..end].replace(
                "<xenc:ReferenceList>",
                "<xenc:ReferenceList xmlns:xenc=\"http://www.w3.org/2001/04/xmlenc#\">",
            );
            let without = format!("{}{}", &s[..at], &s[end..]);
            let k = key_element(&without);
            format!("{}{}{}", &without[..k.end], list, &without[k.end..])
        }))
        .await;
    assert!(answer.is_receipt(), "{answer:?}");
    assert_eq!(r.decrypts(), 1);
}

/// Each `EncryptedData` is still named exactly once across both lists.
#[tokio::test]
async fn encrypted_data_named_in_two_reference_lists_is_refused() {
    let g = bdew2().await;
    let r = counted(&g);
    let answer = r
        .post(g.mutated(|s| {
            let at = s.find("<xenc:ReferenceList>").unwrap();
            let end = s.find("</xenc:ReferenceList>").unwrap() + 21;
            let list = s[at..end].replace(
                "<xenc:ReferenceList>",
                "<xenc:ReferenceList xmlns:xenc=\"http://www.w3.org/2001/04/xmlenc#\">",
            );
            let k = key_element(&s);
            format!("{}{}{}", &s[..k.end], list, &s[k.end..])
        }))
        .await;
    r.assert_pre_key(&answer, "EBMS:0004");
}
