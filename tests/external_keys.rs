//! Keys behind the async `Signer`/`Decrypter` seams: one private-key operation per signature and per decryption, key
//! rollover by reference, a failing signer is `Backend` — for AS4 and AS2 —
//! and no in-memory private key is taken out of a `LocalParty`.

#[cfg(feature = "as4")]
#[path = "common/peers.rs"]
mod peers;

#[cfg(feature = "as2")]
#[path = "common/as2_peers.rs"]
mod as2_peers;

#[cfg(feature = "as4")]
mod as4 {
    use super::peers::{A_URL, B_URL, MP, Preset};
    use asx::as4::{As4, UserMessage};
    use asx::{ErrorKind, LocalParty, MemoryDedup, Profile, Reject, Verified};
    use asx_testkit::keys::CountingKeys;
    use asx_testkit::loopback::Loopback;
    use asx_testkit::pki::{TestCa, TestParty};

    fn local(party: &TestParty, signer: &CountingKeys, decrypters: &[CountingKeys]) -> LocalParty {
        let mut local = LocalParty::new(&party.id)
            .party_type(asx_testkit::pki::BDEW_PARTY_TYPE)
            .signer(signer.clone());
        for d in decrypters {
            local = local.decrypter(d.clone());
        }
        local
    }

    struct Setup {
        sender: As4,
        to_b: asx::Partner,
        a_sign: CountingKeys,
        b_sign: CountingKeys,
        b_enc: Vec<CountingKeys>,
        loopback: Loopback,
    }

    /// `b` holds `extra` additional decryption keys; `a` encrypts to `b_enc_for`.
    fn setup(extra: usize, encrypt_to_last: bool) -> Setup {
        let ca = TestCa::sm_pki();
        let a = ca.bdew_party("9900000000001");
        let b = ca.bdew_party("9900000000002");
        let mut b_keys = vec![b.encryption.clone()];
        for i in 0..extra {
            b_keys.push(ca.issue_named(
                &[
                    (asx_testkit::pki::Nid::COMMONNAME, &format!("b enc {i}")),
                    (
                        asx_testkit::pki::Nid::ORGANIZATIONALUNITNAME,
                        "9900000000002",
                    ),
                ],
                asx_testkit::pki::KeyAlg::EcBrainpoolP256r1,
            ));
        }
        let a_sign = CountingKeys::new(&a.signing);
        let a_enc = CountingKeys::new(&a.encryption);
        let b_sign = CountingKeys::new(&b.signing);
        let b_enc: Vec<CountingKeys> = b_keys.iter().map(CountingKeys::new).collect();
        let target = if encrypt_to_last {
            b_keys.last().unwrap()
        } else {
            &b_keys[0]
        };
        let to_b = asx::Partner::new(&b.id)
            .party_type(asx_testkit::pki::BDEW_PARTY_TYPE)
            .endpoint(B_URL)
            .signing_cert(b.signing.certificate())
            .encryption_cert(target.certificate());
        let loopback = Loopback::new();
        let sender = As4::builder(Profile::bdew())
            .local(local(&a, &a_sign, &[a_enc]))
            .trust_anchor(ca.anchor())
            .partner(to_b.clone())
            .http_client(loopback.clone())
            .build()
            .unwrap();
        let receiver = As4::builder(Profile::bdew())
            .local(local(&b, &b_sign, &b_enc))
            .trust_anchor(ca.anchor())
            .partner(a.partner(A_URL))
            .http_client(loopback.clone())
            .build()
            .unwrap();
        loopback.mount(
            B_URL,
            receiver.inbound(MemoryDedup::default(), |_m: Verified<UserMessage>| async {
                Ok::<(), Reject>(())
            }),
        );
        Setup {
            sender,
            to_b,
            a_sign,
            b_sign,
            b_enc,
            loopback,
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn one_key_operation_per_signature_and_decryption() {
        let s = setup(0, false);
        s.sender
            .send(Preset::Bdew.message(&s.to_b, b"through the HSM"))
            .await
            .expect("delivered with external keys");
        assert_eq!(s.a_sign.signs(), 1, "one signature per message");
        assert_eq!(s.b_sign.signs(), 1, "one signature per receipt");
        assert_eq!(
            s.b_enc[0].decrypts(),
            1,
            "one decryption per encrypted message"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn rollover_selects_the_referenced_key() {
        let s = setup(1, true);
        s.sender
            .send(Preset::Bdew.message(&s.to_b, b"to the new key"))
            .await
            .expect("delivered to the second key");
        assert_eq!(s.b_enc[0].decrypts(), 0, "no trial decryption");
        assert_eq!(s.b_enc[1].decrypts(), 1);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn failing_signer_is_backend_and_nothing_is_sent() {
        let s = setup(0, false);
        s.a_sign.fail();
        let err = s
            .sender
            .send(
                asx::as4::Message::to(&s.to_b)
                    .service(MP)
                    .payload(asx::Payload::new(&b"x"[..], "application/octet-stream")),
            )
            .await
            .expect_err("signer down");
        assert_eq!(err.kind(), ErrorKind::Backend, "{err}");
        assert!(err.is_retryable());
        assert_eq!(s.loopback.requests(), 0);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn failing_decrypter_is_the_uniform_decryption_error() {
        let s = setup(0, false);
        s.b_enc[0].fail();
        let err = s
            .sender
            .send(Preset::Bdew.message(&s.to_b, b"x"))
            .await
            .expect_err("decrypter down");
        assert_eq!(err.ebms_code(), Some("EBMS:0102"), "{err}");
    }
}

#[cfg(feature = "as2")]
mod as2 {
    use super::as2_peers::{A_ID, A_URL, B_ID, B_URL, Delivered, EDI, handler};
    use asx::as2::{As2, Message};
    use asx::{ErrorKind, LocalParty, MemoryDedup, Partner, Payload, Profile};
    use asx_testkit::keys::CountingKeys;
    use asx_testkit::loopback::Loopback;
    use asx_testkit::pki::{KeyAlg, TestCa};

    struct Setup {
        sender: As2,
        to_b: Partner,
        a_sign: CountingKeys,
        a_enc: CountingKeys,
        b_sign: CountingKeys,
        b_enc: Vec<CountingKeys>,
        loopback: Loopback,
        delivered: Delivered,
    }

    /// `b` holds `extra` additional decryption keys; `a` encrypts to the last
    /// one when `encrypt_to_last`.
    fn setup(extra: usize, encrypt_to_last: bool) -> Setup {
        let ca = TestCa::new("asx-test AS2 external keys", KeyAlg::Rsa2048);
        let (a, b) = (ca.as2_party(A_ID), ca.as2_party(B_ID));
        let mut b_keys = vec![b.encryption.clone()];
        for i in 0..extra {
            b_keys.push(ca.issue(&format!("b enc {i}"), KeyAlg::Rsa2048));
        }
        let a_sign = CountingKeys::new(&a.signing);
        let a_enc = CountingKeys::new(&a.encryption);
        let b_sign = CountingKeys::new(&b.signing);
        let b_enc: Vec<CountingKeys> = b_keys.iter().map(CountingKeys::new).collect();
        let target = if encrypt_to_last {
            b_keys.last().unwrap()
        } else {
            &b_keys[0]
        };
        let to_b = Partner::new(B_ID)
            .endpoint(B_URL)
            .signing_cert(b.signing.certificate())
            .encryption_cert(target.certificate());
        let loopback = Loopback::new();
        let sender = As2::builder(Profile::as2())
            .local(
                LocalParty::new(A_ID)
                    .signer(a_sign.clone())
                    .decrypter(a_enc.clone()),
            )
            .trust_anchor(ca.anchor())
            .partner(to_b.clone())
            .http_client(loopback.clone())
            .build()
            .expect("an external-key AS2 sender builds");
        let mut local = LocalParty::new(B_ID).signer(b_sign.clone());
        for d in &b_enc {
            local = local.decrypter(d.clone());
        }
        let receiver = As2::builder(Profile::as2())
            .local(local)
            .trust_anchor(ca.anchor())
            .partner(a.partner(A_URL))
            .http_client(loopback.clone())
            .build()
            .expect("an external-key AS2 receiver builds");
        let delivered: Delivered = Default::default();
        loopback.mount(
            B_URL,
            receiver.inbound(
                MemoryDedup::default(),
                handler(Default::default(), Default::default(), delivered.clone()),
            ),
        );
        Setup {
            sender,
            to_b,
            a_sign,
            a_enc,
            b_sign,
            b_enc,
            loopback,
            delivered,
        }
    }

    fn message(s: &Setup, body: &[u8]) -> Message {
        Message::to(&s.to_b, Payload::new(body.to_vec(), EDI))
    }

    #[tokio::test(flavor = "current_thread")]
    async fn one_key_operation_per_signature_mdn_and_decryption() {
        let s = setup(0, false);
        s.sender
            .send(message(&s, b"through the HSM"))
            .await
            .expect("delivered with external keys");
        assert_eq!(s.a_sign.signs(), 1, "one signature per message");
        assert_eq!(s.b_sign.signs(), 1, "one signature per MDN");
        assert_eq!(s.b_enc[0].decrypts(), 1, "one decryption per message");
        assert_eq!(s.a_enc.decrypts(), 0, "the MDN is not encrypted");
        assert_eq!(s.delivered.lock().unwrap()[0].2, b"through the HSM");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn rollover_selects_the_referenced_key() {
        let s = setup(1, true);
        s.sender
            .send(message(&s, b"to the new key"))
            .await
            .expect("delivered to the second key");
        assert_eq!(s.b_enc[0].decrypts(), 0, "no trial decryption");
        assert_eq!(s.b_enc[1].decrypts(), 1);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn failing_signer_is_backend_and_nothing_is_sent() {
        let s = setup(0, false);
        s.a_sign.fail();
        let err = s
            .sender
            .send(message(&s, b"x"))
            .await
            .expect_err("signer down");
        assert_eq!(err.kind(), ErrorKind::Backend, "{err}");
        assert!(err.is_retryable());
        assert_eq!(s.loopback.requests(), 0);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn failing_decrypter_is_the_uniform_decryption_failure() {
        let s = setup(0, false);
        s.b_enc[0].fail();
        let err = s
            .sender
            .send(message(&s, b"x"))
            .await
            .expect_err("decrypter down");
        assert_eq!(err.kind(), ErrorKind::PartnerError, "{err}");
        assert!(err.to_string().contains("decryption-failed"), "{err}");
        assert!(s.delivered.lock().unwrap().is_empty());
    }
}

/// No in-memory private key is taken out of a `LocalParty` outside
/// `src/keys.rs`. The PEM accessor serves only the TLS identity, and the AS2
/// sources reach keys through the `Signer`/`Decrypter` traits alone.
#[test]
fn no_private_key_leaves_keys_rs() {
    fn rust_files(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
        for entry in std::fs::read_dir(dir).expect("readable source tree") {
            let path = entry.expect("entry").path();
            if path.is_dir() {
                rust_files(&path, out);
            } else if path.extension().is_some_and(|e| e == "rs") {
                out.push(path);
            }
        }
    }
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    rust_files(&root.join("src"), &mut files);
    assert!(files.len() > 10, "the source tree was found");
    for file in files {
        let rel = file
            .strip_prefix(root)
            .unwrap()
            .to_string_lossy()
            .replace('\\', "/");
        let text = std::fs::read_to_string(&file).expect("utf-8 source");
        if rel != "src/keys.rs" && rel != "src/http_client.rs" {
            assert!(
                !text.contains(".key_pem()"),
                "{rel}: KeyPair::key_pem is for the TLS identity only"
            );
        }
        if rel == "src/as2.rs" || rel.starts_with("src/as2/") {
            for needle in ["key_pem()", "as_key_pair", ".key_pair", "PKey<Private>"] {
                assert!(
                    !text.contains(needle),
                    "{rel}: `{needle}` — AS2 keys go through Signer/Decrypter (T060)"
                );
            }
        }
    }
}
