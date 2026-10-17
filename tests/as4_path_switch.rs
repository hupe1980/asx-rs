#![cfg(feature = "as4")]
//! The BDEW transmission-path-switch service (BDEW AS4-Profil 1.2 §2.2.8,
//! §2.3.7): receive and send.
//!
//! `a` sends through the testkit `Loopback` to an `Inbound` of `b` whose
//! handler records `UserMessage::path_switch()` and whose decrypter counts
//! every private-key operation. Mutated messages are re-signed with `a`'s key
//! (`inbound_harness::resign`), so each refusal is *because of* the mutation.

#[path = "common/inbound_harness.rs"]
mod inbound_harness;
#[path = "common/peers.rs"]
mod peers;

use asx::as4::{As4, Message, PathSwitch, UserMessage};
use asx::testkit::keys::CountingKeys;
use asx::{ErrorKind, LocalParty, MemoryDedup, Partner, Payload, Reject, Verified};
use bytes::Bytes;
use inbound_harness::{Answer, genuine_with, post, request, resign};
use peers::{A_URL, B_URL, Pair, Preset, pair, pair_with};
use std::sync::{Arc, Mutex};

const SERVICE: &str = "https://www.bdew.de/as4/communication/services/pathSwitch";
const REQUEST: &str = "https://www.bdew.de/as4/communication/actions/requestSwitch";
const CONFIRM: &str = "https://www.bdew.de/as4/communication/actions/confirmSwitch";
const AGREEMENT: &str = "https://www.bdew.de/as4/communication/agreement";
const INITIATOR: &str = "http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/initiator";
const RESPONDER: &str = "http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/responder";

/// What `b`'s handler saw of one delivery.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Seen {
    message_id: String,
    from: String,
    service: String,
    action: String,
    conversation_id: String,
    path_switch: Option<PathSwitch>,
    payloads: Vec<Vec<u8>>,
}

impl Seen {
    fn of(m: &UserMessage) -> Seen {
        Seen {
            message_id: m.message_id().to_string(),
            from: m.from().to_string(),
            service: m.service().to_string(),
            action: m.action().to_string(),
            conversation_id: m.conversation_id().to_string(),
            path_switch: m.path_switch(),
            payloads: m.payloads().iter().map(|p| p.bytes().to_vec()).collect(),
        }
    }
}

/// `b` rebuilt with a counting decrypter and a recording handler, mounted
/// at `B_URL` in place of the pair's receiver.
struct Switchboard {
    pair: Pair,
    keys: CountingKeys,
    seen: Arc<Mutex<Vec<Seen>>>,
    inbound: asx::Inbound,
}

impl Switchboard {
    fn new(preset: Preset) -> Switchboard {
        Switchboard::over(pair(preset))
    }

    fn over(pair: Pair) -> Switchboard {
        let b = &pair.b;
        let keys = CountingKeys::new(&b.encryption);
        let mut local = LocalParty::new(&b.id)
            .signer(b.signing.key_pair())
            .decrypter(keys.clone())
            .tls_identity(b.tls.key_pair());
        if let Some(t) = &b.party_type {
            local = local.party_type(t);
        }
        let client = As4::builder(pair.preset.profile())
            .local(local)
            .trust_anchor(pair.ca.anchor())
            .partner(pair.a.partner(A_URL))
            .http_client(pair.loopback.clone())
            .build()
            .expect("b builds");
        let seen = Arc::new(Mutex::new(Vec::new()));
        let inbound = {
            let seen = seen.clone();
            client.inbound(MemoryDedup::default(), move |m: Verified<UserMessage>| {
                let seen = seen.clone();
                async move {
                    seen.lock().unwrap().push(Seen::of(&m));
                    Ok::<(), Reject>(())
                }
            })
        };
        pair.loopback.mount(B_URL, inbound.clone());
        Switchboard {
            pair,
            keys,
            seen,
            inbound,
        }
    }

    fn seen(&self) -> Vec<Seen> {
        self.seen.lock().unwrap().clone()
    }

    /// Send `kind` from `a` to `b`; return the captured request.
    async fn send(&self, kind: PathSwitch) -> http::Request<Bytes> {
        self.pair
            .sender
            .send(Message::path_switch(&self.pair.to_b, kind))
            .await
            .expect("the path-switch message is receipted");
        self.pair.loopback.last_request().expect("captured")
    }

    async fn post(&self, request: http::Request<Bytes>) -> Answer {
        post(&self.inbound, request).await
    }

    /// Refused with `code` for `reason`, never delivered, no key used.
    #[track_caller]
    fn assert_refused(&self, answer: &Answer, code: &str, reason: &str) {
        answer.assert_refused_because(code, reason);
        assert!(self.seen().is_empty(), "not delivered: {:?}", self.seen());
        assert_eq!(self.keys.decrypts(), 0, "no private-key operation");
    }
}

fn soap_of(request: &http::Request<Bytes>) -> String {
    String::from_utf8(request.body().to_vec()).expect("utf8 SOAP")
}

fn content_type(request: &http::Request<Bytes>) -> String {
    request
        .headers()
        .get(http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string()
}

fn plain(soap: &str) -> http::Request<Bytes> {
    request("application/soap+xml; charset=UTF-8", soap.to_string())
}

/// Replace the text of the first `<tag …>…</tag>`.
fn set_text(soap: &str, tag: &str, value: &str) -> String {
    let open = soap.find(&format!("<{tag}")).expect(tag);
    let start = open + soap[open..].find('>').expect("tag end") + 1;
    let end = start + soap[start..].find(&format!("</{tag}>")).expect("close");
    format!("{}{value}{}", &soap[..start], &soap[end..])
}

/// Remove every `<tag …>…</tag>` (not nested).
fn strip(soap: &str, tag: &str, filter: impl Fn(&str) -> bool) -> String {
    let mut out = soap.to_string();
    let mut from = 0;
    while let Some(i) = out[from..].find(&format!("<{tag}")) {
        let start = from + i;
        let close = format!("</{tag}>");
        let end = start + out[start..].find(&close).expect("close") + close.len();
        if filter(&out[start..end]) {
            out.replace_range(start..end, "");
        } else {
            from = end;
        }
    }
    out
}

/// `soap` with Service and Action replaced, signed again by `a`.
fn resigned_with(pair: &Pair, soap: &str, service: &str, action: &str) -> String {
    let soap = set_text(
        &set_text(soap, "ebms:Service", service),
        "ebms:Action",
        action,
    );
    resign(&soap, &[], &pair.a.signing)
}

// ── Send ────────────────────────────────────────────────────────────────────

/// The wire shape of a path-switch message.
#[track_caller]
fn assert_wire_shape(request: &http::Request<Bytes>, action: &str) {
    let ct = content_type(request);
    assert_eq!(
        ct, "application/soap+xml; charset=UTF-8",
        "no MIME multipart"
    );
    let soap = soap_of(request);
    assert!(soap.contains("<soap:Envelope"), "{soap}");
    for literal in [
        format!("<ebms:Service>{SERVICE}</ebms:Service>"),
        format!("<ebms:Action>{action}</ebms:Action>"),
        format!("<ebms:AgreementRef>{AGREEMENT}</ebms:AgreementRef>"),
        format!("<ebms:Role>{INITIATOR}</ebms:Role>"),
        format!("<ebms:Role>{RESPONDER}</ebms:Role>"),
        ">9900000000001</ebms:PartyId>".to_string(),
        ">9900000000002</ebms:PartyId>".to_string(),
    ] {
        assert!(soap.contains(&literal), "{literal} in {soap}");
    }
    assert!(
        soap.contains("<ebms:ConversationId></ebms:ConversationId>")
            || soap.contains("<ebms:ConversationId/>"),
        "empty ConversationId: {soap}"
    );
    for absent in [
        "RefToMessageId",
        "PayloadInfo",
        "PartInfo",
        "MessageProperties",
        "xenc:",
        "EncryptedKey",
        "EncryptedData",
        "cid:",
    ] {
        assert!(!soap.contains(absent), "no {absent}: {soap}");
    }
    // AgreementRef without pmode/type; Service without type.
    assert!(!soap.contains("<ebms:AgreementRef "), "{soap}");
    assert!(!soap.contains("<ebms:Service "), "{soap}");
    // Empty Body.
    let body = &soap[soap.find("<soap:Body").expect("Body")..];
    let body = &body[..body.find("</soap:Envelope>").expect("end")];
    assert!(
        body.trim_end().ends_with("/>") || body.contains("></soap:Body>"),
        "empty SOAP Body: {body}"
    );
    // ECDSA over exactly eb:Messaging and the Body; PKIPath token.
    let uris: Vec<&str> = soap
        .match_indices("<ds:Reference URI=\"")
        .map(|(i, m)| {
            let rest = &soap[i + m.len()..];
            &rest[..rest.find('"').expect("URI end")]
        })
        .collect();
    assert_eq!(uris, ["#as4-messaging", "#as4-body"], "{soap}");
    assert!(
        soap.contains("http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"),
        "{soap}"
    );
    assert!(soap.contains("X509PKIPathv1"), "{soap}");
}

#[tokio::test]
async fn send_request_switch_wire_shape() {
    let board = Switchboard::new(Preset::Bdew);
    let receipt = board
        .pair
        .sender
        .send(Message::path_switch(&board.pair.to_b, PathSwitch::Request))
        .await
        .expect("Ok(Verified<Receipt>)");
    let request = board.pair.loopback.last_request().expect("captured");
    assert_wire_shape(&request, REQUEST);
    assert_eq!(
        receipt.signer().der(),
        board.pair.b.signing.certificate().der()
    );
    assert_eq!(board.pair.loopback.requests(), 1);
}

#[tokio::test]
async fn send_confirm_switch_wire_shape() {
    let board = Switchboard::new(Preset::Bdew);
    let request = board.send(PathSwitch::Confirm).await;
    assert_wire_shape(&request, CONFIRM);
}

/// No encryption certificate is needed; a business message to the same
/// partner still needs one.
#[tokio::test]
async fn send_without_encryption_cert_is_allowed() {
    let pair = pair_with(
        Preset::Bdew,
        |b| {
            Partner::new(&b.id)
                .party_type(b.party_type.as_deref().expect("bdew type"))
                .endpoint(B_URL)
                .signing_cert(b.signing.certificate())
        },
        |a| a.partner(A_URL),
    );
    let board = Switchboard::over(pair);
    let to_b = board.pair.to_b.clone();
    board
        .pair
        .sender
        .send(Message::path_switch(&to_b, PathSwitch::Request))
        .await
        .expect("sent without an encryption certificate");
    assert_eq!(board.seen()[0].path_switch, Some(PathSwitch::Request));
    let err = board
        .pair
        .sender
        .send(Preset::Bdew.message(&to_b, b"business"))
        .await
        .expect_err("a business message needs the certificate");
    assert_eq!(err.kind(), ErrorKind::Config, "{err}");
    assert!(err.to_string().contains("encryption_cert"), "{err}");
    assert_eq!(board.pair.loopback.requests(), 1);
}

/// `Config`, nothing sent.
#[tokio::test]
async fn send_refusals() {
    let board = Switchboard::new(Preset::Bdew);
    let to_b = &board.pair.to_b;
    let request = || Message::path_switch(to_b, PathSwitch::Request);
    for (message, field) in [
        (
            request().payload(Payload::new(b"x".to_vec(), "application/octet-stream")),
            "payload",
        ),
        (request().service(SERVICE), "service"),
        (request().action(REQUEST), "action"),
        (request().conversation_id("c1"), "conversation_id"),
    ] {
        let err = board.pair.sender.send(message).await.expect_err(field);
        assert_eq!(err.kind(), ErrorKind::Config, "{field}: {err}");
        assert!(err.to_string().contains(field), "{err}");
    }
    assert_eq!(board.pair.loopback.requests(), 0, "nothing sent");

    for preset in [Preset::Peppol, Preset::Edelivery, Preset::Entsog] {
        let pair = pair(preset);
        for kind in [PathSwitch::Request, PathSwitch::Confirm] {
            let err = pair
                .sender
                .send(Message::path_switch(&pair.to_b, kind))
                .await
                .expect_err("only BDEW has the service");
            assert_eq!(err.kind(), ErrorKind::Config, "{preset:?}: {err}");
            assert!(err.to_string().contains("§2.3.7"), "{preset:?}: {err}");
        }
        assert_eq!(pair.loopback.requests(), 0, "{preset:?}: nothing sent");
    }
}

// ── Receive ─────────────────────────────────────────────────────────────────

/// A request and a confirmation are each delivered once, classified and never
/// decrypted; a duplicate gets a fresh receipt.
#[tokio::test]
async fn receive_request_and_confirm_in_the_handler() {
    let board = Switchboard::new(Preset::Bdew);
    for (kind, action) in [
        (PathSwitch::Request, REQUEST),
        (PathSwitch::Confirm, CONFIRM),
    ] {
        board.seen.lock().unwrap().clear();
        let request = board.send(kind).await;
        let seen = board.seen();
        assert_eq!(seen.len(), 1, "{seen:?}");
        let seen = &seen[0];
        assert_eq!(seen.path_switch, Some(kind));
        assert!(seen.payloads.is_empty());
        assert_eq!(seen.from, board.pair.a.id);
        assert_eq!(seen.service, SERVICE);
        assert_eq!(seen.action, action);
        assert_eq!(seen.conversation_id, "");

        // The same message again → a fresh receipt, no delivery.
        let again = board.post(request).await;
        assert!(again.is_receipt(), "{again:?}");
        assert_eq!(board.seen().len(), 1, "duplicate not delivered");
    }
    assert_eq!(board.keys.decrypts(), 0, "nothing was decrypted");
}

/// The round trip: the confirmation is sent by the application from a task
/// the handler spawns (the documented pattern).
#[tokio::test]
async fn request_is_confirmed_by_the_handler() {
    let pair = pair(Preset::Bdew);
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<Seen>();
    // `a`'s endpoint: records the confirmation.
    pair.loopback.mount(
        A_URL,
        pair.sender
            .inbound(MemoryDedup::default(), move |m: Verified<UserMessage>| {
                let tx = tx.clone();
                async move {
                    tx.send(Seen::of(&m)).expect("test alive");
                    Ok::<(), Reject>(())
                }
            }),
    );
    // `b`'s endpoint: answers a request with a confirmation.
    let b = pair.receiver.clone();
    let a_partner = pair.a.partner(A_URL);
    let (done_tx, mut done_rx) = tokio::sync::mpsc::unbounded_channel();
    pair.loopback.mount(
        B_URL,
        pair.receiver
            .inbound(MemoryDedup::default(), move |m: Verified<UserMessage>| {
                let (b, a_partner, done_tx) = (b.clone(), a_partner.clone(), done_tx.clone());
                async move {
                    if m.path_switch() == Some(PathSwitch::Request) {
                        tokio::spawn(async move {
                            let sent = b
                                .send(Message::path_switch(&a_partner, PathSwitch::Confirm))
                                .await;
                            done_tx.send(sent.map(drop)).expect("test alive");
                        });
                    }
                    Ok::<(), Reject>(())
                }
            }),
    );
    pair.sender
        .send(Message::path_switch(&pair.to_b, PathSwitch::Request))
        .await
        .expect("request receipted");
    done_rx
        .recv()
        .await
        .expect("confirmation attempted")
        .expect("confirmation receipted");
    let confirm = rx.recv().await.expect("confirmation delivered");
    assert_eq!(confirm.path_switch, Some(PathSwitch::Confirm));
    assert_eq!(confirm.action, CONFIRM);
    assert_eq!(confirm.from, pair.b.id);
    assert!(confirm.payloads.is_empty());
}

/// A request in the MIME form: `multipart/related` with only the SOAP root.
#[tokio::test]
async fn root_only_multipart_is_the_same_message() {
    let board = Switchboard::new(Preset::Bdew);
    let captured = soap_of(&board.send(PathSwitch::Request).await);
    board.seen.lock().unwrap().clear();
    let boundary = "asx-root-only";
    let root = |id: &str| {
        let soap = set_text(&captured, "ebms:MessageId", id);
        let soap = resign(&soap, &[], &board.pair.a.signing);
        format!(
            "--{boundary}\r\nContent-Type: application/soap+xml; charset=UTF-8\r\n\
             Content-ID: <root@asx>\r\n\r\n{soap}\r\n"
        )
    };
    let body = format!("{}--{boundary}--\r\n", root("root1@asx"));
    let answer = board.post(request_multipart(boundary, body)).await;
    assert!(answer.is_receipt(), "{answer:?}");
    let seen = board.seen();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].path_switch, Some(PathSwitch::Request));
    board.seen.lock().unwrap().clear();

    // Any non-root part makes it a message with payload: undeclared → refused.
    let body = format!(
        "{}--{boundary}\r\nContent-Type: application/octet-stream\r\n\
         Content-ID: <extra@asx>\r\n\r\nx\r\n--{boundary}--\r\n",
        root("root2@asx")
    );
    let answer = board.post(request_multipart(boundary, body)).await;
    board.assert_refused(&answer, "EBMS:0004", "not declared by eb:PartInfo");
}

fn request_multipart(boundary: &str, body: String) -> http::Request<Bytes> {
    request(
        &format!(
            "multipart/related; boundary=\"{boundary}\"; type=\"application/soap+xml\"; \
             start=\"<root@asx>\""
        ),
        body,
    )
}

/// Both URIs must match exactly; otherwise a payload-less message is refused
/// as one without payload.
#[tokio::test]
async fn non_pair_payload_less_messages_are_refused() {
    let board = Switchboard::new(Preset::Bdew);
    let captured = soap_of(&board.send(PathSwitch::Request).await);
    board.seen.lock().unwrap().clear();
    for (service, action) in [
        (
            SERVICE,
            "https://www.bdew.de/as4/communication/actions/requestSwitchX",
        ),
        (
            SERVICE,
            "http://docs.oasis-open.org/ebxml-msg/as4/200902/action",
        ),
        ("https://www.bdew.de/as4/communication/services/MP", REQUEST),
        (
            "https://www.bdew.de/as4/communication/services/pathswitch",
            CONFIRM,
        ),
    ] {
        // A fresh message id each time so dedup never answers.
        let soap = set_text(
            &captured,
            "ebms:MessageId",
            &format!("{}@asx", action.len() + service.len()),
        );
        let soap = resigned_with(&board.pair, &soap, service, action);
        let answer = board.post(plain(&soap)).await;
        board.assert_refused(
            &answer,
            "EBMS:0103",
            "must be multipart/related with a detached payload attachment",
        );
    }
}

/// The payload exemption never relaxes a security check.
#[tokio::test]
async fn security_failures_are_refused_before_the_handler() {
    let board = Switchboard::new(Preset::Bdew);
    let captured = soap_of(&board.send(PathSwitch::Request).await);
    board.seen.lock().unwrap().clear();
    let fresh = |soap: &str, n: u32| set_text(soap, "ebms:MessageId", &format!("sec{n}@asx"));

    // A broken signature: signed header changed, not re-signed.
    let tampered = fresh(&captured, 1);
    let answer = board.post(plain(&tampered)).await;
    board.assert_refused(&answer, "EBMS:0101", "");

    // The signer's subject does not carry the claimed MP-ID.
    let claimed = resign(
        &fresh(&captured, 2).replace(
            &format!(">{}</ebms:PartyId>", board.pair.a.id),
            ">9900000000099</ebms:PartyId>",
        ),
        &[],
        &board.pair.a.signing,
    );
    let answer = board.post(plain(&claimed)).await;
    board.assert_refused(&answer, "EBMS:0101", "MP-ID");

    // Unsigned (the security header without a signature).
    let unsigned = strip(&fresh(&captured, 3), "ds:Signature", |_| true);
    let answer = board.post(plain(&unsigned)).await;
    board.assert_refused(
        &answer,
        "EBMS:0103",
        "signature is required but not present",
    );
}

/// Encryption structures in a payload-less switch → EBMS:0103 before
/// any private-key operation.
#[tokio::test]
async fn encryption_structures_are_refused_before_any_key_operation() {
    let board = Switchboard::new(Preset::Bdew);
    let captured = soap_of(&board.send(PathSwitch::Request).await);
    board.seen.lock().unwrap().clear();
    const XENC: &str = "http://www.w3.org/2001/04/xmlenc#";

    // An EncryptedKey in wsse:Security (outside every signed subtree).
    let key = format!(
        "<xenc:EncryptedKey xmlns:xenc=\"{XENC}\" Id=\"EK-1\"><xenc:EncryptionMethod \
         Algorithm=\"http://www.w3.org/2001/04/xmlenc#kw-aes128\"/><xenc:CipherData>\
         <xenc:CipherValue>AAAA</xenc:CipherValue></xenc:CipherData></xenc:EncryptedKey>"
    );
    let with_key = set_text(&captured, "ebms:MessageId", "enc1@asx");
    let with_key = resign(&with_key, &[], &board.pair.a.signing);
    let at = with_key.find("<wsse:Security").expect("Security");
    let at = at + with_key[at..].find('>').expect(">") + 1;
    let with_key = format!("{}{key}{}", &with_key[..at], &with_key[at..]);
    let answer = board.post(plain(&with_key)).await;
    board.assert_refused(&answer, "EBMS:0103", "xenc:EncryptedKey");

    // EncryptedData over the Body (the Body is signed: re-sign).
    let data = format!(
        "<xenc:EncryptedData xmlns:xenc=\"{XENC}\" Id=\"ED-1\" \
         Type=\"http://www.w3.org/2001/04/xmlenc#Content\"><xenc:EncryptionMethod \
         Algorithm=\"http://www.w3.org/2009/xmlenc11#aes128-gcm\"/><xenc:CipherData>\
         <xenc:CipherValue>AAAA</xenc:CipherValue></xenc:CipherData></xenc:EncryptedData>"
    );
    let soap = set_text(&captured, "ebms:MessageId", "enc2@asx");
    let body_open = soap.find("<soap:Body").expect("Body");
    let body_end = body_open + soap[body_open..].find("/>").expect("empty Body");
    let soap = format!(
        "{}>{data}</soap:Body>{}",
        &soap[..body_end],
        &soap[body_end + 2..]
    );
    let soap = resign(&soap, &[], &board.pair.a.signing);
    let answer = board.post(plain(&soap)).await;
    board.assert_refused(&answer, "EBMS:0103", "xenc:EncryptedData");
}

/// A payload-less switch with a non-empty Body is refused.
#[tokio::test]
async fn non_empty_body_is_refused() {
    let board = Switchboard::new(Preset::Bdew);
    let captured = soap_of(&board.send(PathSwitch::Request).await);
    board.seen.lock().unwrap().clear();
    let soap = set_text(&captured, "ebms:MessageId", "body1@asx");
    let body_open = soap.find("<soap:Body").expect("Body");
    let body_end = body_open + soap[body_open..].find("/>").expect("empty Body");
    let soap = format!(
        "{}><x:doc xmlns:x=\"urn:x\">payload</x:doc></soap:Body>{}",
        &soap[..body_end],
        &soap[body_end + 2..]
    );
    let soap = resign(&soap, &[], &board.pair.a.signing);
    let answer = board.post(plain(&soap)).await;
    board.assert_refused(&answer, "EBMS:0004", "empty SOAP Body");
}

/// A switch with a payload part gets the full payload rules
/// (encrypted, compressed, digest-verified) and `path_switch()` set.
#[tokio::test]
async fn switch_with_a_payload_is_delivered_with_its_payload() {
    let g = genuine_with(pair(Preset::Bdew), b"switch-with-payload").await;
    let request = g.resigned(|soap| {
        set_text(
            &set_text(&soap, "ebms:Service", SERVICE),
            "ebms:Action",
            REQUEST,
        )
    });
    let board = Switchboard::over(g.pair);
    let answer = board.post(request).await;
    assert!(answer.is_receipt(), "{answer:?}");
    let seen = board.seen();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].path_switch, Some(PathSwitch::Request));
    assert_eq!(seen[0].payloads, vec![b"switch-with-payload".to_vec()]);
    assert_eq!(board.keys.decrypts(), 1, "the payload was decrypted");
}

/// The service exists only in BDEW.
#[tokio::test]
async fn other_profiles_refuse_a_payload_less_switch() {
    for preset in [Preset::Edelivery, Preset::Peppol, Preset::Entsog] {
        let g = genuine_with(pair(preset), b"business").await;
        let board = Switchboard::over(g.pair);
        // The genuine business message, made payload-less and re-signed over
        // eb:Messaging and the Body only.
        let soap = String::from_utf8_lossy(g.request.body()).into_owned();
        let start = soap.find("<soap:Envelope").expect("envelope");
        let end = soap.find("</soap:Envelope>").expect("end") + "</soap:Envelope>".len();
        let soap = strip(&soap[start..end], "ebms:PayloadInfo", |_| true);
        let soap = strip(&soap, "ds:Reference", |r| r.contains("URI=\"cid:"));
        let soap = set_text(&soap, "ebms:MessageId", "switch@asx");
        let soap = resigned_with(&board.pair, &soap, SERVICE, REQUEST);
        let answer = board.post(plain(&soap)).await;
        board.assert_refused(
            &answer,
            "EBMS:0103",
            "must be multipart/related with a detached payload attachment",
        );
    }
}

/// Under every other profile the switch URIs are an ordinary
/// Service/Action: a message with a payload is delivered with
/// `path_switch() == None`.
#[tokio::test]
async fn other_profiles_never_classify_a_switch() {
    for preset in [Preset::Edelivery, Preset::Entsog] {
        let g = genuine_with(pair(preset), b"business").await;
        let request = g.resigned(|soap| {
            let soap = set_text(&soap, "ebms:MessageId", "fr002@asx");
            set_text(
                &set_text(&soap, "ebms:Service", SERVICE),
                "ebms:Action",
                REQUEST,
            )
        });
        let board = Switchboard::over(g.pair);
        let answer = board.post(request).await;
        assert!(answer.is_receipt(), "{preset:?}: {answer:?}");
        let seen = board.seen();
        assert_eq!(seen.len(), 1, "{preset:?}");
        assert_eq!(seen[0].service, SERVICE);
        assert_eq!(seen[0].path_switch, None, "{preset:?}");
    }
}
