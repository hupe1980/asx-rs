//! The AS4 client: [`As4`], its outbound [`Message`] and `send`.

use crate::builder::{Builder, ClientConfig};
use crate::core::SessionContext;
use crate::error::{Error, ErrorKind, Result, Stage};
use crate::keys::Certificate;
use crate::party::Partner;
use crate::profile::{
    CONFIRM_SWITCH_ACTION, DEFAULT_ACTION, PATH_SWITCH_SERVICE, PartnerPolicy, PartyTypeRule,
    Profile, REQUEST_SWITCH_ACTION, SendHeader, ServiceRule, TEST_ACTION, TEST_SERVICE,
};
use crate::verified::{Payload, Receipt, ReceiptKind, Verified};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::SystemTime;

/// An AS4 client: `Clone` (Arc inside), validated once at `build()`.
#[derive(Debug, Clone)]
pub struct As4(pub(crate) Arc<As4Inner>);

#[derive(Debug)]
pub(crate) struct As4Inner {
    pub(crate) config: ClientConfig,
    /// One internal session per registered partner, keyed like the partners.
    pub(crate) sessions: HashMap<(Option<String>, String), SessionContext>,
    /// The session inbound messages are verified under: the anchors and the
    /// revocation rule; who may sign is decided per sender.
    pub(crate) inbound_session: SessionContext,
}

impl As4 {
    /// Start configuring a client for `profile`.
    pub fn builder(profile: Profile) -> Builder<As4> {
        Builder::new(profile)
    }

    pub(crate) fn from_config(config: ClientConfig) -> Result<As4> {
        let mut sessions = HashMap::new();
        for (key, policy) in &config.partners {
            sessions.insert(key.clone(), session_for(&config, policy)?);
        }
        let inbound_session =
            crate::builder::base_session(&config, "inbound", Vec::new(), None, &[])?;
        Ok(As4(Arc::new(As4Inner {
            config,
            sessions,
            inbound_session,
        })))
    }

    /// Build, sign, compress, encrypt, POST and verify the receipt.
    ///
    /// Returns only a receipt that is signed by a pinned certificate of the
    /// partner, refers to the sent message id and (unless the partner has
    /// [`Quirk::ReceiptWithoutNonRepudiation`](crate::Quirk)) echoes the
    /// digests the message was signed over. On `Transport` and
    /// `Indeterminate` errors resend the same `Message` with the same message
    /// id and timestamp.
    pub async fn send(&self, message: Message) -> Result<Verified<Receipt>> {
        crate::as4::send_client::send(self, message).await
    }

    /// A receive endpoint for this client's local party.
    pub fn inbound(
        &self,
        dedup: impl crate::DedupStore,
        handler: impl crate::Handler<UserMessage>,
    ) -> crate::Inbound {
        crate::as4::inbound::inbound(self.clone(), Arc::new(dedup), Arc::new(handler))
    }

    pub(crate) fn config(&self) -> &ClientConfig {
        &self.0.config
    }
}

/// The internal session of one partner policy: anchors, the partner's
/// encryption certificate, its pins, the profile's revocation rule.
pub(crate) fn session_for(config: &ClientConfig, policy: &PartnerPolicy) -> Result<SessionContext> {
    let partner_id = policy
        .partner
        .as_ref()
        .map(|p| p.id().to_string())
        .unwrap_or_else(|| "unregistered".to_string());
    let signing: &[Certificate] = policy
        .partner
        .as_ref()
        .map(|p| p.signing_certs())
        .unwrap_or_default();
    crate::builder::base_session(
        config,
        &partner_id,
        policy.pins.clone(),
        policy.encryption_cert.as_ref(),
        signing,
    )
}

/// The BDEW transmission-path-switch service (BDEW AS4-Profil 1.2 §2.2.8,
/// §2.3.7). Only [`Profile::bdew()`] has it.
///
/// B §2.2.8: a BDEW endpoint "MUSS zusätzlich einen
/// AS4-Übertragungspfadänderungsdienst (Kapitel 2.3.7) implementieren".
/// B §2.3.7: party A sends a user message with Service
/// `https://www.bdew.de/as4/communication/services/pathSwitch` and Action
/// `https://www.bdew.de/as4/communication/actions/requestSwitch`; party B
/// answers "mit einer neuen Nachricht" with the Action
/// `https://www.bdew.de/as4/communication/actions/confirmSwitch`. "Die
/// zwischen Partei A und Partei B ausgetauschten Nachrichten MÜSSEN keine
/// Nutzdaten enthalten."
///
/// Send one with [`Message::path_switch`]; an inbound one is recognised by
/// [`UserMessage::path_switch`]. Correlating a confirmation with its request
/// and recording that AS4 is now mandatory for a partner are the
/// application's.
///
/// ```no_run
/// use asx::{as4::{As4, Message, PathSwitch, UserMessage}, Partner, Reject, Verified};
///
/// async fn handle(msg: Verified<UserMessage>) -> Result<(), Reject> {
///     if let Some(PathSwitch::Request) = msg.path_switch() {
///         record_switch_request(msg.from()).await?; // application state; confirm later
///         return Ok(());
///     }
///     deliver(&msg).await
/// }
///
/// async fn confirm(as4: &As4, requester: &Partner) -> asx::Result<()> {
///     as4.send(Message::path_switch(requester, PathSwitch::Confirm)).await.map(drop)
/// }
/// # async fn record_switch_request(_: &str) -> Result<(), std::io::Error> { Ok(()) }
/// # async fn deliver(_: &Verified<UserMessage>) -> Result<(), Reject> { Ok(()) }
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum PathSwitch {
    /// Action `https://www.bdew.de/as4/communication/actions/requestSwitch`:
    /// ask the partner to switch the transmission path to AS4.
    Request,
    /// Action `https://www.bdew.de/as4/communication/actions/confirmSwitch`:
    /// a new message answering a request (not a receipt, no
    /// `RefToMessageId`, B §2.3.1.2.4).
    Confirm,
}

impl PathSwitch {
    fn action(self) -> &'static str {
        match self {
            PathSwitch::Request => REQUEST_SWITCH_ACTION,
            PathSwitch::Confirm => CONFIRM_SWITCH_ACTION,
        }
    }
}

/// The path-switch kind of a (verified) Service/Action pair: both URIs must
/// match byte for byte (B §2.3.1.2.1, §2.3.1.2.2). Profile-agnostic:
/// callers gate it on [`Profile::path_switch`].
pub(crate) fn classify_path_switch(service: &str, action: &str) -> Option<PathSwitch> {
    if service != PATH_SWITCH_SERVICE {
        return None;
    }
    match action {
        REQUEST_SWITCH_ACTION => Some(PathSwitch::Request),
        CONFIRM_SWITCH_ACTION => Some(PathSwitch::Confirm),
        _ => None,
    }
}

/// What a [`Message`] is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MessageKind {
    Business,
    Ping,
    PathSwitch(PathSwitch),
}

/// An outbound user message.
#[derive(Debug, Clone)]
#[must_use]
pub struct Message {
    pub(crate) partner: Partner,
    pub(crate) service: Option<String>,
    pub(crate) action: Option<String>,
    pub(crate) conversation_id: Option<String>,
    pub(crate) message_id: Option<String>,
    pub(crate) timestamp: Option<SystemTime>,
    pub(crate) payloads: Vec<Payload>,
    pub(crate) kind: MessageKind,
}

impl Message {
    /// A user message to `partner`.
    pub fn to(partner: &Partner) -> Message {
        Message {
            partner: partner.clone(),
            service: None,
            action: None,
            conversation_id: None,
            message_id: None,
            timestamp: None,
            payloads: Vec::new(),
            kind: MessageKind::Business,
        }
    }

    /// An ebMS3 test-service message (eDelivery AS4 1.15 §3.2.4, BDEW
    /// §2.3.6). The receiver answers it with a receipt and never delivers it.
    pub fn ping(partner: &Partner) -> Message {
        Message {
            kind: MessageKind::Ping,
            ..Message::to(partner)
        }
    }

    /// A payload-less BDEW path-switch message to `partner` (BDEW
    /// AS4-Profil 1.2 §2.2.8, §2.3.7): Service
    /// `https://www.bdew.de/as4/communication/services/pathSwitch`, Action
    /// `…/actions/requestSwitch` or `…/actions/confirmSwitch`, an empty
    /// `ConversationId`, no `RefToMessageId`, no `eb:PayloadInfo`.
    ///
    /// Sent as one signed `application/soap+xml` envelope, neither encrypted
    /// nor compressed (there is nothing to encrypt, AS4 Profile 1.0 §5.1.6),
    /// so the partner needs no encryption certificate. `send` refuses it with
    /// [`ErrorKind::Config`](crate::ErrorKind) under any profile but
    /// [`Profile::bdew()`], and with a payload, service, action or
    /// conversation id set. Retry it like any message: the same `Message`
    /// with the same message id and timestamp.
    pub fn path_switch(partner: &Partner, kind: PathSwitch) -> Message {
        Message {
            kind: MessageKind::PathSwitch(kind),
            ..Message::to(partner)
        }
    }

    /// `eb:Service`.
    pub fn service(self, service: impl Into<String>) -> Message {
        Message {
            service: Some(service.into()),
            ..self
        }
    }

    /// `eb:Action`.
    pub fn action(self, action: impl Into<String>) -> Message {
        Message {
            action: Some(action.into()),
            ..self
        }
    }

    /// `eb:ConversationId`.
    pub fn conversation_id(self, id: impl Into<String>) -> Message {
        Message {
            conversation_id: Some(id.into()),
            ..self
        }
    }

    /// Reuse on retry. Default: a fresh RFC 2822 `msg-id`.
    pub fn message_id(self, id: impl Into<String>) -> Message {
        Message {
            message_id: Some(id.into()),
            ..self
        }
    }

    /// `eb:Timestamp`. Reuse the first attempt's value on retry so the NRR
    /// digests do not vary (AS4 Profile 1.0 §3.2). Default: now.
    pub fn timestamp(self, at: SystemTime) -> Message {
        Message {
            timestamp: Some(at),
            ..self
        }
    }

    /// Add a payload part.
    pub fn payload(mut self, payload: Payload) -> Message {
        self.payloads.push(payload);
        self
    }
}

/// A verified inbound user message (only ever inside `Verified`).
#[derive(Debug)]
pub struct UserMessage {
    pub(crate) message_id: String,
    pub(crate) conversation_id: String,
    pub(crate) from: String,
    pub(crate) service: String,
    pub(crate) action: String,
    pub(crate) payloads: Vec<Payload>,
    pub(crate) path_switch: Option<PathSwitch>,
}

impl UserMessage {
    /// `eb:MessageId`.
    pub fn message_id(&self) -> &str {
        &self.message_id
    }

    /// `eb:ConversationId` (empty when absent).
    pub fn conversation_id(&self) -> &str {
        &self.conversation_id
    }

    /// The sender's `eb:From/eb:PartyId` value (authorized per the profile).
    pub fn from(&self) -> &str {
        &self.from
    }

    /// `eb:Service`.
    pub fn service(&self) -> &str {
        &self.service
    }

    /// `eb:Action`.
    pub fn action(&self) -> &str {
        &self.action
    }

    /// Decrypted, decompressed, digest-verified.
    pub fn payloads(&self) -> &[Payload] {
        &self.payloads
    }

    /// `Some` if the verified Service and Action are a BDEW path-switch pair
    /// under [`Profile::bdew()`] (BDEW AS4-Profil 1.2 §2.2.8, §2.3.7; both
    /// URIs compared exactly): Service
    /// `https://www.bdew.de/as4/communication/services/pathSwitch` with Action
    /// `https://www.bdew.de/as4/communication/actions/requestSwitch`
    /// ([`PathSwitch::Request`]) or `…/actions/confirmSwitch`
    /// ([`PathSwitch::Confirm`]). `None` under every other profile.
    ///
    /// [`payloads`](Self::payloads) is then usually empty ("MÜSSEN keine
    /// Nutzdaten enthalten"). Record the switch; answer a `Request` with
    /// `Message::path_switch(&partner, PathSwitch::Confirm)` from a spawned
    /// task after returning `Ok` (the handler holds the duplicate-detection
    /// claim until it returns).
    pub fn path_switch(&self) -> Option<PathSwitch> {
        self.path_switch
    }
}

// ── Send-time validation ─────────────────────────────────────────────────────

fn refuse(profile: &Profile, field: &str, detail: impl std::fmt::Display, section: &str) -> Error {
    if section.is_empty() {
        Error::config(format!("Message::{field}: {detail}"))
    } else {
        Error::config(format!(
            "Message::{field}: {detail} ({} {section})",
            profile.citation()
        ))
    }
}

/// An RFC 2822 `id-left@id-right` without angle brackets, at most 255
/// bytes, printable ASCII without spaces.
pub(crate) fn valid_message_id(id: &str) -> bool {
    let Some((left, right)) = id.split_once('@') else {
        return false;
    };
    !left.is_empty()
        && !right.is_empty()
        && !right.contains('@')
        && id.len() <= 255
        && id
            .bytes()
            .all(|b| (0x21..0x7f).contains(&b) && !matches!(b, b'<' | b'>' | b'"' | b'\\'))
}

/// A valid `Content-Disposition` file name.
pub(crate) fn valid_file_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 255
        && !name
            .bytes()
            .any(|b| matches!(b, b'\r' | b'\n' | b'"' | b'\\' | b'/') || !(0x20..0x7f).contains(&b))
}

/// A fresh RFC 2822 `msg-id`.
pub(crate) fn fresh_message_id() -> Result<String> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).map_err(|err| {
        Error::new(
            ErrorKind::Config,
            format!("no randomness for a message id: {err}"),
        )
    })?;
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    Ok(format!("{hex}@asx"))
}

/// The validated parts of a message.
pub(crate) struct Checked {
    pub(crate) header: SendHeader,
    pub(crate) message_id: String,
    pub(crate) timestamp: String,
}

/// Validate `message` for `policy`. The partner (endpoint, encryption
/// certificate, an unregistered partner's validity) is checked by `send`.
pub(crate) fn check_message(
    config: &ClientConfig,
    policy: &PartnerPolicy,
    message: &Message,
) -> Result<Checked> {
    let profile = &config.profile;
    if let MessageKind::PathSwitch(_) = message.kind {
        check_path_switch(profile, message)?;
    }
    let (service, action) = if let MessageKind::PathSwitch(kind) = message.kind {
        (PATH_SWITCH_SERVICE.to_string(), kind.action().to_string())
    } else if message.kind == MessageKind::Ping {
        (TEST_SERVICE.to_string(), TEST_ACTION.to_string())
    } else {
        let service = match (profile.service_rule(), message.service.as_deref()) {
            (_, None) => {
                return Err(refuse(profile, "service", "a service is required", ""));
            }
            (ServiceRule::OneOf(allowed), Some(s)) if !allowed.contains(&s) => {
                return Err(refuse(
                    profile,
                    "service",
                    format!("{s:?} is not one of {allowed:?}"),
                    "§2.3.1.2.1",
                ));
            }
            (_, Some(s)) => s.to_string(),
        };
        let action = match (profile.fixed_action(), message.action.as_deref()) {
            (Some(fixed), Some(a)) if a != fixed => {
                return Err(refuse(
                    profile,
                    "action",
                    format!("the profile fixes the action to {fixed:?}"),
                    "§2.3.1.2.2",
                ));
            }
            (Some(fixed), _) => fixed.to_string(),
            (None, Some(a)) => a.to_string(),
            (None, None) => DEFAULT_ACTION.to_string(),
        };
        (service, action)
    };
    if message.conversation_id.is_some() && !profile.conversation_id_allowed() {
        return Err(refuse(
            profile,
            "conversation_id",
            "the profile requires an empty ConversationId",
            "§2.3.1.2.4",
        ));
    }
    // A path-switch message carries no payload.
    if message.payloads.is_empty() && !matches!(message.kind, MessageKind::PathSwitch(_)) {
        return Err(refuse(
            profile,
            "payload",
            "at least one payload is required",
            "",
        ));
    }
    let mut total: u64 = 0;
    for payload in &message.payloads {
        if payload.name().is_some() && !profile.filename_allowed() {
            return Err(refuse(
                profile,
                "payload",
                "file names are not allowed",
                "§4.10",
            ));
        }
        crate::as4::mime_packaging::validate_media_type(payload.mime_type(), "Payload::mime_type")
            .map_err(|err| refuse(profile, "payload", err.message, ""))?;
        if let Some(name) = payload.name()
            && !valid_file_name(name)
        {
            return Err(refuse(
                profile,
                "payload",
                "the file name contains CR, LF, '\"', '\\', a path separator or is longer than 255 bytes",
                "",
            ));
        }
        total = total.saturating_add(payload.bytes().len() as u64);
    }
    if total > profile.max_bytes() {
        return Err(refuse(
            profile,
            "payload",
            format!(
                "{total} bytes exceed max_message_bytes {}",
                profile.max_bytes()
            ),
            "",
        ));
    }
    let message_id = match &message.message_id {
        Some(id) if valid_message_id(id) => id.clone(),
        Some(id) => {
            return Err(refuse(
                profile,
                "message_id",
                format!(
                    "{id:?} is not an RFC 2822 id-left@id-right of at most 255 bytes without angle brackets"
                ),
                "",
            ));
        }
        None => fresh_message_id()?,
    };
    let timestamp = crate::time_utils::format_rfc3339_secs(
        message.timestamp.unwrap_or_else(|| policy.clock.now()),
    );
    let (from_type, to_type) = match profile.party_types() {
        PartyTypeRule::Fixed(fixed) => (Some(fixed.to_string()), Some(fixed.to_string())),
        _ => (
            config.local.party_type.clone(),
            message.partner.type_ref().map(str::to_owned),
        ),
    };
    Ok(Checked {
        header: SendHeader {
            from_party: config.local.id.clone(),
            from_type,
            to_party: message.partner.id().to_string(),
            to_type,
            service,
            service_type: String::new(),
            action,
            // BDEW §2.3.1.2.4: the (schema-mandatory) element is always empty.
            conversation_id: if profile.conversation_id_allowed() {
                message.conversation_id.clone()
            } else {
                Some(String::new())
            },
        },
        message_id,
        timestamp,
    })
}

/// A path-switch message exists only under BDEW, and its header is the
/// library's.
fn check_path_switch(profile: &Profile, message: &Message) -> Result<()> {
    if !profile.path_switch() {
        return Err(Error::config(format!(
            "Message::path_switch: the transmission-path-switch service is defined only by \
             BDEW AS4-Profil 1.2 §2.2.8, §2.3.7; {} has none",
            profile.citation()
        )));
    }
    let set = [
        (!message.payloads.is_empty(), "payload"),
        (message.service.is_some(), "service"),
        (message.action.is_some(), "action"),
        (message.conversation_id.is_some(), "conversation_id"),
    ];
    if let Some((_, field)) = set.iter().find(|(is_set, _)| *is_set) {
        return Err(refuse(
            profile,
            field,
            "a path-switch message carries no payload and a library-set Service, Action and \
             empty ConversationId",
            "§2.3.7",
        ));
    }
    Ok(())
}

/// Certificates are re-checked at use, not only at `build()`.
pub(crate) fn check_validity_at_use(config: &ClientConfig, policy: &PartnerPolicy) -> Result<()> {
    let now = policy.clock.now();
    let signer = &config.local.signer_ref().signer;
    if let Some(leaf) = signer.certificate_chain().first()
        && !leaf.is_valid_at(now)
    {
        return Err(Error::config(
            "LocalParty::signer: the signing certificate is expired or not yet valid",
        ));
    }
    let expired = |c: &Certificate| !c.is_valid_at(now);
    if policy.encryption_cert.as_ref().is_some_and(expired) {
        return Err(Error::config(
            "Partner::encryption_cert: the certificate is expired or not yet valid",
        ));
    }
    if let Some(partner) = &policy.partner
        && partner.signing_certs().iter().all(expired)
        && !partner.signing_certs().is_empty()
    {
        return Err(Error::config(
            "Partner::signing_cert: every pinned certificate is expired or not yet valid",
        ));
    }
    Ok(())
}

/// The receipt value of a verified AS4 receipt.
pub(crate) fn as4_receipt(ref_to: &str) -> Receipt {
    Receipt::new(ref_to, ReceiptKind::As4)
}

/// Map an internal failure of the inbound side to `Rejected` (used by
/// `verify` helpers that report through the public error).
#[allow(dead_code)]
pub(crate) fn rejected(err: crate::core::AsxError) -> Error {
    Error::from_internal(Stage::Inbound, err)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_id_rule() {
        assert!(valid_message_id("abc@example.org"));
        assert!(!valid_message_id("<abc@example.org>"));
        assert!(!valid_message_id("abc"));
        assert!(!valid_message_id("a b@c"));
        assert!(!valid_message_id(&format!("{}@x", "a".repeat(260))));
        assert!(valid_message_id(&fresh_message_id().unwrap()));
    }

    /// Exactly the two §2.3.7 pairs classify (byte-exact).
    #[test]
    fn path_switch_classification_table() {
        const S: &str = PATH_SWITCH_SERVICE;
        const MP: &str = "https://www.bdew.de/as4/communication/services/MP";
        let variants = |uri: &str| -> Vec<String> {
            vec![
                format!("{uri} "),
                format!(" {uri}"),
                format!("{uri}\n"),
                uri[..uri.len() - 1].to_string(),
                format!("{}X", &uri[..uri.len() - 1]),
                uri.to_ascii_uppercase(),
                uri.replace("https:", "http:"),
                format!("{uri}/"),
            ]
        };
        let mut rows: Vec<(String, String, Option<PathSwitch>)> = vec![
            (
                S.into(),
                REQUEST_SWITCH_ACTION.into(),
                Some(PathSwitch::Request),
            ),
            (
                S.into(),
                CONFIRM_SWITCH_ACTION.into(),
                Some(PathSwitch::Confirm),
            ),
            (TEST_SERVICE.into(), TEST_ACTION.into(), None),
            (MP.into(), DEFAULT_ACTION.into(), None),
            // swapped and mixed pairs
            (REQUEST_SWITCH_ACTION.into(), S.into(), None),
            (TEST_SERVICE.into(), REQUEST_SWITCH_ACTION.into(), None),
            (S.into(), TEST_ACTION.into(), None),
            (MP.into(), CONFIRM_SWITCH_ACTION.into(), None),
            (S.into(), DEFAULT_ACTION.into(), None),
            (S.into(), String::new(), None),
            (String::new(), REQUEST_SWITCH_ACTION.into(), None),
            // a `type` attribute rendered into the value is not the URI
            (format!("type={S}"), REQUEST_SWITCH_ACTION.into(), None),
        ];
        for service in variants(S) {
            rows.push((service.clone(), REQUEST_SWITCH_ACTION.into(), None));
            rows.push((service, CONFIRM_SWITCH_ACTION.into(), None));
        }
        for action in variants(REQUEST_SWITCH_ACTION)
            .into_iter()
            .chain(variants(CONFIRM_SWITCH_ACTION))
        {
            rows.push((S.into(), action, None));
        }
        let mut classified = 0;
        for (service, action, want) in &rows {
            let got = classify_path_switch(service, action);
            assert_eq!(got, *want, "{service:?} / {action:?}");
            classified += usize::from(got.is_some());
        }
        assert_eq!(classified, 2, "exactly two rows are a path switch");
    }

    /// The path-switch rows of send-time validation.
    #[test]
    fn path_switch_send_rows() {
        let partner = Partner::new("9900000000002");
        let request = || Message::path_switch(&partner, PathSwitch::Request);
        assert!(check_path_switch(&Profile::bdew(), &request()).is_ok());
        assert!(
            check_path_switch(
                &Profile::bdew(),
                &Message::path_switch(&partner, PathSwitch::Confirm)
            )
            .is_ok()
        );
        // Refused under every other AS4 preset.
        for profile in [
            Profile::peppol(),
            Profile::edelivery_1_15(),
            Profile::entsog(),
        ] {
            let err = check_path_switch(&profile, &request()).unwrap_err();
            assert_eq!(err.kind(), ErrorKind::Config);
            assert!(err.to_string().contains("§2.3.7"), "{err}");
        }
        // Nothing the library sets may be set by the caller.
        for (message, field) in [
            (
                request().payload(Payload::new(b"x".to_vec(), "application/octet-stream")),
                "payload",
            ),
            (request().service(PATH_SWITCH_SERVICE), "service"),
            (request().action(REQUEST_SWITCH_ACTION), "action"),
            (request().conversation_id(""), "conversation_id"),
        ] {
            let err = check_path_switch(&Profile::bdew(), &message).unwrap_err();
            assert_eq!(err.kind(), ErrorKind::Config);
            assert!(
                err.to_string().contains(&format!("Message::{field}")),
                "{err}"
            );
        }
        assert_eq!(request().kind, MessageKind::PathSwitch(PathSwitch::Request));
        assert_eq!(Message::to(&partner).kind, MessageKind::Business);
        assert_eq!(Message::ping(&partner).kind, MessageKind::Ping);
    }

    #[test]
    fn file_name_rule() {
        assert!(valid_file_name("UTILMD_9900000000001.txt"));
        assert!(!valid_file_name("a/b"));
        assert!(!valid_file_name("a\\b"));
        assert!(!valid_file_name("a\"b"));
        assert!(!valid_file_name("a\r\nb"));
        assert!(!valid_file_name(&"a".repeat(256)));
    }
}
