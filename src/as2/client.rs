//! The AS2 client: [`As2`], its outbound [`Message`], the asynchronous-MDN
//! state [`PendingMdn`] and the verified inbound [`Received`].

use super::{As2MicAlgorithm, As2SendPolicy, SmimeCipher};
use crate::builder::{Builder, ClientConfig};
use crate::core::SessionContext;
use crate::error::{Error, ErrorKind, Result};
use crate::keys::Certificate;
use crate::party::Partner;
use crate::profile::{PartnerPolicy, Profile, Quirk};
use crate::verified::{Payload, Receipt, Verified};
use std::collections::HashMap;
use std::sync::Arc;

/// An AS2 client: `Clone` (Arc inside), validated once at `build()`.
#[derive(Debug, Clone)]
pub struct As2(pub(crate) Arc<As2Inner>);

#[derive(Debug)]
pub(crate) struct As2Inner {
    pub(crate) config: ClientConfig,
    /// One internal session per registered partner, keyed like the partners:
    /// the anchors, the partner's encryption certificate and its pins.
    pub(crate) sessions: HashMap<(Option<String>, String), SessionContext>,
    /// The session inbound telemetry is reported under.
    pub(crate) inbound_session: SessionContext,
}

impl As2 {
    /// Start configuring a client for `profile`.
    pub fn builder(profile: Profile) -> Builder<As2> {
        Builder::new(profile)
    }

    pub(crate) fn from_config(config: ClientConfig) -> Result<As2> {
        let mut sessions = HashMap::new();
        for (key, policy) in &config.partners {
            sessions.insert(key.clone(), session_for(&config, policy)?);
        }
        let inbound_session =
            crate::builder::base_session(&config, "inbound", Vec::new(), None, &[])?;
        Ok(As2(Arc::new(As2Inner {
            config,
            sessions,
            inbound_session,
        })))
    }

    /// Sign, encrypt, POST requesting a synchronous signed MDN, verify it.
    ///
    /// Returns only an MDN that is signed by a pinned certificate of the
    /// partner (absent only with [`Quirk::UnsignedMdn`]), names the sent
    /// message id in `Original-Message-ID`, echoes the MIC computed over the
    /// signed entity and reports `processed` (a warning is allowed). A
    /// `processed/error` or `failed` MDN is
    /// [`ErrorKind::PartnerError`](crate::ErrorKind::PartnerError). On
    /// `Transport` and `Indeterminate` errors resend the same `Message` with
    /// the same message id.
    pub async fn send(&self, message: Message) -> Result<Verified<Receipt>> {
        super::send_client::send(self, message).await
    }

    /// Same, requesting an asynchronous MDN to `receipt_url`
    /// (`Receipt-Delivery-Option`); persist the returned value and hand it to
    /// [`verify_async_mdn`](As2::verify_async_mdn) when the MDN arrives.
    pub async fn send_async_mdn(&self, message: Message, receipt_url: &str) -> Result<PendingMdn> {
        super::send_client::send_async_mdn(self, message, receipt_url).await
    }

    /// Verify an asynchronous MDN request against what was sent.
    ///
    /// A request that is not an MDN for `pending` is
    /// [`ErrorKind::Rejected`](crate::ErrorKind::Rejected); an MDN for it
    /// that fails verification is
    /// [`ErrorKind::Indeterminate`](crate::ErrorKind::Indeterminate).
    pub async fn verify_async_mdn(
        &self,
        request: http::Request<bytes::Bytes>,
        pending: &PendingMdn,
    ) -> Result<Verified<Receipt>> {
        super::send_client::verify_async_mdn(self, request, pending).await
    }

    /// A receive endpoint for this client's local party. An inbound
    /// asynchronous-MDN request is answered synchronously.
    pub fn inbound(
        &self,
        dedup: impl crate::DedupStore,
        handler: impl crate::Handler<Received>,
    ) -> crate::Inbound {
        super::inbound::inbound(self.clone(), Arc::new(dedup), Arc::new(handler))
    }

    pub(crate) fn config(&self) -> &ClientConfig {
        &self.0.config
    }
}

/// The internal session of one partner policy: anchors, the partner's
/// encryption certificate, its pins (supplied out of band for CMS
/// verification under `PKCS7_NOINTERN`), the profile's revocation rule.
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

// ── Policy views: the only places the internal AS2 policies are built ─────

/// The AS2 send policy view of `policy`:
/// signed (SHA-256) and encrypted (AES-256-CBC), not compressed.
pub(crate) fn send_view(policy: &PartnerPolicy, local_id: &str) -> As2SendPolicy {
    let _ = &policy.profile;
    let view = As2SendPolicy {
        sign: true,
        encrypt: true,
        compress: false,
        payload_content_type: None,
        mic_algorithm: As2MicAlgorithm::Sha256,
        encryption_cipher: SmimeCipher::Aes256Cbc,
        as2_from_id: local_id.to_string(),
    };
    crate::profile::probe::record("as2.send", &view);
    view
}

/// What an inbound AS2 message must carry under the profile.
#[derive(Debug, Clone)]
#[allow(dead_code)] // Every field is read through the profile probe's `Debug`.
pub(crate) struct ReceiveView {
    pub(crate) require_signed: bool,
    pub(crate) require_encrypted: bool,
    pub(crate) mdn_signed: bool,
    pub(crate) detect_duplicates: bool,
}

/// The AS2 inbound view of `profile`: the same for every sender, because
/// inbound acceptance is the profile's (the sender must be configured).
pub(crate) fn receive_view(profile: &Profile) -> ReceiveView {
    let _ = profile;
    let view = ReceiveView {
        require_signed: true,
        require_encrypted: true,
        mdn_signed: true,
        detect_duplicates: true,
    };
    crate::profile::probe::record("as2.receive", &view);
    view
}

/// How an MDN answering our message is verified.
#[derive(Debug, Clone)]
#[allow(dead_code)] // Every field is read through the profile probe's `Debug`.
pub(crate) struct MdnVerifyView {
    /// `false` only with [`Quirk::UnsignedMdn`]; a present signature is
    /// verified either way.
    pub(crate) require_signed_mdn: bool,
    pub(crate) mic_algorithm: As2MicAlgorithm,
    pub(crate) require_mic: bool,
    pub(crate) bind_original_message_id: bool,
    pub(crate) pins: usize,
}

/// The MDN-verification view of `policy`.
pub(crate) fn mdn_verify_view(policy: &PartnerPolicy) -> MdnVerifyView {
    let view = MdnVerifyView {
        require_signed_mdn: !policy.has_quirk(Quirk::UnsignedMdn),
        mic_algorithm: As2MicAlgorithm::Sha256,
        require_mic: true,
        bind_original_message_id: true,
        pins: policy.pins.len(),
    };
    crate::profile::probe::record("as2.mdn_verify", &view);
    view
}

// ── Message ─────────────────────────────────────────────────────────────────

/// An outbound AS2 message: one payload to one partner.
#[derive(Debug, Clone)]
#[must_use]
pub struct Message {
    pub(crate) partner: Partner,
    pub(crate) payload: Payload,
    pub(crate) message_id: Option<String>,
}

impl Message {
    /// `payload` to `partner`.
    pub fn to(partner: &Partner, payload: Payload) -> Message {
        Message {
            partner: partner.clone(),
            payload,
            message_id: None,
        }
    }

    /// Reuse on retry. Default: a fresh RFC 2822 `msg-id`.
    pub fn message_id(self, id: impl Into<String>) -> Message {
        Message {
            message_id: Some(id.into()),
            ..self
        }
    }
}

// ── PendingMdn ──────────────────────────────────────────────────────────────

/// What is needed to verify an asynchronous MDN later. Holds no secret.
/// Serialized form is versioned JSON (`"v": 1`; another version fails to
/// deserialize).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PendingMdn {
    #[serde(deserialize_with = "version_one")]
    pub(crate) v: u8,
    pub(crate) message_id: String,
    /// (type, id).
    pub(crate) partner: (Option<String>, String),
    /// The computed MIC, base64.
    pub(crate) mic: String,
    pub(crate) mic_alg: String,
    pub(crate) signed: bool,
    /// RFC 3339.
    pub(crate) sent_at: String,
}

fn version_one<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<u8, D::Error> {
    let v = <u8 as serde::Deserialize>::deserialize(deserializer)?;
    if v == 1 {
        Ok(v)
    } else {
        Err(serde::de::Error::custom(format!(
            "unsupported PendingMdn version {v}; this release reads version 1"
        )))
    }
}

/// The most of an MDN request [`PendingMdn::lookup_key`] reads.
const LOOKUP_SCAN_BYTES: usize = 64 * 1024;

impl PendingMdn {
    /// The sent `Message-ID` this MDN is awaited for.
    pub fn message_id(&self) -> &str {
        &self.message_id
    }

    /// The `Original-Message-ID` an MDN request claims, without angle
    /// brackets. **Unauthenticated**: use it only to look up the
    /// `PendingMdn`; [`As2::verify_async_mdn`] checks it. Reads at most the
    /// first 64 KiB of the body; `None` when no single, well-formed value is
    /// found there.
    pub fn lookup_key(request: &http::Request<bytes::Bytes>) -> Option<String> {
        let body = request.body();
        let scanned = &body[..body.len().min(LOOKUP_SCAN_BYTES)];
        let text = String::from_utf8_lossy(scanned);
        let mut found: Option<String> = None;
        for line in text.split('\n') {
            let line = line.strip_suffix('\r').unwrap_or(line);
            let Some((name, value)) = line.split_once(':') else {
                continue;
            };
            if !name.trim().eq_ignore_ascii_case("original-message-id") {
                continue;
            }
            let id = super::normalize_message_id(value);
            if id.is_empty() || id.len() > 998 || id.bytes().any(|b| !(0x21..0x7f).contains(&b)) {
                return None;
            }
            match &found {
                // Two different claims are ambiguous.
                Some(previous) if previous != id => return None,
                _ => found = Some(id.to_string()),
            }
        }
        found
    }
}

// ── Received ────────────────────────────────────────────────────────────────

/// A verified inbound AS2 message (only ever inside `Verified`).
#[derive(Debug)]
pub struct Received {
    pub(crate) message_id: String,
    pub(crate) from: String,
    pub(crate) payload: Payload,
}

impl Received {
    /// The `Message-ID`, without angle brackets.
    pub fn message_id(&self) -> &str {
        &self.message_id
    }

    /// `AS2-From` (a configured partner whose pinned certificate signed).
    pub fn from(&self) -> &str {
        &self.from
    }

    /// Decrypted, signature-verified and (if compressed) decompressed; the
    /// media type is the signed entity's `Content-Type`.
    pub fn payload(&self) -> &Payload {
        &self.payload
    }
}

// ── Send-time validation ────────────────────────────────────────────────────

fn refuse(field: &str, detail: impl std::fmt::Display) -> Error {
    Error::config(format!("Message::{field}: {detail}"))
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

/// An RFC 2045 `type/subtype` with optional `; name=value` parameters,
/// no CR or LF.
pub(crate) fn valid_media_type(value: &str) -> bool {
    fn is_tchar(b: u8) -> bool {
        b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)
    }
    fn token(bytes: &[u8], mut i: usize) -> Option<usize> {
        let start = i;
        while i < bytes.len() && is_tchar(bytes[i]) {
            i += 1;
        }
        (i > start).then_some(i)
    }
    fn quoted_string(bytes: &[u8], mut i: usize) -> Option<usize> {
        if bytes.get(i) != Some(&b'"') {
            return None;
        }
        i += 1;
        while i < bytes.len() {
            match bytes[i] {
                b'"' => return Some(i + 1),
                b'\\' => i += 2,
                b'\r' | b'\n' => return None,
                _ => i += 1,
            }
        }
        None
    }
    fn skip_spaces(bytes: &[u8], mut i: usize) -> usize {
        while bytes.get(i) == Some(&b' ') {
            i += 1;
        }
        i
    }
    fn parse(bytes: &[u8]) -> Option<()> {
        let mut i = token(bytes, 0)?;
        if bytes.get(i) != Some(&b'/') {
            return None;
        }
        i = token(bytes, i + 1)?;
        loop {
            let j = skip_spaces(bytes, i);
            if j == bytes.len() {
                return (j == i).then_some(());
            }
            if bytes[j] != b';' {
                return None;
            }
            i = token(bytes, skip_spaces(bytes, j + 1))?;
            if bytes.get(i) != Some(&b'=') {
                return None;
            }
            i = token(bytes, i + 1).or_else(|| quoted_string(bytes, i + 1))?;
        }
    }
    value.len() <= 255 && parse(value.as_bytes()).is_some()
}

/// Validate `message` (media type, size, message id, and AS2's single
/// unnamed payload); returns the message id to send under.
pub(crate) fn check_message(config: &ClientConfig, message: &Message) -> Result<String> {
    let payload = &message.payload;
    if payload.bytes().is_empty() {
        return Err(refuse("payload", "the payload is empty"));
    }
    if !valid_media_type(payload.mime_type()) {
        return Err(refuse(
            "payload",
            format!(
                "{:?} is not an RFC 2045 type/subtype (with optional parameters) without CR or LF",
                payload.mime_type()
            ),
        ));
    }
    // AS2 carries no file name: refuse rather than drop it silently.
    if payload.name().is_some() {
        return Err(refuse(
            "payload",
            "an AS2 message carries no file name (RFC 4130 sends one MIME entity); remove Payload::named",
        ));
    }
    let total = payload.bytes().len() as u64;
    if total > config.profile.max_bytes() {
        return Err(refuse(
            "payload",
            format!(
                "{total} bytes exceed max_message_bytes {}",
                config.profile.max_bytes()
            ),
        ));
    }
    match &message.message_id {
        Some(id) if valid_message_id(id) => Ok(id.clone()),
        Some(id) => Err(refuse(
            "message_id",
            format!(
                "{id:?} is not an RFC 2822 id-left@id-right of at most 255 bytes without angle brackets"
            ),
        )),
        None => fresh_message_id(),
    }
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
        && !partner.signing_certs().is_empty()
        && partner.signing_certs().iter().all(expired)
    {
        return Err(Error::config(
            "Partner::signing_cert: every pinned certificate is expired or not yet valid",
        ));
    }
    Ok(())
}

/// An AS2 identifier as a header value (RFC 4130 §6.2): quoted when it
/// contains a space or a quote.
pub(crate) fn header_id(id: &str) -> String {
    if id.bytes().any(|b| matches!(b, b' ' | b'"' | b'\\')) {
        format!("\"{}\"", id.replace('\\', "\\\\").replace('"', "\\\""))
    } else {
        id.to_string()
    }
}

/// The inverse of [`header_id`]: a received `AS2-From`/`AS2-To` value.
pub(crate) fn parse_header_id(value: &str) -> String {
    let value = value.trim();
    match value.strip_prefix('"').and_then(|v| v.strip_suffix('"')) {
        Some(inner) => {
            let mut out = String::with_capacity(inner.len());
            let mut escaped = false;
            for c in inner.chars() {
                if escaped {
                    out.push(c);
                    escaped = false;
                } else if c == '\\' {
                    escaped = true;
                } else {
                    out.push(c);
                }
            }
            out
        }
        None => value.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_id_rule() {
        assert!(valid_message_id("abc@example.org"));
        assert!(!valid_message_id("<abc@example.org>"));
        assert!(!valid_message_id("abc"));
        assert!(valid_message_id(&fresh_message_id().unwrap()));
    }

    #[test]
    fn media_type_rule() {
        assert!(valid_media_type("application/edi-x12"));
        assert!(valid_media_type("text/plain; charset=utf-8"));
        assert!(!valid_media_type("text/plain\r\nX: y"));
        assert!(!valid_media_type("textplain"));
    }

    #[test]
    fn header_ids_round_trip() {
        for id in ["OURAS2ID", "with space", "q\"uote"] {
            assert_eq!(parse_header_id(&header_id(id)), id);
        }
    }

    #[test]
    fn pending_mdn_rejects_unknown_versions() {
        let pending = PendingMdn {
            v: 1,
            message_id: "a@b".into(),
            partner: (None, "P".into()),
            mic: "AAAA".into(),
            mic_alg: "sha-256".into(),
            signed: true,
            sent_at: "2026-01-01T00:00:00Z".into(),
        };
        let json = serde_json::to_string(&pending).unwrap();
        assert_eq!(serde_json::from_str::<PendingMdn>(&json).unwrap(), pending);
        let v2 = json.replace("\"v\":1", "\"v\":2");
        assert!(serde_json::from_str::<PendingMdn>(&v2).is_err());
    }
}
