//! The AS2 side of `Inbound`: refuse an unknown `AS2-From` before any
//! private-key operation, decrypt, verify the signature by the partner's pin,
//! settle the dedup claim from the handler's answer and answer with a signed
//! MDN.
//!
//! The order differs from AS4 in one place: the signature is inside the CMS
//! envelope, so decryption comes before authentication (RFC 4130 §2.4
//! encrypt(sign(content))). The decryption error is uniform.

use super::client::{As2, Received, header_id, parse_header_id, receive_view};
use super::ingress::parse_signed_receipt_micalg;
use super::mic::compute_mic;
use super::{As2MicAlgorithm, CmsSmimeTrustVerifier};
use crate::audit::{AuditOutcome, Direction, Protocol, RecordBuilder, Signal};
use crate::core::{AsxError, ErrorCode, ErrorContext, SessionContext};
use crate::crypto::as2_smime::{
    As2SmimeVerificationOptions, SmimeFormat, detect_smime_format, verify_smime_signed_payload,
};
use crate::dedup::{Claim, ClaimToken, DedupProtocol, DedupStore, dedup_key};
use crate::error::BoxFuture;
use crate::inbound::{Handler, Inbound, InboundCore, empty, run_handler, with_body};
use crate::keys::{Certificate, Decrypter};
use crate::profile::PartnerPolicy;
use crate::telemetry::{ReceiveOutcome, finish_receive, receive_span};
use crate::verified::{Payload, Verified};
use bytes::Bytes;
use http::StatusCode;
use http_body_util::Full;
use std::sync::Arc;

const PROCESSED: &str = "automatic-action/MDN-sent-automatically; processed";
const DUPLICATE: &str =
    "automatic-action/MDN-sent-automatically; processed/warning: duplicate-document";

/// The `processed/error` dispositions this side issues.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Refusal {
    AuthenticationFailed,
    DecryptionFailed,
    InsufficientSecurity,
    DecompressionFailed,
    Unexpected,
}

impl Refusal {
    fn disposition(self) -> &'static str {
        match self {
            Refusal::AuthenticationFailed => {
                "automatic-action/MDN-sent-automatically; processed/error: authentication-failed"
            }
            Refusal::DecryptionFailed => {
                "automatic-action/MDN-sent-automatically; processed/error: decryption-failed"
            }
            Refusal::InsufficientSecurity => {
                "automatic-action/MDN-sent-automatically; processed/error: insufficient-message-security"
            }
            Refusal::DecompressionFailed => {
                "automatic-action/MDN-sent-automatically; processed/error: decompression-failed"
            }
            Refusal::Unexpected => {
                "automatic-action/MDN-sent-automatically; processed/error: unexpected-processing-error"
            }
        }
    }

    /// The human-readable part. Never the cause.
    fn text(self) -> &'static str {
        match self {
            Refusal::AuthenticationFailed => "The message could not be authenticated.",
            Refusal::DecryptionFailed => "The message could not be decrypted.",
            Refusal::InsufficientSecurity => "The message must be signed and encrypted.",
            Refusal::DecompressionFailed => "The message could not be decompressed.",
            Refusal::Unexpected => "The message could not be processed.",
        }
    }
}

pub(crate) fn inbound(
    client: As2,
    dedup: Arc<dyn DedupStore>,
    handler: Arc<dyn Handler<Received>>,
) -> Inbound {
    Inbound::new(Arc::new(As2Inbound {
        client,
        dedup,
        handler,
    }))
}

#[derive(Clone)]
struct As2Inbound {
    client: As2,
    dedup: Arc<dyn DedupStore>,
    handler: Arc<dyn Handler<Received>>,
}

impl InboundCore for As2Inbound {
    fn max_bytes(&self) -> u64 {
        self.client.config().profile.max_bytes()
    }

    fn process(
        &self,
        request: http::Request<Bytes>,
    ) -> BoxFuture<'static, http::Response<Full<Bytes>>> {
        let this = self.clone();
        Box::pin(async move {
            let session = this.client.0.inbound_session.clone();
            let span = receive_span("as2", &session);
            let started = tokio::time::Instant::now();
            let (response, outcome, message_id, err) =
                tracing::Instrument::instrument(this.handle(request), span.clone()).await;
            finish_receive(
                &span,
                "as2",
                outcome,
                err.as_ref(),
                message_id.as_deref(),
                started,
            );
            response
        })
    }
}

type Answer = (
    http::Response<Full<Bytes>>,
    ReceiveOutcome,
    Option<String>,
    Option<AsxError>,
);

/// What the request headers say.
struct Request {
    message_id: String,
    from: Option<String>,
    to: Option<String>,
    content_type: Option<String>,
    mic_algorithm: As2MicAlgorithm,
}

/// A decrypted, verified message.
struct Opened {
    content: Vec<u8>,
    media_type: String,
    signer_der: Vec<u8>,
    /// The signer's validated path (signer first, anchor last).
    signer_path: Vec<openssl::x509::X509>,
    mic_base64: String,
    mic_alg: &'static str,
}

impl Opened {
    fn mic(&self) -> String {
        format!("{}, {}", self.mic_base64, self.mic_alg)
    }
}

fn header(headers: &http::HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(str::to_owned)
}

impl As2Inbound {
    async fn handle(&self, request: http::Request<Bytes>) -> Answer {
        let config = self.client.config();
        let headers = request.headers();
        let message_id = header(headers, "message-id")
            .map(|v| super::normalize_message_id(&v).to_string())
            .filter(|id| !id.is_empty() && !id.bytes().any(|b| b.is_ascii_control()));
        let Some(message_id) = message_id else {
            // No Message-ID: an MDN cannot be addressed.
            return (
                empty(StatusCode::BAD_REQUEST),
                ReceiveOutcome::Rejected,
                None,
                None,
            );
        };
        if header(headers, "receipt-delivery-option").is_some() {
            tracing::debug!(
                target: "asx",
                message_id = %message_id,
                "AS2 asynchronous MDN requested; answered synchronously (named gap, research R14)"
            );
        }
        let as2_version = header(headers, "as2-version");
        let req = Request {
            from: header(headers, "as2-from").map(|v| parse_header_id(&v)),
            to: header(headers, "as2-to").map(|v| parse_header_id(&v)),
            content_type: header(headers, http::header::CONTENT_TYPE.as_str()),
            mic_algorithm: header(headers, "disposition-notification-options")
                .and_then(|o| parse_signed_receipt_micalg(&o))
                .unwrap_or(As2MicAlgorithm::Sha256),
            message_id,
        };
        let body = request.into_body();
        let message_id = req.message_id.clone();

        // RFC 4130 §6.1: a missing or unknown AS2-Version is refused before
        // anything else is looked at.
        if !as2_version.as_deref().is_some_and(supported_version) {
            return self
                .refuse(
                    &req,
                    StatusCode::BAD_REQUEST,
                    Refusal::Unexpected,
                    format!(
                        "AS2-Version {:?} is not 1.0, 1.1 or 1.2",
                        as2_version.as_deref().unwrap_or("<absent>")
                    ),
                )
                .await;
        }

        let Some(from) = req.from.clone().filter(|f| crate::builder::is_as2_id(f)) else {
            return self
                .refuse(
                    &req,
                    StatusCode::BAD_REQUEST,
                    Refusal::Unexpected,
                    "no valid AS2-From",
                )
                .await;
        };
        // An unknown sender is refused before any private-key operation.
        let Some(policy) = config.policy_for(None, &from).cloned() else {
            return self
                .refuse(
                    &req,
                    StatusCode::OK,
                    Refusal::AuthenticationFailed,
                    format!("AS2-From {from:?} is not a configured partner"),
                )
                .await;
        };
        if req.to.as_deref() != Some(config.local.id.as_str()) {
            return self
                .refuse(
                    &req,
                    StatusCode::OK,
                    Refusal::Unexpected,
                    "AS2-To is not the local party",
                )
                .await;
        }
        if body.is_empty() {
            return self
                .refuse(
                    &req,
                    StatusCode::BAD_REQUEST,
                    Refusal::Unexpected,
                    "empty body",
                )
                .await;
        }
        let view = receive_view(&config.profile);
        let session = match policy
            .partner
            .as_ref()
            .and_then(|p| self.client.0.sessions.get(&p.key()))
        {
            Some(session) => session.clone(),
            None => {
                return self
                    .refuse(
                        &req,
                        StatusCode::OK,
                        Refusal::AuthenticationFailed,
                        "no session for the partner",
                    )
                    .await;
            }
        };
        let opened = match self.open(&session, &policy, &req, body, view).await {
            Ok(Ok(opened)) => opened,
            Ok(Err((refusal, detail))) => {
                return self.refuse(&req, StatusCode::OK, refusal, detail).await;
            }
            Err(err) => return self.backend_failure(&message_id, err.message),
        };
        // Revocation of the signer's whole path, after the signature and the
        // partner pin, before the claim.
        let outcome = config.revocation.check(&opened.signer_path).await;
        if outcome.refused() {
            return self
                .refuse(
                    &req,
                    StatusCode::OK,
                    Refusal::AuthenticationFailed,
                    outcome.describe(),
                )
                .await;
        }

        let key = dedup_key(DedupProtocol::As2, "", &from, &message_id);
        let token = match self.dedup.claim(&key).await {
            Ok(Claim::Claimed(token)) => token,
            Ok(Claim::Duplicate) => {
                // A verified duplicate is answered, never delivered.
                return match self
                    .mdn(
                        &req,
                        DUPLICATE,
                        "The message was already received.",
                        Some(&opened.mic()),
                    )
                    .await
                {
                    Ok(response) => (response, ReceiveOutcome::Duplicate, Some(message_id), None),
                    Err(err) => self.backend_failure(&message_id, err),
                };
            }
            Ok(Claim::InFlight) => {
                return (
                    empty(StatusCode::SERVICE_UNAVAILABLE),
                    ReceiveOutcome::InFlight,
                    Some(message_id),
                    None,
                );
            }
            Err(err) => {
                return self.backend_failure(&message_id, format!("dedup claim failed: {err}"));
            }
        };
        self.deliver(req, from, opened, key, token).await
    }

    async fn deliver(
        &self,
        req: Request,
        from: String,
        opened: Opened,
        key: String,
        token: ClaimToken,
    ) -> Answer {
        use base64::Engine as _;
        let config = self.client.config();
        let message_id = req.message_id.clone();
        let mut builder = RecordBuilder::new(
            &config.clock,
            Protocol::As2,
            Direction::Inbound,
            message_id.as_str(),
            config.local.id.as_str(),
            from.as_str(),
        )
        .profile(Some(config.profile.name()))
        .signer_der(Some(opened.signer_der.clone()));
        if let Ok(digest) = base64::engine::general_purpose::STANDARD.decode(&opened.mic_base64) {
            builder = builder.mic(opened.mic_alg, digest);
        }
        let (record, signer) = match (
            builder.clone().finish(AuditOutcome::Accepted, None),
            Certificate::from_der(&opened.signer_der),
        ) {
            (Ok(record), Ok(signer)) => (record, signer),
            _ => {
                self.abandon(&key, &token).await;
                return self
                    .backend_failure(&message_id, "the inbound evidence could not be built");
            }
        };
        let mic = opened.mic();
        let received = Received {
            message_id: message_id.clone(),
            from,
            payload: Payload::new(Bytes::from(opened.content), opened.media_type),
        };
        let answer = run_handler(
            self.handler.clone(),
            Verified::new(received, signer, record),
        )
        .await;
        match answer {
            Ok(()) => {
                let mdn = match self
                    .mdn_bytes(
                        &req,
                        PROCESSED,
                        "The message has been received and processed.",
                        Some(&mic),
                    )
                    .await
                {
                    Ok(mdn) => mdn,
                    Err(err) => {
                        self.abandon(&key, &token).await;
                        return self.backend_failure(&message_id, err);
                    }
                };
                let finished = builder
                    .disposition(Some(PROCESSED))
                    .signal(Signal {
                        bytes: &mdn,
                        message_id: None,
                        ref_to_message_id: Some(&message_id),
                        timestamp: None,
                        signed: true,
                        nrr: &[],
                    })
                    .finish(AuditOutcome::Accepted, None);
                let written = match &finished {
                    Ok(record) => {
                        crate::audit::record(
                            config.audit.as_deref().map(|s| s as _),
                            record,
                            "as2_inbound_audit",
                        )
                        .await
                    }
                    Err(err) => Err(err.clone()),
                };
                if let Err(err) = written {
                    self.abandon(&key, &token).await;
                    return self.backend_failure(&message_id, err.to_string());
                }
                if let Err(err) = self.dedup.accept(&key, &token).await {
                    // No abandon: the current holder, if any, settles.
                    return self
                        .backend_failure(&message_id, format!("dedup accept failed: {err}"));
                }
                (
                    self.response(&req, StatusCode::OK, mdn),
                    ReceiveOutcome::Accepted,
                    Some(message_id),
                    None,
                )
            }
            Err(_) => {
                self.abandon(&key, &token).await;
                let refusal = Refusal::Unexpected;
                match self
                    .mdn(&req, refusal.disposition(), refusal.text(), None)
                    .await
                {
                    Ok(response) => (response, ReceiveOutcome::Rejected, Some(message_id), None),
                    Err(err) => self.backend_failure(&message_id, err),
                }
            }
        }
    }

    async fn abandon(&self, key: &str, token: &ClaimToken) {
        if let Err(err) = self.dedup.abandon(key, token).await {
            tracing::warn!(
                target: "asx",
                error = %err,
                "failed to release an AS2 dedup claim; it stays held until its lease expires"
            );
        }
    }

    fn backend_failure(&self, message_id: &str, detail: impl std::fmt::Display) -> Answer {
        let err = AsxError::new(
            ErrorCode::StorageBackendFailure,
            detail.to_string(),
            ErrorContext::new("as2_inbound").with_message_id(message_id.to_string()),
        );
        (
            empty(StatusCode::INTERNAL_SERVER_ERROR),
            ReceiveOutcome::Storage,
            Some(message_id.to_string()),
            Some(err),
        )
    }

    /// A refused message: a signed `processed/error` MDN, or `status` without
    /// a body when no MDN can be signed.
    async fn refuse(
        &self,
        req: &Request,
        status: StatusCode,
        refusal: Refusal,
        detail: impl Into<String>,
    ) -> Answer {
        let err = AsxError::new(
            match refusal {
                Refusal::AuthenticationFailed => ErrorCode::SecurityVerificationFailed,
                Refusal::DecryptionFailed => ErrorCode::DecryptionFailed,
                Refusal::InsufficientSecurity => ErrorCode::PolicyViolation,
                Refusal::DecompressionFailed | Refusal::Unexpected => ErrorCode::InvalidInput,
            },
            detail,
            ErrorContext::new("as2_inbound").with_message_id(req.message_id.clone()),
        );
        tracing::debug!(target: "asx", error = %err.message, "AS2 inbound message refused");
        let response = match self
            .mdn_bytes(req, refusal.disposition(), refusal.text(), None)
            .await
        {
            Ok(mdn) => self.response(req, status, mdn),
            Err(_) => empty(StatusCode::BAD_REQUEST),
        };
        (
            response,
            ReceiveOutcome::Rejected,
            Some(req.message_id.clone()),
            Some(err),
        )
    }

    async fn mdn(
        &self,
        req: &Request,
        disposition: &str,
        text: &str,
        mic: Option<&str>,
    ) -> Result<http::Response<Full<Bytes>>, String> {
        let mdn = self.mdn_bytes(req, disposition, text, mic).await?;
        Ok(self.response(req, StatusCode::OK, mdn))
    }

    /// A signed MDN: one `Signer::sign` through the CMS assembly.
    async fn mdn_bytes(
        &self,
        req: &Request,
        disposition: &str,
        text: &str,
        mic: Option<&str>,
    ) -> Result<Vec<u8>, String> {
        let config = self.client.config();
        let original = format!("<{}>", req.message_id);
        if [original.as_str(), config.local.id.as_str()]
            .iter()
            .any(|v| v.bytes().any(|b| matches!(b, b'\r' | b'\n' | 0)))
        {
            return Err("an MDN field contains CR, LF or NUL".to_string());
        }
        let report = super::mdn_report(&config.local.id, &original, disposition, mic, text);
        let signer = config.local.signer_ref().signer.clone();
        super::cms_keys::sign_detached(signer.as_ref(), &report, config.clock.now())
            .await
            .map_err(|err| format!("the MDN could not be signed: {err}"))
    }

    fn response(
        &self,
        req: &Request,
        status: StatusCode,
        mdn: Vec<u8>,
    ) -> http::Response<Full<Bytes>> {
        let config = self.client.config();
        let content_type = super::extract_content_type_header(&mdn)
            .unwrap_or_else(|| "multipart/signed".to_string());
        let mut response = with_body(status, &content_type, mdn);
        let headers = response.headers_mut();
        let mut set = |name: &'static str, value: String| {
            if let Ok(value) = http::HeaderValue::from_str(&value) {
                headers.insert(name, value);
            }
        };
        set("as2-version", "1.2".to_string());
        set("as2-from", header_id(&config.local.id));
        if let Some(from) = &req.from {
            set("as2-to", header_id(from));
        }
        if let Ok(id) = super::client::fresh_message_id() {
            set("message-id", format!("<{id}>"));
        }
        set("mime-version", "1.0".to_string());
        response
    }
}

/// Whether `value` is an `AS2-Version` this side speaks (RFC 4130 §6.1).
fn supported_version(value: &str) -> bool {
    matches!(value.trim(), "1.0" | "1.1" | "1.2")
}

const DECRYPTION_FAILED: &str = "decryption failed";

/// What the first step of [`As2Inbound::open`] found.
enum Unsealed {
    /// An `EnvelopedData` with its recipient selected; the key operation
    /// comes next.
    Enveloped(super::cms_keys::Envelope),
    /// Not encrypted (and allowed to be): the entity as received.
    Plain(Vec<u8>),
}

impl As2Inbound {
    /// The encryption requirement, decryption and authentication, in RFC
    /// 4130 order: parse and select the recipient, one `Decrypter::decrypt`,
    /// then the content and the signature. Every decryption failure is the
    /// same refusal.
    async fn open(
        &self,
        session: &SessionContext,
        policy: &PartnerPolicy,
        req: &Request,
        body: Bytes,
        view: super::client::ReceiveView,
    ) -> crate::core::Result<Result<Opened, (Refusal, String)>> {
        let decrypters: Vec<Arc<dyn Decrypter>> = self
            .client
            .config()
            .local
            .decrypters
            .iter()
            .map(|d| d.decrypter.clone())
            .collect();
        let certificates: Vec<Certificate> =
            decrypters.iter().map(|d| d.certificate().clone()).collect();
        let unsealed = {
            let session = session.clone();
            let content_type = req.content_type.clone();
            let require_encrypted = view.require_encrypted;
            crate::runtime::spawn_crypto("as2_inbound_verify", &session.clone(), move || {
                let original: Arc<[u8]> = Arc::from(body.as_ref());
                let entity =
                    super::body_with_mime_headers(&session, &original, content_type.as_deref());
                Ok(match detect_smime_format(&entity) {
                    SmimeFormat::Enveloped => {
                        super::cms_keys::parse_envelope(&entity, &certificates)
                            .map(Unsealed::Enveloped)
                            .map_err(|_| (Refusal::DecryptionFailed, DECRYPTION_FAILED.to_string()))
                    }
                    // Unencrypted is insufficient.
                    _ if require_encrypted => Err((
                        Refusal::InsufficientSecurity,
                        "the message is not encrypted".to_string(),
                    )),
                    _ => Ok(Unsealed::Plain(entity.to_vec())),
                })
            })
            .await?
        };
        match unsealed {
            Ok(Unsealed::Enveloped(envelope)) => {
                // The one private-key operation; a failed unwrap continues
                // with a random CEK.
                let span = tracing::debug_span!(
                    target: "asx",
                    "asx.decrypt",
                    algorithm = "cms-enveloped-data",
                    outcome = tracing::field::Empty,
                );
                let cek = tracing::Instrument::instrument(
                    super::cms_keys::unwrap_cek(&envelope, &decrypters),
                    span.clone(),
                )
                .await;
                self.verify(session, policy, req, view, Sealed(envelope, cek, span))
                    .await
            }
            Ok(Unsealed::Plain(entity)) => {
                self.verify(session, policy, req, view, Plain(entity)).await
            }
            Err(refusal) => Ok(Err(refusal)),
        }
    }

    async fn verify(
        &self,
        session: &SessionContext,
        policy: &PartnerPolicy,
        req: &Request,
        view: super::client::ReceiveView,
        content: Content,
    ) -> crate::core::Result<Result<Opened, (Refusal, String)>> {
        let session = session.clone();
        let policy = policy.clone();
        let mic_algorithm = req.mic_algorithm;
        crate::runtime::spawn_crypto("as2_inbound_verify", &session.clone(), move || {
            let decrypted = match content {
                Plain(entity) => entity,
                Sealed(envelope, cek, span) => {
                    let decrypted =
                        span.in_scope(|| super::cms_keys::decrypt_content(&envelope, &cek));
                    crate::telemetry::child_outcome(&span, &decrypted);
                    match decrypted {
                        Ok(decrypted) => decrypted,
                        Err(_) => {
                            return Ok(Err((
                                Refusal::DecryptionFailed,
                                DECRYPTION_FAILED.to_string(),
                            )));
                        }
                    }
                }
            };
            Ok(authenticate(
                &session,
                &policy,
                decrypted,
                mic_algorithm,
                view.require_signed,
            ))
        })
        .await
    }
}

/// The content after the first step: as received, or still sealed with the
/// unwrapped CEK.
enum Content {
    Plain(Vec<u8>),
    Sealed(
        super::cms_keys::Envelope,
        zeroize::Zeroizing<Vec<u8>>,
        tracing::Span,
    ),
}
use Content::{Plain, Sealed};

/// The MIME entity inside an RFC 5402 `CompressedData` (RFC 3274 §1.1: the
/// compressed content is a MIME entity): its body, transfer-decoded, and its
/// Content-Type. Content without a MIME header naming the type is refused
/// rather than guessed at.
fn compressed_entity(plain: &[u8]) -> Result<(Vec<u8>, String), String> {
    let refuse = || "the decompressed content is not a MIME entity with a Content-Type".to_string();
    let entity = mailparse::parse_mail(plain).map_err(|_| refuse())?;
    let media_type =
        mailparse::MailHeaderMap::get_first_value(entity.headers.as_slice(), "Content-Type")
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
            .ok_or_else(refuse)?;
    let body = entity.get_body_raw().map_err(|_| refuse())?;
    Ok((body, media_type))
}

/// The signing requirement and the signature by a pin of the partner, over the decrypted entity.
fn authenticate(
    session: &SessionContext,
    policy: &PartnerPolicy,
    decrypted: Vec<u8>,
    mic_algorithm: As2MicAlgorithm,
    require_signed: bool,
) -> Result<Opened, (Refusal, String)> {
    // Unsigned is insufficient.
    if !matches!(
        detect_smime_format(&decrypted),
        SmimeFormat::MultipartSigned | SmimeFormat::OpaqueSignedData
    ) {
        let _ = require_signed;
        return Err((
            Refusal::InsufficientSecurity,
            "the message is not signed".to_string(),
        ));
    }
    let auth = |detail: String| (Refusal::AuthenticationFailed, detail);
    let chain_policy =
        CmsSmimeTrustVerifier::build_chain_policy(session).map_err(|e| auth(e.message))?;
    let verified = verify_smime_signed_payload(
        &decrypted,
        As2SmimeVerificationOptions {
            expected_signer_fingerprint_sha256: None,
            chain_policy,
            intermediate_ca_pems: &session.cert_handle().intermediate_ca_pems,
        },
    )
    .map_err(|e| auth(e.message))?;
    let signer_der = verified
        .signer_der()
        .map(<[u8]>::to_vec)
        .ok_or_else(|| auth("no signer certificate".to_string()))?;
    let pinned = Certificate::from_der(&signer_der)
        .ok()
        .is_some_and(|cert| policy.pins.contains(cert.fingerprint()));
    if !pinned {
        return Err(auth(
            "the signer is not a pinned certificate of the partner".to_string(),
        ));
    }
    let entity_type = verified.content_type().unwrap_or_default();
    let compressed = crate::crypto::compression::is_as2_compressed_content_type(&entity_type);
    let content = super::decode_entity_content(session, &verified).map_err(|err| {
        if err.context.stage.contains("decompress") {
            (Refusal::DecompressionFailed, err.message)
        } else {
            (Refusal::Unexpected, err.message)
        }
    })?;
    let (content, media_type) = if compressed {
        compressed_entity(&content).map_err(|detail| (Refusal::DecompressionFailed, detail))?
    } else if entity_type.trim().is_empty() {
        (content.to_vec(), "application/octet-stream".to_string())
    } else {
        (content.to_vec(), entity_type.trim().to_string())
    };
    let (mic_base64, mic_alg) = compute_mic(verified.entity(), mic_algorithm);
    Ok(Opened {
        content,
        media_type,
        signer_der,
        signer_path: verified.signer_path().to_vec(),
        mic_base64,
        mic_alg,
    })
}
