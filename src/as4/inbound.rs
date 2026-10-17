//! The AS4 side of `Inbound`: verify (signature, sender, revocation,
//! decryption, in that order), settle the dedup claim from the handler's answer, and
//! answer with a signed receipt, an `eb:Error` or a status.

use super::client::{As4, UserMessage};
use super::receive::{SenderAuthorization, SenderAuthorizer, VerifiedInbound};
use crate::audit::{AuditOutcome, Direction, Protocol, RecordBuilder};
use crate::core::{AsxError, ErrorCode, ErrorContext};
use crate::crypto::wssec::xmlenc::{self, RecipientRef};
use crate::dedup::{Claim, ClaimToken, DedupProtocol, DedupStore, dedup_key};
use crate::error::BoxFuture;
use crate::inbound::{Fault, Handler, Inbound, InboundCore, empty, run_handler, with_body};
use crate::keys::{Certificate, KeyPair, OwnedKeyOp};
use crate::profile::{SenderRule, TEST_ACTION, TEST_SERVICE, TokenRef};
use crate::telemetry::{ReceiveOutcome, finish_receive_coded, receive_span};
use crate::verified::{Payload, Verified};
use bytes::Bytes;
use http::StatusCode;
use http_body_util::Full;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use zeroize::Zeroizing;

/// The external decrypters' answers, by (decrypter index, operation).
type Answers = Arc<Mutex<HashMap<(usize, OwnedKeyOp), Option<Zeroizing<Vec<u8>>>>>>;

const SOAP: &str = "application/soap+xml";

pub(crate) fn inbound(
    client: As4,
    dedup: Arc<dyn DedupStore>,
    handler: Arc<dyn Handler<UserMessage>>,
) -> Inbound {
    Inbound::new(Arc::new(As4Inbound {
        client,
        dedup,
        handler,
    }))
}

struct As4Inbound {
    client: As4,
    dedup: Arc<dyn DedupStore>,
    handler: Arc<dyn Handler<UserMessage>>,
}

impl InboundCore for As4Inbound {
    fn max_bytes(&self) -> u64 {
        self.client.config().profile.max_bytes()
    }

    fn process(
        &self,
        request: http::Request<Bytes>,
    ) -> BoxFuture<'static, http::Response<Full<Bytes>>> {
        let this = As4Inbound {
            client: self.client.clone(),
            dedup: self.dedup.clone(),
            handler: self.handler.clone(),
        };
        Box::pin(async move {
            let session = this.client.0.inbound_session.clone();
            let span = receive_span("as4", &session);
            let started = tokio::time::Instant::now();
            let (response, outcome, message_id, err, code) =
                tracing::Instrument::instrument(this.handle(request), span.clone()).await;
            finish_receive_coded(
                &span,
                "as4",
                outcome,
                err.as_ref(),
                code,
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
    // The eb:Error code of a refusal the error does not determine.
    Option<&'static str>,
);

impl As4Inbound {
    async fn handle(&self, request: http::Request<Bytes>) -> Answer {
        let content_type = request
            .headers()
            .get(http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string();
        let body = request.into_body();
        let verified = match self.verify(body, content_type).await {
            Ok(verified) => verified,
            Err(err) => {
                let response = refusal(&err, self.client.config().clock.now());
                return (
                    response,
                    ReceiveOutcome::Rejected,
                    err.context.message_id.clone(),
                    Some(err),
                    None,
                );
            }
        };
        let message_id = verified.parsed.message_id.clone();

        // The test service is receipted, never delivered or claimed.
        if verified.parsed.service.as_deref() == Some(TEST_SERVICE)
            && verified.parsed.action == TEST_ACTION
        {
            let response = match self.receipt(&verified).await {
                Ok(receipt) => with_body(StatusCode::OK, SOAP, receipt),
                Err(err) => return self.backend_failure(&message_id, err),
            };
            return (
                response,
                ReceiveOutcome::Accepted,
                Some(message_id),
                None,
                None,
            );
        }

        let from = verified.parsed.sender_party_id().to_string();
        let from_type = verified.parsed.from_party_type.clone().unwrap_or_default();
        let key = dedup_key(DedupProtocol::As4, &from_type, &from, &message_id);
        let token = match self.dedup.claim(&key).await {
            Ok(Claim::Claimed(token)) => token,
            Ok(Claim::Duplicate) => {
                // A verified duplicate gets a fresh signed receipt.
                let response = match self.receipt(&verified).await {
                    Ok(receipt) => with_body(StatusCode::OK, SOAP, receipt),
                    Err(err) => return self.backend_failure(&message_id, err),
                };
                return (
                    response,
                    ReceiveOutcome::Duplicate,
                    Some(message_id),
                    None,
                    None,
                );
            }
            Ok(Claim::InFlight) => {
                // The sender's reception awareness retries.
                return (
                    empty(StatusCode::SERVICE_UNAVAILABLE),
                    ReceiveOutcome::InFlight,
                    Some(message_id),
                    None,
                    None,
                );
            }
            Err(err) => {
                return self.backend_failure(&message_id, format!("dedup claim failed: {err}"));
            }
        };
        self.deliver(verified, key, token).await
    }

    async fn deliver(&self, verified: VerifiedInbound, key: String, token: ClaimToken) -> Answer {
        let config = self.client.config();
        let parsed = &verified.parsed;
        let message_id = parsed.message_id.clone();
        let builder = RecordBuilder::new(
            &config.clock,
            Protocol::As4,
            Direction::Inbound,
            parsed.message_id.as_str(),
            config.local.id.as_str(),
            parsed.sender_party_id(),
        )
        .ref_to_message_id(parsed.ref_to_message_id.as_deref())
        .conversation_id(parsed.conversation_id.as_deref())
        .profile(Some(config.profile.name()))
        .service_action(parsed.service.as_deref(), Some(parsed.action.as_str()))
        .message_timestamp(parsed.timestamp.as_deref())
        .signer_der(Some(verified.signer_der.clone()))
        .references(
            verified
                .references
                .iter()
                .map(|(uri, alg, digest)| (uri.as_str(), alg.as_str(), digest.as_str())),
        );
        let (record, signer) = match (
            builder.clone().finish(AuditOutcome::Accepted, None),
            Certificate::from_der(&verified.signer_der),
        ) {
            (Ok(record), Ok(signer)) => (record, signer),
            _ => {
                self.abandon(&key, &token).await;
                return self
                    .backend_failure(&message_id, "the inbound evidence could not be built");
            }
        };
        let user_message = UserMessage {
            message_id: parsed.message_id.clone(),
            conversation_id: parsed.conversation_id.clone().unwrap_or_default(),
            from: parsed.sender_party_id().to_string(),
            service: parsed.service.clone().unwrap_or_default(),
            action: parsed.action.clone(),
            payloads: verified
                .payloads
                .iter()
                .map(|(_, bytes, mime_type)| {
                    Payload::new(Bytes::from(bytes.clone()), mime_type.as_str())
                })
                .collect(),
            // Derived once from the verified header, BDEW only.
            path_switch: config
                .profile
                .path_switch()
                .then(|| {
                    super::client::classify_path_switch(
                        parsed.service.as_deref().unwrap_or_default(),
                        &parsed.action,
                    )
                })
                .flatten(),
        };
        let answer = run_handler(
            self.handler.clone(),
            Verified::new(user_message, signer, record),
        )
        .await;
        match answer {
            Ok(()) => {
                let receipt = match self.receipt(&verified).await {
                    Ok(receipt) => receipt,
                    Err(err) => {
                        self.abandon(&key, &token).await;
                        return self.backend_failure(&message_id, err);
                    }
                };
                let finished = builder
                    .signal(crate::audit::Signal {
                        bytes: &receipt,
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
                            "as4_inbound_audit",
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
                    with_body(StatusCode::OK, SOAP, receipt),
                    ReceiveOutcome::Accepted,
                    Some(message_id),
                    None,
                    None,
                )
            }
            Err(reject) => {
                self.abandon(&key, &token).await;
                // A refusal is an ebMS signal (eDelivery 1.15 §3.3.2).
                let (code, short, category, description, detail) = match reject.fault {
                    Fault::DeliveryFailure => (
                        "EBMS:0202",
                        "DeliveryFailure",
                        "Communication",
                        "the receiving application refused the message",
                        None,
                    ),
                    Fault::Permanent => (
                        "EBMS:0004",
                        "Other",
                        "Content",
                        "the receiving application refused the message permanently",
                        None,
                    ),
                    Fault::NotServiced => (
                        "EBMS:0004",
                        "Other",
                        "Content",
                        "the receiver is not serviced by this access point",
                        Some("PEPPOL:NOT_SERVICED"),
                    ),
                };
                let body = error_body(
                    self.client.config().clock.now(),
                    Some(&message_id),
                    code,
                    short,
                    category,
                    description,
                    detail,
                );
                (
                    with_body(StatusCode::OK, SOAP, body),
                    ReceiveOutcome::Rejected,
                    Some(message_id),
                    None,
                    Some(code),
                )
            }
        }
    }

    async fn abandon(&self, key: &str, token: &ClaimToken) {
        if let Err(err) = self.dedup.abandon(key, token).await {
            tracing::warn!(
                target: "asx",
                error = %err,
                "failed to release an AS4 dedup claim; it stays held until its lease expires"
            );
        }
    }

    fn backend_failure(&self, message_id: &str, detail: impl std::fmt::Display) -> Answer {
        let err = AsxError::new(
            ErrorCode::StorageBackendFailure,
            detail.to_string(),
            ErrorContext::new("as4_inbound").with_message_id(message_id.to_string()),
        );
        let body = error_body(
            self.client.config().clock.now(),
            Some(message_id),
            "EBMS:0004",
            "Other",
            "Content",
            "the message could not be processed; retry later",
            None,
        );
        (
            with_body(StatusCode::INTERNAL_SERVER_ERROR, SOAP, body),
            ReceiveOutcome::Storage,
            Some(message_id.to_string()),
            Some(err),
            Some("EBMS:0004"),
        )
    }

    /// Verification up to (not including) the claim. The signature, the sender
    /// rule and `eb:To` on the crypto pool; then the revocation of the
    /// signer's path (async, outside the pool, only for an authorized
    /// signer); then decryption on the pool. An external decrypter
    /// needs a second pass of the last step: the first records the key
    /// operations it asks for, they are awaited here, and the second pass
    /// uses the answers.
    async fn verify(&self, body: Bytes, content_type: String) -> Result<VerifiedInbound, AsxError> {
        let session = self.client.0.inbound_session.clone();
        let authenticated = {
            let client = self.client.clone();
            let body = body.clone();
            let content_type = content_type.clone();
            let session = session.clone();
            crate::runtime::spawn_crypto("as4_inbound_verify", &session.clone(), move || {
                let config = client.config();
                let policy = crate::profile::receive_view(&config.profile);
                super::receive::authenticate_inbound(
                    &session,
                    &policy,
                    &body,
                    &content_type,
                    &Authorizer { client: &client },
                    (config.local.id.as_str(), config.local.party_type.as_deref()),
                )
            })
            .await?
        };
        let outcome = self
            .client
            .config()
            .revocation
            .check(&authenticated.signer_path)
            .await;
        if outcome.refused() {
            return Err(AsxError::new(
                if outcome.is_revoked() {
                    ErrorCode::CertificateRevoked
                } else {
                    ErrorCode::SecurityVerificationFailed
                },
                outcome.describe(),
                ErrorContext::for_session_with_message(
                    "as4_inbound_revocation",
                    &session,
                    &authenticated.parsed.message_id,
                ),
            ));
        }
        let authenticated = Arc::new(authenticated);
        let answers: Answers = Arc::default();
        let config_owner = self.client.clone();
        for pass in 0..2 {
            let keys = Arc::new(Keys::new(&config_owner, answers.clone()));
            let session = session.clone();
            let client = config_owner.clone();
            let body = body.clone();
            let content_type = content_type.clone();
            let pass_keys = keys.clone();
            let authenticated = authenticated.clone();
            let result =
                crate::runtime::spawn_crypto("as4_inbound_verify", &session.clone(), move || {
                    let config = client.config();
                    let policy = crate::profile::receive_view(&config.profile);
                    super::receive::open_inbound(
                        &session,
                        &policy,
                        &body,
                        &content_type,
                        &authenticated,
                        pass_keys.as_ref(),
                        &config.profile.encryption_suite(),
                    )
                })
                .await;
            let pending = keys.take_pending();
            if pending.is_empty() || pass == 1 {
                return result;
            }
            let decrypters = &self.client.config().local.decrypters;
            for (index, op) in pending {
                let answer = decrypters[index]
                    .decrypter
                    .decrypt(op.as_public())
                    .await
                    .inspect_err(|err| {
                        tracing::warn!(target: "asx", error = %err, "the decrypter failed");
                    })
                    .ok();
                answers
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .insert((index, op), answer);
            }
        }
        unreachable!("the loop returns on its second pass")
    }

    /// A fresh signed NRR receipt for a verified message.
    async fn receipt(&self, verified: &VerifiedInbound) -> Result<Vec<u8>, String> {
        let config = self.client.config();
        let signer = &config.local.signer_ref().signer;
        let algorithm = config.profile.signature_algorithm();
        let receipt_id = super::client::fresh_message_id().map_err(|e| e.to_string())?;
        let draft = super::signals::draft_receipt(
            config.clock.now(),
            &receipt_id,
            &verified.parsed.message_id,
            &verified.nri,
            algorithm.internal(),
        )
        .map_err(|e| e.to_string())?;
        let (_, data) = draft.to_sign();
        let raw = signer
            .sign(algorithm, data)
            .await
            .map_err(|e| format!("the signer failed: {e}"))?;
        let chain: Vec<Vec<u8>> = signer
            .certificate_chain()
            .iter()
            .map(|c| c.der().to_vec())
            .collect();
        let key_info = match config.profile.token_ref() {
            TokenRef::PkiPath => crate::crypto::wssec::WsSecOutboundKeyInfoProfile::X509PKIPathv1,
            TokenRef::X509v3 => {
                crate::crypto::wssec::WsSecOutboundKeyInfoProfile::BinarySecurityTokenX509v3
            }
        };
        super::signals::finish_signal(draft, raw, &chain, key_info).map_err(|e| e.to_string())
    }
}

fn error_body(
    now: std::time::SystemTime,
    ref_to: Option<&str>,
    code: &str,
    short: &str,
    category: &str,
    description: &str,
    detail: Option<&str>,
) -> Vec<u8> {
    let id = super::client::fresh_message_id().unwrap_or_else(|_| "error@asx".to_string());
    super::signals::error_signal(now, &id, ref_to, code, short, category, description, detail)
        .unwrap_or_default()
}

/// The HTTP response for a refused message.
fn refusal(err: &AsxError, now: std::time::SystemTime) -> http::Response<Full<Bytes>> {
    let (status, code, short, category) = if err.code == ErrorCode::PayloadTooLarge {
        return empty(StatusCode::PAYLOAD_TOO_LARGE);
    } else if err.context.stage == super::receive::TO_PARTY_STAGE {
        (StatusCode::BAD_REQUEST, "EBMS:0004", "Other", "Content")
    } else if err
        .message
        .contains("signature is required but not present")
    {
        // Unsigned where the profile requires a signature.
        (
            StatusCode::BAD_REQUEST,
            "EBMS:0103",
            "PolicyNoncompliance",
            "Processing",
        )
    } else if err.context.stage.contains("decompress") {
        (
            StatusCode::BAD_REQUEST,
            "EBMS:0303",
            "DecompressionFailure",
            "Content",
        )
    } else {
        match err.code {
            ErrorCode::DecryptionFailed => (
                StatusCode::BAD_REQUEST,
                "EBMS:0102",
                "FailedDecryption",
                "Processing",
            ),
            ErrorCode::SecurityVerificationFailed
            | ErrorCode::CertificateExpired
            | ErrorCode::CertificateRevoked => (
                StatusCode::BAD_REQUEST,
                "EBMS:0101",
                "FailedAuthentication",
                "Processing",
            ),
            ErrorCode::PolicyViolation => (
                StatusCode::BAD_REQUEST,
                "EBMS:0103",
                "PolicyNoncompliance",
                "Processing",
            ),
            _ => (StatusCode::BAD_REQUEST, "EBMS:0004", "Other", "Content"),
        }
    };
    // The decryption failure text is uniform: never the cause.
    let description = if code == "EBMS:0102" {
        "decryption failed".to_string()
    } else {
        err.message.clone()
    };
    let body = error_body(
        now,
        err.context.message_id.as_deref(),
        code,
        short,
        category,
        &description,
        None,
    );
    with_body(status, SOAP, body)
}

// ── Sender authorization ─────────────────────────────────────────────────────

struct Authorizer<'a> {
    client: &'a As4,
}

fn unauthorized(message: impl Into<String>) -> AsxError {
    AsxError::new(
        ErrorCode::SecurityVerificationFailed,
        message,
        ErrorContext::new("as4_inbound_authorize"),
    )
}

impl SenderAuthorizer for Authorizer<'_> {
    fn authorize(
        &self,
        parsed: &super::ParsedAs4UserMessage,
    ) -> crate::core::Result<SenderAuthorization> {
        let config = self.client.config();
        let from = parsed.sender_party_id().to_string();
        let registered = config.policy_for(parsed.from_party_type.as_deref(), &from);
        let rule = config.profile.sender_rule();
        if registered.is_none() && rule == SenderRule::RegisteredOnly {
            return Err(unauthorized(format!(
                "the sender {from:?} is not a configured partner"
            )));
        }
        let check: Option<Box<crate::crypto::wssec::verify::SignerCheck>> = match rule {
            SenderRule::AnchorAndSubject => {
                let from = from.clone();
                Some(Box::new(move |der: &[u8]| {
                    let cert = Certificate::from_der(der)
                        .map_err(|_| unauthorized("the signer certificate is unreadable"))?;
                    if crate::builder::bdew_subject_carries(&cert, &from) {
                        Ok(())
                    } else {
                        Err(unauthorized(format!(
                            "the signer's subject (OU) does not carry the claimed MP-ID {from:?} \
                             (BDEW AS4-Profil 1.2 §2.3.2, §2.3.4.4)"
                        )))
                    }
                }))
            }
            SenderRule::AnchorAndCn => {
                let from = from.clone();
                Some(Box::new(move |der: &[u8]| {
                    let cert = Certificate::from_der(der)
                        .map_err(|_| unauthorized("the signer certificate is unreadable"))?;
                    if cert.subject_cn().as_deref() == Some(from.as_str()) {
                        Ok(())
                    } else {
                        Err(unauthorized(format!(
                            "the signer's CN is not the claimed party {from:?} (Peppol AS4 §4.5)"
                        )))
                    }
                }))
            }
            SenderRule::RegisteredOnly => None,
        };
        let pins = registered.map(|p| p.pins.clone()).unwrap_or_default();
        if pins.is_empty() && check.is_none() {
            return Err(unauthorized(format!(
                "no pinned signing certificate for {from:?}"
            )));
        }
        Ok(SenderAuthorization { pins, check })
    }
}

// ── Key selection and the second pass ───────────────────────────────────────

struct LocalKey {
    cert: Certificate,
    key_pair: Option<KeyPair>,
}

struct Keys {
    keys: Vec<LocalKey>,
    deferred: Vec<Deferred>,
    pending: Arc<Mutex<Vec<(usize, OwnedKeyOp)>>>,
}

impl Keys {
    fn new(client: &As4, answers: Answers) -> Self {
        let pending: Arc<Mutex<Vec<(usize, OwnedKeyOp)>>> = Arc::default();
        let decrypters = &client.config().local.decrypters;
        Keys {
            keys: decrypters
                .iter()
                .map(|d| LocalKey {
                    cert: d.decrypter.certificate().clone(),
                    key_pair: d.key_pair.clone(),
                })
                .collect(),
            deferred: (0..decrypters.len())
                .map(|index| Deferred {
                    index,
                    answers: answers.clone(),
                    pending: pending.clone(),
                })
                .collect(),
            pending,
        }
    }

    fn take_pending(&self) -> Vec<(usize, OwnedKeyOp)> {
        std::mem::take(&mut *self.pending.lock().unwrap_or_else(|e| e.into_inner()))
    }
}

impl xmlenc::RecipientKeys for Keys {
    fn select(
        &self,
        spec: &xmlenc::EncryptedKeySpec,
    ) -> Option<(xmlenc::RecipientKey, &dyn xmlenc::PrivateKeyStep)> {
        let matching: Vec<usize> = (0..self.keys.len())
            .filter(|&i| {
                let cert = &self.keys[i].cert;
                match &spec.recipient {
                    Some(RecipientRef::Ski(ski)) => cert.ski_candidates().contains(ski),
                    Some(RecipientRef::Certificate(der)) => cert.der() == der.as_slice(),
                    Some(RecipientRef::IssuerSerial { issuer, serial }) => {
                        issuer_serial_matches(cert, issuer, serial)
                    }
                    // Selection is by reference only, never by trial or by
                    // key type: no reference, no key.
                    None => false,
                }
            })
            .collect();
        let [index] = matching.as_slice() else {
            return None;
        };
        let key = &self.keys[*index];
        let recipient = crate::keys::recipient_key(&key.cert)?;
        let decrypter: &dyn xmlenc::PrivateKeyStep = match &key.key_pair {
            Some(pair) => pair,
            None => &self.deferred[*index],
        };
        Some((recipient, decrypter))
    }
}

/// An external decrypter on the synchronous seam: answers from the previous
/// pass, or records the operation and fails (uniformly) for this one.
struct Deferred {
    index: usize,
    answers: Answers,
    pending: Arc<Mutex<Vec<(usize, OwnedKeyOp)>>>,
}

impl xmlenc::PrivateKeyStep for Deferred {
    fn decrypt(&self, op: xmlenc::KeyOp<'_>) -> crate::core::Result<Zeroizing<Vec<u8>>> {
        let fail = || {
            AsxError::new(
                ErrorCode::DecryptionFailed,
                "XML Encryption decryption failed",
                ErrorContext::new("wssec_xmlenc"),
            )
        };
        let owned = crate::keys::public_op(&op).ok_or_else(fail)?;
        let key = (self.index, owned);
        let answered = self
            .answers
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&key)
            .cloned();
        match answered {
            Some(Some(secret)) => Ok(secret),
            Some(None) => Err(fail()),
            None => {
                self.pending
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .push(key);
                Err(fail())
            }
        }
    }
}

/// `ds:X509IssuerSerial`: the decimal serial and the issuer DN, compared
/// attribute by attribute in either order (RFC 2253 reverses it).
fn issuer_serial_matches(cert: &Certificate, issuer: &str, serial: &str) -> bool {
    let Ok(wanted) = openssl::bn::BigNum::from_dec_str(serial.trim()) else {
        return false;
    };
    let Ok(own) = cert.x509().serial_number().to_bn() else {
        return false;
    };
    if own != wanted {
        return false;
    }
    let normalize = |s: &str| -> Vec<String> {
        s.split(',')
            .map(|part| {
                let (k, v) = part.split_once('=').unwrap_or((part, ""));
                format!("{}={}", k.trim().to_ascii_uppercase(), v.trim())
            })
            .collect()
    };
    let mut ours: Vec<String> = cert
        .x509()
        .issuer_name()
        .entries()
        .map(|e| {
            format!(
                "{}={}",
                e.object()
                    .nid()
                    .short_name()
                    .unwrap_or("?")
                    .to_ascii_uppercase(),
                String::from_utf8_lossy(e.data().as_slice()).trim()
            )
        })
        .collect();
    let theirs = normalize(issuer);
    if ours == theirs {
        return true;
    }
    ours.reverse();
    ours == theirs
}
