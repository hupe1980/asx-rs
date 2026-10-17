//! `As2::send`, `send_async_mdn` and `verify_async_mdn`: packaging over the
//! internal send path, the HTTP exchange, and MDN verification bound to the
//! sent id, MIC and pin.

use super::client::{
    As2, Message, PendingMdn, check_message, check_validity_at_use, header_id, mdn_verify_view,
    send_view,
};
use super::mdn::{mic_values_match, parse_disposition, parse_mdn_with_signer};
use super::{CmsSmimeTrustVerifier, ParsedMdn};
use crate::audit::{AuditOutcome, AuditRecord, Direction, Protocol, RecordBuilder, Signal};
use crate::core::{AsxError, ErrorCode, ErrorContext, SessionContext};
use crate::error::{Error, ErrorKind, Result, Stage};
use crate::keys::Certificate;
use crate::profile::{PartnerPolicy, Quirk};
use crate::verified::{Receipt, ReceiptKind, Verified};
use bytes::Bytes;
use std::sync::Arc;

/// A signed receipt with a SHA-256 MIC, always.
const MDN_OPTIONS: &str =
    "signed-receipt-protocol=optional, pkcs7-signature; signed-receipt-micalg=optional, sha-256";

/// The most of an MDN this side reads.
const MAX_MDN_BYTES: usize = super::MAX_AS2_MDN_BYTES;

/// A packaged, not yet transmitted message.
struct Outbound {
    policy: PartnerPolicy,
    session: SessionContext,
    message_id: String,
    /// `"base64, sha-256"` (RFC 4130 §7.4.3).
    mic: String,
    mic_base64: String,
    request: http::Request<Bytes>,
}

/// Resolve the partner, validate and package the message.
async fn package(client: &As2, message: Message, receipt_url: Option<&str>) -> Result<Outbound> {
    let config = client.config();
    let key = message.partner.key();
    let (policy, session) = match (config.partners.get(&key), client.0.sessions.get(&key)) {
        (Some(policy), Some(session)) => (policy.clone(), session.clone()),
        _ => {
            // An unregistered partner is validated at send time.
            crate::builder::check_partner(
                &config.profile,
                &message.partner,
                false,
                config.clock.now(),
            )?;
            let policy = crate::profile::resolve(&config.profile, &message.partner, &config.clock);
            let session = super::client::session_for(config, &policy)?;
            (policy, session)
        }
    };
    let Some(endpoint) = policy.endpoint.clone() else {
        return Err(Error::config(format!(
            "Partner({})::endpoint: no endpoint to send to",
            message.partner.id()
        )));
    };
    let Some(recipient) = policy.encryption_cert.clone() else {
        return Err(Error::config(format!(
            "Partner({})::encryption_cert: no certificate to encrypt to",
            message.partner.id()
        )));
    };
    check_validity_at_use(config, &policy)?;
    let message_id = check_message(config, &message)?;
    if let Some(url) = receipt_url {
        check_receipt_url(url)?;
    }
    let view = send_view(&policy, &config.local.id);
    let payload = message.payload;
    let entity = {
        let session = session.clone();
        let message_id = message_id.clone();
        let view = view.clone();
        crate::runtime::spawn_crypto("as2_send", &session.clone(), move || {
            super::send_path::outbound_entity(
                &session,
                &message_id,
                payload.bytes(),
                &view,
                Some(payload.mime_type()),
            )
        })
        .await
        .map_err(Error::internal)?
    };
    // The one private-key operation, through the `Signer`: a failing
    // signer is `Backend` and nothing is sent.
    let signer = config.local.signer_ref().signer.clone();
    let signed =
        super::cms_keys::sign_detached(signer.as_ref(), &entity.entity, config.clock.now())
            .await
            .map_err(super::cms_keys::SignError::into_error)?;
    let mime = {
        let recipient = recipient.clone();
        crate::runtime::spawn_crypto("as2_send", &session.clone(), move || {
            super::send_path::envelope(signed, Some(recipient.x509()), &view, None)
        })
        .await
        .map_err(Error::internal)?
    };
    let sent_mic_base64 = entity.mic_base64;
    let sent_digest_alg = entity.digest_alg;

    let mut request = http::Request::post(endpoint.as_str())
        .header("AS2-Version", "1.2")
        .header("AS2-From", header_id(&config.local.id))
        .header("AS2-To", header_id(message.partner.id()))
        .header("Message-ID", format!("<{message_id}>"))
        .header("MIME-Version", "1.0")
        .header(http::header::CONTENT_TYPE, mime.content_type.as_str())
        .header("Disposition-Notification-To", header_id(&config.local.id))
        .header("Disposition-Notification-Options", MDN_OPTIONS);
    if let Some(url) = receipt_url {
        request = request.header("Receipt-Delivery-Option", url);
    }
    let request = request
        .body(Bytes::from(mime.body.to_vec()))
        .map_err(|err| Error::config(format!("Partner::endpoint: {err}")))?;
    Ok(Outbound {
        policy,
        session,
        message_id,
        mic: format!("{sent_mic_base64}, {sent_digest_alg}"),
        mic_base64: sent_mic_base64,
        request,
    })
}

fn check_receipt_url(url: &str) -> Result<()> {
    let refuse =
        |detail: &str| Error::config(format!("send_async_mdn: receipt_url {url:?} {detail}"));
    if url.bytes().any(|b| b.is_ascii_control()) {
        return Err(refuse("contains a control character"));
    }
    let parsed: http::Uri = url.parse().map_err(|_| refuse("is not a URL"))?;
    match parsed.scheme_str() {
        Some("https") | Some("http") if parsed.authority().is_some() => Ok(()),
        _ => Err(refuse("is not an absolute http(s) URL")),
    }
}

pub(super) async fn send(client: &As2, message: Message) -> Result<Verified<Receipt>> {
    let started = tokio::time::Instant::now();
    let outbound = package(client, message, None).await?;
    let span = crate::telemetry::send_span("as2", &outbound.session, &outbound.message_id);
    let result = tracing::Instrument::instrument(exchange(client, outbound), span.clone()).await;
    close_span(&span, started, &result);
    result
}

async fn exchange(client: &As2, outbound: Outbound) -> Result<Verified<Receipt>> {
    let config = client.config();
    let Outbound {
        policy,
        session,
        message_id,
        mic,
        request,
        ..
    } = outbound;
    let response = config
        .http
        .send(request)
        .await
        .map_err(crate::http_client::classify)?;
    let status = response.status();
    let content_type = response
        .headers()
        .get(http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let body = response.into_body();
    if body.is_empty() {
        return Err(Error::new(
            ErrorKind::Indeterminate,
            format!(
                "the partner answered HTTP {} without an MDN",
                status.as_u16()
            ),
        ));
    }
    verify_mdn(
        client,
        &policy,
        &session,
        &message_id,
        &mic,
        body,
        content_type,
        status,
    )
    .await
}

pub(super) async fn send_async_mdn(
    client: &As2,
    message: Message,
    receipt_url: &str,
) -> Result<PendingMdn> {
    let started = tokio::time::Instant::now();
    let outbound = package(client, message, Some(receipt_url)).await?;
    let span = crate::telemetry::send_span("as2", &outbound.session, &outbound.message_id);
    let pending = PendingMdn {
        v: 1,
        message_id: outbound.message_id.clone(),
        partner: outbound
            .policy
            .partner
            .as_ref()
            .map(|p| p.key())
            .unwrap_or_default(),
        mic: outbound.mic_base64.clone(),
        mic_alg: "sha-256".to_string(),
        signed: true,
        sent_at: crate::time_utils::format_rfc3339_secs(outbound.policy.clock.now()),
    };
    let http = client.config().http.clone();
    let result: Result<PendingMdn> = tracing::Instrument::instrument(
        async move {
            let response = http
                .send(outbound.request)
                .await
                .map_err(crate::http_client::classify)?;
            if response.status().is_success() {
                Ok(pending)
            } else {
                Err(Error::new(
                    ErrorKind::Indeterminate,
                    format!(
                        "the partner answered HTTP {} to a message requesting an asynchronous MDN",
                        response.status().as_u16()
                    ),
                ))
            }
        },
        span.clone(),
    )
    .await;
    {
        use crate::telemetry::{SendOutcome, finish_send};
        match &result {
            // The leg is open until the MDN arrives.
            Ok(_) => finish_send(&span, "as2", SendOutcome::Delivered, None, None, started),
            Err(_) => close_span(
                &span,
                started,
                &Err(Error::new(ErrorKind::Indeterminate, "")),
            ),
        }
    }
    result
}

pub(super) async fn verify_async_mdn(
    client: &As2,
    request: http::Request<Bytes>,
    pending: &PendingMdn,
) -> Result<Verified<Receipt>> {
    let not_ours = |detail: String| {
        Error::from_internal(
            Stage::AsyncMdnMatch,
            AsxError::new(
                ErrorCode::InvalidInput,
                detail,
                ErrorContext::new("as2_verify_async_mdn"),
            ),
        )
    };
    let claimed = PendingMdn::lookup_key(&request).ok_or_else(|| {
        not_ours("the request is not an MDN (no Original-Message-ID)".to_string())
    })?;
    if claimed != pending.message_id {
        return Err(not_ours(format!(
            "the MDN answers {claimed:?}, not the pending message {:?}",
            pending.message_id
        )));
    }
    let config = client.config();
    let key = pending.partner.clone();
    let policy = config
        .partners
        .get(&key)
        .or_else(|| config.policy_for(key.0.as_deref(), &key.1))
        .cloned()
        .ok_or_else(|| {
            Error::config(format!(
                "Partner({}): the partner of this PendingMdn is not configured",
                key.1
            ))
        })?;
    let partner_key = policy
        .partner
        .as_ref()
        .map(|p| p.key())
        .unwrap_or_else(|| key.clone());
    let session = match client.0.sessions.get(&partner_key) {
        Some(session) => session.clone(),
        None => super::client::session_for(config, &policy)?,
    };
    let content_type = request
        .headers()
        .get(http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let mic = format!("{}, {}", pending.mic, pending.mic_alg);
    let span = crate::telemetry::send_span("as2", &session, &pending.message_id);
    let started = tokio::time::Instant::now();
    let result = tracing::Instrument::instrument(
        verify_mdn(
            client,
            &policy,
            &session,
            &pending.message_id,
            &mic,
            request.into_body(),
            content_type,
            http::StatusCode::OK,
        ),
        span.clone(),
    )
    .await;
    close_span(&span, started, &result);
    result
}

fn close_span(
    span: &tracing::Span,
    started: tokio::time::Instant,
    result: &Result<Verified<Receipt>>,
) {
    use crate::telemetry::{SendOutcome, finish_send};
    match result {
        Ok(_) => finish_send(span, "as2", SendOutcome::Delivered, None, None, started),
        Err(err) => {
            let outcome = match err.kind() {
                ErrorKind::PartnerError => SendOutcome::PartnerError,
                ErrorKind::Indeterminate => SendOutcome::Indeterminate,
                ErrorKind::Backend => SendOutcome::Failed("storage"),
                ErrorKind::Transport => SendOutcome::Failed("transport"),
                _ => SendOutcome::Failed("config"),
            };
            let internal = AsxError::new(
                ErrorCode::TransportFailure,
                err.to_string(),
                ErrorContext::new("as2_send"),
            );
            finish_send(span, "as2", outcome, Some(&internal), None, started);
        }
    }
}

// ── MDN verification ────────────────────────────────────────────────────────

/// The verdict on one MDN, before the audit record is written.
enum Verdict {
    Delivered {
        disposition: String,
        warning: Option<String>,
    },
    Refused {
        disposition: String,
    },
    Indeterminate(AsxError),
}

struct Checked {
    parsed: Option<ParsedMdn>,
    signer_der: Option<Vec<u8>>,
    /// The verified signer's path (signer first, anchor last).
    signer_path: Vec<openssl::x509::X509>,
    /// An unsigned MDN accepted under [`Quirk::UnsignedMdn`].
    unsigned_accepted: bool,
    verdict: Verdict,
}

fn verify_failed(message: impl Into<String>) -> AsxError {
    AsxError::new(
        ErrorCode::SecurityVerificationFailed,
        message,
        ErrorContext::new("as2_mdn_verify"),
    )
}

/// Signature (by a pin, or absent under `UnsignedMdn`), Original-Message-ID,
/// disposition and MIC — in that order.
fn check_mdn(
    session: &SessionContext,
    policy: &PartnerPolicy,
    require_signed: bool,
    raw: &[u8],
    content_type: Option<&str>,
    expected_id: &str,
    expected_mic: &str,
) -> Checked {
    let indeterminate = |err: AsxError| Checked {
        parsed: None,
        signer_der: None,
        signer_path: Vec::new(),
        unsigned_accepted: false,
        verdict: Verdict::Indeterminate(err),
    };
    if raw.len() > MAX_MDN_BYTES {
        return indeterminate(AsxError::new(
            ErrorCode::PayloadTooLarge,
            format!("the MDN exceeds {MAX_MDN_BYTES} bytes"),
            ErrorContext::new("as2_mdn_verify"),
        ));
    }
    // Partners differ in whether the HTTP body repeats the MIME headers.
    let original: Arc<[u8]> = Arc::from(raw);
    let entity = super::body_with_mime_headers(session, &original, content_type);
    let verifier = CmsSmimeTrustVerifier::default();
    let (parsed, signer_der, signer_path) =
        match parse_mdn_with_signer(&entity, require_signed, session, &verifier) {
            Ok(parsed) => parsed,
            Err(err) => return indeterminate(err),
        };
    let mut checked = Checked {
        unsigned_accepted: !parsed.is_signed,
        parsed: Some(parsed),
        signer_der,
        signer_path,
        verdict: Verdict::Indeterminate(verify_failed("unverified")),
    };
    let parsed = checked.parsed.as_ref().expect("set above");
    // The signer must be a pin of this partner.
    if parsed.is_signed {
        let pinned = checked
            .signer_der
            .as_deref()
            .and_then(|der| Certificate::from_der(der).ok())
            .is_some_and(|cert| policy.pins.contains(cert.fingerprint()));
        if !pinned {
            checked.verdict = Verdict::Indeterminate(verify_failed(
                "the MDN is not signed by a pinned certificate of the partner",
            ));
            return checked;
        }
    }
    let answers_ours = parsed
        .original_message_id
        .as_deref()
        .is_some_and(|id| super::normalize_message_id(id) == expected_id);
    if !answers_ours {
        checked.verdict = Verdict::Indeterminate(verify_failed(format!(
            "the MDN Original-Message-ID {:?} is not the sent message {expected_id:?}",
            parsed.original_message_id.as_deref().unwrap_or("<absent>")
        )));
        return checked;
    }
    let action = parsed
        .disposition
        .split_once(';')
        .map(|(_, action)| action.trim().to_string())
        .unwrap_or_default();
    let disposition = parse_disposition(&parsed.disposition);
    // `error: decryption-failed` → `error`.
    let modifier = disposition
        .modifier
        .map(|m| m.split(':').next().unwrap_or(m).trim().to_ascii_lowercase());
    let processed = disposition
        .disposition_type
        .eq_ignore_ascii_case("processed");
    checked.verdict = if disposition.disposition_type.eq_ignore_ascii_case("failed")
        || (processed && modifier.as_deref() == Some("error"))
    {
        Verdict::Refused {
            disposition: action,
        }
    } else if processed && matches!(modifier.as_deref(), None | Some("warning")) {
        match parsed.received_content_mic.as_deref() {
            Some(actual) if mic_values_match(actual, expected_mic) => Verdict::Delivered {
                warning: (modifier.is_some()).then(|| {
                    action
                        .split_once(':')
                        .map(|(_, w)| w.trim().to_string())
                        .unwrap_or_default()
                }),
                disposition: action,
            },
            Some(_) => Verdict::Indeterminate(verify_failed(
                "the MDN Received-Content-MIC does not match the MIC of the sent message",
            )),
            None => Verdict::Indeterminate(verify_failed(
                "the processed MDN carries no Received-Content-MIC",
            )),
        }
    } else {
        Verdict::Indeterminate(AsxError::new(
            ErrorCode::InteropViolation,
            format!(
                "the MDN disposition {action:?} is not processed, processed/warning, processed/error or failed"
            ),
            ErrorContext::new("as2_mdn_verify"),
        ))
    };
    checked
}

/// Verify an MDN answering `expected_id` inside the `asx.mdn` span, write its
/// audit record and return it as the one `Verified<Receipt>` of AS2.
#[allow(clippy::too_many_arguments)]
async fn verify_mdn(
    client: &As2,
    policy: &PartnerPolicy,
    session: &SessionContext,
    expected_id: &str,
    expected_mic: &str,
    body: Bytes,
    content_type: Option<String>,
    status: http::StatusCode,
) -> Result<Verified<Receipt>> {
    let span = tracing::debug_span!(
        target: "asx",
        "asx.mdn",
        message_id = expected_id,
        disposition = tracing::field::Empty,
        signed = tracing::field::Empty,
        outcome = tracing::field::Empty,
    );
    let mut signed = false;
    let result = tracing::Instrument::instrument(
        verify_mdn_inner(
            client,
            policy,
            session,
            expected_id,
            expected_mic,
            body,
            content_type,
            status,
            &span,
            &mut signed,
        ),
        span.clone(),
    )
    .await;
    crate::telemetry::child_outcome(&span, &result);
    let nrr = match &result {
        Ok(_) if signed => "verified",
        Ok(_) => "absent",
        Err(_) => "n/a",
    };
    crate::telemetry::receipt_verified("as2", result.is_ok(), nrr);
    result
}

/// The `asx.mdn` `disposition` value: the disposition type and the class of
/// its modifier (`processed`, `processed/warning`, `failed`, ...), never the
/// partner's free text.
fn disposition_class(disposition: &str) -> String {
    let parsed = parse_disposition(disposition);
    let kind = parsed.disposition_type.to_ascii_lowercase();
    match parsed.modifier {
        Some(m) => format!(
            "{kind}/{}",
            m.split(':').next().unwrap_or(m).trim().to_ascii_lowercase()
        ),
        None => kind,
    }
}

#[allow(clippy::too_many_arguments)]
async fn verify_mdn_inner(
    client: &As2,
    policy: &PartnerPolicy,
    session: &SessionContext,
    expected_id: &str,
    expected_mic: &str,
    body: Bytes,
    content_type: Option<String>,
    status: http::StatusCode,
    span: &tracing::Span,
    signed: &mut bool,
) -> Result<Verified<Receipt>> {
    let config = client.config();
    let view = mdn_verify_view(policy);
    let checked = {
        let session = session.clone();
        let policy = policy.clone();
        let body = body.clone();
        let expected_id = expected_id.to_string();
        let expected_mic = expected_mic.to_string();
        let require_signed = view.require_signed_mdn;
        crate::runtime::spawn_crypto("as2_mdn_verify", &session.clone(), move || {
            Ok(check_mdn(
                &session,
                &policy,
                require_signed,
                &body,
                content_type.as_deref(),
                &expected_id,
                &expected_mic,
            ))
        })
        .await
        .map_err(Error::internal)?
    };
    if let Some(parsed) = &checked.parsed {
        span.record("signed", parsed.is_signed);
        *signed = parsed.is_signed;
        span.record(
            "disposition",
            disposition_class(&parsed.disposition).as_str(),
        );
    }
    // The MDN signer's revocation, after the signature and the pin; a refused
    // status leaves the delivery indeterminate.
    let mut checked = checked;
    if !matches!(checked.verdict, Verdict::Indeterminate(_)) && !checked.signer_path.is_empty() {
        let outcome = config.revocation.check(&checked.signer_path).await;
        if outcome.refused() {
            checked.verdict = Verdict::Indeterminate(verify_failed(format!(
                "MDN signer: {}",
                outcome.describe()
            )));
        }
    }

    let quirk_applied = checked.unsigned_accepted
        && policy.has_quirk(Quirk::UnsignedMdn)
        && checked.parsed.is_some();
    let record = mdn_record(
        config,
        policy,
        expected_id,
        expected_mic,
        &body,
        &checked,
        quirk_applied,
    );
    // The record is written before the result is returned.
    let written = match &record {
        Some(record) => {
            crate::audit::record(
                config.audit.as_deref().map(|s| s as _),
                record,
                "as2_send_audit",
            )
            .await
        }
        None => Ok(()),
    };
    match checked.verdict {
        Verdict::Delivered {
            disposition,
            warning,
        } => {
            let Some(record) = record else {
                return Err(Error::new(
                    ErrorKind::Indeterminate,
                    "the verified MDN's evidence could not be built",
                ));
            };
            if let Err(err) = written {
                return Err(Error::delivered_but_unrecorded(
                    Error::internal(err),
                    record,
                ));
            }
            let signer = match checked.signer_der.as_deref() {
                Some(der) => Certificate::from_der(der).ok(),
                // UnsignedMdn: nothing signed; the partner's pinned
                // certificate names whom the MDN is attributed to, and the
                // evidence records the quirk and no signer.
                None => policy
                    .partner
                    .as_ref()
                    .and_then(|p| p.signing_certs().first().cloned()),
            }
            .ok_or_else(|| {
                Error::new(
                    ErrorKind::Indeterminate,
                    "the verified MDN carries no signer certificate",
                )
                .with_evidence(Some(record.clone()))
            })?;
            Ok(Verified::new(
                Receipt::new(
                    expected_id,
                    ReceiptKind::Mdn {
                        disposition,
                        warning,
                    },
                ),
                signer,
                record,
            ))
        }
        Verdict::Refused { disposition } => {
            if let Err(err) = written {
                return Err(Error::internal(err).with_evidence(record));
            }
            Err(Error::partner_mdn(
                disposition.clone(),
                format!("the partner refused the message: {disposition}"),
            )
            .retryable_if(status.is_server_error())
            .with_evidence(record))
        }
        Verdict::Indeterminate(err) => {
            let mapped = Error::from_internal(Stage::ResponseVerify, err).with_evidence(record);
            if !status.is_success() {
                return Err(Error::new(
                    ErrorKind::Indeterminate,
                    format!(
                        "the partner answered HTTP {} without a verifiable MDN: {mapped}",
                        status.as_u16()
                    ),
                )
                .with_evidence(mapped.evidence().cloned()));
            }
            Err(mapped)
        }
    }
}

/// The audit record of a send leg answered by an MDN: the MIC we computed,
/// the disposition verbatim, the MDN as received.
fn mdn_record(
    config: &crate::builder::ClientConfig,
    policy: &PartnerPolicy,
    message_id: &str,
    expected_mic: &str,
    raw: &[u8],
    checked: &Checked,
    quirk_applied: bool,
) -> Option<AuditRecord> {
    let partner = policy
        .partner
        .as_ref()
        .map(|p| p.id().to_string())
        .unwrap_or_default();
    let parsed = checked.parsed.as_ref();
    let ref_to = parsed
        .and_then(|p| p.original_message_id.as_deref())
        .filter(|id| super::normalize_message_id(id) == message_id);
    let mut builder = RecordBuilder::new(
        &policy.clock,
        Protocol::As2,
        Direction::Outbound,
        message_id,
        config.local.id.as_str(),
        partner,
    )
    .profile(Some(config.profile.name()))
    .disposition(parsed.map(|p| p.disposition.as_str()))
    .signer_der(checked.signer_der.clone())
    .signal(Signal {
        bytes: raw,
        message_id: None,
        ref_to_message_id: ref_to,
        timestamp: None,
        signed: parsed.is_some_and(|p| p.is_signed),
        nrr: &[],
    });
    if let Some((algorithm, value)) = super::split_mic(expected_mic) {
        builder = builder.mic(algorithm, value);
    }
    let (outcome, error_kind) = match &checked.verdict {
        Verdict::Delivered { .. } => (AuditOutcome::Delivered, None),
        Verdict::Refused { .. } => (AuditOutcome::PartnerError, Some("partner_error")),
        Verdict::Indeterminate(_) => (AuditOutcome::Indeterminate, Some("indeterminate")),
    };
    let mut record = builder.finish(outcome, error_kind).ok()?;
    let quirks = if quirk_applied {
        vec![Quirk::UnsignedMdn.name().to_string()]
    } else {
        Vec::new()
    };
    record.stamp_profile(config.profile.name(), quirks);
    Some(record)
}
