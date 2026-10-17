//! `As4::send`: construction, the signer `await`, packaging, the HTTP
//! exchange and receipt verification.

use super::client::{As4, Message, MessageKind, as4_receipt, check_message, check_validity_at_use};
use super::receipt_verify::{As4SyncSignal, outbound_record, verify_signal};
use super::send::{DraftInputs, PrimaryPartOverrides, draft_send, finish_send};
use super::types::As4SendOutput;
use super::{As4AdditionalPayload, mime_packaging::PayloadFilename};
use crate::core::SessionContext;
use crate::error::{Error, ErrorKind, Result, Stage};
use crate::keys::Certificate;
use crate::profile::{PartnerPolicy, Quirk};
use crate::verified::{Receipt, Verified};

pub(crate) async fn send(client: &As4, message: Message) -> Result<Verified<Receipt>> {
    let config = client.config();
    let registered = config.partners.get(&message.partner.key()).map(|policy| {
        (
            policy.clone(),
            client.0.sessions.get(&message.partner.key()).cloned(),
        )
    });
    let (policy, session) = match registered {
        Some((policy, Some(session))) => (policy, session),
        _ => {
            // An unregistered partner (e.g. from SMP) is validated at send time.
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
    // A path-switch message has nothing to encrypt.
    let payload_less = matches!(message.kind, MessageKind::PathSwitch(_));
    let recipient = policy.encryption_cert.clone();
    if recipient.is_none() && !payload_less {
        return Err(Error::config(format!(
            "Partner({})::encryption_cert: no certificate to encrypt to",
            message.partner.id()
        )));
    }
    check_validity_at_use(config, &policy)?;
    let checked = check_message(config, &policy, &message)?;
    let view = policy.send_view(&checked.header);
    let profile = &config.profile;

    // Only a path-switch message has no primary part.
    let mut parts = message.payloads.into_iter();
    let primary = parts.next();
    let filename = |name: Option<&str>| -> Result<Option<PayloadFilename>> {
        name.map(|n| {
            PayloadFilename::new(n).map_err(|err| Error::config(format!("Payload::named: {err}")))
        })
        .transpose()
    };
    let part_type = |declared: &str| {
        profile
            .fixed_part_type()
            .map(str::to_owned)
            .unwrap_or_else(|| declared.to_string())
    };
    let mut additional = Vec::new();
    for part in parts {
        let mut extra =
            As4AdditionalPayload::new(part.bytes().to_vec(), part_type(part.mime_type()));
        if let Some(name) = filename(part.name())? {
            extra = extra.with_filename(name);
        }
        additional.push(extra);
    }
    let signer = &config.local.signer_ref().signer;
    let algorithm = profile.signature_algorithm();
    let chain_der: Vec<Vec<u8>> = signer
        .certificate_chain()
        .iter()
        .map(|c| c.der().to_vec())
        .collect();
    let inputs = DraftInputs {
        message_id: checked.message_id.clone(),
        payload: primary.as_ref().map(|p| p.bytes().to_vec()),
        policy: view,
        payload_filename: filename(primary.as_ref().and_then(|p| p.name()))?,
        primary_overrides: PrimaryPartOverrides {
            mime_type: primary.as_ref().map(|p| part_type(p.mime_type())),
            content_id: None,
        },
        additional_payloads: additional,
        timestamp: Some(checked.timestamp.clone()),
        signer: Some((algorithm.internal(), chain_der)),
        content_disposition: profile.filename_allowed(),
    };
    let span = crate::telemetry::send_span("as4", &session, &checked.message_id);
    let started = tokio::time::Instant::now();
    let result = tracing::Instrument::instrument(
        exchange(client, &policy, &session, inputs, recipient, endpoint),
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
        Ok(_) => finish_send(span, "as4", SendOutcome::Delivered, None, None, started),
        Err(err) => {
            let (outcome, code) = match err.kind() {
                ErrorKind::PartnerError => (SendOutcome::PartnerError, None),
                ErrorKind::Indeterminate => (SendOutcome::Indeterminate, None),
                ErrorKind::Backend => (
                    SendOutcome::Failed("storage"),
                    Some(crate::core::ErrorCode::StorageBackendFailure),
                ),
                ErrorKind::Transport => (
                    SendOutcome::Failed("transport"),
                    Some(crate::core::ErrorCode::TransportFailure),
                ),
                _ => (
                    SendOutcome::Failed("config"),
                    Some(crate::core::ErrorCode::InvalidInput),
                ),
            };
            let internal = code.map(|code| {
                crate::core::AsxError::new(
                    code,
                    err.to_string(),
                    crate::core::ErrorContext::new("as4_send"),
                )
            });
            finish_send(
                span,
                "as4",
                outcome,
                internal.as_ref(),
                err.ebms_code(),
                started,
            );
        }
    }
}

async fn exchange(
    client: &As4,
    policy: &PartnerPolicy,
    session: &SessionContext,
    inputs: DraftInputs,
    recipient: Option<Certificate>,
    endpoint: String,
) -> Result<Verified<Receipt>> {
    let config = client.config();
    let draft = {
        let session = session.clone();
        let recipient = recipient.map(|c| c.x509().clone());
        crate::runtime::spawn_crypto("as4_send", &session.clone(), move || {
            draft_send(&session, inputs, recipient, (true, true))
        })
        .await
        .map_err(Error::internal)?
    };
    let raw = match draft.to_sign() {
        Some((algorithm, data)) => {
            let public = match algorithm {
                crate::crypto::alg::SignatureAlgorithm::EcdsaSha256 => {
                    crate::keys::SignatureAlgorithm::EcdsaSha256
                }
                _ => crate::keys::SignatureAlgorithm::RsaSha256,
            };
            let signature = config
                .local
                .signer_ref()
                .signer
                .sign(public, data)
                .await
                .map_err(|err| Error::backend("the signer failed", err))?;
            Some(signature)
        }
        None => None,
    };
    let sent: As4SendOutput = finish_send(draft, raw).map_err(Error::internal)?;

    let request = http::Request::post(endpoint.as_str())
        .header(http::header::CONTENT_TYPE, sent.http_content_type.as_str())
        .body(bytes::Bytes::from(sent.soap_envelope.body.to_vec()))
        .map_err(|err| Error::config(format!("Partner::endpoint: {err}")))?;
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
        .unwrap_or("application/soap+xml")
        .to_string();
    let body = response.into_body();
    if body.is_empty() {
        return Err(Error::new(
            ErrorKind::Indeterminate,
            format!(
                "the partner answered HTTP {} without a signal",
                status.as_u16()
            ),
        ));
    }

    let receipt_policy = policy.receipt_view();
    let (mut result, signer) = {
        let session = session.clone();
        let sent = sent.clone();
        let body = body.clone();
        let receipt_policy = receipt_policy.clone();
        crate::runtime::spawn_crypto("as4_receipt_verify", &session.clone(), move || {
            Ok(verify_signal(
                &session,
                &sent,
                &body,
                &content_type,
                &receipt_policy,
            ))
        })
        .await
        .map_err(Error::internal)?
    };
    // The receipt signer's revocation, after its signature verified; a
    // refused status leaves the delivery indeterminate.
    if result.is_ok() && !signer.path.is_empty() {
        let outcome = config.revocation.check(&signer.path).await;
        if outcome.refused() {
            result = Err(crate::core::AsxError::new(
                crate::core::ErrorCode::SecurityVerificationFailed,
                format!("receipt signer: {}", outcome.describe()),
                crate::core::ErrorContext::for_session("as4_receipt_revocation", session),
            ));
        }
    }
    // The record (it parses the sent message) on the crypto pool too.
    let (result, mut record) = {
        let session = session.clone();
        let sent = sent.clone();
        let signer_der = signer.der;
        crate::runtime::spawn_crypto("as4_receipt_record", &session.clone(), move || {
            let record =
                outbound_record(&session, &sent, &body, &receipt_policy, &result, signer_der);
            Ok((result, record))
        })
        .await
        .map_err(Error::internal)?
    };
    let quirk_applied = matches!(
        &result,
        Ok(As4SyncSignal::Receipt(r)) if !r.non_repudiation.is_verified()
    ) && policy.has_quirk(Quirk::ReceiptWithoutNonRepudiation);
    if let Some(record) = record.as_mut() {
        let quirks = if quirk_applied {
            vec![Quirk::ReceiptWithoutNonRepudiation.name().to_string()]
        } else {
            Vec::new()
        };
        record.stamp_profile(config.profile.name(), quirks);
    }
    // The record is written before the result is returned.
    let written = match &record {
        Some(record) => {
            crate::audit::record(
                config.audit.as_deref().map(|s| s as _),
                record,
                "as4_send_audit",
            )
            .await
        }
        None => Ok(()),
    };
    match result {
        Ok(As4SyncSignal::Receipt(receipt)) => {
            let record = record.expect("a verified receipt always has a record");
            if let Err(err) = written {
                return Err(Error::delivered_but_unrecorded(
                    Error::internal(err),
                    record,
                ));
            }
            let signer = record
                .signer_certificate_der()
                .and_then(|der| Certificate::from_der(der).ok())
                .ok_or_else(|| {
                    Error::new(
                        ErrorKind::Indeterminate,
                        "the verified receipt carries no signer certificate",
                    )
                })?;
            Ok(Verified::new(
                as4_receipt(&receipt.ref_to_message_id),
                signer,
                record,
            ))
        }
        Ok(As4SyncSignal::Error(signal)) => {
            let code = signal
                .errors
                .first()
                .map(|e| e.error_code.clone())
                .unwrap_or_else(|| "EBMS:0004".to_string());
            let detail = signal
                .errors
                .first()
                .and_then(|e| e.short_description.clone())
                .unwrap_or_default();
            if let Err(err) = written {
                return Err(Error::internal(err).with_evidence(record));
            }
            Err(Error::partner_ebms(
                code.clone(),
                format!("the partner refused the message with {code} {detail}"),
            )
            .retryable_if(status.is_server_error())
            .with_evidence(record))
        }
        Err(err) => {
            let mapped = Error::from_internal(Stage::ResponseVerify, err).with_evidence(record);
            if !status.is_success() && mapped.kind() == ErrorKind::Indeterminate {
                return Err(Error::new(
                    ErrorKind::Indeterminate,
                    format!(
                        "the partner answered HTTP {} without a verifiable signal: {mapped}",
                        status.as_u16()
                    ),
                )
                .with_evidence(mapped.evidence().cloned()));
            }
            Err(mapped)
        }
    }
}
