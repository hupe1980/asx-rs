use super::super::large_message::{As4FragmentJoiner, As4JoinProgress, parse_fragment_envelope};
use super::super::services::emit_receive_push_signed_encrypted;
use super::super::stream::MultipartAs4Payload;
use super::super::types::{
    As4PushPolicy, As4ReceivePushOutput, As4ReceivePushProgress, As4ReceivedPayload,
    FragmentScopePolicy,
};
use super::{As4PushReceiveCtx, metadata, payload, receipt};
use crate::core::{AsxError, ErrorCode, ErrorContext, PayloadInput, Result, SessionContext};
use crate::lifecycle::DomainReady;
use crate::observability::EventBus;
use crate::sbdh::SbdhHeader;
use memchr::memmem;
use std::sync::Arc;

/// Return type for verified payload + optional SBDH header.
/// `(primary payload, primary Content-ID, additional payloads, SBDH header)`
type VerifiedPayloadWithSbdh = (
    DomainReady<Arc<[u8]>>,
    String,
    Vec<As4ReceivedPayload>,
    Option<SbdhHeader>,
);

pub(super) fn maybe_handle_fragment_message(
    ctx: &As4PushReceiveCtx<'_>,
    payload_bytes: &[u8],
    receipt_payload: Option<&[u8]>,
    http_content_type: &str,
    fragment_joiner: Option<&mut As4FragmentJoiner>,
    authenticated_sender_scope: Option<&str>,
) -> Result<Option<As4ReceivePushProgress>> {
    // Fragment messages are always multipart/related (ebMS3 Part 2 §5).
    // Plain application/soap+xml envelopes cannot carry mf:MessageFragment,
    // so skip the full-payload memmem scan for the common non-fragment path.
    if !http_content_type
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .eq_ignore_ascii_case("multipart/related")
    {
        return Ok(None);
    }
    if memmem::find(payload_bytes, b"MessageFragment").is_none() {
        return Ok(None);
    }

    let parsed_fragment = parse_fragment_envelope(http_content_type, payload_bytes)?;
    let Some(joiner) = fragment_joiner else {
        return Err(AsxError::new(
            ErrorCode::PolicyViolation,
            "AS4 message contains mf:MessageFragment; use fragment-aware receive API",
            ErrorContext::for_session("as4_receive_push", ctx.session),
        ));
    };

    // Enforce fragment scope policy.  RequireAuthenticatedScope (the default) prevents
    // cross-sender fragment injection by keying groups on the transport-layer identity
    // rather than the unauthenticated SOAP <eb:From> party ID.
    let join_progress = match ctx.policy.fragment_scope_policy {
        FragmentScopePolicy::RequireAuthenticatedScope => {
            let scope = authenticated_sender_scope.ok_or_else(|| {
                AsxError::new(
                    ErrorCode::PolicyViolation,
                    "As4PushPolicy::fragment_scope_policy is RequireAuthenticatedScope \
                     but As4ReceivePushRequest::authenticated_sender_scope is None; \
                     supply the transport-layer identity (e.g., mTLS client cert CN) \
                     or set fragment_scope_policy to UseSoapSenderId for trusted networks",
                    ErrorContext::for_session("as4_receive_push", ctx.session),
                )
            })?;
            joiner.ingest_parsed_fragment_with_authenticated_scope(scope, parsed_fragment)
        }
        FragmentScopePolicy::UseSoapSenderId => joiner.ingest_parsed_fragment(parsed_fragment),
    }?;

    match join_progress {
        As4JoinProgress::Pending {
            group_id,
            received_fragments,
            expected_fragments,
        } => Ok(Some(As4ReceivePushProgress::PendingFragment {
            group_id,
            received_fragments,
            expected_fragments,
        })),
        As4JoinProgress::Complete(joined) => {
            complete_fragment_joined_message(ctx, receipt_payload, joined)
        }
    }
}

fn complete_fragment_joined_message(
    ctx: &As4PushReceiveCtx<'_>,
    receipt_payload: Option<&[u8]>,
    joined: super::super::large_message::As4JoinedLargeMessage,
) -> Result<Option<As4ReceivePushProgress>> {
    let progress = super::receive_push_with_dedup_inner(
        ctx,
        PayloadInput::Owned(joined.body),
        receipt_payload,
        joined.http_content_type.as_str(),
        None, // fragment_joiner: joined message is processed as a regular push
        None, // authenticated_sender_scope: not applicable for reassembled messages
    )?;
    Ok(Some(progress))
}

pub(super) fn process_non_fragment_push(
    ctx: &As4PushReceiveCtx<'_>,
    payload_bytes: &[u8],
    receipt_payload: Option<&[u8]>,
    http_content_type: &str,
) -> Result<As4ReceivePushProgress> {
    let (multipart, soap_bytes, parsed, gate, is_duplicate) =
        metadata::parse_verify_and_emit_receive_push_metadata(
            ctx.session,
            ctx.event_bus,
            payload_bytes,
            http_content_type,
            ctx.policy,
            ctx.dedup_backend,
            ctx.verifier,
        )?;

    if is_duplicate {
        return Ok(As4ReceivePushProgress::Duplicate {
            message_id: parsed.message_id,
        });
    }

    enforce_non_fragment_timestamp_freshness(ctx.session, ctx.policy, &parsed)?;

    let (payload, payload_content_id, additional_payloads, sbdh_header) =
        materialize_non_fragment_payload(
            ctx.session,
            ctx.event_bus,
            ctx.policy,
            &parsed,
            multipart,
            soap_bytes,
            gate,
        )?;

    let receipt = verify_non_fragment_receipt(
        ctx.session,
        ctx.event_bus,
        receipt_payload,
        ctx.policy,
        &parsed,
    )?;

    Ok(assemble_non_fragment_output(
        payload,
        payload_content_id,
        additional_payloads,
        sbdh_header,
        parsed,
        receipt,
    ))
}

fn enforce_non_fragment_timestamp_freshness(
    #[cfg_attr(not(feature = "trace"), allow(unused_variables))] session: &SessionContext,
    policy: &As4PushPolicy,
    parsed: &super::super::ParsedAs4UserMessage,
) -> Result<()> {
    // Enforce eb:Timestamp freshness per eDelivery AS4 v1.15 §5.1.3.
    // This is a secondary replay defence on top of the dedup store: the dedup
    // TTL protects against replays while the dedup window is hot, but a
    // timestamp freshness gate rejects replays whose message_id was evicted
    // from the dedup store after TTL expiry.
    if let Some(window) = policy.timestamp_freshness_window {
        parsed
            .check_timestamp_freshness(window)
            .inspect_err(|_err| {
                #[cfg(feature = "trace")]
                tracing::warn!(
                    message_id = %parsed.message_id,
                    partner_id = %session.partner_id(),
                    "AS4 inbound message rejected: eb:Timestamp outside freshness window"
                );
            })?;
    }

    Ok(())
}

fn materialize_non_fragment_payload<'a>(
    session: &SessionContext,
    event_bus: &EventBus,
    policy: &As4PushPolicy,
    parsed: &super::super::ParsedAs4UserMessage,
    multipart: Option<MultipartAs4Payload<'a>>,
    soap_bytes: &'a [u8],
    gate: payload::WsSecVerifiedGate,
) -> Result<VerifiedPayloadWithSbdh> {
    let resolved = payload::resolve_verified_payloads(
        session,
        policy,
        &parsed.message_id,
        multipart,
        soap_bytes,
    )?;

    // The gate is a zero-sized proof that WS-Security verification covered this
    // message; every attachment was checked against it, so each promotion
    // presents its own copy.
    let _ = &gate;

    // Compression is declared in the signed eb:Messaging header, so this map is
    // integrity-protected along with the rest of the ebMS3 metadata.
    let compression_types = payload::compression_types_by_content_id(soap_bytes);

    let mut promoted: Vec<(String, DomainReady<Arc<[u8]>>)> = Vec::with_capacity(resolved.len());
    let mut sbdh_header = None;
    for (index, named) in resolved.into_iter().enumerate() {
        // Decompress before anything inspects the bytes: SBDH detection and the
        // application both need the business document, not the gzip stream.
        let named_payload = payload::decompress_payload_if_declared(
            session,
            &named.content_id,
            &compression_types,
            named.payload,
        )?;

        // SBDH wrapping applies to the business document, i.e. the primary
        // attachment. Additional parts travel as-is.
        let payload_bytes = if index == 0 {
            let (unwrapped, header) =
                payload::maybe_unwrap_sbdh_payload(session, &parsed.message_id, named_payload)?;
            sbdh_header = header;
            unwrapped
        } else {
            named_payload
        };

        let verified =
            payload::WsSecVerifiedPayload::new(payload_bytes, payload::WsSecVerifiedGate);
        promoted.push((
            named.content_id,
            payload::promote_payload_to_domain_ready(session, verified)?,
        ));
    }

    emit_receive_push_signed_encrypted(
        session,
        event_bus,
        &parsed.message_id,
        policy.fail_closed_audit_events,
    )?;

    let mut promoted = promoted.into_iter();
    let (primary_cid, primary) = promoted
        .next()
        .expect("resolve_verified_payloads returns at least one payload");
    let additional = promoted
        .map(|(content_id, payload)| As4ReceivedPayload {
            content_id,
            payload,
        })
        .collect();

    Ok((primary, primary_cid, additional, sbdh_header))
}

fn verify_non_fragment_receipt(
    session: &SessionContext,
    event_bus: &EventBus,
    receipt_payload: Option<&[u8]>,
    policy: &As4PushPolicy,
    parsed: &super::super::ParsedAs4UserMessage,
) -> Result<Option<super::super::ParsedAs4Receipt>> {
    receipt::parse_and_verify_receipt_if_present(
        session,
        event_bus,
        receipt_payload,
        policy,
        &parsed.message_id,
    )
}

#[allow(clippy::too_many_arguments)]
fn assemble_non_fragment_output(
    payload: DomainReady<Arc<[u8]>>,
    payload_content_id: String,
    additional_payloads: Vec<As4ReceivedPayload>,
    sbdh_header: Option<SbdhHeader>,
    parsed: super::super::ParsedAs4UserMessage,
    receipt: Option<super::super::ParsedAs4Receipt>,
) -> As4ReceivePushProgress {
    As4ReceivePushProgress::Complete(Box::new(As4ReceivePushOutput {
        payload,
        payload_content_id,
        additional_payloads,
        sbdh_header,
        user_message: parsed,
        receipt,
    }))
}
