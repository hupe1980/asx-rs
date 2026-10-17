use crate::as4::types::As4SendPolicy;
use crate::core::{AsxError, ErrorCode, ErrorContext, Result, SessionContext};
use crate::crypto::CertFingerprint;
use crate::crypto::wssec::ChainPolicy;

/// The single-partner pin configured on the session, as a permitted-signer set.
///
/// Empty when nothing is pinned. A malformed value is an error, never "no
/// pin". `SessionContext` already refuses one at `build()`, `with_cert_handle`
/// and `rotate_cert_handle`, so this is defence in depth.
pub(crate) fn session_signer_pins(session: &SessionContext) -> Result<Vec<CertFingerprint>> {
    if session.metadata().profile_built {
        return Ok(session.metadata().signer_pins.clone());
    }
    let fp = session.cert_handle().fingerprint_sha256.trim();
    if fp.is_empty() {
        return Ok(Vec::new());
    }
    CertFingerprint::parse(fp).map(|f| vec![f]).map_err(|err| {
        AsxError::new(
            ErrorCode::InvalidInput,
            format!(
                "session cert_handle.fingerprint_sha256 is a malformed signer pin: {}",
                err.message
            ),
            ErrorContext::for_session("as4_signer_pins", session),
        )
    })
}

/// The session's anchors as the offline chain policy (revocation is the
/// caller's).
pub(crate) fn wssec_chain_policy_from_session<'a>(
    session: &'a SessionContext,
) -> Result<ChainPolicy<'a>> {
    Ok(ChainPolicy {
        trust_anchor_pems: &session.cert_handle().trust_anchor_pems,
        require_chain_validation: true,
        pre_parsed_trust_anchors: Some(session.trust_anchors_x509()?),
        pre_built_x509_store: Some(session.trust_anchor_x509_store()?),
    })
}

pub(crate) fn enforce_strict_as4_send_runtime_policy_consistency(
    session: &SessionContext,
    stage: &'static str,
    policy: &As4SendPolicy,
) -> Result<()> {
    if !policy.sign {
        return Err(AsxError::new(
            ErrorCode::PolicyViolation,
            "strict AS4 send policy forbids sign=false",
            ErrorContext::for_session(stage, session),
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Signal signature coverage (XML Signature Wrapping defence)
// ---------------------------------------------------------------------------

/// ebMS3 core namespace.
const EBMS3_CORE_NS: &str = "http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/";
/// WS-Security utility namespace, source of the `wsu:Id` attribute.
const WSU_NS: &str =
    "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd";

/// Require that the `eb:SignalMessage` a caller acts on is actually covered by
/// the verified WS-Security signature.
///
/// Without this binding, a counterparty could take a receipt it legitimately
/// signed for message A, leave the signed element in place so the signature
/// still verifies, and add an unsigned element acknowledging message B —
/// manufacturing non-repudiation evidence it never signed. This is the signal
/// counterpart of the `eb:UserMessage` defence in
/// [`crate::as4::As4WsSecVerifier`].
///
/// Coverage is satisfied by the SignalMessage itself **or any ancestor** (in
/// practice `eb:Messaging`) appearing in the verified same-document id set:
/// signing an ancestor necessarily covers its descendants. Both conventions
/// occur in the wild — this crate signs `eb:Messaging`, other MSHs sign
/// `eb:SignalMessage` — and both are conformant.
///
/// Uniqueness of `eb:Messaging` and `eb:SignalMessage` is enforced by
/// [`crate::as4::parser::parse_as4_signal_envelope`] before this runs, so the
/// element located here is unambiguous.
pub(super) fn enforce_signal_signature_coverage(
    session: &SessionContext,
    doc: &roxmltree::Document<'_>,
    stage: &'static str,
    message_id: &str,
    coverage: &crate::crypto::wssec::verify::VerifiedSignatureCoverage,
) -> Result<()> {
    let signal_nodes: Vec<_> = doc
        .descendants()
        .filter(|node| {
            node.is_element()
                && node.tag_name().name() == "SignalMessage"
                && node.tag_name().namespace() == Some(EBMS3_CORE_NS)
        })
        .collect();

    if signal_nodes.len() != 1 {
        return Err(AsxError::new(
            ErrorCode::SecurityVerificationFailed,
            format!(
                "AS4 signal must contain exactly one eb:SignalMessage (found {})",
                signal_nodes.len()
            ),
            ErrorContext::for_session_with_message(stage, session, message_id),
        ));
    }

    let covered = signal_nodes[0]
        .ancestors() // `ancestors()` yields the node itself first.
        .filter_map(|node| {
            node.attribute((WSU_NS, "Id"))
                .or_else(|| node.attribute("Id"))
        })
        .any(|id| {
            coverage
                .signed_same_document_ids
                .iter()
                .any(|signed| signed == id)
        });

    if !covered {
        return Err(AsxError::new(
            ErrorCode::SecurityVerificationFailed,
            "AS4 eb:SignalMessage is not covered by the verified WS-Security signature \
             (possible XML signature wrapping); the acknowledgement asserts content the \
             counterparty did not sign",
            ErrorContext::for_session_with_message(stage, session, message_id),
        ));
    }

    Ok(())
}
