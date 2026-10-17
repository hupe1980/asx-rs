use roxmltree::Document;

use super::super::services::wssec_chain_policy_from_session;
use super::super::types::As4PushPolicy;
use crate::core::{AsxError, ErrorCode, ErrorContext, Result, SessionContext};
use crate::crypto::wssec::WsSecVerifyOptions;

/// Sealing module — prevents external crates from implementing
/// [`As4Verifier`]; the only implementation is [`As4WsSecVerifier`].
pub(crate) mod private {
    pub(crate) trait Sealed {}
}

/// Everything a [`As4Verifier`] is given about one inbound message.
///
/// A struct rather than eight parameters, so adding a fact the verifier needs
/// does not reorder an argument list that is easy to get silently wrong — two
/// of these fields are `&str` and two are slices.
#[non_exhaustive]
pub(crate) struct As4SecurityVerification<'a> {
    pub session: &'a SessionContext,
    pub policy: &'a As4PushPolicy,
    /// The SOAP envelope as text, for canonicalization.
    pub soap_xml: &'a str,
    /// The same envelope, parsed.
    pub soap_doc: &'a Document<'a>,
    pub message_id: &'a str,
    /// Every declared payload part as `(content_id, _)`: each must be
    /// covered by a signed `cid:` reference (its digest is checked after
    /// decryption).
    pub external_references: &'a [(&'a str, &'a [u8])],
    /// The primary `<eb:From>/<eb:PartyId>` the message *claims* to be from.
    ///
    /// Unauthenticated at this point. `permitted_signers` is what a successful
    /// verification binds it to.
    pub from_party_id: &'a str,
    /// The fingerprints that claimed sender is allowed to sign with, already
    /// resolved by the caller.
    ///
    /// Empty means the sender is unpinned: a **signed** message must then be
    /// refused, because a signature that verifies against the network's
    /// anchors proves membership of the network and not the identity of the
    /// sender. An unsigned message has no signer to attribute and is
    /// unaffected.
    pub permitted_signers: &'a [crate::crypto::CertFingerprint],
    /// The profile's sender rule, checked with the pins.
    /// When present, an empty pin list is not a refusal: the rule decides.
    pub(crate) signer_check: Option<&'a crate::crypto::wssec::verify::SignerCheck>,
    /// Where a successful verification leaves the signer and the verified
    /// references, for the audit record.
    pub(crate) evidence:
        &'a std::sync::OnceLock<crate::crypto::wssec::verify::VerifiedSignatureCoverage>,
}

impl std::fmt::Debug for As4SecurityVerification<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("As4SecurityVerification")
            .field("message_id", &self.message_id)
            .field("from_party_id", &self.from_party_id)
            .field("permitted_signers", &self.permitted_signers)
            .field("signer_check", &self.signer_check.is_some())
            .finish_non_exhaustive()
    }
}

/// Security-verification hook for the AS4 push receive pipeline.
///
/// This trait is sealed — external crates cannot implement it unless the
/// testing feature is enabled. This mirrors the sealing approach used on
/// AS2 trust-verifier surfaces and prevents silent trust bypasses on AS4.
pub(crate) trait As4Verifier: private::Sealed {
    fn verify_security(&self, ctx: As4SecurityVerification<'_>) -> Result<()>;
}

#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct As4WsSecVerifier;

impl private::Sealed for As4WsSecVerifier {}

impl As4Verifier for As4WsSecVerifier {
    fn verify_security(&self, ctx: As4SecurityVerification<'_>) -> Result<()> {
        let As4SecurityVerification {
            session,
            policy,
            soap_xml,
            soap_doc,
            message_id,
            external_references,
            from_party_id,
            permitted_signers,
            signer_check,
            evidence,
        } = ctx;
        let chain_policy = wssec_chain_policy_from_session(session)?;
        let opts = WsSecVerifyOptions::new()
            .with_expected_fingerprints(permitted_signers)
            .with_signer_check(signer_check)
            .with_chain_policy(chain_policy)
            .at(session.clock().now())
            // `cid:` digests over the decrypted parts are the caller's; so is
            // revocation, after the sender rule.
            .deferring_attachments();

        let coverage = crate::crypto::wssec::verify::verify_enveloped_signature_optional_with_doc(
            soap_doc,
            soap_xml,
            crate::crypto::wssec::verify::SignedDocClass::UserMessage,
            opts,
        )?;

        let signature_present = coverage.is_some();

        if policy.require_signed_push && !signature_present {
            return Err(AsxError::new(
                ErrorCode::SecurityVerificationFailed,
                "AS4 push message signature is required but not present",
                ErrorContext::for_session_with_message("as4_receive_push", session, message_id),
            ));
        }

        // A signature that verifies against the network's anchors proves
        // membership of the network, not the identity of the sender — every
        // access point shares those anchors. Without a pin for the claimed
        // party there is nothing to attribute the signature to, so refuse
        // rather than accept an unattributable one.
        if signature_present && permitted_signers.is_empty() && signer_check.is_none() {
            return Err(AsxError::new(
                ErrorCode::PolicyViolation,
                format!(
                    "no signing certificate is pinned for the claimed sender '{from_party_id}', \
                     so a valid signature could not be attributed to it; pin the partner's \
                     signing certificate (Partner::signing_cert)"
                ),
                ErrorContext::for_session("as4_receive_push", session),
            ));
        }

        // XML Signature Wrapping defence: when a signature is present, the
        // eb:Messaging block the pipeline routes on MUST be the one the
        // signature actually covered. Otherwise an attacker could relocate the
        // signed block (still resolvable by wsu:Id) and inject an unsigned
        // replacement that the parser consumes.
        if let Some(coverage) = coverage {
            enforce_messaging_signature_coverage(session, soap_doc, message_id, &coverage)?;
            enforce_attachment_signature_coverage(
                session,
                message_id,
                external_references,
                &coverage,
            )?;
            let _ = evidence.set(coverage);
        }

        Ok(())
    }
}

/// Require that the payload attachment the pipeline is about to surface was
/// covered by a verified `cid:` reference.
///
/// Signing `eb:Messaging` and the SOAP Body proves nothing about the payload —
/// the actual business document travels as a detached MIME part. Without this
/// check, a signature covering only the header and body verifies happily while
/// an intermediary swaps the attachment, and the receive pipeline hands the
/// substituted bytes to the application as `DomainReady`.
pub(super) fn enforce_attachment_signature_coverage(
    session: &SessionContext,
    message_id: &str,
    attachments: &[(&str, &[u8])],
    coverage: &crate::crypto::wssec::verify::VerifiedSignatureCoverage,
) -> Result<()> {
    // Every attachment must be covered, not just the first: a multi-payload
    // message whose signature references only payload 1 leaves payloads 2..n
    // swappable.
    for (cid, _) in attachments {
        let cid = normalize_cid(cid);
        if coverage
            .signed_cid_references
            .iter()
            .any(|signed| normalize_cid(signed) == cid)
        {
            continue;
        }

        return Err(AsxError::new(
            ErrorCode::SecurityVerificationFailed,
            format!(
                "AS4 payload attachment cid:{cid} is not covered by the WS-Security \
                 signature; the signature must include a ds:Reference URI=\"cid:{cid}\" \
                 so the payload is integrity-protected alongside the eb:Messaging header"
            ),
            ErrorContext::for_session_with_message("as4_receive_push", session, message_id),
        ));
    }

    Ok(())
}

/// Strip an optional `cid:` scheme prefix and angle brackets, so a reference
/// written `cid:x@y`, `<x@y>` or `x@y` all compare equal.
fn normalize_cid(value: &str) -> &str {
    let value = value.trim();
    let value = value.strip_prefix('<').unwrap_or(value);
    let value = value.strip_suffix('>').unwrap_or(value);
    value
        .get(..4)
        .filter(|prefix| prefix.eq_ignore_ascii_case("cid:"))
        .map_or(value, |_| &value[4..])
}

/// ebMS3 core namespace.
const EBMS3_NS: &str = "http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/";
const WSU_NS: &str =
    "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd";

/// Require that the single `eb:Messaging` header block is covered by a verified
/// signature reference (matched by its `wsu:Id`).
fn enforce_messaging_signature_coverage(
    session: &SessionContext,
    soap_doc: &Document<'_>,
    message_id: &str,
    coverage: &crate::crypto::wssec::verify::VerifiedSignatureCoverage,
) -> Result<()> {
    let messaging_nodes: Vec<_> = soap_doc
        .descendants()
        .filter(|n| {
            n.is_element()
                && n.tag_name().name() == "Messaging"
                && n.tag_name().namespace() == Some(EBMS3_NS)
        })
        .collect();

    // Exactly one eb:Messaging block is expected; 0 or >1 is a wrapping attempt
    // or a malformed envelope.
    if messaging_nodes.len() != 1 {
        return Err(AsxError::new(
            ErrorCode::SecurityVerificationFailed,
            format!(
                "AS4 envelope must contain exactly one eb:Messaging header block (found {})",
                messaging_nodes.len()
            ),
            ErrorContext::for_session_with_message("as4_receive_push", session, message_id),
        ));
    }

    let messaging = messaging_nodes[0];
    let messaging_id = messaging
        .attribute((WSU_NS, "Id"))
        .or_else(|| messaging.attribute("Id"));

    let covered =
        messaging_id.is_some_and(|id| coverage.signed_same_document_ids.iter().any(|s| s == id));

    if !covered {
        return Err(AsxError::new(
            ErrorCode::SecurityVerificationFailed,
            "AS4 eb:Messaging header block is not covered by the verified WS-Security signature \
             (possible XML signature wrapping)",
            ErrorContext::for_session_with_message("as4_receive_push", session, message_id),
        ));
    }

    Ok(())
}

#[cfg(test)]
mod xsw_coverage_tests {
    use super::{
        EBMS3_NS, ErrorCode, enforce_attachment_signature_coverage,
        enforce_messaging_signature_coverage,
    };
    use crate::core::SessionContext;
    use crate::crypto::wssec::verify::VerifiedSignatureCoverage;
    use roxmltree::Document;

    fn session() -> SessionContext {
        SessionContext::new("s-xsw", "partner", "strict").expect("session")
    }

    fn coverage(ids: &[&str]) -> VerifiedSignatureCoverage {
        VerifiedSignatureCoverage {
            signed_same_document_ids: ids.iter().map(|s| s.to_string()).collect(),
            signed_cid_references: Vec::new(),
            signer_certificate_der: None,
            references: Vec::new(),
            deferred: None,
            signer_path: Vec::new(),
        }
    }

    fn cid_coverage(cids: &[&str]) -> VerifiedSignatureCoverage {
        VerifiedSignatureCoverage {
            signed_same_document_ids: Vec::new(),
            signed_cid_references: cids.iter().map(|s| s.to_string()).collect(),
            signer_certificate_der: None,
            references: Vec::new(),
            deferred: None,
            signer_path: Vec::new(),
        }
    }

    #[test]
    fn attachment_covered_by_a_signed_cid_reference_is_accepted() {
        enforce_attachment_signature_coverage(
            &session(),
            "m1",
            &[("payload@example.com", b"bytes".as_slice())],
            &cid_coverage(&["payload@example.com"]),
        )
        .expect("covered attachment must verify");
    }

    #[test]
    fn cid_comparison_ignores_scheme_prefix_and_angle_brackets() {
        for (attachment, signed) in [
            ("cid:p@e.com", "p@e.com"),
            ("p@e.com", "cid:p@e.com"),
            ("<p@e.com>", "p@e.com"),
            ("CID:p@e.com", "p@e.com"),
        ] {
            enforce_attachment_signature_coverage(
                &session(),
                "m1",
                &[(attachment, b"bytes".as_slice())],
                &cid_coverage(&[signed]),
            )
            .unwrap_or_else(|err| panic!("{attachment} vs {signed} must match: {err}"));
        }
    }

    #[test]
    fn attachment_not_covered_by_any_signed_reference_is_rejected() {
        // The signature covers the eb:Messaging header but no attachment — the
        // payload could be swapped in transit without breaking it.
        let err = enforce_attachment_signature_coverage(
            &session(),
            "m1",
            &[("payload@example.com", b"bytes".as_slice())],
            &coverage(&["as4-messaging"]),
        )
        .expect_err("uncovered attachment must be rejected");
        assert_eq!(err.code, ErrorCode::SecurityVerificationFailed);
        assert!(err.message.contains("payload@example.com"));
    }

    #[test]
    fn attachment_covered_by_a_different_cid_is_rejected() {
        let err = enforce_attachment_signature_coverage(
            &session(),
            "m1",
            &[("payload@example.com", b"bytes".as_slice())],
            &cid_coverage(&["decoy@example.com"]),
        )
        .expect_err("a signed reference to a different part must not count");
        assert_eq!(err.code, ErrorCode::SecurityVerificationFailed);
    }

    #[test]
    fn no_attachment_needs_no_cid_coverage() {
        enforce_attachment_signature_coverage(&session(), "m1", &[], &coverage(&["as4-messaging"]))
            .expect("a message with no attachment has nothing to cover");
    }

    /// Every attachment must be covered — a signature referencing only the
    /// first payload leaves payloads 2..n swappable.
    #[test]
    fn every_attachment_must_be_covered_not_just_the_first() {
        let attachments: &[(&str, &[u8])] =
            &[("xmlpayload@gitb", b"one"), ("custompayload@gitb", b"two")];

        enforce_attachment_signature_coverage(
            &session(),
            "m1",
            attachments,
            &cid_coverage(&["xmlpayload@gitb", "custompayload@gitb"]),
        )
        .expect("both covered");

        let err = enforce_attachment_signature_coverage(
            &session(),
            "m1",
            attachments,
            &cid_coverage(&["xmlpayload@gitb"]),
        )
        .expect_err("the second attachment is not covered");
        assert_eq!(err.code, ErrorCode::SecurityVerificationFailed);
        assert!(
            err.message.contains("custompayload@gitb"),
            "{}",
            err.message
        );
    }

    fn envelope_with(messaging_blocks: &str) -> String {
        format!(
            r#"<S12:Envelope xmlns:S12="http://www.w3.org/2003/05/soap-envelope"
                xmlns:eb="{EBMS3_NS}"
                xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
              <S12:Header>{messaging_blocks}</S12:Header>
              <S12:Body/>
            </S12:Envelope>"#
        )
    }

    #[test]
    fn accepts_single_signed_messaging() {
        let xml = envelope_with(
            r#"<eb:Messaging wsu:Id="as4-messaging"><eb:UserMessage/></eb:Messaging>"#,
        );
        let doc = Document::parse(&xml).unwrap();
        enforce_messaging_signature_coverage(&session(), &doc, "m1", &coverage(&["as4-messaging"]))
            .expect("signed eb:Messaging must be accepted");
    }

    #[test]
    fn rejects_uncovered_messaging_id() {
        let xml =
            envelope_with(r#"<eb:Messaging wsu:Id="attacker-id"><eb:UserMessage/></eb:Messaging>"#);
        let doc = Document::parse(&xml).unwrap();
        let err = enforce_messaging_signature_coverage(
            &session(),
            &doc,
            "m1",
            &coverage(&["as4-messaging"]),
        )
        .expect_err("eb:Messaging id not in signed set must reject");
        assert_eq!(err.code, crate::core::ErrorCode::SecurityVerificationFailed);
    }

    #[test]
    fn rejects_injected_second_messaging_block() {
        // Signature covers the original block; attacker injected a second one.
        let xml = envelope_with(
            r#"<eb:Messaging wsu:Id="as4-messaging"><eb:UserMessage/></eb:Messaging>
               <eb:Messaging><eb:UserMessage/></eb:Messaging>"#,
        );
        let doc = Document::parse(&xml).unwrap();
        let err = enforce_messaging_signature_coverage(
            &session(),
            &doc,
            "m1",
            &coverage(&["as4-messaging"]),
        )
        .expect_err("two eb:Messaging blocks must reject");
        assert_eq!(err.code, crate::core::ErrorCode::SecurityVerificationFailed);
    }

    #[test]
    fn rejects_messaging_without_wsu_id() {
        let xml = envelope_with(r#"<eb:Messaging><eb:UserMessage/></eb:Messaging>"#);
        let doc = Document::parse(&xml).unwrap();
        let err = enforce_messaging_signature_coverage(
            &session(),
            &doc,
            "m1",
            &coverage(&["as4-messaging"]),
        )
        .expect_err("unsigned eb:Messaging must reject");
        assert_eq!(err.code, crate::core::ErrorCode::SecurityVerificationFailed);
    }
}
