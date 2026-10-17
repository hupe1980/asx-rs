//! Message Level Status — the transport half.
//!
//! Peppol Network Policy 1.0.0 (2026-07-02) rule **MLS-1** makes MLS mandatory:
//! every Peppol Service Provider *must* support sending and receiving it. An
//! MLS message is an ordinary AS4 transmission carrying a Peppol document, so
//! the parts this crate owns are: **who** it is addressed to, **when** it has
//! to arrive, and **whether** the sender wants it at all.
//!
//! The document itself is a business document and is not built here.

use std::time::Duration;

use crate::sbdh::{SbdhHeader, peppol_scope};

/// The ISO 6523 ICD that identifies a **Peppol Service Provider**, as opposed
/// to a trading participant.
///
/// Network Policy rule MLS-2 requires every Service Provider to register its
/// SPIS Main ID for MLS receiving — the worked example is a provider with Seat
/// ID `POP987654` registering participant `0242:987654`.
pub const SPIS_ICD: &str = "0242";

/// The identifier scheme an MLS receiver is expressed in, matching every other
/// Peppol participant identifier.
pub const SPIS_PARTICIPANT_SCHEME: &str = super::PEPPOL_PARTICIPANT_SCHEME;

/// The only `MLS_TYPE` value the specifications in this repository name, and
/// the behaviour an absent `MLS_TYPE` means.
///
/// Network Policy rule MLS-3: a **negative** MLS is always sent when
/// applicable; a **positive** one only when the sending Service Provider opted
/// in. The opt-in is the `MLS_TYPE` scope, and *"if no MLS_TYPE parameter is
/// provided in the Business Message Envelope (SBDH) it must be interpreted as
/// FAILURE_ONLY"*.
///
/// Other values exist in the MLS specification, which is not part of this
/// repository's reference corpus; [`mls_type`] therefore returns the raw
/// string rather than an enum whose variants would be guesses.
pub const MLS_TYPE_FAILURE_ONLY: &str = "FAILURE_ONLY";

/// Build the Peppol participant identifier of a Service Provider from its Seat
/// ID, for registering or addressing MLS.
///
/// ```text
/// use asx::peppol::mls;
///
/// // Network Policy rule MLS-2's worked example: seat POP987654.
/// assert_eq!(mls::spis_participant_id("987654"), "0242:987654");
/// ```
pub fn spis_participant_id(seat_id: &str) -> String {
    format!("{SPIS_ICD}:{}", seat_id.trim())
}

/// The `MLS_TYPE` the sender requested, or the network default.
///
/// Implements rule MLS-3: an absent scope means [`MLS_TYPE_FAILURE_ONLY`], so
/// a receiver that forgets to look never mistakes "unspecified" for "send
/// everything".
///
/// ```text
/// # use asx::sbdh::{SbdhHeader, SbdhScope, peppol_scope};
/// # use asx::peppol::mls;
/// # fn example(header: &SbdhHeader) {
/// // Absent => FAILURE_ONLY, never "all".
/// assert_eq!(mls::mls_type(header), mls::MLS_TYPE_FAILURE_ONLY);
/// # }
/// ```
pub fn mls_type(header: &SbdhHeader) -> &str {
    header
        .scope_value(peppol_scope::MLS_TYPE)
        .filter(|v| !v.trim().is_empty())
        .unwrap_or(MLS_TYPE_FAILURE_ONLY)
}

/// Whether a **positive** MLS was opted into for this message.
///
/// The inverse — a negative MLS — is always required when applicable, so there
/// is deliberately no `is_negative_mls_wanted`: the answer is always yes.
pub fn positive_mls_requested(header: &SbdhHeader) -> bool {
    mls_type(header) != MLS_TYPE_FAILURE_ONLY
}

/// The participant an MLS for this message must be addressed to, when the
/// sender named one explicitly (`MLS_TO`, Business Message Envelope §2.6.1).
///
/// `None` means the sender did not override it, and the MLS goes to the
/// sending Service Provider's registered SPIS Main ID — which is a fact about
/// the *sender*, not about this message, so it is not in the envelope.
pub fn explicit_mls_receiver(header: &SbdhHeader) -> Option<MlsReceiver<'_>> {
    header.scope(peppol_scope::MLS_TO).map(|scope| MlsReceiver {
        participant_id: scope.instance_identifier.as_str(),
        scheme: scope
            .identifier
            .as_deref()
            .unwrap_or(SPIS_PARTICIPANT_SCHEME),
    })
}

/// A participant identifier to address an MLS to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MlsReceiver<'a> {
    /// The participant identifier value, e.g. `0242:987654`.
    pub participant_id: &'a str,
    /// The identifier scheme, defaulting to [`SPIS_PARTICIPANT_SCHEME`] when
    /// the envelope omits it.
    pub scheme: &'a str,
}

// ── Service Level Requirements ───────────────────────────────────────────────

/// Peppol Network Policy **SLR MLS-1**: 99.5% of MLS messages for payloads
/// under 10 MB must be sent within this long of milestone M1, measured monthly.
pub const SLR_LATEST_MLS_SENDING: Duration = Duration::from_secs(20 * 60);

/// Peppol Network Policy **SLR MLS-2**: the same population must be *received*
/// within this long of M1.
pub const SLR_LATEST_MLS_RECEPTION: Duration = Duration::from_secs(25 * 60);

/// The payload size below which the MLS service levels apply.
///
/// Network Policy rule PT-1 measures the **uncompressed, unencrypted and
/// unsigned** envelope, and defines a megabyte as 1 000 000 bytes — not
/// 1 048 576.
pub const SLR_PAYLOAD_SIZE_LIMIT_BYTES: u64 = 10 * 1_000_000;

/// Milestone **M1**: when transmission of the original document was initiated
/// at C2.
///
/// The Network Policy names the field exactly — the AS4 `UserMessage`'s
/// `eb:MessageInfo/Timestamp` of the *original* transmission — so this reads
/// it rather than substituting a local clock. Returns `None` when the sender
/// omitted the element, which ebMS3 allows and which makes the SLR
/// unmeasurable for that message.
pub fn milestone_m1(user_message: &crate::as4::ParsedAs4UserMessage) -> Option<&str> {
    user_message
        .timestamp
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sbdh::{SbdhDocumentIdentification, SbdhParty, SbdhScope};

    fn header(scopes: Vec<SbdhScope>) -> SbdhHeader {
        SbdhHeader {
            header_version: "1.0".into(),
            sender: SbdhParty {
                identifier: "0088:1".into(),
                authority: SPIS_PARTICIPANT_SCHEME.into(),
            },
            receiver: SbdhParty {
                identifier: "0088:2".into(),
                authority: SPIS_PARTICIPANT_SCHEME.into(),
            },
            business_scope: scopes,
            document_identification: SbdhDocumentIdentification {
                standard: "s".into(),
                type_version: "2.1".into(),
                instance_identifier: "i".into(),
                r#type: "Invoice".into(),
                multiple_type: false,
                creation_date_and_time: "2026-01-01T00:00:00Z".into(),
            },
        }
    }

    #[test]
    fn spis_identifier_matches_the_policy_example() {
        // Network Policy rule MLS-2: seat POP987654 registers 0242:987654.
        assert_eq!(spis_participant_id("987654"), "0242:987654");
        assert_eq!(spis_participant_id("  987654 "), "0242:987654");
    }

    /// Rule MLS-3: absent means FAILURE_ONLY, which is the safe direction —
    /// a receiver that never looks sends only negative statuses.
    #[test]
    fn an_absent_mls_type_defaults_to_failure_only() {
        let h = header(Vec::new());
        assert_eq!(mls_type(&h), MLS_TYPE_FAILURE_ONLY);
        assert!(!positive_mls_requested(&h));
    }

    /// An empty value is absent, not a distinct opt-in.
    #[test]
    fn an_empty_mls_type_defaults_to_failure_only() {
        let h = header(vec![SbdhScope::new(peppol_scope::MLS_TYPE, "   ")]);
        assert_eq!(mls_type(&h), MLS_TYPE_FAILURE_ONLY);
        assert!(!positive_mls_requested(&h));
    }

    #[test]
    fn an_explicit_mls_type_is_returned_verbatim() {
        let h = header(vec![SbdhScope::new(peppol_scope::MLS_TYPE, "ALL")]);
        assert_eq!(mls_type(&h), "ALL");
        assert!(positive_mls_requested(&h));
    }

    /// BME §2.6.1's worked example.
    #[test]
    fn an_explicit_mls_receiver_is_read_with_its_scheme() {
        let h = header(vec![SbdhScope::with_scheme(
            peppol_scope::MLS_TO,
            "0242:987654-TEST",
            "iso6523-actorid-upis",
        )]);
        let to = explicit_mls_receiver(&h).expect("MLS_TO present");
        assert_eq!(to.participant_id, "0242:987654-TEST");
        assert_eq!(to.scheme, "iso6523-actorid-upis");
    }

    #[test]
    fn an_mls_receiver_without_a_scheme_falls_back_to_the_participant_scheme() {
        let h = header(vec![SbdhScope::new(peppol_scope::MLS_TO, "0242:987654")]);
        let to = explicit_mls_receiver(&h).expect("MLS_TO present");
        assert_eq!(to.scheme, SPIS_PARTICIPANT_SCHEME);
    }

    #[test]
    fn no_mls_to_means_the_sending_service_providers_own_registration() {
        assert!(explicit_mls_receiver(&header(Vec::new())).is_none());
    }

    /// The SLR windows are the numbers the policy prints, not rounded ones.
    #[test]
    fn service_level_windows_match_the_policy() {
        assert_eq!(SLR_LATEST_MLS_SENDING.as_secs(), 1_200);
        assert_eq!(SLR_LATEST_MLS_RECEPTION.as_secs(), 1_500);
        // Rule PT-1: a megabyte is 1 000 000 bytes, not 1 048 576.
        assert_eq!(SLR_PAYLOAD_SIZE_LIMIT_BYTES, 10_000_000);
    }
}
