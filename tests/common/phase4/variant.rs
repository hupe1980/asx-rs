//! Profile variants: a phase4 profile paired with an `asx` preset and the
//! collaboration values that phase4's profile validator and the preset both
//! accept.

use asx::Profile;

/// ebMS3 Core default roles (both phase4's BDEW validator and `Profile::bdew()` fix them).
pub const INITIATOR_ROLE: &str =
    "http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/initiator";
pub const RESPONDER_ROLE: &str =
    "http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/responder";
/// BDEW AS4-Profil 1.2 §2.3.1.2.1 (Marktprozesse).
pub const BDEW_SERVICE_MP: &str = "https://www.bdew.de/as4/communication/services/MP";
/// BDEW §2.3.2.
pub const BDEW_AGREEMENT: &str = "https://www.bdew.de/as4/communication/agreement";
/// BDEW §2.3.1.2.2: the fixed action (ebMS3 Core default action).
pub const BDEW_ACTION: &str = "http://docs.oasis-open.org/ebxml-msg/as4/200902/action";
/// BDEW §2.3.1.1 party-id type for 99-prefixed MP-IDs.
pub const BDEW_PARTY_TYPE: &str = "urn:oasis:names:tc:ebcore:partyid-type:unregistered:BDEW";
/// The crate's MP-ID in the BDEW variant.
pub const CRATE_MP_ID: &str = "9900000000001";
/// phase4's MP-ID in the BDEW variant.
pub const PHASE4_MP_ID: &str = "9900000000002";

/// A phase4 profile variant served by the peer at `/as4/<id>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProfileVariant {
    /// phase4 `bdew` ↔ `Profile::bdew()`.
    Bdew,
    /// phase4 `cef` ↔ `Profile::edelivery_1_15()` (the peer's `/control/send`
    /// does not implement it).
    Cef,
}

/// The collaboration values of a variant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Collaboration {
    /// (party id, party-id type) of the crate.
    pub crate_party: (String, String),
    /// (party id, party-id type) of phase4.
    pub phase4_party: (String, String),
    pub service: String,
    /// `None`: the preset's default.
    pub action: Option<String>,
    pub agreement: Option<String>,
}

impl ProfileVariant {
    /// The variant id: the peer's `/as4/<id>` path segment and `peer.json` id.
    pub fn id(&self) -> &'static str {
        match self {
            ProfileVariant::Bdew => "bdew",
            ProfileVariant::Cef => "cef",
        }
    }

    /// The phase4 profile id the variant's endpoint is fixed to.
    pub fn phase4_profile_id(&self) -> &'static str {
        match self {
            ProfileVariant::Bdew => "bdew",
            ProfileVariant::Cef => "cef",
        }
    }

    /// `/as4/<id>`.
    pub fn path(&self) -> String {
        format!("/as4/{}", self.id())
    }

    /// The `asx` preset.
    pub fn profile(&self) -> Profile {
        match self {
            ProfileVariant::Bdew => Profile::bdew(),
            ProfileVariant::Cef => Profile::edelivery_1_15(),
        }
    }

    pub fn collaboration(&self) -> Collaboration {
        match self {
            ProfileVariant::Bdew => Collaboration {
                crate_party: (CRATE_MP_ID.into(), BDEW_PARTY_TYPE.into()),
                phase4_party: (PHASE4_MP_ID.into(), BDEW_PARTY_TYPE.into()),
                service: BDEW_SERVICE_MP.into(),
                action: Some(BDEW_ACTION.into()),
                agreement: Some(BDEW_AGREEMENT.into()),
            },
            ProfileVariant::Cef => Collaboration {
                crate_party: (
                    "asx-crate".into(),
                    "urn:oasis:names:tc:ebcore:partyid-type:unregistered".into(),
                ),
                phase4_party: (
                    "asx-phase4".into(),
                    "urn:oasis:names:tc:ebcore:partyid-type:unregistered".into(),
                ),
                service: "urn:asx:test:service".into(),
                action: None,
                agreement: None,
            },
        }
    }
}
