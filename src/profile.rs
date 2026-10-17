//! Network profiles: the only source of security settings.
//!
//! A [`Profile`] is an opaque preset. Together with a [`Partner`] it resolves,
//! at `build()`, into the crate-private [`PartnerPolicy`] that every send and
//! receive path reads. The per-protocol policy structs are *views* of a
//! `PartnerPolicy` and are constructed nowhere else (`tests/source_gates.rs`).

use crate::party::Partner;
use openssl::nid::Nid;

/// The maximum message size every preset allows.
const CEILING: u64 = 256 * 1024 * 1024;

pub(crate) const BDEW_PARTY_TYPES: &[&str] = &[
    "urn:oasis:names:tc:ebcore:partyid-type:iso6523:0088",
    "urn:oasis:names:tc:ebcore:partyid-type:unregistered:BDEW",
    "urn:oasis:names:tc:ebcore:partyid-type:unregistered:DVGW",
    "urn:oasis:names:tc:ebcore:partyid-type:unregistered:BAHN",
];

pub(crate) const BDEW_SERVICES: &[&str] = &[
    "https://www.bdew.de/as4/communication/services/MP",
    "https://www.bdew.de/as4/communication/services/FP",
    "https://www.bdew.de/as4/communication/services/RD",
    "https://www.bdew.de/as4/communication/services/KW",
    "https://www.bdew.de/as4/communication/services/SO",
];

/// The BDEW transmission-path-switch service (B §2.3.1.2.1, §2.3.7).
pub(crate) const PATH_SWITCH_SERVICE: &str =
    "https://www.bdew.de/as4/communication/services/pathSwitch";
/// The path-switch request action (B §2.3.1.2.2, §2.3.7).
pub(crate) const REQUEST_SWITCH_ACTION: &str =
    "https://www.bdew.de/as4/communication/actions/requestSwitch";
/// The path-switch confirmation action (B §2.3.1.2.2, §2.3.7).
pub(crate) const CONFIRM_SWITCH_ACTION: &str =
    "https://www.bdew.de/as4/communication/actions/confirmSwitch";

pub(crate) const BDEW_AGREEMENT: &str = "https://www.bdew.de/as4/communication/agreement";
pub(crate) const PEPPOL_AGREEMENT: &str = "urn:fdc:peppol.eu:2017:agreements:tia:ap_provider";
pub(crate) const PEPPOL_PARTY_TYPE: &str = "urn:fdc:peppol.eu:2017:identifiers:ap";
/// ebMS3 Core §5.2.2 default action, also BDEW's fixed action (B §2.3.1.2.2).
pub(crate) const DEFAULT_ACTION: &str = "http://docs.oasis-open.org/ebxml-msg/as4/200902/action";
pub(crate) const INITIATOR_ROLE: &str =
    "http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/initiator";
pub(crate) const RESPONDER_ROLE: &str =
    "http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/responder";
/// ebMS3 Core §5.2.2.9 test service and action.
pub(crate) const TEST_SERVICE: &str =
    "http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/service";
pub(crate) const TEST_ACTION: &str =
    "http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/test";

/// A network profile: every security and wire setting, cited. Opaque;
/// obtained only from a preset. There is no `Default` and no method that
/// loosens a value.
///
/// ```compile_fail
/// let profile = asx::Profile::default();
/// ```
#[derive(Debug, Clone)]
pub struct Profile {
    id: ProfileId,
    max_message_bytes: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum ProfileId {
    Bdew12,
    Peppol203,
    Edelivery115,
    Entsog36,
    As2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Protocol {
    As4,
    As2,
}

/// Who may send to us.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SenderRule {
    /// Chains to an anchor and the claimed MP-ID is in the signer's subject
    /// (BDEW AS4-Profil 1.2 §2.3.2, §2.3.4.4).
    AnchorAndSubject,
    /// Chains to an anchor and the signer's CN equals the claimed party id
    /// (Peppol AS4 2.0.3 §4.5, §4.7).
    AnchorAndCn,
    /// A configured partner only (eDelivery AS4 1.15 without the Dynamic
    /// Receiver, §4.3; RFC 4130).
    RegisteredOnly,
}

/// The form of the signing certificate reference.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TokenRef {
    /// BST `#X509PKIPathv1` (BDEW §2.2.6.2.1).
    PkiPath,
    /// BST `#X509v3`.
    X509v3,
}

/// Which keys a side may use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KeyRule {
    EcCurve(Nid),
    RsaMin(u32),
    RsaOrEc {
        rsa_min: u32,
        curves: &'static [Nid],
    },
}

impl KeyRule {
    pub(crate) fn allows(self, kind: crate::keys::KeyKind) -> bool {
        use crate::keys::KeyKind;
        match (self, kind) {
            (KeyRule::EcCurve(want), KeyKind::Ec { curve: Some(have) }) => want == have,
            (KeyRule::RsaMin(min), KeyKind::Rsa { bits }) => bits >= min,
            (KeyRule::RsaOrEc { rsa_min, .. }, KeyKind::Rsa { bits }) => bits >= rsa_min,
            (KeyRule::RsaOrEc { curves, .. }, KeyKind::Ec { curve: Some(have) }) => {
                curves.contains(&have)
            }
            _ => false,
        }
    }

    pub(crate) fn describe(self) -> String {
        match self {
            KeyRule::EcCurve(nid) => format!("EC {}", nid.short_name().unwrap_or("?")),
            KeyRule::RsaMin(min) => format!("RSA >= {min}"),
            KeyRule::RsaOrEc { rsa_min, .. } => format!("RSA >= {rsa_min} or EC P-256/P-384"),
        }
    }
}

/// How the party-id type is set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PartyTypeRule {
    OneOf(&'static [&'static str]),
    Fixed(&'static str),
    CallerSet,
}

/// How the AS4 `eb:Service` is set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ServiceRule {
    OneOf(&'static [&'static str]),
    Required,
}

const AS2_CURVES: &[Nid] = &[Nid::X9_62_PRIME256V1, Nid::SECP384R1];

impl Profile {
    /// **BDEW AS4-Profil 1.2** (01.04.2026) with **Regelungen zum
    /// Übertragungsweg AS4 2.6** — the German energy market (MaKo).
    ///
    /// | Setting | Value |
    /// |---|---|
    /// | MEP | One-Way/Push, receipts and errors synchronous (B §2.2.1, §2.2.2, §2.2.4, §2.2.5) |
    /// | Packaging | SwA, one MIME part per payload, empty Body; part type `application/octet-stream` (B §2.2.3.2) |
    /// | Compression | gzip, always (B §2.2.3.3 "MUSS"); uncompressed inbound accepted (eDelivery 1.15 §3.3.1) |
    /// | Signature | `ecdsa-sha256` on BrainpoolP256r1, SHA-256 digests (B §2.2.6.2.1; BSI TR-03116-3 §9.1) |
    /// | Signing token | BST `#X509PKIPathv1` (B §2.2.6.2.1) |
    /// | Encryption | ECDH-ES + ConcatKDF (SHA-256) + `kw-aes128`, `aes128-gcm`, recipient by `X509SKI` (B §2.2.6.2.2, §2.3.4.3; TR §9.2) |
    /// | Keys | separate EC BrainpoolP256r1 key pairs for signing, encryption and TLS (B §2.3.4.4) |
    /// | Party id | the 13-digit MP-ID; type one of `…:iso6523:0088`, `…:unregistered:BDEW`, `…:DVGW`, `…:BAHN` (B §2.3.1.1) |
    /// | Service | one of `https://www.bdew.de/as4/communication/services/{MP,FP,RD,KW,SO}` (B §2.3.1.2.1) |
    /// | Action | fixed `http://docs.oasis-open.org/ebxml-msg/as4/200902/action` (B §2.3.1.2.2); the path-switch service has its own two |
    /// | Roles | fixed initiator / responder (B §2.3.1.2.3) |
    /// | ConversationId | always empty (B §2.3.1.2.4) |
    /// | AgreementRef | `https://www.bdew.de/as4/communication/agreement`, no `pmode`/`type` (B §2.3.2) |
    /// | Inbound senders | any sender whose verified SM-PKI subject carries the claimed MP-ID, plus the pins of a configured partner (B §2.3.2, §2.3.4.4) |
    /// | Test service | receipted, never delivered (B §2.3.6) |
    /// | Path switch | B §2.2.8 "MUSS zusätzlich einen AS4-Übertragungspfadänderungsdienst (Kapitel 2.3.7) implementieren": Service `https://www.bdew.de/as4/communication/services/pathSwitch`, Actions `https://www.bdew.de/as4/communication/actions/requestSwitch` and `…/actions/confirmSwitch` (B §2.3.1.2.1, §2.3.1.2.2, §2.3.7); payload-less, signed, not encrypted; sent with [`Message::path_switch`](crate::as4::Message::path_switch), recognised by [`UserMessage::path_switch`](crate::as4::UserMessage::path_switch) |
    /// | Duplicate detection | required (B §2.2.5) |
    /// | Revocation | CRL from each certificate's CRL distribution point only, no OCSP (CP SM-PKI §4.9, §7.3); `nextUpdate` required (BSI TR-03109-4 Anhang B); refetched after 24 h, the last known CRL used while a fetch fails (CP Tabelle 10, §4.8.3); a certificate without CDP refused (TR Anhang A item 10); the three-day rule below (RzÜ AS4 2.6 §5.4) |
    ///
    /// Revocation (RzÜ AS4 2.6 §5.4): "Wenn die CRL einer CA über die im
    /// Zertifikat eingetragene Certificate Revocation List Distribution Point
    /// (CRL-DP) von einer CA über 3 Tage nicht abrufbar ist oder im
    /// Gültigkeitszeitraum nicht verlängert wurde, dann ist der ausstellenden
    /// CA und aller darunter gelisteten Zertifikate bis zur Veröffentlichung
    /// einer aktuellen CRL nach den Regelungen der CP zu misstrauen." Every
    /// certificate under a CA is refused when the CA's newest valid CRL is
    /// past its `nextUpdate`, or when a fetch fails more than 72 h after the
    /// last successful one; the first current CRL ends it. Every non-anchor
    /// certificate of the signer's path is checked, after the signature and
    /// the sender rule. The SM-PKI Root-CA CRL is indirect: supply its signer
    /// with [`Builder::crl_signer`](crate::Builder::crl_signer). Only `http`
    /// and `https` distribution points are fetched (an LDAP-only CDP is not
    /// obtainable).
    #[cfg(feature = "as4")]
    pub fn bdew() -> Profile {
        Self::preset(ProfileId::Bdew12)
    }

    /// **Peppol AS4 Profile 2.0.3**.
    ///
    /// | Setting | Value |
    /// |---|---|
    /// | MEP | One-Way/Push (P §4.1) |
    /// | Packaging | attachments only; no file names (P §4.10 "SHALL NOT be used") |
    /// | Compression | gzip (P §4.10) |
    /// | Signature | `rsa-sha256`, SHA-256 (P §3 → eDelivery 1.15 §3.2.6); RSA >= 2048 |
    /// | Signing token | BST `#X509v3` (P §4.7) |
    /// | Encryption | RSA-OAEP (MGF1-SHA-256, SHA-256), `aes128-gcm` (eDelivery 1.15 §3.2.6) |
    /// | Party id | fixed type `urn:fdc:peppol.eu:2017:identifiers:ap`; id = AP certificate CN (P §4.5) |
    /// | Service / Action | the process id / document type id (P §4.6), caller-set |
    /// | Roles | fixed initiator / responder (P §4.5) |
    /// | AgreementRef | `urn:fdc:peppol.eu:2017:agreements:tia:ap_provider`, no `pmode` (P §4.3) |
    /// | Inbound senders | any AP whose CN equals `eb:From/PartyId` (P §4.5, §4.7), plus pins of a configured partner |
    /// | Revocation | CRL-DP, then OCSP from the AIA; a revoked status from either refuses; a certificate publishing neither is refused (G3 certificates carry both) |
    /// | Not implemented | G3-only anchors and MLS |
    #[cfg(feature = "as4")]
    pub fn peppol() -> Profile {
        Self::preset(ProfileId::Peppol203)
    }

    /// **eDelivery AS4 1.15 Common Profile**.
    ///
    /// | Setting | Value |
    /// |---|---|
    /// | MEP | One-Way/Push, signed NRR receipt synchronous (E §3.2.1, §3.3.2) |
    /// | Packaging | SwA (E §3.2.3) |
    /// | Compression | gzip (E §3.3.1 "SHOULD compress") |
    /// | Signature | `rsa-sha256`, SHA-256 (E §3.2.6); RSA >= 2048 |
    /// | Signing token | BST `#X509v3` (E §3.2.6) |
    /// | Encryption | RSA-OAEP (MGF1-SHA-256, SHA-256), `aes128-gcm` (E §3.2.6) |
    /// | Service / Action | caller-set (E §3.4.4); the service is required |
    /// | Inbound senders | configured partners with pinned certificates only (the Dynamic Receiver, E §4.3, is not selected) |
    /// | Test service | answered, never delivered (E §3.2.4, §3.4.3) |
    /// | Revocation | CRL-DP, then OCSP from the AIA; a revoked status from either refuses; a pinned certificate publishing neither is accepted and recorded (`reason=no_source`) |
    #[cfg(feature = "as4")]
    pub fn edelivery_1_15() -> Profile {
        Self::preset(ProfileId::Edelivery115)
    }

    /// **ENTSOG AS4 Usage Profile 3.6** (cited through ENTSOG AS4 FAQ 2025
    /// §2.4, which lists every section changed between 3.6 and 4.0; the 3.6
    /// text itself is not in the reference set).
    ///
    /// | Setting | Value |
    /// |---|---|
    /// | MEP | One-Way/Push (G4 §2.2.1–2.2.2, unchanged per G-FAQ §2.4) |
    /// | Packaging | SwA (G4 §2.2.3) |
    /// | Compression | gzip, always (3.6 "Mandatory", G-FAQ §2.4 on §2.2.3.3) |
    /// | Signature | `rsa-sha256` (3.6 RSA, G-FAQ §2.4 on §2.2.6.2); RSA >= 2048 |
    /// | Encryption | RSA-OAEP, `aes128-gcm` (G-FAQ §2.4 on §2.2.6.3) |
    /// | Inbound senders | configured partners with pinned certificates only |
    /// | Revocation | CRL-DP, then OCSP from the AIA; a pinned certificate publishing neither is accepted and recorded |
    /// | Not implemented | ebCore Agreement Update; the 3.6 primary text |
    #[cfg(feature = "as4")]
    pub fn entsog() -> Profile {
        Self::preset(ProfileId::Entsog36)
    }

    /// **AS2** (RFC 4130) with this crate's floor.
    ///
    /// | Setting | Value |
    /// |---|---|
    /// | Outbound | signed (SHA-256, RFC 5751/5754) and encrypted (AES-256-CBC), not compressed (R4130 §2.4) |
    /// | MDN request | synchronous, signed, `signed-receipt-micalg=sha-256` (R4130 §7.3) |
    /// | MDN verification | signature by the partner pin (absent only with [`Quirk::UnsignedMdn`]); `Original-Message-ID` = sent id; MIC = computed MIC; disposition `processed` (R4130 §7.3.1, §7.4.3, §7.5) |
    /// | Inbound | signed and encrypted, else `processed/error: insufficient-message-security` (R4130 §7.5.3); duplicates answered `processed/warning: duplicate-document` (R4130 §9.3, §7.5.6) |
    /// | Inbound async-MDN request | answered synchronously (named gap) |
    /// | Senders | configured partners with pinned certificates |
    /// | Signer key | RSA >= 2048 or EC P-256/P-384 |
    /// | Revocation | the signer's whole path (and an MDN signer's): CRL-DP, then OCSP from the AIA; a pinned certificate publishing neither is accepted and recorded |
    #[cfg(feature = "as2")]
    pub fn as2() -> Profile {
        Self::preset(ProfileId::As2)
    }

    /// Lower the maximum inbound and outbound message size. A value above the
    /// preset's limit is refused by `build()` (tighten-only; never clamped).
    pub fn max_message_bytes(self, bytes: u64) -> Profile {
        Profile {
            max_message_bytes: Some(bytes),
            ..self
        }
    }

    // ── crate-private ───────────────────────────────────────────────────────

    #[cfg_attr(not(any(feature = "as2", feature = "as4")), allow(dead_code))]
    fn preset(id: ProfileId) -> Profile {
        Profile {
            id,
            max_message_bytes: None,
        }
    }

    pub(crate) fn id(&self) -> ProfileId {
        self.id
    }

    /// The preset name recorded in evidence and telemetry.
    pub(crate) fn name(&self) -> &'static str {
        match self.id {
            ProfileId::Bdew12 => "bdew-1.2",
            ProfileId::Peppol203 => "peppol-2.0.3",
            ProfileId::Edelivery115 => "edelivery-1.15",
            ProfileId::Entsog36 => "entsog-3.6",
            ProfileId::As2 => "as2",
        }
    }

    /// The section a refusal names.
    pub(crate) fn citation(&self) -> &'static str {
        match self.id {
            ProfileId::Bdew12 => "BDEW AS4-Profil 1.2",
            ProfileId::Peppol203 => "Peppol AS4 Profile 2.0.3",
            ProfileId::Edelivery115 => "eDelivery AS4 1.15",
            ProfileId::Entsog36 => "ENTSOG AS4 Usage Profile 3.6",
            ProfileId::As2 => "RFC 4130",
        }
    }

    pub(crate) fn protocol(&self) -> Protocol {
        match self.id {
            ProfileId::As2 => Protocol::As2,
            _ => Protocol::As4,
        }
    }

    pub(crate) fn ceiling(&self) -> u64 {
        CEILING
    }

    pub(crate) fn requested_max(&self) -> Option<u64> {
        self.max_message_bytes
    }

    /// The effective size limit (validated at `build()`).
    pub(crate) fn max_bytes(&self) -> u64 {
        self.max_message_bytes.unwrap_or(CEILING).min(CEILING)
    }

    /// The revocation rule: BDEW CRL-DP only with the three-day rule (RzÜ AS4
    /// 2.6 §5.4); Peppol CRL-DP then OCSP, no source refused; the pin-based
    /// profiles CRL-DP then OCSP, no source accepted and recorded.
    pub(crate) fn revocation(&self) -> crate::revocation::RevocationRule {
        use crate::revocation::{MissingSource, RevocationRule};
        match self.id {
            ProfileId::Bdew12 => RevocationRule::bdew(),
            ProfileId::Peppol203 => RevocationRule::crl_then_ocsp(MissingSource::Refuse),
            _ => RevocationRule::crl_then_ocsp(MissingSource::AcceptRecorded),
        }
    }

    pub(crate) fn sender_rule(&self) -> SenderRule {
        match self.id {
            ProfileId::Bdew12 => SenderRule::AnchorAndSubject,
            ProfileId::Peppol203 => SenderRule::AnchorAndCn,
            _ => SenderRule::RegisteredOnly,
        }
    }

    pub(crate) fn signer_keys(&self) -> KeyRule {
        match self.id {
            ProfileId::Bdew12 => KeyRule::EcCurve(Nid::BRAINPOOL_P256R1),
            ProfileId::As2 => KeyRule::RsaOrEc {
                rsa_min: 2048,
                curves: AS2_CURVES,
            },
            _ => KeyRule::RsaMin(2048),
        }
    }

    pub(crate) fn decrypter_keys(&self) -> KeyRule {
        match self.id {
            ProfileId::Bdew12 => KeyRule::EcCurve(Nid::BRAINPOOL_P256R1),
            _ => KeyRule::RsaMin(2048),
        }
    }

    pub(crate) fn signature_algorithm(&self) -> crate::keys::SignatureAlgorithm {
        match self.id {
            ProfileId::Bdew12 => crate::keys::SignatureAlgorithm::EcdsaSha256,
            _ => crate::keys::SignatureAlgorithm::RsaSha256,
        }
    }

    pub(crate) fn token_ref(&self) -> TokenRef {
        match self.id {
            ProfileId::Bdew12 => TokenRef::PkiPath,
            _ => TokenRef::X509v3,
        }
    }

    /// How an outbound `xenc:EncryptedKey` names the recipient: the Subject
    /// Key Identifier for BDEW (B §2.2.6.2.2 "x509SKI"; phase4
    /// `Phase4BDEWSender` `X509_SKI_KEY_IDENTIFIER`), a BST reference elsewhere
    /// (eDelivery 1.15 §3.2.6 "most widely implemented"; Peppol §4.7).
    #[cfg(feature = "as4")]
    pub(crate) fn recipient_form(&self) -> crate::crypto::wssec::xmlenc::RecipientForm {
        use crate::crypto::wssec::xmlenc::RecipientForm;
        match self.id {
            ProfileId::Bdew12 => RecipientForm::Ski,
            _ => RecipientForm::Bst,
        }
    }

    /// The encryption suite an inbound message must use, as identifiers:
    /// ECDH-ES + ConcatKDF (SHA-256) + `kw-aes128`, `aes128-gcm` for BDEW
    /// (B §2.2.6.2.2; BSI TR-03116-3 §9.2); RSA-OAEP (`xmlenc11#rsa-oaep`),
    /// `aes128-gcm` elsewhere (eDelivery 1.15 §3.2.6; `rsa-oaep-mgf1p` is
    /// refused).
    #[cfg(feature = "as4")]
    pub(crate) fn encryption_suite(&self) -> crate::crypto::wssec::xmlenc::Suite {
        use crate::crypto::alg::{AgreementAlg, KdfAlg, KeyTransportAlg, KeyWrapAlg};
        use crate::crypto::wssec::{WsSecDigestMethod, XmlEncPayloadAlgorithm};
        let content = XmlEncPayloadAlgorithm::Aes128Gcm.uri();
        match self.id {
            ProfileId::Bdew12 => crate::crypto::wssec::xmlenc::Suite {
                key_method: KeyWrapAlg::Aes128.uri(),
                agreement: Some((
                    AgreementAlg::EcdhEs.uri(),
                    KdfAlg::ConcatKdf.uri(),
                    WsSecDigestMethod::Sha256.algorithm_uri(),
                )),
                content,
            },
            _ => crate::crypto::wssec::xmlenc::Suite {
                key_method: KeyTransportAlg::RsaOaep.uri(),
                agreement: None,
                content,
            },
        }
    }

    pub(crate) fn separate_keys(&self) -> bool {
        self.id == ProfileId::Bdew12
    }

    pub(crate) fn compress(&self) -> bool {
        self.protocol() == Protocol::As4
    }

    pub(crate) fn filename_allowed(&self) -> bool {
        self.id != ProfileId::Peppol203
    }

    /// The part media type the profile fixes (BDEW §2.2.3.2).
    pub(crate) fn fixed_part_type(&self) -> Option<&'static str> {
        (self.id == ProfileId::Bdew12).then_some("application/octet-stream")
    }

    pub(crate) fn fixed_action(&self) -> Option<&'static str> {
        (self.id == ProfileId::Bdew12).then_some(DEFAULT_ACTION)
    }

    pub(crate) fn service_rule(&self) -> ServiceRule {
        match self.id {
            ProfileId::Bdew12 => ServiceRule::OneOf(BDEW_SERVICES),
            _ => ServiceRule::Required,
        }
    }

    /// Whether the profile has the payload-less transmission-path-switch
    /// service (B §2.2.8 "MUSS zusätzlich einen
    /// AS4-Übertragungspfadänderungsdienst (Kapitel 2.3.7) implementieren").
    /// BDEW only.
    pub(crate) fn path_switch(&self) -> bool {
        self.id == ProfileId::Bdew12
    }

    pub(crate) fn conversation_id_allowed(&self) -> bool {
        self.id != ProfileId::Bdew12
    }

    pub(crate) fn agreement_ref(&self) -> Option<&'static str> {
        match self.id {
            ProfileId::Bdew12 => Some(BDEW_AGREEMENT),
            ProfileId::Peppol203 => Some(PEPPOL_AGREEMENT),
            _ => None,
        }
    }

    pub(crate) fn party_types(&self) -> PartyTypeRule {
        match self.id {
            ProfileId::Bdew12 => PartyTypeRule::OneOf(BDEW_PARTY_TYPES),
            ProfileId::Peppol203 => PartyTypeRule::Fixed(PEPPOL_PARTY_TYPE),
            _ => PartyTypeRule::CallerSet,
        }
    }
}

/// A named, per-partner tolerance of one *absent* element. Never
/// tolerates a wrong value. Every acceptance it enables is recorded in the
/// evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Quirk {
    /// AS2: accept an MDN without a signature although a signed MDN was
    /// requested. A present signature that fails is still refused. Recorded in
    /// the evidence.
    UnsignedMdn,
    /// AS4: accept a *signed* receipt without
    /// `ebbp:NonRepudiationInformation`. An unsigned receipt is never
    /// accepted. Recorded in the evidence.
    ReceiptWithoutNonRepudiation,
}

impl Quirk {
    pub(crate) fn protocol(self) -> Protocol {
        match self {
            Quirk::UnsignedMdn => Protocol::As2,
            Quirk::ReceiptWithoutNonRepudiation => Protocol::As4,
        }
    }

    pub(crate) fn name(self) -> &'static str {
        match self {
            Quirk::UnsignedMdn => "unsigned_mdn",
            Quirk::ReceiptWithoutNonRepudiation => "receipt_without_non_repudiation",
        }
    }
}

// ── Resolution ──────────────────────────────────────────────────────────────

/// The resolved policy of one partner under one profile — the only thing the
/// pipelines read. Built by [`resolve`] at `build()` (or at `send`
/// for an unregistered partner), and by [`unregistered`] for senders the
/// profile admits without configuration.
#[derive(Debug, Clone)]
pub(crate) struct PartnerPolicy {
    pub(crate) profile: Profile,
    /// `None` for the unregistered-sender policy.
    pub(crate) partner: Option<Partner>,
    pub(crate) pins: Vec<crate::crypto::CertFingerprint>,
    pub(crate) encryption_cert: Option<crate::keys::Certificate>,
    pub(crate) endpoint: Option<String>,
    pub(crate) quirks: Vec<Quirk>,
    /// The client's clock: every time decision for this partner reads it
    /// (the system clock in every built client).
    pub(crate) clock: crate::clock::SharedClock,
}

/// Resolve `partner` under `profile`, read against `clock`.
pub(crate) fn resolve(
    profile: &Profile,
    partner: &Partner,
    clock: &crate::clock::SharedClock,
) -> PartnerPolicy {
    PartnerPolicy {
        clock: clock.clone(),
        profile: profile.clone(),
        partner: Some(partner.clone()),
        pins: partner
            .signing_certs()
            .iter()
            .map(|c| c.fingerprint().clone())
            .collect(),
        encryption_cert: partner.encryption_certificate().cloned(),
        endpoint: partner.endpoint_url().map(str::to_owned),
        quirks: partner.quirks().to_vec(),
    }
}

/// The header values of one outbound AS4 user message, already validated.
#[cfg(feature = "as4")]
#[derive(Debug, Clone)]
pub(crate) struct SendHeader {
    pub(crate) from_party: String,
    pub(crate) from_type: Option<String>,
    pub(crate) to_party: String,
    pub(crate) to_type: Option<String>,
    pub(crate) service: String,
    pub(crate) service_type: String,
    pub(crate) action: String,
    pub(crate) conversation_id: Option<String>,
}

impl PartnerPolicy {
    pub(crate) fn has_quirk(&self, quirk: Quirk) -> bool {
        self.quirks.contains(&quirk)
    }

    /// The AS4 send policy view.
    #[cfg(feature = "as4")]
    pub(crate) fn send_view(&self, header: &SendHeader) -> crate::as4::As4SendPolicy {
        use crate::crypto::wssec::WsSecOutboundKeyInfoProfile;
        // A path-switch message has no payload part: nothing to encrypt or
        // compress (AS4 §5.1.6; B P-Mode `Encrypt.Element[]` empty).
        // It is still signed.
        let payload_less = self.profile.path_switch()
            && crate::as4::classify_path_switch(&header.service, &header.action).is_some();
        let view = crate::as4::As4SendPolicy {
            outbound_key_info_profile: match self.profile.token_ref() {
                TokenRef::PkiPath => WsSecOutboundKeyInfoProfile::X509PKIPathv1,
                TokenRef::X509v3 => WsSecOutboundKeyInfoProfile::BinarySecurityTokenX509v3,
            },
            sign: true,
            encrypt: !payload_less,
            outbound_xmlenc_payload_algorithm:
                crate::crypto::wssec::XmlEncPayloadAlgorithm::Aes128Gcm,
            recipient_form: self.profile.recipient_form(),
            compress: self.profile.compress() && !payload_less,
            action: header.action.clone(),
            service: header.service.clone(),
            service_type: header.service_type.clone(),
            from_party_id: Some(header.from_party.clone()),
            to_party_id: Some(header.to_party.clone()),
            from_party_id_type: header.from_type.clone(),
            to_party_id_type: header.to_type.clone(),
            from_role: INITIATOR_ROLE.to_string(),
            to_role: RESPONDER_ROLE.to_string(),
            agreement_ref: self.profile.agreement_ref().map(str::to_owned),
            agreement_ref_type: None,
            ref_to_message_id: None,
            // The four-corner properties are the Peppol envelope's.
            original_sender: None,
            final_recipient: None,
            tracking_identifier: None,
            conversation_id: header.conversation_id.clone(),
            ws_addressing: None,
            sbdh_header: None,
        };
        probe::record("as4.send", &view);
        view
    }

    /// The AS4 inbound (push) policy view.
    #[cfg(feature = "as4")]
    #[allow(dead_code)]
    pub(crate) fn receive_view(&self) -> crate::as4::As4PushPolicy {
        receive_view(&self.profile)
    }
}

/// The AS4 inbound (push) policy view of `profile`: the same for every
/// sender, because inbound acceptance is the profile's.
#[cfg(feature = "as4")]
pub(crate) fn receive_view(profile: &Profile) -> crate::as4::As4PushPolicy {
    {
        let view = crate::as4::As4PushPolicy {
            require_signed_receipt: true,
            require_signed_push: true,
            require_encrypted_inbound: true,
            accept_path_switch: profile.path_switch(),
            timestamp_window: Some(crate::as4::TimestampWindow {
                future: std::time::Duration::from_secs(300),
                past: crate::dedup::MIN_RETENTION,
            }),
        };
        probe::record("as4.receive", &view);
        view
    }
}

impl PartnerPolicy {
    /// The AS4 receipt-verification view.
    #[cfg(feature = "as4")]
    pub(crate) fn receipt_view(&self) -> crate::as4::As4ReceiptPolicy {
        let view = crate::as4::As4ReceiptPolicy {
            reject_unexpected_references: true,
            require_signed_receipt: true,
            require_non_repudiation: !self.has_quirk(Quirk::ReceiptWithoutNonRepudiation),
            expected_signer_fingerprint_sha256: None,
            timestamp_freshness_window: Some(std::time::Duration::from_secs(300)),
            max_receipt_bytes: crate::as4::DEFAULT_MAX_RECEIPT_BYTES,
        };
        probe::record("as4.receipt_verify", &view);
        view
    }
}

/// The `#[doc(hidden)]` test probe of `tests/profile_reaches_wire.rs`: when
/// enabled, each use site records the policy view it read. Never public in
/// the documentation and inert unless a test enables it.
#[doc(hidden)]
pub mod probe {
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, Ordering};

    static ENABLED: AtomicBool = AtomicBool::new(false);
    static SEEN: Mutex<Vec<(&'static str, String)>> = Mutex::new(Vec::new());

    /// Start recording.
    #[doc(hidden)]
    pub fn enable() {
        ENABLED.store(true, Ordering::SeqCst);
    }

    /// The views recorded so far, as `(use site, Debug of the view)`; clears.
    #[doc(hidden)]
    pub fn take() -> Vec<(&'static str, String)> {
        std::mem::take(&mut *SEEN.lock().unwrap_or_else(|e| e.into_inner()))
    }

    #[cfg_attr(not(any(feature = "as2", feature = "as4")), allow(dead_code))]
    pub(crate) fn record(site: &'static str, view: &dyn std::fmt::Debug) {
        if ENABLED.load(Ordering::Relaxed) {
            SEEN.lock()
                .unwrap_or_else(|e| e.into_inner())
                .push((site, format!("{view:?}")));
        }
    }
}

#[cfg(all(test, feature = "as4", feature = "as2"))]
mod tests {
    use super::*;

    /// The profile table, as data: (preset, sender rule, signature,
    /// token, separate keys, compress, filename, fixed action, agreement,
    /// conversation id allowed).
    #[test]
    fn presets_match_the_profiles_contract() {
        use crate::keys::SignatureAlgorithm::*;
        type Row = (
            Profile,
            SenderRule,
            crate::keys::SignatureAlgorithm,
            TokenRef,
            bool,
            bool,
            bool,
            Option<&'static str>,
            Option<&'static str>,
            bool,
        );
        let table: [Row; 5] = [
            (
                Profile::bdew(),
                SenderRule::AnchorAndSubject,
                EcdsaSha256,
                TokenRef::PkiPath,
                true,
                true,
                true,
                Some(DEFAULT_ACTION),
                Some(BDEW_AGREEMENT),
                false,
            ),
            (
                Profile::peppol(),
                SenderRule::AnchorAndCn,
                RsaSha256,
                TokenRef::X509v3,
                false,
                true,
                false,
                None,
                Some(PEPPOL_AGREEMENT),
                true,
            ),
            (
                Profile::edelivery_1_15(),
                SenderRule::RegisteredOnly,
                RsaSha256,
                TokenRef::X509v3,
                false,
                true,
                true,
                None,
                None,
                true,
            ),
            (
                Profile::entsog(),
                SenderRule::RegisteredOnly,
                RsaSha256,
                TokenRef::X509v3,
                false,
                true,
                true,
                None,
                None,
                true,
            ),
            (
                Profile::as2(),
                SenderRule::RegisteredOnly,
                RsaSha256,
                TokenRef::X509v3,
                false,
                false,
                true,
                None,
                None,
                true,
            ),
        ];
        for (p, rule, sig, token, separate, compress, filename, action, agreement, conv) in table {
            assert_eq!(p.sender_rule(), rule, "{}", p.name());
            assert_eq!(p.signature_algorithm(), sig, "{}", p.name());
            assert_eq!(p.token_ref(), token, "{}", p.name());
            assert_eq!(p.separate_keys(), separate, "{}", p.name());
            assert_eq!(p.compress(), compress, "{}", p.name());
            assert_eq!(p.filename_allowed(), filename, "{}", p.name());
            assert_eq!(p.fixed_action(), action, "{}", p.name());
            assert_eq!(p.agreement_ref(), agreement, "{}", p.name());
            assert_eq!(p.conversation_id_allowed(), conv, "{}", p.name());
            assert_eq!(p.ceiling(), 256 * 1024 * 1024);
        }
        assert_eq!(
            Profile::bdew().party_types(),
            PartyTypeRule::OneOf(BDEW_PARTY_TYPES)
        );
        assert_eq!(
            Profile::peppol().party_types(),
            PartyTypeRule::Fixed("urn:fdc:peppol.eu:2017:identifiers:ap")
        );
        assert_eq!(
            Profile::bdew().fixed_part_type(),
            Some("application/octet-stream")
        );
        assert_eq!(BDEW_SERVICES.len(), 5);
        // The revocation rule per preset.
        {
            use crate::revocation::{MissingSource, Sources};
            use std::time::Duration;
            let day = Duration::from_secs(86_400);
            for (p, sources, next_required, distrust, missing) in [
                (
                    Profile::bdew(),
                    Sources::CrlOnly,
                    true,
                    Some(3 * day),
                    MissingSource::Refuse,
                ),
                (
                    Profile::peppol(),
                    Sources::CrlThenOcsp,
                    false,
                    None,
                    MissingSource::Refuse,
                ),
                (
                    Profile::edelivery_1_15(),
                    Sources::CrlThenOcsp,
                    false,
                    None,
                    MissingSource::AcceptRecorded,
                ),
                (
                    Profile::entsog(),
                    Sources::CrlThenOcsp,
                    false,
                    None,
                    MissingSource::AcceptRecorded,
                ),
                (
                    Profile::as2(),
                    Sources::CrlThenOcsp,
                    false,
                    None,
                    MissingSource::AcceptRecorded,
                ),
            ] {
                let rule = p.revocation();
                assert_eq!(rule.sources, sources, "{}", p.name());
                assert_eq!(rule.next_update_required, next_required, "{}", p.name());
                assert_eq!(rule.refresh_after, day, "{}", p.name());
                assert_eq!(rule.distrust_after, distrust, "{}", p.name());
                assert_eq!(rule.missing_source, missing, "{}", p.name());
                assert!(!rule.unobtainable_accepted, "{}", p.name());
            }
        }
        // The path-switch service is BDEW's alone (B §2.2.8).
        for (p, switch) in [
            (Profile::bdew(), true),
            (Profile::peppol(), false),
            (Profile::edelivery_1_15(), false),
            (Profile::entsog(), false),
            (Profile::as2(), false),
        ] {
            assert_eq!(p.path_switch(), switch, "{}", p.name());
            assert_eq!(receive_view(&p).accept_path_switch, switch, "{}", p.name());
        }
    }

    /// B §2.3.1.2.1/§2.3.1.2.2 name the path-switch URIs exactly; they are
    /// pinned as literals (phase4 `BDEWPMode.java:68-78` carries the same).
    #[test]
    fn the_path_switch_uris_match_the_profile() {
        assert_eq!(
            PATH_SWITCH_SERVICE,
            "https://www.bdew.de/as4/communication/services/pathSwitch"
        );
        assert_eq!(
            REQUEST_SWITCH_ACTION,
            "https://www.bdew.de/as4/communication/actions/requestSwitch"
        );
        assert_eq!(
            CONFIRM_SWITCH_ACTION,
            "https://www.bdew.de/as4/communication/actions/confirmSwitch"
        );
    }

    /// A path-switch message is signed, never encrypted or compressed: it has
    /// no payload part (AS4 §5.1.6).
    #[test]
    fn a_path_switch_send_view_signs_only() {
        let partner = Partner::new("9900000000002");
        let policy = resolve(&Profile::bdew(), &partner, &crate::clock::system());
        let header = |action: &str, service: &str| SendHeader {
            from_party: "9900000000001".into(),
            from_type: None,
            to_party: "9900000000002".into(),
            to_type: None,
            service: service.into(),
            service_type: String::new(),
            action: action.into(),
            conversation_id: Some(String::new()),
        };
        for action in [REQUEST_SWITCH_ACTION, CONFIRM_SWITCH_ACTION] {
            let view = policy.send_view(&header(action, PATH_SWITCH_SERVICE));
            assert!(view.sign && !view.encrypt && !view.compress, "{action}");
        }
        let business = policy.send_view(&header(DEFAULT_ACTION, BDEW_SERVICES[0]));
        assert!(business.sign && business.encrypt && business.compress);
        let mixed = policy.send_view(&header(REQUEST_SWITCH_ACTION, BDEW_SERVICES[0]));
        assert!(mixed.encrypt, "both URIs must match (D45)");
    }

    /// ebMS3 §5.2.2 specifies the Test Service URIs exactly; a typo here is
    /// a silently undetected ping, so they are pinned as literals.
    #[test]
    fn the_test_service_uris_match_the_specification() {
        assert_eq!(
            TEST_SERVICE,
            "http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/service"
        );
        assert_eq!(
            TEST_ACTION,
            "http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/test"
        );
    }

    /// An embedder's (makod's) hand-built BDEW send policy equals the
    /// resolved view, except that the view also signs, encrypts and fixes the
    /// agreement without attributes.
    #[test]
    fn bdew_send_view_matches_makod() {
        let partner = Partner::new("9900000000002")
            .party_type("urn:oasis:names:tc:ebcore:partyid-type:unregistered:BDEW");
        let policy = resolve(&Profile::bdew(), &partner, &crate::clock::system());
        let view = policy.send_view(&SendHeader {
            from_party: "9900000000001".into(),
            from_type: Some(BDEW_PARTY_TYPES[1].into()),
            to_party: "9900000000002".into(),
            to_type: Some(BDEW_PARTY_TYPES[1].into()),
            service: BDEW_SERVICES[0].into(),
            service_type: String::new(),
            action: DEFAULT_ACTION.into(),
            conversation_id: None,
        });
        assert!(view.sign && view.encrypt && view.compress);
        assert_eq!(
            view.outbound_key_info_profile,
            crate::crypto::wssec::WsSecOutboundKeyInfoProfile::X509PKIPathv1
        );
        assert_eq!(view.from_role, INITIATOR_ROLE);
        assert_eq!(view.to_role, RESPONDER_ROLE);
        assert_eq!(view.agreement_ref.as_deref(), Some(BDEW_AGREEMENT));
        assert_eq!(view.agreement_ref_type, None);
        assert_eq!(view.conversation_id, None);
        assert_eq!(view.action, DEFAULT_ACTION);
    }
}
