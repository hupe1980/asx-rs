//! Outbound send policy (`As4SendPolicy`, its builder) and its consistency checks.

use super::*;

/// Policy for AS4 message sending.
///
/// ## Two-Way / Push-and-Push MEP (eDelivery AS4 v1.15 §3.2.1)
///
/// To send a **response** UserMessage that correlates to a previously received push,
/// set [`ref_to_message_id`](Self::ref_to_message_id) to the `message_id` of the
/// original inbound message.  The builder emits `<eb:RefToMessageId>` in the SOAP
/// `<eb:MessageInfo>` block, which is the correlation mechanism defined by ebMS3
/// for the Two-Way/Push-and-Push MEP.
///
/// On the **receive** side, the correlation value is available via
/// [`ParsedAs4UserMessage::ref_to_message_id`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct As4SendPolicy {
    pub outbound_key_info_profile: WsSecOutboundKeyInfoProfile,
    pub sign: bool,
    pub encrypt: bool,
    /// XML Encryption payload algorithm used when `encrypt = true`.
    ///
    /// Defaults to `Aes128Gcm` for eDelivery AS4 v1.15 Common Profile
    /// conformance. Set to `Aes256Gcm` only for partner-specific agreements.
    pub outbound_xmlenc_payload_algorithm: XmlEncPayloadAlgorithm,
    /// How the `xenc:EncryptedKey` names the recipient (profile data).
    pub recipient_form: crate::crypto::wssec::xmlenc::RecipientForm,
    pub compress: bool,
    /// ebMS3 `<eb:Action>` value for this message.
    ///
    /// Per ebMS3 Core Specification §5.2.2.7, the action identifies the
    /// business process step within the service agreement.  Must be agreed
    /// with the trading partner.  Defaults to a placeholder; always override
    /// for production deployments.
    pub action: String,
    /// ebMS3 `<eb:Service>` value (URI or name).
    ///
    /// Identifies the service or business process.  Must match the trading
    /// partner P-Mode agreement.  Defaults to a placeholder.
    pub service: String,
    /// ebMS3 `<eb:Service type="…">` attribute value.
    ///
    /// Typically `"urn:oasis:names:tc:ebcore:partyid-type:unregistered"` for
    /// unregistered services or a specific scheme URI for Peppol/CEF networks.
    /// Defaults to `"example"`.
    pub service_type: String,
    /// Explicit `<eb:From>/<eb:PartyId>` value.
    ///
    /// When `None`, the session id is used — acceptable for closed loops where
    /// both ends are asx, but a real counterparty resolves its P-Mode against
    /// this value, so production sends should always set it to the party
    /// identifier from the trading-partner agreement.
    pub from_party_id: Option<String>,
    /// Explicit `<eb:To>/<eb:PartyId>` value. Defaults to the session's
    /// partner id when `None`; same caveat as [`Self::from_party_id`].
    pub to_party_id: Option<String>,
    /// `type` attribute of the From `<eb:PartyId>`. `None` omits the
    /// attribute (an *untyped* identifier). Defaults to the ebCore
    /// "unregistered" scheme. Typed and untyped identifiers with identical
    /// text do **not** match during P-Mode resolution — this must mirror the
    /// counterparty's P-Mode exactly.
    pub from_party_id_type: Option<String>,
    /// `type` attribute of the To `<eb:PartyId>`; see [`Self::from_party_id_type`].
    pub to_party_id_type: Option<String>,
    /// `<eb:From>/<eb:Role>` — REQUIRED by the ebMS3 schema. Defaults to the
    /// ebMS3 default-role URI.
    pub from_role: String,
    /// `<eb:To>/<eb:Role>` — REQUIRED by the ebMS3 schema. Defaults to the
    /// ebMS3 default-role URI.
    pub to_role: String,
    /// Optional `<eb:AgreementRef>` naming the trading-partner agreement this
    /// exchange runs under (first child of `CollaborationInfo`).
    pub agreement_ref: Option<String>,
    /// `type` attribute of `<eb:AgreementRef>`.
    pub agreement_ref_type: Option<String>,
    /// Optional `<eb:RefToMessageId>` for **Two-Way/Push-and-Push MEP**.
    ///
    /// When `Some(id)`, the outbound SOAP envelope includes
    /// `<eb:RefToMessageId>id</eb:RefToMessageId>` in `<eb:MessageInfo>`,
    /// correlating this message to the original inbound message with that ID.
    pub ref_to_message_id: Option<String>,
    /// Four Corner topology `originalSender` MessageProperty override.
    ///
    /// When `None`, outbound generation defaults to the primary `From/PartyId`.
    pub original_sender: Option<String>,
    /// Four Corner topology `finalRecipient` MessageProperty override.
    ///
    /// When `None`, outbound generation defaults to the primary `To/PartyId`.
    pub final_recipient: Option<String>,
    /// Four Corner topology `trackingIdentifier` MessageProperty override.
    ///
    /// When `None`, outbound generation defaults to the ebMS `MessageId`.
    pub tracking_identifier: Option<String>,
    /// Optional ebMS3 `<eb:ConversationId>` override.
    pub conversation_id: Option<String>,
    /// Optional WS-Addressing headers to include in outbound SOAP messages.
    ///
    /// When `Some`, the SOAP Header block will include `wsa:MessageID`,
    /// `wsa:Action`, `wsa:To`, and (optionally) `wsa:ReplyTo`.
    ///
    /// Required for CEF strict conformance testing and SOAP intermediary routing.
    /// Set `wsa:Action` to match the ebMS3 `<eb:Action>` value.
    pub ws_addressing: Option<WsAddressingHeaders>,
    /// Optional SBDH header used to wrap outbound business payloads.
    ///
    /// When set, AS4 send paths wrap the supplied business payload bytes in a
    /// `StandardBusinessDocument` envelope before compression/encryption/signing.
    pub sbdh_header: Option<SbdhHeader>,
}
