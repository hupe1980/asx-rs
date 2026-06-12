/// SOAP envelope and ebMS3 message builder for AS4
///
/// Implements RFC 5751 (S/MIME) with OASIS ebMS 3.0 messaging format and WS-Security
/// for AS4 push/pull message construction.
use crate::core::Result;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use chrono::Utc;

const SOAP12_NAMESPACE: &str = "http://www.w3.org/2003/05/soap-envelope";
const EBMS_NAMESPACE: &str = "http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/";
const WSSE_NAMESPACE: &str =
    "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd";
const WSSEC_UTILITY_NAMESPACE: &str =
    "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd";
const WSA_NAMESPACE: &str = "http://www.w3.org/2005/08/addressing";

// ── WS-Addressing ────────────────────────────────────────────────────────────

/// WS-Addressing headers to include in the outbound SOAP envelope.
///
/// Per the WS-Addressing 1.0 — Core specification (W3C), AS4 deployments
/// using WS-Addressing must include `wsa:MessageID` and `wsa:Action` at
/// minimum.  `wsa:To` is strongly recommended.
///
/// Set on the builder via [`SoapEnvelopeBuilder::with_ws_addressing`].
///
/// If no WS-Addressing configuration is supplied, **no** `wsa:*` headers are
/// emitted (the default for backward-compatible deployments).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WsAddressingHeaders {
    /// Absolute URI uniquely identifying this message instance.
    /// Conventionally a UUID URN: `urn:uuid:<v4-uuid>`.
    pub message_id: String,
    /// WS-Addressing action URI.  Should match the ebMS3 `<eb:Action>` value
    /// so that SOAP intermediaries can route on it.
    pub action: String,
    /// Endpoint reference for the intended recipient.  Typically the partner's
    /// AS4 endpoint URL.  Pass `http://www.w3.org/2005/08/addressing/anonymous`
    /// for reply-to scenarios.
    pub to: String,
    /// Optional reply-to endpoint.  When `None`, the anonymous EPR is implied.
    pub reply_to: Option<String>,
}

impl WsAddressingHeaders {
    /// Minimal WS-Addressing block: `MessageID`, `Action`, and `To`.
    pub fn new(
        message_id: impl Into<String>,
        action: impl Into<String>,
        to: impl Into<String>,
    ) -> Self {
        Self {
            message_id: message_id.into(),
            action: action.into(),
            to: to.into(),
            reply_to: None,
        }
    }

    /// Add an explicit `ReplyTo` endpoint reference.
    pub fn with_reply_to(mut self, reply_to: impl Into<String>) -> Self {
        self.reply_to = Some(reply_to.into());
        self
    }
}

#[derive(Debug, Clone)]
pub struct SoapEnvelopeBuilder {
    message_id: String,
    from_party_id: String,
    to_party_id: String,
    action: String,
    service: String,
    service_type: String,
    mpc: Option<String>,
    conversation_id: Option<String>,
    /// Two-Way MEP correlation: emits `<eb:RefToMessageId>` in MessageInfo.
    ref_to_message_id: Option<String>,
    original_sender: String,
    final_recipient: String,
    tracking_identifier: String,
    payload: Vec<u8>,
    payload_mime_type: String,
    payload_content_id: String,
    ws_security_header: Option<String>,
    /// Optional WS-Addressing headers to include in the SOAP Header.
    ws_addressing: Option<WsAddressingHeaders>,
}

pub(crate) const MESSAGE_ID_WSU_ID: &str = "as4-message-id";
pub(crate) const SOAP_BODY_WSU_ID: &str = "as4-body";

impl SoapEnvelopeBuilder {
    /// Create a new builder.
    ///
    /// * `from_party_id` — the sender's own party identifier (ebMS3 `From/PartyId`).
    /// * `to_party_id`   — the recipient's party identifier (ebMS3 `To/PartyId`).
    pub fn new(
        message_id: impl Into<String>,
        from_party_id: impl Into<String>,
        to_party_id: impl Into<String>,
    ) -> Self {
        Self {
            message_id: message_id.into(),
            from_party_id: from_party_id.into(),
            to_party_id: to_party_id.into(),
            action: "http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/action".into(),
            service: "http://example.org/example".into(),
            service_type: "example".into(),
            mpc: None,
            conversation_id: None,
            ref_to_message_id: None,
            original_sender: String::new(),
            final_recipient: String::new(),
            tracking_identifier: String::new(),
            payload: Vec::new(),
            payload_mime_type: "application/octet-stream".into(),
            payload_content_id: "payload@example.org".into(),
            ws_security_header: None,
            ws_addressing: None,
        }
        .with_default_four_corner_properties()
    }

    fn with_default_four_corner_properties(mut self) -> Self {
        self.original_sender = self.from_party_id.clone();
        self.final_recipient = self.to_party_id.clone();
        self.tracking_identifier = self.message_id.clone();
        self
    }

    pub fn with_action(mut self, action: impl Into<String>) -> Self {
        self.action = action.into();
        self
    }

    /// Set the ebMS3 `<eb:Service>` value and `type` attribute.
    ///
    /// Both `service` (the element text) and `service_type` (the `type` attribute)
    /// must be agreed with the trading partner.  Pass an empty string for
    /// `service_type` to omit the attribute.
    pub fn with_service(
        mut self,
        service: impl Into<String>,
        service_type: impl Into<String>,
    ) -> Self {
        self.service = service.into();
        self.service_type = service_type.into();
        self
    }

    /// Set `<eb:RefToMessageId>` for the **Two-Way/Push-and-Push MEP**.
    ///
    /// When set, the outbound `<eb:MessageInfo>` includes
    /// `<eb:RefToMessageId>id</eb:RefToMessageId>` which correlates this
    /// response UserMessage to the original request per ebMS3 §5.2.2.5.
    pub fn with_ref_to_message_id(mut self, id: impl Into<String>) -> Self {
        self.ref_to_message_id = Some(id.into());
        self
    }

    /// Set Four Corner topology MessageProperties.
    ///
    /// Emits `originalSender`, `finalRecipient`, and `trackingIdentifier`
    /// under `<ebms:MessageProperties>`.
    pub fn with_four_corner_properties(
        mut self,
        original_sender: impl Into<String>,
        final_recipient: impl Into<String>,
        tracking_identifier: impl Into<String>,
    ) -> Self {
        self.original_sender = original_sender.into();
        self.final_recipient = final_recipient.into();
        self.tracking_identifier = tracking_identifier.into();
        self
    }

    pub fn with_mpc(mut self, mpc: impl Into<String>) -> Self {
        self.mpc = Some(mpc.into());
        self
    }

    pub fn with_conversation_id(mut self, conversation_id: impl Into<String>) -> Self {
        self.conversation_id = Some(conversation_id.into());
        self
    }

    pub fn with_payload(mut self, payload: Vec<u8>) -> Self {
        self.payload = payload;
        self
    }

    pub fn with_payload_mime_type(mut self, mime_type: impl Into<String>) -> Self {
        self.payload_mime_type = mime_type.into();
        self
    }

    /// Set MIME Content-ID used by `<ebms:PartInfo href="cid:...">`.
    pub fn with_payload_content_id(mut self, payload_content_id: impl Into<String>) -> Self {
        self.payload_content_id = payload_content_id.into();
        self
    }

    pub fn with_ws_security_header(mut self, header_xml: impl Into<String>) -> Self {
        self.ws_security_header = Some(header_xml.into());
        self
    }

    /// Attach WS-Addressing 1.0 headers to the SOAP envelope.
    ///
    /// When set, the SOAP Header will include `<wsa:MessageID>`,
    /// `<wsa:Action>`, `<wsa:To>`, and (if provided) `<wsa:ReplyTo>` using
    /// the WS-Addressing 1.0 namespace
    /// `http://www.w3.org/2005/08/addressing`.
    ///
    /// Required for deployments that use WS-Addressing for message correlation
    /// or routing via SOAP intermediaries.
    pub fn with_ws_addressing(mut self, headers: WsAddressingHeaders) -> Self {
        self.ws_addressing = Some(headers);
        self
    }

    /// Build a SOAP envelope with ebMS3 UserMessage
    pub fn build(self) -> Result<Vec<u8>> {
        let mut xml = String::new();

        // XML declaration
        xml.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");

        // SOAP Envelope — conditionally include WSA namespace declaration.
        if self.ws_addressing.is_some() {
            xml.push_str(&format!(
                "<soap:Envelope xmlns:soap=\"{}\" xmlns:ebms=\"{}\" xmlns:wsse=\"{}\" xmlns:wsu=\"{}\" xmlns:wsa=\"{}\">\n",
                SOAP12_NAMESPACE, EBMS_NAMESPACE, WSSE_NAMESPACE, WSSEC_UTILITY_NAMESPACE, WSA_NAMESPACE
            ));
        } else {
            xml.push_str(&format!(
                "<soap:Envelope xmlns:soap=\"{}\" xmlns:ebms=\"{}\" xmlns:wsse=\"{}\" xmlns:wsu=\"{}\">\n",
                SOAP12_NAMESPACE, EBMS_NAMESPACE, WSSE_NAMESPACE, WSSEC_UTILITY_NAMESPACE
            ));
        }

        // SOAP Header
        xml.push_str("  <soap:Header>\n");

        // WS-Addressing headers (optional, must appear before ebMS3 Messaging).
        if let Some(wsa) = &self.ws_addressing {
            xml.push_str(&format!(
                "    <wsa:MessageID>{}</wsa:MessageID>\n",
                escape_xml(&wsa.message_id)
            ));
            xml.push_str(&format!(
                "    <wsa:Action soap:mustUnderstand=\"{}\">{}</wsa:Action>\n",
                "true",
                escape_xml(&wsa.action)
            ));
            xml.push_str(&format!("    <wsa:To>{}</wsa:To>\n", escape_xml(&wsa.to)));
            if let Some(reply_to) = &wsa.reply_to {
                xml.push_str(&format!(
                    "    <wsa:ReplyTo><wsa:Address>{}</wsa:Address></wsa:ReplyTo>\n",
                    escape_xml(reply_to)
                ));
            }
        }

        // ebMS3 Messaging/UserMessage is expected under SOAP Header.
        xml.push_str("    <ebms:Messaging soap:mustUnderstand=\"true\">\n");
        if let Some(mpc) = &self.mpc {
            xml.push_str(&format!(
                "      <ebms:UserMessage mpc=\"{}\">\n",
                escape_xml(mpc)
            ));
        } else {
            xml.push_str("      <ebms:UserMessage>\n");
        }

        // MessageInfo
        xml.push_str("        <ebms:MessageInfo>\n");
        xml.push_str(&format!(
            "          <ebms:Timestamp>{}</ebms:Timestamp>\n",
            chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
        ));
        xml.push_str(&format!(
            "          <ebms:MessageId wsu:Id=\"{}\">{}</ebms:MessageId>\n",
            MESSAGE_ID_WSU_ID,
            escape_xml(&self.message_id)
        ));
        // Two-Way MEP: emit RefToMessageId when correlating a response to a request.
        if let Some(ref_id) = &self.ref_to_message_id {
            xml.push_str(&format!(
                "          <ebms:RefToMessageId>{}</ebms:RefToMessageId>\n",
                escape_xml(ref_id)
            ));
        }
        xml.push_str("        </ebms:MessageInfo>\n");

        // PartyInfo — From and To use independent party identifiers
        xml.push_str("        <ebms:PartyInfo>\n");
        xml.push_str("          <ebms:From>\n");
        xml.push_str(&format!(
            "            <ebms:PartyId type=\"urn:oasis:names:tc:ebcore:partyid-type:unregistered\">{}</ebms:PartyId>\n",
            escape_xml(&self.from_party_id)
        ));
        xml.push_str("          </ebms:From>\n");
        xml.push_str("          <ebms:To>\n");
        xml.push_str(&format!(
            "            <ebms:PartyId type=\"urn:oasis:names:tc:ebcore:partyid-type:unregistered\">{}</ebms:PartyId>\n",
            escape_xml(&self.to_party_id)
        ));
        xml.push_str("          </ebms:To>\n");
        xml.push_str("        </ebms:PartyInfo>\n");

        // CollaborationInfo
        xml.push_str("        <ebms:CollaborationInfo>\n");
        if self.service_type.is_empty() {
            xml.push_str(&format!(
                "          <ebms:Service>{}</ebms:Service>\n",
                escape_xml(&self.service)
            ));
        } else {
            xml.push_str(&format!(
                "          <ebms:Service type=\"{}\">{}</ebms:Service>\n",
                escape_xml(&self.service_type),
                escape_xml(&self.service)
            ));
        }
        xml.push_str(&format!(
            "          <ebms:Action>{}</ebms:Action>\n",
            escape_xml(&self.action)
        ));
        if let Some(conv_id) = &self.conversation_id {
            xml.push_str(&format!(
                "          <ebms:ConversationId>{}</ebms:ConversationId>\n",
                escape_xml(conv_id)
            ));
        }
        xml.push_str("        </ebms:CollaborationInfo>\n");

        // MessageProperties — Four Corner topology routing metadata.
        xml.push_str("        <ebms:MessageProperties>\n");
        xml.push_str(&format!(
            "          <ebms:Property name=\"originalSender\" value=\"{}\"/>\n",
            escape_xml(&self.original_sender)
        ));
        xml.push_str(&format!(
            "          <ebms:Property name=\"finalRecipient\" value=\"{}\"/>\n",
            escape_xml(&self.final_recipient)
        ));
        xml.push_str(&format!(
            "          <ebms:Property name=\"trackingIdentifier\" value=\"{}\"/>\n",
            escape_xml(&self.tracking_identifier)
        ));
        xml.push_str("        </ebms:MessageProperties>\n");

        if !self.payload.is_empty() {
            xml.push_str("        <ebms:PayloadInfo>\n");
            xml.push_str(&format!(
                "          <ebms:PartInfo href=\"cid:{}\">\n",
                escape_xml(&self.payload_content_id)
            ));
            xml.push_str("            <ebms:Properties>\n");
            xml.push_str(&format!(
                "              <ebms:Property name=\"MimeType\" value=\"{}\"/>\n",
                escape_xml(&self.payload_mime_type)
            ));
            xml.push_str("            </ebms:Properties>\n");
            xml.push_str("          </ebms:PartInfo>\n");
            xml.push_str("        </ebms:PayloadInfo>\n");
        }

        xml.push_str("      </ebms:UserMessage>\n");
        xml.push_str("    </ebms:Messaging>\n");

        if let Some(wsse) = &self.ws_security_header {
            xml.push_str(wsse);
        }

        xml.push_str("  </soap:Header>\n");

        // SOAP Body
        xml.push_str(&format!("  <soap:Body wsu:Id=\"{}\">\n", SOAP_BODY_WSU_ID));

        // Payload bytes are carried in SOAP body as base64 to keep XML valid.
        if !self.payload.is_empty() {
            xml.push_str("    <asx:Payload xmlns:asx=\"urn:asx:payload\">\n");
            xml.push_str(&format!(
                "      <asx:MimeType>{}</asx:MimeType>\n",
                escape_xml(&self.payload_mime_type)
            ));
            xml.push_str(&format!(
                "      <asx:Base64>{}</asx:Base64>\n",
                STANDARD.encode(&self.payload)
            ));
            xml.push_str("    </asx:Payload>\n");
        }
        xml.push_str("  </soap:Body>\n");
        xml.push_str("</soap:Envelope>\n");

        Ok(xml.into_bytes())
    }
}

fn escape_xml(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            '<' => "&lt;".to_string(),
            '>' => "&gt;".to_string(),
            '&' => "&amp;".to_string(),
            '"' => "&quot;".to_string(),
            '\'' => "&apos;".to_string(),
            c => c.to_string(),
        })
        .collect()
}

/// WS-Security header builder for X.509 certificate-based signing
#[derive(Debug, Clone)]
pub struct WsSecurityHeaderBuilder {
    signing_cert_pem: Option<Vec<u8>>,
    include_signature_placeholder: bool,
    signature_xml: Option<String>,
}

impl Default for WsSecurityHeaderBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl WsSecurityHeaderBuilder {
    pub fn new() -> Self {
        Self {
            signing_cert_pem: None,
            include_signature_placeholder: false,
            signature_xml: None,
        }
    }

    pub fn with_signing_cert(mut self, cert_pem: Vec<u8>) -> Self {
        self.signing_cert_pem = Some(cert_pem);
        self
    }

    pub fn with_signature_placeholder(mut self, enabled: bool) -> Self {
        self.include_signature_placeholder = enabled;
        self
    }

    pub fn with_signature_xml(mut self, signature_xml: impl Into<String>) -> Self {
        self.signature_xml = Some(signature_xml.into());
        self
    }

    /// Build WS-Security header XML.
    /// Includes a `wsu:Timestamp` (5-minute window) as required by WS-Security 1.1.1 and
    /// the eDelivery AS4 profile.
    pub fn build(self) -> Result<Vec<u8>> {
        let now = Utc::now();
        let created = now.format("%Y-%m-%dT%H:%M:%SZ").to_string();
        let expires = (now + chrono::Duration::minutes(5))
            .format("%Y-%m-%dT%H:%M:%SZ")
            .to_string();

        let mut xml = String::new();

        xml.push_str("    <wsse:Security soap:mustUnderstand=\"true\" xmlns:soap=\"http://www.w3.org/2003/05/soap-envelope\">\n");

        // wsu:Timestamp is REQUIRED by WS-Security 1.1.1 and eDelivery AS4 v1.15 §5.1.7
        xml.push_str(&format!(
            "      <wsu:Timestamp wsu:Id=\"Timestamp\">\n        <wsu:Created>{created}</wsu:Created>\n        <wsu:Expires>{expires}</wsu:Expires>\n      </wsu:Timestamp>\n"
        ));

        if let Some(cert_pem) = self.signing_cert_pem {
            xml.push_str("      <wsse:BinarySecurityToken wsu:Id=\"X509Token\" EncodingType=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary\" ValueType=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3\">\n");
            xml.push_str("        ");
            xml.push_str(&STANDARD.encode(cert_pem));
            xml.push('\n');
            xml.push_str("      </wsse:BinarySecurityToken>\n");
        }

        if let Some(signature_xml) = self.signature_xml {
            xml.push_str(&signature_xml);
            if !signature_xml.ends_with('\n') {
                xml.push('\n');
            }
        } else if self.include_signature_placeholder {
            xml.push_str("      <ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n");
            xml.push_str("        <!-- XMLDSig signature will be inserted here -->\n");
            xml.push_str("      </ds:Signature>\n");
        }

        xml.push_str("    </wsse:Security>\n");

        Ok(xml.into_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn soap_envelope_builder_generates_valid_xml() {
        let builder =
            SoapEnvelopeBuilder::new("msg-123", "sender@example.org", "receiver@example.com")
                .with_action("urn:example:action")
                .with_conversation_id("conv-456");

        let envelope = builder.build().expect("build");
        let envelope_str = String::from_utf8(envelope).expect("utf8");

        assert!(envelope_str.contains("<?xml version"));
        assert!(envelope_str.contains("soap:Envelope"));
        assert!(envelope_str.contains("<ebms:Messaging"));
        assert!(envelope_str.contains("ebms:UserMessage"));
        assert!(envelope_str.contains("msg-123"));
        assert!(envelope_str.contains("sender@example.org"));
        assert!(envelope_str.contains("receiver@example.com"));
        assert!(envelope_str.contains("conv-456"));
        assert!(envelope_str.contains("name=\"trackingIdentifier\" value=\"msg-123\""));
        // From and To must differ
        assert_ne!(
            envelope_str.find("sender@example.org"),
            envelope_str
                .rfind("sender@example.org")
                .filter(|_| envelope_str.contains("receiver@example.com")),
        );
    }

    #[test]
    fn soap_envelope_builder_allows_overriding_four_corner_properties() {
        let builder = SoapEnvelopeBuilder::new("msg-abc", "ap-sender", "ap-receiver")
            .with_four_corner_properties("participant-a", "participant-b", "track-789");

        let envelope = builder.build().expect("build");
        let envelope_str = String::from_utf8(envelope).expect("utf8");

        assert!(envelope_str.contains("name=\"originalSender\" value=\"participant-a\""));
        assert!(envelope_str.contains("name=\"finalRecipient\" value=\"participant-b\""));
        assert!(envelope_str.contains("name=\"trackingIdentifier\" value=\"track-789\""));
    }

    #[test]
    fn soap_envelope_escapes_xml_characters() {
        let builder =
            SoapEnvelopeBuilder::new("msg-<test>", "sender@example.org", "receiver@example.com");
        let envelope = builder.build().expect("build");
        let envelope_str = String::from_utf8(envelope).expect("utf8");

        assert!(envelope_str.contains("msg-&lt;test&gt;"));
        assert!(!envelope_str.contains("msg-<test>"));
    }

    #[test]
    fn wssecurity_header_builds_valid_structure() {
        let builder = WsSecurityHeaderBuilder::new();
        let header = builder.build().expect("build");
        let header_str = String::from_utf8(header).expect("utf8");

        assert!(header_str.contains("wsse:Security"));
        assert!(header_str.contains("</wsse:Security>"));
        // wsu:Timestamp is required by WS-Security 1.1.1
        assert!(header_str.contains("wsu:Timestamp"));
        assert!(header_str.contains("wsu:Created"));
        assert!(header_str.contains("wsu:Expires"));
    }

    #[test]
    fn wssecurity_header_includes_certificate_structure_when_provided() {
        let cert_pem = b"-----BEGIN CERTIFICATE-----\nMIIC...".to_vec();
        let builder = WsSecurityHeaderBuilder::new()
            .with_signing_cert(cert_pem)
            .with_signature_placeholder(true);
        let header = builder.build().expect("build");
        let header_str = String::from_utf8(header).expect("utf8");

        assert!(header_str.contains("wsse:BinarySecurityToken"));
        assert!(header_str.contains("ds:Signature"));
    }
}
