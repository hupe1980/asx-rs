/// SOAP envelope and ebMS3 message builder for AS4.
///
/// Every element is written with the crate's one XML writer:
/// caller values are escaped, a character XML 1.0 cannot carry is refused with
/// `InvalidInput` naming the field, and the `wsse:Security` position of a
/// signed message is a slot reserved by the writer — not a textual placeholder.
use base64::{Engine as _, engine::general_purpose::STANDARD};

use crate::core::{AsxError, ErrorCode, ErrorContext, Result};
use crate::xml::{Slot, XmlDoc, XmlFragment, XmlLimits, XmlOut, ns};

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
/// emitted (the default).
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
}

#[derive(Debug, Clone)]
pub struct SoapEnvelopeBuilder {
    message_id: String,
    /// `eb:Timestamp` for `eb:MessageInfo`. **Required** — see
    /// [`with_message_timestamp`](SoapEnvelopeBuilder::with_message_timestamp).
    message_timestamp: Option<String>,
    from_party_id: String,
    to_party_id: String,
    /// `type` attribute on the From `<eb:PartyId>`; `None` omits the attribute.
    from_party_id_type: Option<String>,
    /// `type` attribute on the To `<eb:PartyId>`; `None` omits the attribute.
    to_party_id_type: Option<String>,
    /// `<eb:From>/<eb:Role>` — REQUIRED by the ebMS3 schema.
    from_role: String,
    /// `<eb:To>/<eb:Role>` — REQUIRED by the ebMS3 schema.
    to_role: String,
    /// Optional `<eb:AgreementRef>` (first child of `CollaborationInfo`).
    agreement_ref: Option<String>,
    /// `type` attribute on `<eb:AgreementRef>`.
    agreement_ref_type: Option<String>,
    action: String,
    service: String,
    service_type: String,
    conversation_id: Option<String>,
    /// Two-Way MEP correlation: emits `<eb:RefToMessageId>` in MessageInfo.
    ref_to_message_id: Option<String>,
    original_sender: String,
    /// Emit `eb:MessageProperties` (the four-corner properties).
    message_properties: bool,
    final_recipient: String,
    tracking_identifier: String,
    payload: Vec<u8>,
    /// AS4 SwA packaging: reference the payload as a detached MIME attachment
    /// (`eb:PartInfo href="cid:…"`) and leave the SOAP Body **empty**, as the
    /// AS4 profile requires. When false, payload bytes are embedded base64 in
    /// the Body (asx's non-MIME test mode).
    detached_payload_reference: bool,
    payload_mime_type: String,
    /// `CompressionType` part property, set when the payload attachment is a
    /// compressed stream (AS4 profile §3.1).
    payload_compression_type: Option<String>,
    payload_content_id: String,
    /// Additional `eb:PartInfo` entries for a multi-payload UserMessage:
    /// `(content_id, mime_type, compression_type)`.
    extra_part_infos: Vec<(String, String, Option<String>)>,
    /// Optional WS-Addressing headers to include in the SOAP Header.
    ws_addressing: Option<WsAddressingHeaders>,
}

pub(crate) const SOAP_BODY_WSU_ID: &str = "as4-body";
/// `wsu:Id` placed on the `<ebms:Messaging>` header block so the **entire**
/// ebMS3 UserMessage (party info, service/action, message properties, payload
/// info) is covered by the WS-Security signature — not just the MessageId.
/// Signing only MessageId leaves the routing/authorization metadata tamperable.
pub(crate) const MESSAGING_WSU_ID: &str = "as4-messaging";

/// ebMS3 Core §5.2.2.3/§5.2.2.9: the default party role when a business
/// process defines no specific roles. `eb:Role` itself is REQUIRED — an
/// envelope without it violates the ebMS3 schema and strict receivers
/// (Holodeck B2B, Domibus in strict-validation mode) reject it.
pub const EBMS_DEFAULT_ROLE: &str =
    "http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/defaultRole";
/// The ebCore "unregistered" party-id scheme — the `type` value eDelivery/CEF
/// conformance setups use for party identifiers outside a registered scheme.
pub const EBCORE_PARTY_ID_TYPE_UNREGISTERED: &str =
    "urn:oasis:names:tc:ebcore:partyid-type:unregistered";

/// An envelope whose `wsse:Security` position is reserved and still empty:
/// sign [`Self::text`] (the slot lies outside every signed subtree), then
/// [`Self::seal`] it with the finished header.
#[derive(Debug)]
pub(crate) struct UnsignedEnvelope {
    doc: XmlDoc,
    slot: Slot,
    text: String,
}

impl UnsignedEnvelope {
    /// The envelope as signed: the security slot empty.
    pub(crate) fn text(&self) -> &str {
        &self.text
    }

    /// The envelope with `header` in the reserved slot.
    pub(crate) fn seal(mut self, header: XmlFragment) -> Result<String> {
        self.doc.fill(self.slot, header)?;
        self.doc.into_string()
    }
}

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
            message_timestamp: None,
            from_party_id: from_party_id.into(),
            to_party_id: to_party_id.into(),
            from_party_id_type: Some(EBCORE_PARTY_ID_TYPE_UNREGISTERED.into()),
            to_party_id_type: Some(EBCORE_PARTY_ID_TYPE_UNREGISTERED.into()),
            from_role: EBMS_DEFAULT_ROLE.into(),
            to_role: EBMS_DEFAULT_ROLE.into(),
            agreement_ref: None,
            agreement_ref_type: None,
            action: "http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/action".into(),
            service: "http://example.org/example".into(),
            service_type: "example".into(),
            conversation_id: None,
            ref_to_message_id: None,
            original_sender: String::new(),
            message_properties: true,
            final_recipient: String::new(),
            tracking_identifier: String::new(),
            payload: Vec::new(),
            detached_payload_reference: false,
            payload_mime_type: "application/octet-stream".into(),
            payload_compression_type: None,
            payload_content_id: "payload@example.org".into(),
            extra_part_infos: Vec::new(),
            ws_addressing: None,
        }
        .with_default_four_corner_properties()
    }

    /// Omit `eb:MessageProperties`: a profile without message properties
    /// (BDEW).
    pub(crate) fn without_message_properties(mut self) -> Self {
        self.message_properties = false;
        self
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
    /// under `<ebms:MessageProperties>`, each value as element text.
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

    /// AS4 SwA packaging: emit `eb:PayloadInfo/eb:PartInfo` referencing the
    /// detached MIME attachment and leave the SOAP Body empty. Combine with
    /// [`Self::with_payload_content_id`] and [`Self::with_payload_mime_type`].
    pub fn with_detached_payload_reference(mut self) -> Self {
        self.detached_payload_reference = true;
        self
    }

    /// Additional `eb:PartInfo` entries after the primary:
    /// `(content_id, mime_type, compression_type)` per part.
    pub fn with_extra_part_infos(mut self, parts: Vec<(String, String, Option<String>)>) -> Self {
        self.extra_part_infos = parts;
        self
    }

    /// Set the `type` attribute of the From/To `<eb:PartyId>` elements.
    ///
    /// `None` omits the attribute entirely (an *untyped* party identifier —
    /// what Holodeck B2B's example P-Modes use). The default is the ebCore
    /// "unregistered" scheme, which eDelivery/CEF setups expect. The value
    /// must match the counterparty's P-Mode exactly: a typed and an untyped
    /// identifier with the same text do **not** match.
    pub fn with_party_id_types(
        mut self,
        from_type: Option<String>,
        to_type: Option<String>,
    ) -> Self {
        self.from_party_id_type = from_type;
        self.to_party_id_type = to_type;
        self
    }

    /// Set the mandatory `<eb:Role>` values for From and To.
    ///
    /// Defaults to the ebMS3 default role URI for both parties. Business
    /// processes with named roles (e.g. Holodeck's example "Sender"/"Receiver")
    /// must set the values their counterparty's P-Mode declares.
    pub fn with_roles(mut self, from_role: impl Into<String>, to_role: impl Into<String>) -> Self {
        self.from_role = from_role.into();
        self.to_role = to_role.into();
        self
    }

    /// Emit an `<eb:AgreementRef>` (with optional `type` attribute) as the
    /// first child of `<eb:CollaborationInfo>`, per the ebMS3 schema order.
    pub fn with_agreement_ref(
        mut self,
        agreement: impl Into<String>,
        agreement_type: Option<String>,
    ) -> Self {
        self.agreement_ref = Some(agreement.into());
        self.agreement_ref_type = agreement_type;
        self
    }

    /// Pin `eb:MessageInfo/eb:Timestamp`. **Required** — [`build`](Self::build)
    /// fails without it.
    ///
    /// `eb:Timestamp` is inside the signed `eb:Messaging` block. Making it an
    /// input rather than an ambient clock read keeps every build of one
    /// message byte-identical, so the envelope that ships is the one that was
    /// signed.
    #[must_use]
    pub fn with_message_timestamp(mut self, timestamp: impl Into<String>) -> Self {
        self.message_timestamp = Some(timestamp.into());
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

    /// Declare that the payload attachment is compressed.
    ///
    /// `compression_type` is the media type of the compression applied
    /// (`application/gzip` for AS4). Per the AS4 profile the `MimeType`
    /// property must continue to describe the *uncompressed* payload, so set
    /// [`with_payload_mime_type`](Self::with_payload_mime_type) to the original
    /// business media type.
    pub fn with_payload_compression_type(mut self, compression_type: impl Into<String>) -> Self {
        self.payload_compression_type = Some(compression_type.into());
        self
    }

    /// Set MIME Content-ID used by `<ebms:PartInfo href="cid:...">`.
    pub fn with_payload_content_id(mut self, payload_content_id: impl Into<String>) -> Self {
        self.payload_content_id = payload_content_id.into();
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

    /// Build a SOAP envelope with an ebMS3 UserMessage.
    pub fn build(self) -> Result<Vec<u8>> {
        let (doc, _) = self.write(false)?;
        Ok(doc.into_string()?.into_bytes())
    }

    /// Build the envelope with the `wsse:Security` position reserved.
    pub(crate) fn build_with_security_slot(self) -> Result<UnsignedEnvelope> {
        let (doc, slot) = self.write(true)?;
        let slot = slot.expect("a slot was reserved");
        let text = doc.text_with_empty_slots();
        Ok(UnsignedEnvelope { doc, slot, text })
    }

    fn write(self, reserve_security: bool) -> Result<(XmlDoc, Option<Slot>)> {
        // Required, not defaulted: `eb:Timestamp` sits inside the signed
        // `eb:Messaging` block; reading the clock here would let two builds of
        // one message disagree.
        let Some(message_timestamp) = self.message_timestamp.as_deref() else {
            return Err(AsxError::new(
                ErrorCode::InvalidInput,
                "SoapEnvelopeBuilder requires an eb:Timestamp pinned with \
                 with_message_timestamp(..); reading the clock inside build() lets two \
                 builds of the same message disagree and ship an envelope its own \
                 signature does not cover",
                ErrorContext::new("as4_soap_builder"),
            ));
        };

        let mut out = XmlOut::new();
        out.declaration();
        out.start("soap:Envelope")?
            .ns("soap", ns::SOAP12)?
            .ns("ebms", ns::EBMS3)?
            .ns("wsse", ns::WSSE)?
            .ns("wsu", ns::WSU)?;
        if self.ws_addressing.is_some() {
            out.ns("wsa", ns::WSA)?;
        }
        out.start("soap:Header")?;

        // WS-Addressing headers (optional) precede ebMS3 Messaging.
        if let Some(wsa) = &self.ws_addressing {
            out.leaf("wsa:MessageID", &wsa.message_id, "wsa:MessageID")?;
            out.start("wsa:Action")?
                .attr("soap:mustUnderstand", "true", "soap:mustUnderstand")?
                .text(&wsa.action, "wsa:Action")?
                .end()?;
            out.leaf("wsa:To", &wsa.to, "wsa:To")?;
            if let Some(reply_to) = &wsa.reply_to {
                out.start("wsa:ReplyTo")?;
                out.leaf("wsa:Address", reply_to, "wsa:ReplyTo/wsa:Address")?;
                out.end()?;
            }
        }

        // The wsu:Id makes the whole block referenceable so the signature
        // covers all UserMessage routing/authorization metadata.
        out.start("ebms:Messaging")?
            .attr("soap:mustUnderstand", "true", "soap:mustUnderstand")?
            .attr("wsu:Id", MESSAGING_WSU_ID, "wsu:Id")?;
        out.start("ebms:UserMessage")?;

        out.start("ebms:MessageInfo")?;
        out.leaf("ebms:Timestamp", message_timestamp, "eb:Timestamp")?;
        // The ebMS3 header schema gives eb:MessageId no attributes (phase4
        // answers a wsu:Id there with EBMS:0009).
        out.leaf("ebms:MessageId", &self.message_id, "eb:MessageId")?;
        if let Some(ref_id) = &self.ref_to_message_id {
            out.leaf("ebms:RefToMessageId", ref_id, "eb:RefToMessageId")?;
        }
        out.end()?;

        // PartyInfo: each party carries the schema-mandatory eb:Role
        // (ebMS3 Core §5.2.2.3).
        out.start("ebms:PartyInfo")?;
        for (element, id, id_type, role) in [
            (
                "ebms:From",
                &self.from_party_id,
                &self.from_party_id_type,
                &self.from_role,
            ),
            (
                "ebms:To",
                &self.to_party_id,
                &self.to_party_id_type,
                &self.to_role,
            ),
        ] {
            out.start(element)?;
            out.start("ebms:PartyId")?;
            if let Some(t) = id_type {
                out.attr("type", t, "eb:PartyId/@type")?;
            }
            out.text(id, "eb:PartyId")?.end()?;
            out.leaf("ebms:Role", role, "eb:Role")?;
            out.end()?;
        }
        out.end()?;

        // CollaborationInfo — schema order: AgreementRef?, Service, Action,
        // ConversationId (ebMS3 Core §5.2.2.6).
        out.start("ebms:CollaborationInfo")?;
        if let Some(agreement) = &self.agreement_ref {
            out.start("ebms:AgreementRef")?;
            if let Some(t) = &self.agreement_ref_type {
                out.attr("type", t, "eb:AgreementRef/@type")?;
            }
            out.text(agreement, "eb:AgreementRef")?.end()?;
        }
        out.start("ebms:Service")?;
        if !self.service_type.is_empty() {
            out.attr("type", &self.service_type, "eb:Service/@type")?;
        }
        out.text(&self.service, "eb:Service")?.end()?;
        out.leaf("ebms:Action", &self.action, "eb:Action")?;
        // ConversationId is REQUIRED by the ebMS3 schema (minOccurs=1); the
        // Peppol convention for "no conversation semantics" is "1".
        out.leaf(
            "ebms:ConversationId",
            self.conversation_id.as_deref().unwrap_or("1"),
            "eb:ConversationId",
        )?;
        out.end()?;

        // MessageProperties — Four Corner topology routing metadata; ebMS3
        // Property values are element text.
        if self.message_properties {
            out.start("ebms:MessageProperties")?;
            for (name, value) in [
                ("originalSender", &self.original_sender),
                ("finalRecipient", &self.final_recipient),
                ("trackingIdentifier", &self.tracking_identifier),
            ] {
                write_property(&mut out, name, value)?;
            }
            out.end()?;
        }

        if !self.payload.is_empty() || self.detached_payload_reference {
            out.start("ebms:PayloadInfo")?;
            // AS4 profile §3.1 (Compression): a compressed payload MUST carry
            // a `CompressionType` part property, and `MimeType` MUST describe
            // the payload *before* compression.
            write_part_info(
                &mut out,
                &self.payload_content_id,
                &self.payload_mime_type,
                self.payload_compression_type.as_deref(),
            )?;
            for (content_id, mime_type, compression_type) in &self.extra_part_infos {
                write_part_info(&mut out, content_id, mime_type, compression_type.as_deref())?;
            }
            out.end()?;
        }

        out.end()?; // UserMessage
        out.end()?; // Messaging

        let slot = reserve_security.then(|| out.slot());

        out.end()?; // Header

        // SOAP Body. With SwA packaging the Body is EMPTY per the AS4 profile
        // — payloads travel as MIME parts referenced from the signed
        // `eb:PartInfo`.
        out.start("soap:Body")?
            .attr("wsu:Id", SOAP_BODY_WSU_ID, "wsu:Id")?;
        if !self.payload.is_empty() && !self.detached_payload_reference {
            // Payload bytes carried in the Body as base64 (non-MIME test mode).
            out.start("asx:Payload")?.ns("asx", "urn:asx:payload")?;
            out.leaf("asx:MimeType", &self.payload_mime_type, "MimeType")?;
            out.leaf("asx:Base64", &STANDARD.encode(&self.payload), "payload")?;
            out.end()?;
        }
        out.end()?;
        out.end()?;

        Ok((out.finish()?, slot))
    }
}

fn write_property(out: &mut XmlOut, name: &'static str, value: &str) -> Result<()> {
    out.start("ebms:Property")?
        .attr("name", name, "eb:Property/@name")?
        .text(value, name)?
        .end()?;
    Ok(())
}

fn write_part_info(
    out: &mut XmlOut,
    content_id: &str,
    mime_type: &str,
    compression_type: Option<&str>,
) -> Result<()> {
    out.start("ebms:PartInfo")?
        .attr("href", &format!("cid:{content_id}"), "eb:PartInfo/@href")?;
    out.start("ebms:PartProperties")?;
    write_property(out, "MimeType", mime_type)?;
    if let Some(compression_type) = compression_type {
        write_property(out, "CompressionType", compression_type)?;
    }
    out.end()?;
    out.end()?;
    Ok(())
}

/// Encode `cert_der` as a minimal DER `SEQUENCE { Certificate }` suitable for
/// embedding in a `wsse:BinarySecurityToken` with `ValueType="...#X509PKIPathv1"`.
///
/// RFC 3820 defines PKIPath as `SEQUENCE SIZE (1..MAX) OF Certificate`.  For
/// single-certificate chains — the typical case for asx-rs — this is a SEQUENCE
/// wrapping exactly one DER-encoded certificate.
pub fn build_pkipath_der(cert_der: &[u8]) -> Vec<u8> {
    let len = cert_der.len();
    let mut result = vec![0x30u8]; // SEQUENCE tag
    if len < 128 {
        result.push(len as u8);
    } else if len < 0x100 {
        result.extend_from_slice(&[0x81, len as u8]);
    } else if len < 0x1_0000 {
        result.extend_from_slice(&[0x82, (len >> 8) as u8, len as u8]);
    } else {
        result.extend_from_slice(&[0x83, (len >> 16) as u8, (len >> 8) as u8, len as u8]);
    }
    result.extend_from_slice(cert_der);
    result
}

/// A PKIPath (RFC 3820 `SEQUENCE OF Certificate`) of `root_first`: the
/// issuer before the subject, the signer last. One certificate gives exactly
/// [`build_pkipath_der`]'s output.
pub(crate) fn build_pkipath_chain_der(root_first: &[&[u8]]) -> Vec<u8> {
    let content: Vec<u8> = root_first.concat();
    build_pkipath_der(&content)
}

/// The `wsse:Security` header for a prepared signature: `ds:Signature` from
/// `raw_signature` (DER for ECDSA; converted to `r‖s`) and the signer chain
/// (leaf first, DER) as the token `key_info` names — a PKIPath (root first)
/// for `X509PKIPathv1`, the leaf as X509v3 otherwise.
pub(crate) fn security_header(
    prepared: crate::crypto::wssec::sign::PreparedSignature,
    raw_signature: Vec<u8>,
    chain_der: &[Vec<u8>],
    key_info: crate::crypto::wssec::WsSecOutboundKeyInfoProfile,
    now: std::time::SystemTime,
    encryption: Option<XmlFragment>,
) -> Result<XmlFragment> {
    let leaf_der = chain_der.first().ok_or_else(|| {
        AsxError::new(
            ErrorCode::PolicyViolation,
            "the signer has no certificate",
            ErrorContext::new("wssec_sign"),
        )
    })?;
    let signature_xml =
        crate::crypto::wssec::sign::finish_signature(prepared, raw_signature, leaf_der, key_info)?
            .into_string();
    let mut builder = WsSecurityHeaderBuilder::new()
        .at(now)
        .with_signature_xml(signature_xml);
    builder.encryption = encryption;
    let builder = if key_info == crate::crypto::wssec::WsSecOutboundKeyInfoProfile::X509PKIPathv1 {
        let root_first: Vec<&[u8]> = chain_der.iter().rev().map(Vec::as_slice).collect();
        builder.with_signing_cert_pkipath_der(build_pkipath_chain_der(&root_first))
    } else {
        let pem = openssl::x509::X509::from_der(leaf_der)
            .and_then(|cert| cert.to_pem())
            .map_err(|_err| {
                AsxError::new(
                    ErrorCode::ParseFailed,
                    "failed to serialize the signing certificate to PEM",
                    ErrorContext::new("wssec_sign"),
                )
            })?;
        builder.with_signing_cert(pem)
    };
    builder.build_fragment()
}

/// WS-Security header builder for X.509 certificate-based signing
#[derive(Debug, Clone)]
pub struct WsSecurityHeaderBuilder {
    signing_cert_pem: Option<Vec<u8>>,
    /// When `Some`, emits a `wsse:BinarySecurityToken` with
    /// `ValueType="...#X509PKIPathv1"` instead of `#X509v3`.
    /// The value is the base64-encoded DER-encoded PKIPath (SEQUENCE OF Certificate).
    signing_cert_pkipath_der: Option<Vec<u8>>,
    signature_xml: Option<String>,
    /// `wsu:Created`; `wsu:Expires` is five minutes later.
    now: std::time::SystemTime,
    /// The SwA encryption envelope (recipient BST, `EncryptedKey`,
    /// `EncryptedData`s), placed before the signer's token.
    encryption: Option<XmlFragment>,
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
            signing_cert_pkipath_der: None,
            signature_xml: None,
            now: crate::clock::system().now(),
            encryption: None,
        }
    }

    /// Stamp the `wsu:Timestamp` at `now` (the session clock).
    pub(crate) fn at(mut self, now: std::time::SystemTime) -> Self {
        self.now = now;
        self
    }

    pub fn with_signing_cert(mut self, cert_pem: Vec<u8>) -> Self {
        self.signing_cert_pem = Some(cert_pem);
        self
    }

    /// Emit a `wsse:BinarySecurityToken` with
    /// `ValueType="...#X509PKIPathv1"` carrying a DER-encoded PKIPath
    /// (`SEQUENCE { Certificate }`).
    ///
    /// Used together with [`WsSecOutboundKeyInfoProfile::X509PKIPathv1`](crate::crypto::wssec::WsSecOutboundKeyInfoProfile::X509PKIPathv1) so
    /// that the `ds:KeyInfo` `<wsse:SecurityTokenReference>` in the signature
    /// references this BST by `wsu:Id="X509PKIPathToken"`.
    ///
    /// Build the PKIPath bytes from a single DER certificate:
    /// ```text
    /// let cert_der = signing_cert_ref.to_der()?;
    /// let pkipath = build_pkipath_der(&cert_der);
    /// builder = builder.with_signing_cert_pkipath_der(pkipath);
    /// ```
    pub fn with_signing_cert_pkipath_der(mut self, pkipath_der: Vec<u8>) -> Self {
        self.signing_cert_pkipath_der = Some(pkipath_der);
        self
    }

    /// The `ds:Signature` element to place in the header. It must be one
    /// well-formed element (it is parsed with the envelope limits and inserted
    /// as that element).
    pub fn with_signature_xml(mut self, signature_xml: impl Into<String>) -> Self {
        self.signature_xml = Some(signature_xml.into());
        self
    }

    /// Build WS-Security header XML: a standalone `wsse:Security` element that
    /// declares the namespaces it uses.
    /// Includes a `wsu:Timestamp` with a 5-minute window. WS-Security 1.1.1 §10
    /// makes the element optional; it is emitted so a receiver can bound the
    /// message lifetime, and inbound timestamps are validated when present.
    pub fn build(self) -> Result<Vec<u8>> {
        Ok(self.build_fragment()?.into_string().into_bytes())
    }

    /// [`Self::build`] as a writer fragment, for a writer slot.
    pub(crate) fn build_fragment(self) -> Result<XmlFragment> {
        let now = self.now;
        let created = crate::time_utils::format_rfc3339_secs(now);
        let expires =
            crate::time_utils::format_rfc3339_secs(now + std::time::Duration::from_secs(300));

        let mut out = XmlOut::new();
        out.start("wsse:Security")?
            .ns("wsse", ns::WSSE)?
            .ns("wsu", ns::WSU)?
            .ns("soap", ns::SOAP12)?
            .attr("soap:mustUnderstand", "true", "soap:mustUnderstand")?;

        out.start("wsu:Timestamp")?
            .attr("wsu:Id", "Timestamp", "wsu:Id")?;
        out.leaf("wsu:Created", &created, "wsu:Created")?;
        out.leaf("wsu:Expires", &expires, "wsu:Expires")?;
        out.end()?;

        if let Some(encryption) = &self.encryption {
            out.fragment(encryption)?;
        }

        if let Some(cert_pem) = self.signing_cert_pem {
            // The BST carries base64(DER), never base64(PEM).
            let cert_der = openssl::x509::X509::from_pem(&cert_pem)
                .and_then(|cert| cert.to_der())
                .map_err(|err| {
                    AsxError::new(
                        ErrorCode::ParseFailed,
                        format!("signing certificate PEM could not be converted to DER: {err}"),
                        ErrorContext::new("wssec_header_builder"),
                    )
                })?;
            write_binary_security_token(
                &mut out,
                "X509Token",
                ns::WSSE_X509V3_VALUE_TYPE,
                &cert_der,
            )?;
        }

        if let Some(pkipath_der) = self.signing_cert_pkipath_der {
            write_binary_security_token(
                &mut out,
                "X509PKIPathToken",
                ns::WSSE_X509_PKIPATH_VALUE_TYPE,
                &pkipath_der,
            )?;
        }

        if let Some(signature_xml) = &self.signature_xml {
            out.document_element(
                signature_xml,
                XmlLimits::ENVELOPE,
                "WsSecurityHeaderBuilder signature",
            )?;
        }

        out.end()?;
        out.finish()?.into_fragment()
    }
}

fn write_binary_security_token(
    out: &mut XmlOut,
    id: &str,
    value_type: &'static str,
    der: &[u8],
) -> Result<()> {
    out.start("wsse:BinarySecurityToken")?
        .attr("wsu:Id", id, "wsu:Id")?
        .attr("EncodingType", ns::WSSE_BASE64_ENCODING, "EncodingType")?
        .attr("ValueType", value_type, "ValueType")?
        .text(&STANDARD.encode(der), "BinarySecurityToken")?
        .end()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn soap_envelope_builder_generates_valid_xml() {
        let builder =
            SoapEnvelopeBuilder::new("msg-123", "sender@example.org", "receiver@example.com")
                .with_message_timestamp("2026-09-06T12:00:00Z")
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
        assert!(envelope_str.contains("name=\"trackingIdentifier\">msg-123</"));
        // From and To must differ
        assert_ne!(
            envelope_str.find("sender@example.org"),
            envelope_str
                .rfind("sender@example.org")
                .filter(|_| envelope_str.contains("receiver@example.com")),
        );
    }

    /// ebMS3 schema conformance of PartyInfo/CollaborationInfo:
    /// mandatory eb:Role on both parties, optional PartyId type attribute,
    /// AgreementRef ordered before Service, and an always-present
    /// ConversationId (defaulting to "1", the Peppol convention).
    #[test]
    fn soap_envelope_emits_schema_mandatory_party_and_collaboration_elements() {
        // Defaults: unregistered party-id type, ebMS3 default role, conv "1".
        let default_envelope = String::from_utf8(
            SoapEnvelopeBuilder::new("m-1", "pa", "pb")
                .with_message_timestamp("2026-09-06T12:00:00Z")
                .build()
                .expect("build"),
        )
        .expect("utf8");
        assert!(default_envelope.contains(
            "<ebms:PartyId type=\"urn:oasis:names:tc:ebcore:partyid-type:unregistered\">pa</ebms:PartyId>"
        ));
        assert_eq!(
            default_envelope
                .matches(&format!("<ebms:Role>{EBMS_DEFAULT_ROLE}</ebms:Role>"))
                .count(),
            2,
            "both From and To must carry the mandatory eb:Role: {default_envelope}"
        );
        assert!(
            default_envelope.contains("<ebms:ConversationId>1</ebms:ConversationId>"),
            "ConversationId is schema-mandatory and must default to \"1\": {default_envelope}"
        );

        // Explicit overrides: untyped party ids, named roles, agreement ref.
        let envelope = String::from_utf8(
            SoapEnvelopeBuilder::new("m-2", "org:example:company:A", "org:example:company:B")
                .with_message_timestamp("2026-09-06T12:00:00Z")
                .with_party_id_types(None, None)
                .with_roles("Sender", "Receiver")
                .with_agreement_ref("http://agreements.example.org/a0", None)
                .build()
                .expect("build"),
        )
        .expect("utf8");
        assert!(envelope.contains("<ebms:PartyId>org:example:company:A</ebms:PartyId>"));
        assert!(envelope.contains("<ebms:Role>Sender</ebms:Role>"));
        assert!(envelope.contains("<ebms:Role>Receiver</ebms:Role>"));
        let agreement_pos = envelope
            .find("<ebms:AgreementRef>http://agreements.example.org/a0</ebms:AgreementRef>")
            .expect("AgreementRef present");
        let service_pos = envelope.find("<ebms:Service").expect("Service present");
        assert!(
            agreement_pos < service_pos,
            "schema order: AgreementRef must precede Service"
        );
    }

    #[test]
    fn soap_envelope_builder_allows_overriding_four_corner_properties() {
        let builder = SoapEnvelopeBuilder::new("msg-abc", "ap-sender", "ap-receiver")
            .with_message_timestamp("2026-09-06T12:00:00Z")
            .with_four_corner_properties("participant-a", "participant-b", "track-789");

        let envelope = builder.build().expect("build");
        let envelope_str = String::from_utf8(envelope).expect("utf8");

        assert!(envelope_str.contains("name=\"originalSender\">participant-a</"));
        assert!(envelope_str.contains("name=\"finalRecipient\">participant-b</"));
        assert!(envelope_str.contains("name=\"trackingIdentifier\">track-789</"));
    }

    #[test]
    fn soap_envelope_escapes_xml_characters() {
        let builder =
            SoapEnvelopeBuilder::new("msg-<test>", "sender@example.org", "receiver@example.com")
                .with_message_timestamp("2026-09-06T12:00:00Z");
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
        // A real certificate is required: the BST carries base64(DER), so the
        // builder converts the PEM — garbage input is a build error
        // instead of a silently unparseable token.
        let rsa = openssl::rsa::Rsa::generate(2048).expect("rsa");
        let pkey = openssl::pkey::PKey::from_rsa(rsa).expect("pkey");
        let mut name = openssl::x509::X509NameBuilder::new().expect("name");
        name.append_entry_by_nid(openssl::nid::Nid::COMMONNAME, "bst-test")
            .expect("cn");
        let name = name.build();
        let mut cert = openssl::x509::X509::builder().expect("builder");
        cert.set_subject_name(&name).expect("subject");
        cert.set_issuer_name(&name).expect("issuer");
        cert.set_pubkey(&pkey).expect("pubkey");
        let not_before = openssl::asn1::Asn1Time::days_from_now(0).expect("nb");
        let not_after = openssl::asn1::Asn1Time::days_from_now(1).expect("na");
        cert.set_not_before(&not_before).expect("nb");
        cert.set_not_after(&not_after).expect("na");
        cert.sign(&pkey, openssl::hash::MessageDigest::sha256())
            .expect("sign");
        let cert = cert.build();
        let cert_pem = cert.to_pem().expect("pem");

        let builder = WsSecurityHeaderBuilder::new()
            .with_signing_cert(cert_pem)
            .with_signature_xml(r#"<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"/>"#);
        let header = builder.build().expect("build");
        let header_str = String::from_utf8(header).expect("utf8");

        assert!(header_str.contains("wsse:BinarySecurityToken"));
        assert!(header_str.contains("ds:Signature"));
        // The token content must be base64(DER), not base64(PEM).
        let der_b64 = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            cert.to_der().expect("der"),
        );
        assert!(
            header_str.contains(&der_b64),
            "BinarySecurityToken must carry base64(DER)"
        );
    }
}

#[cfg(test)]
mod timestamp_pinning_tests {
    use super::*;

    /// `eb:Timestamp` sits inside the signed `eb:Messaging` block. A `build()` that read the clock itself would disagree with an earlier
    /// build of the same message whenever the two straddled a second, shipping
    /// an envelope that is not the one that was signed. Making the timestamp a
    /// *required input* turns that race into an error at the first build.
    #[test]
    fn build_refuses_without_a_pinned_timestamp() {
        let err = SoapEnvelopeBuilder::new("msg-1", "from", "to")
            .with_action("urn:example:action")
            .build()
            .expect_err("an unpinned timestamp must be an error, not a clock read");

        assert_eq!(err.code, crate::core::ErrorCode::InvalidInput);
        assert!(
            err.message.contains("with_message_timestamp"),
            "the error names the fix: {}",
            err.message
        );
    }

    /// Two builds of the same message must be byte-identical, because the
    /// second is what ships and the first is what was digested.
    #[test]
    fn two_builds_with_a_pinned_timestamp_agree() {
        let make = || {
            SoapEnvelopeBuilder::new("msg-1", "from", "to")
                .with_action("urn:example:action")
                .with_message_timestamp("2026-09-06T12:00:00Z")
                .build()
                .expect("build")
        };

        assert_eq!(
            make(),
            make(),
            "a pinned timestamp must make the build deterministic"
        );
    }

    /// The reserved `wsse:Security` slot sits outside both signed subtrees, so
    /// sealing the header into it cannot change `eb:Messaging` or `soap:Body`
    /// — which is what makes one build plus a fill safe where two builds were
    /// not. There is no textual placeholder to search for.
    #[test]
    fn sealing_the_security_header_leaves_the_signed_subtrees_untouched() {
        let unsigned = SoapEnvelopeBuilder::new("msg-1", "from", "to")
            .with_action("urn:example:action")
            .with_message_timestamp("2026-09-06T12:00:00Z")
            .build_with_security_slot()
            .expect("build");
        let before = unsigned.text().to_string();
        assert!(!before.contains("wsse:Security"));
        let header = WsSecurityHeaderBuilder::new()
            .build_fragment()
            .expect("header");
        let sealed = unsigned.seal(header).expect("seal");

        let messaging = |xml: &str| {
            let start = xml.find("<ebms:Messaging").expect("messaging");
            let end = xml.find("</ebms:Messaging>").expect("messaging end");
            xml[start..end].to_string()
        };
        let body = |xml: &str| {
            let start = xml.find("<soap:Body").expect("body");
            xml[start..].to_string()
        };

        assert_eq!(messaging(&before), messaging(&sealed));
        assert_eq!(body(&before), body(&sealed));
        assert!(sealed.contains("<wsse:Security"));
        roxmltree::Document::parse(&sealed).expect("sealed envelope is well-formed");
    }

    /// The negative half: one second's difference changes the signed bytes,
    /// which is precisely why the pin has to exist — and proves the test above
    /// is testing something.
    #[test]
    fn a_timestamp_one_second_apart_changes_the_signed_bytes() {
        let make = |ts: &str| {
            SoapEnvelopeBuilder::new("msg-1", "from", "to")
                .with_action("urn:example:action")
                .with_message_timestamp(ts)
                .build()
                .expect("build")
        };

        assert_ne!(
            make("2026-09-06T12:00:00Z"),
            make("2026-09-06T12:00:01Z"),
            "eb:Timestamp is inside the signed eb:Messaging block"
        );
    }
}
