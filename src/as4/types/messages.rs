//! Send output, receive request/output, parsed messages and receive outcomes.

use super::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SoapEnvelope {
    pub action: String,
    pub body: Arc<[u8]>,
}

/// Output from AS4 message sending
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct As4SendOutput {
    pub message_id: String,
    pub action: String,
    /// HTTP `Content-Type` to use for transport send.
    ///
    /// `multipart/related` for MIME attachment mode.
    pub http_content_type: String,
    pub soap_envelope: SoapEnvelope,
    /// The `<eb:RefToMessageId>` value emitted in the outbound envelope, if any.
    ///
    /// Mirrors [`As4SendPolicy::ref_to_message_id`].  Callers can use this to
    /// confirm which correlation ID was embedded in the sent message.
    pub ref_to_message_id: Option<String>,
}

// ---------------------------------------------------------------------------
// WS-Addressing receive-path types
// ---------------------------------------------------------------------------

/// WS-Addressing headers extracted from an inbound AS4 SOAP envelope.
///
/// These are read from the `http://www.w3.org/2005/08/addressing` namespace
/// elements in the SOAP Header.  Fields are `None` when the corresponding
/// element was absent.
///
/// # Conformance note
///
/// For CEF eDelivery AS4 v1.15 strict mode, `message_id` and `action` are
/// mandatory.  `to` is strongly recommended.  Missing `message_id` or `action`
/// in strict mode triggers an `InteropPolicyViolation` error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ParsedWsAddressingHeaders {
    /// `wsa:MessageID` — unique URI identifying this message instance.
    pub message_id: Option<String>,
    /// `wsa:Action` — SOAP action URI; should match `<eb:Action>`.
    pub action: Option<String>,
    /// `wsa:To` — intended recipient endpoint URI.
    pub to: Option<String>,
    /// `wsa:ReplyTo/wsa:Address` — reply-to endpoint, if present.
    pub reply_to: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(test, derive(Default))]
pub(crate) struct ParsedAs4UserMessage {
    pub message_id: String,
    pub action: String,
    /// All `<eb:From>/<eb:PartyId>` values from the inbound UserMessage.
    ///
    /// ebMS3 §5.2.2.4 permits multiple `<eb:PartyId>` per party for
    /// multi-scheme identifiers (e.g., GLN + DUNS).  This `Vec` is always
    /// non-empty; the **first element** is the primary routing identifier,
    /// accessible via [`from_party_id()`][Self::from_party_id].
    pub from_party_ids: Vec<String>,
    /// All `<eb:To>/<eb:PartyId>` values from the inbound UserMessage.
    ///
    /// Always non-empty; primary routing identifier accessible via
    /// [`to_party_id()`][Self::to_party_id].
    pub to_party_ids: Vec<String>,
    /// The `type` of the first `eb:From/eb:PartyId`.
    pub from_party_type: Option<String>,
    /// The `type` of the first `eb:To/eb:PartyId`.
    pub to_party_type: Option<String>,
    pub mpc: Option<String>,
    pub conversation_id: Option<String>,
    pub has_ws_security_header: bool,
    /// `<eb:Service>` value from the inbound UserMessage's `<eb:CollaborationInfo>`.
    ///
    /// Required for P-Mode resolution and Test Service detection.
    pub service: Option<String>,
    /// Present when the inbound UserMessage carries `<eb:RefToMessageId>`.
    ///
    /// Non-`None` indicates the sender is using the **Two-Way/Push-and-Push MEP**
    /// and this message is a response correlated to the original request message.
    pub ref_to_message_id: Option<String>,
    /// Four Corner topology `originalSender` MessageProperty value.
    pub original_sender: Option<String>,
    /// Four Corner topology `finalRecipient` MessageProperty value.
    pub final_recipient: Option<String>,
    /// Four Corner topology `trackingIdentifier` MessageProperty value.
    pub tracking_identifier: Option<String>,
    /// `<eb:Timestamp>` from `<eb:MessageInfo>` in RFC 3339 / ISO 8601 format.
    ///
    /// Present on virtually all conformant AS4 messages.  When `Some`, callers
    /// should validate freshness via [`ParsedAs4UserMessage::check_timestamp_freshness`]
    /// before processing the payload.  A missing timestamp is allowed (the field is
    /// optional in ebMS3) but signals an older or non-conformant sender implementation.
    pub timestamp: Option<String>,
    /// WS-Addressing headers extracted from the inbound SOAP envelope, if present.
    ///
    /// `None` when the inbound message carries no `wsa:*` elements in the SOAP
    /// Header.  Non-`None` when at least one WS-Addressing element was present;
    /// individual fields may still be `None` if omitted by the sender.
    ///
    /// CEF strict conformance requires `wsa:MessageID` and `wsa:Action`.
    pub wsa_headers: Option<ParsedWsAddressingHeaders>,
}

impl ParsedAs4UserMessage {
    /// Returns the primary sender party identifier (first `<eb:From>/<eb:PartyId>`).
    ///
    /// For peers that advertise only a single `<eb:PartyId>` this is equivalent
    /// to the sole identifier.  When multiple scheme-specific identifiers are
    /// present (ebMS3 §5.2.2.4), this returns the first one as encountered in
    /// the XML, which is the primary routing identifier by convention.
    #[inline]
    pub(crate) fn sender_party_id(&self) -> &str {
        &self.from_party_ids[0]
    }

    /// Returns the primary recipient party identifier (first `<eb:To>/<eb:PartyId>`).
    #[inline]
    pub(crate) fn to_party_id(&self) -> &str {
        &self.to_party_ids[0]
    }

    /// Validate that the `<eb:Timestamp>` is within the allowed freshness window.
    ///
    /// Judge `eb:Timestamp` against `window` at `now` (asymmetric): more
    /// than `window.future` ahead is refused (clock skew, eDelivery AS4 1.15
    /// §5.1.3), and more than `window.past` behind (the dedup retention: a
    /// replay inside it is recognised as a duplicate, one outside it is not).
    /// A retry that reuses the first attempt's timestamp is therefore
    /// accepted for as long as the receiver remembers the message.
    ///
    /// An absent timestamp passes (the parser requires one for user
    /// messages); an unparseable one is refused.
    pub(crate) fn check_timestamp_freshness(
        &self,
        window: super::TimestampWindow,
        now: std::time::SystemTime,
    ) -> crate::core::Result<()> {
        use crate::core::{AsxError, ErrorCode, ErrorContext};

        let ts_str = match &self.timestamp {
            Some(s) => s,
            None => return Ok(()),
        };

        let ts_secs = crate::time_utils::parse_rfc3339_to_unix_secs(ts_str).ok_or_else(|| {
            AsxError::new(
                ErrorCode::ParseFailed,
                format!("eb:Timestamp value '{ts_str}' is not a valid RFC 3339 timestamp"),
                ErrorContext::new("as4_timestamp_freshness"),
            )
        })?;

        let now_secs = crate::time_utils::unix_secs(now);
        let (ahead, behind) = (ts_secs - now_secs, now_secs - ts_secs);
        let refused = |detail: String| {
            AsxError::new(
                ErrorCode::SecurityVerificationFailed,
                format!("eb:Timestamp {detail}; message rejected to prevent replay"),
                ErrorContext::new("as4_timestamp_freshness")
                    .with_message_id(self.message_id.clone()),
            )
        };
        if ahead > window.future.as_secs() as i64 {
            return Err(refused(format!(
                "is {ahead} s in the future (allowed {} s)",
                window.future.as_secs()
            )));
        }
        if behind > window.past.as_secs() as i64 {
            return Err(refused(format!(
                "is {behind} s old, beyond the duplicate-detection retention ({} s)",
                window.past.as_secs()
            )));
        }

        Ok(())
    }
}
