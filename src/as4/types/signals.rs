//! Receipt NRI references, received errors and verified receipts.

use super::*;

/// A single `<ds:Reference>` extracted from an inbound message's XMLDSig
/// `<ds:SignedInfo>`.  Pass a slice of these to
/// [`crate::as4::signals::generate_receipt_with_nri`] to build a conformant
/// Non-Repudiation of Origin (NRO) receipt per ebMS3 §5.2.2.1.
///
/// Obtain these values from [`crate::crypto::wssec::parse_signature_references`]
/// after verifying the inbound message signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct As4NriReference {
    /// The `URI` attribute of the `<ds:Reference>` element (e.g., `"#body"`).
    pub uri: String,
    /// The `Algorithm` attribute of `<ds:DigestMethod>`.
    pub digest_method_uri: String,
    /// The base64-encoded digest value from `<ds:DigestValue>`.
    pub digest_value_b64: String,
}

impl From<&WsSecSignatureReference> for As4NriReference {
    /// Convert a [`WsSecSignatureReference`] (from `parse_signature_references`)
    /// directly into an [`As4NriReference`] suitable for
    /// [`crate::as4::signals::generate_receipt_with_nri`].
    fn from(r: &WsSecSignatureReference) -> Self {
        Self {
            uri: r.uri.clone(),
            digest_method_uri: r.digest_method.algorithm_uri().to_string(),
            digest_value_b64: r.digest_value_base64.clone(),
        }
    }
}

impl From<WsSecSignatureReference> for As4NriReference {
    /// Convert an owned [`WsSecSignatureReference`] into an [`As4NriReference`]
    /// while reusing owned string buffers where possible.
    fn from(r: WsSecSignatureReference) -> Self {
        Self {
            uri: r.uri,
            digest_method_uri: r.digest_method.algorithm_uri().to_string(),
            digest_value_b64: r.digest_value_base64,
        }
    }
}

/// A single `<eb:Error>` entry parsed from a counterparty `eb:SignalMessage`.
///
/// ebMS3 §6.2 defines `eb:Error` with the attributes reproduced here plus the
/// optional `eb:Description` / `eb:ErrorDetail` child elements.  All fields
/// except [`error_code`](Self::error_code) are optional in the schema and are
/// reported exactly as received — no normalization, no defaulting.
///
/// Use [`As4ErrorCode::from_ebms_code`] to map [`error_code`](Self::error_code)
/// onto the subset of codes this crate models, and
/// [`As4ErrorSeverity::from_ebms_severity`] for
/// [`severity`](Self::severity).  Codes outside that subset are still fully
/// available as the raw string — an unrecognised code is never dropped.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub(crate) struct As4ReceivedError {
    /// The `errorCode` attribute, e.g. `"EBMS:0302"`.  `"unknown"` when the
    /// counterparty omitted the attribute (schema-invalid but observed in the
    /// wild).
    pub error_code: String,
    /// The `severity` attribute, e.g. `"failure"` / `"warning"`.
    pub severity: Option<String>,
    /// The `category` attribute, e.g. `"Content"`, `"Processing"`.
    pub category: Option<String>,
    /// The `origin` attribute, e.g. `"ebMS"`, `"security"`, `"reliability"`.
    pub origin: Option<String>,
    /// The `refToMessageId` attribute — the message this error refers to.
    ///
    /// Note that ebMS3 also allows the correlation to be carried only by the
    /// enclosing `eb:MessageInfo/eb:RefToMessageId`; see
    /// [`As4ErrorSignal::ref_to_message_id`].
    pub ref_to_message_id: Option<String>,
    /// The `shortDescription` attribute, e.g. `"InvalidReceipt"`.
    pub short_description: Option<String>,
    /// Text of the `eb:Description` child element.
    pub description: Option<String>,
    /// Text of the `eb:ErrorDetail` child element.
    pub error_detail: Option<String>,
}

/// A counterparty `eb:SignalMessage` carrying one or more `eb:Error` entries.
///
/// The synchronous answer when the remote MSH rejected the message instead
/// of acknowledging it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub(crate) struct As4ErrorSignal {
    /// `eb:MessageInfo/eb:MessageId` of the error signal itself.
    pub message_id: Option<String>,
    /// `eb:MessageInfo/eb:RefToMessageId` — the message being rejected.
    pub ref_to_message_id: Option<String>,
    /// `eb:MessageInfo/eb:Timestamp` as received (RFC 3339).
    pub timestamp: Option<String>,
    /// Every `eb:Error` entry in the signal, in document order.
    pub errors: Vec<As4ReceivedError>,
}

/// A counterparty `eb:Receipt` that passed every check demanded by an
/// [`As4ReceiptPolicy`](crate::as4::As4ReceiptPolicy).
///
/// Produced by the send path's receipt verification.  Holding one of these is
/// the evidence that the message was delivered: when
/// [`non_repudiation`](Self::non_repudiation) is
/// [`Verified`](crate::as4::As4NonRepudiation::Verified) the counterparty
/// signed a statement about the exact digests the sent message was signed over.
///
/// The library hands the same evidence — the receipt bytes, its signer and the
/// NRR digests — to the configured [`crate::audit::AuditSink`] before this
/// value is returned.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub(crate) struct As4VerifiedReceipt {
    /// `eb:MessageId` of the receipt SignalMessage itself, when present.
    pub message_id: Option<String>,
    /// `eb:RefToMessageId` — verified equal to the sent message id.
    pub ref_to_message_id: String,
    /// `eb:Timestamp` as received (RFC 3339), when present.
    pub timestamp: Option<String>,
    /// Whether the receipt carried a WS-Security XML Signature.  When `true`
    /// the signature was verified — an unverifiable signature is an error, never
    /// a `true` here.
    pub signed: bool,
    /// SHA-256 fingerprint the signer certificate was pinned against, when the
    /// receipt was signed.
    pub signer_fingerprint_sha256: Option<String>,
    /// Outcome of the Non-Repudiation of Receipt digest check.
    pub non_repudiation: crate::as4::As4NonRepudiation,
}
