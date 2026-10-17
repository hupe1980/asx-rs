//! What the library verified (`Verified<T>`), a partner's acknowledgement
//! (`Receipt`) and one payload part (`Payload`).

use crate::audit::AuditRecord;
use crate::keys::Certificate;

/// A value the library verified: signature, signer authorization, decryption,
/// digests and replay checks passed, in that order. There
/// is no public constructor.
///
/// ```compile_fail
/// // Only the library creates a `Verified`.
/// let forged = asx::Verified::new(asx::Receipt::default());
/// ```
pub struct Verified<T> {
    inner: T,
    signer: Certificate,
    evidence: AuditRecord,
}

impl<T> Verified<T> {
    /// The single constructor. Called by exactly four pipelines: AS4 inbound,
    /// AS4 receipt verification, AS2 inbound and AS2 MDN verification
    /// (`tests/source_gates.rs` counts the call sites).
    #[cfg_attr(not(any(feature = "as2", feature = "as4")), allow(dead_code))]
    pub(crate) fn new(inner: T, signer: Certificate, evidence: AuditRecord) -> Self {
        Self {
            inner,
            signer,
            evidence,
        }
    }

    /// The certificate that made the verified signature (pinned or
    /// anchor-and-subject bound).
    pub fn signer(&self) -> &Certificate {
        &self.signer
    }

    /// The audit record of this leg, exactly as handed to the `AuditSink`. For
    /// a receipt or MDN it carries the verified signal bytes
    /// ([`AuditRecord::signal`]); for an inbound message the receipt is not
    /// yet issued, so `signal()` is `None` until the record the sink receives
    /// after `accept`.
    pub fn evidence(&self) -> &AuditRecord {
        &self.evidence
    }

    /// The verified value.
    pub fn into_inner(self) -> T {
        self.inner
    }
}

impl<T> std::ops::Deref for Verified<T> {
    type Target = T;

    fn deref(&self) -> &T {
        &self.inner
    }
}

impl<T: std::fmt::Debug> std::fmt::Debug for Verified<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Verified")
            .field("inner", &self.inner)
            .field("signer", &self.signer)
            .field("record_id", &self.evidence.record_id())
            .finish()
    }
}

/// A partner's acknowledgement: AS4 `eb:Receipt` or AS2 MDN (`processed`).
/// Read it through [`Verified`]: the evidence carries the bytes.
#[derive(Debug, Clone)]
pub struct Receipt {
    #[allow(dead_code)]
    ref_to_message_id: String,
    #[allow(dead_code)]
    kind: ReceiptKind,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub(crate) enum ReceiptKind {
    As4,
    Mdn {
        disposition: String,
        warning: Option<String>,
    },
}

impl Receipt {
    #[cfg_attr(not(any(feature = "as2", feature = "as4")), allow(dead_code))]
    pub(crate) fn new(ref_to_message_id: impl Into<String>, kind: ReceiptKind) -> Self {
        Self {
            ref_to_message_id: ref_to_message_id.into(),
            kind,
        }
    }
}

/// One payload part (AS4 `eb:PartInfo` / AS2 body).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Payload {
    bytes: bytes::Bytes,
    mime_type: String,
    name: Option<String>,
}

impl Payload {
    /// `mime_type` is validated (no CR/LF, RFC 2045 token syntax) at `send`.
    pub fn new(bytes: impl Into<bytes::Bytes>, mime_type: impl Into<String>) -> Payload {
        Payload {
            bytes: bytes.into(),
            mime_type: mime_type.into(),
            name: None,
        }
    }

    /// A file name (`Content-Disposition`; BDEW AF §2.12). Refused under
    /// `Profile::peppol()` (Peppol AS4 §4.10). Validated at `send`.
    pub fn named(self, name: impl Into<String>) -> Payload {
        Payload {
            name: Some(name.into()),
            ..self
        }
    }

    /// The payload octets.
    pub fn bytes(&self) -> &bytes::Bytes {
        &self.bytes
    }

    /// The business media type.
    pub fn mime_type(&self) -> &str {
        &self.mime_type
    }

    /// The file name, if any.
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_fields_are_stored_verbatim() {
        let p = Payload::new(&b"x"[..], "text/plain\r\nX: y").named("a\"b");
        assert_eq!(p.mime_type(), "text/plain\r\nX: y");
        assert_eq!(p.name(), Some("a\"b"));
        assert_eq!(&p.bytes()[..], b"x");
    }
}
