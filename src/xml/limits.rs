//! Per-class XML limits: the one table.
//!
//! None of these values is public or configurable. They bound the work an
//! unauthenticated sender can cause before the signature is checked
//! (`ENVELOPE`, `SMP`) and the memory an authenticated payload can take
//! (`payload`).

/// Limits for one document class.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct XmlLimits {
    /// Largest accepted document, in bytes (checked before anything else).
    pub(crate) max_bytes: usize,
    /// Most DOM nodes (elements, text, comments, PIs) `roxmltree` may build.
    pub(crate) max_nodes: u32,
    /// Deepest element nesting, checked by a linear pre-scan **before** the
    /// tree is built: `roxmltree` recurses once per nesting level.
    pub(crate) max_depth: u16,
    /// Most attributes (namespace declarations included) on one element.
    pub(crate) max_attributes: u16,
}

impl XmlLimits {
    /// SOAP envelopes: push, signals and receipts, outbound C14N input, the
    /// sent-envelope re-read. 20,000 nodes ≈ 10,000 elements of an indented
    /// document; depth 64 is ~6× the deepest element of an AS4 envelope with
    /// `wsse:Security`.
    pub(crate) const ENVELOPE: Self = Self {
        max_bytes: 4 * 1024 * 1024,
        max_nodes: 20_000,
        max_depth: 64,
        max_attributes: 64,
    };

    /// Peppol SMP responses (`SignedServiceMetadata`).
    pub(crate) const SMP: Self = Self {
        max_bytes: 2 * 1024 * 1024,
        max_nodes: 20_000,
        max_depth: 64,
        max_attributes: 64,
    };

    /// Business payloads: SBDH documents, XML attachments digested for a
    /// `cid:` reference, encrypted payloads. Parsed only after the envelope
    /// signature verified, so these bound memory, not pre-authentication
    /// work; 4,000,000 nodes covers a 10,000-line UBL invoice with headroom.
    pub(crate) const fn payload(max_bytes: usize) -> Self {
        Self {
            max_bytes,
            max_nodes: 4_000_000,
            max_depth: 256,
            max_attributes: 256,
        }
    }
}

/// Depth bound of the C14N serializer: the largest class depth. Every input
/// it sees came through [`crate::xml::parse`], so this is defence in depth.
pub(crate) const MAX_C14N_DEPTH: u16 = 256;
