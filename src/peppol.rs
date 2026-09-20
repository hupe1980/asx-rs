//! Peppol network rules that sit above a single protocol.
//!
//! Most of what Peppol mandates is expressed elsewhere in this crate — the
//! envelope in [`crate::sbdh`], discovery in [`crate::smp`], the wire in
//! [`crate::as4`]. What lives here is the part that spans them: **Message
//! Level Status**, which is an AS4 message, carrying a Peppol document,
//! addressed by an SMP lookup, requested through the envelope.
//!
//! # What this module is not
//!
//! It does not build an MLS document. That is a Peppol business document and
//! belongs to the layer that knows what business documents mean — the same
//! boundary that keeps EDIFACT and UBL out of this crate. What is here is the
//! transport half: which participant to send it to, when it must be sent, and
//! whether it is wanted at all.

/// The Peppol participant identifier scheme, used everywhere a party is named.
///
/// ISO 6523 ICD-qualified identifiers, e.g. `0088:5790002590993` for a trading
/// participant or `0242:987654` for a Service Provider.
pub const PEPPOL_PARTICIPANT_SCHEME: &str = "iso6523-actorid-upis";

pub mod mls;
