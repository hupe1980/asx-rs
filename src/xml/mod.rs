//! The crate's one XML layer.
//!
//! - [`parse`] is the only way the library turns text into a DOM: every
//!   inbound document — and every crate-internal re-parse — goes through it
//!   with the byte, depth, node and attribute limits of its document class
//!   ([`XmlLimits`]). `DOCTYPE` is refused everywhere.
//! - `writer::XmlOut` is the only way the library writes markup: caller values
//!   are escaped with the C14N rules, characters XML 1.0 cannot carry are
//!   refused (never stripped), end tags come from the writer's own stack, and a
//!   position for a later fragment (the `wsse:Security` header) is a reserved
//!   slot rather than a textual placeholder.
//! - [`ns`] holds the namespace URIs, once.

pub(crate) mod limits;
pub(crate) mod ns;
pub(crate) mod parse;
pub(crate) mod writer;

pub(crate) use limits::{MAX_C14N_DEPTH, XmlLimits};
pub(crate) use parse::{parse, parse_bytes};
pub(crate) use writer::{Slot, XmlDoc, XmlFragment, XmlOut};
