mod client;
mod inbound;
mod send_client;
pub(crate) use client::classify_path_switch;
pub use client::{As4, Message, PathSwitch, UserMessage};

pub(crate) mod receipt_verify;
mod receive;
mod send;
mod send_mime;
mod services;
pub(crate) mod signals;
mod stream;

pub(crate) mod types;
pub(crate) use types::*;

// The building blocks the clients are built on (crate-private).
pub(crate) use receipt_verify::{As4NonRepudiation, As4ReceiptPolicy, DEFAULT_MAX_RECEIPT_BYTES};
pub(crate) use send::As4AdditionalPayload;

pub(crate) mod mime_packaging;
mod parser;

#[cfg(test)]
mod tests;
