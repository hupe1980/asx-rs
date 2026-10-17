//! Inbound push policy (`As4PushPolicy` and its builder).

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct As4PushPolicy {
    pub require_signed_receipt: bool,
    /// Whether inbound push messages must carry a valid WS-Security signature.
    ///
    /// Defaults to `true`.  Setting to `false` disables signature enforcement
    /// and should only be used in controlled test environments.
    pub require_signed_push: bool,
    /// When `true`, every declared payload part must be encrypted (every
    /// AS4 preset); otherwise EBMS:0103.
    pub require_encrypted_inbound: bool,
    /// Accept a payload-less BDEW path-switch message (B §2.2.8, §2.3.7):
    /// `Profile::bdew()` only.
    pub accept_path_switch: bool,
    /// Replay-window enforcement for inbound `<eb:Timestamp>`: refused more
    /// than `future` ahead or `past` behind (see [`TimestampWindow`]).
    pub timestamp_window: Option<TimestampWindow>,
}

/// The inbound `eb:Timestamp` window, asymmetric: `future` is the clock skew (eDelivery AS4 1.15 §5.1.3, 300 s);
/// `past` is the duplicate-detection retention, because the window only has
/// to catch replays the dedup store no longer remembers — and a retry that
/// reuses `Message::timestamp` must not be refused after five minutes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TimestampWindow {
    pub future: std::time::Duration,
    pub past: std::time::Duration,
}

impl std::fmt::Debug for As4PushPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("As4PushPolicy")
            .field("require_signed_receipt", &self.require_signed_receipt)
            .field("require_signed_push", &self.require_signed_push)
            .field("require_encrypted_inbound", &self.require_encrypted_inbound)
            .field("accept_path_switch", &self.accept_path_switch)
            .field("timestamp_window", &self.timestamp_window)
            .finish()
    }
}
