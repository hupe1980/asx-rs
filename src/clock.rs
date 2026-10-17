//! The only source of wall-clock time in the library.
//!
//! Every built client carries [`system()`]; nothing public reaches the clock,
//! so no knob moves validity or freshness decisions. Crate
//! tests inject a [`ManualClock`]. Durations (leases, timeouts, elapsed
//! times) use `tokio::time::Instant`, which tests pause and advance.

use std::sync::{Arc, LazyLock};
use std::time::SystemTime;

/// The only source of wall-clock time in the library.
pub(crate) trait Clock: Send + Sync + std::fmt::Debug + 'static {
    fn now(&self) -> SystemTime;
}

/// The operating system's clock.
#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> SystemTime {
        SystemTime::now()
    }
}

pub(crate) type SharedClock = Arc<dyn Clock>;

static SYSTEM: LazyLock<SharedClock> = LazyLock::new(|| Arc::new(SystemClock));

/// The system clock every built client carries. Every handle is one shared
/// object, so `Arc::ptr_eq` tells whether two holders read the same clock.
pub(crate) fn system() -> SharedClock {
    Arc::clone(&SYSTEM)
}

/// A clock a crate test sets and advances.
#[cfg(test)]
#[derive(Debug)]
pub(crate) struct ManualClock {
    now: std::sync::Mutex<SystemTime>,
}

#[cfg(test)]
impl ManualClock {
    pub(crate) fn at(t: SystemTime) -> Arc<Self> {
        Arc::new(Self {
            now: std::sync::Mutex::new(t),
        })
    }

    pub(crate) fn set(&self, t: SystemTime) {
        *self.now.lock().expect("manual clock poisoned") = t;
    }

    pub(crate) fn advance(&self, by: std::time::Duration) {
        *self.now.lock().expect("manual clock poisoned") += by;
    }
}

#[cfg(test)]
impl Clock for ManualClock {
    fn now(&self) -> SystemTime {
        *self.now.lock().expect("manual clock poisoned")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, UNIX_EPOCH};

    #[test]
    fn manual_clock_set_and_advance() {
        let t0 = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let clock = ManualClock::at(t0);
        assert_eq!(clock.now(), t0);
        clock.advance(Duration::from_secs(90));
        assert_eq!(clock.now(), t0 + Duration::from_secs(90));
        let t1 = UNIX_EPOCH + Duration::from_secs(42);
        clock.set(t1);
        assert_eq!(clock.now(), t1);
        // Shared as the crate's clock type, it reads the same value.
        let shared: SharedClock = clock.clone();
        assert_eq!(shared.now(), t1);
    }

    #[test]
    fn system_clock_is_close_to_now() {
        let before = SystemTime::now();
        let read = system().now();
        let after = SystemTime::now();
        assert!(
            before <= read && read <= after,
            "{before:?} {read:?} {after:?}"
        );
        assert!(SystemClock.now() >= read);
    }

    #[test]
    fn system_handles_are_one_clock_and_manual_clocks_differ() {
        assert!(Arc::ptr_eq(&system(), &system()));
        let manual: SharedClock = ManualClock::at(UNIX_EPOCH);
        assert!(!Arc::ptr_eq(&manual, &system()));
    }
}
