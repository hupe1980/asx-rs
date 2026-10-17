//! Capture `tracing` spans and events for assertions on the telemetry
//! contract (span names, targets, levels, field values).
//!
//! ```
//! use asx::testkit::trace::TraceCapture;
//!
//! let capture = TraceCapture::new();
//! {
//!     let _guard = capture.set_default();
//!     let span = tracing::info_span!(target: "asx", "asx.send", message_id = "m-1");
//!     span.in_scope(|| tracing::info!(target: "asx", "message sent"));
//! }
//! assert_eq!(capture.spans()[0].fields["message_id"], "m-1");
//! assert_eq!(capture.events()[0].span, Some("asx.send"));
//! ```
//!
//! The subscriber is installed for the current thread only, so parallel tests
//! do not see each other's spans. `asx-rs` carries the caller's dispatcher and
//! span onto its crypto pool, so work it moves off-thread is captured too.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::{Arc, Mutex, Once};

use tracing::field::{Field, Visit};
use tracing::span::{Attributes, Id, Record};
use tracing::subscriber::Interest;
use tracing::{Event, Level, Metadata, Subscriber};
use tracing_subscriber::Layer;
use tracing_subscriber::layer::{Context, SubscriberExt};
use tracing_subscriber::registry::LookupSpan;

/// Tests run in parallel, and a callsite first reached by a thread with no
/// subscriber is cached as disabled for every later capture. A global
/// subscriber that is interested in everything keeps callsites enabled; each
/// capture still receives its own thread's events. Skipped if the process
/// already has a global subscriber.
fn install_always_interested_global() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let _ = tracing::subscriber::set_global_default(
            tracing_subscriber::registry().with(AlwaysInterested),
        );
    });
}

struct AlwaysInterested;

impl<S: Subscriber> Layer<S> for AlwaysInterested {
    fn register_callsite(&self, _: &'static Metadata<'static>) -> Interest {
        Interest::always()
    }
}

/// A capture layer whose records are shared between clones.
#[derive(Debug, Clone, Default)]
pub struct TraceCapture {
    inner: Arc<Mutex<Captured>>,
}

#[derive(Debug, Default)]
struct Captured {
    spans: Vec<CapturedSpan>,
    events: Vec<CapturedEvent>,
}

/// One span, with every field recorded at creation or later.
#[derive(Debug, Clone)]
pub struct CapturedSpan {
    pub name: &'static str,
    pub target: String,
    pub level: Level,
    /// Declared fields that received a value; values as `Debug`/`Display` text.
    pub fields: BTreeMap<String, String>,
    /// Every field the span declared, recorded or not.
    pub declared: Vec<&'static str>,
    pub parent: Option<&'static str>,
}

/// One event; its message is the `message` field.
#[derive(Debug, Clone)]
pub struct CapturedEvent {
    pub target: String,
    pub level: Level,
    pub fields: BTreeMap<String, String>,
    /// The name of the span the event was emitted in.
    pub span: Option<&'static str>,
}

impl CapturedEvent {
    /// The event's message, or `""`.
    pub fn message(&self) -> &str {
        self.fields.get("message").map(String::as_str).unwrap_or("")
    }
}

/// Index of a span in `Captured::spans`, kept in the span's extensions.
struct SpanIndex(usize);

impl TraceCapture {
    pub fn new() -> Self {
        Self::default()
    }

    /// Install a thread-local subscriber with this capture layer; drop the
    /// guard to uninstall.
    pub fn set_default(&self) -> tracing::subscriber::DefaultGuard {
        install_always_interested_global();
        tracing::subscriber::set_default(tracing_subscriber::registry().with(self.clone()))
    }

    /// Every span created while installed, in creation order.
    pub fn spans(&self) -> Vec<CapturedSpan> {
        self.lock().spans.clone()
    }

    /// Every event emitted while installed, in order.
    pub fn events(&self) -> Vec<CapturedEvent> {
        self.lock().events.clone()
    }

    /// The spans named `name`.
    pub fn spans_named(&self, name: &str) -> Vec<CapturedSpan> {
        self.lock()
            .spans
            .iter()
            .filter(|s| s.name == name)
            .cloned()
            .collect()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Captured> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }
}

#[derive(Default)]
struct FieldVisitor(BTreeMap<String, String>);

impl Visit for FieldVisitor {
    fn record_str(&mut self, field: &Field, value: &str) {
        self.0.insert(field.name().to_owned(), value.to_owned());
    }

    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        self.0.insert(field.name().to_owned(), format!("{value:?}"));
    }
}

impl<S> Layer<S> for TraceCapture
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    fn on_new_span(&self, attrs: &Attributes<'_>, id: &Id, ctx: Context<'_, S>) {
        let mut visitor = FieldVisitor::default();
        attrs.record(&mut visitor);
        let parent = if attrs.is_contextual() {
            ctx.lookup_current().map(|s| s.name())
        } else {
            attrs.parent().and_then(|p| ctx.span(p)).map(|s| s.name())
        };
        let meta = attrs.metadata();
        let captured = CapturedSpan {
            name: meta.name(),
            target: meta.target().to_owned(),
            level: *meta.level(),
            fields: visitor.0,
            declared: meta.fields().iter().map(|f| f.name()).collect(),
            parent,
        };
        let index = {
            let mut inner = self.lock();
            inner.spans.push(captured);
            inner.spans.len() - 1
        };
        if let Some(span) = ctx.span(id) {
            span.extensions_mut().insert(SpanIndex(index));
        }
    }

    fn on_record(&self, id: &Id, values: &Record<'_>, ctx: Context<'_, S>) {
        let Some(span) = ctx.span(id) else { return };
        let Some(index) = span.extensions().get::<SpanIndex>().map(|i| i.0) else {
            return;
        };
        let mut visitor = FieldVisitor::default();
        values.record(&mut visitor);
        if let Some(captured) = self.lock().spans.get_mut(index) {
            captured.fields.extend(visitor.0);
        }
    }

    fn on_event(&self, event: &Event<'_>, ctx: Context<'_, S>) {
        let mut visitor = FieldVisitor::default();
        event.record(&mut visitor);
        let meta = event.metadata();
        let captured = CapturedEvent {
            target: meta.target().to_owned(),
            level: *meta.level(),
            fields: visitor.0,
            span: ctx.event_span(event).map(|s| s.name()),
        };
        self.lock().events.push(captured);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nested_spans_record_their_parent() {
        let capture = TraceCapture::new();
        {
            let _g = capture.set_default();
            let outer = tracing::info_span!(target: "asx", "asx.send");
            let _e = outer.enter();
            let _inner = tracing::debug_span!(target: "asx", "asx.sign", algorithm = "rsa");
        }
        let spans = capture.spans();
        assert_eq!(spans.len(), 2);
        assert_eq!(spans[1].parent, Some("asx.send"));
        assert_eq!(spans[1].level, Level::DEBUG);
        assert_eq!(spans[1].fields["algorithm"], "rsa");
    }

    #[test]
    fn late_recorded_fields_are_captured_and_declared_ones_listed() {
        let capture = TraceCapture::new();
        {
            let _g = capture.set_default();
            let span = tracing::info_span!(
                target: "asx",
                "asx.receive",
                outcome = tracing::field::Empty,
                duration_ms = tracing::field::Empty,
            );
            span.record("outcome", "accepted");
            span.in_scope(|| tracing::info!(target: "asx", "message received"));
        }
        let span = &capture.spans()[0];
        assert_eq!(span.fields["outcome"], "accepted");
        assert!(!span.fields.contains_key("duration_ms"));
        assert!(span.declared.contains(&"duration_ms"));
        let event = &capture.events()[0];
        assert_eq!(event.message(), "message received");
        assert_eq!(event.span, Some("asx.receive"));
    }

    #[test]
    fn two_captures_on_two_threads_do_not_mix() {
        let a = TraceCapture::new();
        let b = TraceCapture::new();
        let b2 = b.clone();
        let handle = std::thread::spawn(move || {
            let _g = b2.set_default();
            tracing::info!(target: "asx", "from b");
        });
        {
            let _g = a.set_default();
            tracing::info!(target: "asx", "from a");
        }
        handle.join().unwrap();
        assert_eq!(a.events().len(), 1);
        assert_eq!(a.events()[0].message(), "from a");
        assert_eq!(b.events().len(), 1);
        assert_eq!(b.events()[0].message(), "from b");
    }
}
