use super::send::{As4SendRequest, send_sync};
use super::types::{As4SendCredentials, As4SendOutput, As4SendPolicy};
use crate::as4::send_mime::package_as_mime;
use crate::core::{AsxError, ErrorCode, ErrorContext, Result, SessionContext};
use crate::observability::EventBus;
use quick_xml::events::Event;
use quick_xml::{Reader, Writer};
use roxmltree::Document;
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::sync::Arc;

const MF_NS: &str = "http://docs.oasis-open.org/ebxml-msg/ns/v3.0/mf/2010/04/";
const SOAP12_HTTP_CONTENT_TYPE: &str = "application/soap+xml";

/// Maximum number of entries kept in the rejected-group denylist.
/// Older entries are evicted when the list is full to bound memory use.
const MAX_REJECTED_GROUPS: usize = 4096;

/// Return type of `parse_multipart_related_params`:
/// `(media_type, boundary, mime_type, start, start_info)`
type MultipartParams = (String, String, String, Option<String>, Option<String>);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct As4SplitFragmentOutput {
    pub group_id: String,
    pub fragment_message_id: String,
    pub fragment_num: usize,
    pub fragment_count: usize,
    pub http_content_type: String,
    pub body: Arc<[u8]>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct As4JoinedLargeMessage {
    pub group_id: String,
    pub action: Option<String>,
    pub http_content_type: String,
    pub body: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum As4JoinProgress {
    Pending {
        group_id: String,
        received_fragments: usize,
        expected_fragments: Option<usize>,
    },
    Complete(As4JoinedLargeMessage),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MessageHeaderMeta {
    boundary: String,
    mime_type: String,
    start: String,
    start_info: Option<String>,
    content_description: Option<String>,
}

#[derive(Debug, Clone)]
pub(crate) struct ParsedFragmentEnvelope {
    sender_scope: String,
    group_id: String,
    message_size: Option<usize>,
    fragment_count: Option<usize>,
    fragment_num: usize,
    action: Option<String>,
    message_header: Option<MessageHeaderMeta>,
    data_part: Vec<u8>,
}

#[derive(Debug, Clone)]
struct JoinState {
    expected_fragments: Option<usize>,
    message_size: Option<usize>,
    action: Option<String>,
    message_header: Option<MessageHeaderMeta>,
    parts: BTreeMap<usize, Vec<u8>>,
    /// Wall-clock instant when the first fragment of this group was ingested.
    /// Used by [`As4FragmentJoiner::prune_stale_groups`] for time-based eviction.
    created_at: std::time::Instant,
}

/// Resource-limit configuration for [`As4FragmentJoiner`].
///
/// Unbounded joiners are a DoS vector: a malicious sender can open thousands of
/// fragment groups or stream multi-GB fragments that are never completed.
/// These limits bound the group count, the per-group byte budget, and optionally
/// the maximum age of an in-progress group.
#[derive(Debug, Clone)]
pub struct As4FragmentJoinerLimits {
    /// Maximum number of concurrently in-flight fragment groups.
    ///
    /// When a new group would exceed this limit, `ingest_fragment` returns
    /// [`ErrorCode::CapacityExhausted`] and the fragment is rejected.
    ///
    /// Default: 256.
    pub max_concurrent_groups: usize,

    /// Maximum accumulated payload bytes for a single fragment group.
    ///
    /// When a newly ingested fragment would push the group over this limit the
    /// group is evicted and `ingest_fragment` returns
    /// [`ErrorCode::CapacityExhausted`].
    ///
    /// Default: 128 MiB (`128 * 1024 * 1024`).
    pub max_bytes_per_group: usize,

    /// Maximum age of an in-progress fragment group before it is eligible for
    /// time-based eviction via [`As4FragmentJoiner::prune_stale_groups`].
    ///
    /// When `Some(duration)`, any group whose first fragment was ingested more
    /// than `duration` ago is evicted (and permanently rejected) the next time
    /// `prune_stale_groups` is called.  When `None` (the default), time-based
    /// eviction is disabled and incomplete groups are only removed when the
    /// count or byte limits are hit.
    ///
    /// Recommended value for production BDEW MaKo deployments: `Some(Duration::from_secs(3600))`
    /// (1 hour), which is sufficient for any reasonable large-message transfer
    /// while protecting against memory exhaustion from abandoned groups.
    ///
    /// Default: `None` (disabled — preserves existing behaviour).
    pub max_group_age: Option<std::time::Duration>,
}

impl Default for As4FragmentJoinerLimits {
    fn default() -> Self {
        Self {
            max_concurrent_groups: 256,
            max_bytes_per_group: 128 * 1024 * 1024,
            // 1-hour TTL: matches the recommended BDEW MaKo production value.
            // Abandoned fragment groups are evicted the next time
            // `prune_stale_groups` is called, bounding memory consumption.
            // Override with `None` to disable time-based eviction (not recommended).
            max_group_age: Some(std::time::Duration::from_secs(3600)),
        }
    }
}

#[derive(Debug, Default)]
pub struct As4FragmentJoiner {
    groups: HashMap<String, JoinState>,
    /// FIFO denylist: `rejected_groups_set` gives O(1) membership tests;
    /// `rejected_groups_order` tracks insertion order for deterministic eviction.
    rejected_groups_set: HashSet<String>,
    rejected_groups_order: VecDeque<String>,
    limits: As4FragmentJoinerLimits,
}

impl As4FragmentJoiner {
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a joiner with custom resource limits.
    pub fn with_limits(limits: As4FragmentJoinerLimits) -> Self {
        Self {
            groups: HashMap::new(),
            rejected_groups_set: HashSet::new(),
            rejected_groups_order: VecDeque::new(),
            limits,
        }
    }

    /// Mark a group as permanently rejected and cap the denylist size.
    ///
    /// When the denylist reaches `MAX_REJECTED_GROUPS`, the oldest entry is
    /// evicted (FIFO) before the new one is inserted.  Deterministic eviction
    /// prevents memory growth and avoids the undefined ordering of HashSet
    /// iteration that the previous implementation relied on.  Evicting a live
    /// entry is safe: it will simply be re-rejected on the next incoming
    /// fragment via the concurrent-group or per-group-byte limit check.
    fn reject_group(&mut self, scope_key: String) {
        if self.rejected_groups_set.len() >= MAX_REJECTED_GROUPS
            && let Some(oldest) = self.rejected_groups_order.pop_front()
        {
            self.rejected_groups_set.remove(&oldest);
        }
        self.rejected_groups_order.push_back(scope_key.clone());
        self.rejected_groups_set.insert(scope_key);
    }

    /// Remove a group from the active map and permanently reject it.
    /// Callers in error-return paths should use this to combine two operations
    /// and avoid a redundant `scope_key.clone()`.
    fn evict_and_reject_group(&mut self, scope_key: String) {
        self.groups.remove(scope_key.as_str());
        self.reject_group(scope_key);
    }

    pub fn ingest_fragment(
        &mut self,
        http_content_type: &str,
        body: &[u8],
    ) -> Result<As4JoinProgress> {
        let parsed = parse_fragment_envelope(http_content_type, body)?;
        self.ingest_parsed_fragment(parsed)
    }

    pub(crate) fn ingest_parsed_fragment(
        &mut self,
        parsed: ParsedFragmentEnvelope,
    ) -> Result<As4JoinProgress> {
        let sender_scope = parsed.sender_scope.clone();
        self.ingest_parsed_fragment_with_sender_scope(sender_scope.as_str(), parsed)
    }

    /// Ingest an already-parsed fragment using an externally supplied, authenticated
    /// sender scope instead of the SOAP-claimed `<eb:From>` party ID.
    ///
    /// Use this when `FragmentScopePolicy::RequireAuthenticatedScope` is active:
    /// the caller provides the transport-layer identity (e.g., mTLS client cert CN)
    /// that was verified before the request was admitted, avoiding a double parse
    /// while still pinning group correlation to an authenticated identity.
    pub(crate) fn ingest_parsed_fragment_with_authenticated_scope(
        &mut self,
        authenticated_scope: &str,
        parsed: ParsedFragmentEnvelope,
    ) -> Result<As4JoinProgress> {
        self.ingest_parsed_fragment_with_sender_scope(authenticated_scope, parsed)
    }

    /// Ingest a fragment and correlate it within a sender-scoped GroupId space.
    ///
    /// This follows ebMS3 Part 2 security guidance: fragment correlation should
    /// not rely on GroupId alone when multiple senders can target the same
    /// receiver, to prevent cross-sender fragment mixing.
    pub fn ingest_fragment_for_sender(
        &mut self,
        sender_scope: &str,
        http_content_type: &str,
        body: &[u8],
    ) -> Result<As4JoinProgress> {
        let parsed = parse_fragment_envelope(http_content_type, body)?;
        self.ingest_parsed_fragment_with_sender_scope(sender_scope, parsed)
    }

    fn ingest_parsed_fragment_with_sender_scope(
        &mut self,
        sender_scope: &str,
        frag: ParsedFragmentEnvelope,
    ) -> Result<As4JoinProgress> {
        let ParsedFragmentEnvelope {
            group_id,
            message_size,
            fragment_count,
            fragment_num,
            action,
            message_header,
            data_part,
            ..
        } = frag;
        let scope_key = scoped_group_key(sender_scope, group_id.as_str());

        if self.rejected_groups_set.contains(scope_key.as_str()) {
            return Err(AsxError::new(
                ErrorCode::InteropViolation,
                "received a fragment for a group that was previously rejected",
                ErrorContext::new("as4_fragment_join"),
            ));
        }

        // Enforce concurrent-group limit before inserting a new entry.
        if !self.groups.contains_key(scope_key.as_str())
            && self.groups.len() >= self.limits.max_concurrent_groups
        {
            return Err(AsxError::new(
                ErrorCode::CapacityExhausted,
                format!(
                    "fragment joiner has reached the concurrent-group limit ({}); \
                     reject new group to protect memory",
                    self.limits.max_concurrent_groups,
                ),
                ErrorContext::new("as4_fragment_join"),
            ));
        }

        // Enforce per-group byte budget before inserting the data part.
        let current_group_bytes: usize = self
            .groups
            .get(scope_key.as_str())
            .map(|s| s.parts.values().map(|v| v.len()).sum())
            .unwrap_or(0);
        if current_group_bytes.saturating_add(data_part.len()) > self.limits.max_bytes_per_group {
            self.evict_and_reject_group(scope_key.clone());
            return Err(AsxError::new(
                ErrorCode::CapacityExhausted,
                format!(
                    "fragment group would exceed per-group byte limit ({} bytes); \
                     group rejected",
                    self.limits.max_bytes_per_group,
                ),
                ErrorContext::new("as4_fragment_join"),
            ));
        }

        let state = self
            .groups
            .entry(scope_key.clone())
            .or_insert_with(|| JoinState {
                expected_fragments: None,
                message_size: None,
                action: None,
                message_header: None,
                parts: BTreeMap::new(),
                created_at: std::time::Instant::now(),
            });

        if state.parts.contains_key(&fragment_num) {
            self.evict_and_reject_group(scope_key.clone());
            return Err(AsxError::new(
                ErrorCode::InteropViolation,
                "duplicate fragment number received for group",
                ErrorContext::new("as4_fragment_join"),
            ));
        }

        if let Some(count) = fragment_count {
            match state.expected_fragments {
                Some(existing) if existing != count => {
                    self.evict_and_reject_group(scope_key.clone());
                    return Err(AsxError::new(
                        ErrorCode::InteropViolation,
                        "fragment count mismatch within group",
                        ErrorContext::new("as4_fragment_join"),
                    ));
                }
                None => state.expected_fragments = Some(count),
                _ => {}
            }
        }

        if let Some(size) = message_size {
            match state.message_size {
                Some(existing) if existing != size => {
                    self.evict_and_reject_group(scope_key.clone());
                    return Err(AsxError::new(
                        ErrorCode::InteropViolation,
                        "message size mismatch within group",
                        ErrorContext::new("as4_fragment_join"),
                    ));
                }
                None => state.message_size = Some(size),
                _ => {}
            }
        }

        if let Some(action) = action {
            match state.action.as_ref() {
                Some(existing) if existing != &action => {
                    self.evict_and_reject_group(scope_key.clone());
                    return Err(AsxError::new(
                        ErrorCode::InteropViolation,
                        "action mismatch within group",
                        ErrorContext::new("as4_fragment_join"),
                    ));
                }
                None => state.action = Some(action),
                _ => {}
            }
        }

        if let Some(header) = message_header {
            match state.message_header.as_ref() {
                Some(existing) if existing != &header => {
                    self.evict_and_reject_group(scope_key.clone());
                    return Err(AsxError::new(
                        ErrorCode::InteropViolation,
                        "message header mismatch within group",
                        ErrorContext::new("as4_fragment_join"),
                    ));
                }
                None => state.message_header = Some(header),
                _ => {}
            }
        }

        if let Some(expected) = state.expected_fragments
            && fragment_num > expected
        {
            self.evict_and_reject_group(scope_key.clone());
            return Err(AsxError::new(
                ErrorCode::InteropViolation,
                "fragment number exceeds known fragment count",
                ErrorContext::new("as4_fragment_join"),
            ));
        }

        state.parts.insert(fragment_num, data_part);

        let expected = state.expected_fragments;
        let received = state.parts.len();
        if let Some(expected_count) = expected
            && received == expected_count
        {
            let message = finalize_joined_message(group_id, state)?;
            self.groups.remove(scope_key.as_str());
            return Ok(As4JoinProgress::Complete(message));
        }

        Ok(As4JoinProgress::Pending {
            group_id,
            received_fragments: received,
            expected_fragments: expected,
        })
    }

    /// Evict all fragment groups whose first fragment was ingested more than
    /// `limits.max_group_age` ago.
    ///
    /// Returns the number of groups evicted.  Each evicted group is added to
    /// the permanent reject-list so that late-arriving fragments for the same
    /// group are rejected immediately rather than starting a new (also stale)
    /// accumulation window.
    ///
    /// Call this periodically \u2014 for example from a `tokio::time::interval` task
    /// \u2014 to reclaim memory held by abandoned or crashed senders.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use asx_rs::as4::{As4FragmentJoiner, As4FragmentJoinerLimits};
    /// # use std::time::{Duration, Instant};
    /// let limits = As4FragmentJoinerLimits {
    ///     max_group_age: Some(Duration::from_secs(3600)),
    ///     ..Default::default()
    /// };
    /// let mut joiner = As4FragmentJoiner::with_limits(limits);
    /// // Call periodically:
    /// let evicted = joiner.prune_stale_groups(Instant::now());
    /// assert_eq!(evicted, 0); // nothing in-flight yet
    /// ```
    pub fn prune_stale_groups(&mut self, now: std::time::Instant) -> usize {
        let Some(max_age) = self.limits.max_group_age else {
            return 0;
        };
        let stale_keys: Vec<String> = self
            .groups
            .iter()
            .filter(|(_, s)| now.saturating_duration_since(s.created_at) > max_age)
            .map(|(k, _)| k.clone())
            .collect();
        let evicted = stale_keys.len();
        for key in stale_keys {
            self.evict_and_reject_group(key);
        }
        evicted
    }
}

fn scoped_group_key(sender_scope: &str, group_id: &str) -> String {
    if sender_scope.is_empty() {
        return group_id.to_string();
    }
    format!("{sender_scope}\u{0}{group_id}")
}

pub fn send_sync_fragmented(
    session: &SessionContext,
    event_bus: &EventBus,
    message_id: String,
    payload: Vec<u8>,
    policy: As4SendPolicy,
    credentials: Option<As4SendCredentials>,
    fragment_size_bytes: usize,
) -> Result<Vec<As4SplitFragmentOutput>> {
    if fragment_size_bytes == 0 {
        return Err(AsxError::new(
            ErrorCode::InvalidInput,
            "fragment_size_bytes must be greater than zero",
            ErrorContext::new("as4_send_fragment_split"),
        ));
    }

    let source = send_sync(
        session,
        event_bus,
        As4SendRequest {
            message_id: message_id.clone(),
            payload,
            policy: policy.clone(),
            credentials,
            payload_filename: None,
        },
    )?;

    split_send_output_into_fragments(session, &policy, &source, fragment_size_bytes)
}

fn split_send_output_into_fragments(
    session: &SessionContext,
    policy: &As4SendPolicy,
    source: &As4SendOutput,
    fragment_size_bytes: usize,
) -> Result<Vec<As4SplitFragmentOutput>> {
    let (boundary, mime_type, start, start_info, content_description) =
        parse_multipart_related_params(source.http_content_type.as_str())?;

    let group_id = source.message_id.clone();
    let body = source.soap_envelope.body.as_ref();
    let fragment_count = body.len().div_ceil(fragment_size_bytes);
    let fragment_count = fragment_count.max(1);

    let header = MessageHeaderMeta {
        boundary,
        mime_type,
        start,
        start_info,
        content_description,
    };

    let mut fragments = Vec::with_capacity(fragment_count);
    for idx in 0..fragment_count {
        let start_index = idx * fragment_size_bytes;
        let end_index = ((idx + 1) * fragment_size_bytes).min(body.len());
        let part = body[start_index..end_index].to_vec();

        let fragment_num = idx + 1;
        let fragment_message_id = format!("{}-fragment-{fragment_num}", source.message_id);
        let data_content_id = format!("fragment-{group_id}-{fragment_num}@asx");

        let soap = build_fragment_envelope(
            session,
            policy,
            source,
            FragmentEnvelopeSpec {
                fragment_message_id: fragment_message_id.as_str(),
                group_id: group_id.as_str(),
                message_size: body.len(),
                fragment_num,
                fragment_count,
                data_content_id: data_content_id.as_str(),
                message_header: &header,
            },
        )?;

        let (mime_body, mime_content_type) = package_as_mime(
            soap,
            part,
            data_content_id.as_str(),
            "application/octet-stream",
            SOAP12_HTTP_CONTENT_TYPE,
            None,
        )?;

        fragments.push(As4SplitFragmentOutput {
            group_id: group_id.clone(),
            fragment_message_id,
            fragment_num,
            fragment_count,
            http_content_type: mime_content_type,
            body: Arc::from(mime_body),
        });
    }

    Ok(fragments)
}

/// Fragment-specific parameters for [`build_fragment_envelope`].
///
/// Groups the 7 per-fragment fields into a single struct so
/// `build_fragment_envelope` stays within the `too_many_arguments` budget
/// while keeping `session`, `policy`, and `source` as first-class parameters.
struct FragmentEnvelopeSpec<'a> {
    fragment_message_id: &'a str,
    group_id: &'a str,
    message_size: usize,
    fragment_num: usize,
    fragment_count: usize,
    data_content_id: &'a str,
    message_header: &'a MessageHeaderMeta,
}

fn build_fragment_envelope(
    session: &SessionContext,
    policy: &As4SendPolicy,
    source: &As4SendOutput,
    spec: FragmentEnvelopeSpec<'_>,
) -> Result<Vec<u8>> {
    use crate::crypto::soap_builder::SoapEnvelopeBuilder;

    let FragmentEnvelopeSpec {
        fragment_message_id,
        group_id,
        message_size,
        fragment_num,
        fragment_count,
        data_content_id,
        message_header,
    } = spec;

    let original_sender = policy
        .original_sender
        .clone()
        .unwrap_or_else(|| session.session_id().to_string());
    let final_recipient = policy
        .final_recipient
        .clone()
        .unwrap_or_else(|| session.partner_id().to_string());
    let tracking_identifier = policy
        .tracking_identifier
        .clone()
        .unwrap_or_else(|| source.message_id.clone());

    let xml = SoapEnvelopeBuilder::new(
        fragment_message_id,
        session.session_id(),
        session.partner_id(),
    )
    .with_action(&policy.action)
    .with_service(&policy.service, &policy.service_type)
    .with_four_corner_properties(
        original_sender.as_str(),
        final_recipient.as_str(),
        tracking_identifier.as_str(),
    )
    .build()
    .map_err(|err| {
        AsxError::new(
            ErrorCode::ParseFailed,
            format!("failed to build SOAP envelope for fragment: {err:?}"),
            ErrorContext::new("as4_send_fragment_split"),
        )
    })?;

    let xml = String::from_utf8(xml).map_err(|_| {
        AsxError::new(
            ErrorCode::ParseFailed,
            "fragment SOAP envelope is not valid UTF-8",
            ErrorContext::new("as4_send_fragment_split"),
        )
    })?;

    let mf_xml = format!(
        "<mf:MessageFragment href=\"cid:{data_content_id}\" xmlns:mf=\"{MF_NS}\">\
<mf:GroupId>{group_id}</mf:GroupId>\
<mf:MessageSize>{message_size}</mf:MessageSize>\
<mf:FragmentCount>{fragment_count}</mf:FragmentCount>\
<mf:FragmentNum>{fragment_num}</mf:FragmentNum>\
<mf:MessageHeader>\
<mf:Content-Type>Multipart/Related</mf:Content-Type>\
<mf:Boundary>{}</mf:Boundary>\
<mf:Type>{}</mf:Type>\
<mf:Start>{}</mf:Start>{}\
{}\
</mf:MessageHeader>\
<mf:Action>{}</mf:Action>\
</mf:MessageFragment>",
        escape_xml(message_header.boundary.as_str()),
        escape_xml(message_header.mime_type.as_str()),
        escape_xml(message_header.start.as_str()),
        message_header
            .start_info
            .as_ref()
            .map(|v| format!("<mf:StartInfo>{}</mf:StartInfo>", escape_xml(v.as_str())))
            .unwrap_or_default(),
        message_header
            .content_description
            .as_ref()
            .map(|v| {
                format!(
                    "<mf:Content-Description>{}</mf:Content-Description>",
                    escape_xml(v.as_str())
                )
            })
            .unwrap_or_default(),
        escape_xml(policy.action.as_str())
    );

    inject_message_fragment_header(xml.as_str(), mf_xml.as_str())
}

fn inject_message_fragment_header(soap_xml: &str, header_xml: &str) -> Result<Vec<u8>> {
    let mut reader = Reader::from_str(soap_xml);
    reader.config_mut().trim_text(false);
    let mut writer = Writer::new(Vec::new());
    let mut buf = Vec::new();

    let mut inserted = false;
    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::End(end)) if local_name(end.name().as_ref()) == b"Header" => {
                if !inserted {
                    writer.get_mut().extend_from_slice(header_xml.as_bytes());
                    inserted = true;
                }
                writer
                    .write_event(Event::End(end.into_owned()))
                    .map_err(|e| {
                        AsxError::new(
                            ErrorCode::ParseFailed,
                            format!("failed to inject MessageFragment header: {e}"),
                            ErrorContext::new("as4_send_fragment_split"),
                        )
                    })?;
            }
            Ok(Event::Eof) => break,
            Ok(event) => {
                writer.write_event(event.into_owned()).map_err(|e| {
                    AsxError::new(
                        ErrorCode::ParseFailed,
                        format!("failed to reserialize SOAP envelope: {e}"),
                        ErrorContext::new("as4_send_fragment_split"),
                    )
                })?;
            }
            Err(e) => {
                return Err(AsxError::new(
                    ErrorCode::ParseFailed,
                    format!("failed to parse SOAP envelope while injecting MessageFragment: {e}"),
                    ErrorContext::new("as4_send_fragment_split"),
                ));
            }
        }
        buf.clear();
    }

    if !inserted {
        return Err(AsxError::new(
            ErrorCode::ParseFailed,
            "SOAP envelope does not contain a Header element",
            ErrorContext::new("as4_send_fragment_split"),
        ));
    }

    Ok(writer.into_inner())
}

fn finalize_joined_message(group_id: String, state: &JoinState) -> Result<As4JoinedLargeMessage> {
    let expected = state.expected_fragments.ok_or_else(|| {
        AsxError::new(
            ErrorCode::InteropViolation,
            "cannot finalize join without a known fragment count",
            ErrorContext::new("as4_fragment_join"),
        )
    })?;

    let mut joined = Vec::new();
    for idx in 1..=expected {
        let Some(part) = state.parts.get(&idx) else {
            return Err(AsxError::new(
                ErrorCode::InteropViolation,
                "fragment set is incomplete",
                ErrorContext::new("as4_fragment_join"),
            ));
        };
        joined.extend_from_slice(part);
    }

    if let Some(expected_size) = state.message_size
        && joined.len() != expected_size
    {
        return Err(AsxError::new(
            ErrorCode::InteropViolation,
            "joined message size does not match MessageSize metadata",
            ErrorContext::new("as4_fragment_join"),
        ));
    }

    let header = state.message_header.as_ref().ok_or_else(|| {
        AsxError::new(
            ErrorCode::InteropViolation,
            "missing MessageHeader metadata for joined message",
            ErrorContext::new("as4_fragment_join"),
        )
    })?;

    let mut http_content_type = format!(
        "multipart/related; boundary=\"{}\"; type=\"{}\"; start=\"<{}>\"",
        header.boundary, header.mime_type, header.start
    );
    if let Some(start_info) = &header.start_info {
        http_content_type.push_str(format!("; start-info=\"{}\"", start_info).as_str());
    }

    Ok(As4JoinedLargeMessage {
        group_id,
        action: state.action.clone(),
        http_content_type,
        body: joined,
    })
}

pub(crate) fn parse_fragment_envelope(
    http_content_type: &str,
    body: &[u8],
) -> Result<ParsedFragmentEnvelope> {
    let boundary = extract_boundary(http_content_type)?;
    let mut parts = parse_multipart_parts(body, boundary.as_str())?;
    if parts.len() != 2 {
        return Err(AsxError::new(
            ErrorCode::ParseFailed,
            "fragment message must contain exactly two MIME parts",
            ErrorContext::new("as4_fragment_join"),
        ));
    }

    let data_part = parts.pop().expect("parts length checked");
    let soap_part = parts.pop().expect("parts length checked");

    let soap = std::str::from_utf8(soap_part.body.as_slice()).map_err(|_| {
        AsxError::new(
            ErrorCode::ParseFailed,
            "fragment SOAP part is not valid UTF-8",
            ErrorContext::new("as4_fragment_join"),
        )
    })?;
    let doc = Document::parse(soap).map_err(|e| {
        AsxError::new(
            ErrorCode::ParseFailed,
            format!("failed to parse fragment SOAP envelope: {e}"),
            ErrorContext::new("as4_fragment_join"),
        )
    })?;

    let message_fragment = doc
        .descendants()
        .find(|n| {
            n.is_element()
                && n.tag_name().namespace() == Some(MF_NS)
                && n.tag_name().name() == "MessageFragment"
        })
        .ok_or_else(|| {
            AsxError::new(
                ErrorCode::ParseFailed,
                "fragment SOAP envelope is missing mf:MessageFragment",
                ErrorContext::new("as4_fragment_join"),
            )
        })?;

    let href = message_fragment.attribute("href").ok_or_else(|| {
        AsxError::new(
            ErrorCode::ParseFailed,
            "mf:MessageFragment is missing href attribute",
            ErrorContext::new("as4_fragment_join"),
        )
    })?;

    let href_cid = normalize_cid(href);

    let body_node = doc
        .descendants()
        .find(|n| n.is_element() && n.tag_name().name() == "Body")
        .ok_or_else(|| {
            AsxError::new(
                ErrorCode::ParseFailed,
                "fragment SOAP envelope is missing Body",
                ErrorContext::new("as4_fragment_join"),
            )
        })?;

    if body_node.children().any(|n| n.is_element()) {
        return Err(AsxError::new(
            ErrorCode::ParseFailed,
            "fragment SOAP Body must be empty",
            ErrorContext::new("as4_fragment_join"),
        ));
    }

    let sender_scope = doc
        .descendants()
        .find(|n| {
            n.is_element()
                && n.tag_name().namespace()
                    == Some("http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/")
                && n.tag_name().name() == "From"
        })
        .and_then(|from| {
            from.children().find(|n| {
                n.is_element()
                    && n.tag_name().namespace()
                        == Some("http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/")
                    && n.tag_name().name() == "PartyId"
            })
        })
        .and_then(|n| n.text())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            AsxError::new(
                ErrorCode::ParseFailed,
                "fragment SOAP envelope is missing eb:From/eb:PartyId",
                ErrorContext::new("as4_fragment_join"),
            )
        })?;

    let group_id = text_child_required(message_fragment, "GroupId")?;
    let message_size = text_child_optional(message_fragment, "MessageSize")
        .map(|v| parse_positive_usize(v.as_str(), "MessageSize"))
        .transpose()?;
    let fragment_count = text_child_optional(message_fragment, "FragmentCount")
        .map(|v| parse_positive_usize(v.as_str(), "FragmentCount"))
        .transpose()?;
    let fragment_num = parse_positive_usize(
        text_child_required(message_fragment, "FragmentNum")?.as_str(),
        "FragmentNum",
    )?;
    let action = text_child_optional(message_fragment, "Action");

    let message_header = message_fragment
        .children()
        .find(|n| {
            n.is_element()
                && n.tag_name().namespace() == Some(MF_NS)
                && n.tag_name().name() == "MessageHeader"
        })
        .map(parse_message_header_meta)
        .transpose()?;

    let data_part_cid = normalize_cid(data_part.content_id.as_str());
    if href_cid != data_part_cid {
        return Err(AsxError::new(
            ErrorCode::ParseFailed,
            "mf:MessageFragment href does not match MIME data part Content-ID",
            ErrorContext::new("as4_fragment_join"),
        ));
    }

    Ok(ParsedFragmentEnvelope {
        sender_scope,
        group_id,
        message_size,
        fragment_count,
        fragment_num,
        action,
        message_header,
        data_part: data_part.body,
    })
}

fn parse_message_header_meta(node: roxmltree::Node<'_, '_>) -> Result<MessageHeaderMeta> {
    let boundary = text_child_required(node, "Boundary")?;
    let mime_type = text_child_required(node, "Type")?;
    let start = text_child_required(node, "Start")?;
    let start_info = text_child_optional(node, "StartInfo");
    let content_description = text_child_optional(node, "Content-Description");
    Ok(MessageHeaderMeta {
        boundary,
        mime_type,
        start,
        start_info,
        content_description,
    })
}

fn text_child_required(node: roxmltree::Node<'_, '_>, local_name: &str) -> Result<String> {
    text_child_optional(node, local_name).ok_or_else(|| {
        AsxError::new(
            ErrorCode::ParseFailed,
            format!("mf:MessageFragment missing required element {local_name}"),
            ErrorContext::new("as4_fragment_join"),
        )
    })
}

fn text_child_optional(node: roxmltree::Node<'_, '_>, local_name: &str) -> Option<String> {
    node.children()
        .find(|n| {
            n.is_element()
                && n.tag_name().namespace() == Some(MF_NS)
                && n.tag_name().name() == local_name
        })
        .and_then(|n| n.text())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn parse_positive_usize(value: &str, label: &str) -> Result<usize> {
    let parsed = value.parse::<usize>().map_err(|_| {
        AsxError::new(
            ErrorCode::ParseFailed,
            format!("{label} is not a valid integer"),
            ErrorContext::new("as4_fragment_join"),
        )
    })?;
    if parsed == 0 {
        return Err(AsxError::new(
            ErrorCode::ParseFailed,
            format!("{label} must be greater than zero"),
            ErrorContext::new("as4_fragment_join"),
        ));
    }
    Ok(parsed)
}

#[derive(Debug, Clone)]
struct ParsedMimePart {
    content_id: String,
    body: Vec<u8>,
}

fn parse_multipart_parts(raw: &[u8], boundary: &str) -> Result<Vec<ParsedMimePart>> {
    let marker = format!("--{boundary}").into_bytes();
    if !raw.starts_with(marker.as_slice()) {
        return Err(AsxError::new(
            ErrorCode::ParseFailed,
            "multipart body does not start with boundary marker",
            ErrorContext::new("as4_fragment_join"),
        ));
    }

    let mut idx = marker.len();
    if raw.get(idx..idx + 2) == Some(b"\r\n") {
        idx += 2;
    } else if raw.get(idx) == Some(&b'\n') {
        idx += 1;
    }

    let mut parts = Vec::new();
    loop {
        if raw.get(idx..idx + marker.len() + 2) == Some(format!("--{boundary}--").as_bytes()) {
            break;
        }

        let header_end = find_subslice(raw, idx, b"\r\n\r\n")
            .or_else(|| find_subslice(raw, idx, b"\n\n"))
            .ok_or_else(|| {
                AsxError::new(
                    ErrorCode::ParseFailed,
                    "multipart part missing header/body separator",
                    ErrorContext::new("as4_fragment_join"),
                )
            })?;
        let separator_len = if raw.get(header_end..header_end + 4) == Some(b"\r\n\r\n") {
            4
        } else {
            2
        };
        let headers = &raw[idx..header_end];
        let body_start = header_end + separator_len;

        let next_marker = find_subslice(raw, body_start, format!("\r\n--{boundary}").as_bytes())
            .or_else(|| find_subslice(raw, body_start, format!("\n--{boundary}").as_bytes()))
            .ok_or_else(|| {
                AsxError::new(
                    ErrorCode::ParseFailed,
                    "multipart part missing terminating boundary",
                    ErrorContext::new("as4_fragment_join"),
                )
            })?;

        let body = raw[body_start..next_marker].to_vec();
        let content_id = parse_header_value(headers, "Content-ID").ok_or_else(|| {
            AsxError::new(
                ErrorCode::ParseFailed,
                "multipart part missing Content-ID header",
                ErrorContext::new("as4_fragment_join"),
            )
        })?;

        parts.push(ParsedMimePart { content_id, body });

        idx = next_marker;
        if raw.get(idx..idx + 2) == Some(b"\r\n") {
            idx += 2;
        } else if raw.get(idx) == Some(&b'\n') {
            idx += 1;
        }
        if raw.get(idx..idx + marker.len() + 2) == Some(format!("--{boundary}--").as_bytes()) {
            break;
        }
        if raw.get(idx..idx + marker.len()) == Some(marker.as_slice()) {
            idx += marker.len();
            if raw.get(idx..idx + 2) == Some(b"\r\n") {
                idx += 2;
            } else if raw.get(idx) == Some(&b'\n') {
                idx += 1;
            }
            continue;
        }

        return Err(AsxError::new(
            ErrorCode::ParseFailed,
            "multipart boundary delimiter is malformed",
            ErrorContext::new("as4_fragment_join"),
        ));
    }

    Ok(parts)
}

fn parse_header_value(headers: &[u8], name: &str) -> Option<String> {
    for raw_line in headers.split(|b| *b == b'\n') {
        let line = raw_line.strip_suffix(b"\r").unwrap_or(raw_line);
        if line.is_empty() {
            continue;
        }
        let Some(colon_idx) = line.iter().position(|b| *b == b':') else {
            continue;
        };
        let key = String::from_utf8_lossy(line[..colon_idx].trim_ascii())
            .trim()
            .to_string();
        if !key.eq_ignore_ascii_case(name) {
            continue;
        }
        let value = String::from_utf8_lossy(line[colon_idx + 1..].trim_ascii())
            .trim()
            .to_string();
        if value.is_empty() {
            return None;
        }
        return Some(value);
    }
    None
}

fn extract_boundary(http_content_type: &str) -> Result<String> {
    parse_multipart_related_params(http_content_type).map(|(boundary, _, _, _, _)| boundary)
}

fn parse_multipart_related_params(http_content_type: &str) -> Result<MultipartParams> {
    let mut media_type = "";
    let mut boundary = None;
    let mut mime_type = None;
    let mut start = None;
    let mut start_info = None;
    let mut content_description = None;

    for (idx, part) in http_content_type.split(';').enumerate() {
        if idx == 0 {
            media_type = part.trim();
            continue;
        }
        let mut kv = part.trim().splitn(2, '=');
        let key = kv.next().unwrap_or("").trim().to_ascii_lowercase();
        let value = kv.next().map(|v| {
            v.trim()
                .trim_matches('"')
                .trim_matches('<')
                .trim_matches('>')
                .to_string()
        });
        match key.as_str() {
            "boundary" => boundary = value,
            "type" => mime_type = value,
            "start" => start = value,
            "start-info" => start_info = value,
            "content-description" => content_description = value,
            _ => {}
        }
    }

    if !media_type.eq_ignore_ascii_case("multipart/related") {
        return Err(AsxError::new(
            ErrorCode::InvalidInput,
            "expected multipart/related content type",
            ErrorContext::new("as4_large_message"),
        ));
    }

    let boundary = boundary.ok_or_else(|| {
        AsxError::new(
            ErrorCode::InvalidInput,
            "multipart/related content type is missing boundary",
            ErrorContext::new("as4_large_message"),
        )
    })?;

    let mime_type = mime_type.unwrap_or_else(|| "application/xop+xml".to_string());
    let start = start.unwrap_or_else(|| "soap-body@example.com".to_string());

    Ok((boundary, mime_type, start, start_info, content_description))
}

fn normalize_cid(value: &str) -> String {
    let mut out = value.trim().trim_matches('<').trim_matches('>').to_string();
    if out.len() >= 4 && out[..4].eq_ignore_ascii_case("cid:") {
        out = out[4..].to_string();
    }
    out
}

fn local_name(name: &[u8]) -> &[u8] {
    match name.iter().rposition(|b| *b == b':') {
        Some(idx) => &name[idx + 1..],
        None => name,
    }
}

fn find_subslice(haystack: &[u8], start: usize, needle: &[u8]) -> Option<usize> {
    if start >= haystack.len() {
        return None;
    }
    memchr::memmem::find(&haystack[start..], needle).map(|pos| start + pos)
}

fn escape_xml(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

#[cfg(test)]
mod tests {
    #![cfg_attr(not(feature = "interop-relaxed"), allow(unused_imports, dead_code))]
    #[cfg(feature = "interop-relaxed")]
    use super::*;
    #[cfg(feature = "interop-relaxed")]
    use crate::as4::As4SendPolicyBuilder;
    #[cfg(feature = "interop-relaxed")]
    use crate::core::SessionContext;

    #[cfg(feature = "interop-relaxed")]
    #[test]
    fn fragmented_roundtrip_reassembles_original_message() {
        let session = SessionContext::new("s-large", "p-large", "strict").expect("session");
        let event_bus = EventBus::new(16).expect("bus");
        let payload = vec![b'x'; 16384];
        let (policy, credentials) = As4SendPolicyBuilder::new()
            .interop(crate::core::InteropMode::Relaxed)
            .sign(false)
            .encrypt(false)
            .fail_closed_audit_events(false)
            .action("urn:test:large")
            .service("urn:test:svc", "")
            .build()
            .expect("policy");

        let source = send_sync(
            &session,
            &event_bus,
            As4SendRequest {
                message_id: "mid-large-1".to_string(),
                payload,
                policy: policy.clone(),
                credentials: Some(credentials.clone()),
                payload_filename: None,
            },
        )
        .expect("source send");

        let fragments =
            split_send_output_into_fragments(&session, &policy, &source, 1024).expect("split");
        assert!(fragments.len() > 1);

        let mut joiner = As4FragmentJoiner::new();
        let mut completed = None;
        for fragment in &fragments {
            let progress = joiner
                .ingest_fragment(fragment.http_content_type.as_str(), fragment.body.as_ref())
                .expect("ingest");
            if let As4JoinProgress::Complete(msg) = progress {
                completed = Some(msg);
            }
        }

        let completed = completed.expect("complete");
        assert_eq!(completed.group_id, source.message_id);
        assert_eq!(completed.http_content_type, source.http_content_type);
        assert_eq!(
            completed.body.as_slice(),
            source.soap_envelope.body.as_ref()
        );
        assert_eq!(completed.action.as_deref(), Some("urn:test:large"));
    }

    #[cfg(feature = "interop-relaxed")]
    #[test]
    fn joiner_rejects_duplicate_fragment_num() {
        let session = SessionContext::new("s-large-dup", "p-large", "strict").expect("session");
        let event_bus = EventBus::new(16).expect("bus");
        let payload = vec![b'y'; 4096];
        let (policy, credentials) = As4SendPolicyBuilder::new()
            .interop(crate::core::InteropMode::Relaxed)
            .sign(false)
            .encrypt(false)
            .fail_closed_audit_events(false)
            .action("urn:test:dup")
            .service("urn:test:svc", "")
            .build()
            .expect("policy");

        let source = send_sync(
            &session,
            &event_bus,
            As4SendRequest {
                message_id: "mid-large-2".to_string(),
                payload,
                policy: policy.clone(),
                credentials: Some(credentials.clone()),
                payload_filename: None,
            },
        )
        .expect("source send");

        let fragments =
            split_send_output_into_fragments(&session, &policy, &source, 1024).expect("split");
        assert!(fragments.len() > 1);

        let mut joiner = As4FragmentJoiner::new();
        let first = &fragments[0];
        joiner
            .ingest_fragment(first.http_content_type.as_str(), first.body.as_ref())
            .expect("first accepted");

        let err = joiner
            .ingest_fragment(first.http_content_type.as_str(), first.body.as_ref())
            .expect_err("duplicate must fail");
        assert_eq!(err.code, ErrorCode::InteropViolation);
    }

    #[cfg(feature = "interop-relaxed")]
    #[test]
    fn joiner_scopes_group_id_by_sender() {
        let session = SessionContext::new("s-large-scope", "p-large", "strict").expect("session");
        let event_bus = EventBus::new(16).expect("bus");
        let payload = vec![b'z'; 4096];
        let (policy, credentials) = As4SendPolicyBuilder::new()
            .interop(crate::core::InteropMode::Relaxed)
            .sign(false)
            .encrypt(false)
            .fail_closed_audit_events(false)
            .action("urn:test:scope")
            .service("urn:test:svc", "")
            .build()
            .expect("policy");

        let source = send_sync(
            &session,
            &event_bus,
            As4SendRequest {
                message_id: "mid-large-3".to_string(),
                payload,
                policy: policy.clone(),
                credentials: Some(credentials),
                payload_filename: None,
            },
        )
        .expect("source send");

        let fragments =
            split_send_output_into_fragments(&session, &policy, &source, 1024).expect("split");
        let first = &fragments[0];

        let mut joiner = As4FragmentJoiner::new();
        let p1 = joiner
            .ingest_fragment_for_sender(
                "sender-a",
                first.http_content_type.as_str(),
                first.body.as_ref(),
            )
            .expect("sender a ingest");
        let p2 = joiner
            .ingest_fragment_for_sender(
                "sender-b",
                first.http_content_type.as_str(),
                first.body.as_ref(),
            )
            .expect("sender b ingest");

        match (p1, p2) {
            (
                As4JoinProgress::Pending {
                    received_fragments: a,
                    ..
                },
                As4JoinProgress::Pending {
                    received_fragments: b,
                    ..
                },
            ) => {
                assert_eq!(a, 1);
                assert_eq!(b, 1);
            }
            _ => panic!("both sender-scoped ingests must stay independent"),
        }
    }

    #[cfg(feature = "interop-relaxed")]
    fn make_fragments_for_limit_test(
        session_id: &str,
        msg_id: &str,
    ) -> (As4SendOutput, Vec<As4SplitFragmentOutput>, As4SendPolicy) {
        let session = SessionContext::new(session_id, "p-limit", "strict").expect("session");
        let event_bus = EventBus::new(16).expect("bus");
        let payload = vec![b'L'; 4096];
        let (policy, credentials) = As4SendPolicyBuilder::new()
            .interop(crate::core::InteropMode::Relaxed)
            .sign(false)
            .encrypt(false)
            .fail_closed_audit_events(false)
            .action("urn:test:limit")
            .service("urn:test:svc", "")
            .build()
            .expect("policy");
        let source = send_sync(
            &session,
            &event_bus,
            As4SendRequest {
                message_id: msg_id.to_string(),
                payload,
                policy: policy.clone(),
                credentials: Some(credentials),
                payload_filename: None,
            },
        )
        .expect("source send");
        let fragments =
            split_send_output_into_fragments(&session, &policy, &source, 512).expect("split");
        assert!(
            fragments.len() > 1,
            "need multiple fragments for limit tests"
        );
        (source, fragments, policy)
    }

    #[cfg(feature = "interop-relaxed")]
    #[test]
    fn joiner_enforces_concurrent_group_limit() {
        let (_, frags_a, _) = make_fragments_for_limit_test("s-limit-a", "mid-limit-a");
        let (_, frags_b, _) = make_fragments_for_limit_test("s-limit-b", "mid-limit-b");
        // Two groups, create a third that should be rejected.
        let (_, frags_c, _) = make_fragments_for_limit_test("s-limit-c", "mid-limit-c");

        let limits = As4FragmentJoinerLimits {
            max_concurrent_groups: 2,
            max_bytes_per_group: 128 * 1024 * 1024,
            max_group_age: None,
        };
        let mut joiner = As4FragmentJoiner::with_limits(limits);

        // Ingest first fragment of each of the first two groups (stays pending).
        joiner
            .ingest_fragment(
                frags_a[0].http_content_type.as_str(),
                frags_a[0].body.as_ref(),
            )
            .expect("group-a first fragment");
        joiner
            .ingest_fragment(
                frags_b[0].http_content_type.as_str(),
                frags_b[0].body.as_ref(),
            )
            .expect("group-b first fragment");

        // Opening a third group exceeds max_concurrent_groups=2.
        let err = joiner
            .ingest_fragment(
                frags_c[0].http_content_type.as_str(),
                frags_c[0].body.as_ref(),
            )
            .expect_err("third group should be rejected");
        assert_eq!(err.code, ErrorCode::CapacityExhausted);
        assert!(
            err.message.contains("concurrent-group limit"),
            "expected concurrent-group message, got: {}",
            err.message
        );
    }

    #[cfg(feature = "interop-relaxed")]
    #[test]
    fn joiner_enforces_per_group_byte_limit() {
        let (_, frags, _) = make_fragments_for_limit_test("s-limit-bytes", "mid-limit-bytes");
        assert!(!frags.is_empty());

        // Set limit to 1 byte: any real data_part will exceed it immediately.
        let limits = As4FragmentJoinerLimits {
            max_concurrent_groups: 256,
            max_bytes_per_group: 1,
            max_group_age: None,
        };
        let mut joiner = As4FragmentJoiner::with_limits(limits);

        let err = joiner
            .ingest_fragment(frags[0].http_content_type.as_str(), frags[0].body.as_ref())
            .expect_err("data_part must exceed 1-byte limit");
        assert_eq!(err.code, ErrorCode::CapacityExhausted);
        assert!(
            err.message.contains("byte limit"),
            "expected byte-limit message, got: {}",
            err.message
        );
    }
}
