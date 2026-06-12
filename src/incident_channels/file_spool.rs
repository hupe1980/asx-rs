use std::fs::{File, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};

use crate::core::{AsxError, ErrorCode, ErrorContext, Result};
use crate::observability::{
    As2ProviderHealthAlertIncident, As2ProviderHealthIncidentChannel,
    As4ReceiptTaxonomyAlertIncident, As4ReceiptTaxonomyIncidentChannel,
};

pub struct FileSpoolIncidentConfig {
    pub path: PathBuf,
    pub fsync_each_write: bool,
    pub idempotency_ledger_policy: FileSpoolIdempotencyLedgerPolicy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileSpoolIdempotencyLedgerPolicy {
    pub max_entries: usize,
    pub retention_secs: u64,
}

impl Default for FileSpoolIdempotencyLedgerPolicy {
    fn default() -> Self {
        Self {
            max_entries: 50_000,
            retention_secs: 86_400 * 30,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileSpoolIncidentEntry {
    pub adapter: String,
    pub protocol: String,
    pub signal: String,
    pub dedup_key: String,
    pub severity: String,
    pub category: String,
    pub observed_rate_ppm: u64,
    pub sample_size: u64,
    pub runbook_hint: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FileSpoolReplayCheckpointStatus {
    Committed,
    Failed,
}

impl FileSpoolReplayCheckpointStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::Committed => "committed",
            Self::Failed => "failed",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileSpoolReplayCheckpoint {
    pub status: String,
    pub protocol: String,
    pub drained_entries: usize,
    pub forwarded_entries: usize,
    pub skipped_duplicate_entries: usize,
    pub requeued_entries: usize,
    pub last_forwarded_dedup_key: Option<String>,
    pub updated_unix_millis: u128,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileSpoolForwardSummary {
    pub checkpoint: FileSpoolReplayCheckpoint,
}

#[derive(Debug)]
struct FileSpoolIncidentWriter {
    file: Mutex<File>,
    path: PathBuf,
    fsync_each_write: bool,
}

impl FileSpoolIncidentWriter {
    fn new(config: FileSpoolIncidentConfig) -> Result<Self> {
        if config.path.as_os_str().is_empty() {
            return Err(AsxError::new(
                ErrorCode::InvalidInput,
                "incident file spool path must not be empty",
                ErrorContext::new("incident_file_spool_new"),
            ));
        }

        if let Some(parent) = config.path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent).map_err(|err| {
                AsxError::new(
                    ErrorCode::ReliabilityFailure,
                    format!("failed to create incident spool directory: {err}"),
                    ErrorContext::new("incident_file_spool_new"),
                )
            })?;
        }

        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&config.path)
            .map_err(|err| {
                AsxError::new(
                    ErrorCode::ReliabilityFailure,
                    format!("failed to open incident spool file: {err}"),
                    ErrorContext::new("incident_file_spool_new"),
                )
            })?;

        Ok(Self {
            file: Mutex::new(file),
            path: config.path,
            fsync_each_write: config.fsync_each_write,
        })
    }

    fn append_record<T: Serialize>(&self, record: &T) -> Result<()> {
        let mut file = self.file.lock();

        serde_json::to_writer(&mut *file, record).map_err(|err| {
            AsxError::new(
                ErrorCode::ReliabilityFailure,
                format!("failed to serialize incident spool record: {err}"),
                ErrorContext::new("incident_file_spool_append"),
            )
        })?;
        file.write_all(b"\n").map_err(|err| {
            AsxError::new(
                ErrorCode::ReliabilityFailure,
                format!("failed to append newline to incident spool file: {err}"),
                ErrorContext::new("incident_file_spool_append"),
            )
        })?;
        file.flush().map_err(|err| {
            AsxError::new(
                ErrorCode::ReliabilityFailure,
                format!("failed to flush incident spool file: {err}"),
                ErrorContext::new("incident_file_spool_append"),
            )
        })?;

        if self.fsync_each_write {
            file.sync_data().map_err(|err| {
                AsxError::new(
                    ErrorCode::ReliabilityFailure,
                    format!("failed to fsync incident spool file: {err}"),
                    ErrorContext::new("incident_file_spool_append"),
                )
            })?;
        }

        Ok(())
    }

    fn append_entries(&self, entries: &[FileSpoolIncidentEntry]) -> Result<()> {
        for entry in entries {
            self.append_record(entry)?;
        }
        Ok(())
    }

    fn replay_entries(&self) -> Result<Vec<FileSpoolIncidentEntry>> {
        let mut file = self.file.lock();

        file.flush().map_err(|err| {
            AsxError::new(
                ErrorCode::ReliabilityFailure,
                format!("failed to flush incident spool file before replay: {err}"),
                ErrorContext::new("incident_file_spool_replay"),
            )
        })?;

        let contents = std::fs::read_to_string(&self.path).map_err(|err| {
            AsxError::new(
                ErrorCode::ReliabilityFailure,
                format!("failed to read incident spool file: {err}"),
                ErrorContext::new("incident_file_spool_replay"),
            )
        })?;

        parse_spool_entries(&contents)
    }

    fn drain_entries(&self) -> Result<Vec<FileSpoolIncidentEntry>> {
        let mut file = self.file.lock();

        file.flush().map_err(|err| {
            AsxError::new(
                ErrorCode::ReliabilityFailure,
                format!("failed to flush incident spool file before drain: {err}"),
                ErrorContext::new("incident_file_spool_drain"),
            )
        })?;

        let contents = std::fs::read_to_string(&self.path).map_err(|err| {
            AsxError::new(
                ErrorCode::ReliabilityFailure,
                format!("failed to read incident spool file before drain: {err}"),
                ErrorContext::new("incident_file_spool_drain"),
            )
        })?;

        let entries = parse_spool_entries(&contents)?;

        file.set_len(0).map_err(|err| {
            AsxError::new(
                ErrorCode::ReliabilityFailure,
                format!("failed to truncate incident spool file: {err}"),
                ErrorContext::new("incident_file_spool_drain"),
            )
        })?;
        file.seek(SeekFrom::Start(0)).map_err(|err| {
            AsxError::new(
                ErrorCode::ReliabilityFailure,
                format!("failed to rewind incident spool file after truncate: {err}"),
                ErrorContext::new("incident_file_spool_drain"),
            )
        })?;
        file.flush().map_err(|err| {
            AsxError::new(
                ErrorCode::ReliabilityFailure,
                format!("failed to flush incident spool file after drain: {err}"),
                ErrorContext::new("incident_file_spool_drain"),
            )
        })?;
        if self.fsync_each_write {
            file.sync_data().map_err(|err| {
                AsxError::new(
                    ErrorCode::ReliabilityFailure,
                    format!("failed to fsync incident spool file after drain: {err}"),
                    ErrorContext::new("incident_file_spool_drain"),
                )
            })?;
        }

        Ok(entries)
    }
}

fn parse_spool_entries(contents: &str) -> Result<Vec<FileSpoolIncidentEntry>> {
    let mut entries = Vec::new();
    for (idx, line) in contents.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let entry = serde_json::from_str::<FileSpoolIncidentEntry>(trimmed).map_err(|err| {
            AsxError::new(
                ErrorCode::ReliabilityFailure,
                format!(
                    "failed to parse incident spool entry on line {}: {err}",
                    idx + 1
                ),
                ErrorContext::new("incident_file_spool_parse"),
            )
        })?;
        entries.push(entry);
    }
    Ok(entries)
}

fn write_replay_checkpoint(
    checkpoint_path: PathBuf,
    checkpoint: &FileSpoolReplayCheckpoint,
) -> Result<()> {
    if checkpoint_path.as_os_str().is_empty() {
        return Err(AsxError::new(
            ErrorCode::InvalidInput,
            "checkpoint path must not be empty",
            ErrorContext::new("incident_file_spool_checkpoint_write"),
        ));
    }

    if let Some(parent) = checkpoint_path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent).map_err(|err| {
            AsxError::new(
                ErrorCode::ReliabilityFailure,
                format!("failed to create checkpoint directory: {err}"),
                ErrorContext::new("incident_file_spool_checkpoint_write"),
            )
        })?;
    }

    let serialized = serde_json::to_vec_pretty(checkpoint).map_err(|err| {
        AsxError::new(
            ErrorCode::ReliabilityFailure,
            format!("failed to serialize replay checkpoint: {err}"),
            ErrorContext::new("incident_file_spool_checkpoint_write"),
        )
    })?;

    std::fs::write(&checkpoint_path, serialized).map_err(|err| {
        AsxError::new(
            ErrorCode::ReliabilityFailure,
            format!("failed to write replay checkpoint: {err}"),
            ErrorContext::new("incident_file_spool_checkpoint_write"),
        )
    })
}

pub(super) fn replay_idempotency_ledger_path(checkpoint_path: &Path) -> PathBuf {
    checkpoint_path.with_extension("checkpoint.ledger")
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct FileSpoolReplayLedgerEntry {
    pub(super) dedup_key: String,
    pub(super) forwarded_unix_millis: u128,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct FileSpoolReplayLedgerFile {
    pub(super) version: u8,
    pub(super) entries: Vec<FileSpoolReplayLedgerEntry>,
}

fn load_replay_idempotency_ledger(
    ledger_path: &Path,
) -> Result<std::collections::HashMap<String, u128>> {
    if !ledger_path.exists() {
        return Ok(std::collections::HashMap::new());
    }

    let contents = std::fs::read_to_string(ledger_path).map_err(|err| {
        AsxError::new(
            ErrorCode::ReliabilityFailure,
            format!("failed to read replay idempotency ledger: {err}"),
            ErrorContext::new("incident_file_spool_idempotency_load"),
        )
    })?;

    let ledger = serde_json::from_str::<FileSpoolReplayLedgerFile>(&contents).map_err(|err| {
        AsxError::new(
            ErrorCode::ReliabilityFailure,
            format!(
                "failed to parse replay idempotency ledger as structured JSON (legacy formats are no longer supported): {err}"
            ),
            ErrorContext::new("incident_file_spool_idempotency_load"),
        )
    })?;

    if ledger.version != 1 {
        return Err(AsxError::new(
            ErrorCode::ReliabilityFailure,
            format!(
                "unsupported replay idempotency ledger version {}; expected version 1",
                ledger.version
            ),
            ErrorContext::new("incident_file_spool_idempotency_load"),
        ));
    }

    let mut map = std::collections::HashMap::new();
    for entry in ledger.entries {
        map.insert(entry.dedup_key, entry.forwarded_unix_millis);
    }
    Ok(map)
}

fn compact_replay_idempotency_ledger(
    dedup_keys: &mut std::collections::HashMap<String, u128>,
    policy: FileSpoolIdempotencyLedgerPolicy,
    now_unix_millis: u128,
) {
    if policy.retention_secs > 0 {
        let retention_millis = u128::from(policy.retention_secs) * 1_000;
        let cutoff = now_unix_millis.saturating_sub(retention_millis);
        dedup_keys.retain(|_, forwarded_at| *forwarded_at == 0 || *forwarded_at >= cutoff);
    }

    let max_entries = policy.max_entries.max(1);
    if dedup_keys.len() <= max_entries {
        return;
    }

    let mut ordered: Vec<(String, u128)> =
        dedup_keys.iter().map(|(k, v)| (k.clone(), *v)).collect();
    ordered.sort_by(|a, b| a.1.cmp(&b.1).then_with(|| a.0.cmp(&b.0)));

    let to_remove = ordered.len() - max_entries;
    for (key, _) in ordered.into_iter().take(to_remove) {
        dedup_keys.remove(&key);
    }
}

pub(super) fn persist_replay_idempotency_ledger(
    ledger_path: &Path,
    dedup_keys: &std::collections::HashMap<String, u128>,
) -> Result<()> {
    if let Some(parent) = ledger_path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent).map_err(|err| {
            AsxError::new(
                ErrorCode::ReliabilityFailure,
                format!("failed to create replay idempotency directory: {err}"),
                ErrorContext::new("incident_file_spool_idempotency_write"),
            )
        })?;
    }

    let mut entries: Vec<FileSpoolReplayLedgerEntry> = dedup_keys
        .iter()
        .map(
            |(dedup_key, forwarded_unix_millis)| FileSpoolReplayLedgerEntry {
                dedup_key: dedup_key.clone(),
                forwarded_unix_millis: *forwarded_unix_millis,
            },
        )
        .collect();
    entries.sort_by(|a, b| {
        a.forwarded_unix_millis
            .cmp(&b.forwarded_unix_millis)
            .then_with(|| a.dedup_key.cmp(&b.dedup_key))
    });

    let out = serde_json::to_string_pretty(&FileSpoolReplayLedgerFile {
        version: 1,
        entries,
    })
    .map_err(|err| {
        AsxError::new(
            ErrorCode::ReliabilityFailure,
            format!("failed to serialize replay idempotency ledger: {err}"),
            ErrorContext::new("incident_file_spool_idempotency_write"),
        )
    })?;

    std::fs::write(ledger_path, out).map_err(|err| {
        AsxError::new(
            ErrorCode::ReliabilityFailure,
            format!("failed to persist replay idempotency ledger: {err}"),
            ErrorContext::new("incident_file_spool_idempotency_write"),
        )
    })
}

pub(super) fn now_unix_millis() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

fn parse_as2_severity(value: &str) -> Result<crate::observability::As2ProviderHealthAlertSeverity> {
    match value {
        "warning" => Ok(crate::observability::As2ProviderHealthAlertSeverity::Warning),
        "critical" => Ok(crate::observability::As2ProviderHealthAlertSeverity::Critical),
        _ => Err(AsxError::new(
            ErrorCode::InvalidInput,
            format!("unsupported AS2 severity in spool entry: {value}"),
            ErrorContext::new("incident_file_spool_as2_parse"),
        )),
    }
}

fn parse_as2_category(value: &str) -> Result<crate::observability::As2ProviderHealthAlertCategory> {
    match value {
        "transition_to_failing_rate" => {
            Ok(crate::observability::As2ProviderHealthAlertCategory::TransitionToFailingRate)
        }
        _ => Err(AsxError::new(
            ErrorCode::InvalidInput,
            format!("unsupported AS2 category in spool entry: {value}"),
            ErrorContext::new("incident_file_spool_as2_parse"),
        )),
    }
}

fn replay_as2_runbook_hint(
    category: crate::observability::As2ProviderHealthAlertCategory,
) -> &'static str {
    match category {
        crate::observability::As2ProviderHealthAlertCategory::TransitionToFailingRate => {
            "Investigate provider health."
        }
    }
}

fn parse_as4_severity(
    value: &str,
) -> Result<crate::observability::As4ReceiptTaxonomyAlertSeverity> {
    match value {
        "warning" => Ok(crate::observability::As4ReceiptTaxonomyAlertSeverity::Warning),
        "critical" => Ok(crate::observability::As4ReceiptTaxonomyAlertSeverity::Critical),
        _ => Err(AsxError::new(
            ErrorCode::InvalidInput,
            format!("unsupported AS4 severity in spool entry: {value}"),
            ErrorContext::new("incident_file_spool_as4_parse"),
        )),
    }
}

fn parse_as4_category(
    value: &str,
) -> Result<crate::observability::As4ReceiptTaxonomyAlertCategory> {
    match value {
        "security_verification_failed" => {
            Ok(crate::observability::As4ReceiptTaxonomyAlertCategory::SecurityVerificationFailed)
        }
        "semantic_interop_failure" => {
            Ok(crate::observability::As4ReceiptTaxonomyAlertCategory::SemanticInteropFailure)
        }
        _ => Err(AsxError::new(
            ErrorCode::InvalidInput,
            format!("unsupported AS4 category in spool entry: {value}"),
            ErrorContext::new("incident_file_spool_as4_parse"),
        )),
    }
}

fn replay_as4_runbook_hint(
    category: crate::observability::As4ReceiptTaxonomyAlertCategory,
) -> &'static str {
    match category {
        crate::observability::As4ReceiptTaxonomyAlertCategory::SecurityVerificationFailed => {
            "Check WS-Security signature verification."
        }
        crate::observability::As4ReceiptTaxonomyAlertCategory::SemanticInteropFailure => {
            "Review interoperability profile mapping and payload semantics."
        }
    }
}

#[derive(Debug)]
pub struct As2ProviderHealthFileSpoolIncidentChannel {
    writer: Arc<FileSpoolIncidentWriter>,
    ledger_policy: FileSpoolIdempotencyLedgerPolicy,
}

impl As2ProviderHealthFileSpoolIncidentChannel {
    pub fn new(path: impl Into<PathBuf>) -> Result<Self> {
        Self::with_config(FileSpoolIncidentConfig {
            path: path.into(),
            fsync_each_write: true,
            idempotency_ledger_policy: FileSpoolIdempotencyLedgerPolicy::default(),
        })
    }

    pub fn with_config(config: FileSpoolIncidentConfig) -> Result<Self> {
        let ledger_policy = config.idempotency_ledger_policy;
        Ok(Self {
            writer: Arc::new(FileSpoolIncidentWriter::new(config)?),
            ledger_policy,
        })
    }

    pub fn spool_path(&self) -> &PathBuf {
        &self.writer.path
    }

    pub fn replay_spooled_incidents(&self) -> Result<Vec<FileSpoolIncidentEntry>> {
        self.writer.replay_entries()
    }

    pub fn drain_spooled_incidents(&self) -> Result<Vec<FileSpoolIncidentEntry>> {
        self.writer.drain_entries()
    }

    pub fn drain_and_forward_with_checkpoint(
        &self,
        channel: &dyn As2ProviderHealthIncidentChannel,
        checkpoint_path: impl Into<PathBuf>,
    ) -> Result<FileSpoolForwardSummary> {
        let checkpoint_path = checkpoint_path.into();
        let ledger_path = replay_idempotency_ledger_path(&checkpoint_path);
        let mut dedup_ledger = load_replay_idempotency_ledger(&ledger_path)?;
        let now_millis = now_unix_millis();
        compact_replay_idempotency_ledger(&mut dedup_ledger, self.ledger_policy, now_millis);
        let drained = self.writer.drain_entries()?;
        let total_drained = drained.len();
        let mut forwarded = 0usize;
        let mut skipped_duplicates = 0usize;
        let mut requeued_entries = Vec::new();
        let mut last_forwarded_dedup_key = None;

        for idx in 0..drained.len() {
            let entry = drained[idx].clone();
            if entry.protocol != "as2" {
                requeued_entries.push(entry);
                continue;
            }

            if dedup_ledger.contains_key(&entry.dedup_key) {
                skipped_duplicates += 1;
                continue;
            }

            let severity = parse_as2_severity(&entry.severity)?;
            let category = parse_as2_category(&entry.category)?;
            let incident = As2ProviderHealthAlertIncident {
                dedup_key: entry.dedup_key.clone(),
                signal: "as2",
                severity,
                category,
                observed_rate_ppm: entry.observed_rate_ppm,
                sample_size: entry.sample_size,
                runbook_hint: replay_as2_runbook_hint(category),
            };

            match channel.send_incident(&incident) {
                Ok(()) => {
                    forwarded += 1;
                    last_forwarded_dedup_key = Some(entry.dedup_key.clone());
                    dedup_ledger.insert(entry.dedup_key, now_millis);
                }
                Err(err) => {
                    requeued_entries.push(entry);
                    if idx + 1 < drained.len() {
                        requeued_entries.extend_from_slice(&drained[idx + 1..]);
                    }
                    self.writer.append_entries(&requeued_entries)?;
                    compact_replay_idempotency_ledger(
                        &mut dedup_ledger,
                        self.ledger_policy,
                        now_millis,
                    );
                    persist_replay_idempotency_ledger(&ledger_path, &dedup_ledger)?;
                    let checkpoint = FileSpoolReplayCheckpoint {
                        status: FileSpoolReplayCheckpointStatus::Failed.as_str().to_string(),
                        protocol: "as2".to_string(),
                        drained_entries: total_drained,
                        forwarded_entries: forwarded,
                        skipped_duplicate_entries: skipped_duplicates,
                        requeued_entries: requeued_entries.len(),
                        last_forwarded_dedup_key,
                        updated_unix_millis: now_unix_millis(),
                    };
                    write_replay_checkpoint(checkpoint_path.clone(), &checkpoint)?;
                    return Err(err);
                }
            }
        }

        compact_replay_idempotency_ledger(&mut dedup_ledger, self.ledger_policy, now_millis);
        persist_replay_idempotency_ledger(&ledger_path, &dedup_ledger)?;
        let checkpoint = FileSpoolReplayCheckpoint {
            status: FileSpoolReplayCheckpointStatus::Committed
                .as_str()
                .to_string(),
            protocol: "as2".to_string(),
            drained_entries: total_drained,
            forwarded_entries: forwarded,
            skipped_duplicate_entries: skipped_duplicates,
            requeued_entries: requeued_entries.len(),
            last_forwarded_dedup_key,
            updated_unix_millis: now_unix_millis(),
        };
        write_replay_checkpoint(checkpoint_path, &checkpoint)?;
        Ok(FileSpoolForwardSummary { checkpoint })
    }
}

impl As2ProviderHealthIncidentChannel for As2ProviderHealthFileSpoolIncidentChannel {
    fn send_incident(&self, incident: &As2ProviderHealthAlertIncident) -> Result<()> {
        let record = FileSpoolIncidentEntry {
            adapter: "as2_provider_health_file_spool".to_string(),
            protocol: "as2".to_string(),
            signal: incident.signal.to_string(),
            dedup_key: incident.dedup_key.clone(),
            severity: incident.severity.as_str().to_string(),
            category: incident.category.as_str().to_string(),
            observed_rate_ppm: incident.observed_rate_ppm,
            sample_size: incident.sample_size,
            runbook_hint: incident.runbook_hint.to_string(),
        };
        self.writer.append_record(&record)
    }
}

#[derive(Debug)]
pub struct As4ReceiptTaxonomyFileSpoolIncidentChannel {
    writer: Arc<FileSpoolIncidentWriter>,
    ledger_policy: FileSpoolIdempotencyLedgerPolicy,
}

impl As4ReceiptTaxonomyFileSpoolIncidentChannel {
    pub fn new(path: impl Into<PathBuf>) -> Result<Self> {
        Self::with_config(FileSpoolIncidentConfig {
            path: path.into(),
            fsync_each_write: true,
            idempotency_ledger_policy: FileSpoolIdempotencyLedgerPolicy::default(),
        })
    }

    pub fn with_config(config: FileSpoolIncidentConfig) -> Result<Self> {
        let ledger_policy = config.idempotency_ledger_policy;
        Ok(Self {
            writer: Arc::new(FileSpoolIncidentWriter::new(config)?),
            ledger_policy,
        })
    }

    pub fn spool_path(&self) -> &PathBuf {
        &self.writer.path
    }

    pub fn replay_spooled_incidents(&self) -> Result<Vec<FileSpoolIncidentEntry>> {
        self.writer.replay_entries()
    }

    pub fn drain_spooled_incidents(&self) -> Result<Vec<FileSpoolIncidentEntry>> {
        self.writer.drain_entries()
    }

    pub fn drain_and_forward_with_checkpoint(
        &self,
        channel: &dyn As4ReceiptTaxonomyIncidentChannel,
        checkpoint_path: impl Into<PathBuf>,
    ) -> Result<FileSpoolForwardSummary> {
        let checkpoint_path = checkpoint_path.into();
        let ledger_path = replay_idempotency_ledger_path(&checkpoint_path);
        let mut dedup_ledger = load_replay_idempotency_ledger(&ledger_path)?;
        let now_millis = now_unix_millis();
        compact_replay_idempotency_ledger(&mut dedup_ledger, self.ledger_policy, now_millis);
        let drained = self.writer.drain_entries()?;
        let total_drained = drained.len();
        let mut forwarded = 0usize;
        let mut skipped_duplicates = 0usize;
        let mut requeued_entries = Vec::new();
        let mut last_forwarded_dedup_key = None;

        for idx in 0..drained.len() {
            let entry = drained[idx].clone();
            if entry.protocol != "as4" {
                requeued_entries.push(entry);
                continue;
            }

            if dedup_ledger.contains_key(&entry.dedup_key) {
                skipped_duplicates += 1;
                continue;
            }

            let severity = parse_as4_severity(&entry.severity)?;
            let category = parse_as4_category(&entry.category)?;
            let incident = As4ReceiptTaxonomyAlertIncident {
                dedup_key: entry.dedup_key.clone(),
                signal: "as4",
                severity,
                category,
                observed_rate_ppm: entry.observed_rate_ppm,
                sample_size: entry.sample_size,
                runbook_hint: replay_as4_runbook_hint(category),
            };

            match channel.send_incident(&incident) {
                Ok(()) => {
                    forwarded += 1;
                    last_forwarded_dedup_key = Some(entry.dedup_key.clone());
                    dedup_ledger.insert(entry.dedup_key, now_millis);
                }
                Err(err) => {
                    requeued_entries.push(entry);
                    if idx + 1 < drained.len() {
                        requeued_entries.extend_from_slice(&drained[idx + 1..]);
                    }
                    self.writer.append_entries(&requeued_entries)?;
                    compact_replay_idempotency_ledger(
                        &mut dedup_ledger,
                        self.ledger_policy,
                        now_millis,
                    );
                    persist_replay_idempotency_ledger(&ledger_path, &dedup_ledger)?;
                    let checkpoint = FileSpoolReplayCheckpoint {
                        status: FileSpoolReplayCheckpointStatus::Failed.as_str().to_string(),
                        protocol: "as4".to_string(),
                        drained_entries: total_drained,
                        forwarded_entries: forwarded,
                        skipped_duplicate_entries: skipped_duplicates,
                        requeued_entries: requeued_entries.len(),
                        last_forwarded_dedup_key,
                        updated_unix_millis: now_unix_millis(),
                    };
                    write_replay_checkpoint(checkpoint_path.clone(), &checkpoint)?;
                    return Err(err);
                }
            }
        }

        compact_replay_idempotency_ledger(&mut dedup_ledger, self.ledger_policy, now_millis);
        persist_replay_idempotency_ledger(&ledger_path, &dedup_ledger)?;
        let checkpoint = FileSpoolReplayCheckpoint {
            status: FileSpoolReplayCheckpointStatus::Committed
                .as_str()
                .to_string(),
            protocol: "as4".to_string(),
            drained_entries: total_drained,
            forwarded_entries: forwarded,
            skipped_duplicate_entries: skipped_duplicates,
            requeued_entries: requeued_entries.len(),
            last_forwarded_dedup_key,
            updated_unix_millis: now_unix_millis(),
        };
        write_replay_checkpoint(checkpoint_path, &checkpoint)?;
        Ok(FileSpoolForwardSummary { checkpoint })
    }
}

impl As4ReceiptTaxonomyIncidentChannel for As4ReceiptTaxonomyFileSpoolIncidentChannel {
    fn send_incident(&self, incident: &As4ReceiptTaxonomyAlertIncident) -> Result<()> {
        let record = FileSpoolIncidentEntry {
            adapter: "as4_receipt_taxonomy_file_spool".to_string(),
            protocol: "as4".to_string(),
            signal: incident.signal.to_string(),
            dedup_key: incident.dedup_key.clone(),
            severity: incident.severity.as_str().to_string(),
            category: incident.category.as_str().to_string(),
            observed_rate_ppm: incident.observed_rate_ppm,
            sample_size: incident.sample_size,
            runbook_hint: incident.runbook_hint.to_string(),
        };
        self.writer.append_record(&record)
    }
}
