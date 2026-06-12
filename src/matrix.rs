//! Interoperability matrix execution APIs for the `testing` feature.
//!
//! This module executes fixture catalogs produced by `crate::fixtures` and
//! emits deterministic summary records that can drive CI gates and quarantine
//! workflows.

#[cfg(any(feature = "as2", feature = "as4"))]
use crate::core::InteropMode;
#[cfg(feature = "as2")]
use crate::core::ReceivedBodyHandle;
use crate::core::{AsxError, ErrorCode, ErrorContext, Result, SessionContext};
#[cfg(feature = "as4")]
use crate::core::{CertHandle, OcspMode};
use crate::fixtures::{
    FixtureExpectedOutcome, FixtureMode, FixtureProtocol, InteropFixtureMetadata,
    load_fixture_catalog, validate_fixture_catalog,
};
#[cfg(feature = "as2")]
use crate::lifecycle::TrustEvidence;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

#[cfg(feature = "as2")]
use crate::as2::{
    As2MdnMode, As2ReceiveMdnRequest, As2ReceivePolicy, As2RegulatedSpoolKeyProvider,
    As2TrustVerifier, TrustResult, receive_with_mdn_with_reliability,
};
// `matrix` is an in-crate module so we can access the private sealing marker.
#[cfg(feature = "as2")]
use crate::as2::private::Sealed as TrustVerifierSeal;
#[cfg(feature = "as4")]
use crate::as4::{
    As4PushPolicy, As4ReceivePushRequest, As4ReceivePushSyncRequest, receive_push_with_dedup_sync,
};
#[cfg(feature = "as4")]
use crate::crypto::wssec::{WsSecOutboundKeyInfoProfile, generate_xmlsig_signature};
#[cfg(feature = "as2")]
use crate::interop::{InteropExceptionCode, InteropExceptionPolicy};
#[cfg(any(feature = "as2", feature = "as4"))]
use crate::observability::EventBus;
#[cfg(any(feature = "as2", feature = "as4"))]
use crate::reliability::InMemoryDedupBackend;
#[cfg(feature = "as2")]
use crate::reliability::InMemoryReconciliationHook;

#[cfg(feature = "as2")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DeterministicTrustVerifier {
    trust: TrustEvidence,
}

#[cfg(feature = "as2")]
impl DeterministicTrustVerifier {
    fn new(trust: TrustEvidence) -> Self {
        Self { trust }
    }
}

#[cfg(feature = "as4")]
fn infer_as4_fixture_http_content_type(payload: &[u8]) -> String {
    let Some(first_line) = payload
        .split(|byte| *byte == b'\n')
        .next()
        .and_then(|line| std::str::from_utf8(line).ok())
    else {
        return "application/soap+xml".to_string();
    };

    let trimmed = first_line.trim_end_matches('\r').trim();
    if !trimmed.starts_with("--") {
        return "application/soap+xml".to_string();
    }

    let boundary = trimmed.trim_start_matches("--").trim();
    if boundary.is_empty() {
        return "application/soap+xml".to_string();
    }

    format!("multipart/related; boundary={boundary}")
}
#[cfg(feature = "as2")]
impl TrustVerifierSeal for DeterministicTrustVerifier {}

#[cfg(feature = "as2")]
impl As2TrustVerifier for DeterministicTrustVerifier {
    fn verify_and_decrypt(
        &self,
        _session: &SessionContext,
        _body: &ReceivedBodyHandle,
    ) -> Result<TrustResult> {
        Ok(TrustResult {
            signature: self.trust.signature,
            decryption: self.trust.decryption,
            decrypted_payload: None,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MatrixExecutionRecord {
    pub fixture_id: String,
    pub protocol: FixtureProtocol,
    pub mode: FixtureMode,
    pub partner_id: String,
    pub profile_name: String,
    pub stage: String,
    pub expected_outcome: FixtureExpectedOutcome,
    pub observed_outcome: FixtureExpectedOutcome,
    pub observed_error_code: Option<String>,
    pub pass: bool,
    pub flaky: bool,
    pub quarantined: bool,
    pub quarantine_owner: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MatrixSummary {
    pub catalog_path: String,
    pub iterations: usize,
    pub total: usize,
    pub passed: usize,
    pub failed: usize,
    pub flaky: usize,
    pub quarantined: usize,
    pub records: Vec<MatrixExecutionRecord>,
}

impl MatrixSummary {
    pub fn to_json_pretty(&self) -> Result<String> {
        serde_json::to_string_pretty(self).map_err(|err| {
            AsxError::new(
                ErrorCode::ParseFailed,
                format!("failed to serialize matrix summary: {err}"),
                ErrorContext::new("interop_matrix_summary_serialize"),
            )
        })
    }

    pub fn has_blocking_failures(&self) -> bool {
        self.records
            .iter()
            .any(|record| !(record.pass || (record.flaky && record.quarantined)))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct MatrixQuarantineList {
    pub entries: Vec<MatrixQuarantineEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MatrixQuarantineEntry {
    pub fixture_id: String,
    pub owner: String,
    pub reason: String,
}

/// Load optional flaky-fixture quarantine declarations.
///
/// Missing files are treated as an empty quarantine list.
pub fn load_quarantine_list(path: &Path) -> Result<MatrixQuarantineList> {
    if !path.exists() {
        return Ok(MatrixQuarantineList::default());
    }
    let raw = std::fs::read_to_string(path).map_err(|err| {
        AsxError::new(
            ErrorCode::ParseFailed,
            format!(
                "failed to read matrix quarantine list {}: {err}",
                path.display()
            ),
            ErrorContext::new("interop_matrix_quarantine_read"),
        )
    })?;
    let list: MatrixQuarantineList = serde_json::from_str(&raw).map_err(|err| {
        AsxError::new(
            ErrorCode::ParseFailed,
            format!(
                "failed to parse matrix quarantine list {}: {err}",
                path.display()
            ),
            ErrorContext::new("interop_matrix_quarantine_parse"),
        )
    })?;
    for entry in &list.entries {
        if entry.fixture_id.trim().is_empty() || entry.owner.trim().is_empty() {
            return Err(AsxError::new(
                ErrorCode::InvalidInput,
                "matrix quarantine entry must include non-empty fixture_id and owner",
                ErrorContext::new("interop_matrix_quarantine_validate"),
            ));
        }
    }
    Ok(list)
}

/// Execute the fixture matrix for `iterations` rounds and compute pass/flaky
/// outcomes suitable for test-gate enforcement.
pub fn run_interop_fixture_matrix(
    catalog_path: &Path,
    quarantine_path: &Path,
    iterations: usize,
) -> Result<MatrixSummary> {
    if iterations == 0 {
        return Err(AsxError::new(
            ErrorCode::InvalidInput,
            "matrix iterations must be greater than zero",
            ErrorContext::new("interop_matrix_run"),
        ));
    }

    let _ = validate_fixture_catalog(catalog_path)?;
    let catalog = load_fixture_catalog(catalog_path)?;
    let quarantine = load_quarantine_list(quarantine_path)?;
    let quarantine_map: HashMap<String, String> = quarantine
        .entries
        .iter()
        .map(|entry| (entry.fixture_id.clone(), entry.owner.clone()))
        .collect();

    let base_dir = catalog_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .to_path_buf();

    let mut records = Vec::with_capacity(catalog.fixtures.len());

    for fixture in &catalog.fixtures {
        let mut observed = Vec::with_capacity(iterations);
        for idx in 0..iterations {
            observed.push(execute_fixture(&base_dir, fixture, idx)?);
        }

        let unique: HashSet<String> = observed
            .iter()
            .map(|out| {
                format!(
                    "{:?}|{}",
                    out.outcome,
                    out.error_code
                        .map(|code| code.as_str().to_string())
                        .unwrap_or_else(|| "none".to_string())
                )
            })
            .collect();
        let flaky = unique.len() > 1;

        let pass = observed
            .iter()
            .all(|out| out.outcome == fixture.expected_outcome);
        let failing = observed
            .iter()
            .copied()
            .find(|out| out.outcome != fixture.expected_outcome);
        let observed_outcome = failing
            .map(|out| out.outcome)
            .unwrap_or(fixture.expected_outcome);
        let observed_error_code = failing.and_then(|out| out.error_code);

        let quarantine_owner = quarantine_map.get(&fixture.fixture_id).cloned();
        let quarantined = flaky && quarantine_owner.is_some();

        records.push(MatrixExecutionRecord {
            fixture_id: fixture.fixture_id.clone(),
            protocol: fixture.protocol,
            mode: fixture.mode,
            partner_id: fixture.grouping.partner_id.clone(),
            profile_name: fixture.grouping.profile_name.clone(),
            stage: fixture.grouping.protocol_stage.clone(),
            expected_outcome: fixture.expected_outcome,
            observed_outcome,
            observed_error_code: observed_error_code.map(|code| code.as_str().to_string()),
            pass,
            flaky,
            quarantined,
            quarantine_owner,
        });
    }

    let total = records.len();
    let passed = records.iter().filter(|record| record.pass).count();
    let failed = total - passed;
    let flaky = records.iter().filter(|record| record.flaky).count();
    let quarantined = records.iter().filter(|record| record.quarantined).count();

    Ok(MatrixSummary {
        catalog_path: catalog_path.display().to_string(),
        iterations,
        total,
        passed,
        failed,
        flaky,
        quarantined,
        records,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ObservedOutcome {
    outcome: FixtureExpectedOutcome,
    error_code: Option<ErrorCode>,
}

fn execute_fixture(
    base_dir: &Path,
    fixture: &InteropFixtureMetadata,
    run_idx: usize,
) -> Result<ObservedOutcome> {
    let session = SessionContext::new(
        format!("matrix:{}:{}", fixture.fixture_id, run_idx),
        fixture.grouping.partner_id.clone(),
        fixture.grouping.profile_name.clone(),
    )?;

    let payload_path = resolve_payload_path(base_dir, &fixture.payload_path);
    let payload = std::fs::read(&payload_path).map_err(|err| {
        AsxError::new(
            ErrorCode::ParseFailed,
            format!(
                "failed reading fixture payload {}: {err}",
                payload_path.display()
            ),
            ErrorContext::new("interop_matrix_fixture_read"),
        )
    })?;

    let receipt_payload = fixture
        .receipt_payload_path
        .as_ref()
        .map(|path| resolve_payload_path(base_dir, path))
        .map(|path| {
            std::fs::read(&path).map_err(|err| {
                AsxError::new(
                    ErrorCode::ParseFailed,
                    format!(
                        "failed reading fixture receipt payload {}: {err}",
                        path.display()
                    ),
                    ErrorContext::new("interop_matrix_fixture_read"),
                )
            })
        })
        .transpose()?;
    #[cfg(feature = "as4")]
    let generated_receipt_payload = fixture
        .generated_receipt_ref_to_message_id
        .as_ref()
        .map(|ref_to_message_id| generate_signed_receipt_fixture(base_dir, ref_to_message_id))
        .transpose()?;
    #[cfg(not(feature = "as4"))]
    let generated_receipt_payload: Option<Vec<u8>> = None;
    let receipt_payload = receipt_payload.or(generated_receipt_payload);

    match fixture.protocol {
        FixtureProtocol::As2Mime => execute_as2_fixture(&session, fixture, payload),
        FixtureProtocol::As4Soap => {
            execute_as4_fixture(base_dir, &session, fixture, payload, receipt_payload)
        }
    }
}

#[cfg(feature = "as2")]
fn execute_as2_fixture(
    session: &SessionContext,
    fixture: &InteropFixtureMetadata,
    payload: Vec<u8>,
) -> Result<ObservedOutcome> {
    let bus = EventBus::new(32)?;
    let _events = bus.subscribe_scoped_events();
    let mut policy = As2ReceivePolicy {
        interop_mode: interop_mode_from_fixture(fixture.mode),
        interop_exceptions: InteropExceptionPolicy::default(),
        fail_closed_audit_events: false,
        regulated_spool_key_provider: As2RegulatedSpoolKeyProvider::LocalEnv,
        enforce_as2_version: true,
    };

    if fixture.mode == FixtureMode::Relaxed {
        policy.interop_exceptions = InteropExceptionPolicy::scoped(
            session.profile_name().to_string(),
            vec![InteropExceptionCode::As2AllowMissingMdnBoundary],
        );
    }

    let hook = InMemoryReconciliationHook::default();
    let dedup = InMemoryDedupBackend::default();
    let verifier = DeterministicTrustVerifier::new(TrustEvidence::verified_and_decryptable());
    let result = receive_with_mdn_with_reliability(
        session,
        &bus,
        As2ReceiveMdnRequest {
            payload: b"matrix-payload".to_vec().into(),
            mdn_payload: payload.into(),
            mdn_mode: As2MdnMode::Synchronous,
            expected_mic: None,
            policy,
            original_message_id: None,
        },
        &hook,
        &dedup,
        &verifier,
    );

    Ok(map_result(result))
}

#[cfg(not(feature = "as2"))]
fn execute_as2_fixture(
    _session: &SessionContext,
    _fixture: &InteropFixtureMetadata,
    _payload: Vec<u8>,
) -> Result<ObservedOutcome> {
    Ok(ObservedOutcome {
        outcome: FixtureExpectedOutcome::ParseFailed,
        error_code: Some(ErrorCode::ParseFailed),
    })
}

#[cfg(feature = "as4")]
fn execute_as4_fixture(
    base_dir: &Path,
    session: &SessionContext,
    fixture: &InteropFixtureMetadata,
    payload: Vec<u8>,
    receipt_payload: Option<Vec<u8>>,
) -> Result<ObservedOutcome> {
    let bus = EventBus::new(32)?;
    let _events = bus.subscribe_scoped_events();
    let mut policy = As4PushPolicy::strict();
    policy.interop = interop_mode_from_fixture(fixture.mode);
    // Interop matrix payloads are parser/interop fixtures and intentionally
    // not full cryptographic WS-Security vectors.
    policy.require_signed_push = false;
    // Matrix fixtures may omit receipts when exercising parser/interop behavior.
    // Disable signed-receipt requirement so fixture outcomes reflect the target
    // protocol signal instead of receipt-policy preconditions.
    policy.require_signed_receipt = false;
    policy.fail_closed_audit_events = false;

    let http_content_type = infer_as4_fixture_http_content_type(&payload);
    let dedup = InMemoryDedupBackend::default();
    let configured_session = configure_matrix_as4_trust_anchor(base_dir, session)?;
    let result = receive_push_with_dedup_sync(
        &configured_session,
        &bus,
        As4ReceivePushSyncRequest {
            request: As4ReceivePushRequest {
                http_content_type,
                payload: payload.into(),
                receipt_payload,
                policy,
                authenticated_sender_scope: None,
            },
            dedup_backend: &dedup,
        },
    );

    Ok(map_result(result))
}

#[cfg(not(feature = "as4"))]
fn execute_as4_fixture(
    _base_dir: &Path,
    _session: &SessionContext,
    _fixture: &InteropFixtureMetadata,
    _payload: Vec<u8>,
    _receipt_payload: Option<Vec<u8>>,
) -> Result<ObservedOutcome> {
    Ok(ObservedOutcome {
        outcome: FixtureExpectedOutcome::ParseFailed,
        error_code: Some(ErrorCode::ParseFailed),
    })
}

#[cfg(feature = "as4")]
fn configure_matrix_as4_trust_anchor(
    base_dir: &Path,
    session: &SessionContext,
) -> Result<SessionContext> {
    let pki_dir = base_dir.parent().map(|parent| parent.join("pki"));
    let Some(pki_dir) = pki_dir else {
        return Ok(session.clone());
    };

    let receipt_signing_cert = pki_dir.join("receipt_signing.cert.pem");
    if !receipt_signing_cert.exists() {
        return Ok(session.clone());
    }

    let cert_pem = std::fs::read_to_string(&receipt_signing_cert).map_err(|err| {
        AsxError::new(
            ErrorCode::ParseFailed,
            format!(
                "failed reading matrix receipt signing cert {}: {err}",
                receipt_signing_cert.display()
            ),
            ErrorContext::new("interop_matrix_fixture_read"),
        )
    })?;

    let mut cert_handle = CertHandle::new("matrix-receipt-signing-anchor");
    cert_handle.trust_anchor_pems = vec![cert_pem];
    cert_handle.ocsp_mode = OcspMode::Disabled;
    session.clone().with_cert_handle(cert_handle)
}

#[cfg(feature = "as4")]
fn generate_signed_receipt_fixture(base_dir: &Path, ref_to_message_id: &str) -> Result<Vec<u8>> {
    const SIGNAL_WSU_ID: &str = "as4-receipt-signal";

    let pki_dir = base_dir
        .parent()
        .ok_or_else(|| {
            AsxError::new(
                ErrorCode::InvalidInput,
                "failed to resolve fixture PKI directory for generated receipt",
                ErrorContext::new("interop_matrix_fixture_read"),
            )
        })?
        .join("pki");

    let signing_key_path = pki_dir.join("receipt_signing.key.pem");
    let signing_cert_path = pki_dir.join("receipt_signing.cert.pem");

    let signing_key_pem = std::fs::read(&signing_key_path).map_err(|err| {
        AsxError::new(
            ErrorCode::ParseFailed,
            format!(
                "failed reading generated receipt signing key {}: {err}",
                signing_key_path.display()
            ),
            ErrorContext::new("interop_matrix_fixture_read"),
        )
    })?;
    let signing_cert_pem = std::fs::read(&signing_cert_path).map_err(|err| {
        AsxError::new(
            ErrorCode::ParseFailed,
            format!(
                "failed reading generated receipt signing cert {}: {err}",
                signing_cert_path.display()
            ),
            ErrorContext::new("interop_matrix_fixture_read"),
        )
    })?;

    let unsigned = format!(
        r#"<S12:Envelope xmlns:S12="http://www.w3.org/2003/05/soap-envelope"
    xmlns:eb="http://docs.oasis-open.org/ebxml-msg/ebms/v3.0/ns/core/200704/"
    xmlns:ebbpsig="http://docs.oasis-open.org/ebxml-bp/ebbp-signals-2.0"
    xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"
    xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
  <S12:Header>
    <eb:Messaging>
      <eb:SignalMessage wsu:Id="{signal_wsu_id}">
        <eb:MessageInfo>
          <eb:RefToMessageId>{ref_to_message_id}</eb:RefToMessageId>
        </eb:MessageInfo>
        <eb:Receipt>
                    <ebbpsig:NonRepudiationInformation>
                        <ebbpsig:MessagePartNRInformation>
                            <ebbpsig:MessagePartIdentifier>body</ebbpsig:MessagePartIdentifier>
                        </ebbpsig:MessagePartNRInformation>
                    </ebbpsig:NonRepudiationInformation>
        </eb:Receipt>
      </eb:SignalMessage>
    </eb:Messaging>
    <!-- signature-placeholder -->
  </S12:Header>
  <S12:Body/>
</S12:Envelope>"#,
        signal_wsu_id = SIGNAL_WSU_ID,
        ref_to_message_id = ref_to_message_id,
    );

    let reference_uri = format!("#{SIGNAL_WSU_ID}");
    let reference_uris = [reference_uri.as_str()];
    let signature_xml = generate_xmlsig_signature(
        &unsigned,
        &reference_uris,
        &signing_key_pem,
        &signing_cert_pem,
        WsSecOutboundKeyInfoProfile::X509DataAndRsaKeyValue,
    )
    .map_err(|err| {
        AsxError::new(
            ErrorCode::SecurityVerificationFailed,
            format!("failed to generate signed matrix receipt fixture: {err}"),
            ErrorContext::new("interop_matrix_fixture_read"),
        )
    })?;

    Ok(unsigned
        .replace("<!-- signature-placeholder -->", &signature_xml)
        .into_bytes())
}

#[cfg(any(feature = "as2", feature = "as4"))]
fn map_result<T>(result: Result<T>) -> ObservedOutcome {
    match result {
        Ok(_) => ObservedOutcome {
            outcome: FixtureExpectedOutcome::Pass,
            error_code: None,
        },
        Err(err) => ObservedOutcome {
            outcome: expected_from_error(err.code),
            error_code: Some(err.code),
        },
    }
}

#[cfg(any(feature = "as2", feature = "as4"))]
fn expected_from_error(code: ErrorCode) -> FixtureExpectedOutcome {
    match code {
        ErrorCode::InteropViolation => FixtureExpectedOutcome::InteropViolation,
        ErrorCode::PolicyViolation => FixtureExpectedOutcome::PolicyViolation,
        ErrorCode::ParseFailed => FixtureExpectedOutcome::ParseFailed,
        ErrorCode::SecurityVerificationFailed => FixtureExpectedOutcome::SecurityVerificationFailed,
        ErrorCode::DecryptionFailed => FixtureExpectedOutcome::DecryptionFailed,
        ErrorCode::InvalidInput
        | ErrorCode::TransportFailure
        | ErrorCode::ReliabilityFailure
        | ErrorCode::NotFound
        | ErrorCode::CapacityExhausted
        | ErrorCode::PayloadTooLarge => FixtureExpectedOutcome::ParseFailed,
    }
}

#[cfg(any(feature = "as2", feature = "as4"))]
fn interop_mode_from_fixture(mode: FixtureMode) -> InteropMode {
    match mode {
        FixtureMode::Strict => InteropMode::Strict,
        #[cfg_attr(not(feature = "interop-relaxed"), allow(deprecated))]
        FixtureMode::Relaxed => InteropMode::Relaxed,
    }
}

fn resolve_payload_path(base_dir: &Path, payload_path: &str) -> PathBuf {
    let payload = Path::new(payload_path);
    if payload.is_absolute() {
        payload.to_path_buf()
    } else {
        base_dir.join(payload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matrix_runs_against_fixture_catalog() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let catalog = root.join("tests/fixtures/interop/catalog.json");
        let quarantine = root.join("tests/fixtures/interop/quarantine.json");
        let catalog_data = load_fixture_catalog(&catalog).expect("catalog");

        let summary = run_interop_fixture_matrix(&catalog, &quarantine, 2).expect("matrix summary");
        assert_eq!(summary.total, catalog_data.fixtures.len());
        #[cfg(all(feature = "as2", feature = "as4"))]
        {
            assert_eq!(summary.passed, summary.total);
            assert!(!summary.has_blocking_failures());
        }
        #[cfg(all(not(feature = "as2"), feature = "as4"))]
        {
            assert!(summary.passed >= 3);

            // In AS4-only builds, AS2 fixtures are expected to fail because
            // the AS2 execution path is compiled out. Treat only AS4
            // non-quarantined failures as blocking for this test profile.
            let has_as4_blocking_failures = summary.records.iter().any(|record| {
                let blocking = !(record.pass || (record.flaky && record.quarantined));
                blocking && record.protocol == FixtureProtocol::As4Soap
            });
            assert!(!has_as4_blocking_failures);
        }
        assert_eq!(summary.failed, summary.total - summary.passed);
        assert_eq!(summary.flaky, 0);
    }

    #[test]
    fn flaky_required_check_blocks_when_not_quarantined() {
        let summary = MatrixSummary {
            catalog_path: "inline".to_string(),
            iterations: 3,
            total: 1,
            passed: 0,
            failed: 1,
            flaky: 1,
            quarantined: 0,
            records: vec![MatrixExecutionRecord {
                fixture_id: "f1".to_string(),
                protocol: FixtureProtocol::As4Soap,
                mode: FixtureMode::Strict,
                partner_id: "p1".to_string(),
                profile_name: "strict".to_string(),
                stage: "receive".to_string(),
                expected_outcome: FixtureExpectedOutcome::Pass,
                observed_outcome: FixtureExpectedOutcome::ParseFailed,
                observed_error_code: Some("ParseFailed".to_string()),
                pass: false,
                flaky: true,
                quarantined: false,
                quarantine_owner: None,
            }],
        };

        assert!(summary.has_blocking_failures());
    }
}
