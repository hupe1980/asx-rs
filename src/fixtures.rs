//! Fixture-catalog APIs for `testing` feature integration harnesses.
//!
//! This module defines the canonical JSON schema used by ASX interoperability
//! fixture repositories and provides validation/report helpers used by CI gates.
//!
//! Typical flow:
//! 1. `load_fixture_catalog(...)` to deserialize a catalog.
//! 2. `validate_fixture_catalog(...)` to enforce schema/content invariants.
//! 3. Feed validated fixture metadata into the matrix runner in `crate::matrix`.

use crate::core::{AsxError, ErrorCode, ErrorContext, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::{Path, PathBuf};

const CATALOG_SCHEMA_VERSION: &str = "1.0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FixtureProtocol {
    As2Mime,
    As4Soap,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FixtureMode {
    Strict,
    Relaxed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FixtureExpectedOutcome {
    Pass,
    InteropViolation,
    PolicyViolation,
    ParseFailed,
    SecurityVerificationFailed,
    DecryptionFailed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FixtureGrouping {
    pub partner_id: String,
    pub profile_name: String,
    pub protocol_stage: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InteropFixtureMetadata {
    pub fixture_id: String,
    pub protocol: FixtureProtocol,
    pub mode: FixtureMode,
    pub grouping: FixtureGrouping,
    pub payload_path: String,
    pub receipt_payload_path: Option<String>,
    pub generated_receipt_ref_to_message_id: Option<String>,
    pub expected_outcome: FixtureExpectedOutcome,
    pub reason_annotations: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InteropFixtureCatalog {
    pub schema_version: String,
    pub fixtures: Vec<InteropFixtureMetadata>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FixtureRepositoryReport {
    pub catalog_path: String,
    pub fixture_count: usize,
    pub grouping_count: usize,
    pub protocol_mode_coverage: Vec<String>,
}

impl FixtureRepositoryReport {
    pub fn to_json_pretty(&self) -> Result<String> {
        serde_json::to_string_pretty(self).map_err(|err| {
            AsxError::new(
                ErrorCode::ParseFailed,
                format!("failed to serialize fixture repository report: {err}"),
                ErrorContext::new("fixture_repo_report_serialize"),
            )
        })
    }
}

pub fn load_fixture_catalog(catalog_path: &Path) -> Result<InteropFixtureCatalog> {
    let raw = std::fs::read_to_string(catalog_path).map_err(|err| {
        AsxError::new(
            ErrorCode::ParseFailed,
            format!(
                "failed to read fixture catalog {}: {err}",
                catalog_path.display()
            ),
            ErrorContext::new("fixture_repo_catalog_read"),
        )
    })?;

    serde_json::from_str(&raw).map_err(|err| {
        AsxError::new(
            ErrorCode::ParseFailed,
            format!(
                "failed to parse fixture catalog {}: {err}",
                catalog_path.display()
            ),
            ErrorContext::new("fixture_repo_catalog_parse"),
        )
    })
}

/// Validate catalog schema, fixture metadata, and referenced payload files.
///
/// Returns a normalized report that can be emitted in CI logs/artifacts.
pub fn validate_fixture_catalog(catalog_path: &Path) -> Result<FixtureRepositoryReport> {
    let catalog = load_fixture_catalog(catalog_path)?;
    validate_fixture_catalog_data(catalog_path, &catalog)
}

fn validate_fixture_catalog_data(
    catalog_path: &Path,
    catalog: &InteropFixtureCatalog,
) -> Result<FixtureRepositoryReport> {
    if catalog.schema_version != CATALOG_SCHEMA_VERSION {
        return Err(AsxError::new(
            ErrorCode::InvalidInput,
            format!(
                "unsupported fixture catalog schema version {}; expected {}",
                catalog.schema_version, CATALOG_SCHEMA_VERSION
            ),
            ErrorContext::new("fixture_repo_catalog_validate"),
        ));
    }

    if catalog.fixtures.is_empty() {
        return Err(AsxError::new(
            ErrorCode::InvalidInput,
            "fixture catalog must include at least one fixture",
            ErrorContext::new("fixture_repo_catalog_validate"),
        ));
    }

    let base_dir = catalog_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .to_path_buf();

    let mut fixture_ids = HashSet::new();
    let mut groups = HashSet::new();
    let mut coverage = HashSet::new();

    for fixture in &catalog.fixtures {
        validate_fixture(&base_dir, fixture, &mut fixture_ids)?;
        groups.insert(format!(
            "{}|{}|{}",
            fixture.grouping.partner_id,
            fixture.grouping.profile_name,
            fixture.grouping.protocol_stage
        ));
        coverage.insert((fixture.protocol, fixture.mode));
    }

    let required_coverage = [
        (FixtureProtocol::As2Mime, FixtureMode::Strict),
        (FixtureProtocol::As2Mime, FixtureMode::Relaxed),
        (FixtureProtocol::As4Soap, FixtureMode::Strict),
        (FixtureProtocol::As4Soap, FixtureMode::Relaxed),
    ];

    for required in required_coverage {
        if !coverage.contains(&required) {
            return Err(AsxError::new(
                ErrorCode::InvalidInput,
                format!(
                    "fixture catalog missing required protocol/mode coverage: {:?}/{:?}",
                    required.0, required.1
                ),
                ErrorContext::new("fixture_repo_catalog_validate"),
            ));
        }
    }

    let mut protocol_mode_coverage: Vec<String> = coverage
        .iter()
        .map(|(protocol, mode)| format!("{:?}/{:?}", protocol, mode))
        .collect();
    protocol_mode_coverage.sort();

    Ok(FixtureRepositoryReport {
        catalog_path: catalog_path.display().to_string(),
        fixture_count: catalog.fixtures.len(),
        grouping_count: groups.len(),
        protocol_mode_coverage,
    })
}

fn validate_fixture(
    base_dir: &Path,
    fixture: &InteropFixtureMetadata,
    fixture_ids: &mut HashSet<String>,
) -> Result<()> {
    if fixture.fixture_id.trim().is_empty() {
        return Err(AsxError::new(
            ErrorCode::InvalidInput,
            "fixture_id must not be empty",
            ErrorContext::new("fixture_repo_fixture_validate"),
        ));
    }
    if !fixture_ids.insert(fixture.fixture_id.clone()) {
        return Err(AsxError::new(
            ErrorCode::InvalidInput,
            format!("duplicate fixture_id {}", fixture.fixture_id),
            ErrorContext::new("fixture_repo_fixture_validate"),
        ));
    }

    if fixture.grouping.partner_id.trim().is_empty()
        || fixture.grouping.profile_name.trim().is_empty()
        || fixture.grouping.protocol_stage.trim().is_empty()
    {
        return Err(AsxError::new(
            ErrorCode::InvalidInput,
            format!(
                "fixture {} has incomplete grouping metadata",
                fixture.fixture_id
            ),
            ErrorContext::new("fixture_repo_fixture_validate"),
        ));
    }

    if fixture.reason_annotations.is_empty()
        || fixture
            .reason_annotations
            .iter()
            .any(|reason| reason.trim().is_empty())
    {
        return Err(AsxError::new(
            ErrorCode::InvalidInput,
            format!(
                "fixture {} must include non-empty reason annotations",
                fixture.fixture_id
            ),
            ErrorContext::new("fixture_repo_fixture_validate"),
        ));
    }

    let payload = resolve_payload_path(base_dir, &fixture.payload_path);
    if !payload.exists() {
        return Err(AsxError::new(
            ErrorCode::InvalidInput,
            format!(
                "fixture {} payload does not exist: {}",
                fixture.fixture_id,
                payload.display()
            ),
            ErrorContext::new("fixture_repo_fixture_validate"),
        ));
    }
    if !payload.is_file() {
        return Err(AsxError::new(
            ErrorCode::InvalidInput,
            format!(
                "fixture {} payload path is not a file: {}",
                fixture.fixture_id,
                payload.display()
            ),
            ErrorContext::new("fixture_repo_fixture_validate"),
        ));
    }

    let metadata = std::fs::metadata(&payload).map_err(|err| {
        AsxError::new(
            ErrorCode::ParseFailed,
            format!(
                "failed to inspect payload metadata for fixture {} at {}: {err}",
                fixture.fixture_id,
                payload.display()
            ),
            ErrorContext::new("fixture_repo_fixture_validate"),
        )
    })?;
    if metadata.len() == 0 {
        return Err(AsxError::new(
            ErrorCode::InvalidInput,
            format!(
                "fixture {} payload is empty: {}",
                fixture.fixture_id,
                payload.display()
            ),
            ErrorContext::new("fixture_repo_fixture_validate"),
        ));
    }

    match fixture.protocol {
        FixtureProtocol::As2Mime if !fixture.payload_path.ends_with(".mime") => {
            return Err(AsxError::new(
                ErrorCode::InvalidInput,
                format!(
                    "fixture {} is As2Mime but payload is not .mime: {}",
                    fixture.fixture_id, fixture.payload_path
                ),
                ErrorContext::new("fixture_repo_fixture_validate"),
            ));
        }
        FixtureProtocol::As4Soap
            if !(fixture.payload_path.ends_with(".xml")
                || fixture.payload_path.ends_with(".mime")) =>
        {
            return Err(AsxError::new(
                ErrorCode::InvalidInput,
                format!(
                    "fixture {} is As4Soap but payload is not .xml/.mime: {}",
                    fixture.fixture_id, fixture.payload_path
                ),
                ErrorContext::new("fixture_repo_fixture_validate"),
            ));
        }
        _ => {}
    }

    if fixture.protocol == FixtureProtocol::As4Soap
        && fixture.grouping.protocol_stage == "as4_receive_receipt"
        && !fixture.payload_path.ends_with(".mime")
    {
        return Err(AsxError::new(
            ErrorCode::InvalidInput,
            format!(
                "fixture {} stage as4_receive_receipt requires multipart payload (.mime): {}",
                fixture.fixture_id, fixture.payload_path
            ),
            ErrorContext::new("fixture_repo_fixture_validate"),
        ));
    }

    if fixture.receipt_payload_path.is_some()
        && fixture.generated_receipt_ref_to_message_id.is_some()
    {
        return Err(AsxError::new(
            ErrorCode::InvalidInput,
            format!(
                "fixture {} cannot set both receipt_payload_path and generated_receipt_ref_to_message_id",
                fixture.fixture_id
            ),
            ErrorContext::new("fixture_repo_fixture_validate"),
        ));
    }

    if let Some(receipt_path) = &fixture.receipt_payload_path {
        if fixture.protocol != FixtureProtocol::As4Soap {
            return Err(AsxError::new(
                ErrorCode::InvalidInput,
                format!(
                    "fixture {} sets receipt_payload_path but protocol is not As4Soap",
                    fixture.fixture_id
                ),
                ErrorContext::new("fixture_repo_fixture_validate"),
            ));
        }
        if !receipt_path.ends_with(".xml") {
            return Err(AsxError::new(
                ErrorCode::InvalidInput,
                format!(
                    "fixture {} receipt payload is not .xml: {}",
                    fixture.fixture_id, receipt_path
                ),
                ErrorContext::new("fixture_repo_fixture_validate"),
            ));
        }

        let receipt = resolve_payload_path(base_dir, receipt_path);
        if !receipt.exists() {
            return Err(AsxError::new(
                ErrorCode::InvalidInput,
                format!(
                    "fixture {} receipt payload does not exist: {}",
                    fixture.fixture_id,
                    receipt.display()
                ),
                ErrorContext::new("fixture_repo_fixture_validate"),
            ));
        }
        if !receipt.is_file() {
            return Err(AsxError::new(
                ErrorCode::InvalidInput,
                format!(
                    "fixture {} receipt payload path is not a file: {}",
                    fixture.fixture_id,
                    receipt.display()
                ),
                ErrorContext::new("fixture_repo_fixture_validate"),
            ));
        }

        let receipt_meta = std::fs::metadata(&receipt).map_err(|err| {
            AsxError::new(
                ErrorCode::ParseFailed,
                format!(
                    "failed to inspect receipt payload metadata for fixture {} at {}: {err}",
                    fixture.fixture_id,
                    receipt.display()
                ),
                ErrorContext::new("fixture_repo_fixture_validate"),
            )
        })?;
        if receipt_meta.len() == 0 {
            return Err(AsxError::new(
                ErrorCode::InvalidInput,
                format!(
                    "fixture {} receipt payload is empty: {}",
                    fixture.fixture_id,
                    receipt.display()
                ),
                ErrorContext::new("fixture_repo_fixture_validate"),
            ));
        }
    }

    if let Some(ref_to_message_id) = &fixture.generated_receipt_ref_to_message_id {
        if fixture.protocol != FixtureProtocol::As4Soap {
            return Err(AsxError::new(
                ErrorCode::InvalidInput,
                format!(
                    "fixture {} sets generated_receipt_ref_to_message_id but protocol is not As4Soap",
                    fixture.fixture_id
                ),
                ErrorContext::new("fixture_repo_fixture_validate"),
            ));
        }
        if ref_to_message_id.trim().is_empty() {
            return Err(AsxError::new(
                ErrorCode::InvalidInput,
                format!(
                    "fixture {} generated_receipt_ref_to_message_id must not be empty",
                    fixture.fixture_id
                ),
                ErrorContext::new("fixture_repo_fixture_validate"),
            ));
        }
    }

    Ok(())
}

fn resolve_payload_path(base_dir: &Path, payload_path: &str) -> PathBuf {
    let payload = Path::new(payload_path);
    if payload.is_absolute() {
        payload.to_path_buf()
    } else {
        base_dir.join(payload)
    }
}

// ── Test key-pair generation ─────────────────────────────────────────────────

/// EC curve selector for [`generate_self_signed_ec_keypair`].
///
/// Covers the curves used by the major AS4 profiles:
/// - PEPPOL/CEF eDelivery: `P256` (NIST P-256)
/// - BDEW AS4-Profil (BSI TR-03116-3): `BrainpoolP256r1`
///
/// All variants are tested with OpenSSL EC key generation.
#[cfg(feature = "crypto")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EcCurve {
    /// NIST P-256 (`prime256v1`), used by PEPPOL and general AS4 profiles.
    P256,
    /// NIST P-384 (`secp384r1`).
    P384,
    /// NIST P-521 (`secp521r1`).
    P521,
    /// BSI BrainpoolP256r1, mandated by BDEW AS4-Profil §2.2.6.2.1/2.2.6.2.2.
    BrainpoolP256r1,
    /// BSI BrainpoolP384r1.
    BrainpoolP384r1,
}

#[cfg(feature = "crypto")]
impl EcCurve {
    fn to_nid(self) -> openssl::nid::Nid {
        use openssl::nid::Nid;
        match self {
            Self::P256 => Nid::X9_62_PRIME256V1,
            Self::P384 => Nid::SECP384R1,
            Self::P521 => Nid::SECP521R1,
            // BrainpoolP256r1: NID 927 in OpenSSL 1.1+
            Self::BrainpoolP256r1 => Nid::from_raw(927),
            Self::BrainpoolP384r1 => Nid::from_raw(931),
        }
    }
}

/// Generate a minimal self-signed **EC** X.509 certificate and private key.
///
/// Returns `(cert_pem, key_pem)`.  Both are PEM-encoded and suitable for
/// passing to [`As4SendPolicyBuilder`][crate::as4::As4SendPolicyBuilder]
/// (`signing_cert_pem` / `signing_key_pem` / `recipient_cert_pem`) in tests.
///
/// The certificate has:
/// - Subject/Issuer: `CN=subject_cn`
/// - Validity: 10 years from now
/// - `KeyUsage`: `digitalSignature` + `keyAgreement` (covers both signing and
///   ECDH-ES encryption without issuing separate certs for tests)
/// - `BasicConstraints`: `CA:FALSE`
///
/// # Panics
///
/// Panics if key generation or certificate building fails (this should never
/// happen for well-known NIST/Brainpool curves).
///
/// # Example
///
/// ```rust,no_run
/// # #[cfg(all(feature = "testing", feature = "as4", feature = "crypto"))]
/// # {
/// use asx_rs::fixtures::{EcCurve, generate_self_signed_ec_keypair};
/// use asx_rs::as4::As4SendPolicyBuilder;
///
/// let (cert_pem, key_pem) = generate_self_signed_ec_keypair("test-ap", EcCurve::BrainpoolP256r1);
/// let (policy, creds) = As4SendPolicyBuilder::new()
///     .signing_cert_pem(cert_pem)
///     .signing_key_pem(key_pem)
///     .action("urn:test:action")
///     .service("urn:test:svc", "")
///     .build()
///     .expect("policy");
/// # }
/// ```
#[cfg(feature = "crypto")]
pub fn generate_self_signed_ec_keypair(subject_cn: &str, curve: EcCurve) -> (Vec<u8>, Vec<u8>) {
    use openssl::asn1::Asn1Time;
    use openssl::bn::BigNum;
    use openssl::ec::{EcGroup, EcKey};
    use openssl::hash::MessageDigest;
    use openssl::pkey::PKey;
    use openssl::x509::{X509, X509NameBuilder, extension::BasicConstraints, extension::KeyUsage};

    let group = EcGroup::from_curve_name(curve.to_nid())
        .unwrap_or_else(|e| panic!("EcGroup::from_curve_name failed: {e}"));
    let ec_key = EcKey::generate(&group).unwrap_or_else(|e| panic!("EcKey::generate failed: {e}"));
    let pkey =
        PKey::from_ec_key(ec_key).unwrap_or_else(|e| panic!("PKey::from_ec_key failed: {e}"));

    let mut name = X509NameBuilder::new().expect("X509NameBuilder");
    name.append_entry_by_text("CN", subject_cn)
        .expect("CN entry");
    let name = name.build();

    let mut serial = BigNum::new().expect("BigNum");
    serial
        .pseudo_rand(64, openssl::bn::MsbOption::MAYBE_ZERO, false)
        .expect("serial rand");
    let serial = serial.to_asn1_integer().expect("to_asn1_integer");

    let mut builder = X509::builder().expect("X509::builder");
    builder.set_version(2).expect("set_version");
    builder.set_serial_number(&serial).expect("set_serial");
    builder.set_subject_name(&name).expect("set_subject");
    builder.set_issuer_name(&name).expect("set_issuer");
    builder
        .set_not_before(&Asn1Time::days_from_now(0).expect("not_before"))
        .expect("set_not_before");
    builder
        .set_not_after(&Asn1Time::days_from_now(3650).expect("not_after"))
        .expect("set_not_after");
    builder.set_pubkey(&pkey).expect("set_pubkey");

    // KeyUsage: digitalSignature (for signing) + keyAgreement (for ECDH-ES key agreement).
    // Marked critical per RFC 5280 §4.2.1.3 and BSI TR-03116-3 requirement.
    // NOT keyEncipherment — that is for RSA-OAEP; ECDH-ES uses keyAgreement.
    let ku = KeyUsage::new()
        .critical()
        .digital_signature()
        .key_agreement()
        .build()
        .expect("KeyUsage");
    builder.append_extension(ku).expect("append KeyUsage");

    let bc = BasicConstraints::new()
        .critical()
        .build()
        .expect("BasicConstraints");
    builder
        .append_extension(bc)
        .expect("append BasicConstraints");

    builder.sign(&pkey, MessageDigest::sha256()).expect("sign");

    let cert = builder.build();
    let cert_pem = cert.to_pem().expect("cert to_pem");
    let key_pem = pkey.private_key_to_pem_pkcs8().expect("key to_pem");
    (cert_pem, key_pem)
}

/// Generate a minimal self-signed **RSA** X.509 certificate and private key.
///
/// Returns `(cert_pem, key_pem)`.  Both are PEM-encoded and suitable for
/// PEPPOL/CEF eDelivery AS4 testing where RSA-SHA256 signing and RSA-OAEP
/// encryption are used.
///
/// The certificate has:
/// - Subject/Issuer: `CN=subject_cn`
/// - Validity: 10 years from now
/// - `KeyUsage`: `digitalSignature` + `keyEncipherment`
/// - `BasicConstraints`: `CA:FALSE`
///
/// Use `bits = 2048` for normal testing; `bits = 4096` for stronger keys.
///
/// # Panics
///
/// Panics if key generation fails.
#[cfg(feature = "crypto")]
pub fn generate_self_signed_rsa_keypair(subject_cn: &str, bits: u32) -> (Vec<u8>, Vec<u8>) {
    use openssl::asn1::Asn1Time;
    use openssl::bn::BigNum;
    use openssl::hash::MessageDigest;
    use openssl::pkey::PKey;
    use openssl::rsa::Rsa;
    use openssl::x509::{X509, X509NameBuilder, extension::BasicConstraints, extension::KeyUsage};

    let rsa = Rsa::generate(bits).unwrap_or_else(|e| panic!("Rsa::generate({bits}) failed: {e}"));
    let pkey = PKey::from_rsa(rsa).unwrap_or_else(|e| panic!("PKey::from_rsa failed: {e}"));

    let mut name = X509NameBuilder::new().expect("X509NameBuilder");
    name.append_entry_by_text("CN", subject_cn)
        .expect("CN entry");
    let name = name.build();

    let mut serial = BigNum::new().expect("BigNum");
    serial
        .pseudo_rand(64, openssl::bn::MsbOption::MAYBE_ZERO, false)
        .expect("serial rand");
    let serial = serial.to_asn1_integer().expect("to_asn1_integer");

    let mut builder = X509::builder().expect("X509::builder");
    builder.set_version(2).expect("set_version");
    builder.set_serial_number(&serial).expect("set_serial");
    builder.set_subject_name(&name).expect("set_subject");
    builder.set_issuer_name(&name).expect("set_issuer");
    builder
        .set_not_before(&Asn1Time::days_from_now(0).expect("not_before"))
        .expect("set_not_before");
    builder
        .set_not_after(&Asn1Time::days_from_now(3650).expect("not_after"))
        .expect("set_not_after");
    builder.set_pubkey(&pkey).expect("set_pubkey");

    // KeyUsage: digitalSignature (for signing) + keyEncipherment (for RSA-OAEP key wrap).
    // Marked critical per RFC 5280 §4.2.1.3.
    // NOT keyAgreement — that is for ECDH-ES; RSA-OAEP uses keyEncipherment.
    let ku = KeyUsage::new()
        .critical()
        .digital_signature()
        .key_encipherment()
        .build()
        .expect("KeyUsage");
    builder.append_extension(ku).expect("append KeyUsage");

    let bc = BasicConstraints::new()
        .critical()
        .build()
        .expect("BasicConstraints");
    builder
        .append_extension(bc)
        .expect("append BasicConstraints");

    builder.sign(&pkey, MessageDigest::sha256()).expect("sign");

    let cert = builder.build();
    let cert_pem = cert.to_pem().expect("cert to_pem");
    let key_pem = pkey.private_key_to_pem_pkcs8().expect("key to_pem");
    (cert_pem, key_pem)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn validates_real_catalog() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let catalog = root.join("tests/fixtures/interop/catalog.json");
        let report = validate_fixture_catalog(&catalog).expect("catalog valid");

        assert!(report.fixture_count >= 4);
        assert!(report.grouping_count >= 4);
        assert!(
            report
                .protocol_mode_coverage
                .iter()
                .any(|v| v == "As2Mime/Strict")
        );
        assert!(
            report
                .protocol_mode_coverage
                .iter()
                .any(|v| v == "As4Soap/Relaxed")
        );
    }

    #[test]
    fn malformed_catalog_is_rejected() {
        let temp_root = std::env::temp_dir().join(format!(
            "asx_fixture_repo_test_{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        fs::create_dir_all(temp_root.join("interop")).expect("create dirs");
        fs::write(
            temp_root.join("interop/sample.mime"),
            "MIME-Version: 1.0\r\n\r\nbody",
        )
        .expect("payload");
        fs::write(
            temp_root.join("interop/catalog.json"),
            r#"{
  "schema_version": "1.0",
  "fixtures": [
    {
      "fixture_id": "bad-empty-reasons",
      "protocol": "As2Mime",
      "mode": "Strict",
      "grouping": {
        "partner_id": "partner-a",
        "profile_name": "strict",
        "protocol_stage": "as2_receive_mdn_boundary"
      },
      "payload_path": "sample.mime",
            "receipt_payload_path": null,
      "expected_outcome": "InteropViolation",
      "reason_annotations": []
    }
  ]
}"#,
        )
        .expect("catalog");

        let err = validate_fixture_catalog(&temp_root.join("interop/catalog.json"))
            .expect_err("must fail malformed metadata");
        assert_eq!(err.code, ErrorCode::InvalidInput);
        assert!(err.message.contains("non-empty reason annotations"));

        let _ = fs::remove_dir_all(&temp_root);
    }

    #[test]
    fn receipt_stage_requires_multipart_payload() {
        let temp_root = std::env::temp_dir().join(format!(
            "asx_fixture_repo_test_{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        fs::create_dir_all(temp_root.join("interop/partner/strict/as4_receive_receipt"))
            .expect("create dirs");
        fs::write(
            temp_root.join("interop/partner/strict/as4_receive_receipt/push-user-message.xml"),
            "<Envelope><Header></Header><Body></Body></Envelope>",
        )
        .expect("payload");
        fs::write(
            temp_root.join("interop/catalog.json"),
            r#"{
    "schema_version": "1.0",
    "fixtures": [
        {
            "fixture_id": "bad-as4-receipt-non-multipart",
            "protocol": "As4Soap",
            "mode": "Strict",
            "grouping": {
                "partner_id": "partner",
                "profile_name": "strict",
                "protocol_stage": "as4_receive_receipt"
            },
            "payload_path": "partner/strict/as4_receive_receipt/push-user-message.xml",
            "receipt_payload_path": null,
            "generated_receipt_ref_to_message_id": "msg-1",
            "expected_outcome": "InteropViolation",
            "reason_annotations": ["test"]
        },
        {
            "fixture_id": "coverage-as2-strict",
            "protocol": "As2Mime",
            "mode": "Strict",
            "grouping": {
                "partner_id": "partner",
                "profile_name": "strict",
                "protocol_stage": "as2_receive_mdn_boundary"
            },
            "payload_path": "sample.mime",
            "receipt_payload_path": null,
            "generated_receipt_ref_to_message_id": null,
            "expected_outcome": "Pass",
            "reason_annotations": ["coverage"]
        },
        {
            "fixture_id": "coverage-as2-relaxed",
            "protocol": "As2Mime",
            "mode": "Relaxed",
            "grouping": {
                "partner_id": "partner",
                "profile_name": "relaxed",
                "protocol_stage": "as2_receive_mdn_boundary"
            },
            "payload_path": "sample.mime",
            "receipt_payload_path": null,
            "generated_receipt_ref_to_message_id": null,
            "expected_outcome": "Pass",
            "reason_annotations": ["coverage"]
        },
        {
            "fixture_id": "coverage-as4-relaxed",
            "protocol": "As4Soap",
            "mode": "Relaxed",
            "grouping": {
                "partner_id": "partner",
                "profile_name": "relaxed",
                "protocol_stage": "as4_parse_user_message"
            },
            "payload_path": "sample.xml",
            "receipt_payload_path": null,
            "generated_receipt_ref_to_message_id": null,
            "expected_outcome": "Pass",
            "reason_annotations": ["coverage"]
        }
    ]
}"#,
        )
        .expect("catalog");
        fs::write(
            temp_root.join("interop/sample.mime"),
            "MIME-Version: 1.0\r\n\r\nbody",
        )
        .expect("sample mime");
        fs::write(temp_root.join("interop/sample.xml"), "<Envelope/>").expect("sample xml");

        let err = validate_fixture_catalog(&temp_root.join("interop/catalog.json"))
            .expect_err("must fail non-multipart receipt-stage payload");
        assert_eq!(err.code, ErrorCode::InvalidInput);
        assert!(
            err.message
                .contains("stage as4_receive_receipt requires multipart payload")
        );

        let _ = fs::remove_dir_all(&temp_root);
    }
}
