//! BDXL — locating the SMP that holds a participant's metadata.
//!
//! An SMP lookup needs an SMP to ask. BDXL (OASIS *Business Document Metadata
//! Service Location*, as profiled by CEF eDelivery BDXL 1.6 and Peppol) answers
//! that from DNS: the participant identifier is hashed into a host name, and a
//! U-NAPTR record at that name carries the SMP's base URL.
//!
//! ```text
//! name = strip-trailing(base32(sha256(lowercase(ID-VALUE))), "=")
//!        + "." + ID-SCHEME + "." + DNS-ZONE
//!
//! name. IN NAPTR 100 10 "U" "Meta:SMP" "!.*!https://smp.example.org!" .
//! ```
//!
//! Everything in this module except the resolver itself is pure computation
//! over the identifier and the record, so the parts that decide *where a
//! message goes* are unit-testable against the specification's own vectors
//! rather than against a live network.
//!
//! # The legacy CNAME scheme
//!
//! [`SmlDiscovery::LegacyCname`] builds `B-<md5-hex>.<scheme>.<zone>`, a CNAME
//! to the SMP host that a client can `GET` without a DNS query of its own. The
//! public Peppol zones do not publish these records; it is for closed networks
//! that still do.
//!
//! # Why the resolver is a trait
//!
//! A NAPTR query is not a plain host lookup, so `getaddrinfo` cannot serve it
//! and some DNS client has to. Which one is a deployment decision: whether to
//! validate DNSSEC (the Peppol SML zones are signed), which resolver to trust,
//! how a service mesh or split-horizon zone is reached. [`BdxlResolver`] is
//! that seam — enable the `dns` feature for [`HickoryBdxlResolver`], or
//! implement it over whatever already resolves names in your process.

use std::collections::HashMap;
#[cfg(feature = "dns")]
use std::sync::Arc;

use crate::core::{AsxError, ErrorCode, ErrorContext, Result};
use crate::storage::BoxFuture;

/// How the SMP base URL is located for a participant.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum SmlDiscovery {
    /// BDXL U-NAPTR over SHA-256/base32 — what Peppol and CEF eDelivery
    /// publish today. Requires a [`BdxlResolver`].
    Naptr,

    /// The withdrawn Peppol CNAME scheme: `https://B-<md5-hex>.<scheme>.<zone>/`
    /// used directly as the SMP base URL, with no NAPTR step.
    ///
    /// Retained for closed networks that still publish these records. The
    /// public Peppol zones stopped answering them in the 2025 migration.
    LegacyCname,

    /// A fixed SMP base URL, skipping DNS discovery entirely.
    ///
    /// For a bilateral agreement, a test SMP, or a deployment whose SMP is
    /// named by configuration rather than found by lookup.
    Static {
        /// Base URL of the SMP, e.g. `https://smp.example.org`.
        smp_base_url: String,
    },
}

/// RFC 4648 §6 base32 alphabet (uppercase, no padding emitted).
const BASE32_ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// Base32-encode `input` with the RFC 4648 standard alphabet, omitting the
/// trailing `=` padding — the encoding BDXL specifies for the DNS label.
fn base32_nopad(input: &[u8]) -> String {
    let mut out = String::with_capacity(input.len().div_ceil(5) * 8);
    for chunk in input.chunks(5) {
        // Left-align the chunk in a 40-bit buffer, then peel off 5 bits at a
        // time; a partial chunk yields fewer characters and no padding.
        let mut buffer: u64 = 0;
        for (i, &byte) in chunk.iter().enumerate() {
            buffer |= u64::from(byte) << (32 - 8 * i);
        }
        let chars = (chunk.len() * 8).div_ceil(5);
        for i in 0..chars {
            let index = ((buffer >> (35 - 5 * i)) & 0x1f) as usize;
            out.push(BASE32_ALPHABET[index] as char);
        }
    }
    out
}

/// Lowercase hex-encode `input`.
fn hex_lower(input: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(input.len() * 2);
    for &b in input {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

/// The BDXL DNS name for a participant.
///
/// `strip-trailing(base32(sha256(lowercase(value))), "=") + "." + scheme + "." + zone`
/// — CEF eDelivery BDXL 1.6 §4, Peppol *Policy for use of Identifiers* §5.
///
/// Only the identifier **value** is hashed. Folding the scheme into the hash
/// input is a plausible reading that produces a name nothing publishes.
///
/// ```
/// # use asx_rs::smp::bdxl_dns_name;
/// assert_eq!(
///     bdxl_dns_name("iso6523-actorid-upis", "0088:5790002590993", "participant.sml.prod.tech.peppol.org"),
///     "2M2UFGZNGSS25JOOMOV2S4VGG7PW64KIVYNONDSVZSRT4EAZVCLQ\
///      .iso6523-actorid-upis.participant.sml.prod.tech.peppol.org"
/// );
/// ```
pub fn bdxl_dns_name(scheme: &str, participant_id: &str, sml_zone: &str) -> String {
    use sha2::Digest;
    let digest = sha2::Sha256::digest(participant_id.to_lowercase().as_bytes());
    format!(
        "{}.{}.{}",
        base32_nopad(&digest),
        scheme,
        sml_zone.trim_end_matches('.')
    )
}

/// The legacy Peppol CNAME host for a participant:
/// `B-<md5-hex(lowercase(value))>.<scheme>.<zone>`.
///
/// As with [`bdxl_dns_name`], only the identifier **value** is hashed.
///
/// ```
/// # use asx_rs::smp::legacy_cname_host;
/// // Peppol "Policy for use of Identifiers" worked example.
/// assert_eq!(
///     legacy_cname_host("iso6523-actorid-upis", "0088:123abc", "edelivery.tech.ec.europa.eu"),
///     "B-f5e78500450d37de5aabe6648ac3bb70.iso6523-actorid-upis.edelivery.tech.ec.europa.eu"
/// );
/// ```
pub fn legacy_cname_host(scheme: &str, participant_id: &str, sml_zone: &str) -> String {
    // MD5 here is a DNS naming convention, not a security control: the name it
    // produces is public and its collision resistance is irrelevant.
    let digest = openssl::hash::hash(
        openssl::hash::MessageDigest::md5(),
        participant_id.to_lowercase().as_bytes(),
    )
    .expect("MD5 is available in every OpenSSL build this crate supports");
    format!(
        "B-{}.{}.{}",
        hex_lower(&digest),
        scheme,
        sml_zone.trim_end_matches('.')
    )
}

/// One DNS NAPTR record (RFC 3403 §4.1), as a resolver hands it back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NaptrRecord {
    /// Lower values are tried first.
    pub order: u16,
    /// Tie-breaker within one `order`; lower is preferred.
    pub preference: u16,
    /// `U` marks a terminal rule whose `regexp` yields a URI.
    pub flags: String,
    /// Service field — `Meta:SMP` for an SMP location record.
    pub service: String,
    /// Substitution expression, `!<ere>!<uri>!` for a U-NAPTR.
    pub regexp: String,
    /// Replacement domain name; `.` (root) for a terminal U rule.
    pub replacement: String,
}

/// BDXL service field naming an SMP, compared case-insensitively (RFC 4848 §4.5).
const BDXL_SERVICE_SMP: &str = "meta:smp";

/// Choose the SMP base URL from a NAPTR record set.
///
/// Records that are not terminal `U` rules for `Meta:SMP` are ignored; the rest
/// are ordered by `(order, preference)` and the first whose substitution yields
/// a usable `https` URI wins (RFC 3403 §4.1, RFC 4848 §2.2).
///
/// # Errors
///
/// [`ErrorCode::NotFound`] when no record qualifies — including the case where
/// every candidate carried an unusable URI, whose reason is reported.
pub fn select_smp_base_url(records: &[NaptrRecord]) -> Result<String> {
    let mut candidates: Vec<&NaptrRecord> = records
        .iter()
        .filter(|r| {
            r.flags.eq_ignore_ascii_case("U") && r.service.eq_ignore_ascii_case(BDXL_SERVICE_SMP)
        })
        .collect();
    candidates.sort_by_key(|r| (r.order, r.preference));

    let mut rejections: Vec<String> = Vec::new();
    for record in candidates {
        match unaptr_uri(&record.regexp) {
            Ok(uri) => return Ok(uri),
            Err(reason) => rejections.push(format!("{:?}: {reason}", record.regexp)),
        }
    }

    let detail = if rejections.is_empty() {
        format!(
            "no NAPTR record with flags=\"U\" and service=\"Meta:SMP\" among {} record(s)",
            records.len()
        )
    } else {
        format!(
            "every Meta:SMP record was unusable — {}",
            rejections.join("; ")
        )
    };
    Err(AsxError::new(
        ErrorCode::NotFound,
        format!("BDXL discovery found no SMP for this participant: {detail}"),
        ErrorContext::new("bdxl_select_smp"),
    ))
}

/// Extract the URI from a U-NAPTR substitution expression `!<ere>!<uri>!`.
///
/// RFC 4848 §2.2 forbids backreferences and fixes the ERE at "match
/// everything", so the replacement is used literally rather than as a regex
/// substitution — which is also why no regex engine is needed here.
fn unaptr_uri(regexp: &str) -> std::result::Result<String, String> {
    let mut chars = regexp.chars();
    let delimiter = chars.next().ok_or("empty regexp field")?;
    if delimiter.is_alphanumeric() || delimiter == '\\' {
        return Err(format!("invalid delimiter {delimiter:?}"));
    }

    // Split on unescaped delimiters (RFC 3402 §3.2 allows `\<delim>`).
    // `\1`..`\9` is a backreference, which RFC 4848 §2.2 forbids: the URI must
    // be literal, or the record could interpolate part of the queried name
    // into the address a message is sent to. It has to be caught here, while
    // the escape is still visible — after unescaping, `\1` and `1` are the
    // same character.
    let mut fields: Vec<String> = vec![String::new()];
    let mut escaped = false;
    let mut saw_backreference = false;
    for ch in chars {
        if escaped {
            if ch.is_ascii_digit() {
                saw_backreference = true;
            }
            fields.last_mut().expect("one field always exists").push(ch);
            escaped = false;
        } else if ch == '\\' {
            escaped = true;
        } else if ch == delimiter {
            fields.push(String::new());
        } else {
            fields.last_mut().expect("one field always exists").push(ch);
        }
    }
    if escaped {
        return Err("regexp ends with a dangling escape".to_string());
    }
    if saw_backreference {
        return Err("backreferences are not permitted in a U-NAPTR replacement".to_string());
    }
    if fields.len() != 3 || !fields[2].is_empty() {
        return Err(format!(
            "expected the U-NAPTR form !<ere>!<uri>!, got {} field(s)",
            fields.len()
        ));
    }

    let uri = fields.swap_remove(1);
    // BDXL 1.6 §4: an SMP reachable over TLS MUST be published as `https`.
    // Accepting `http` here would let a DNS answer downgrade every subsequent
    // metadata fetch, and the metadata decides where a message goes.
    if !uri.starts_with("https://") {
        return Err(format!("{uri:?} is not an https URI"));
    }
    Ok(uri.trim_end_matches('/').to_string())
}

/// Resolves BDXL U-NAPTR records.
///
/// Implement over whatever DNS client the deployment already trusts, or enable
/// the `dns` feature for [`HickoryBdxlResolver`]. The name passed in is
/// already fully qualified; an implementation should not append a search
/// domain to it.
pub trait BdxlResolver: Send + Sync + std::fmt::Debug {
    /// Return every NAPTR record published at `name`.
    ///
    /// An empty vector means "no such records", which the caller reports as a
    /// participant that is not registered. Transport and DNSSEC failures
    /// should be errors, so that "not registered" is never confused with
    /// "could not ask".
    fn lookup_naptr<'a>(&'a self, name: &'a str) -> BoxFuture<'a, Result<Vec<NaptrRecord>>>;
}

/// A [`BdxlResolver`] backed by a fixed table, for tests and closed networks.
///
/// Nothing here touches the network, so a discovery path can be exercised
/// end-to-end — including the ordering and URI rules — without DNS.
#[derive(Debug, Clone, Default)]
pub struct StaticBdxlResolver {
    records: HashMap<String, Vec<NaptrRecord>>,
}

impl StaticBdxlResolver {
    /// An empty table: every lookup reports "not registered".
    pub fn new() -> Self {
        Self::default()
    }

    /// Publish `records` at `name`.
    #[must_use]
    pub fn with_records(mut self, name: impl Into<String>, records: Vec<NaptrRecord>) -> Self {
        self.records.insert(name.into(), records);
        self
    }

    /// Publish a single terminal `Meta:SMP` record pointing at `smp_base_url`.
    #[must_use]
    pub fn with_smp(mut self, name: impl Into<String>, smp_base_url: &str) -> Self {
        self.records.insert(
            name.into(),
            vec![NaptrRecord {
                order: 100,
                preference: 10,
                flags: "U".to_string(),
                service: "Meta:SMP".to_string(),
                regexp: format!("!.*!{smp_base_url}!"),
                replacement: ".".to_string(),
            }],
        );
        self
    }
}

impl BdxlResolver for StaticBdxlResolver {
    fn lookup_naptr<'a>(&'a self, name: &'a str) -> BoxFuture<'a, Result<Vec<NaptrRecord>>> {
        let records = self.records.get(name).cloned().unwrap_or_default();
        Box::pin(async move { Ok(records) })
    }
}

/// A [`BdxlResolver`] over [`hickory_resolver`], using the system resolver
/// configuration (`/etc/resolv.conf`, or the Windows registry).
///
/// Available under the `dns` feature. A deployment that needs DNSSEC
/// validation, a specific resolver, or a mesh-aware client should implement
/// [`BdxlResolver`] itself instead — that choice is the reason this is a trait.
#[cfg(feature = "dns")]
#[derive(Debug, Clone)]
pub struct HickoryBdxlResolver {
    resolver: Arc<hickory_resolver::TokioResolver>,
}

#[cfg(feature = "dns")]
impl HickoryBdxlResolver {
    /// Build a resolver from the system configuration.
    ///
    /// # Errors
    ///
    /// [`ErrorCode::InvalidInput`] when the system resolver configuration
    /// cannot be read.
    pub fn from_system_config() -> Result<Self> {
        let init_error = |e: hickory_resolver::net::NetError| {
            AsxError::new(
                ErrorCode::InvalidInput,
                format!("could not build a DNS resolver from the system configuration: {e}"),
                ErrorContext::new("bdxl_resolver_init"),
            )
        };
        let resolver = hickory_resolver::Resolver::builder_tokio()
            .map_err(init_error)?
            .build()
            .map_err(init_error)?;
        Ok(Self {
            resolver: Arc::new(resolver),
        })
    }

    /// Wrap an already-configured resolver.
    pub fn from_resolver(resolver: hickory_resolver::TokioResolver) -> Self {
        Self {
            resolver: Arc::new(resolver),
        }
    }
}

#[cfg(feature = "dns")]
impl BdxlResolver for HickoryBdxlResolver {
    fn lookup_naptr<'a>(&'a self, name: &'a str) -> BoxFuture<'a, Result<Vec<NaptrRecord>>> {
        Box::pin(async move {
            use hickory_resolver::proto::rr::{RData, RecordType};

            // A BDXL name is absolute. Without the trailing dot the resolver
            // would append each `search` domain from the host configuration
            // first, which turns an unregistered participant into a lookup
            // against somebody else's zone.
            let fqdn = if name.ends_with('.') {
                name.to_string()
            } else {
                format!("{name}.")
            };

            let lookup = match self.resolver.lookup(fqdn.as_str(), RecordType::NAPTR).await {
                Ok(lookup) => lookup,
                // NXDOMAIN and an empty answer both mean "not registered",
                // which is a result, not a failure.
                Err(e) if e.is_no_records_found() => return Ok(Vec::new()),
                Err(e) => {
                    return Err(AsxError::new(
                        ErrorCode::TransportFailure,
                        format!("NAPTR lookup for '{fqdn}' failed: {e}"),
                        ErrorContext::new("bdxl_lookup_naptr"),
                    ));
                }
            };

            Ok(lookup
                .answers()
                .iter()
                .filter_map(|record| match &record.data {
                    RData::NAPTR(naptr) => Some(NaptrRecord {
                        order: naptr.order,
                        preference: naptr.preference,
                        flags: String::from_utf8_lossy(&naptr.flags).into_owned(),
                        service: String::from_utf8_lossy(&naptr.services).into_owned(),
                        regexp: String::from_utf8_lossy(&naptr.regexp).into_owned(),
                        replacement: naptr.replacement.to_string(),
                    }),
                    _ => None,
                })
                .collect())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Encoding ─────────────────────────────────────────────────────────

    #[test]
    fn base32_matches_rfc4648_test_vectors() {
        // RFC 4648 §10, with the padding stripped as BDXL requires.
        for (input, expected) in [
            ("", ""),
            ("f", "MY"),
            ("fo", "MZXQ"),
            ("foo", "MZXW6"),
            ("foob", "MZXW6YQ"),
            ("fooba", "MZXW6YTB"),
            ("foobar", "MZXW6YTBOI"),
        ] {
            assert_eq!(base32_nopad(input.as_bytes()), expected, "input {input:?}");
        }
    }

    // ── DNS names ────────────────────────────────────────────────────────

    /// The name asserted here is the one the live Peppol production SML
    /// answers a `Meta:SMP` NAPTR on; getting the hash input wrong produces a
    /// name that resolves to nothing, which is indistinguishable from an
    /// unregistered participant.
    #[test]
    fn bdxl_name_hashes_the_identifier_value_only() {
        assert_eq!(
            bdxl_dns_name(
                "iso6523-actorid-upis",
                "0088:5790002590993",
                "participant.sml.prod.tech.peppol.org"
            ),
            "2M2UFGZNGSS25JOOMOV2S4VGG7PW64KIVYNONDSVZSRT4EAZVCLQ\
             .iso6523-actorid-upis.participant.sml.prod.tech.peppol.org"
        );
    }

    #[test]
    fn bdxl_name_lowercases_the_identifier_before_hashing() {
        assert_eq!(
            bdxl_dns_name("iso6523-actorid-upis", "0088:ABC", "example.org"),
            bdxl_dns_name("iso6523-actorid-upis", "0088:abc", "example.org"),
        );
    }

    #[test]
    fn bdxl_name_tolerates_a_fully_qualified_zone() {
        assert_eq!(
            bdxl_dns_name("iso6523-actorid-upis", "0088:abc", "example.org."),
            bdxl_dns_name("iso6523-actorid-upis", "0088:abc", "example.org"),
        );
    }

    /// Peppol *Policy for use of Identifiers* worked example.
    #[test]
    fn legacy_cname_matches_the_peppol_worked_example() {
        assert_eq!(
            legacy_cname_host(
                "iso6523-actorid-upis",
                "0088:123abc",
                "edelivery.tech.ec.europa.eu"
            ),
            "B-f5e78500450d37de5aabe6648ac3bb70.iso6523-actorid-upis.edelivery.tech.ec.europa.eu"
        );
    }

    // ── U-NAPTR selection ────────────────────────────────────────────────

    fn naptr(order: u16, preference: u16, regexp: &str) -> NaptrRecord {
        NaptrRecord {
            order,
            preference,
            flags: "U".to_string(),
            service: "Meta:SMP".to_string(),
            regexp: regexp.to_string(),
            replacement: ".".to_string(),
        }
    }

    /// The exact record the Peppol production SML returns today.
    #[test]
    fn selects_the_uri_from_a_live_shaped_record() {
        let records = vec![naptr(100, 10, "!.*!https://smp.logiq.no!")];
        assert_eq!(
            select_smp_base_url(&records).expect("record is usable"),
            "https://smp.logiq.no"
        );
    }

    #[test]
    fn selects_by_order_then_preference() {
        let records = vec![
            naptr(200, 1, "!.*!https://third.example!"),
            naptr(100, 20, "!.*!https://second.example!"),
            naptr(100, 10, "!.*!https://first.example!"),
        ];
        assert_eq!(
            select_smp_base_url(&records).expect("record is usable"),
            "https://first.example"
        );
    }

    #[test]
    fn ignores_records_for_other_services_and_non_terminal_rules() {
        let mut other_service = naptr(10, 10, "!.*!https://not-an-smp.example!");
        other_service.service = "Meta:SMP-OTHER".to_string();
        let mut non_terminal = naptr(20, 10, "!.*!https://non-terminal.example!");
        non_terminal.flags = "S".to_string();

        let records = vec![
            other_service,
            non_terminal,
            naptr(30, 10, "!.*!https://smp.example!"),
        ];
        assert_eq!(
            select_smp_base_url(&records).expect("record is usable"),
            "https://smp.example"
        );
    }

    #[test]
    fn service_and_flags_are_matched_case_insensitively() {
        let mut record = naptr(10, 10, "!.*!https://smp.example!");
        record.service = "meta:smp".to_string();
        record.flags = "u".to_string();
        assert_eq!(
            select_smp_base_url(&[record]).expect("RFC 4848 §4.5 is case-insensitive"),
            "https://smp.example"
        );
    }

    /// A DNS answer that could downgrade the metadata fetch to plaintext is
    /// refused, not used: the metadata decides where a message goes and which
    /// key it is encrypted to.
    #[test]
    fn rejects_a_plaintext_uri() {
        let err = select_smp_base_url(&[naptr(10, 10, "!.*!http://smp.example!")])
            .expect_err("http must be refused");
        assert_eq!(err.code, ErrorCode::NotFound);
        assert!(err.message.contains("not an https URI"), "{}", err.message);
    }

    #[test]
    fn falls_through_to_the_next_record_when_the_first_is_unusable() {
        let records = vec![
            naptr(10, 10, "!.*!http://insecure.example!"),
            naptr(20, 10, "!.*!https://smp.example!"),
        ];
        assert_eq!(
            select_smp_base_url(&records).expect("second record is usable"),
            "https://smp.example"
        );
    }

    #[test]
    fn rejects_a_malformed_substitution_expression() {
        for regexp in ["", "!.*!https://smp.example", "!.*!", "https://smp.example"] {
            assert!(
                select_smp_base_url(&[naptr(10, 10, regexp)]).is_err(),
                "regexp {regexp:?} must be refused"
            );
        }
    }

    /// A backreference would let the record interpolate part of the queried
    /// name into the address messages are sent to.
    #[test]
    fn rejects_a_backreference_in_the_replacement() {
        let err = select_smp_base_url(&[naptr(10, 10, r"!(.*)!https://\1.example!")])
            .expect_err("backreferences must be refused");
        assert!(err.message.contains("backreference"), "{}", err.message);
    }

    /// An escaped delimiter is legal (RFC 3402 §3.2) and must not split the field.
    #[test]
    fn honours_an_escaped_delimiter() {
        let records = vec![naptr(10, 10, r"!.*!https://smp.example/a\!b!")];
        assert_eq!(
            select_smp_base_url(&records).expect("escaped delimiter is legal"),
            "https://smp.example/a!b"
        );
    }

    #[test]
    fn reports_not_found_for_an_empty_record_set() {
        let err = select_smp_base_url(&[]).expect_err("no records means no SMP");
        assert_eq!(err.code, ErrorCode::NotFound);
    }

    #[test]
    fn trailing_slash_is_normalized_away() {
        let records = vec![naptr(10, 10, "!.*!https://smp.example/!")];
        assert_eq!(
            select_smp_base_url(&records).expect("record is usable"),
            "https://smp.example"
        );
    }

    // ── Static resolver ──────────────────────────────────────────────────

    #[tokio::test]
    async fn static_resolver_answers_registered_names_only() {
        let resolver = StaticBdxlResolver::new().with_smp("a.example", "https://smp.example");
        assert_eq!(
            resolver
                .lookup_naptr("a.example")
                .await
                .expect("lookup succeeds")
                .len(),
            1
        );
        assert!(
            resolver
                .lookup_naptr("b.example")
                .await
                .expect("lookup succeeds")
                .is_empty()
        );
    }
}
