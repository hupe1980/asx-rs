#![cfg(all(feature = "peppol", feature = "http-client"))]
//! Live-network oracle for BDXL participant discovery.
//!
//! # Why this exists
//!
//! Discovery decides *where a message goes*, and every offline check of it is a
//! check against a document.
//!
//! The offline vectors in `smp::bdxl` pin the *computation* to the
//! specification's own worked example. This pins the *result* to what the
//! Peppol SML actually answers, which is the only thing that catches a zone
//! migration, a NAPTR format change, or another move like the CNAME→NAPTR one.
//!
//! # Running
//!
//! `#[ignore]`d so the default `cargo test` stays hermetic and offline:
//!
//! ```text
//! cargo test --all-features --test interop_peppol_sml_discovery -- --ignored --nocapture
//! ```
//!
//! A failure here is not necessarily a defect in this crate — it can equally
//! mean the network moved. Read it as "the assumption expired", and check the
//! Peppol *Policy for use of Identifiers* and the SML zone before changing code.

use asx::__fuzz::smp::{
    BdxlResolver, HickoryBdxlResolver, PEPPOL_PRODUCTION_SML_ZONE, PEPPOL_TEST_SML_ZONE,
    bdxl_dns_name, select_smp_base_url,
};

/// A participant registered in Peppol production, used here only as a name that
/// is expected to resolve. If this one is ever deregistered the test reports a
/// stale fixture rather than a broken implementation — the assertion message
/// says so.
const KNOWN_PRODUCTION_PARTICIPANT: &str = "0088:5790002590993";

const PEPPOL_SCHEME: &str = "iso6523-actorid-upis";

fn resolver() -> HickoryBdxlResolver {
    HickoryBdxlResolver::from_system_config().expect("system DNS configuration")
}

/// The name this crate computes must be the name the SML answers on.
///
/// No offline test can make this assertion.
#[tokio::test]
#[ignore = "requires network access to the Peppol production SML"]
async fn production_sml_answers_the_name_the_crate_computes() {
    let name = bdxl_dns_name(
        PEPPOL_SCHEME,
        KNOWN_PRODUCTION_PARTICIPANT,
        PEPPOL_PRODUCTION_SML_ZONE,
    );
    println!("querying NAPTR {name}");

    let records = resolver()
        .lookup_naptr(&name)
        .await
        .expect("NAPTR lookup must not fail at the transport level");

    assert!(
        !records.is_empty(),
        "no NAPTR records at {name}.\n\
         Either the DNS name construction is wrong (check the Peppol \"Policy for use of \
         Identifiers\": the hash covers the lowercased identifier VALUE only, and the scheme \
         is its own label), the SML zone moved again, or participant \
         {KNOWN_PRODUCTION_PARTICIPANT} was deregistered."
    );

    for record in &records {
        println!(
            "  {} {} {:?} {:?} {:?}",
            record.order, record.preference, record.flags, record.service, record.regexp
        );
    }

    let smp = select_smp_base_url(&records)
        .expect("the SML must publish a usable Meta:SMP U-NAPTR for a registered participant");
    println!("resolved SMP base URL: {smp}");
    assert!(
        smp.starts_with("https://"),
        "BDXL requires an https SMP URI, got {smp}"
    );
}

/// The test SML (SMK) must answer on the same construction, so a deployment can
/// rehearse discovery without touching production.
#[tokio::test]
#[ignore = "requires network access to the Peppol test SML"]
async fn test_sml_zone_is_reachable() {
    // Nothing is asserted about *which* participants exist in the test network,
    // only that the zone resolves. Either answer is legitimate — the test SML
    // has been observed to answer with a wildcard record — whereas a transport
    // error means the zone name itself is wrong.
    let name = bdxl_dns_name(PEPPOL_SCHEME, "0088:0000000000000", PEPPOL_TEST_SML_ZONE);
    println!("querying NAPTR {name}");

    let records = resolver()
        .lookup_naptr(&name)
        .await
        .expect("the test SML zone must resolve; an unregistered participant is an empty answer");

    println!(
        "{} record(s); either count is a valid answer here",
        records.len()
    );
}

/// The zones the presets name must be the ones in use.
///
/// The European Commission zones these replaced stopped answering participant
/// lookups on 31 August 2026, and a stale constant is a lookup that silently
/// finds nothing.
#[test]
fn peppol_zone_constants_are_the_openpeppol_ones() {
    assert_eq!(
        PEPPOL_PRODUCTION_SML_ZONE,
        "participant.sml.prod.tech.peppol.org"
    );
    assert_eq!(PEPPOL_TEST_SML_ZONE, "participant.sml.test.tech.peppol.org");
}
