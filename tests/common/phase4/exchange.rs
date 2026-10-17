//! Exchanges with phase4 in both directions, the evidence each side must
//! show, and the strict expectation (pass or a named known gap).

use std::time::Duration;

use asx::as4::{As4, Message};
use asx::{ErrorKind, Payload};
use asx_testkit::audit::MemoryAuditSink;
use serde_json::Value;

use super::http::{PeerHttp, Tamper, apply_tamper};
use super::inbound::{CrateInbound, Delivered, RawResponse};
use super::peer::{PeerSendRequest, Phase4Peer, TestPayload};
use super::pki::RunPki;
use super::variant::ProfileVariant;
use super::{CaseFailure, HarnessError, sha256_hex};

/// What a case sends.
#[derive(Debug, Clone)]
pub enum Case {
    /// An ebMS3 test-service message (`Message::ping` / phase4's test
    /// service and action): receipted, never delivered. Both stacks require
    /// a payload on it under BDEW (`As4::send`; `Phase4BDEWSender`), so it
    /// carries [`ping_payload`].
    Ping,
    /// A business message to the variant's service with these payloads.
    Payloads(Vec<TestPayload>),
}

impl Case {
    pub fn payloads(&self) -> Vec<TestPayload> {
        match self {
            Case::Ping => vec![ping_payload()],
            Case::Payloads(p) => p.clone(),
        }
    }

    pub fn is_ping(&self) -> bool {
        matches!(self, Case::Ping)
    }
}

/// The payload a ping carries.
pub fn ping_payload() -> TestPayload {
    TestPayload {
        mime_type: "application/octet-stream".into(),
        bytes: b"asx phase4 interop ping".to_vec(),
    }
}

/// A small EDIFACT-like business payload.
pub fn edifact_payload() -> TestPayload {
    TestPayload {
        mime_type: "application/octet-stream".into(),
        bytes: b"UNA:+.? 'UNB+UNOC:3+9900000000001:500+9900000000002:500+261016:1200+ASX1'UNH+1+UTILMD:D:11A:UN:S2.1'UNT+2+1'UNZ+1+ASX1'".to_vec(),
    }
}

/// How a case is expected to end.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Expectation {
    Pass,
    /// The case is known to fail. A case failure prints
    /// the gap and passes; a pass fails ("remove the KnownGap marker").
    KnownGap {
        item: &'static str,
        reason: &'static str,
    },
}

/// The crate side's evidence for one send.
#[derive(Debug, Clone)]
pub struct SentEvidence {
    pub message_id: String,
    /// The `delivered` audit record (JSON form).
    pub audit: Value,
    /// Request bodies as forwarded to phase4.
    pub sent: Vec<Vec<u8>>,
}

/// phase4's evidence for one push to the crate.
#[derive(Debug, Clone)]
pub struct ReceivedEvidence {
    pub message_id: String,
    pub phase4_result: String,
    /// The receipt bytes phase4 received and accepted.
    pub receipt: Vec<u8>,
    /// `ebbp:MessagePartNRInformation` entries in that receipt.
    pub nrr_count: usize,
    pub delivered: Option<Delivered>,
}

fn case(msg: impl Into<String>) -> HarnessError {
    HarnessError::Case(CaseFailure(msg.into()))
}

fn fresh_message_id() -> String {
    format!("{}@asx.phase4.test", uuid::Uuid::new_v4())
}

/// The crate's client for `variant`, talking to `peer` through `http`.
pub fn crate_client(
    pki: &RunPki,
    variant: &ProfileVariant,
    http: PeerHttp,
    audit: MemoryAuditSink,
) -> Result<As4, HarnessError> {
    As4::builder(variant.profile())
        .local(pki.local_party(variant))
        .trust_anchor(pki.anchor())
        .partner(pki.phase4_partner(variant))
        .http_client(http)
        .audit(audit)
        .build()
        .map_err(|e| case(format!("As4::build refused the harness configuration: {e}")))
}

fn message(pki: &RunPki, variant: &ProfileVariant, case: &Case, message_id: &str) -> Message {
    let partner = pki.phase4_partner(variant);
    let mut msg = match case {
        Case::Ping => Message::ping(&partner),
        Case::Payloads(_) => Message::to(&partner).service(variant.collaboration().service),
    };
    msg = msg.message_id(message_id);
    for p in case.payloads() {
        msg = msg.payload(Payload::new(p.bytes, p.mime_type));
    }
    msg
}

fn triples(v: &Value) -> Vec<(String, String, String)> {
    v.as_array()
        .map(|a| {
            a.iter()
                .map(|e| {
                    (
                        e["uri"].as_str().unwrap_or_default().to_owned(),
                        e["digest_algorithm"]
                            .as_str()
                            .unwrap_or_default()
                            .to_owned(),
                        e["digest"].as_str().unwrap_or_default().to_owned(),
                    )
                })
                .collect()
        })
        .unwrap_or_default()
}

async fn wait_inbox(
    peer: &Phase4Peer,
    message_id: &str,
    timeout: Duration,
) -> Result<Option<super::peer::PeerInboxEntry>, HarnessError> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if let Some(entry) = peer.inbox(message_id).await? {
            return Ok(Some(entry));
        }
        if tokio::time::Instant::now() >= deadline {
            return Ok(None);
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

/// crate → phase4: `As4::send` through `PeerHttp`; asserts `Ok(Verified<Receipt>)`
/// signed by phase4's pinned signing certificate, one `delivered` audit
/// record whose signed signal's NRR digests equal the references the crate
/// signed, and phase4's inbox: decrypted, signed by the crate's signing
/// certificate, plaintext digests equal to what was sent (phase4's BDEW
/// profile hands pings to its application as well).
pub async fn crate_to_phase4(
    peer: &Phase4Peer,
    pki: &RunPki,
    variant: &ProfileVariant,
    case_: &Case,
) -> Result<SentEvidence, HarnessError> {
    let http = peer.http_client();
    let audit = MemoryAuditSink::new();
    let as4 = crate_client(pki, variant, http.clone(), audit.clone())?;
    let message_id = fresh_message_id();
    let receipt = as4
        .send(message(pki, variant, case_, &message_id))
        .await
        .map_err(|e| {
            case(format!(
                "As4::send to phase4 failed: kind {:?}, ebms {:?}: {e}",
                e.kind(),
                e.ebms_code()
            ))
        })?;

    let phase4_sign = pki.phase4_side.sign.fingerprint();
    if sha256_hex(receipt.signer().der()) != phase4_sign {
        return Err(case(
            "the receipt signer is not phase4's signing certificate",
        ));
    }
    let records = audit.records_json();
    let delivered: Vec<&Value> = records
        .iter()
        .filter(|r| r["message_id"] == message_id.as_str())
        .collect();
    let [record] = delivered.as_slice() else {
        return Err(case(format!(
            "expected one audit record for {message_id}, found {}",
            delivered.len()
        )));
    };
    let record = (*record).clone();
    if record["outcome"] != "delivered" {
        return Err(case(format!("audit outcome {}", record["outcome"])));
    }
    if record["signal"]["signed"] != true {
        return Err(case("audit: the receipt signal is not signed"));
    }
    let nrr = triples(&record["signal"]["nrr"]);
    let refs = triples(&record["references"]);
    if nrr.is_empty() || nrr != refs {
        return Err(case(format!(
            "audit: NRR digests {nrr:?} differ from the signed references {refs:?}"
        )));
    }
    if record["signer"]["fingerprint_sha256"] != phase4_sign.as_str() {
        return Err(case("audit: signer is not phase4's signing certificate"));
    }

    // phase4's BDEW profile passes pings to its application too
    // (`AS4Profile#isInvokeSPIForPingMessage`), so every case is delivered.
    let inbox = wait_inbox(peer, &message_id, Duration::from_secs(10)).await?;
    let Some(entry) = inbox else {
        return Err(case("phase4 receipted but did not deliver the message"));
    };
    if !entry.decrypted {
        return Err(case("phase4 reports the message was not decrypted"));
    }
    if entry.signing_cert_sha256 != pki.crate_side.sign.fingerprint() {
        return Err(case(
            "phase4's verified signer is not the crate's signing certificate",
        ));
    }
    let got: Vec<&str> = entry
        .parts
        .iter()
        .map(|p| p.sha256_plaintext.as_str())
        .collect();
    let want: Vec<String> = case_
        .payloads()
        .iter()
        .map(|p| sha256_hex(&p.bytes))
        .collect();
    if got != want.iter().map(String::as_str).collect::<Vec<_>>() {
        return Err(case(format!("phase4 delivered {got:?}, sent {want:?}")));
    }
    Ok(SentEvidence {
        message_id,
        audit: record,
        sent: http.sent(),
    })
}

/// Start tags `<[prefix:]local` (not end tags) in `hay`.
fn count_start_tags(hay: &[u8], local: &[u8]) -> usize {
    hay.windows(local.len())
        .enumerate()
        .filter(|(i, w)| {
            *w == local && {
                // Walk back over an optional `prefix:` to the '<'.
                let before = &hay[..*i];
                let lt = before.iter().rposition(|&b| b == b'<');
                lt.is_some_and(|lt| {
                    let between = &before[lt + 1..];
                    !between.starts_with(b"/")
                        && between.iter().all(|&b| {
                            b.is_ascii_alphanumeric() || b == b':' || b == b'_' || b == b'-'
                        })
                })
            }
        })
        .count()
}

/// phase4 → crate: phase4's BDEW sender pushes to [`CrateInbound`]; asserts
/// phase4 reports `SUCCESS` (it verified the crate's receipt, NRR included),
/// the receipt carries NRR entries, and the handler saw exactly the payload
/// (none for a ping) signed by phase4's signing certificate.
pub async fn phase4_to_crate(
    peer: &Phase4Peer,
    pki: &RunPki,
    inbound: &CrateInbound,
    variant: &ProfileVariant,
    case_: &Case,
    encrypt: bool,
) -> Result<ReceivedEvidence, HarnessError> {
    let before = inbound.handler_calls();
    let message_id = fresh_message_id();
    let result = peer
        .send(PeerSendRequest {
            variant: *variant,
            to_url: inbound.container_url(),
            message_id: message_id.clone(),
            ping: case_.is_ping(),
            payloads: case_.payloads(),
            encrypt,
        })
        .await?;
    if result.phase4_result != "SUCCESS" {
        let body = result
            .receipt
            .as_deref()
            .map(String::from_utf8_lossy)
            .unwrap_or_default();
        return Err(case(format!(
            "phase4 reports {} (error {:?}); the crate answered:\n{body}",
            result.phase4_result, result.error
        )));
    }
    let receipt = result
        .receipt
        .ok_or_else(|| case("phase4 reports SUCCESS without response bytes"))?;
    let nrr_count = count_start_tags(&receipt, b"MessagePartNRInformation");
    if nrr_count == 0 {
        return Err(case("the crate's receipt carries no NRR entry"));
    }
    let calls = inbound.delivered();
    let new: Vec<&Delivered> = calls[before..].iter().collect();
    let delivered = match case_ {
        Case::Ping => {
            if !new.is_empty() {
                return Err(case("the crate's handler was called for a ping"));
            }
            None
        }
        Case::Payloads(payloads) => {
            let [d] = new.as_slice() else {
                return Err(case(format!(
                    "expected one handler call, saw {}",
                    new.len()
                )));
            };
            if d.message_id != message_id {
                return Err(case(format!("delivered {} not {message_id}", d.message_id)));
            }
            if d.signer_sha256 != pki.phase4_side.sign.fingerprint() {
                return Err(case("Verified::signer is not phase4's signing certificate"));
            }
            let want: Vec<String> = payloads.iter().map(|p| sha256_hex(&p.bytes)).collect();
            if d.payload_sha256 != want {
                return Err(case(format!(
                    "delivered digests {:?}, phase4 sent {want:?}",
                    d.payload_sha256
                )));
            }
            Some((*d).clone())
        }
    };
    Ok(ReceivedEvidence {
        message_id,
        phase4_result: result.phase4_result,
        receipt,
        nrr_count,
        delivered,
    })
}

/// phase4 → crate that the crate must refuse (e.g. an unencrypted BDEW
/// payload): phase4 does not report `SUCCESS`, the crate answered with an
/// ebMS error, and the handler was not called. Returns the error code.
pub async fn refused_phase4_to_crate(
    peer: &Phase4Peer,
    inbound: &CrateInbound,
    variant: &ProfileVariant,
    case_: &Case,
    encrypt: bool,
) -> Result<String, HarnessError> {
    let before = inbound.handler_calls();
    let result = peer
        .send(PeerSendRequest {
            variant: *variant,
            to_url: inbound.container_url(),
            message_id: fresh_message_id(),
            ping: case_.is_ping(),
            payloads: case_.payloads(),
            encrypt,
        })
        .await?;
    if result.phase4_result == "SUCCESS" {
        return Err(case("the crate receipted a message it must refuse"));
    }
    if inbound.handler_calls() != before {
        return Err(case("the handler was called for a refused message"));
    }
    let body = result.receipt.unwrap_or_default();
    let response = RawResponse {
        status: http::StatusCode::OK,
        content_type: result.receipt_content_type,
        body: body.into(),
    };
    if !response.is_ebms_error() {
        return Err(case(format!(
            "phase4 reports {} but the crate's answer is no ebMS error: {}",
            result.phase4_result,
            response.text()
        )));
    }
    let code = response.ebms_error_code().unwrap_or_default();
    println!(
        "phase4 reports {}; the crate answered {code}",
        result.phase4_result
    );
    Ok(code)
}

/// crate → phase4 with one byte flipped by `tamper`: `send` must return
/// `Err` with kind `PartnerError` or `Rejected`, and phase4 must deliver
/// nothing. The same message untampered is sent first and must be accepted,
/// so the refusal is the flipped byte's (phase4 reports every WS-Security
/// failure, signature or decryption, as `EBMS:0102`, so the code cannot
/// tell them apart).
pub async fn tampered_crate_to_phase4(
    peer: &Phase4Peer,
    pki: &RunPki,
    variant: &ProfileVariant,
    case_: &Case,
    tamper: Tamper,
) -> Result<(), HarnessError> {
    crate_to_phase4(peer, pki, variant, case_)
        .await
        .map_err(|e| match e {
            HarnessError::Case(f) => case(format!(
                "control (untampered) send failed, so the negative proves nothing: {f}"
            )),
            infra => infra,
        })?;
    let http = peer.http_client().tampering(tamper);
    let as4 = crate_client(pki, variant, http.clone(), MemoryAuditSink::new())?;
    let message_id = fresh_message_id();
    let outcome = as4.send(message(pki, variant, case_, &message_id)).await;
    if http.tampered_at().is_empty() {
        return Err(case("nothing was tampered (no request reached PeerHttp)"));
    }
    match outcome {
        Ok(_) => Err(case(format!(
            "phase4 accepted a message with a byte flipped ({tamper:?} at {:?})",
            http.tampered_at()
        ))),
        Err(e) if matches!(e.kind(), ErrorKind::PartnerError | ErrorKind::Rejected) => {
            if wait_inbox(peer, &message_id, Duration::from_millis(500))
                .await?
                .is_some()
            {
                return Err(case("phase4 refused the tampered message but delivered it"));
            }
            println!(
                "tampered crate → phase4 refused: kind {:?}, ebms {:?}",
                e.kind(),
                e.ebms_code()
            );
            Ok(())
        }
        Err(e) => Err(case(format!(
            "tampered send failed with kind {:?} (want PartnerError or Rejected): {e}",
            e.kind()
        ))),
    }
}

/// phase4 → crate, tampered: phase4 pushes once to `/capture`; the harness
/// flips one byte and feeds it to the same `Inbound`. The answer must be an
/// ebMS error, no receipt, no handler call. The untampered capture is fed
/// afterwards and must be receipted, so the refusal is the flipped byte's.
pub async fn tampered_phase4_to_crate(
    peer: &Phase4Peer,
    inbound: &CrateInbound,
    variant: &ProfileVariant,
    case_: &Case,
    encrypt: bool,
    tamper: Tamper,
) -> Result<RawResponse, HarnessError> {
    let before = inbound.handler_calls();
    let message_id = fresh_message_id();
    let _ = peer
        .send(PeerSendRequest {
            variant: *variant,
            to_url: inbound.capture_url(),
            message_id,
            ping: case_.is_ping(),
            payloads: case_.payloads(),
            encrypt,
        })
        .await?;
    let original = inbound
        .take_capture(Duration::from_secs(15))
        .await
        .ok_or_else(|| case("phase4 sent nothing to /capture"))?;
    let mut tampered = original.clone();
    let mut body = tampered.body.to_vec();
    let at = apply_tamper(&mut body, tamper).map_err(case)?;
    tampered.body = body.into();

    let response = inbound.feed(&tampered).await;
    if response.is_receipt() || !response.is_ebms_error() {
        return Err(case(format!(
            "the crate did not answer a byte flipped at {at} ({tamper:?}) with an ebMS error: {} {}",
            response.status,
            response.text()
        )));
    }
    if inbound.handler_calls() != before {
        return Err(case("the handler was called for a tampered message"));
    }
    let control = inbound.feed(&original).await;
    if !control.is_receipt() {
        return Err(case(format!(
            "the untampered capture was not receipted either, so the negative proves nothing: {} {}",
            control.status,
            control.text()
        )));
    }
    println!(
        "tampered phase4 → crate refused: HTTP {} errorCode {:?} (flipped byte {at})",
        response.status,
        response.ebms_error_code()
    );
    Ok(response)
}

/// Apply the strict expectation. `Pass`+`Ok` → ok; `Pass`+`Err` → panic with
/// the peer log; `KnownGap`+`Err(Case)` → print `known gap <item>: …`, ok;
/// `KnownGap`+`Ok` → panic "known gap <item> closed"; `Err(Infra)` → panic.
pub fn expect<T>(result: Result<T, HarnessError>, expectation: Expectation, peer_log: &str) {
    match (result, expectation) {
        (Ok(_), Expectation::Pass) => {}
        (Err(HarnessError::Infra(msg)), _) => {
            panic!("INFRA: {msg}\n--- peer log ---\n{peer_log}")
        }
        (Err(HarnessError::Case(failure)), Expectation::Pass) => {
            panic!("case failed: {failure}\n--- peer log ---\n{peer_log}")
        }
        (Err(HarnessError::Case(failure)), Expectation::KnownGap { item, reason }) => {
            let line = format!("known gap {item}: {reason}: {failure}");
            println!("{line}");
            if let Ok(path) = std::env::var("GITHUB_STEP_SUMMARY") {
                use std::io::Write as _;
                if let Ok(mut f) = std::fs::OpenOptions::new()
                    .append(true)
                    .create(true)
                    .open(path)
                {
                    let _ = writeln!(f, "- {line}");
                }
            }
        }
        (Ok(_), Expectation::KnownGap { item, .. }) => {
            panic!("known gap {item} closed: remove the KnownGap marker")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GAP: Expectation = Expectation::KnownGap {
        item: "example gap",
        reason: "test",
    };

    #[test]
    fn expect_pass_ok_is_ok() {
        expect(Ok::<_, HarnessError>(()), Expectation::Pass, "");
    }

    #[test]
    #[should_panic(expected = "case failed")]
    fn expect_pass_err_panics() {
        expect::<()>(Err(case("boom")), Expectation::Pass, "");
    }

    #[test]
    fn expect_known_gap_case_failure_is_reported_and_passes() {
        expect::<()>(Err(case("still broken")), GAP, "");
    }

    #[test]
    #[should_panic(expected = "known gap example gap closed")]
    fn expect_known_gap_that_passes_fails() {
        expect(Ok::<_, HarnessError>(()), GAP, "");
    }

    #[test]
    #[should_panic(expected = "INFRA:")]
    fn expect_infra_never_satisfies_a_known_gap() {
        expect::<()>(Err(HarnessError::infra("docker down")), GAP, "");
    }

    #[test]
    #[should_panic(expected = "INFRA:")]
    fn expect_infra_never_passes() {
        expect::<()>(
            Err(HarnessError::infra("docker down")),
            Expectation::Pass,
            "",
        );
    }

    #[test]
    fn harness_error_infra_is_labelled() {
        assert!(HarnessError::infra("x").to_string().starts_with("INFRA: "));
        assert!(!case("x").to_string().starts_with("INFRA"));
    }
}
