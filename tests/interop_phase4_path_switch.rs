#![cfg(all(feature = "as4", feature = "http-client"))]
//! phase4 witnesses the BDEW transmission-path-switch service (BDEW
//! AS4-Profil 1.2 §2.2.8, §2.3.7).
//!
//! ```text
//! just interop
//! # or, against a locally built peer:
//! ASX_PHASE4_IMAGE=$(docker build -q tests/fixtures/phase4) cargo test --all-features --test interop_phase4_path_switch -- --ignored --nocapture
//! ```
//!
//! crate → phase4: `As4::send(Message::path_switch(..))` — a signed,
//! unencrypted, payload-less plain SOAP message — must be receipted by
//! phase4's BDEW servlet (receipt verified as NRR evidence by the crate) and
//! delivered to phase4's SPI with Service/Action byte for byte.
//!
//! phase4 → crate: phase4's `Phase4BDEWSender` sends a payload-less
//! `requestSwitch` (`Phase4BDEWSender.java:181-189` lets exactly these two
//! actions go without payload); the crate's handler sees
//! `PathSwitch::Request` and sends `confirmSwitch` back from a spawned task.
//! The peer's `/control/send` honours the request's `"service"`/`"action"`
//! fields (peer image revision r3 or later).

#[path = "common/phase4/mod.rs"]
mod phase4;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use asx::as4::{As4, Message, PathSwitch, UserMessage};
use asx::testkit::audit::MemoryAuditSink;
use asx::{MemoryDedup, Reject, Verified};
use phase4::exchange::{Expectation, crate_client, expect};
use phase4::peer::{PeerConfig, Phase4Peer};
use phase4::pki::RunPki;
use phase4::variant::ProfileVariant;
use phase4::{CaseFailure, HarnessError, sha256_hex};
use serde_json::{Value, json};

const SERVICE: &str = "https://www.bdew.de/as4/communication/services/pathSwitch";
const REQUEST: &str = "https://www.bdew.de/as4/communication/actions/requestSwitch";
const CONFIRM: &str = "https://www.bdew.de/as4/communication/actions/confirmSwitch";

/// A handler call: message id and its path-switch kind.
type Seen = (String, Option<PathSwitch>);

fn case(msg: impl Into<String>) -> HarnessError {
    HarnessError::Case(CaseFailure(msg.into()))
}

fn infra(msg: impl std::fmt::Display) -> HarnessError {
    HarnessError::infra(msg.to_string())
}

async fn start(variant: ProfileVariant) -> (Phase4Peer, RunPki) {
    let pki = RunPki::generate(&variant);
    let peer = Phase4Peer::start(PeerConfig {
        variants: vec![variant],
        pki: vec![(variant, &pki)],
        ..PeerConfig::default()
    })
    .await
    .unwrap_or_else(|e| panic!("{e}"));
    (peer, pki)
}

/// phase4's raw inbox entry (it records Service and Action).
async fn inbox_json(peer: &Phase4Peer, message_id: &str) -> Result<Option<Value>, HarnessError> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        let resp = reqwest::get(format!("{}/control/inbox/{message_id}", peer.base_url()))
            .await
            .map_err(infra)?;
        if resp.status().is_success() {
            return Ok(Some(resp.json().await.map_err(infra)?));
        }
        if tokio::time::Instant::now() >= deadline {
            return Ok(None);
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

/// crate → phase4, one kind: receipt signed by phase4, NRR digests ==
/// signed references, phase4's SPI saw the exact URIs, no part, the crate's
/// signer.
async fn crate_to_phase4(
    peer: &Phase4Peer,
    pki: &RunPki,
    v: &ProfileVariant,
    kind: PathSwitch,
    action: &str,
) -> Result<String, HarnessError> {
    let audit = MemoryAuditSink::new();
    let as4 = crate_client(pki, v, peer.http_client(), audit.clone())?;
    let message_id = format!("{}@asx.phase4.test", uuid::Uuid::new_v4());
    let receipt = as4
        .send(Message::path_switch(&pki.phase4_partner(v), kind).message_id(&message_id))
        .await
        .map_err(|e| {
            case(format!(
                "As4::send(path_switch) to phase4 failed: kind {:?}, ebms {:?}: {e}",
                e.kind(),
                e.ebms_code()
            ))
        })?;
    if sha256_hex(receipt.signer().der()) != pki.phase4_side.sign.fingerprint() {
        return Err(case(
            "the receipt signer is not phase4's signing certificate",
        ));
    }
    let records = audit.records_json();
    let record = records
        .iter()
        .find(|r| r["message_id"] == message_id.as_str())
        .ok_or_else(|| case("no audit record"))?;
    if record["outcome"] != "delivered" || record["signal"]["signed"] != true {
        return Err(case(format!("audit record {record}")));
    }
    let nrr = record["signal"]["nrr"].as_array().map_or(0, Vec::len);
    let refs = record["references"].as_array().map_or(0, Vec::len);
    if nrr != 2 || refs != 2 {
        return Err(case(format!(
            "expected 2 NRR digests over 2 signed references (eb:Messaging, Body); got {nrr}/{refs}"
        )));
    }
    let entry = inbox_json(peer, &message_id)
        .await?
        .ok_or_else(|| case("phase4 receipted but did not hand the message to its SPI"))?;
    if entry["service"] != SERVICE || entry["action"] != action {
        return Err(case(format!(
            "phase4 recorded service {} action {}",
            entry["service"], entry["action"]
        )));
    }
    if entry["parts"].as_array().is_some_and(|p| !p.is_empty()) {
        return Err(case(format!("phase4 saw parts {}", entry["parts"])));
    }
    if entry["signingCertSha256"] != pki.crate_side.sign.fingerprint().as_str() {
        return Err(case("phase4's verified signer is not the crate's"));
    }
    Ok(message_id)
}

/// Both kinds: our request and our confirmation are accepted by
/// phase4's BDEW profile.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs Docker and the phase4 peer: just interop"]
async fn bdew_path_switch_to_phase4() {
    let v = ProfileVariant::Bdew;
    let (peer, pki) = start(v).await;
    for (kind, action) in [
        (PathSwitch::Request, REQUEST),
        (PathSwitch::Confirm, CONFIRM),
    ] {
        let result = crate_to_phase4(&peer, &pki, &v, kind, action).await;
        if let Ok(id) = &result {
            println!("phase4 receipted and delivered {kind:?} {id}");
        }
        expect(result, Expectation::Pass, &peer.log().await);
    }
}

/// phase4 sends a payload-less `requestSwitch`; the crate's handler
/// confirms from a spawned task; phase4 receipts the confirmation.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs Docker and the phase4 peer: just interop"]
async fn bdew_path_switch_from_phase4_and_confirm() {
    let v = ProfileVariant::Bdew;
    let (peer, pki) = start(v).await;
    let result = from_phase4_and_confirm(&peer, &pki, &v).await;
    expect(result, Expectation::Pass, &peer.log().await);
}

async fn from_phase4_and_confirm(
    peer: &Phase4Peer,
    pki: &RunPki,
    v: &ProfileVariant,
) -> Result<(), HarnessError> {
    let as4: As4 = crate_client(pki, v, peer.http_client(), MemoryAuditSink::new())?;
    let seen: Arc<Mutex<Vec<Seen>>> = Arc::default();
    let (done_tx, mut done_rx) = tokio::sync::mpsc::unbounded_channel::<Result<String, String>>();
    let handler = {
        let (seen, as4, partner) = (seen.clone(), as4.clone(), pki.phase4_partner(v));
        move |m: Verified<UserMessage>| {
            let (seen, as4, partner, done_tx) =
                (seen.clone(), as4.clone(), partner.clone(), done_tx.clone());
            async move {
                seen.lock()
                    .unwrap()
                    .push((m.message_id().to_string(), m.path_switch()));
                if m.path_switch() == Some(PathSwitch::Request) {
                    tokio::spawn(async move {
                        let id = format!("{}@asx.phase4.test", uuid::Uuid::new_v4());
                        let sent = as4
                            .send(
                                Message::path_switch(&partner, PathSwitch::Confirm).message_id(&id),
                            )
                            .await
                            .map(|_| id)
                            .map_err(|e| e.to_string());
                        let _ = done_tx.send(sent);
                    });
                }
                Ok::<(), Reject>(())
            }
        }
    };
    let inbound = as4.inbound(MemoryDedup::default(), handler);
    let app = axum::Router::new().route_service("/as4", inbound);
    let listener = tokio::net::TcpListener::bind("0.0.0.0:0")
        .await
        .map_err(infra)?;
    let port = listener.local_addr().map_err(infra)?.port();
    let server = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    let message_id = format!("{}@asx.phase4.test", uuid::Uuid::new_v4());
    let body = json!({
        "variant": v.id(),
        "toUrl": format!("http://host.docker.internal:{port}/as4"),
        "messageId": message_id,
        "ping": false,
        "encrypt": false,
        "service": SERVICE,
        "action": REQUEST,
        "payloads": [],
    });
    let resp = reqwest::Client::new()
        .post(format!("{}/control/send", peer.base_url()))
        .json(&body)
        .send()
        .await
        .map_err(infra)?;
    let status = resp.status();
    let value: Value = resp.json().await.map_err(infra)?;
    let outcome = async {
        if !status.is_success() {
            return Err(case(format!("/control/send answered {status}: {value}")));
        }
        if value["result"] != "SUCCESS" {
            return Err(case(format!(
                "phase4 could not send a payload-less requestSwitch: result {} error {}",
                value["result"], value["error"]
            )));
        }
        let delivered = seen.lock().unwrap().clone();
        if delivered != [(message_id.clone(), Some(PathSwitch::Request))] {
            return Err(case(format!("the handler saw {delivered:?}")));
        }
        let confirm = tokio::time::timeout(Duration::from_secs(20), done_rx.recv())
            .await
            .map_err(|_| case("no confirmation was attempted"))?
            .ok_or_else(|| case("the confirmation task ended"))?
            .map_err(|e| case(format!("phase4 refused the confirmation: {e}")))?;
        let entry = inbox_json(peer, &confirm)
            .await?
            .ok_or_else(|| case("phase4 did not deliver the confirmation"))?;
        if entry["service"] != SERVICE || entry["action"] != CONFIRM {
            return Err(case(format!("phase4 recorded {entry}")));
        }
        println!("phase4 requestSwitch {message_id} confirmed by {confirm}");
        Ok(())
    }
    .await;
    server.abort();
    outcome
}
