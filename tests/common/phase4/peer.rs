//! The phase4 peer container: start, readiness, version check, control API.

use std::time::{Duration, Instant};

use base64::Engine as _;
use serde_json::{Value, json};
use testcontainers::core::{Host, IntoContainerPort};
use testcontainers::runners::AsyncRunner;
use testcontainers::{ContainerAsync, GenericImage, ImageExt};

use super::http::PeerHttp;
use super::image::{PHASE4_VERSION, PinnedImage, check_version, parse_pinned, resolve_peer_image};
use super::pki::RunPki;
use super::variant::ProfileVariant;
use super::{CaseFailure, HarnessError};

/// Readiness ceiling (JVM start plus key-store load).
pub const READINESS_TIMEOUT: Duration = Duration::from_secs(120);

/// The largest tolerated difference between the host's and the peer
/// container's wall clocks. Both sides check `wsu:Timestamp` freshness
/// (WSS4J refuses a Created more than 60 s in the future), so a larger skew
/// (e.g. a Docker Desktop VM clock that drifted while the host slept) fails
/// every exchange for a reason that is not the code under test.
pub const MAX_CLOCK_SKEW: Duration = Duration::from_secs(30);

/// INFRA when the peer reports (`nowEpochMillis`) a wall clock
/// more than [`MAX_CLOCK_SKEW`] away from the host's. Older peers report
/// nothing and are not checked.
fn check_clock_skew(raw: &Value) -> Result<(), HarnessError> {
    let Some(peer_ms) = raw["nowEpochMillis"].as_i64() else {
        return Ok(());
    };
    let host_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(infra)?
        .as_millis() as i64;
    let skew_ms = peer_ms - host_ms;
    if skew_ms.unsigned_abs() > MAX_CLOCK_SKEW.as_millis() as u64 {
        return Err(infra(format!(
            "the peer container's clock is {:+.1} s off the host's (limit {} s): \
             WS-Security timestamp checks would fail on both sides; resync the Docker VM \
             clock (Docker Desktop: restart it, or wait for its time sync) and re-run",
            skew_ms as f64 / 1000.0,
            MAX_CLOCK_SKEW.as_secs()
        )));
    }
    Ok(())
}

/// What `/control/version` reported.
#[derive(Debug, Clone)]
pub struct PeerVersion {
    pub phase4: String,
    pub peer: Option<String>,
    pub java: String,
    pub bouncycastle: String,
    pub raw: Value,
}

/// What the peer is started with.
#[derive(Debug, Default)]
pub struct PeerConfig<'a> {
    pub variants: Vec<ProfileVariant>,
    /// One `RunPki` per variant (the same run CA may be shared).
    pub pki: Vec<(ProfileVariant, &'a RunPki)>,
    /// Where phase4 pushes to (informational; each send names its URL).
    pub crate_inbound_url: Option<String>,
    /// An image reference overriding `resolve_peer_image()`; pinned like it.
    pub image: Option<String>,
}

/// A payload as the peer sends it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TestPayload {
    pub mime_type: String,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct PeerSendRequest {
    pub variant: ProfileVariant,
    pub to_url: String,
    pub message_id: String,
    pub ping: bool,
    pub payloads: Vec<TestPayload>,
    pub encrypt: bool,
}

#[derive(Debug, Clone)]
pub struct PeerSendResult {
    /// phase4's `EAS4UserMessageSendResult` name (`SUCCESS`, …).
    pub phase4_result: String,
    /// The raw HTTP response body phase4 received (the receipt, MIME or XML).
    pub receipt: Option<Vec<u8>>,
    pub receipt_content_type: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartDigest {
    pub content_id: String,
    pub mime_type: String,
    pub sha256_plaintext: String,
}

#[derive(Debug, Clone)]
pub struct PeerInboxEntry {
    pub message_id: String,
    pub variant: String,
    pub signing_cert_sha256: String,
    pub decrypted: bool,
    pub parts: Vec<PartDigest>,
}

/// A running peer.
pub struct Phase4Peer {
    container: ContainerAsync<GenericImage>,
    base: String,
    image: PinnedImage,
    version: PeerVersion,
    control: reqwest::Client,
}

impl std::fmt::Debug for Phase4Peer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Phase4Peer")
            .field("base", &self.base)
            .field("image", &self.image.reference())
            .field("phase4", &self.version.phase4)
            .finish_non_exhaustive()
    }
}

fn infra(msg: impl std::fmt::Display) -> HarnessError {
    HarnessError::infra(msg.to_string())
}

impl Phase4Peer {
    /// Resolve the image → write `/config` → start (with `host.docker.internal`
    /// → host-gateway) → poll `GET /control/health` → check `/control/version`.
    pub async fn start(config: PeerConfig<'_>) -> Result<Phase4Peer, HarnessError> {
        let image = match &config.image {
            Some(reference) => parse_pinned(reference),
            None => resolve_peer_image(),
        }
        .map_err(infra)?;

        let mut files = Vec::new();
        let mut entries = Vec::new();
        for variant in &config.variants {
            let (_, pki) = config
                .pki
                .iter()
                .find(|(v, _)| v == variant)
                .ok_or_else(|| infra(format!("no RunPki for variant {variant:?}")))?;
            let (variant_files, entry) = pki.phase4_config_files(variant);
            files.extend(variant_files);
            entries.push(entry);
        }
        let peer_json =
            serde_json::to_vec_pretty(&json!({ "variants": entries })).map_err(infra)?;

        let (name, tag) = image.testcontainers_name_tag();
        let mut request = GenericImage::new(name, tag)
            .with_exposed_port(8080.tcp())
            .with_host("host.docker.internal", Host::HostGateway)
            .with_copy_to("/config/peer.json", peer_json);
        for (path, bytes) in files {
            request = request.with_copy_to(path, bytes);
        }
        let container = request
            .start()
            .await
            .map_err(|e| infra(format!("start {}: {e}", image.reference())))?;
        let port = container
            .get_host_port_ipv4(8080.tcp())
            .await
            .map_err(|e| infra(format!("mapped port: {e}")))?;
        let base = format!("http://127.0.0.1:{port}");
        let control = reqwest::Client::builder()
            .timeout(Duration::from_secs(90))
            .build()
            .map_err(infra)?;

        // Readiness.
        let started = Instant::now();
        loop {
            let ready = control
                .get(format!("{base}/control/health"))
                .send()
                .await
                .is_ok_and(|r| r.status().is_success());
            if ready {
                break;
            }
            let running = container.is_running().await.unwrap_or(false);
            if !running || started.elapsed() > READINESS_TIMEOUT {
                let log = logs(&container).await;
                return Err(infra(format!(
                    "peer {} not healthy after {:?} (running: {running})\n--- peer log ---\n{log}",
                    image.reference(),
                    started.elapsed()
                )));
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        let startup = started.elapsed();

        let raw: Value = control
            .get(format!("{base}/control/version"))
            .send()
            .await
            .map_err(infra)?
            .json()
            .await
            .map_err(infra)?;
        let text = |k: &str| raw[k].as_str().unwrap_or_default().to_string();
        let version = PeerVersion {
            phase4: text("phase4"),
            peer: raw["peer"].as_str().map(str::to_string),
            java: text("java"),
            bouncycastle: text("bouncycastle"),
            raw: raw.clone(),
        };
        check_version(PHASE4_VERSION, &version.phase4).map_err(infra)?;
        check_clock_skew(&raw)?;
        println!(
            "phase4 peer: image {} phase4 {} java {} bc {} ready in {startup:?}",
            image.reference(),
            version.phase4,
            version.java,
            version.bouncycastle
        );
        Ok(Phase4Peer {
            container,
            base,
            image,
            version,
            control,
        })
    }

    /// The crate's `HttpClient` to this peer.
    pub fn http_client(&self) -> PeerHttp {
        PeerHttp::new(self.base.clone())
    }

    pub fn version(&self) -> &PeerVersion {
        &self.version
    }

    pub fn image(&self) -> &PinnedImage {
        &self.image
    }

    /// `http://127.0.0.1:<port>`.
    pub fn base_url(&self) -> &str {
        &self.base
    }

    /// `POST /control/send`: phase4's own profile sender.
    pub async fn send(&self, req: PeerSendRequest) -> Result<PeerSendResult, HarnessError> {
        let b64 = base64::engine::general_purpose::STANDARD;
        let body = json!({
            "variant": req.variant.id(),
            "toUrl": req.to_url,
            "messageId": req.message_id,
            "ping": req.ping,
            "encrypt": req.encrypt,
            "payloads": req.payloads.iter().map(|p| json!({
                "mimeType": p.mime_type,
                "base64": b64.encode(&p.bytes),
            })).collect::<Vec<_>>(),
        });
        let resp = self
            .control
            .post(format!("{}/control/send", self.base))
            .json(&body)
            .send()
            .await
            .map_err(infra)?;
        let status = resp.status();
        let value: Value = resp.json().await.map_err(infra)?;
        if !status.is_success() {
            return Err(infra(format!("/control/send answered {status}: {value}")));
        }
        Ok(PeerSendResult {
            phase4_result: value["result"].as_str().unwrap_or_default().to_string(),
            receipt: value["receiptBase64"]
                .as_str()
                .map(|s| b64.decode(s).map_err(infra))
                .transpose()?,
            receipt_content_type: value["receiptContentType"].as_str().map(str::to_string),
            error: value["error"].as_str().map(str::to_string),
        })
    }

    /// `GET /control/inbox/{id}`: `None` until phase4's SPI delivered it.
    pub async fn inbox(&self, message_id: &str) -> Result<Option<PeerInboxEntry>, HarnessError> {
        let resp = self
            .control
            .get(format!("{}/control/inbox/{message_id}", self.base))
            .send()
            .await
            .map_err(infra)?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        let v: Value = resp.json().await.map_err(infra)?;
        let s = |v: &Value, k: &str| v[k].as_str().unwrap_or_default().to_string();
        Ok(Some(PeerInboxEntry {
            message_id: s(&v, "messageId"),
            variant: s(&v, "variant"),
            signing_cert_sha256: s(&v, "signingCertSha256"),
            decrypted: v["decrypted"].as_bool().unwrap_or(false),
            parts: v["parts"]
                .as_array()
                .map(|parts| {
                    parts
                        .iter()
                        .map(|p| PartDigest {
                            content_id: s(p, "contentId"),
                            mime_type: s(p, "mimeType"),
                            sha256_plaintext: s(p, "sha256"),
                        })
                        .collect()
                })
                .unwrap_or_default(),
        }))
    }

    /// The peer's stdout and stderr so far.
    pub async fn log(&self) -> String {
        logs(&self.container).await
    }
}

async fn logs(container: &ContainerAsync<GenericImage>) -> String {
    let out = container.stdout_to_vec().await.unwrap_or_default();
    let err = container.stderr_to_vec().await.unwrap_or_default();
    format!(
        "{}{}",
        String::from_utf8_lossy(&out),
        String::from_utf8_lossy(&err)
    )
}

/// A case failure carrying context.
pub fn case(msg: impl Into<String>) -> HarnessError {
    HarnessError::Case(CaseFailure(msg.into()))
}
