//! Which phase4 peer runs: an image pinned by digest, and the phase4 version
//! it reports checked at run time. Pure; no Docker access.

/// The phase4 release inside the pinned peer.
pub const PHASE4_VERSION: &str = "4.8.1";

/// The default peer: the local image id of the `4.8.1-r3` build recorded in
/// `tests/fixtures/phase4/PROVENANCE.md`. CI and `just interop` build the
/// image from `tests/fixtures/phase4` and pass its id in [`IMAGE_ENV`]; this
/// default resolves only on a machine that built that exact image, elsewhere
/// the run fails `INFRA:` (no such image), never passes.
pub const PHASE4_PEER_IMAGE: &str =
    "sha256:5d343139a158d5270f143819b9a3545664bd24070229399d22e0be25a32b8bc7";

/// The environment variable that overrides the compiled-in pin.
pub const IMAGE_ENV: &str = "ASX_PHASE4_IMAGE";

/// A resolved, pinned image reference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinnedImage {
    /// `registry/repository`, e.g. `ghcr.io/hupe1980/asx-phase4-peer`; `sha256` for a local id.
    pub name: String,
    /// e.g. `4.8.1-r1`; informational only.
    pub tag: Option<String>,
    /// `sha256:` + 64 lowercase hex.
    pub digest: String,
    /// A bare local image id (`sha256:<hex>`), not a registry reference.
    pub local_id: bool,
}

impl PinnedImage {
    /// The `(name, tag)` pair testcontainers renders as `name:tag`: a
    /// registry reference resolves by digest (`name:tag@sha256:…` or
    /// `name@sha256:…`), a local id as `sha256:<hex>`.
    pub fn testcontainers_name_tag(&self) -> (String, String) {
        if self.local_id {
            return (
                "sha256".to_string(),
                self.digest.trim_start_matches("sha256:").to_string(),
            );
        }
        match &self.tag {
            Some(tag) => (self.name.clone(), format!("{tag}@{}", self.digest)),
            // `name@sha256:<hex>` split at the last ':' renders back unchanged.
            None => {
                let full = format!("{}@{}", self.name, self.digest);
                let (n, t) = full.rsplit_once(':').expect("digest has a colon");
                (n.to_string(), t.to_string())
            }
        }
    }

    /// The reference as Docker writes it.
    pub fn reference(&self) -> String {
        let (name, tag) = self.testcontainers_name_tag();
        format!("{name}:{tag}")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImagePinError {
    /// No `@sha256:` digest (`latest`, a bare tag, no tag).
    Unpinned { reference: String },
    /// A digest that is not `sha256:` + 64 lowercase hex.
    MalformedDigest { reference: String },
    /// The peer reports a phase4 version other than the pinned one.
    VersionMismatch { expected: String, reported: String },
}

impl std::fmt::Display for ImagePinError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ImagePinError::Unpinned { reference } => write!(
                f,
                "image {reference:?} is not pinned: a counterparty image must be referenced as name[:tag]@sha256:<64 lowercase hex>"
            ),
            ImagePinError::MalformedDigest { reference } => write!(
                f,
                "image {reference:?} has a malformed digest: expected sha256:<64 lowercase hex>"
            ),
            ImagePinError::VersionMismatch { expected, reported } => write!(
                f,
                "the peer reports phase4 {reported:?}, the pin says {expected:?}"
            ),
        }
    }
}

impl std::error::Error for ImagePinError {}

fn is_sha256_digest(s: &str) -> bool {
    s.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}

fn looks_like_digest(s: &str) -> bool {
    s.to_ascii_lowercase().starts_with("sha256:")
}

/// Parse `reference`, accepting only `name[:tag]@sha256:<64 lowercase hex>`
/// or a bare local id `sha256:<64 lowercase hex>`.
pub fn parse_pinned(reference: &str) -> Result<PinnedImage, ImagePinError> {
    let refused = |e: fn(String) -> ImagePinError| Err(e(reference.to_string()));
    let reference_trimmed = reference.trim();
    if reference_trimmed.is_empty() {
        return refused(|reference| ImagePinError::Unpinned { reference });
    }

    // A bare local image id.
    if looks_like_digest(reference_trimmed) && !reference_trimmed.contains('@') {
        if !is_sha256_digest(reference_trimmed) {
            return refused(|reference| ImagePinError::MalformedDigest { reference });
        }
        return Ok(PinnedImage {
            name: "sha256".to_string(),
            tag: None,
            digest: reference_trimmed.to_string(),
            local_id: true,
        });
    }

    let Some((name_tag, digest)) = reference_trimmed.rsplit_once('@') else {
        return refused(|reference| ImagePinError::Unpinned { reference });
    };
    if !looks_like_digest(digest) {
        return refused(|reference| ImagePinError::Unpinned { reference });
    }
    if !is_sha256_digest(digest) {
        return refused(|reference| ImagePinError::MalformedDigest { reference });
    }
    // The tag separator is a ':' after the last '/' (a registry port is not a tag).
    let last_slash = name_tag.rfind('/').map_or(0, |i| i + 1);
    let (name, tag) = match name_tag[last_slash..].find(':') {
        Some(i) => (
            &name_tag[..last_slash + i],
            Some(name_tag[last_slash + i + 1..].to_string()),
        ),
        None => (name_tag, None),
    };
    if name.is_empty() || tag.as_deref() == Some("") {
        return refused(|reference| ImagePinError::Unpinned { reference });
    }
    Ok(PinnedImage {
        name: name.to_string(),
        tag,
        digest: digest.to_string(),
        local_id: false,
    })
}

/// The run-time half of the pin: the peer's reported phase4 version.
pub fn check_version(expected: &str, reported: &str) -> Result<(), ImagePinError> {
    if expected == reported {
        Ok(())
    } else {
        Err(ImagePinError::VersionMismatch {
            expected: expected.to_string(),
            reported: reported.to_string(),
        })
    }
}

/// `ASX_PHASE4_IMAGE` if set, else [`PHASE4_PEER_IMAGE`]; then [`parse_pinned`].
pub fn resolve_peer_image() -> Result<PinnedImage, ImagePinError> {
    let reference = std::env::var(IMAGE_ENV).unwrap_or_else(|_| PHASE4_PEER_IMAGE.to_string());
    parse_pinned(&reference)
}

#[cfg(test)]
mod tests {
    use super::*;

    const HEX: &str = "4f1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c";

    #[test]
    fn image_rejects_latest() {
        assert!(matches!(
            parse_pinned("ghcr.io/hupe1980/asx-phase4-peer:latest"),
            Err(ImagePinError::Unpinned { .. })
        ));
    }

    #[test]
    fn image_rejects_bare_tag() {
        assert!(matches!(
            parse_pinned("ghcr.io/hupe1980/asx-phase4-peer:4.8.1-r1"),
            Err(ImagePinError::Unpinned { .. })
        ));
    }

    #[test]
    fn image_rejects_no_digest() {
        assert!(matches!(
            parse_pinned("ghcr.io/hupe1980/asx-phase4-peer"),
            Err(ImagePinError::Unpinned { .. })
        ));
        assert!(matches!(
            parse_pinned(""),
            Err(ImagePinError::Unpinned { .. })
        ));
    }

    #[test]
    fn image_rejects_uppercase_digest() {
        let upper = HEX.to_ascii_uppercase();
        assert!(matches!(
            parse_pinned(&format!(
                "ghcr.io/hupe1980/asx-phase4-peer:4.8.1-r1@sha256:{upper}"
            )),
            Err(ImagePinError::MalformedDigest { .. })
        ));
        assert!(matches!(
            parse_pinned(&format!("sha256:{upper}")),
            Err(ImagePinError::MalformedDigest { .. })
        ));
    }

    #[test]
    fn image_rejects_short_digest() {
        assert!(matches!(
            parse_pinned(&format!(
                "ghcr.io/hupe1980/asx-phase4-peer@sha256:{}",
                &HEX[..63]
            )),
            Err(ImagePinError::MalformedDigest { .. })
        ));
        assert!(matches!(
            parse_pinned("sha256:abc"),
            Err(ImagePinError::MalformedDigest { .. })
        ));
    }

    #[test]
    fn image_accepts_name_tag_digest() {
        let reference = format!("ghcr.io/hupe1980/asx-phase4-peer:4.8.1-r1@sha256:{HEX}");
        let pinned = parse_pinned(&reference).expect("pinned");
        assert_eq!(pinned.name, "ghcr.io/hupe1980/asx-phase4-peer");
        assert_eq!(pinned.tag.as_deref(), Some("4.8.1-r1"));
        assert_eq!(pinned.digest, format!("sha256:{HEX}"));
        assert!(!pinned.local_id);
        assert_eq!(pinned.reference(), reference);
    }

    #[test]
    fn image_accepts_name_digest() {
        let reference = format!("localhost:5000/asx-phase4-peer@sha256:{HEX}");
        let pinned = parse_pinned(&reference).expect("pinned");
        assert_eq!(pinned.name, "localhost:5000/asx-phase4-peer");
        assert_eq!(pinned.tag, None);
        assert_eq!(pinned.reference(), reference);
    }

    #[test]
    fn image_accepts_local_id() {
        let pinned = parse_pinned(&format!("sha256:{HEX}")).expect("local id");
        assert!(pinned.local_id);
        assert_eq!(pinned.reference(), format!("sha256:{HEX}"));
    }

    #[test]
    fn image_version_mismatch_fails() {
        assert!(check_version(PHASE4_VERSION, "4.8.1").is_ok());
        assert_eq!(
            check_version(PHASE4_VERSION, "4.8.0"),
            Err(ImagePinError::VersionMismatch {
                expected: "4.8.1".into(),
                reported: "4.8.0".into()
            })
        );
    }

    #[test]
    fn image_compiled_in_pin_parses() {
        let pinned = parse_pinned(PHASE4_PEER_IMAGE).expect("the compiled-in pin is pinned");
        assert!(pinned.digest.starts_with("sha256:"));
        if let Some(tag) = &pinned.tag {
            assert!(tag.starts_with(PHASE4_VERSION), "{tag}");
        }
    }
}
