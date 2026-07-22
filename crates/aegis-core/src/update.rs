//! Update & integrity domain types (spec §5 Etap 5, §10, §14 "Aktualizacje").
//!
//! Every artifact (VM image, package) is described by a signed manifest. The
//! `update-client` crate verifies an ed25519 signature over the canonical
//! manifest bytes, checks each artifact's SHA-256, and refuses any version that
//! is not strictly newer than the installed one (downgrade protection). A
//! corrupt update triggers rollback.

use serde::{Deserialize, Serialize};
use std::fmt;

/// A simple, totally-ordered semantic version (major.minor.patch).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Version {
    /// Major.
    pub major: u32,
    /// Minor.
    pub minor: u32,
    /// Patch.
    pub patch: u32,
}

impl Version {
    /// Construct a version.
    #[must_use]
    pub const fn new(major: u32, minor: u32, patch: u32) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }

    /// Whether `self` is strictly newer than `other` (downgrade check).
    #[must_use]
    pub fn is_newer_than(&self, other: &Version) -> bool {
        self > other
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

impl std::str::FromStr for Version {
    type Err = crate::Error;
    fn from_str(s: &str) -> crate::Result<Self> {
        let mut it = s.trim().splitn(3, '.');
        let mut next = || -> crate::Result<u32> {
            it.next()
                .ok_or_else(|| crate::Error::Config(format!("invalid version: {s}")))?
                .parse()
                .map_err(|_| crate::Error::Config(format!("invalid version component in: {s}")))
        };
        Ok(Version::new(next()?, next()?, next()?))
    }
}

/// The kind of artifact an update carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ArtifactKind {
    /// A gateway VM base image.
    GatewayImage,
    /// A browser VM base image.
    BrowserImage,
    /// A host-side application package.
    AppPackage,
}

/// One artifact described by a manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Artifact {
    /// What it is.
    pub kind: ArtifactKind,
    /// Download path or URL (relative to the manifest base).
    pub location: String,
    /// Lowercase hex SHA-256 of the artifact bytes.
    pub sha256: String,
    /// Size in bytes.
    pub size: u64,
}

/// Whether an update is a full replacement or a binary delta.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum UpdateKind {
    /// Full artifact replacement.
    Full,
    /// Delta from a specific base version.
    Delta,
}

/// The signed update manifest.
///
/// The signature covers the canonical JSON serialization of everything EXCEPT
/// the `signature` field itself (see `update-client` for the canonicalization).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpdateManifest {
    /// Schema version of this manifest format.
    pub schema: u32,
    /// The product version this manifest publishes.
    pub version: Version,
    /// Minimum installed version required to apply a delta (for `Delta` kind).
    #[serde(default)]
    pub delta_base: Option<Version>,
    /// Full or delta.
    pub kind: UpdateKind,
    /// The artifacts.
    pub artifacts: Vec<Artifact>,
    /// Reference to the SBOM document for this release.
    #[serde(default)]
    pub sbom: Option<String>,
    /// Detached ed25519 signature over the canonical manifest bytes (hex).
    pub signature: String,
}

/// The verified outcome of checking a manifest + artifacts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifiedArtifact {
    /// The version being installed.
    pub version: Version,
    /// The verified artifacts (all hashes matched).
    pub artifacts: Vec<Artifact>,
}

/// The result of applying an update.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ApplyOutcome {
    /// Applied successfully.
    Applied,
    /// Rolled back after a failed apply; previous version intact.
    RolledBack,
}

/// Version info the client presents when checking for updates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct VersionInfo {
    /// The currently-installed product version.
    pub current: Version,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn version_ordering_and_parse() {
        assert!(Version::new(1, 2, 0).is_newer_than(&Version::new(1, 1, 9)));
        assert!(!Version::new(1, 0, 0).is_newer_than(&Version::new(1, 0, 0)));
        assert_eq!(Version::from_str("2.3.4").unwrap(), Version::new(2, 3, 4));
        assert!(Version::from_str("2.x").is_err());
    }

    #[test]
    fn manifest_roundtrips() {
        let m = UpdateManifest {
            schema: 1,
            version: Version::new(1, 0, 0),
            delta_base: None,
            kind: UpdateKind::Full,
            artifacts: vec![Artifact {
                kind: ArtifactKind::BrowserImage,
                location: "browser-1.0.0.qcow2".into(),
                sha256: "00".repeat(32),
                size: 42,
            }],
            sbom: Some("sbom-1.0.0.spdx.json".into()),
            signature: "ab".repeat(32),
        };
        let json = serde_json::to_string(&m).unwrap();
        let back: UpdateManifest = serde_json::from_str(&json).unwrap();
        assert_eq!(m, back);
    }
}
