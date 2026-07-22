//! Browsing profiles: the user-facing unit of isolation (spec §8, §11).
//!
//! A profile bundles a network mode, a protection level, and a permission
//! policy. Ephemeral profiles leave nothing behind; persistent profiles live in
//! an encrypted volume and can be re-opened, but never by two sessions at once
//! (spec §8: "brak możliwości współdzielenia profilu przez dwie jednoczesne
//! instancje").

use crate::fingerprint::ProtectionLevel;
use crate::ids::ProfileId;
use crate::network::NetworkConfig;
use crate::permissions::PermissionPolicy;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Whether a profile survives session end.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum ProfileType {
    /// Destroyed at session end — no writable residue, no recoverable data
    /// (spec §8 "Profile jednorazowe").
    #[default]
    Ephemeral,
    /// Stored in an encrypted volume, password-protected, re-openable.
    Persistent,
}

impl ProfileType {
    /// UI label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Ephemeral => "ephemeral",
            Self::Persistent => "persistent",
        }
    }

    /// Whether data must be shredded when the session closes.
    #[must_use]
    pub const fn is_ephemeral(self) -> bool {
        matches!(self, Self::Ephemeral)
    }
}

/// The specification used to create a profile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileSpec {
    /// Human-facing name.
    pub name: String,
    /// Ephemeral or persistent.
    pub kind: ProfileType,
    /// Network mode + DNS/IPv6 policy.
    pub network: NetworkConfig,
    /// Fingerprint protection level.
    pub protection: ProtectionLevel,
    /// Where this profile runs: a dedicated VM (full isolation, needs KVM) or a
    /// hardened host process routed through a proxy (works on Windows/macOS).
    /// Defaults to full VM isolation.
    #[serde(default)]
    pub isolation: crate::config::IsolationLevel,
    /// Permission policy (defaults to the secure table).
    #[serde(default)]
    pub permissions: PermissionPolicy,
}

impl ProfileSpec {
    /// A sensible default spec: an ephemeral, Tor, Balanced profile.
    #[must_use]
    pub fn ephemeral(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            kind: ProfileType::Ephemeral,
            network: NetworkConfig::default(),
            protection: ProtectionLevel::Balanced,
            isolation: crate::config::IsolationLevel::FullVm,
            permissions: PermissionPolicy::secure_default(),
        }
    }

    /// Builder: set the isolation level (full VM vs hardened host process).
    #[must_use]
    pub fn with_isolation(mut self, isolation: crate::config::IsolationLevel) -> Self {
        self.isolation = isolation;
        self
    }

    /// Validate the spec (name non-empty, fingerprint policy sane).
    ///
    /// # Errors
    /// Returns [`crate::Error::Config`] on invalid input.
    pub fn validate(&self) -> crate::Result<()> {
        if self.name.trim().is_empty() {
            return Err(crate::Error::Config(
                "profile name must not be empty".into(),
            ));
        }
        if let Some(reason) = self.protection.policy().validate() {
            return Err(crate::Error::Config(format!(
                "fingerprint policy invalid: {reason}"
            )));
        }
        Ok(())
    }
}

/// Disk usage accounting for a profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct StorageUsage {
    /// Bytes on disk for this profile's encrypted volume/overlay.
    pub bytes: u64,
}

impl StorageUsage {
    /// Human-readable size (base-1024).
    #[must_use]
    pub fn human(&self) -> String {
        const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
        let mut size = self.bytes as f64;
        let mut unit = 0;
        while size >= 1024.0 && unit < UNITS.len() - 1 {
            size /= 1024.0;
            unit += 1;
        }
        if unit == 0 {
            format!("{} {}", self.bytes, UNITS[0])
        } else {
            format!("{size:.1} {}", UNITS[unit])
        }
    }
}

/// A materialized profile with metadata for the profiles view (spec §11).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Profile {
    /// Stable id.
    pub id: ProfileId,
    /// The spec (name, kind, network, protection, permissions).
    pub spec: ProfileSpec,
    /// When the profile was created.
    pub created_at: DateTime<Utc>,
    /// Last time a session was launched from it (if ever).
    #[serde(default)]
    pub last_launched: Option<DateTime<Utc>>,
    /// Disk usage.
    #[serde(default)]
    pub storage: StorageUsage,
    /// Whether a session currently holds the single-writer lock.
    #[serde(default)]
    pub locked: bool,
}

impl Profile {
    /// Age of the profile relative to `now`.
    #[must_use]
    pub fn age(&self, now: DateTime<Utc>) -> chrono::Duration {
        now - self.created_at
    }

    /// Whether this profile can be opened by a new session (persistent profiles
    /// may not be opened twice concurrently; ephemeral are always fresh).
    #[must_use]
    pub fn can_open(&self) -> bool {
        !self.locked
    }
}

/// A patch applied to a profile's mutable settings.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfilePatch {
    /// New name.
    #[serde(default)]
    pub name: Option<String>,
    /// New network config.
    #[serde(default)]
    pub network: Option<NetworkConfig>,
    /// New protection level.
    #[serde(default)]
    pub protection: Option<ProtectionLevel>,
    /// Replacement permission policy.
    #[serde(default)]
    pub permissions: Option<PermissionPolicy>,
}

impl ProfilePatch {
    /// Whether the patch changes nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.name.is_none()
            && self.network.is_none()
            && self.protection.is_none()
            && self.permissions.is_none()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ephemeral_spec_is_valid() {
        let spec = ProfileSpec::ephemeral("shopping");
        assert!(spec.validate().is_ok());
        assert!(spec.kind.is_ephemeral());
    }

    #[test]
    fn empty_name_is_rejected() {
        let mut spec = ProfileSpec::ephemeral("  ");
        spec.name = "  ".into();
        assert!(spec.validate().is_err());
    }

    #[test]
    fn storage_human_readable() {
        assert_eq!(StorageUsage { bytes: 512 }.human(), "512 B");
        assert_eq!(StorageUsage { bytes: 2048 }.human(), "2.0 KiB");
        assert_eq!(
            StorageUsage {
                bytes: 5 * 1024 * 1024
            }
            .human(),
            "5.0 MiB"
        );
    }

    #[test]
    fn locked_profile_cannot_open() {
        let mut p = Profile {
            id: ProfileId::new(),
            spec: ProfileSpec::ephemeral("x"),
            created_at: Utc::now(),
            last_launched: None,
            storage: StorageUsage::default(),
            locked: false,
        };
        assert!(p.can_open());
        p.locked = true;
        assert!(!p.can_open());
    }
}
