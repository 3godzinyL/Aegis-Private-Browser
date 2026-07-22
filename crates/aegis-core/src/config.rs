//! Application configuration and storage-path resolution.
//!
//! Paths deliberately avoid embedding the host username in anything exposed to a
//! guest (spec §14: "brak ścieżek plików zawierających nazwę użytkownika
//! hosta"). Host-side config paths may of course reference the user's home; the
//! rule applies to paths that could reach the Browser VM.

use crate::fingerprint::ProtectionLevel;
use crate::network::NetworkMode;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// A reference to a signed VM base image on the host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImageRef {
    /// Path to the qcow2 base image.
    pub path: PathBuf,
    /// Path to the detached signature over the image.
    pub signature: PathBuf,
    /// The semantic version of the image.
    pub version: String,
    /// Lowercase hex SHA-256 of the image contents.
    pub sha256: String,
}

/// The pair of base images required for a session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImageSet {
    /// Gateway base image.
    pub gateway: ImageRef,
    /// Browser base image.
    pub browser: ImageRef,
}

/// Top-level application configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppConfig {
    /// Default network mode for new profiles.
    pub default_network: NetworkMode,
    /// Default protection level for new profiles.
    pub default_protection: ProtectionLevel,
    /// The isolated libvirt network name prefix.
    pub network_prefix: String,
    /// Base image set.
    #[serde(default)]
    pub images: Option<ImageSet>,
    /// The public key (hex ed25519) used to verify updates and image manifests.
    #[serde(default)]
    pub update_verify_key: Option<String>,
    /// Storage paths.
    pub paths: Paths,
    /// Which containment layers are mandatory (advanced). Defaults to the fully
    /// secure posture. Relaxing these enables the reduced host-browser mode so
    /// Aegis can run on hosts without a hypervisor (e.g. Windows dev machines).
    #[serde(default)]
    pub enforcement: Enforcement,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            default_network: NetworkMode::Tor(crate::network::TorConfig::default()),
            default_protection: ProtectionLevel::Balanced,
            network_prefix: "aegis".into(),
            images: None,
            update_verify_key: None,
            paths: Paths::default(),
            enforcement: Enforcement::default(),
        }
    }
}

/// Which containment layers Aegis insists on before it will let a session reach
/// the internet (spec §5, §16 — "priorytet: brak wycieku przed kompatybilnością").
///
/// The default is the **fully secure** posture: a session must run in a
/// dedicated Browser VM behind a Gateway VM. Relaxing these toggles trades
/// isolation for the ability to run on a host without a hypervisor. Every
/// relaxation is surfaced honestly to the user as *reduced protection* — the
/// UI never claims full anonymity in a reduced mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Enforcement {
    /// Require the browser to run in its own isolated VM. When `false`, the
    /// browser may run as a host process (no VM isolation — reduced protection).
    #[serde(default = "crate::config::default_true")]
    pub require_vm_isolation: bool,
    /// Require a dedicated Gateway VM for the network path. When `false`, the
    /// browser is routed through a proxy/Tor on the host instead.
    #[serde(default = "crate::config::default_true")]
    pub require_gateway: bool,
    /// Permit launching the browser directly on the host (through a verified
    /// proxy). This is the escape hatch that makes Aegis usable on Windows/macOS
    /// without KVM. Off by default.
    #[serde(default)]
    pub allow_host_browser: bool,
}

pub(crate) const fn default_true() -> bool {
    true
}

impl Default for Enforcement {
    fn default() -> Self {
        Self::secure()
    }
}

impl Enforcement {
    /// The fully-secure posture: VM isolation and gateway are both mandatory.
    #[must_use]
    pub const fn secure() -> Self {
        Self {
            require_vm_isolation: true,
            require_gateway: true,
            allow_host_browser: false,
        }
    }

    /// The reduced host-browser posture: no VM, no gateway VM; the browser runs
    /// on the host behind a proxy/Tor. Usable on hosts without a hypervisor.
    #[must_use]
    pub const fn host_browser() -> Self {
        Self {
            require_vm_isolation: false,
            require_gateway: false,
            allow_host_browser: true,
        }
    }

    /// Whether the full VM-isolation posture is in force.
    #[must_use]
    pub const fn is_full_isolation(&self) -> bool {
        self.require_vm_isolation && self.require_gateway
    }

    /// The isolation level a session will actually get under this policy.
    #[must_use]
    pub const fn isolation_level(&self) -> IsolationLevel {
        if self.is_full_isolation() {
            IsolationLevel::FullVm
        } else {
            IsolationLevel::HostProcess
        }
    }
}

/// How strongly the browser is isolated from the host in a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum IsolationLevel {
    /// The browser runs in a dedicated VM behind a gateway (full model).
    #[default]
    FullVm,
    /// The browser runs as a host process, routed through a proxy/Tor. No VM
    /// isolation — the site executes on the real OS. Reduced protection.
    HostProcess,
}

impl IsolationLevel {
    /// UI label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::FullVm => "full VM isolation",
            Self::HostProcess => "host process (reduced)",
        }
    }

    /// Whether this is the full VM-isolation model.
    #[must_use]
    pub const fn is_full(self) -> bool {
        matches!(self, Self::FullVm)
    }
}

/// Resolved storage locations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Paths {
    /// Directory holding persistent profile volumes (encrypted).
    pub profiles_dir: PathBuf,
    /// Directory for base images.
    pub images_dir: PathBuf,
    /// Ephemeral runtime directory (should be tmpfs / RAM-backed) for overlays
    /// and in-RAM keys of disposable sessions.
    pub runtime_dir: PathBuf,
    /// Append-only audit log path.
    pub audit_log: PathBuf,
    /// Daemon control socket path (unix) or endpoint descriptor (dev fallback).
    pub daemon_socket: PathBuf,
}

impl Default for Paths {
    fn default() -> Self {
        // Reasonable Linux defaults; the daemon overrides these from AppConfig.
        Self {
            profiles_dir: PathBuf::from("/var/lib/aegis/profiles"),
            images_dir: PathBuf::from("/var/lib/aegis/images"),
            runtime_dir: PathBuf::from("/run/aegis"),
            audit_log: PathBuf::from("/var/log/aegis/audit.jsonl"),
            daemon_socket: PathBuf::from("/run/aegis/daemon.sock"),
        }
    }
}

/// The rendering mode in effect for a session (diagnostics, spec §11).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RenderMode {
    /// Hardware-accelerated via virtio-gpu (virtualized, not host GPU).
    VirtioGpu,
    /// Software rendering.
    Software,
}

impl RenderMode {
    /// UI label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::VirtioGpu => "virtio-gpu",
            Self::Software => "software",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_roundtrips_toml() {
        let cfg = AppConfig::default();
        // Ensure the default config serializes and deserializes cleanly.
        let json = serde_json::to_string(&cfg).unwrap();
        let back: AppConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(cfg, back);
        assert_eq!(cfg.default_network.label(), "Tor");
    }

    #[test]
    fn enforcement_defaults_to_full_isolation() {
        let e = Enforcement::default();
        assert!(e.is_full_isolation());
        assert!(!e.allow_host_browser);
        assert_eq!(e.isolation_level(), IsolationLevel::FullVm);
    }

    #[test]
    fn host_browser_posture_is_reduced() {
        let e = Enforcement::host_browser();
        assert!(!e.is_full_isolation());
        assert!(e.allow_host_browser);
        assert_eq!(e.isolation_level(), IsolationLevel::HostProcess);
        assert!(!IsolationLevel::HostProcess.is_full());
    }

    #[test]
    fn omitted_enforcement_fields_default_true() {
        // A partial config that only flips allow_host_browser must still default
        // the require_* fields to true (field-level serde defaults), not false.
        let e: Enforcement = serde_json::from_str(r#"{"allow_host_browser":true}"#).unwrap();
        assert!(e.require_vm_isolation);
        assert!(e.require_gateway);
        assert!(e.allow_host_browser);
    }
}
