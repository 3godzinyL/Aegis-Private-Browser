//! Browser-backend domain types (spec §6 "interfejs BrowserBackend").
//!
//! The [`crate::traits::BrowserBackend`] trait is what lets the MVP ship a
//! Chromium backend now and add a Firefox/Mullvad backend later without touching
//! the daemon. These types describe a launch request, the rendered policy
//! bundle, and a running handle.

use crate::config::RenderMode;
use crate::fingerprint::FingerprintPolicy;
use crate::ids::{ProfileId, SessionId};
use crate::permissions::PermissionPolicy;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;

/// Identifies a concrete browser backend implementation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BrowserBackendId {
    /// Hardened Chromium (MVP, spec §6 decision).
    Chromium,
    /// Firefox/Mullvad-based backend (planned, spec §6 Variant A).
    Firefox,
}

impl BrowserBackendId {
    /// UI label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Chromium => "Chromium",
            Self::Firefox => "Firefox/Mullvad",
        }
    }
}

/// Static capabilities advertised by a backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackendCapabilities {
    /// Whether the backend supports letterboxing.
    pub letterboxing: bool,
    /// Whether the backend enforces Site Isolation.
    pub site_isolation: bool,
    /// Whether the backend keeps an OS-process renderer sandbox.
    pub renderer_sandbox: bool,
    /// Whether the backend can enforce a WebRTC non-proxied-UDP block.
    pub webrtc_policy: bool,
}

/// A request to launch the browser for a session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrowserLaunchRequest {
    /// The owning session.
    pub session: SessionId,
    /// The profile providing settings.
    pub profile: ProfileId,
    /// The user-data directory INSIDE the browser VM (never a host path).
    pub user_data_dir: PathBuf,
    /// The resolved fingerprint policy.
    pub fingerprint: FingerprintPolicy,
    /// The permission policy.
    pub permissions: PermissionPolicy,
    /// The proxy/gateway address the browser must route through (the gateway).
    pub proxy_endpoint: String,
    /// The rendering mode to request.
    pub render_mode: RenderMode,
    /// Whether this is a production build (must forbid remote debugging).
    pub production: bool,
}

/// The rendered, backend-specific policy artifacts.
///
/// For Chromium this is a set of managed-policy JSON documents plus a vetted
/// command line. The launcher writes the policies into the managed-policy
/// directory inside the VM; nothing is applied via ad-hoc content scripts
/// (spec §6, §16).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackendPolicyBundle {
    /// Backend that produced the bundle.
    pub backend: BrowserBackendId,
    /// Managed policy documents keyed by filename.
    pub managed_policies: BTreeMap<String, serde_json::Value>,
    /// The exact command-line arguments (sandbox on, no remote debugging, etc.).
    pub command_line: Vec<String>,
    /// Preference/pref.js overrides (used by the Firefox backend).
    #[serde(default)]
    pub preferences: BTreeMap<String, serde_json::Value>,
}

impl BackendPolicyBundle {
    /// Assert the command line contains none of the forbidden flags (spec §16).
    ///
    /// # Errors
    /// Returns [`crate::Error::Config`] if a forbidden flag is present or a
    /// required guarantee (e.g. no remote debugging in production) is violated.
    pub fn assert_safe(&self, production: bool) -> crate::Result<()> {
        const FORBIDDEN: [&str; 3] = [
            "--no-sandbox",
            "--disable-web-security",
            "--disable-site-isolation-trials",
        ];
        for arg in &self.command_line {
            for bad in FORBIDDEN {
                if arg == bad || arg.starts_with(&format!("{bad}=")) {
                    return Err(crate::Error::Config(format!(
                        "forbidden browser flag: {arg}"
                    )));
                }
            }
            if production && arg.starts_with("--remote-debugging") {
                return Err(crate::Error::Config(
                    "remote debugging must not be enabled in production builds".into(),
                ));
            }
        }
        Ok(())
    }
}

/// A handle to a running browser process (inside the VM, addressed via the VM).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrowserHandle {
    /// The owning session.
    pub session: SessionId,
    /// The backend.
    pub backend: BrowserBackendId,
    /// An opaque process/agent token used to address the browser via the VM.
    pub process_token: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bundle(cmd: Vec<&str>) -> BackendPolicyBundle {
        BackendPolicyBundle {
            backend: BrowserBackendId::Chromium,
            managed_policies: BTreeMap::new(),
            command_line: cmd.into_iter().map(String::from).collect(),
            preferences: BTreeMap::new(),
        }
    }

    #[test]
    fn safe_command_line_passes() {
        let b = bundle(vec!["--enable-features=StrictOriginIsolation"]);
        assert!(b.assert_safe(true).is_ok());
    }

    #[test]
    fn no_sandbox_is_rejected() {
        assert!(bundle(vec!["--no-sandbox"]).assert_safe(true).is_err());
    }

    #[test]
    fn disable_web_security_is_rejected() {
        assert!(bundle(vec!["--disable-web-security"])
            .assert_safe(true)
            .is_err());
    }

    #[test]
    fn remote_debugging_rejected_in_production_only() {
        let b = bundle(vec!["--remote-debugging-port=9222"]);
        assert!(b.assert_safe(true).is_err());
        assert!(b.assert_safe(false).is_ok());
    }
}
