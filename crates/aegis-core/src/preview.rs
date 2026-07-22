//! A human-readable preview of what a profile will present to websites.
//!
//! This powers the UI's **Preview** tab: before you create a session you can see
//! exactly the environment a site will observe — the (representative) User-Agent,
//! the pinned timezone and language, the WebGL/WebGPU/Canvas treatment, the
//! reported CPU count, which device APIs are blocked, the isolation level, and
//! the network route. Everything here is *derived* from the profile spec, so the
//! preview can never drift from what the launcher actually applies.

use crate::browser::BrowserBackendId;
use crate::config::IsolationLevel;
use crate::fingerprint::{CanvasMode, LetterboxMode, ProtectionLevel, WebGlMode};
use crate::profile::ProfileSpec;
use serde::{Deserialize, Serialize};

/// A resolved, display-friendly summary of a profile's observable properties.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfilePreview {
    /// Browser engine family.
    pub browser: BrowserBackendId,
    /// A representative User-Agent string (the real engine version is preserved
    /// at runtime — this is illustrative, not a spoof).
    pub user_agent: String,
    /// Isolation level (full VM vs host process).
    pub isolation: IsolationLevel,
    /// Human label for the isolation level.
    pub isolation_label: String,
    /// Network route label (Tor / VPN / Proxy).
    pub network: String,
    /// Coarse protection level.
    pub protection: ProtectionLevel,
    /// Pinned timezone (or "system-derived" when not pinned).
    pub timezone: String,
    /// Pinned primary language.
    pub language: String,
    /// Reported `navigator.hardwareConcurrency`, if fixed.
    pub hardware_concurrency: Option<u32>,
    /// WebGL treatment label.
    pub webgl: String,
    /// Whether WebGPU is exposed.
    pub webgpu_enabled: bool,
    /// Canvas treatment label.
    pub canvas: String,
    /// Whether letterboxing (window-size bucketing) is on.
    pub letterbox: bool,
    /// Timer coarsening in microseconds.
    pub timer_coarsening_us: u32,
    /// Whether Bluetooth/USB/Serial/HID/MIDI are blocked.
    pub device_apis_blocked: bool,
    /// Whether the media-device list is limited.
    pub limit_media_devices: bool,
    /// Whether the Battery Status API is suppressed.
    pub battery_disabled: bool,
    /// Whether motion/orientation sensors are suppressed.
    pub sensors_disabled: bool,
}

impl ProfilePreview {
    /// Derive a preview from a profile spec (never performs I/O).
    #[must_use]
    pub fn from_spec(spec: &ProfileSpec) -> Self {
        let fp = spec.resolved_fingerprint();
        Self {
            browser: spec.browser,
            user_agent: crate::fingerprint::representative_user_agent(spec.browser),
            isolation: spec.isolation,
            isolation_label: spec.isolation.label().to_string(),
            network: spec.network.mode.label().to_string(),
            protection: fp.level,
            timezone: fp
                .timezone
                .clone()
                .unwrap_or_else(|| "system-derived".into()),
            language: fp.primary_language.clone(),
            hardware_concurrency: fp.hardware_concurrency,
            webgl: match fp.webgl {
                WebGlMode::VirtualBackend => "virtual backend",
                WebGlMode::Restricted => "restricted",
                WebGlMode::Disabled => "disabled",
            }
            .to_string(),
            webgpu_enabled: fp.webgpu_enabled,
            canvas: match fp.canvas {
                CanvasMode::Passthrough => "passthrough",
                CanvasMode::Limited => "limited",
            }
            .to_string(),
            letterbox: matches!(fp.letterbox, LetterboxMode::On),
            timer_coarsening_us: fp.timer_coarsening_us,
            device_apis_blocked: fp.block_device_apis,
            limit_media_devices: fp.limit_media_device_enumeration,
            battery_disabled: fp.disable_battery_api,
            sensors_disabled: fp.disable_sensor_apis,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fingerprint::SafetyPreset;

    #[test]
    fn preview_reflects_preset_and_browser() {
        let mut spec = ProfileSpec::ephemeral("p");
        spec.browser = BrowserBackendId::Firefox;
        spec.fingerprint = Some(SafetyPreset::Paranoid.policy());
        let p = spec.preview();
        assert_eq!(p.browser, BrowserBackendId::Firefox);
        assert!(p.user_agent.contains("Firefox"));
        assert_eq!(p.webgl, "disabled");
        assert!(p.letterbox);
        assert!(p.device_apis_blocked);
    }

    #[test]
    fn preview_defaults_to_protection_level() {
        let spec = ProfileSpec::ephemeral("p"); // Balanced, Chromium, no override
        let p = spec.preview();
        assert_eq!(p.browser, BrowserBackendId::Chromium);
        assert!(p.user_agent.contains("Chrome"));
        assert_eq!(p.webgl, "virtual backend");
        assert_eq!(p.timezone, "UTC");
        assert_eq!(p.language, "en-US");
    }
}
