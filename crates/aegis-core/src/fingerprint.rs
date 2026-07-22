//! Fingerprint-normalization policy.
//!
//! Spec §7. The design goal is **unlinkability through uniformity**, not random
//! spoofing. Every Aegis session of a given [`ProtectionLevel`] should look like
//! every other Aegis session — a large anonymity set — rather than a unique
//! random device. Consequently:
//!
//! * Values are *stable within a session* (same across main frame, iframes,
//!   workers, service workers, WebGL, Canvas, AudioContext). Inconsistency is
//!   itself a fingerprint (spec §7 "Stabilizacja").
//! * We *normalize / restrict* rather than fabricate hardware the VM does not
//!   have (spec §4 "Nie deklarować fikcyjnego modelu RTX czy Radeon").
//! * The User-Agent keeps the real engine version (spec §6, §14).

use serde::{Deserialize, Serialize};

/// The two supported protection levels. The UI must communicate that stronger
/// protection can reduce site compatibility (spec §7 "Dwa poziomy ochrony").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum ProtectionLevel {
    /// WebGL via virtual backend, WebRTC through proxy, basic normalization —
    /// most sites work normally.
    #[default]
    Balanced,
    /// Restricted/disabled WebGL, no WebGPU, stronger Canvas limiting,
    /// letterboxing, standard fonts — more privacy, more breakage.
    Strict,
}

impl ProtectionLevel {
    /// Short UI label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Balanced => "Balanced",
            Self::Strict => "Strict",
        }
    }

    /// The full normalization policy implied by this level.
    #[must_use]
    pub fn policy(self) -> FingerprintPolicy {
        match self {
            Self::Balanced => FingerprintPolicy::balanced(),
            Self::Strict => FingerprintPolicy::strict(),
        }
    }
}

/// How WebGL is exposed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum WebGlMode {
    /// Enabled through the virtual (virtio/software) backend, with the driver
    /// strings normalized to the real virtual environment (no fake RTX/Radeon).
    VirtualBackend,
    /// Enabled but with restricted parameter/extension exposure.
    Restricted,
    /// Disabled entirely.
    Disabled,
}

/// How Canvas readback is treated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CanvasMode {
    /// Pass through the real (virtualized) rendering. Stable within a session.
    Passthrough,
    /// Apply session-stable, uniform limiting to readback.
    Limited,
}

/// Screen/content-size rounding to shared buckets (letterboxing, spec §7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LetterboxMode {
    /// Report the exact virtualized viewport (still host-independent).
    Off,
    /// Round the content area to shared buckets so many users share a size.
    On,
}

/// The font-exposure strategy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FontPolicy {
    /// Expose a standard bundled font set only; never enumerate host fonts.
    /// (There are no host fonts in the VM to begin with — this makes the set
    /// uniform across sessions.)
    StandardSet,
}

/// The complete, serializable normalization policy for a session.
///
/// This structure is the single source of truth that `browser-launcher` renders
/// into Chromium managed policies / flags and (later) into the Firefox backend's
/// preferences. Keeping it declarative makes each control testable (spec §16:
/// "każdą ochronę potwierdzić testem automatycznym").
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FingerprintPolicy {
    /// The originating level, for display and audit.
    pub level: ProtectionLevel,
    /// WebGL exposure mode.
    pub webgl: WebGlMode,
    /// Whether WebGPU is available. Always disabled in Strict (spec §4, §7).
    pub webgpu_enabled: bool,
    /// Canvas readback treatment.
    pub canvas: CanvasMode,
    /// Letterboxing of the content area.
    pub letterbox: LetterboxMode,
    /// Font exposure strategy.
    pub fonts: FontPolicy,
    /// Timer precision: microseconds of coarsening applied to high-res timers.
    /// A fixed, stable value — never jittered per read (spec §7 "stała precyzja
    /// timerów"). Balanced uses 100µs; Strict uses 100 000µs (100 ms).
    pub timer_coarsening_us: u32,
    /// Whether `navigator.mediaDevices.enumerateDevices` is limited.
    pub limit_media_device_enumeration: bool,
    /// A fixed value reported for `navigator.hardwareConcurrency`, or `None` to
    /// expose the real (virtual) CPU count.
    pub hardware_concurrency: Option<u32>,
    /// Whether the Battery Status API is suppressed.
    pub disable_battery_api: bool,
    /// Whether motion/orientation/other sensor APIs are suppressed.
    pub disable_sensor_apis: bool,
    /// Whether Web Bluetooth / USB / Serial / HID / MIDI are blocked.
    pub block_device_apis: bool,
    /// A shared, canonical timezone for the session (IANA name), or `None` to
    /// use the tunnel/gateway-derived zone.
    pub timezone: Option<String>,
    /// A shared, canonical primary language tag (e.g. `en-US`).
    pub primary_language: String,
}

impl FingerprintPolicy {
    /// Balanced level: maximize compatibility while cutting host linkage.
    #[must_use]
    pub fn balanced() -> Self {
        Self {
            level: ProtectionLevel::Balanced,
            webgl: WebGlMode::VirtualBackend,
            webgpu_enabled: false,
            canvas: CanvasMode::Passthrough,
            letterbox: LetterboxMode::Off,
            fonts: FontPolicy::StandardSet,
            timer_coarsening_us: 100,
            limit_media_device_enumeration: true,
            hardware_concurrency: Some(4),
            disable_battery_api: true,
            disable_sensor_apis: true,
            block_device_apis: true,
            timezone: Some("UTC".into()),
            primary_language: "en-US".into(),
        }
    }

    /// Strict level: maximize uniformity/unlinkability, accept more breakage.
    #[must_use]
    pub fn strict() -> Self {
        Self {
            level: ProtectionLevel::Strict,
            webgl: WebGlMode::Disabled,
            webgpu_enabled: false,
            canvas: CanvasMode::Limited,
            letterbox: LetterboxMode::On,
            fonts: FontPolicy::StandardSet,
            timer_coarsening_us: 100_000,
            limit_media_device_enumeration: true,
            hardware_concurrency: Some(2),
            disable_battery_api: true,
            disable_sensor_apis: true,
            block_device_apis: true,
            timezone: Some("UTC".into()),
            primary_language: "en-US".into(),
        }
    }

    /// Compatibility level: the loosest normalization for maximum site
    /// compatibility. Still cuts host linkage (device APIs blocked, timezone and
    /// language pinned) but keeps WebGL and a realistic CPU count so demanding
    /// sites work. Maps to the `Balanced` protection level.
    #[must_use]
    pub fn compatibility() -> Self {
        Self {
            level: ProtectionLevel::Balanced,
            webgl: WebGlMode::VirtualBackend,
            webgpu_enabled: false,
            canvas: CanvasMode::Passthrough,
            letterbox: LetterboxMode::Off,
            fonts: FontPolicy::StandardSet,
            timer_coarsening_us: 20,
            limit_media_device_enumeration: true,
            hardware_concurrency: Some(8),
            disable_battery_api: true,
            disable_sensor_apis: true,
            block_device_apis: true,
            timezone: Some("UTC".into()),
            primary_language: "en-US".into(),
        }
    }

    /// Paranoid level: the tightest normalization. Everything the Strict level
    /// does, plus a fully disabled WebGL, limited Canvas, letterboxing, coarse
    /// timers and the smallest CPU count — maximum uniformity, most breakage.
    /// Maps to the `Strict` protection level.
    #[must_use]
    pub fn paranoid() -> Self {
        Self {
            level: ProtectionLevel::Strict,
            webgl: WebGlMode::Disabled,
            webgpu_enabled: false,
            canvas: CanvasMode::Limited,
            letterbox: LetterboxMode::On,
            fonts: FontPolicy::StandardSet,
            timer_coarsening_us: 100_000,
            limit_media_device_enumeration: true,
            hardware_concurrency: Some(2),
            disable_battery_api: true,
            disable_sensor_apis: true,
            block_device_apis: true,
            timezone: Some("UTC".into()),
            primary_language: "en-US".into(),
        }
    }

    /// Invariant checks the auditor relies on. Returns the reason if violated.
    ///
    /// These encode non-negotiable rules from the spec regardless of level:
    /// device APIs blocked, WebGPU off in Strict, sensors/battery suppressed.
    #[must_use]
    pub fn validate(&self) -> Option<&'static str> {
        if !self.block_device_apis {
            return Some("Bluetooth/USB/Serial/HID/MIDI must be blocked");
        }
        if self.level == ProtectionLevel::Strict && self.webgpu_enabled {
            return Some("WebGPU must be disabled in Strict mode");
        }
        if self.level == ProtectionLevel::Strict && self.webgl != WebGlMode::Disabled {
            // Strict permits Restricted or Disabled, but not a full backend.
            if self.webgl == WebGlMode::VirtualBackend {
                return Some("Strict mode must not expose a full WebGL backend");
            }
        }
        None
    }
}

impl Default for FingerprintPolicy {
    fn default() -> Self {
        Self::balanced()
    }
}

/// The four one-click safety presets shown in the UI ("how safe do you want to
/// be?"). Each maps to a concrete [`FingerprintPolicy`]; the user can then
/// expand "Advanced" to fine-tune individual switches on top of a preset.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum SafetyPreset {
    /// Loosest — maximum site compatibility.
    Compatibility,
    /// Sensible default — most sites work, good unlinkability.
    #[default]
    Balanced,
    /// Stronger — more uniform, some sites break.
    Strict,
    /// Tightest — maximum uniformity, expect breakage.
    Paranoid,
}

impl SafetyPreset {
    /// All presets in order (loosest → tightest), for building the UI.
    #[must_use]
    pub const fn all() -> [SafetyPreset; 4] {
        [
            Self::Compatibility,
            Self::Balanced,
            Self::Strict,
            Self::Paranoid,
        ]
    }

    /// The fingerprint policy this preset applies.
    #[must_use]
    pub fn policy(self) -> FingerprintPolicy {
        match self {
            Self::Compatibility => FingerprintPolicy::compatibility(),
            Self::Balanced => FingerprintPolicy::balanced(),
            Self::Strict => FingerprintPolicy::strict(),
            Self::Paranoid => FingerprintPolicy::paranoid(),
        }
    }

    /// The coarse protection level (used for the profile's `protection` field).
    #[must_use]
    pub const fn protection_level(self) -> ProtectionLevel {
        match self {
            Self::Compatibility | Self::Balanced => ProtectionLevel::Balanced,
            Self::Strict | Self::Paranoid => ProtectionLevel::Strict,
        }
    }

    /// Short UI label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Compatibility => "Compatibility",
            Self::Balanced => "Balanced",
            Self::Strict => "Strict",
            Self::Paranoid => "Paranoid",
        }
    }

    /// One-line description of the tradeoff.
    #[must_use]
    pub const fn description(self) -> &'static str {
        match self {
            Self::Compatibility => "Loosest — best site compatibility, still hides your host.",
            Self::Balanced => "Recommended — most sites work, strong unlinkability.",
            Self::Strict => "Stronger — more uniform fingerprint, some sites break.",
            Self::Paranoid => "Tightest — maximum uniformity, expect breakage.",
        }
    }
}

/// A representative User-Agent string for the chosen browser family.
///
/// Aegis does **not** spoof the User-Agent — the real engine version is always
/// preserved at runtime (spec §6, §14). This helper returns a *representative*
/// value purely so the UI's preview tab can show the shape of the UA a session
/// will present. The Firefox value matches the uniform Tor-Browser UA (which
/// keeps every Tor user's UA identical); the Chromium value is a recent stable
/// desktop UA. Callers should present it as representative, not exact.
#[must_use]
pub fn representative_user_agent(browser: crate::browser::BrowserBackendId) -> String {
    match browser {
        crate::browser::BrowserBackendId::Chromium => {
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
             (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
                .to_string()
        }
        crate::browser::BrowserBackendId::Firefox => {
            // The uniform Tor Browser / Firefox ESR UA.
            "Mozilla/5.0 (Windows NT 10.0; rv:128.0) Gecko/20100101 Firefox/128.0".to_string()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn levels_produce_valid_policies() {
        assert!(FingerprintPolicy::balanced().validate().is_none());
        assert!(FingerprintPolicy::strict().validate().is_none());
    }

    #[test]
    fn strict_disables_webgpu_and_full_webgl() {
        let p = FingerprintPolicy::strict();
        assert!(!p.webgpu_enabled);
        assert_ne!(p.webgl, WebGlMode::VirtualBackend);
        assert_eq!(p.letterbox, LetterboxMode::On);
    }

    #[test]
    fn device_apis_are_always_blocked() {
        for level in [ProtectionLevel::Balanced, ProtectionLevel::Strict] {
            assert!(level.policy().block_device_apis);
        }
    }

    #[test]
    fn validation_rejects_unblocked_devices() {
        let mut p = FingerprintPolicy::balanced();
        p.block_device_apis = false;
        assert!(p.validate().is_some());
    }
}
