//! Per-profile, per-origin permission policy (spec §9).
//!
//! Grants apply only to a given profile+origin and, for ephemeral profiles,
//! vanish when the session ends. The default policy is deny-heavy: dangerous
//! device classes (USB/Bluetooth/Serial/HID/MIDI) are blocked outright and
//! cannot be granted through the normal UI.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// A browser capability governed by policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Feature {
    /// Geolocation.
    Location,
    /// Camera capture.
    Camera,
    /// Microphone capture.
    Microphone,
    /// Web notifications.
    Notifications,
    /// Clipboard read.
    ClipboardRead,
    /// WebUSB.
    Usb,
    /// Web Bluetooth.
    Bluetooth,
    /// Web Serial.
    Serial,
    /// WebHID.
    Hid,
    /// Web MIDI.
    Midi,
    /// File System Access API.
    FileSystemAccess,
    /// Autoplay of media with sound.
    Autoplay,
    /// Downloads.
    Downloads,
}

impl Feature {
    /// Every governed feature, for building the default table and audits.
    #[must_use]
    pub const fn all() -> &'static [Feature] {
        use Feature::*;
        &[
            Location,
            Camera,
            Microphone,
            Notifications,
            ClipboardRead,
            Usb,
            Bluetooth,
            Serial,
            Hid,
            Midi,
            FileSystemAccess,
            Autoplay,
            Downloads,
        ]
    }

    /// Device classes that are *hard-blocked*: no UI path may grant them, in any
    /// mode (spec §7, §9). Attempting to grant returns an error.
    #[must_use]
    pub const fn is_hard_blocked(self) -> bool {
        matches!(
            self,
            Self::Usb | Self::Bluetooth | Self::Serial | Self::Hid | Self::Midi
        )
    }
}

/// The decision for a feature.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PermissionState {
    /// Always deny.
    Block,
    /// Prompt the user in-session (grant scoped to profile+origin).
    Ask,
    /// Allow (only reachable for non-hard-blocked features).
    Allow,
    /// Allow but constrained to a directory inside the VM (File System Access).
    ConfinedToVm,
    /// Route downloads to quarantine (Downloads).
    Quarantine,
    /// Limited behavior (Autoplay).
    Limited,
}

/// The complete permission policy for a profile: defaults plus per-origin grants.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PermissionPolicy {
    /// Default state per feature.
    pub defaults: BTreeMap<Feature, PermissionState>,
    /// Per-origin overrides: origin -> feature -> state.
    #[serde(default)]
    pub overrides: BTreeMap<String, BTreeMap<Feature, PermissionState>>,
}

impl PermissionPolicy {
    /// The spec §9 default table.
    #[must_use]
    pub fn secure_default() -> Self {
        use Feature::*;
        use PermissionState::*;
        let mut defaults = BTreeMap::new();
        defaults.insert(Location, Block);
        defaults.insert(Camera, Block);
        defaults.insert(Microphone, Block);
        defaults.insert(Notifications, Ask);
        defaults.insert(ClipboardRead, Block);
        defaults.insert(Usb, Block);
        defaults.insert(Bluetooth, Block);
        defaults.insert(Serial, Block);
        defaults.insert(Hid, Block);
        defaults.insert(Midi, Block);
        defaults.insert(FileSystemAccess, ConfinedToVm);
        defaults.insert(Autoplay, Limited);
        defaults.insert(Downloads, Quarantine);
        Self {
            defaults,
            overrides: BTreeMap::new(),
        }
    }

    /// Resolve the effective state for `feature` at `origin`.
    #[must_use]
    pub fn effective(&self, origin: &str, feature: Feature) -> PermissionState {
        if let Some(state) = self.overrides.get(origin).and_then(|m| m.get(&feature)) {
            return *state;
        }
        self.defaults
            .get(&feature)
            .copied()
            .unwrap_or(PermissionState::Block)
    }

    /// Grant a feature for an origin. Fails for hard-blocked device classes and
    /// only ever sets `Allow`/`ConfinedToVm` for features that permit it.
    ///
    /// # Errors
    /// Returns an error if `feature` is a hard-blocked device class.
    pub fn grant(&mut self, origin: &str, feature: Feature) -> crate::Result<()> {
        if feature.is_hard_blocked() {
            return Err(crate::Error::Precondition(format!(
                "feature {feature:?} is hard-blocked and cannot be granted"
            )));
        }
        let state = match feature {
            Feature::FileSystemAccess => PermissionState::ConfinedToVm,
            Feature::Downloads => PermissionState::Quarantine,
            _ => PermissionState::Allow,
        };
        self.overrides
            .entry(origin.to_string())
            .or_default()
            .insert(feature, state);
        Ok(())
    }

    /// Remove all per-origin grants (used when an ephemeral session ends).
    pub fn clear_grants(&mut self) {
        self.overrides.clear();
    }
}

impl Default for PermissionPolicy {
    fn default() -> Self {
        Self::secure_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_block_dangerous_devices() {
        let p = PermissionPolicy::secure_default();
        for f in [
            Feature::Usb,
            Feature::Bluetooth,
            Feature::Serial,
            Feature::Hid,
            Feature::Midi,
        ] {
            assert_eq!(p.effective("https://x", f), PermissionState::Block);
        }
        assert_eq!(
            p.effective("https://x", Feature::Camera),
            PermissionState::Block
        );
        assert_eq!(
            p.effective("https://x", Feature::Downloads),
            PermissionState::Quarantine
        );
    }

    #[test]
    fn cannot_grant_hard_blocked() {
        let mut p = PermissionPolicy::secure_default();
        assert!(p.grant("https://x", Feature::Usb).is_err());
        assert!(p.grant("https://x", Feature::Bluetooth).is_err());
    }

    #[test]
    fn grant_is_scoped_to_origin() {
        let mut p = PermissionPolicy::secure_default();
        p.grant("https://a.example", Feature::Notifications)
            .unwrap();
        assert_eq!(
            p.effective("https://a.example", Feature::Notifications),
            PermissionState::Allow
        );
        assert_eq!(
            p.effective("https://b.example", Feature::Notifications),
            PermissionState::Ask
        );
    }

    #[test]
    fn clearing_grants_restores_defaults() {
        let mut p = PermissionPolicy::secure_default();
        p.grant("https://a.example", Feature::Notifications)
            .unwrap();
        p.clear_grants();
        assert_eq!(
            p.effective("https://a.example", Feature::Notifications),
            PermissionState::Ask
        );
    }

    #[test]
    fn all_features_have_a_default() {
        let p = PermissionPolicy::secure_default();
        for f in Feature::all() {
            assert!(p.defaults.contains_key(f), "missing default for {f:?}");
        }
    }
}
