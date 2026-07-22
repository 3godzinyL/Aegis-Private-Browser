//! Generic health levels used by the diagnostics panel (spec §11).

use serde::{Deserialize, Serialize};

/// How strongly a value shown in diagnostics is backed by runtime evidence.
///
/// Keeping this separate from [`HealthLevel`] prevents a configured policy from
/// being presented as if the browser or gateway had actually been measured.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EvidenceState {
    /// The value comes from the requested profile or policy only.
    Configured,
    /// The value was observed at runtime but is not itself a passing guarantee.
    Measured,
    /// A runtime check verified the required property.
    Verified,
    /// No trustworthy runtime evidence is currently available.
    #[default]
    Unknown,
}

impl EvidenceState {
    /// Stable UI/API label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Configured => "configured",
            Self::Measured => "measured",
            Self::Verified => "verified",
            Self::Unknown => "unknown",
        }
    }
}

/// A tri-state health signal for a single subsystem shown in diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HealthLevel {
    /// Operating correctly.
    Ok,
    /// Working but degraded.
    Degraded,
    /// Not working / unsafe.
    Down,
    /// Not applicable / not measured.
    Unknown,
}

impl HealthLevel {
    /// UI label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Degraded => "degraded",
            Self::Down => "down",
            Self::Unknown => "unknown",
        }
    }
}

/// A named diagnostics item (subsystem + level + human detail).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiagnosticItem {
    /// Machine-readable key (e.g. `dns`, `ipv6`, `webrtc`, `render_mode`).
    pub key: String,
    /// Health level.
    pub level: HealthLevel,
    /// Human-readable detail (no secrets).
    pub detail: String,
    /// Provenance of the displayed value.
    #[serde(default)]
    pub evidence: EvidenceState,
}

impl DiagnosticItem {
    /// Convenience constructor.
    #[must_use]
    pub fn new(key: impl Into<String>, level: HealthLevel, detail: impl Into<String>) -> Self {
        Self {
            key: key.into(),
            level,
            detail: detail.into(),
            evidence: EvidenceState::Unknown,
        }
    }

    /// Attach an explicit evidence state to this item.
    #[must_use]
    pub const fn with_evidence(mut self, evidence: EvidenceState) -> Self {
        self.evidence = evidence;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diagnostic_evidence_defaults_to_unknown_for_compatibility() {
        let item = DiagnosticItem::new("dns", HealthLevel::Ok, "configured");
        assert_eq!(item.evidence, EvidenceState::Unknown);

        let json = serde_json::to_value(&item).unwrap();
        assert_eq!(json["evidence"], "unknown");
    }

    #[test]
    fn explicit_verified_evidence_roundtrips() {
        let item = DiagnosticItem::new("dns", HealthLevel::Ok, "probe passed")
            .with_evidence(EvidenceState::Verified);
        let json = serde_json::to_string(&item).unwrap();
        let decoded: DiagnosticItem = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.evidence, EvidenceState::Verified);
    }
}
