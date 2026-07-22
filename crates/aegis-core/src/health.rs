//! Generic health levels used by the diagnostics panel (spec §11).

use serde::{Deserialize, Serialize};

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
}

impl DiagnosticItem {
    /// Convenience constructor.
    #[must_use]
    pub fn new(key: impl Into<String>, level: HealthLevel, detail: impl Into<String>) -> Self {
        Self {
            key: key.into(),
            level,
            detail: detail.into(),
        }
    }
}
