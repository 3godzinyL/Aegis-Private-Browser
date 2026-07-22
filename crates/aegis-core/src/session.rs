//! Session lifecycle: one gateway VM + one browser VM bound to a profile.
//!
//! Spec §8 disposable flow:
//! start → clone clean snapshot → random key in RAM → start gateway → start
//! browser → session → close processes → wipe key → destroy qcow2 layer.
//!
//! The state machine below makes the ordering explicit and enforces that the
//! browser is never `Browsing` unless preflight passed. Any failure transitions
//! to [`SessionState::Failed`], which the daemon treats as a kill-switch event.

use crate::ids::{ProfileId, SessionId};
use crate::preflight::ProtectionStatus;
use serde::{Deserialize, Serialize};

/// The lifecycle state of a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SessionState {
    /// Requested but nothing provisioned yet.
    Requested,
    /// Cloning the clean base snapshot and provisioning VMs.
    Provisioning,
    /// Gateway VM starting; tunnel establishing.
    GatewayStarting,
    /// Running the preflight connectivity checklist.
    Preflight,
    /// Browser VM launched and internet permitted (all checks passed).
    Browsing,
    /// Tearing down: closing processes, wiping keys, destroying overlays.
    Closing,
    /// Fully destroyed; nothing left behind.
    Destroyed,
    /// A failure occurred; connectivity has been cut. Terminal.
    Failed,
}

impl SessionState {
    /// The canonical successor states permitted from `self`.
    #[must_use]
    pub fn allowed_next(self) -> &'static [SessionState] {
        use SessionState::*;
        match self {
            Requested => &[Provisioning, Failed, Closing],
            Provisioning => &[GatewayStarting, Failed, Closing],
            GatewayStarting => &[Preflight, Failed, Closing],
            Preflight => &[Browsing, Failed, Closing],
            Browsing => &[Closing, Failed],
            Closing => &[Destroyed, Failed],
            Destroyed => &[],
            Failed => &[Closing, Destroyed],
        }
    }

    /// Whether a transition `self -> next` is permitted.
    #[must_use]
    pub fn can_transition_to(self, next: SessionState) -> bool {
        self.allowed_next().contains(&next)
    }

    /// Whether the session is in a terminal state.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Destroyed)
    }

    /// Whether the browser currently has live internet access.
    #[must_use]
    pub const fn is_browsing(self) -> bool {
        matches!(self, Self::Browsing)
    }
}

/// A request to start a session for a profile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionRequest {
    /// The profile to launch.
    pub profile: ProfileId,
    /// For persistent profiles, the reference to the unlock secret.
    #[serde(default)]
    pub unlock_ref: Option<crate::network::CredentialRef>,
}

/// A running/summary view of a session for the UI.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionSummary {
    /// Session id.
    pub id: SessionId,
    /// The profile it belongs to.
    pub profile: ProfileId,
    /// Current lifecycle state.
    pub state: SessionState,
    /// The aggregate protection status (from the last preflight/refresh).
    pub protection: ProtectionStatus,
    /// The observed public IP visible from the session, if known.
    #[serde(default)]
    pub public_ip: Option<String>,
}

impl SessionSummary {
    /// A session is only "safe to use" when browsing *and* protection is active.
    #[must_use]
    pub fn is_safe(&self) -> bool {
        self.state.is_browsing() && self.protection.permits_browsing()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn happy_path_transitions_are_allowed() {
        use SessionState::*;
        let path = [
            Requested,
            Provisioning,
            GatewayStarting,
            Preflight,
            Browsing,
            Closing,
            Destroyed,
        ];
        for pair in path.windows(2) {
            assert!(
                pair[0].can_transition_to(pair[1]),
                "{:?} -> {:?}",
                pair[0],
                pair[1]
            );
        }
    }

    #[test]
    fn cannot_skip_preflight_to_browsing() {
        assert!(!SessionState::GatewayStarting.can_transition_to(SessionState::Browsing));
    }

    #[test]
    fn any_state_can_fail() {
        use SessionState::*;
        for s in [
            Requested,
            Provisioning,
            GatewayStarting,
            Preflight,
            Browsing,
        ] {
            assert!(s.can_transition_to(Failed), "{s:?} must be able to fail");
        }
    }

    #[test]
    fn destroyed_is_terminal() {
        assert!(SessionState::Destroyed.is_terminal());
        assert!(SessionState::Destroyed.allowed_next().is_empty());
    }
}
