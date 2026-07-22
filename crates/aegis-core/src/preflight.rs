//! Preflight connectivity checks and the resulting protection status
//! (spec §5, §11).
//!
//! Before the first tab is allowed to load, the auditor runs a fixed checklist.
//! If ANY check fails, the browser does not get internet access — there is no
//! partial-pass path to a live session. The diagnostics panel renders the
//! aggregate as one of four labels (spec §11): protection active / partial /
//! unsafe / none. The UI must never claim "100% anonymous" (spec §11, §16).

use serde::{Deserialize, Serialize};
use std::fmt;

/// The six mandatory preflight checks (spec §5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckId {
    /// The gateway VM is up and reachable on the management channel.
    GatewayReady,
    /// The tunnel (Tor/VPN/proxy) is established.
    TunnelReady,
    /// DNS is verified to leave only through the intended route.
    DnsRouteVerified,
    /// A public IP was observed from inside the session (and it is not the
    /// host's real IP).
    PublicIpObserved,
    /// The browser's WebRTC policy that blocks non-proxied UDP is loaded.
    WebrtcPolicyLoaded,
    /// The IPv6 policy (block or tunnel-only) is verified in effect.
    Ipv6PolicyVerified,
}

impl CheckId {
    /// All checks, in execution order.
    #[must_use]
    pub const fn all() -> [CheckId; 6] {
        [
            CheckId::GatewayReady,
            CheckId::TunnelReady,
            CheckId::DnsRouteVerified,
            CheckId::PublicIpObserved,
            CheckId::WebrtcPolicyLoaded,
            CheckId::Ipv6PolicyVerified,
        ]
    }

    /// Whether this check protects network containment (a failure here is a hard
    /// stop that must engage the kill switch).
    #[must_use]
    pub const fn is_containment_critical(self) -> bool {
        // Every preflight check is containment-critical: none may be bypassed.
        true
    }

    /// The stable machine-readable name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::GatewayReady => "gateway_ready",
            Self::TunnelReady => "tunnel_ready",
            Self::DnsRouteVerified => "dns_route_verified",
            Self::PublicIpObserved => "public_ip_observed",
            Self::WebrtcPolicyLoaded => "webrtc_policy_loaded",
            Self::Ipv6PolicyVerified => "ipv6_policy_verified",
        }
    }
}

impl fmt::Display for CheckId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The outcome of a single check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CheckOutcome {
    /// The check passed.
    Pass,
    /// The check failed — containment cannot be guaranteed.
    Fail,
    /// The check could not run (dependency not ready). Treated as failure for
    /// gating purposes (fail-closed).
    Skipped,
}

impl CheckOutcome {
    /// Only `Pass` counts as satisfying the check (fail-closed).
    #[must_use]
    pub const fn is_pass(self) -> bool {
        matches!(self, Self::Pass)
    }
}

/// A single check's report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckReport {
    /// Which check.
    pub id: CheckId,
    /// The outcome.
    pub outcome: CheckOutcome,
    /// Human-readable detail (no secrets, no host identifiers).
    pub detail: String,
}

impl CheckReport {
    /// Construct a passing report.
    #[must_use]
    pub fn pass(id: CheckId, detail: impl Into<String>) -> Self {
        Self {
            id,
            outcome: CheckOutcome::Pass,
            detail: detail.into(),
        }
    }
    /// Construct a failing report.
    #[must_use]
    pub fn fail(id: CheckId, detail: impl Into<String>) -> Self {
        Self {
            id,
            outcome: CheckOutcome::Fail,
            detail: detail.into(),
        }
    }
    /// Construct a skipped report.
    #[must_use]
    pub fn skipped(id: CheckId, detail: impl Into<String>) -> Self {
        Self {
            id,
            outcome: CheckOutcome::Skipped,
            detail: detail.into(),
        }
    }
}

/// An observation of the session's apparent public IP (from inside the VM).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IpObservation {
    /// The observed exit IP as a string (may be redacted in logs).
    pub ip: String,
    /// Whether the observation was made through the tunnel.
    pub via_tunnel: bool,
    /// Whether it differs from the host's real public IP (must be true).
    pub differs_from_host: bool,
}

/// The four-state aggregate protection status shown to the user (spec §11).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProtectionStatus {
    /// All checks pass — protection active.
    Active,
    /// Core containment holds but some non-fatal item is degraded.
    Partial,
    /// A containment guarantee is not met — unsafe configuration.
    Unsafe,
    /// No protection in effect (no gateway/tunnel at all).
    None,
}

impl ProtectionStatus {
    /// The UI badge text (never "100% anonymous").
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Active => "protection active",
            Self::Partial => "partial protection",
            Self::Unsafe => "unsafe configuration",
            Self::None => "no protection",
        }
    }

    /// Whether a session may be allowed to reach the internet in this state.
    /// Only `Active` permits browsing (fail-closed).
    #[must_use]
    pub const fn permits_browsing(self) -> bool {
        matches!(self, Self::Active)
    }
}

/// The full checklist and its computed aggregate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectivityChecklist {
    /// Individual check reports, one per [`CheckId`].
    pub reports: Vec<CheckReport>,
    /// The observed public IP, if the `PublicIpObserved` check produced one.
    #[serde(default)]
    pub observed_ip: Option<IpObservation>,
}

impl ConnectivityChecklist {
    /// Build from a set of reports.
    #[must_use]
    pub fn new(reports: Vec<CheckReport>) -> Self {
        Self {
            reports,
            observed_ip: None,
        }
    }

    /// Find a specific report.
    #[must_use]
    pub fn report(&self, id: CheckId) -> Option<&CheckReport> {
        self.reports.iter().find(|r| r.id == id)
    }

    /// Whether every mandatory check passed.
    #[must_use]
    pub fn all_passed(&self) -> bool {
        CheckId::all().iter().all(|id| {
            self.report(*id)
                .map(|r| r.outcome.is_pass())
                .unwrap_or(false)
        })
    }

    /// The list of failing/missing checks.
    #[must_use]
    pub fn failures(&self) -> Vec<CheckId> {
        CheckId::all()
            .into_iter()
            .filter(|id| {
                !self
                    .report(*id)
                    .map(|r| r.outcome.is_pass())
                    .unwrap_or(false)
            })
            .collect()
    }

    /// Compute the aggregate protection status.
    ///
    /// Logic (fail-closed):
    /// * all pass → `Active`.
    /// * gateway or tunnel missing → `None`.
    /// * any containment check fails → `Unsafe`.
    #[must_use]
    pub fn status(&self) -> ProtectionStatus {
        if self.all_passed() {
            return ProtectionStatus::Active;
        }
        let gw = self
            .report(CheckId::GatewayReady)
            .map(|r| r.outcome.is_pass())
            .unwrap_or(false);
        let tun = self
            .report(CheckId::TunnelReady)
            .map(|r| r.outcome.is_pass())
            .unwrap_or(false);
        if !gw || !tun {
            return ProtectionStatus::None;
        }
        // Gateway + tunnel are up but a leak-relevant check failed.
        ProtectionStatus::Unsafe
    }

    /// Whether browsing may proceed (only when status is `Active`).
    #[must_use]
    pub fn permits_browsing(&self) -> bool {
        self.status().permits_browsing()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn all_pass() -> Vec<CheckReport> {
        CheckId::all()
            .into_iter()
            .map(|id| CheckReport::pass(id, "ok"))
            .collect()
    }

    #[test]
    fn all_pass_is_active_and_permits() {
        let cl = ConnectivityChecklist::new(all_pass());
        assert!(cl.all_passed());
        assert_eq!(cl.status(), ProtectionStatus::Active);
        assert!(cl.permits_browsing());
    }

    #[test]
    fn dns_failure_is_unsafe_and_blocks() {
        let mut reports = all_pass();
        // Fail DNS route.
        for r in &mut reports {
            if r.id == CheckId::DnsRouteVerified {
                r.outcome = CheckOutcome::Fail;
            }
        }
        let cl = ConnectivityChecklist::new(reports);
        assert_eq!(cl.status(), ProtectionStatus::Unsafe);
        assert!(!cl.permits_browsing());
        assert!(cl.failures().contains(&CheckId::DnsRouteVerified));
    }

    #[test]
    fn no_gateway_is_none() {
        let mut reports = all_pass();
        for r in &mut reports {
            if r.id == CheckId::GatewayReady {
                r.outcome = CheckOutcome::Fail;
            }
        }
        let cl = ConnectivityChecklist::new(reports);
        assert_eq!(cl.status(), ProtectionStatus::None);
        assert!(!cl.permits_browsing());
    }

    #[test]
    fn skipped_counts_as_not_passed() {
        let mut reports = all_pass();
        for r in &mut reports {
            if r.id == CheckId::WebrtcPolicyLoaded {
                r.outcome = CheckOutcome::Skipped;
            }
        }
        let cl = ConnectivityChecklist::new(reports);
        assert!(!cl.all_passed());
        assert!(!cl.permits_browsing());
    }
}
