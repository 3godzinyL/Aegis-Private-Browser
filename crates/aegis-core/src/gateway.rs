//! Gateway configuration, firewall policy, tunnel health, and kill switch
//! (spec §5, §10).
//!
//! The gateway is the only component with an upstream path to the host network.
//! Its firewall is default-deny; only traffic through the configured tunnel is
//! allowed. If the tunnel drops, the kill switch engages and the Browser VM is
//! instantly isolated — never allowed to fall back to a direct connection
//! (spec §16: "awaria ma zawsze kończyć się blokadą, nigdy połączeniem bez
//! ochrony").

use crate::network::{DnsPolicy, Ipv6Policy, NetworkMode};
use serde::{Deserialize, Serialize};

/// Complete gateway configuration derived from a profile's network settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GatewayConfig {
    /// The tunnel mode.
    pub mode: NetworkMode,
    /// DNS policy.
    pub dns: DnsPolicy,
    /// IPv6 policy.
    pub ipv6: Ipv6Policy,
    /// The downstream (browser-facing) network CIDR, e.g. `10.152.152.0/24`.
    pub downstream_cidr: String,
    /// The gateway's downstream address the Browser VM routes through.
    pub gateway_address: String,
}

/// A declarative firewall policy the gateway renders into nftables.
///
/// This is intentionally high-level: `gateway-controller` compiles it into the
/// concrete ruleset in `firewall/nftables`. Keeping it declarative lets tests
/// assert properties ("default policy is drop", "no direct UDP allowed") without
/// parsing nft syntax.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FirewallPolicy {
    /// The base policy for the forward/output chains. Must be `Drop`.
    pub default_policy: DefaultPolicy,
    /// Transparent-proxy redirect targets (e.g. Tor TransPort/DNSPort).
    pub redirect_dns_to: Option<u16>,
    /// Transparent TCP redirect target port, if any (Tor TransPort).
    pub redirect_tcp_to: Option<u16>,
    /// Whether direct (non-tunnel) UDP is blocked.
    pub block_direct_udp: bool,
    /// IPv6 handling.
    pub ipv6: Ipv6Policy,
    /// Whether traffic initiated from the host (outside the management channel)
    /// is rejected.
    pub reject_host_initiated: bool,
}

/// Base chain policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DefaultPolicy {
    /// Drop everything not explicitly allowed (the only acceptable value).
    Drop,
    /// Accept by default — never used; present only to make misconfiguration
    /// representable so the validator can reject it.
    Accept,
}

impl FirewallPolicy {
    /// Build the fail-closed policy for a gateway configuration.
    #[must_use]
    pub fn fail_closed(cfg: &GatewayConfig) -> Self {
        let (redirect_dns_to, redirect_tcp_to) = match &cfg.mode {
            NetworkMode::Tor(_) => (Some(5353), Some(9040)), // DNSPort, TransPort
            _ => (None, None),
        };
        Self {
            default_policy: DefaultPolicy::Drop,
            redirect_dns_to,
            redirect_tcp_to,
            block_direct_udp: true,
            ipv6: cfg.ipv6,
            reject_host_initiated: true,
        }
    }

    /// Validate that the policy cannot leak. Returns a reason if unsafe.
    #[must_use]
    pub fn validate(&self) -> Option<&'static str> {
        if self.default_policy != DefaultPolicy::Drop {
            return Some("firewall default policy must be Drop");
        }
        if !self.block_direct_udp {
            return Some("direct UDP must be blocked");
        }
        if !self.reject_host_initiated {
            return Some("host-initiated traffic must be rejected");
        }
        None
    }
}

/// The state of the tunnel to the outside world.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TunnelState {
    /// Not yet established.
    Down,
    /// Establishing (Tor bootstrapping, VPN handshaking).
    Connecting,
    /// Established and carrying traffic.
    Up,
    /// Was up, now failed — kill switch must be engaged.
    Failed,
}

impl TunnelState {
    /// Whether the tunnel is fully usable.
    #[must_use]
    pub const fn is_up(self) -> bool {
        matches!(self, Self::Up)
    }
}

/// A snapshot of tunnel status.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TunnelStatus {
    /// Current state.
    pub state: TunnelState,
    /// For Tor, bootstrap percentage 0..=100.
    #[serde(default)]
    pub bootstrap_percent: Option<u8>,
    /// A short human-readable detail (never contains secrets).
    #[serde(default)]
    pub detail: Option<String>,
}

impl TunnelStatus {
    /// A convenience constructor for a fully-up tunnel.
    #[must_use]
    pub fn up() -> Self {
        Self {
            state: TunnelState::Up,
            bootstrap_percent: Some(100),
            detail: None,
        }
    }
}

/// Kill-switch state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum KillSwitchState {
    /// Traffic is permitted through the tunnel (normal operation).
    Armed,
    /// Traffic is fully cut — the browser is isolated.
    Engaged,
}

impl KillSwitchState {
    /// Whether connectivity is currently permitted.
    #[must_use]
    pub const fn allows_traffic(self) -> bool {
        matches!(self, Self::Armed)
    }
}

/// Aggregate gateway health used by the diagnostics panel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GatewayHealth {
    /// Whether the gateway domain is running.
    pub gateway_up: bool,
    /// Firewall applied and validated.
    pub firewall_applied: bool,
    /// Tunnel status.
    pub tunnel: TunnelStatus,
    /// Kill-switch state.
    pub killswitch: KillSwitchState,
}

impl GatewayHealth {
    /// Whether the gateway is in a safe-to-browse state.
    #[must_use]
    pub fn is_ready(&self) -> bool {
        self.gateway_up
            && self.firewall_applied
            && self.tunnel.state.is_up()
            && self.killswitch.allows_traffic()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::TorConfig;

    fn tor_cfg() -> GatewayConfig {
        GatewayConfig {
            mode: NetworkMode::Tor(TorConfig::default()),
            dns: DnsPolicy::tor(),
            ipv6: Ipv6Policy::Block,
            downstream_cidr: "10.152.152.0/24".into(),
            gateway_address: "10.152.152.1".into(),
        }
    }

    #[test]
    fn fail_closed_policy_is_valid_and_drops() {
        let fw = FirewallPolicy::fail_closed(&tor_cfg());
        assert_eq!(fw.default_policy, DefaultPolicy::Drop);
        assert!(fw.block_direct_udp);
        assert!(fw.validate().is_none());
        // Tor mode wires transparent redirects.
        assert_eq!(fw.redirect_dns_to, Some(5353));
        assert_eq!(fw.redirect_tcp_to, Some(9040));
    }

    #[test]
    fn accept_default_is_rejected() {
        let mut fw = FirewallPolicy::fail_closed(&tor_cfg());
        fw.default_policy = DefaultPolicy::Accept;
        assert!(fw.validate().is_some());
    }

    #[test]
    fn health_requires_everything() {
        let mut h = GatewayHealth {
            gateway_up: true,
            firewall_applied: true,
            tunnel: TunnelStatus::up(),
            killswitch: KillSwitchState::Armed,
        };
        assert!(h.is_ready());
        h.killswitch = KillSwitchState::Engaged;
        assert!(!h.is_ready());
    }
}
