//! Network-mode configuration: the outbound path every session is pinned to.
//!
//! Spec §5. The Browser VM has exactly one virtual NIC and can only reach the
//! Gateway VM. The gateway forces all traffic through one of three tunnels
//! (Tor / VPN / SOCKS5). No credential is ever stored in plaintext here — only a
//! [`CredentialRef`] pointing into secure storage (spec §16: "nie przechowywać
//! haseł proxy jawnie").

use serde::{Deserialize, Serialize};

/// Opaque handle to a secret held in secure storage.
///
/// Carries no secret material itself; it is an identifier the daemon resolves
/// against `secure-storage` at launch time. Safe to serialize into config files
/// and to log.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CredentialRef(pub String);

impl CredentialRef {
    /// Construct a reference from an identifier string.
    #[must_use]
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }
}

/// The outbound tunnel a session uses. Serialized tagged so config is explicit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum NetworkMode {
    /// Browser VM → Gateway VM → Tor → Internet. Strongest IP hiding.
    Tor(TorConfig),
    /// Browser VM → Gateway VM → VPN tunnel → Internet. Better compatibility.
    Vpn(VpnConfig),
    /// Browser VM → Gateway VM → SOCKS5/HTTP CONNECT → Internet. Must prove DNS
    /// and required protocols actually traverse the proxy before use (spec §5).
    Proxy(ProxyConfig),
}

impl NetworkMode {
    /// A short, stable label for UI/logs.
    #[must_use]
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Tor(_) => "Tor",
            Self::Vpn(_) => "VPN",
            Self::Proxy(_) => "Proxy",
        }
    }

    /// The DNS policy implied by this mode unless explicitly overridden.
    #[must_use]
    pub fn default_dns_policy(&self) -> DnsPolicy {
        match self {
            Self::Tor(_) => DnsPolicy::tor(),
            Self::Vpn(cfg) => DnsPolicy {
                mode: DnsMode::TunnelDns,
                servers: cfg.dns_servers.clone(),
                block_plain_dns: true,
            },
            Self::Proxy(cfg) => {
                if cfg.remote_dns {
                    DnsPolicy {
                        mode: DnsMode::ProxyRemote,
                        servers: Vec::new(),
                        block_plain_dns: true,
                    }
                } else {
                    // A proxy that cannot carry DNS remotely is a leak risk; the
                    // auditor must reject it. We still describe it as blocked so
                    // no plaintext DNS escapes the gateway.
                    DnsPolicy {
                        mode: DnsMode::ProxyRemote,
                        servers: Vec::new(),
                        block_plain_dns: true,
                    }
                }
            }
        }
    }
}

/// Tor tunnel configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct TorConfig {
    /// Whether to connect via pluggable-transport bridges.
    #[serde(default)]
    pub use_bridges: bool,
    /// Bridge lines (e.g. `obfs4 ...`). Never contain host identity.
    #[serde(default)]
    pub bridges: Vec<String>,
    /// Optional preferred exit-node country hint (best-effort only).
    #[serde(default)]
    pub exit_country: Option<String>,
}

/// VPN protocols supported by the gateway.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum VpnProtocol {
    /// WireGuard tunnel.
    WireGuard,
    /// OpenVPN tunnel.
    OpenVpn,
}

/// VPN tunnel configuration. Secrets are referenced, never inlined.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VpnConfig {
    /// Tunnel protocol.
    pub protocol: VpnProtocol,
    /// Endpoint host:port (public information).
    pub endpoint: String,
    /// Reference to the tunnel config/keys in secure storage.
    pub credentials_ref: CredentialRef,
    /// DNS servers to use inside the tunnel.
    #[serde(default)]
    pub dns_servers: Vec<String>,
}

/// Proxy protocols.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProxyProtocol {
    /// SOCKS5 (supports remote DNS via SOCKS5h).
    Socks5,
    /// HTTP CONNECT tunnel.
    HttpConnect,
}

/// Proxy tunnel configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProxyConfig {
    /// Proxy protocol.
    pub protocol: ProxyProtocol,
    /// Proxy host.
    pub host: String,
    /// Proxy port.
    pub port: u16,
    /// Optional reference to proxy credentials in secure storage.
    #[serde(default)]
    pub credentials_ref: Option<CredentialRef>,
    /// Whether the proxy resolves DNS remotely (SOCKS5h / CONNECT). Required to
    /// be `true` before the auditor will permit this mode.
    #[serde(default)]
    pub remote_dns: bool,
}

/// How DNS is resolved for a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DnsMode {
    /// Tor's `DNSPort`, with the gateway transparently redirecting all UDP/TCP
    /// port-53 traffic to it.
    TorDnsPort,
    /// DNS servers provided/pushed by the VPN tunnel.
    TunnelDns,
    /// DNS resolved remotely by the proxy (SOCKS5h / HTTP CONNECT).
    ProxyRemote,
    /// A fixed set of DNS servers reachable only through the tunnel.
    StaticDns,
}

/// DNS handling policy. `block_plain_dns` must always hold at the gateway so no
/// port-53 traffic can escape outside the chosen route (spec §5, §14).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsPolicy {
    /// Resolution mode.
    pub mode: DnsMode,
    /// Explicit DNS servers, if applicable.
    #[serde(default)]
    pub servers: Vec<String>,
    /// Whether the gateway blocks any plaintext DNS not going through the route.
    pub block_plain_dns: bool,
}

impl DnsPolicy {
    /// The canonical Tor DNS policy: capture all DNS to Tor's DNSPort.
    #[must_use]
    pub fn tor() -> Self {
        Self {
            mode: DnsMode::TorDnsPort,
            servers: Vec::new(),
            block_plain_dns: true,
        }
    }
}

/// IPv6 handling. Default is to block entirely; some VPNs can route it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum Ipv6Policy {
    /// Drop all IPv6 at the gateway (default — prevents v6 leaks; spec §5).
    #[default]
    Block,
    /// Route IPv6 through the tunnel (only when the tunnel genuinely supports it).
    RouteThroughTunnel,
}

/// The complete network configuration attached to a profile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// The tunnel mode and its parameters.
    pub mode: NetworkMode,
    /// DNS policy (defaults derived from `mode` when omitted).
    #[serde(default = "NetworkConfig::default_dns")]
    pub dns: DnsPolicy,
    /// IPv6 policy.
    #[serde(default)]
    pub ipv6: Ipv6Policy,
}

impl NetworkConfig {
    fn default_dns() -> DnsPolicy {
        DnsPolicy::tor()
    }

    /// Build a config for `mode`, deriving DNS/IPv6 policy from sensible defaults.
    #[must_use]
    pub fn from_mode(mode: NetworkMode) -> Self {
        let dns = mode.default_dns_policy();
        Self {
            mode,
            dns,
            ipv6: Ipv6Policy::Block,
        }
    }
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self::from_mode(NetworkMode::Tor(TorConfig::default()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tor_default_captures_dns_and_blocks_plain() {
        let cfg = NetworkConfig::default();
        assert_eq!(cfg.mode.label(), "Tor");
        assert_eq!(cfg.dns.mode, DnsMode::TorDnsPort);
        assert!(cfg.dns.block_plain_dns);
        assert_eq!(cfg.ipv6, Ipv6Policy::Block);
    }

    #[test]
    fn proxy_dns_always_blocks_plaintext() {
        let cfg = NetworkConfig::from_mode(NetworkMode::Proxy(ProxyConfig {
            protocol: ProxyProtocol::Socks5,
            host: "10.0.0.1".into(),
            port: 1080,
            credentials_ref: None,
            remote_dns: false,
        }));
        assert!(cfg.dns.block_plain_dns);
    }

    #[test]
    fn credentials_are_references_not_secrets() {
        let cfg = VpnConfig {
            protocol: VpnProtocol::WireGuard,
            endpoint: "vpn.example:51820".into(),
            credentials_ref: CredentialRef::new("vpn-key-1"),
            dns_servers: vec!["10.64.0.1".into()],
        };
        let json = serde_json::to_string(&cfg).unwrap();
        // The reference id is present; no secret bytes are.
        assert!(json.contains("vpn-key-1"));
    }
}
