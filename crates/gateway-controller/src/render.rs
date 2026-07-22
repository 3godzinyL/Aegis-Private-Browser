//! Pure rendering of nftables rulesets from a declarative [`FirewallPolicy`].
//!
//! These functions perform **no I/O**: they turn policy + config into the exact
//! `nft` script the controller later feeds to `nft -f -`. Keeping them pure lets
//! the tests assert security properties (default drop, DNS capture, no direct
//! UDP, IPv6 dropped, kill-switch is a total block) by inspecting a `String`,
//! never by parsing kernel state.
//!
//! The generated ruleset implements the fail-closed network layer of spec §5:
//!
//! * base chains default to `policy drop`;
//! * established/related return traffic is allowed;
//! * loopback is allowed (intra-VM services such as Tor's DNSPort/TransPort);
//! * DNS is transparently redirected to the tunnel resolver
//!   ([`FirewallPolicy::redirect_dns_to`]);
//! * TCP from the downstream browser subnet is transparently redirected to the
//!   tunnel's TransPort ([`FirewallPolicy::redirect_tcp_to`]);
//! * direct (non-tunnel) UDP is dropped when
//!   [`FirewallPolicy::block_direct_udp`];
//! * IPv6 is dropped outright, or routed, per [`FirewallPolicy::ipv6`];
//! * host-initiated traffic outside the management channel is rejected;
//! * only the downstream browser subnet is granted a path toward the tunnel —
//!   nothing else forwards.

use aegis_core::gateway::{FirewallPolicy, GatewayConfig};
use aegis_core::network::Ipv6Policy;

/// The nftables table name Aegis owns. Isolated so we can `flush`/replace it
/// atomically without disturbing anything else on the gateway.
pub const TABLE: &str = "aegis";

/// The loopback interface allowed for intra-VM services (Tor ports live here).
const LOOPBACK: &str = "lo";

/// Render the complete fail-closed nftables ruleset for `policy` under `cfg`.
///
/// The returned script is safe to feed verbatim to `nft -f -`. It begins by
/// deleting any prior `aegis` table so application is idempotent, then rebuilds
/// the inet table with default-drop base chains.
#[must_use]
pub fn render_nftables(policy: &FirewallPolicy, cfg: &GatewayConfig) -> String {
    let mut s = String::new();
    let cidr = &cfg.downstream_cidr;

    // Idempotent replace: ignore the delete if the table is absent.
    s.push_str("#!/usr/sbin/nft -f\n");
    s.push_str("# Aegis Gateway fail-closed ruleset (spec §5). Generated; do not edit.\n");
    s.push_str(&format!("add table inet {TABLE}\n"));
    s.push_str(&format!("delete table inet {TABLE}\n"));
    s.push_str(&format!("table inet {TABLE} {{\n"));

    // ---- NAT (transparent redirects for DNS + TCP) ----------------------
    // The prerouting NAT chain rewrites destinations for downstream traffic so
    // the browser's DNS and TCP transparently enter the tunnel's local ports.
    s.push_str("\tchain prerouting {\n");
    s.push_str("\t\ttype nat hook prerouting priority dstnat; policy accept;\n");
    if let Some(dns_port) = policy.redirect_dns_to {
        // Capture ALL port-53 DNS (udp+tcp) from the browser subnet to the
        // tunnel resolver. No plaintext DNS may escape the gateway (spec §5).
        s.push_str(&format!(
            "\t\tip saddr {cidr} udp dport 53 redirect to :{dns_port}\n"
        ));
        s.push_str(&format!(
            "\t\tip saddr {cidr} tcp dport 53 redirect to :{dns_port}\n"
        ));
    }
    if let Some(tcp_port) = policy.redirect_tcp_to {
        // Everything else TCP from the browser subnet enters Tor's TransPort.
        s.push_str(&format!(
            "\t\tip saddr {cidr} tcp flags syn tcp dport != 53 redirect to :{tcp_port}\n"
        ));
    }
    s.push_str("\t}\n");

    // ---- INPUT (host/gateway-local) -------------------------------------
    // Traffic addressed to the gateway itself.
    s.push_str("\tchain input {\n");
    s.push_str("\t\ttype filter hook input priority filter; policy drop;\n");
    s.push_str("\t\tct state established,related accept\n");
    s.push_str(&format!("\t\tiif \"{LOOPBACK}\" accept\n"));
    // Allow the browser subnet to reach the gateway's redirect/resolver ports.
    if let Some(dns_port) = policy.redirect_dns_to {
        s.push_str(&format!(
            "\t\tip saddr {cidr} udp dport {dns_port} accept\n"
        ));
        s.push_str(&format!(
            "\t\tip saddr {cidr} tcp dport {dns_port} accept\n"
        ));
    }
    if let Some(tcp_port) = policy.redirect_tcp_to {
        s.push_str(&format!(
            "\t\tip saddr {cidr} tcp dport {tcp_port} accept\n"
        ));
    }
    if policy.reject_host_initiated {
        // Host-initiated traffic outside the management channel is rejected.
        // (The mgmt channel is a local Unix socket, not IP — see spec §5/§10 —
        // so nothing on the IP input path is host management traffic.)
        s.push_str("\t\t# reject host-initiated traffic (mgmt channel is a local unix socket)\n");
        s.push_str("\t\tmeta nfproto ipv4 reject with icmp type admin-prohibited\n");
    }
    s.push_str("\t}\n");

    // ---- FORWARD (browser subnet -> tunnel) -----------------------------
    // The only forwarding permitted is the browser subnet toward the tunnel.
    s.push_str("\tchain forward {\n");
    s.push_str("\t\ttype filter hook forward priority filter; policy drop;\n");
    s.push_str("\t\tct state established,related accept\n");

    // IPv6 handling: drop outright unless routing is explicitly permitted.
    match policy.ipv6 {
        Ipv6Policy::Block => {
            s.push_str("\t\t# IPv6 fully blocked at the gateway (no v6 leaks)\n");
            s.push_str("\t\tmeta nfproto ipv6 drop\n");
        }
        Ipv6Policy::RouteThroughTunnel => {
            s.push_str("\t\t# IPv6 routed through the tunnel (tunnel supports v6)\n");
            s.push_str("\t\tip6 saddr fe80::/10 ip6 daddr fe80::/10 accept\n");
        }
    }

    // Direct (non-tunnel) UDP from the browser subnet is dropped unless the
    // tunnel carries it. This prevents WebRTC/QUIC UDP leaks (spec §5).
    if policy.block_direct_udp {
        s.push_str("\t\t# drop direct UDP (only tunnel-carried UDP is permitted)\n");
        s.push_str(&format!("\t\tip saddr {cidr} meta l4proto udp drop\n"));
    }

    // Only the downstream browser subnet may forward (toward the tunnel).
    s.push_str("\t\t# only the downstream browser subnet may reach the tunnel\n");
    s.push_str(&format!("\t\tip saddr {cidr} accept\n"));
    // Everything else hits the default drop.
    s.push_str("\t}\n");

    // ---- OUTPUT (gateway-originated, e.g. Tor to the internet) ----------
    s.push_str("\tchain output {\n");
    s.push_str("\t\ttype filter hook output priority filter; policy drop;\n");
    s.push_str("\t\tct state established,related accept\n");
    s.push_str(&format!("\t\toif \"{LOOPBACK}\" accept\n"));
    match policy.ipv6 {
        Ipv6Policy::Block => {
            s.push_str("\t\tmeta nfproto ipv6 drop\n");
        }
        Ipv6Policy::RouteThroughTunnel => {}
    }
    // The gateway's own resolver/tunnel process is allowed out (Tor/VPN/proxy
    // originates the actual upstream connections).
    s.push_str("\t\tmeta nfproto ipv4 ct state new accept\n");
    s.push_str("\t}\n");

    s.push_str("}\n");
    s
}

/// Render the kill-switch ruleset: a total, unconditional block.
///
/// Engaging the kill switch swaps the normal ruleset for *this* one. Every base
/// chain drops, and there are **no accept rules at all** — not even for
/// established connections — so traffic is instantly and completely cut. This is
/// the fail-closed endpoint: any error in the network path lands here (spec §5,
/// §16: "awaria ma zawsze kończyć się blokadą, nigdy połączeniem bez ochrony").
#[must_use]
pub fn render_killswitch() -> String {
    let mut s = String::new();
    s.push_str("#!/usr/sbin/nft -f\n");
    s.push_str("# Aegis kill switch: total block. All chains drop, no exceptions.\n");
    s.push_str(&format!("add table inet {TABLE}\n"));
    s.push_str(&format!("delete table inet {TABLE}\n"));
    s.push_str(&format!("table inet {TABLE} {{\n"));
    for hook in ["input", "forward", "output"] {
        s.push_str(&format!("\tchain {hook} {{\n"));
        s.push_str(&format!(
            "\t\ttype filter hook {hook} priority filter; policy drop;\n"
        ));
        // Deliberately no rules: default drop is the whole story.
        s.push_str("\t}\n");
    }
    s.push_str("}\n");
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_core::gateway::DefaultPolicy;
    use aegis_core::network::{DnsPolicy, NetworkMode, TorConfig};

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
    fn renders_default_drop_on_every_base_chain() {
        let cfg = tor_cfg();
        let out = render_nftables(&FirewallPolicy::fail_closed(&cfg), &cfg);
        // Base filter chains all drop.
        assert!(out.contains("hook input priority filter; policy drop;"));
        assert!(out.contains("hook forward priority filter; policy drop;"));
        assert!(out.contains("hook output priority filter; policy drop;"));
        assert_eq!(out.matches("policy drop;").count(), 3);
    }

    #[test]
    fn renders_dns_and_tcp_redirects_for_tor() {
        let cfg = tor_cfg();
        let out = render_nftables(&FirewallPolicy::fail_closed(&cfg), &cfg);
        // DNS captured to Tor DNSPort (5353), TCP to TransPort (9040).
        assert!(out.contains("udp dport 53 redirect to :5353"));
        assert!(out.contains("tcp dport 53 redirect to :5353"));
        assert!(out.contains("redirect to :9040"));
    }

    #[test]
    fn blocks_direct_udp_and_ipv6_by_default() {
        let cfg = tor_cfg();
        let out = render_nftables(&FirewallPolicy::fail_closed(&cfg), &cfg);
        assert!(out.contains("meta l4proto udp drop"));
        assert!(out.contains("meta nfproto ipv6 drop"));
    }

    #[test]
    fn only_downstream_subnet_forwards() {
        let cfg = tor_cfg();
        let out = render_nftables(&FirewallPolicy::fail_closed(&cfg), &cfg);
        assert!(out.contains("ip saddr 10.152.152.0/24 accept"));
    }

    #[test]
    fn host_initiated_is_rejected() {
        let cfg = tor_cfg();
        let out = render_nftables(&FirewallPolicy::fail_closed(&cfg), &cfg);
        assert!(out.contains("reject with icmp type admin-prohibited"));
    }

    #[test]
    fn no_redirects_without_ports() {
        let cfg = GatewayConfig {
            mode: NetworkMode::Tor(TorConfig::default()),
            ..tor_cfg()
        };
        let policy = FirewallPolicy {
            default_policy: DefaultPolicy::Drop,
            redirect_dns_to: None,
            redirect_tcp_to: None,
            block_direct_udp: true,
            ipv6: Ipv6Policy::Block,
            reject_host_initiated: true,
        };
        let out = render_nftables(&policy, &cfg);
        assert!(!out.contains("redirect to"));
    }

    #[test]
    fn ipv6_route_mode_does_not_drop_v6() {
        let mut cfg = tor_cfg();
        cfg.ipv6 = Ipv6Policy::RouteThroughTunnel;
        let mut policy = FirewallPolicy::fail_closed(&cfg);
        policy.ipv6 = Ipv6Policy::RouteThroughTunnel;
        let out = render_nftables(&policy, &cfg);
        assert!(!out.contains("meta nfproto ipv6 drop"));
        assert!(out.contains("routed through the tunnel"));
    }

    #[test]
    fn killswitch_is_total_drop_with_no_accepts() {
        let out = render_killswitch();
        assert_eq!(out.matches("policy drop;").count(), 3);
        // A total block: no accept rules whatsoever.
        assert!(!out.contains("accept"));
        assert!(!out.contains("redirect"));
    }
}
