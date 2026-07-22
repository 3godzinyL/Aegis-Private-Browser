//! Red-team: the firewall ruleset properties (spec §15.6 direct UDP outside the
//! proxy, §15.4 IPv6 leak) asserted against the *rendered* nftables scripts.
//!
//! The gateway firewall is a pure function
//! ([`gateway_controller::render_nftables`]): policy + config in, an exact `nft`
//! script out. That lets these red-team properties be proven by inspecting a
//! `String`, with no kernel and no root, exactly as the crate intends.

use aegis_core::gateway::{DefaultPolicy, FirewallPolicy, GatewayConfig};
use aegis_core::network::{DnsPolicy, Ipv6Policy, NetworkMode, TorConfig};
use gateway_controller::{render_killswitch, render_nftables};

/// A Tor gateway config (IPv6 blocked, Tor transparent redirects).
fn tor_cfg() -> GatewayConfig {
    GatewayConfig {
        mode: NetworkMode::Tor(TorConfig::default()),
        dns: DnsPolicy::tor(),
        ipv6: Ipv6Policy::Block,
        downstream_cidr: "10.152.152.0/24".into(),
        gateway_address: "10.152.152.1".into(),
    }
}

// ---------------------------------------------------------------------------
// §15.6 — a direct UDP send outside the proxy is dropped.
// ---------------------------------------------------------------------------

/// §15.6: the fail-closed ruleset defaults to `policy drop` on every base chain
/// and drops direct (non-tunnel) UDP from the browser subnet — so a WebRTC/QUIC
/// UDP datagram sent outside the proxy never leaves the gateway.
#[test]
fn s15_6_direct_udp_outside_proxy_is_dropped() {
    let cfg = tor_cfg();
    let policy = FirewallPolicy::fail_closed(&cfg);
    // The policy itself must validate (it is the one the orchestrator applies).
    assert!(
        policy.validate().is_none(),
        "§15.6: fail_closed policy must validate"
    );
    assert!(
        policy.block_direct_udp,
        "§15.6: policy must declare direct UDP blocked"
    );

    let ruleset = render_nftables(&policy, &cfg);

    // Default-deny on all three base chains (nothing is allowed unless a rule
    // explicitly permits it).
    assert_eq!(
        ruleset.matches("policy drop;").count(),
        3,
        "§15.6: input/forward/output must all default to drop"
    );
    assert!(
        ruleset.contains("policy drop"),
        "§15.6: the ruleset must contain a default `policy drop`"
    );

    // Direct UDP from the downstream browser subnet is explicitly dropped.
    assert!(
        ruleset.contains("meta l4proto udp drop"),
        "§15.6: direct (non-tunnel) UDP must be dropped"
    );
    assert!(
        ruleset.contains(&format!(
            "ip saddr {} meta l4proto udp drop",
            cfg.downstream_cidr
        )),
        "§15.6: the UDP drop must be scoped to the browser subnet"
    );
}

/// §15.6: an unsafe policy that would *permit* direct UDP is rejected by the
/// validator, so it can never be rendered/applied. (Fail-closed configuration.)
#[test]
fn s15_6_policy_permitting_direct_udp_is_rejected() {
    let cfg = tor_cfg();
    let mut bad = FirewallPolicy::fail_closed(&cfg);
    bad.block_direct_udp = false;
    assert_eq!(
        bad.validate(),
        Some("direct UDP must be blocked"),
        "§15.6: a policy that allows direct UDP must be rejected by validate()"
    );

    // Likewise an Accept default policy is rejected (no accidental open firewall).
    let mut accept = FirewallPolicy::fail_closed(&cfg);
    accept.default_policy = DefaultPolicy::Accept;
    assert!(
        accept.validate().is_some(),
        "§15.6: a default-accept policy must be rejected"
    );
}

/// §15.6: the kill switch is a *total* block — every base chain drops with no
/// accept and no redirect rules at all. When engaged, not even UDP that would
/// normally be tunnelled can move.
#[test]
fn s15_6_killswitch_is_total_block() {
    let ks = render_killswitch();
    assert_eq!(
        ks.matches("policy drop;").count(),
        3,
        "§15.6: kill switch must drop on all three base chains"
    );
    assert!(
        !ks.contains("accept"),
        "§15.6: kill switch must contain no accept rules"
    );
    assert!(
        !ks.contains("redirect"),
        "§15.6: kill switch must contain no redirect rules"
    );
    // No UDP is exempt because there are no rules at all beyond the default drop.
    assert!(
        !ks.contains("udp dport"),
        "§15.6: kill switch must not carve out any UDP path"
    );
}

// ---------------------------------------------------------------------------
// §15.4 — IPv6 leak (a DNS answer / route over IPv6 outside the tunnel).
// ---------------------------------------------------------------------------

/// §15.4: with the default (Block) IPv6 policy the rendered ruleset drops all
/// IPv6 outright on both the forward and output paths, so no v6 leak is possible.
#[test]
fn s15_4_ipv6_is_blocked_by_default() {
    let cfg = tor_cfg();
    assert_eq!(
        cfg.ipv6,
        Ipv6Policy::Block,
        "§15.4: default IPv6 policy is Block"
    );
    let policy = FirewallPolicy::fail_closed(&cfg);
    assert_eq!(policy.ipv6, Ipv6Policy::Block);

    let ruleset = render_nftables(&policy, &cfg);
    // IPv6 is dropped (documented + enforced). The forward and output chains each
    // carry a v6 drop, so there are at least two occurrences.
    assert!(
        ruleset.contains("meta nfproto ipv6 drop"),
        "§15.4: IPv6 must be dropped when the policy is Block"
    );
    assert!(
        ruleset.matches("meta nfproto ipv6 drop").count() >= 2,
        "§15.4: IPv6 drop must be enforced on both the forward and output paths"
    );
    // The rule is also documented (spec §14 'brak wycieku IPv6').
    assert!(
        ruleset.contains("no v6 leaks"),
        "§15.4: the IPv6 block must be documented in the ruleset"
    );
}

/// §15.4: when IPv6 is explicitly routed through the tunnel (a tunnel that
/// supports v6), the ruleset documents that choice instead of dropping — proving
/// the two v6 policies are distinct and neither silently leaks. Even then, direct
/// UDP is still dropped and the default remains drop.
#[test]
fn s15_4_ipv6_route_mode_is_documented_not_dropped() {
    let mut cfg = tor_cfg();
    cfg.ipv6 = Ipv6Policy::RouteThroughTunnel;
    let mut policy = FirewallPolicy::fail_closed(&cfg);
    policy.ipv6 = Ipv6Policy::RouteThroughTunnel;

    let ruleset = render_nftables(&policy, &cfg);
    assert!(
        !ruleset.contains("meta nfproto ipv6 drop"),
        "§15.4: route-through-tunnel mode must not drop v6 outright"
    );
    assert!(
        ruleset.contains("routed through the tunnel"),
        "§15.4: the route-through-tunnel choice must be documented"
    );
    // Containment properties still hold in this mode.
    assert!(
        ruleset.contains("meta l4proto udp drop"),
        "direct UDP still dropped"
    );
    assert_eq!(
        ruleset.matches("policy drop;").count(),
        3,
        "still default-deny"
    );
}

/// §15.4 + §15.6: host-initiated traffic outside the management channel is
/// rejected, closing the last leak vector on the gateway's own input path.
#[test]
fn s15_4_host_initiated_traffic_is_rejected() {
    let cfg = tor_cfg();
    let ruleset = render_nftables(&FirewallPolicy::fail_closed(&cfg), &cfg);
    assert!(
        ruleset.contains("reject with icmp type admin-prohibited"),
        "§15.4/§15.6: host-initiated traffic must be rejected"
    );
}
