# Aegis Private Browser — Data-Flow Model

Status: Stage 0 (foundations).

This document describes how data moves through Aegis and, critically, **where it
must be cut**. The governing rule is fail-closed: if any containment guarantee
cannot be upheld, connectivity is severed rather than degraded (spec §16). For the
full list of host information that must be cut and *how*, see
[`host-info-to-cut.md`](./host-info-to-cut.md).

---

## 1. Structural data flow

```
┌──────────────────────────────────────────────────────────────────────────────┐
│ HOST (Linux; KVM/QEMU + libvirt)                                               │
│                                                                                │
│   Real NIC ── real public IP, real DNS, real MAC, LAN topology                 │
│      ▲                                                                          │
│      │ upstream: NAT network (host-facing)                                      │
│      │                                                                          │
│  ┌───┴──────────────┐        management (local Unix socket, authorized)        │
│  │  Aegis Manager   │◄───────────────────────────────────────────────┐        │
│  │  (+ privileged   │                                                 │        │
│  │   daemon,        │   provisions / controls / audits                │        │
│  │   NOT root)      │──────────────┬───────────────────────┐         │        │
│  │  · profile UI    │              │                       │         │        │
│  │  · VM controller │              ▼                       ▼         │        │
│  │  · config store  │      ┌───────────────┐       ┌───────────────┐ │        │
│  │  · updates       │      │  GATEWAY VM   │       │  BROWSER VM   │ │        │
│  │  · local audit   │      │               │       │               │ │        │
│  └──────────────────┘      │  NIC-up  ─────┼───►   │  (no upstream)│ │        │
│                            │  (to host NAT)│       │               │ │        │
│                            │               │       │  Chromium     │ │        │
│                            │  nftables     │       │  hardened     │ │        │
│                            │  DEFAULT DROP │       │  Linux        │ │        │
│                            │               │       │  read-only /  │ │        │
│                            │  Tor/VPN/SOCKS│       │  ephemeral    │ │        │
│                            │  DNS capture  │       │  overlay      │ │        │
│                            │  IPv6 block   │       │               │ │        │
│                            │  KILL SWITCH  │       │  ONE NIC ─────┼─┼───┐    │
│                            │  NIC-down ◄───┼───────┼──(only route) │ │   │    │
│                            └───────┬───────┘       └───────────────┘ │   │    │
│                                    │  isolated libvirt network       │   │    │
│                                    │  (aegis-net-<rand>, e.g.        │◄──────┘  │
│                                    │   10.152.152.0/24)              │          │
└────────────────────────────────────┼───────────────────────────────┼──────────┘
                                     │
                     tunnel egress  ▼   (Tor / VPN / SOCKS5 only)
                              ┌─────────────┐
                              │  INTERNET   │  ── sees the EXIT IP, never the host
                              └─────────────┘
```

Key structural facts (spec §3):

- The **Browser VM has exactly one NIC**, attached only to the isolated
  downstream network. It has **no** route to the host NIC and **no** alternative
  path to the Internet.
- The **Gateway VM is the only** component with an upstream path. Its firewall is
  default-deny; only tunnel traffic is allowed out.
- The **Manager/daemon** talks to the VMs over a management channel only; the
  gateway rejects any traffic the host initiates outside that channel
  (`reject_host_initiated`).

---

## 2. Request lifecycle (fail-closed gating)

```
User clicks "New private session"
        │
        ▼
[Requested] ── clone clean base snapshot, random key in RAM
        │
        ▼
[Provisioning] ── provision Gateway VM + Browser VM (IsolationPolicy::hardened)
        │
        ▼
[GatewayStarting] ── apply nftables DEFAULT DROP; bring up tunnel; capture DNS
        │
        ▼
[Preflight] ── run the 6 checks (see §3). ANY failure ─────────────┐
        │  all pass                                                 │
        ▼                                                           ▼
[Browsing] ── first tab allowed; ProtectionStatus::Active     [Failed]
        │                                                      (kill switch
        ▼                                                       engaged;
[Closing] ── terminate processes, wipe RAM key,                connectivity
        │    shred ephemeral qcow2 overlay                     cut)
        ▼
[Destroyed] ── nothing recoverable left behind
```

`session.rs` forbids `GatewayStarting -> Browsing`; the only path into `Browsing`
is through `Preflight`, and only `ProtectionStatus::Active` permits browsing. Any
state may transition to `Failed`, which the daemon treats as a kill-switch event.

---

## 3. The six preflight checks (the single NIC gate)

Before the first tab loads, the network auditor runs the fixed checklist
(`preflight.rs`, `CheckId`). A `Skipped` check counts as a failure.

| Check (`CheckId`) | Confirms |
|-------------------|----------|
| `gateway_ready` | Gateway VM up and reachable on the management channel. |
| `tunnel_ready` | Tor/VPN/SOCKS tunnel established. |
| `dns_route_verified` | DNS leaves only through the intended route. |
| `public_ip_observed` | An exit IP is visible from inside the VM **and differs from the host's real IP**. |
| `webrtc_policy_loaded` | The browser policy blocking non-proxied UDP is installed. |
| `ipv6_policy_verified` | IPv6 is blocked (or tunnel-only) and cannot leak. |

Aggregate outcome maps to `ProtectionStatus`: all pass → **Active** (browsing
permitted); gateway/tunnel missing → **None**; any containment check failing →
**Unsafe**. Only **Active** permits browsing.

---

## 4. What must be cut, and where

| Signal | Where it is cut | Mechanism |
|--------|-----------------|-----------|
| Real public IP | Gateway VM egress | All traffic forced through the tunnel; Browser VM never sees the host NIC. `public_ip_observed` asserts exit ≠ host IP. |
| Local IP / LAN / MAC | Browser VM boundary + browser | Fresh virtual NIC on an isolated network (`fresh_network_device`); WebRTC non-proxied-UDP policy prevents local-candidate leaks. |
| DNS queries | Gateway VM | Transparent capture/redirect; `block_plain_dns`; mode-specific `DnsMode` (Tor `DNSPort`, VPN tunnel DNS, SOCKS5h remote). |
| IPv6 | Gateway VM | `Ipv6Policy::Block` drops all IPv6, or routes only through a tunnel that genuinely supports it. |
| Direct/leaked UDP | Gateway firewall | `block_direct_udp` in `FirewallPolicy::fail_closed`. |
| Host-initiated traffic | Gateway firewall | `reject_host_initiated` — only the management channel is allowed. |
| Host hardware (GPU/camera/mic/USB/sensors) | VM boundary | `IsolationPolicy::hardened()`: no PCI/GPU/USB passthrough, no camera/mic; `GpuBackend::VirtioGpu`/`Software`. |
| Host fonts / OS / locale / timezone | Browser normalization | Standard bundled font set, shared timezone/language, letterboxing (see [`browser-api-table.md`](./browser-api-table.md)). |
| Cross-profile data | Profile store | Per-profile stores; ephemeral overlay shredded (`DestroyReport::is_clean`). |

---

## 5. Kill switch

The kill switch is the enforcement of fail-closed at the network layer
(`gateway.rs`).

```
tunnel UP ──► KillSwitchState::Armed ──► traffic permitted (Browser VM online)
     │
     │  tunnel drops / health check fails / containment error
     ▼
TunnelState::Failed ──► KillSwitchState::Engaged ──► ALL traffic cut
                                                     (Browser VM isolated;
                                                      NEVER falls back to a
                                                      direct connection)
```

`GatewayHealth::is_ready()` requires gateway up **and** firewall applied **and**
tunnel up **and** kill switch armed — all four. Errors classified as
`FailureClass::NetworkContainment` or `FailureClass::Isolation` engage the kill
switch **before** the error is surfaced. Red-team suites under `tests/network` and
`tests/destructive` exercise VPN-stop-mid-load, gateway restart, bad DNS, IPv6 DNS
answers, and STUN/UDP attempts (spec §15).
