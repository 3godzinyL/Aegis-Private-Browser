# Gateway VM firewall

The Aegis Gateway VM is a Whonix-style network gateway: the **only** component
with a path to the host network, running a **default-deny** nftables firewall so
the Browser VM can reach the Internet **exclusively** through the configured
tunnel (Tor by default). If the tunnel drops, the kill switch isolates the
browser instantly — it never falls back to a direct connection
(`promt.txt` §5, §16: *"awaria ma zawsze kończyć się blokadą, nigdy połączeniem
bez ochrony"*).

```
 Host NAT ── [ eth0 / upstream ] ── Gateway VM ── [ eth1 / downstream ] ── Browser VM
                                                    10.152.152.0/24 (gw .1)   one NIC only
```

The Browser VM has exactly one NIC whose only route is `10.152.152.1`. It never
sees the host's physical interface or the real public IP (§3).

## Files

| File | Table(s) | Role |
| --- | --- | --- |
| [`nftables/gateway.nft`](nftables/gateway.nft) | `inet filter` | Default-deny input/forward/output; loopback + established; browser subnet only toward the local transparent proxy; drop everything else. |
| [`nftables/nat-tor.nft`](nftables/nat-tor.nft) | `ip nat` | Redirect browser-subnet DNS (udp/tcp 53) → Tor DNSPort and TCP → Tor TransPort. Documents the paired `torrc`. |
| [`nftables/ipv6-block.nft`](nftables/ipv6-block.nft) | `ip6 filter` | Drop all IPv6 (default); notes the tunnel-routed alternative. |
| [`nftables/killswitch.nft`](nftables/killswitch.nft) | `inet killswitch` | Drop-all isolation — the engaged kill-switch state. |
| [`tests/`](tests/) | — | Leak-scenario harness for §14/§15/§16 (see `tests/README.md`). |

### Apply order

The normal (armed) state is three files, loaded in this order:

```sh
nft -f firewall/nftables/ipv6-block.nft   # drop v6 first
nft -f firewall/nftables/nat-tor.nft      # install transparent redirect
nft -f firewall/nftables/gateway.nft      # default-deny filter (matches post-redirect ports)
```

Engaging the kill switch replaces all of the above with one drop-all set:

```sh
nft -f firewall/nftables/killswitch.nft   # flushes filter+nat, leaves loopback-only drop-all
```

## Mapping to `aegis-core::gateway::FirewallPolicy`

`FirewallPolicy` (`crates/aegis-core/src/gateway.rs`) is the declarative,
testable model; the nftables files are its concrete rendering. Every field has a
direct counterpart:

| `FirewallPolicy` field | Value (Tor mode) | Rendered as |
| --- | --- | --- |
| `default_policy: DefaultPolicy::Drop` | `Drop` | `policy drop` on every base chain in `gateway.nft` (and `killswitch.nft`). `Accept` is rejected by `FirewallPolicy::validate` and never rendered. |
| `redirect_dns_to: Some(5353)` | Tor DNSPort | `nat-tor.nft` `udp/tcp dport 53 redirect to :5353` (udp) / `:9040` (tcp/53) |
| `redirect_tcp_to: Some(9040)` | Tor TransPort | `nat-tor.nft` `meta l4proto tcp redirect to :9040` |
| `block_direct_udp: true` | always | `gateway.nft` forward chain: `ip saddr $lan_net meta l4proto udp drop` (plus explicit udp/53 drop as defence-in-depth) |
| `ipv6: Ipv6Policy::Block` | default | `ipv6-block.nft` drops the whole `ip6` family |
| `reject_host_initiated: true` | always | `gateway.nft` input chain accepts only loopback + `ct established,related` on the upstream NIC — no host-initiated data flow is accepted; the Tor ControlPort is loopback-only |

The port constants (`5353`, `9040`), the downstream CIDR (`10.152.152.0/24`) and
the gateway address (`10.152.152.1`) are exactly the values wired in
`FirewallPolicy::fail_closed` / the `aegis-core` tests, so the rendered ruleset
and the model stay in lockstep.

### Kill switch and tunnel state

| `aegis-core` type | State | Firewall action |
| --- | --- | --- |
| `KillSwitchState::Armed` | normal | ipv6-block + nat-tor + gateway loaded |
| `KillSwitchState::Engaged` | isolated | `killswitch.nft` loaded (drop-all) |
| `TunnelState::Failed` / `Down` | tunnel lost | controller engages the kill switch |

Because the base policy is `drop`, a failed tunnel needs no special "block" rule:
the transparent redirect in `nat-tor.nft` points at a now-dead Tor port and the
packet is dropped with nowhere to fall back to. The kill switch makes that
isolation explicit and total.

## How `gateway-controller` renders and applies it

`gateway-controller` implements the `aegis_core::traits::GatewayController`
trait:

```rust
async fn configure(&self, cfg: &GatewayConfig) -> Result<()>;
async fn apply_firewall(&self, policy: &FirewallPolicy) -> Result<()>;
async fn engage_killswitch(&self) -> Result<()>;
async fn release_killswitch(&self) -> Result<()>;
async fn killswitch_state(&self) -> Result<KillSwitchState>;
async fn health(&self) -> Result<GatewayHealth>;
```

The intended flow:

1. **`configure(cfg)`** — takes the `GatewayConfig` (mode, DNS/IPv6 policy,
   `downstream_cidr`, `gateway_address`) and substitutes the `define` values at
   the top of each `.nft` file (interface names, `lan_net`, `gw_addr`, and the
   Tor ports). The files ship with the documented defaults so they are valid and
   syntax-checkable as-is.
2. **`apply_firewall(policy)`** — first calls `policy.validate()`; if it returns
   a reason (e.g. non-`Drop` default, `block_direct_udp == false`), application
   is refused. On success it applies the three armed rulesets in order
   (ipv6-block → nat-tor → gateway) via `nft -f`, after a `nft -c -f` dry run.
3. **`engage_killswitch()`** — applies `killswitch.nft` (drop-all). Called
   automatically when `tunnel_status()` reports `Failed`/`Down`, or on any
   `Error` whose class `requires_killswitch()` (see
   `crates/aegis-core/src/error.rs`).
4. **`release_killswitch()`** — only after a verified-safe reconfiguration:
   re-applies the armed rulesets. Never released implicitly.
5. **`health()`** — reports `GatewayHealth { gateway_up, firewall_applied,
   tunnel, killswitch }`; the browser is allowed to launch only when
   `GatewayHealth::is_ready()` (firewall applied, tunnel up, kill switch armed).

Validation before browsing is enforced by the preflight checks
(`crates/aegis-core/src/preflight.rs`, spec §5: `gateway_ready`, `tunnel_ready`,
`dns_route_verified`, `ipv6_policy_verified`, …). If any fails, the browser gets
no Internet access.

## Paired `torrc`

`nat-tor.nft` documents the exact Tor configuration it depends on (DNSPort 5353,
TransPort 9040, `VirtualAddrNetworkIPv4 10.192.0.0/10`, loopback-only
ControlPort). The ports are unprivileged so Tor binds them without root
(§10: *"proces ... nie działa jako root"*). See the header of that file.

## Testing

See [`tests/README.md`](tests/README.md). Run `tests/leak-scenarios.sh` — it is
self-documenting, needs no privileges to run the static assertions, and adds
live namespace tests when run as root with `nft` + `ip` present.
