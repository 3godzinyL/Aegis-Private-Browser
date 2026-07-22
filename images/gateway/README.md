# Aegis Gateway VM image

Minimal, hardened, headless Debian image for the **Gateway VM** — the only
component with an upstream path to the host network. It runs a default-deny
`nftables` firewall and routes every packet from the isolated Browser network
through **Tor** (the first supported backend). If the tunnel drops, the kill
switch cuts the Browser VM off entirely: **failure always ends in a block, never
a direct connection** (spec §5, §16).

This directory is the build definition only. It is meant to be built on a Linux
host; the scripts are not run on Windows.

## What this image is

- **Role:** `VmRole::Gateway` (aegis-core). Two NICs at runtime:
  - `eth0` upstream → host NAT network (Tor circuits egress here).
  - `eth1` downstream → isolated Browser network `10.152.152.0/24`, gateway
    address `10.152.152.1` (matches `GatewayConfig` defaults).
- **No desktop.** No X/Wayland, no spice-vdagent. `qemu-guest-agent` is present
  only for clean ACPI shutdown/fsfreeze and is locked down to a minimal RPC
  allow-list (`files/etc/systemd/system/qemu-guest-agent.service.d/`).
- **Read-only root** with tmpfs scratch (`files/etc/fstab`). The base image is
  mounted read-only; a disposable qcow2 overlay is added per instance by
  `vm-controller`.
- **machine-id randomized per instance, not host-derived**: the image ships an
  empty `/etc/machine-id`, so systemd generates a fresh random id on first boot
  of every clone.

## Build

Two interchangeable build paths produce the same logical image.

### mkosi (preferred, declarative & reproducible)

```sh
cd images/gateway
mkosi --image-version=1.0.0 --force build
# → mkosi.output/aegis-gateway_1.0.0.raw  (convert to qcow2 in packaging)
```

`mkosi.conf` pins the distribution/release, honors `SOURCE_DATE_EPOCH`, installs
only the gateway package set, overlays `files/`, and runs `mkosi.postinst`
(enables units, locks root, randomizes machine-id).

### debootstrap (fallback, no mkosi required)

```sh
sudo ./build.sh --version 1.0.0 \
     --mirror https://snapshot.debian.org/archive/debian/20260701T000000Z/
# → mkosi.output/aegis-gateway_1.0.0.qcow2 (+ .sha256)
```

For byte-reproducible builds, point `--mirror` / `mkosi.conf`'s `Mirror=` at a
timestamped `snapshot.debian.org` archive and keep `SOURCE_DATE_EPOCH` fixed.

## Files shipped into the image (`files/`)

| Path in image | Purpose |
|---|---|
| `etc/systemd/system/aegis-gateway-firewall.service` | Loads the nftables ruleset **before** the network (fail-closed). |
| `etc/systemd/system/aegis-tor.service` | Runs Tor as the transparent proxy; `BindsTo` the firewall unit. |
| `etc/systemd/system/aegis-healthcheck.service` | Publishes tunnel/kill-switch health JSON for the manager; engages the kill switch on tunnel loss. |
| `usr/local/sbin/aegis-healthcheck` | The probe. Emits `GatewayHealth`-shaped JSON to `/run/aegis/health.json`. |
| `etc/tor/torrc` | `DNSPort 5353`, `TransPort 9040`, `AutomapHostsOnResolve`, `VirtualAddrNetworkIPv4 10.192.0.0/10`, loopback `ControlPort 9051`. |
| `etc/nftables/aegis-gateway.nft` | Complete default-deny ruleset (ipv6 block + nat-tor + inet filter). |
| `etc/nftables/aegis-killswitch.nft` | Drop-all isolation state (loopback only). |
| `etc/sysctl.d/99-aegis-gateway.conf` | Disables IPv6 by default, no redirects/source-routing, strict rp_filter, no core dumps. |
| `etc/systemd/network/10-upstream.network` | `eth0` DHCP from host NAT, no DNS/NTP/IPv6. |
| `etc/systemd/network/20-downstream.network` | `eth1` static `10.152.152.1/24`, serves DHCP to the Browser VM. |
| `etc/fstab` | Read-only root + tmpfs scratch. |

## Firewall / Tor port contract

These MUST stay consistent across the ruleset, `torrc`, and
`aegis_core::gateway::FirewallPolicy::fail_closed`:

| Port | Role |
|---|---|
| `5353` | Tor **DNSPort** — firewall redirects downstream `:53` (udp/tcp) here. |
| `9040` | Tor **TransPort** — firewall redirects downstream TCP here. |
| `9051` | Tor **ControlPort**, loopback only, cookie auth — read by the health probe. |

`VirtualAddrNetworkIPv4 = 10.192.0.0/10` in `torrc` matches `tor_virtual` in the
ruleset so Automap results are re-torified.

## Boot / enforcement order (fail-closed)

1. `systemd-sysctl` applies `99-aegis-gateway.conf` (IPv6 off, no redirects).
2. `aegis-gateway-firewall.service` loads the default-deny ruleset **before**
   `network-pre.target` and `systemd-networkd`. No packet window exists without
   the firewall.
3. `systemd-networkd` brings up `eth0`/`eth1`.
4. `aegis-tor.service` starts (`BindsTo` the firewall unit — if the firewall
   isn't up, Tor doesn't run).
5. `aegis-healthcheck.service` probes Tor bootstrap; while not fully bootstrapped
   it applies `aegis-killswitch.nft` so the Browser VM is cut off until the
   tunnel is genuinely up.

Kill switch engages **without** needing the host manager: containment does not
depend on the manager being reachable.

## Health document

`/run/aegis/health.json` matches `aegis_core::gateway::GatewayHealth`:

```json
{
  "gateway_up": true,
  "firewall_applied": true,
  "tunnel": { "state": "up", "bootstrap_percent": 100, "detail": "tor bootstrapped" },
  "killswitch": "armed"
}
```

`gateway-controller` reads it over the management channel to render diagnostics
and gate the `tunnel_ready` preflight check.

## Consumption by vm-controller

The produced qcow2 is a **read-only backing image**. Per session, `vm-controller`
creates a disposable qcow2 overlay (`backing_image` = this image, `read_only_root
= true`, `destroy_on_close = true`) and defines a libvirt domain with the two
NICs. The overlay is securely destroyed at session end. See `../README.md` for
the reproducible-build + signing + consumption flow shared by both images.
