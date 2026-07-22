# Aegis Browser VM image

Minimal, hardened, single-app Debian image for the **Browser VM** — the isolated
workstation that runs Chromium and reaches the internet through **one NIC to the
gateway only**. It has **no host integration** (no spice-vdagent, no
qemu-guest-agent desktop bits, no shared folders, no clipboard, no drag-and-drop,
no USB/PCI passthrough), a **read-only root** with tmpfs writable layers, and
Chromium launched inside a locked-down kiosk with its sandbox and Site Isolation
intact (spec §4, §6, §8, §10).

Build definition only; built on a Linux host, not on Windows.

## What this image is

- **Role:** `VmRole::Browser` (aegis-core). **Exactly one NIC** (`eth0`) →
  isolated gateway network; DHCP + DNS + default route all point at the gateway
  `10.152.152.1`. There is no alternative route (spec §3/§5).
- **Single-app kiosk:** `cage` (a one-app Wayland compositor) launches **only**
  Chromium fullscreen — no desktop, file manager, or terminal.
- **Read-only root** + tmpfs for `/home`, `/tmp`, `/var/downloads` (spec §10),
  so an ephemeral session leaves no profile residue (spec §8).
- **No host integration:** spice/vm-tools/ssh/samba are not installed and are
  masked; `qemu-guest-agent` is kept only for clean shutdown/fsfreeze and is
  locked to a minimal RPC allow-list.
- **machine-id randomized per instance, not host-derived** — see
  `files/etc/machine-id.README`.

## Build

### mkosi (preferred)

```sh
cd images/browser
mkosi --image-version=1.0.0 --force build
# → mkosi.output/aegis-browser_1.0.0.raw
```

### debootstrap (fallback)

```sh
sudo ./build.sh --version 1.0.0 \
     --mirror https://snapshot.debian.org/archive/debian/20260701T000000Z/
# → mkosi.output/aegis-browser_1.0.0.qcow2 (+ .sha256)
```

Reproducibility: fixed `SOURCE_DATE_EPOCH`, pinned snapshot mirror, fixed package
set, no host state copied into the image.

## Files shipped into the image (`files/`)

| Path in image | Purpose |
|---|---|
| `etc/systemd/system/aegis-browser-firstboot.service` | Firstboot: applies the managed Chromium policy + fresh per-session user-data-dir. |
| `usr/local/sbin/aegis-browser-firstboot` | The firstboot script (installs `balanced`/`strict` policy, prepares user-data-dir). |
| `etc/systemd/system/aegis-kiosk.service` | Launches `cage` → Chromium; systemd sandbox confinement of the launcher. |
| `etc/systemd/system/aegis-kiosk.service.d/10-hardening.conf` | seccomp / syscall-filter drop-in (keeps Chromium's own sandbox intact). |
| `usr/local/sbin/aegis-launch-chromium` | Chromium launch flags: sandbox ON, Site Isolation ON, WebRTC non-proxied UDP disabled, no remote debugging. |
| `usr/share/aegis/policies/{balanced,strict}.json` | Managed enterprise policies (copied from `browser/policies/managed/`). |
| `etc/sysctl.d/99-aegis-browser.conf` | IPv6 off, no redirects, ptrace_scope, no core dumps; keeps userns for the sandbox. |
| `etc/systemd/network/10-gateway.network` | The single NIC → gateway (DHCP, gateway DNS, no IPv6). |
| `etc/fstab` | Read-only root + tmpfs `/home`, `/tmp`, `/var/downloads`, managed-policy dir. |
| `etc/systemd/system/qemu-guest-agent.service.d/aegis-lockdown.conf` | Strips guest-agent desktop/file RPCs. |
| `etc/machine-id` (empty) + `etc/machine-id.README` | Per-instance randomized machine-id; handling note. |

## Non-negotiable Chromium rules (spec §16)

The launcher enforces — and must always keep — these:

- **Never** `--no-sandbox` (Chromium sandbox stays on; `chrome-sandbox` is
  setuid-root, which is why `NoNewPrivileges=no` on the kiosk unit).
- **Never** `--disable-web-security`.
- **No** `--remote-debugging-port` (no DevTools Protocol on any interface).
- **Never** disable Site Isolation.
- WebRTC forced to `disable_non_proxied_udp` so no local/host IP leaks (spec §5),
  reinforcing the `WebRtc*` managed policies.

## Protection levels

The manager writes the desired level to `/run/aegis/session.env`
(`AEGIS_PROTECTION_LEVEL=balanced|strict`) over the management channel before
firstboot runs. Firstboot installs the matching enterprise policy into
`/etc/chromium/policies/managed/aegis.json`. If unset, it **fails closed to
Strict**. Levels map to `aegis_core::fingerprint::ProtectionLevel`. Proper
fingerprint normalization (letterboxing, Canvas/WebGL limiting, timer precision,
WebGPU off) lives in the Chromium patch set (`browser/chromium-patches`), not in
this image — the image governs only launch flags + enterprise policy + OS
hardening.

## GPU

No physical GPU is ever passed through (spec §4). Chromium uses the virtio-gpu
DRI device (`--use-gl=angle --use-angle=gl`) in Balanced, and the pure software
path (`--disable-gpu`) in Strict, matching `GpuBackend::{VirtioGpu, Software}`
and the strict managed policy's `HardwareAccelerationModeEnabled=false`.

## Consumption by vm-controller

The produced qcow2 is a **read-only backing image**. Per session, `vm-controller`
creates a disposable qcow2 overlay (`read_only_root = true`,
`destroy_on_close = true`), attaches exactly one virtual NIC (fresh MAC) to the
isolated gateway network, sets a fresh random domain UUID, and applies the
hardened `IsolationPolicy`. The overlay is securely destroyed at session end so
nothing persists. See `../README.md` for the shared reproducible-build + signing
+ consumption flow.
