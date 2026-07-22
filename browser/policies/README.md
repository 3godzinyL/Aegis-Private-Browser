# `browser/policies/` — Chromium managed policies and how Aegis emits them

This directory contains the Chromium **enterprise managed-policy** documents that
harden the browser inside the Browser VM (spec §6 Variant B, §9, §10, §16).

```
policies/
├── README.md              ← this file (mapping + WebRTC mechanism)
└── managed/
    ├── balanced.json      ← ProtectionLevel::Balanced
    ├── strict.json        ← ProtectionLevel::Strict
    └── README.md          ← key-by-key reference for every policy
```

The policy layer is **one of two** browser-privacy layers. It handles what a
managed policy *can* express (accounts, telemetry, permissions, capture,
network, Safe Browsing). Fingerprint **normalization** that a policy cannot
express (letterboxing, timer coarsening, Canvas/WebGL/WebGPU control,
`hardwareConcurrency`, timezone/language pinning, font limiting) lives in the C++
patch set under `../chromium-patches/`. Both are required by spec §7/§16.

---

## 1. How policies map to `aegis-core`

`aegis-core` is the single source of truth. Two structs drive the browser:

* [`aegis_core::permissions::PermissionPolicy`](../../crates/aegis-core/src/permissions.rs)
  — the per-profile/per-origin permission table (spec §9).
* [`aegis_core::fingerprint::FingerprintPolicy`](../../crates/aegis-core/src/fingerprint.rs)
  — the normalization policy for a `ProtectionLevel` (spec §7).

`browser-launcher` renders both into an
[`aegis_core::browser::BackendPolicyBundle`](../../crates/aegis-core/src/browser.rs)
whose `managed_policies` map is exactly the JSON in `managed/`.

### 1a. `PermissionPolicy` → managed policy keys

| `Feature` | secure-default `PermissionState` | Managed policy key(s) | Value |
|-----------|----------------------------------|-----------------------|-------|
| `Location` | `Block` | `DefaultGeolocationSetting` | `2` |
| `Camera` | `Block` | `VideoCaptureAllowed` | `false` |
| `Microphone` | `Block` | `AudioCaptureAllowed` | `false` |
| `Notifications` | `Ask` | `DefaultNotificationsSetting` | `2` block (see managed/README) |
| `ClipboardRead` | `Block` | `DefaultClipboardSetting` | `2` |
| `Usb` | `Block` (hard) | `DefaultWebUsbGuardSetting` | `2` |
| `Bluetooth` | `Block` (hard) | `DefaultWebBluetoothGuardSetting` | `2` |
| `Serial` | `Block` (hard) | `DefaultSerialGuardSetting` | `2` |
| `Hid` | `Block` (hard) | `DefaultWebHidGuardSetting` | `2` |
| `Midi` | `Block` (hard) | *(no managed key — enforced in patch set)* | — |
| `FileSystemAccess` | `ConfinedToVm` | `DefaultFileSystemReadGuardSetting`, `DefaultFileSystemWriteGuardSetting` | `2` |
| `Autoplay` | `Limited` | `AutoplayAllowed` + patch | `false`/gated |
| `Downloads` | `Quarantine` | launcher-managed download dir + patch | quarantine |

`Feature::is_hard_blocked()` (USB/Bluetooth/Serial/HID/MIDI) is enforced twice:
the managed policy pins the guard to `2`, and the Rust `PermissionPolicy::grant`
refuses to ever produce an `Allow`. A page therefore cannot obtain these even if
a future UI bug tried to grant them.

Per-origin `overrides` (e.g. a user granting `Notifications` to one site) are
**not** written into the static managed JSON — managed policy is site-agnostic.
Origin grants are applied by the launcher through Chromium's per-origin content
settings for the profile and are wiped when an ephemeral session ends
(`PermissionPolicy::clear_grants`).

### 1b. `FingerprintPolicy` → policy vs. patch

Only a few `FingerprintPolicy` fields have a managed-policy expression; the rest
are enforced by the patch set. This table makes the split explicit:

| `FingerprintPolicy` field | Balanced | Strict | Enforced by |
|---------------------------|----------|--------|-------------|
| `webgl` | `VirtualBackend` | `Disabled` | Patch (WebGL virtual backend / disable) + `HardwareAccelerationModeEnabled` |
| `webgpu_enabled` | `false` | `false` | Patch (`--disable-features=WebGPU`) — WebGPU always off |
| `canvas` | `Passthrough` | `Limited` | Patch (Canvas readback control) |
| `letterbox` | `Off` | `On` | Patch (window-size buckets) |
| `fonts` | `StandardSet` | `StandardSet` | Patch (font set) + `DefaultLocalFontsSetting=2` |
| `timer_coarsening_us` | `100` | `100000` | Patch (timer coarsening) |
| `limit_media_device_enumeration` | `true` | `true` | Patch (mediaDevices limiting); capture also off via policy |
| `hardware_concurrency` | `Some(4)` | `Some(2)` | Patch (`hardwareConcurrency` clamp) |
| `disable_battery_api` | `true` | `true` | Patch (Battery off) |
| `disable_sensor_apis` | `true` | `true` | Patch + `DefaultSensorsSetting=2` |
| `block_device_apis` | `true` | `true` | Policy guards `2` + patch (MIDI) |
| `timezone` | `Some("UTC")` | `Some("UTC")` | Patch (timezone pinning) |
| `primary_language` | `en-US` | `en-US` | Patch (language pinning) + `--lang` / `Accept-Language` |

The launcher calls `FingerprintPolicy::validate()` before emitting anything; a
policy that failed the spec invariants (device APIs unblocked, WebGPU on in
Strict, full WebGL backend in Strict) never reaches Chromium.

---

## 2. How `browser-launcher` emits them

`browser-launcher`'s `ChromiumBackend` (spec §6 `BrowserBackend`) does:

1. Take a `BrowserLaunchRequest { fingerprint, permissions, proxy_endpoint,
   render_mode, production, user_data_dir, .. }`.
2. Select the base managed document by `fingerprint.level`
   (`balanced.json` / `strict.json`), then overlay the resolved
   `PermissionPolicy` values (e.g. flip `DefaultNotificationsSetting` if a
   deployment chose "ask" for Balanced) so the emitted JSON always agrees with
   the live Rust policy.
3. Insert the WebRTC managed pref (see §3) computed from `proxy_endpoint`.
4. Produce a `BackendPolicyBundle { backend: Chromium, managed_policies,
   command_line, .. }`.
5. Call `BackendPolicyBundle::assert_safe(production)` — this rejects
   `--no-sandbox`, `--disable-web-security`, `--disable-site-isolation-trials`
   and any `--remote-debugging*` in production builds (spec §16). The sandbox and
   Site Isolation are never disabled.
6. The daemon writes `managed_policies` into the managed-policy directory
   **inside the Browser VM** (Linux Chromium reads
   `/etc/chromium/policies/managed/*.json`), writes any per-origin content
   settings into the profile's `user_data_dir`, then launches Chromium with the
   vetted `command_line`. Nothing is applied via injected content scripts
   (spec §6/§16).

Because managed policies are *mandatory*, the guarantees hold even if the page
(or the user) tries to change them in `chrome://settings`.

---

## 3. WebRTC: `disable_non_proxied_udp` mechanism and why

### The requirement (spec §5)

> W Chromium należy wymusić politykę blokującą nieproksowany UDP … wariant
> `disable_non_proxied_udp` zapobiega użyciu zwykłego UDP poza skonfigurowaną
> trasą.

WebRTC can gather ICE candidates directly from the network stack. Left alone it
will (a) expose local interface IPs (the VM's, and historically the host's) and
(b) try to send media over **plain UDP** that bypasses the configured
HTTP/SOCKS proxy — sending packets straight out the VM's NIC. In the Aegis model
that NIC only reaches the Gateway VM, but a non-proxied UDP flow could still skip
DNS/route controls and, on a misconfigured tunnel, leak. Spec §14 makes
"WebRTC nie ujawnia interfejsu hosta" an acceptance criterion.

### What `disable_non_proxied_udp` does

It forces WebRTC's IP-handling policy so that:

* only the **default public interface** may be used, and
* **UDP that does not traverse the configured proxy is disabled** — media falls
  back to TCP/TLS through the proxy or fails closed.

This is the strongest of Chromium's `WebRTCIPHandlingPolicy` values
(`default` → `default_public_interface_only` →
`disable_non_proxied_udp` → `disable_udp`-adjacent behavior).

### How Aegis applies it (managed pref + flag), and why not a pure JSON policy

Historically Chromium exposed the enterprise policy
`WebRtcUdpPortRange` and a `WebRTCIPHandlingPolicy` pref. The dedicated
enterprise **policy key was removed**, so the value can no longer be set by a
plain managed-policy JSON key alone. Aegis therefore pins it through a
**managed preference + launch flag** applied by the launcher:

1. **Managed pref** — the launcher writes the profile preference
   `webrtc.ip_handling_policy = "disable_non_proxied_udp"` into the managed
   pref surface (`Preferences`/`Managed Preferences`) of the VM's Chromium so it
   is applied at startup and cannot be changed from the UI.
2. **Launch flag** — the command line additionally carries
   `--force-webrtc-ip-handling-policy=disable_non_proxied_udp`
   (and `--webrtc-ip-handling-policy=disable_non_proxied_udp` on builds that
   still honor it) so the behavior is set before any renderer starts. These are
   *not* on the forbidden list in `BackendPolicyBundle::assert_safe`, so they
   pass the safety gate.
3. **Local-IP hiding** — `WebRtcLocalIpsAllowedUrls: []` in the managed JSON
   ensures no site can be allow-listed to see local IPs (mDNS candidate
   obfuscation stays on).

### Why this specific value (not just "disable UDP")

* Fully disabling UDP breaks far more sites; `disable_non_proxied_udp` keeps
  WebRTC working *when it can go through the proxy*, matching Balanced's goal of
  "most sites work" while still failing closed for any non-proxied path.
* The value is identical for Balanced and Strict — WebRTC leakage is a
  never-acceptable event regardless of level (spec §16 "priorytet: brak wycieku
  przed kompatybilnością").

### Defense in depth

The browser-side policy is **not** the only guard. The **Gateway VM firewall**
(spec §5, `firewall/nftables/`) is default-deny and drops any UDP that is not the
tunnel, so even a hypothetical WebRTC bypass cannot reach the internet outside
the tunnel. The preflight check `webrtc_policy_loaded` (spec §5) verifies the
policy was actually applied before the first tab is allowed to load; if it is
missing, the browser gets no internet (fail-closed).
