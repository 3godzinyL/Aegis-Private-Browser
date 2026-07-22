# Aegis Private Browser — Privacy-Relevant Browser API Table

Status: Stage 0 (foundations).

This table is the per-API treatment for the two protection levels, with rationale.
It is the human-readable companion to `FingerprintPolicy` in
`crates/aegis-core/src/fingerprint.rs` and the permission table in
`crates/aegis-core/src/permissions.rs`, both of which are the machine-checked
source of truth. Every entry is normalization or restriction — **never random
spoofing** (spec §7, §16) and never simulation of hardware the VM lacks (spec §4).

Cross-cutting invariants (enforced regardless of level, `FingerprintPolicy::validate`):
- Bluetooth/USB/Serial/HID/MIDI are **always blocked**.
- WebGPU is **always off in Strict**.
- Battery and sensor APIs are **always suppressed**.
- All values are **stable within a session** across main frame, iframes, workers,
  service workers, WebGL, Canvas, and AudioContext (inconsistency is itself a
  fingerprint).

---

## Fingerprinting-surface APIs

| API / signal | Balanced | Strict | Rationale |
|--------------|----------|--------|-----------|
| **WebRTC** | Non-proxied UDP blocked (`disable_non_proxied_udp`); media/data routed only through the tunnel | Same, plus stricter interface restriction | Prevents local/public IP leak — the single most damaging leak (spec §5). Verified by `webrtc_policy_loaded` and `tests/network` STUN red-team. |
| **Canvas** (2D readback) | `Passthrough` — real virtualized rendering, session-stable | `Limited` — session-stable uniform limiting of readback | Canvas hashes are high-entropy. We keep it consistent (not per-read random) so it is uniform across Aegis sessions, not a unique signature. |
| **WebGL** | `VirtualBackend` — enabled via virtio/software; renderer/vendor strings normalized to the real virtual GPU (no fake RTX/Radeon) | `Disabled` (or `Restricted`) | No physical GPU is passed through; the value reflects the real virtual environment. Strict removes the surface entirely for uniformity. |
| **WebGPU** | Disabled | Disabled | New, high-entropy hardware surface with limited privacy hardening; off by default, mandatory off in Strict (spec §4, §7). |
| **AudioContext** | Session-stable values from the virtual audio device | Session-stable values | AudioContext readback fingerprints hardware DSP; the virtual device yields a uniform, stable value. |
| **Fonts** | `StandardSet` — standard bundled fonts only; no host-font enumeration | `StandardSet` | Installed fonts are a classic high-entropy signal. The VM has no host fonts; the bundled set is identical across sessions. |
| **`mediaDevices.enumerateDevices`** | Limited | Limited | Device count/labels fingerprint hardware. Enumeration is restricted; camera/mic are `Block` by default. |
| **Battery Status API** | Suppressed | Suppressed | Charge level/rate is a short-term cross-site correlator; removed. |
| **Generic Sensor APIs** (accelerometer, gyroscope, magnetometer, ambient light, etc.) | Suppressed | Suppressed | Sensor data reveals device class and can correlate sessions; removed. |
| **Web Bluetooth** | Blocked | Blocked | Physical device access; hard-blocked (`Feature::is_hard_blocked`) — no UI grant path. |
| **WebUSB** | Blocked | Blocked | Physical device access; hard-blocked. |
| **Web Serial** | Blocked | Blocked | Physical device access; hard-blocked. |
| **WebHID** | Blocked | Blocked | Physical device access; hard-blocked. |
| **Web MIDI** | Blocked | Blocked | Enumerates MIDI hardware; hard-blocked. |
| **Timezone** (`Intl`, `Date`) | Shared canonical (default `UTC`) | Shared canonical (default `UTC`) | Host timezone geolocates the user; a shared zone maximizes the crowd. |
| **Language / locale** | Shared canonical (default `en-US`) | Shared canonical (default `en-US`) | `navigator.languages` / `Accept-Language` are stable identifiers; standardized. |
| **`navigator.hardwareConcurrency`** | Fixed = 4 | Fixed = 2 | Core count fingerprints the CPU; a fixed common value normalizes it. |
| **`deviceMemory`** | Normalized to a common value | Normalized to a common value | Memory tier fingerprints hardware; standardized alongside core count. |
| **Screen / window size** (`screen.*`, `window.inner*`, `devicePixelRatio`) | Virtualized viewport (host-independent) | Letterboxed — content area rounded to shared buckets | Exact window size is high-entropy; letterboxing groups users into buckets (Tor/Mullvad approach). |
| **High-resolution timers** (`performance.now`, timer-based side channels) | Coarsened to 100 µs, fixed | Coarsened to 100 000 µs (100 ms), fixed | Fine timers enable side-channel and hardware fingerprints; coarsening is fixed, never jittered per read. |
| **User-Agent / UA-CH** | Real engine version retained | Real engine version retained | A random or mismatched UA is itself anomalous and can conflict with anti-fraud systems; Aegis stays a plausible, standards-compliant browser (spec §6, §14). |

---

## Permission-governed capabilities (default states, spec §9)

From `PermissionPolicy::secure_default()`. Grants are scoped to profile+origin and,
for ephemeral profiles, are cleared at session end. Hard-blocked device classes
cannot be granted through any UI path.

| Feature | Default state | Notes |
|---------|---------------|-------|
| Geolocation | `Block` | Location is directly identifying. |
| Camera | `Block` | No physical camera reaches the VM either. |
| Microphone | `Block` | No physical mic reaches the VM either. |
| Notifications | `Ask` | User-driven; scoped to origin. |
| Clipboard read | `Block` | Prevents silent exfiltration of clipboard contents. |
| WebUSB | `Block` (hard-blocked) | Cannot be granted. |
| Web Bluetooth | `Block` (hard-blocked) | Cannot be granted. |
| Web Serial | `Block` (hard-blocked) | Cannot be granted. |
| WebHID | `Block` (hard-blocked) | Cannot be granted. |
| Web MIDI | `Block` (hard-blocked) | Cannot be granted. |
| File System Access | `ConfinedToVm` | Confined to a directory inside the VM; no host paths. |
| Autoplay | `Limited` | Restricted autoplay. |
| Downloads | `Quarantine` | Routed to quarantine; not auto-exported to the host. |

---

## Notes on treatment philosophy

- **Uniformity over uniqueness.** The objective is that many users share the same
  values (a large anonymity set), not that each user is a random device.
- **Truth about the VM, restriction by the browser.** Where a value is exposed
  (e.g. WebGL virtual backend), it describes the real virtual environment, limited
  by the browser — not a fabricated GPU.
- **No anti-fraud interference.** Aegis does not modify APIs to pass anti-bot
  tests (spec §1, §7). Being recognized *as* an Aegis-class environment is
  acceptable; being linked to the host is not.
- **Stronger privacy can break sites.** Strict disables WebGL, letterboxes, and
  coarsens timers heavily; the UI must communicate that Strict causes more
  breakage than Balanced (spec §7). Every treatment above is covered by the
  `tests/browser-api` suite (spec §16: each protection confirmed by an automated
  test).
