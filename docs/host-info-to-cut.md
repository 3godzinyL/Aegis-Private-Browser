# Aegis Private Browser — Host Information That Must Be Cut

Status: Stage 0 (foundations).

This is the comprehensive catalogue of host information that must **not** reach the
Browser VM or any website, and *how* each channel is cut. It operationalizes the
spec §14 acceptance criteria ("Host" section) and the four-layer unlinkability
model in [`privacy-model.md`](./privacy-model.md).

Legend for the **How cut** column:
- **VM boundary** — prevented by `IsolationPolicy::hardened()` in `vm.rs`
  (no passthrough/sharing between host and guest).
- **Network** — prevented at the Gateway VM (`gateway.rs`, `network.rs`).
- **Browser** — prevented by fingerprint normalization / permission policy
  (`fingerprint.rs`, `permissions.rs`; see
  [`browser-api-table.md`](./browser-api-table.md)).
- **Storage** — prevented by per-profile separation and shredding (`profile.rs`).

---

## 1. Network identifiers

| Host info | Leak path if unprotected | How cut | Enforcement |
|-----------|--------------------------|---------|-------------|
| Real public IP | Any outbound request; WebRTC; STUN | **Network** — all egress forced through Tor/VPN/SOCKS; Browser VM never sees the host NIC | Single NIC to gateway; `public_ip_observed` asserts exit ≠ host IP |
| Host DNS resolver / DNS queries | Plaintext DNS escaping the tunnel | **Network** — DNS captured/redirected at gateway; `block_plain_dns`; `DnsMode` per mode | `dns_route_verified` preflight; `network::tests::*_blocks_plain` |
| Local/LAN IP addresses | WebRTC ICE local candidates | **Browser** + **Network** — WebRTC non-proxied-UDP policy; isolated network | `webrtc_policy_loaded`; `tests/network` STUN red-team |
| Host MAC address / NIC identity | ARP/DHCP/driver identifiers | **VM boundary** — fresh virtual NIC (new MAC) per instance | `IsolationPolicy.fresh_network_device` |
| IPv6 address | Dual-stack requests / IPv6 DNS answers | **Network** — `Ipv6Policy::Block` (default) or tunnel-only | `ipv6_policy_verified`; `network.rs` default |
| Direct UDP path | Non-tunnel UDP (e.g. QUIC, WebRTC media) | **Network** — `block_direct_udp` | `gateway::tests::fail_closed_policy_is_valid_and_drops` |

---

## 2. Hardware profile

| Host info | Leak path if unprotected | How cut | Enforcement |
|-----------|--------------------------|---------|-------------|
| Physical GPU model/driver | WebGL/WebGPU renderer strings, `RENDERER`/`VENDOR` | **VM boundary** + **Browser** — no PCI/GPU passthrough; `virtio-gpu`/software; driver strings normalized to the real virtual environment (no fake RTX/Radeon) | `IsolationPolicy.no_pci_passthrough`; `WebGlMode::VirtualBackend`/`Disabled` |
| Camera / microphone | `getUserMedia`, device enumeration | **VM boundary** + **Browser** — no camera/mic exposed to guest; `Camera`/`Microphone` permission = `Block` | `IsolationPolicy.no_camera_microphone`; `permissions::tests::defaults_block_dangerous_devices` |
| Audio hardware fingerprint | AudioContext readback | **Browser** — session-stable, uniform values from the virtual audio device | `FingerprintPolicy` (see browser-api-table) |
| USB / Bluetooth / Serial / HID / MIDI devices | WebUSB/WebBluetooth/WebSerial/WebHID/WebMIDI enumeration | **VM boundary** + **Browser** — no USB passthrough; APIs hard-blocked in every mode | `IsolationPolicy.no_usb_passthrough`; `Feature::is_hard_blocked`; `block_device_apis` |
| CPU core count | `navigator.hardwareConcurrency` | **Browser** — fixed value (Balanced 4 / Strict 2) | `FingerprintPolicy.hardware_concurrency` |
| Battery state | Battery Status API | **Browser** — API suppressed | `FingerprintPolicy.disable_battery_api` |
| Motion / orientation / other sensors | Generic Sensor APIs | **Browser** — sensor APIs suppressed | `FingerprintPolicy.disable_sensor_apis` |
| Media device count/labels | `enumerateDevices` | **Browser** — enumeration limited | `FingerprintPolicy.limit_media_device_enumeration` |

---

## 3. Software / OS profile

| Host info | Leak path if unprotected | How cut | Enforcement |
|-----------|--------------------------|---------|-------------|
| Installed host fonts | Font enumeration / metrics probing | **Browser** — standard bundled font set only; no host-font enumeration (the VM has no host fonts to begin with) | `FontPolicy::StandardSet`; `tests/browser-api` font-enumeration red-team |
| Screen / window size | `screen.*`, `window.inner*`, `devicePixelRatio` | **Browser** — virtualized viewport; Strict rounds the content area to shared buckets (letterboxing) | `LetterboxMode::On` in Strict |
| Timezone | `Intl.DateTimeFormat`, `Date.getTimezoneOffset` | **Browser** — shared canonical timezone (default `UTC`), not the host zone | `FingerprintPolicy.timezone` |
| Locale / language | `navigator.language(s)`, `Accept-Language` | **Browser** — shared canonical language (default `en-US`) | `FingerprintPolicy.primary_language` |
| High-resolution timers | `performance.now`, timing side channels | **Browser** — fixed timer coarsening (Balanced 100 µs / Strict 100 ms), never jittered | `FingerprintPolicy.timer_coarsening_us` |
| Real browser build oddities | Non-standard UA | **Browser** — UA keeps the *real* engine version (no random UA); no synthetic anomalies | spec §6, §14; `fingerprint.rs` module doc |

Normalization is deliberately *uniform*, not random: every Aegis session of a
level looks like every other, maximizing the anonymity set (see
[`privacy-model.md`](./privacy-model.md)).

---

## 4. Filesystem, identity, and install identifiers

| Host info | Leak path if unprotected | How cut | Enforcement |
|-----------|--------------------------|---------|-------------|
| Host username in file paths | File dialogs, `File System Access`, download paths, crash dumps | **VM boundary** + **Browser** — paths live inside the VM only; File System Access confined to a VM directory | `IsolationPolicy` (no shared folders); `PermissionState::ConfinedToVm`; §14 "brak ścieżek plików zawierających nazwę użytkownika hosta" |
| Host home directory / arbitrary files | Shared folders, disk automount, drag-and-drop, clipboard | **VM boundary** — no shared clipboard, no drag-and-drop, no shared folders, no host disk automount | `IsolationPolicy.no_shared_clipboard/no_drag_and_drop/no_shared_folders/no_host_disk_automount` |
| Host SSH agent / keys | SSH agent forwarding | **VM boundary** — no host SSH agent access | `IsolationPolicy.no_host_ssh_agent` |
| Desktop-integration guest tools | Guest additions exposing host state | **VM boundary** — no desktop-integration guest tools installed | `IsolationPolicy.no_desktop_integration_tools` |
| Shared install / machine ID | Reused instance identifier across sessions/host | **VM boundary** — locally-generated random instance id per instance, unrelated to any host id | `IsolationPolicy.random_instance_id`; §14 "brak współdzielonych identyfikatorów instalacji" |
| Downloaded-file provenance | Auto-open on host / metadata | **Browser** — downloads quarantined, not auto-exported to host | `PermissionState::Quarantine`; §14 "brak automatycznego eksportu danych do hosta" |
| Crash dumps with user data | Core dumps written with browsing data | **VM boundary** + build config — core dumps containing user data disabled | spec §10 |

---

## 5. Cross-profile / cross-session data

| Host info | Leak path if unprotected | How cut | Enforcement |
|-----------|--------------------------|---------|-------------|
| Cookies / storage / cache / service workers / history | Shared profile directory or shared VM | **Storage** — each profile has its own stores; separate VM filesystem per disposable session | `profile.rs`; spec §8 full data list |
| Ephemeral-session residue | Undeleted write layer or RAM key | **Storage** — qcow2 overlay shredded and RAM key wiped on close | `DestroyReport::is_clean`; `vm::tests::destroy_report_clean_only_when_both` |
| Two sessions sharing one profile | Concurrent open of a persistent profile | **Storage** — single-writer lock (`Busy` on second open) | `Profile::can_open`; `ProfileRepository::acquire_lock` |

---

## 6. Management / secrets channels

| Host info | Leak path if unprotected | How cut | Enforcement |
|-----------|--------------------------|---------|-------------|
| Proxy / VPN credentials | Plaintext in config or logs | **Storage** — secrets referenced by `CredentialRef`, resolved from secure storage at launch; never inlined or logged | `network::tests::credentials_are_references_not_secrets`; spec §16 |
| Profile encryption keys | Keys in logs / on disk unprotected | **Storage** — password-derived keys, kept in RAM while unlocked, never logged | spec §8; `AuditSink` must never persist secrets |
| Host-initiated traffic into the tunnel | Host processes reaching the Internet through the gateway | **Network** — `reject_host_initiated`; only the authorized management channel is allowed | `FirewallPolicy.reject_host_initiated` |
