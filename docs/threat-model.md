# Aegis Private Browser — Threat Model

Status: Stage 0 (foundations). This is a living document. Per the executive
specification (§13), no fingerprint normalization or API modification may be
implemented until this threat model is approved.

Aegis makes **no** claim of being "undetectable" or "100% anonymous". A website
can always observe *that a specific browser environment exists*; the goal is that
what it observes cannot be linked back to your real computer. See
[`privacy-model.md`](./privacy-model.md) and [`limitations.md`](./limitations.md).

---

## 1. What Aegis is

Aegis manages disposable or persistent, encrypted browsing environments. Each
session runs in its own set of virtual machines and reaches the Internet **only**
through a separate network gateway:

```
Host  ──►  Aegis Manager  ──►  Gateway VM  ──►  Browser VM
                                (firewall +      (Chromium,
                                 tunnel + DNS     one NIC to
                                 + kill switch)   the gateway)
```

The three structural guarantees, restated from the specification (§3):

- The Browser VM does not know the host's physical network interface.
- The Browser VM does not know the host's real public IP.
- The Browser VM has no alternative network route.

This mirrors the Whonix Gateway/Workstation split and the Qubes principle of
isolating components into separate domains.

---

## 2. Assets to protect

| # | Asset | Why it matters |
|---|-------|----------------|
| A1 | Host real public IP and ISP-visible identity | The single most linkable identifier; one leak collapses the whole model. |
| A2 | Host local IP / LAN topology / MAC addresses | Local addresses leak via WebRTC and reveal a stable device/network. |
| A3 | DNS query stream | Reveals browsing targets and, if it escapes the tunnel, the host resolver/IP. |
| A4 | Host hardware profile (GPU, CPU, audio devices, cameras, sensors) | Cross-session, cross-site hardware fingerprint tied to the physical machine. |
| A5 | Host software profile (installed fonts, OS build, locale, timezone) | High-entropy fingerprint; ties the environment to the host configuration. |
| A6 | Host filesystem, usernames, paths, install IDs | Direct identifiers of the real user/machine. |
| A7 | Per-profile browser state (cookies, storage, cache, service workers, history, saved logins) | Cross-site tracking and cross-profile correlation if mixed. |
| A8 | Secrets at rest (proxy/VPN credentials, profile encryption keys) | Compromise re-links traffic or decrypts persistent profiles. |
| A9 | Software supply chain (VM images, app packages, updates) | A tampered image/update can disable every other control. |
| A10 | Ephemeral-session residue (write layer, RAM key) | Recoverable residue defeats the "disposable" guarantee. |

---

## 3. Threat model (spec §2)

### 3.1 What Aegis IS designed to protect against

- Tracking via cookies and page storage.
- Correlation via ordinary fingerprinting APIs.
- Leakage of local and public IP via WebRTC.
- DNS queries escaping the chosen route.
- The Browser VM reading host hardware.
- Data of different profiles mixing together.
- Accidentally opening a session with no active network protection.
- Basic malicious page code running inside the renderer.
- Recovering data after a disposable profile is destroyed.

A fingerprint may be built from, among other things, browser version, timezone,
language, fonts, codecs, and screen size. Clearing cookies alone does **not**
solve this — hence the layered approach.

### 3.2 What Aegis does NOT guarantee (spec §2, "nie gwarantuje")

- Identification after you log in to your own account.
- Giving away your real e-mail, phone number, address, or payment data.
- Correlation of characteristic behavior by a very strong adversary.
- Compromise of the host via a hypervisor or firmware attack.
- An adversary observing all ingress and egress traffic simultaneously
  (global passive adversary).
- Zero-day bugs in the browser, OS, or hypervisor.
- Tracking outside the application.

These are enumerated in full in [`limitations.md`](./limitations.md).

---

## 4. Adversary tiers

| Tier | Adversary | Capability | Aegis posture |
|------|-----------|------------|---------------|
| T0 | Ordinary website / ad-tech / tracker | Reads cookies, runs fingerprinting scripts, requests device access, attempts WebRTC/STUN. | **Primary target.** Contained by profile isolation, permission deny-defaults, WebRTC policy, and fingerprint normalization. |
| T1 | Malicious page code in the renderer | Exploits web-facing APIs, tries to enumerate devices/fonts, tries to open UDP/files. | Contained by Chromium sandbox + Site Isolation, hard-blocked device APIs, single-NIC network, VM boundary. Renderer compromise still cannot reach host hardware or an alternate route. |
| T2 | Network operator (VPN/proxy operator, exit node, on-path observer of one side) | Sees the tunnel ingress or egress, not both. | Reduced: Tor hides the public IP even from the operator of the entry relay; VPN/proxy operators see the entry address but not host hardware/profile. Choice of mode is an explicit tradeoff (§5). |
| T3 | Very strong adversary / global passive observer | Correlates behavior, or observes ingress **and** egress simultaneously. | **Out of scope (spec §2).** Not defeated. Documented as a residual risk. |
| T4 | Host-level / firmware / hypervisor attacker | Breaks out of the VM, attacks the hypervisor or firmware, or already owns the host. | **Out of scope (spec §2).** If the host is compromised, isolation cannot be assumed. |

Design priority (spec §16): **no leak before compatibility**. When a control and
a convenience conflict, the control wins.

---

## 5. Attack surface

| Surface | Description | Primary mitigations |
|---------|-------------|---------------------|
| Web content APIs | JS access to WebRTC, Canvas, WebGL, WebGPU, AudioContext, mediaDevices, sensors, Bluetooth/USB/Serial/HID/MIDI, timezone, `hardwareConcurrency`, screen size. | Fingerprint normalization + permission deny-defaults. See [`browser-api-table.md`](./browser-api-table.md). |
| Renderer process | Parsing untrusted HTML/CSS/JS/media. | Chromium multiprocess sandbox + Site Isolation (never disabled; no `--no-sandbox`, no `--disable-web-security`). |
| Network egress | Any packet leaving toward the Internet. | Single virtual NIC to the Gateway; nftables default-deny (`DefaultPolicy::Drop`); tunnel-only egress; kill switch. |
| DNS | Name resolution. | DNS captured/redirected at the gateway; plaintext DNS blocked (`DnsPolicy::block_plain_dns`); mode-specific `DnsMode`. |
| IPv6 | Dual-stack leak path. | `Ipv6Policy::Block` by default, or tunnel-only. |
| VM <-> host channels | Clipboard, drag-and-drop, shared folders, disk automount, USB/PCI passthrough, camera/mic, SSH agent, guest tools. | All disabled via `IsolationPolicy::hardened()` (twelve booleans, all validated). |
| Profile storage | Cookies, cache, storage, history, keys on disk. | Per-profile separation; ephemeral overlays shredded; persistent volumes encrypted with a password-derived key. |
| Update / supply chain | VM images and app packages. | ed25519-signed manifests, SHA-256 per artifact, downgrade block, rollback, SBOM. |
| Management channel | UI ↔ privileged daemon. | Local Unix socket with authorization; privileged daemon is small and not root; host-initiated traffic rejected at the gateway. |
| Diagnostics/logs | Audit records and status output. | Records must never persist secrets or host identifiers (`AuditSink` contract). |

---

## 6. The fail-closed principle

The cardinal rule (spec §16): *failure must always end in a block, never in a
connection without protection.* This is not advisory prose — it is encoded in the
type system.

- Every error carries a `FailureClass` (`crates/aegis-core/src/error.rs`).
- `FailureClass::NetworkContainment` and `FailureClass::Isolation` return `true`
  from `requires_killswitch()`. The daemon engages the kill switch for these
  **before** surfacing the error.
- The six preflight checks gate the first tab. Only `ProtectionStatus::Active`
  returns `true` from `permits_browsing()`; a `Skipped` check counts as a failure
  (`CheckOutcome::is_pass` is `Pass`-only). There is no partial-pass path to a
  live session.
- The session state machine (`session.rs`) forbids `GatewayStarting -> Browsing`;
  `Browsing` is reachable only through `Preflight`, and any state can transition
  to `Failed`, which the daemon treats as a kill-switch event.
- The gateway firewall's only acceptable base policy is `DefaultPolicy::Drop`;
  `FirewallPolicy::validate()` rejects `Accept`. On tunnel loss `TunnelState`
  becomes `Failed` and `KillSwitchState::Engaged` cuts all traffic.

---

## 7. Protection → enforcement mapping

Every protection is backed by code and by an automated test (spec §16: "każdą
ochronę potwierdzić testem automatycznym"). The unit tests below already exist in
`crates/aegis-core`; the named integration/leak suites under `tests/` are the
Stage 1–6 harnesses that exercise the running system.

| Protection (spec) | Enforced by (code) | Verified by (test) |
|-------------------|--------------------|--------------------|
| Failure severs connectivity (fail-closed) | `error.rs` `FailureClass::requires_killswitch` | `error::tests::killswitch_classes`, `error::tests::retryable_only_for_transient` |
| First tab gated on 6 preflight checks | `preflight.rs` `CheckId::all`, `ConnectivityChecklist::permits_browsing` | `preflight::tests::all_pass_is_active_and_permits`, `dns_failure_is_unsafe_and_blocks`, `no_gateway_is_none`, `skipped_counts_as_not_passed` |
| Never advertise "100% anonymous" | `preflight.rs` `ProtectionStatus::label` (four labels only) | Code review + `security-acceptance-criteria.md` checklist |
| Firewall default-deny, no direct UDP, reject host-initiated | `gateway.rs` `FirewallPolicy::fail_closed`, `validate` | `gateway::tests::fail_closed_policy_is_valid_and_drops`, `accept_default_is_rejected` |
| DNS captured, plaintext DNS blocked | `network.rs` `DnsPolicy`, `NetworkMode::default_dns_policy` | `network::tests::tor_default_captures_dns_and_blocks_plain`, `proxy_dns_always_blocks_plaintext` |
| IPv6 blocked by default | `network.rs` `Ipv6Policy::Block` (default) | `network::tests::tor_default_captures_dns_and_blocks_plain` |
| Kill switch on tunnel loss | `gateway.rs` `TunnelState::Failed`, `KillSwitchState`, `GatewayHealth::is_ready` | `gateway::tests::health_requires_everything`; `tests/network`, `tests/destructive` (gateway-failure red-team, spec §15) |
| No host device passthrough; hardened VM | `vm.rs` `IsolationPolicy::hardened`, `validate`, `VmProvisionRequest::validate` | `vm::tests::hardened_policy_validates`, `any_weakening_is_rejected`, `browser_requires_readonly_root` |
| Ephemeral overlay shredded, nothing left behind | `vm.rs` `DestroyReport::is_clean`; `session.rs` teardown states | `vm::tests::destroy_report_clean_only_when_both`; `tests/destructive` (disposable-VM destruction, spec §15) |
| Browser never reaches `Browsing` without preflight | `session.rs` `SessionState::allowed_next`, `SessionSummary::is_safe` | `session::tests::cannot_skip_preflight_to_browsing`, `happy_path_transitions_are_allowed`, `any_state_can_fail` |
| Device classes hard-blocked; deny-default permissions | `permissions.rs` `Feature::is_hard_blocked`, `PermissionPolicy::secure_default`, `grant` | `permissions::tests::defaults_block_dangerous_devices`, `cannot_grant_hard_blocked`, `grant_is_scoped_to_origin`, `clearing_grants_restores_defaults` |
| Fingerprint normalized, not spoofed; device APIs off; WebGPU off in Strict | `fingerprint.rs` `FingerprintPolicy::balanced/strict/validate` | `fingerprint::tests::levels_produce_valid_policies`, `strict_disables_webgpu_and_full_webgl`, `device_apis_are_always_blocked`, `validation_rejects_unblocked_devices`; `tests/browser-api` |
| Per-origin/per-profile grants; cleared on ephemeral close | `permissions.rs` `PermissionPolicy::clear_grants` | `permissions::tests::clearing_grants_restores_defaults` |
| Single-writer per persistent profile | `profile.rs` `Profile::can_open`; `traits.rs` `ProfileRepository::acquire_lock` (returns `Busy`) | `profile::tests::locked_profile_cannot_open`; `tests/integration` (two-sessions-one-profile, spec §15) |
| Signed updates, downgrade block, rollback | `update.rs` `Version::is_newer_than`, `UpdateManifest`, `ApplyOutcome` | `update::tests::version_ordering_and_parse`, `manifest_roundtrips`; `tests/integration` (update integrity) |
| Credentials never stored in plaintext | `network.rs` `CredentialRef` (reference only) | `network::tests::credentials_are_references_not_secrets` |
| WebRTC blocks non-proxied UDP | Browser managed policy (`webrtc_policy_loaded` preflight check) | `tests/browser-api`, `tests/network` (STUN/UDP red-team, spec §15) |

---

## 8. Residual risk summary

Even with every control in place, an adversary at tier T3/T4, a user who
self-identifies (logs in, enters a real e-mail/phone), or a zero-day in the
engine/OS/hypervisor can defeat the model. These residual risks are documented in
[`limitations.md`](./limitations.md). The honest, measurable claim is
**unlinkability to the host**, not anonymity.
