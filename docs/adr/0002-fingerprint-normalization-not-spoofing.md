# ADR-0002: Fingerprint normalization, not spoofing

- Status: Accepted
- Date: 2026-07-22
- Deciders: Aegis Project
- Spec references: §1, §4, §7, §16, §17

## Context

A browser fingerprint can be built from browser version, timezone, language, fonts,
codecs, screen size, GPU strings, `hardwareConcurrency`, Canvas/WebGL/AudioContext
readback, and more (spec §2, §7). Clearing cookies does not address this. Aegis must
reduce how identifying and how *host-tied* this fingerprint is — without turning the
environment into an anomaly.

Two philosophies exist:

1. **Random spoofing ("anti-detect").** Randomize the User-Agent, GPU strings,
   Canvas per read, and pick from a catalog of hundreds of fake hardware profiles.
2. **Normalization / uniformity.** Expose a small set of consistent, standard
   configurations so that every user of the tool looks alike, and keep values
   *stable within a session*.

Random spoofing is self-defeating for Aegis's goal: inconsistent or improbable
values are *themselves* a strong, unique fingerprint; mismatches between the main
frame, iframes, workers, WebGL, and Canvas are trivially detectable; and fabricating
hardware the VM does not have (e.g. a fake RTX/Radeon) is both a lie that can be
caught and an active attempt to defeat anti-fraud systems — which the spec forbids
(spec §1, §4, §7, §16). The stated goal is **unlinkability to the host**, not
evading bot detection, and explicitly **not** "undetectable" (spec §17).

## Decision

Aegis **normalizes and restricts**; it does **not** randomly spoof (spec §7).

- **Stabilization.** Within a session, every value a site can read is stable and
  consistent across the main frame, iframes, workers, service workers, WebGL,
  Canvas, and AudioContext. Inconsistency between contexts is itself a fingerprint
  and is forbidden (spec §7 "Stabilizacja").
- **Normalization to the truth about the VM.** Instead of fabricating hardware,
  Aegis exposes the *real (virtualized) environment* restricted by the browser: a
  virtio/software GPU with driver strings normalized to the real virtual backend (no
  fake model), a standard bundled font set (the VM has no host fonts to enumerate), a
  standardized viewport, fixed timer precision, suppressed battery/sensor APIs, and
  blocked Bluetooth/USB/Serial/HID/MIDI.
- **Real engine version.** The User-Agent keeps the **real engine version** (spec
  §6, §14) so the environment remains a plausible, standards-compliant browser.
- **Two levels.** `Balanced` maximizes compatibility (WebGL via virtual backend,
  basic normalization); `Strict` maximizes uniformity (WebGL restricted/disabled,
  WebGPU off, stronger Canvas limiting, letterboxing). Both share non-negotiable
  invariants (device APIs blocked, WebGPU off in Strict), enforced by
  `FingerprintPolicy::validate`.

The policy is a single declarative source of truth, `FingerprintPolicy`
(`crates/aegis-core/src/fingerprint.rs`), rendered into Chromium managed policies
(and later Firefox preferences) — never applied via ad-hoc content scripts (spec §6,
§16). The aim is a **large anonymity set** (the letterboxing/uniformity philosophy of
Tor Browser and Mullvad Browser), not a unique random device.

## Consequences

**Positive**

- Values are consistent and plausible, so the environment does not stand out as an
  anomaly and does not fight anti-fraud systems (spec §1, §7).
- The "normalized" values are honest — they describe the VM — so there is no fake
  hardware that can be exposed by a clever probe.
- The policy is declarative and testable; each control is covered by an automated
  test (spec §16), and defaults are self-checked (`aegis_core::self_check`).
- Combined with VM isolation and controlled networking, this delivers measurable
  unlinkability to the host.

**Negative / costs**

- Aegis is **recognizable** *as an Aegis environment within a session* — that is
  intentional (unlinkability *to the host*, not per-request unlinkability). A reused
  persistent profile can be linked across its own sessions; ephemeral profiles are
  the answer for unlinkable sessions.
- Stronger normalization (Strict) reduces site compatibility. The UI must state this
  tradeoff clearly and never imply "undetectable" (spec §7, §11).
- The anonymity set is only as large as the population of Aegis users sharing a
  configuration — smaller than Tor Browser's today.

## Alternatives considered

- **Random spoofing / anti-detect catalog.** Rejected (spec §7, §16): inconsistent
  values are a unique fingerprint, fabricating absent hardware is a detectable lie,
  and it targets anti-bot evasion, which is out of scope and forbidden.
- **Per-read Canvas/WebGL randomization.** Rejected: breaks intra-session
  stability, which is itself detectable.
- **No normalization (raw virtualized values).** Better than the host's values, but
  leaves avoidable entropy (fonts, timers, device enumeration) and no shared
  anonymity set. Normalization is a net improvement.

## Related

- [ADR-0001](0001-whonix-style-vm-isolation.md) — the VM that makes normalized
  values *true* (no host devices/fonts to leak).
- [ADR-0003](0003-chromium-mvp-then-firefox-backend.md) — where the Firefox/Mullvad
  backend brings mature RFP/letterboxing.
- [`../privacy-model.md`](../privacy-model.md).
