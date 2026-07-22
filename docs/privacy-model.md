# Aegis Private Browser — Privacy Model

Status: Stage 0 (foundations).

This document states *what privacy property Aegis actually provides* and how it is
achieved. It deliberately does not promise anonymity, undetectability, or "100%"
of anything (spec §16). What Aegis targets is **unlinkability to your real
computer**.

---

## 1. The goal: unlinkability

The property, in plain terms (spec, closing dialogue):

> A website may observe something about the environment, but that data must not
> lead back to your real computer or your normal browser.

A site can legitimately conclude:

> "This particular browser environment has a particular fingerprint."

A site should **not** be able to easily conclude:

> "This is the same Chrome profile, the same cookies, the same real IP, the same
> physical graphics card, and the same devices as on the host."

This is a real, measurable protection level — not mathematical anonymity. The
strength comes from combining *all* of the following (spec §17); any single layer
alone is cosmetic:

```
VM isolation
  + controlled network
  + disposable profiles
  + fingerprint normalization
  + a current, unweakened engine
  + no self-identifying user actions
```

---

## 2. The four layers of linkage (all must be cut at once)

Unlinkability holds only if **all four** layers are cut simultaneously. A leak in
any one re-links the environment to the host.

### Layer 1 — Browser data

Separate cookies, cache, `localStorage`, `sessionStorage`, IndexedDB, Cache
Storage, HTTP cache, service workers, HSTS/network state, client certificates,
history, downloads, permissions, extension data, saved logins, autofill, shader
cache, and crash dumps. No shared profile with the host. Ephemeral profiles are
destroyed entirely after the session.

Enforced by: per-profile stores (`profile.rs`, `ProfileType::Ephemeral`
shredding), separate `user-data-dir` per persistent profile, separate VM
filesystem per disposable session.

### Layer 2 — Hardware and OS

The site should not see the host's real fonts, resolution, audio devices,
cameras, GPU, sensors, or OS settings. Aegis runs a full VM with **no physical
passthrough** of GPU, camera, microphone, USB, or clipboard.

Enforced by: `IsolationPolicy::hardened()` (`vm.rs`), `GpuBackend::VirtioGpu` or
`Software` (never physical passthrough), and fingerprint normalization
(`fingerprint.rs`).

### Layer 3 — Network

All traffic, DNS, and WebRTC must exit through the same channel: Tor, VPN, or
proxy. A single leak of the real IP breaks the entire isolation.

Enforced by: single NIC to the Gateway VM, nftables default-deny, DNS capture,
IPv6 block, WebRTC non-proxied-UDP policy, and the kill switch. See
[`data-flow.md`](./data-flow.md) and [`host-info-to-cut.md`](./host-info-to-cut.md).

### Layer 4 — Behavior and accounts

If you log in to your own Google account, type your real e-mail, or reuse the same
phone number, the fingerprint stops being the deciding factor. Aegis cannot
protect against self-identification; it explicitly does not perform automatic
logins (spec §16) and does not promise anonymity after you supply identifying
data (spec §1, §2).

This layer is the user's responsibility. Aegis documents it plainly rather than
implying it away.

---

## 3. Fingerprint normalization, NOT spoofing

This is the central design decision (spec §7), and it is the opposite of what
"anti-detect" browsers do.

### What Aegis does NOT do (forbidden, spec §7, §16)

- No random User-Agent.
- No random GPU strings.
- No catalog of hundreds of fake hardware configurations.
- No per-read random Canvas.
- No independently swapped values across contexts.
- No tampering aimed at passing anti-bot / anti-fraud tests.
- No simulating physical hardware the VM does not actually have (no fake
  RTX/Radeon model — spec §4).

Random spoofing is self-defeating: inconsistent or improbable values are
*themselves* a strong, unique fingerprint, and they invite conflict with
anti-fraud systems (which the spec explicitly forbids interfering with, §1).

### What Aegis does instead

**Stabilization (uniformity within a session).** Every value a site can read is
stable and consistent across the main frame, iframes, workers, service workers,
WebGL, Canvas, and AudioContext. Inconsistency between contexts is itself a
fingerprint, so it is forbidden.

**Normalization / restriction.** Instead of fabricating hardware, Aegis exposes
the *real (virtualized) environment*, restricted by the browser. The VM genuinely
has a virtio/software GPU, a standard bundled font set, a standardized viewport,
and no host devices — so the "normalized" value is the truth about the VM, not a
lie about a nonexistent machine.

The aim is a **large anonymity set**: every Aegis session of a given protection
level looks like every other Aegis session, rather than being a unique random
device. This is the letterboxing / uniformity philosophy used by Tor Browser and
Mullvad Browser.

The User-Agent keeps the **real engine version** (spec §6, §14) so the environment
remains a plausible, standards-compliant browser rather than an anomaly.

Implemented by `FingerprintPolicy` in `crates/aegis-core/src/fingerprint.rs`,
which is the single declarative source of truth rendered into Chromium managed
policies (and later Firefox preferences).

---

## 4. Two protection levels: Balanced vs Strict

Both levels share the non-negotiable invariants (device APIs blocked, WebGPU off
in Strict, sensors/battery suppressed — enforced by `FingerprintPolicy::validate`).
They differ in how aggressively they normalize.

| Aspect | Balanced (`ProtectionLevel::Balanced`) | Strict (`ProtectionLevel::Strict`) |
|--------|----------------------------------------|-------------------------------------|
| WebGL | `VirtualBackend` (virtio/software, driver strings normalized) | `Disabled` (or `Restricted`) |
| WebGPU | Disabled | Disabled |
| Canvas | `Passthrough` (session-stable) | `Limited` (session-stable, uniform limiting) |
| Letterboxing | Off | On (content area rounded to shared buckets) |
| Fonts | Standard bundled set only | Standard bundled set only |
| Timer coarsening | 100 µs (fixed, never jittered) | 100 000 µs / 100 ms (fixed) |
| Media device enumeration | Limited | Limited |
| `hardwareConcurrency` | Fixed = 4 | Fixed = 2 |
| Battery API | Suppressed | Suppressed |
| Sensor APIs | Suppressed | Suppressed |
| Bluetooth/USB/Serial/HID/MIDI | Blocked | Blocked |
| Timezone / language | Shared canonical (`UTC` / `en-US`) | Shared canonical (`UTC` / `en-US`) |
| Site compatibility | Most sites work normally | More breakage |

These values are the defaults in `FingerprintPolicy::balanced()` and
`FingerprintPolicy::strict()`; per-API rationale is in
[`browser-api-table.md`](./browser-api-table.md).

---

## 5. The compatibility tradeoff

The core conflict (spec §7, closing dialogue): *the more you block or fake, the
less you look like an ordinary Chrome — and the more sites break.*

- The UI must clearly communicate that **stronger privacy can mean lower
  compatibility** (spec §7). Mozilla issues the same warning for strong Resist
  Fingerprinting.
- The design resolution is *not* "randomize 100 monitors and cards" but "produce
  a few very consistent, standard configurations so every user of the app looks
  alike."
- Design priority is fixed by the spec (§16): **no leak before compatibility.**
  When a normalization and a broken site conflict, the user may step down from
  Strict to Balanced, but Aegis never weakens network containment or host
  isolation for the sake of a site.

Aegis also never modifies APIs to defeat anti-fraud systems (spec §1, §7); a
normalized-but-honest environment is allowed to be recognized *as that
environment* — it just cannot be tied to the host.

---

## 6. The realistic end result (spec §17)

After a correct implementation, a website can still say:

> "This specific browser environment has a specific fingerprint."

It should **not** be able to easily say:

> "This is the same Chrome profile, the same cookies, the same real IP, the same
> physical graphics card, and the same host devices."

Two honest caveats that follow directly from the model:

1. **Within a session**, the environment is recognizable (values are stable by
   design). That is intentional — it is unlinkability *to the host*, not
   unlinkability *of requests within one session*.
2. **A reused persistent profile can be linked across sessions.** If you always
   use the same virtual profile, sites may correlate its sessions with each other
   — even though they still cannot tell what your real computer is. Use ephemeral
   profiles for unlinkable sessions.

The measurable claim is therefore: *each Aegis session is a genuinely separate
environment — not merely a tab with a swapped User-Agent — that is hard to link
back to the host.* Nothing stronger is promised.
