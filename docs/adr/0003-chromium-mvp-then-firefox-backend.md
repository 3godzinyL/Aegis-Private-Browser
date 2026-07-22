# ADR-0003: Chromium MVP first, Firefox/Mullvad backend later, behind a `BrowserBackend` trait

- Status: Accepted
- Date: 2026-07-22
- Deciders: Aegis Project
- Spec references: §6, §7, §10, §13 (Etap 2, Etap 4), §16

## Context

Aegis needs a browser engine that (a) keeps a strong process sandbox and Site
Isolation, (b) can be driven by managed policies rather than ad-hoc content scripts,
and (c) keeps a real, standards-compliant engine version so the environment is not an
anomaly (spec §6, §7, §16). The spec identifies two realistic options (spec §6):

- **Variant A — highest privacy:** a Firefox-ESR-based engine with Tor/Mullvad
  hardening (mature anti-fingerprinting: letterboxing, timer clamping, font/device
  restriction, first-party isolation, a large shared anonymity set). Mullvad Browser
  is developed with the Tor Project for exactly this uniformity goal.
- **Variant B — Chromium compatibility:** a fork of Chromium with a minimal patch
  set, preserving the sandbox and Site Isolation, removing Google account
  login/sync, disabling unneeded telemetry, and applying privacy policies in code.

The spec's own decision (spec §6, "Decyzja dla agenta") is: implement Chromium in the
Browser VM first (MVP), then prepare a `BrowserBackend` interface so a Firefox/Mullvad
backend can be added later.

## Decision

1. Ship the **MVP with a hardened Chromium backend** inside the Browser VM, with **no
   hardware spoofing** (spec §6, Etap 2/Etap 4). Requirements: keep the Chromium
   sandbox and Site Isolation, keep the real engine version in the User-Agent, remove
   Google login/sync, disable unneeded telemetry, apply privacy policies via the
   managed-policy mechanism, and use a separate `user-data-dir` per persistent profile
   / a separate VM filesystem per disposable session (spec §6).
2. Define a **`BrowserBackend` trait** in `aegis-core`
   (`crates/aegis-core/src/traits.rs` + `browser.rs`) so the engine sits behind an
   abstraction and a **Firefox/Mullvad backend can be added later without touching the
   daemon**. `render_policy` is pure and synchronous (returns a `BackendPolicyBundle`
   of managed policies + a vetted command line) so the generated flags/policies are
   unit-testable without launching anything.
3. Enforce the hard rules in code at the backend boundary:
   `BackendPolicyBundle::assert_safe` rejects `--no-sandbox`,
   `--disable-web-security`, `--disable-site-isolation-trials`, and — in production —
   any `--remote-debugging*` flag (spec §10, §16).

Chromium is chosen for the MVP because its multi-process sandbox and Site Isolation
are strong and well-documented, its managed-policy mechanism lets us apply privacy
controls in-code (not via content scripts), and it maximizes site compatibility for a
first release.

## Consequences

**Positive**

- Fastest path to a usable, compatible MVP on a mature, sandboxed engine.
- The abstraction (`BrowserBackend`) keeps the daemon engine-agnostic; adding the
  Firefox/Mullvad backend is additive, and the daemon can pick a backend by advertised
  `BackendCapabilities` (letterboxing, Site Isolation, renderer sandbox, WebRTC
  policy).
- Policy rendering is pure and testable; forbidden flags are impossible to ship by
  construction (`browser::tests`).
- The path to the strongest anti-fingerprinting (Firefox/Mullvad RFP + letterboxing +
  a larger shared anonymity set) is preserved for Variant A.

**Negative / costs**

- Chromium's anti-fingerprinting is weaker than Firefox/Mullvad's; the MVP leans on VM
  isolation + normalization to compensate and does not match Tor/Mullvad's anonymity
  set.
- Maintaining a Chromium fork is heavy: every modification must be described and
  covered by a regression test (spec §16), and security-relevant patches must track
  upstream (`browser/chromium-patches/`, `tests/browser-api`).
- Two backends mean two policy renderers and two regression suites to keep honest over
  time.

## Alternatives considered

- **Firefox/Mullvad first (Variant A first).** Rejected as the MVP per spec §6, which
  sequences Chromium first, then the Firefox backend. Variant A remains the target for
  the strongest-privacy backend behind the same trait.
- **Chromium only, no abstraction.** Rejected: it would couple the daemon to one
  engine and make the future Firefox/Mullvad backend a rewrite rather than an addition
  (spec §6 explicitly asks for the `BrowserBackend` interface).
- **Electron / CEF as the page container.** Rejected by spec §16 ("do not use
  Electron as the primary page container"); not a security boundary for untrusted web
  content, and it weakens the sandbox/Site-Isolation guarantees.
- **Weaken Chromium for development convenience** (`--no-sandbox`,
  `--disable-web-security`, open remote debugging). Rejected by spec §16 and blocked
  in code by `assert_safe`.

## Related

- [ADR-0002](0002-fingerprint-normalization-not-spoofing.md) — the normalization
  policy both backends render.
- [ADR-0001](0001-whonix-style-vm-isolation.md) — the VM the browser runs inside.
- [`../architecture.md`](../architecture.md) §6, [`../release-process.md`](../release-process.md).
