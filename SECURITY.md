# Security Policy

Aegis Private Browser is security-critical software: its whole purpose is to keep a
browsing environment **unlinkable to the host**. We take reports seriously and hold
the project to the engineering guardrails below.

**Honest scope.** Aegis does **not** claim to be "undetectable" or "100%
anonymous." A website can always observe *that a specific browser environment
exists*; the goal is that what it observes cannot be linked back to your real
computer. Aegis cannot protect you once you log into your own accounts or supply
identifying data. See the threat-model summary below.

---

## Supported versions

Aegis is pre-1.0 (`0.x`). During this phase, security fixes are provided for the
**latest released `0.x` version only**. Older `0.x` versions are not maintained;
because updates enforce monotonic-version downgrade protection (see
[`docs/release-process.md`](docs/release-process.md)), users are expected to stay
on the newest release.

| Version | Supported |
|---------|-----------|
| latest `0.x` | Yes (security fixes) |
| older `0.x` | No |
| `< 0.1` / pre-release | No |

Once a stable line is released, this table will be updated with a longer support
window and end-of-life dates.

---

## Reporting a vulnerability

**Please do not open a public issue for a security vulnerability.**

- Report privately via GitHub's **"Report a vulnerability"** (Security Advisories)
  on the repository, or email the maintainers at the address published in the
  repository's security contact.
- Include: affected version/commit, a description of the issue, reproduction steps
  or a proof of concept, and the impact you observed (e.g. IP/DNS/WebRTC leak,
  profile cross-contamination, isolation escape, signature/downgrade bypass).
- **Do not include real secrets** (proxy/VPN credentials, private keys, personal
  data) in a report.

What to expect:

- Acknowledgement of your report within a few business days.
- An assessment and, for valid issues, a remediation plan and a coordinated
  disclosure timeline.
- Credit in the release notes if you would like it.

Leak-class findings (real IP / DNS / WebRTC / IPv6 escaping the tunnel), isolation
escapes (Browser VM reaching host devices or an alternate route), and
update-integrity bypasses (accepting an unsigned/older/corrupt update) are treated
as the **highest** severity, consistent with the project's "no leak before
compatibility" priority.

---

## Threat-model summary

Aegis targets **unlinkability to the host** by cutting four layers of linkage at
once — browser data, host hardware/OS, network, and user behavior/accounts. It is
built **fail-closed**: any failure that could break network containment or host
isolation severs connectivity rather than degrading to a direct connection.

Aegis **is** designed to resist: cookie/storage tracking, ordinary
fingerprinting-API correlation, WebRTC IP leaks, DNS escaping the tunnel, the
Browser VM reading host hardware, profile cross-contamination, opening a session
with no active protection, basic malicious page code in the renderer, and data
recovery after a disposable profile is destroyed.

Aegis does **not** defend against: identification after you log into your own
accounts or supply real data; a global passive adversary who observes both ingress
and egress; hypervisor/firmware compromise; zero-days in the browser/OS/hypervisor;
or tracking outside the application.

Full details:

- [`docs/threat-model.md`](docs/threat-model.md) — assets, adversary tiers, attack
  surface, protection→enforcement mapping.
- [`docs/privacy-model.md`](docs/privacy-model.md) — the exact privacy property and
  fingerprint normalization (not spoofing).
- [`docs/architecture.md`](docs/architecture.md) — the Whonix-style split, the
  privileged-daemon/unprivileged-UI boundary, and the fail-closed session state
  machine.

---

## Engineering guardrails (agent hard-rules, spec §16)

The executive specification (`promt.txt`, §16) lays down non-negotiable rules.
They are treated as **engineering guardrails**: wherever possible they are enforced
in code and covered by automated tests, not left to convention.

| # | Hard rule (spec §16) | How it is upheld |
|---|----------------------|------------------|
| 1 | Do **not** replace full isolation with a browser extension. | Isolation is a VM boundary (`vm.rs` `IsolationPolicy`), never an in-page extension. |
| 2 | Do **not** use Electron as the primary page container. | Pages run in a hardened browser inside the Browser VM; the UI (Tauri) never hosts untrusted content. |
| 3 | Do **not** implement accidental spoofing. | Fingerprint values are normalized and session-stable, not randomized (`fingerprint.rs`); see [ADR-0002](docs/adr/0002-fingerprint-normalization-not-spoofing.md). |
| 4 | Do **not** use `--no-sandbox`. | Rejected by `BackendPolicyBundle::assert_safe` (`browser.rs`), unit-tested. |
| 5 | Do **not** use `--disable-web-security`. | Rejected by `assert_safe`, unit-tested. |
| 6 | Do **not** run a production browser with remote debugging open. | `assert_safe(production=true)` rejects `--remote-debugging*`; no networked DevTools endpoint (spec §10). |
| 7 | Do **not** pass through the host GPU. | `GpuBackend` is `VirtioGpu` or `Software` only — physical passthrough is not representable; `no_pci_passthrough` in `IsolationPolicy`. |
| 8 | Do **not** store proxy passwords in plaintext. | Credentials are held as `CredentialRef` references (`network.rs`); secrets are sealed with XChaCha20-Poly1305 (`secure-storage`). |
| 9 | Do **not** perform automatic login to user accounts. | Aegis never automates account logins; this is documented as a user-responsibility layer. |
| 10 | Do **not** advertise the product as "undetectable." | Only four honest status labels exist (`ProtectionStatus::label`); "100% anonymous" is never shown (spec §11). |
| 11 | Confirm **every** protection with an automated test. | Each control has a unit/integration test; see the protection→enforcement table in [`docs/threat-model.md`](docs/threat-model.md). |
| 12 | Describe **every** Chromium modification and cover it with a regression test. | `browser/chromium-patches/` documents each change; `tests/browser-api` regresses them. |
| 13 | Priority: **no leak before compatibility.** | When a control and a convenience conflict, the control wins; the UI states the tradeoff. |
| 14 | A failure must **always end in a block, never a connection without protection.** | Fail-closed: `FailureClass::requires_killswitch`, six-check preflight gate, `DefaultPolicy::Drop`, kill switch (`error.rs`, `preflight.rs`, `gateway.rs`). |

Additional standing invariants enforced across the codebase:

- The Chromium sandbox and Site Isolation are preserved and never disabled.
- The User-Agent keeps the real engine version (spec §6, §14) — no anomalies.
- The privileged VM-management process does not run root-heavy; the UI is
  unprivileged and talks to a small daemon over a local, authorized socket.
- Updates are ed25519-signed with SHA-256 artifacts; downgrades and unsigned or
  corrupt updates are rejected, with automatic rollback (see
  [`docs/release-process.md`](docs/release-process.md)).
- `unsafe_code` is `forbid`-en workspace-wide (`Cargo.toml`).

---

## Disclosure

We follow coordinated disclosure. Please give us a reasonable window to release a
fix before any public write-up. We are happy to credit reporters.
