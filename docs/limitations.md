# Aegis Private Browser — Limitations and Residual Risks

Status: Stage 0 (foundations).

Aegis is designed to be honest about its boundaries. It provides **unlinkability
to your real computer**, not anonymity and not undetectability. This document is
the authoritative list of what the product does **not** protect against. It must
never be contradicted by marketing copy, the UI, or documentation (spec §16 —
never advertise the product as "undetectable"; the diagnostics panel must never
show "100% anonymous", spec §11).

---

## 1. What Aegis does NOT guarantee (spec §2, "nie gwarantuje")

These are explicit non-goals from the specification. None of them is a bug; they
are outside the model.

| # | Not protected against | Why it is out of scope |
|---|-----------------------|------------------------|
| L1 | **Identification after you log in to your own account** | Once you authenticate as yourself, the site knows who you are. Isolation cannot undo an intentional login. |
| L2 | **Giving away real identifying data** — e-mail, phone, address, payment details | Self-supplied identity bypasses every technical layer. Aegis never auto-logs-in (spec §16) precisely to avoid doing this on your behalf. |
| L3 | **Behavioral correlation by a very strong adversary** | Typing rhythm, timing, mouse dynamics, writing style, and site-visit patterns are content-layer signals Aegis does not normalize. |
| L4 | **Host compromise via hypervisor or firmware attack** | If the hypervisor, firmware, or host OS is compromised, the isolation boundary itself is broken. Aegis assumes an uncompromised host and hypervisor. |
| L5 | **A global adversary observing all ingress and egress at once** | End-to-end traffic correlation defeats tunnels including Tor. This is a well-known limit of low-latency anonymity networks. |
| L6 | **Zero-day bugs in the browser, OS, or hypervisor** | Aegis reduces exposure (sandbox, Site Isolation, read-only root, syscall filtering, no remote debugging) but cannot preempt unknown vulnerabilities. |
| L7 | **Tracking outside the application** | Anything done in another browser, another app, or offline is beyond Aegis's boundary. |

---

## 2. Residual risks (present even when everything works)

These risks remain *by design* after all controls are correctly implemented.

### 2.1 Intra-session recognizability
Fingerprint values are deliberately **stable within a session** (spec §7). A site
can therefore recognize the environment for the duration of that session. This is
intended: the goal is unlinkability to the host, not unlinkability of requests
inside one session.

### 2.2 Cross-session linkage of reused persistent profiles
If the same persistent profile is reused, sites may link its sessions to each
other (shared cookies/storage and a stable fingerprint), even though they still
cannot identify the real host. **Use ephemeral profiles when cross-session
unlinkability matters.**

### 2.3 Network-operator visibility
- **Tor mode**: strongest at hiding the public IP, but some sites block exit
  nodes, and a global observer can still attempt end-to-end correlation (L5).
- **VPN mode**: better compatibility, but the VPN operator sees the entry
  address (they know *where you connect from*, not your host hardware/profile).
- **Proxy mode**: acceptable only after Aegis confirms DNS and required protocols
  actually traverse the proxy; a proxy that cannot carry DNS remotely is rejected.

The choice of mode is an explicit, user-visible tradeoff.

### 2.4 The anonymity set is finite
Uniformity works only in proportion to how many users share the same
configuration. A small user base, an unusual screen bucket, or an exotic locale
reduces the crowd you blend into. Aegis maximizes uniformity but cannot manufacture
a large population by itself.

### 2.5 Fingerprint normalization is not perfection
Normalization reduces host linkage; it does not make the environment
indistinguishable from a mainstream retail Chrome install. A determined site may
detect that it is a virtualized/normalized environment. Aegis deliberately does
**not** fight anti-fraud systems to hide this (spec §1, §7) — being recognized *as
an Aegis-class environment* is acceptable; being linked *to your host* is not.

### 2.6 Content-layer and application-layer leaks
Uploaded files may contain metadata (EXIF, author fields, document properties);
pasted text, form contents, and downloaded-then-opened files can carry identity.
Downloads are quarantined, but Aegis cannot scrub the *content* users choose to
send.

### 2.7 Timing and side channels
High-resolution timing is coarsened (fixed, never jittered), but no client-side
mitigation eliminates all timing/side-channel signal available to a sophisticated
adversary.

### 2.8 Persistent-profile secrets
Persistent profiles are only as strong as the user's password and the host's
integrity. A weak password, a keylogger on a compromised host, or an unlocked
machine defeats at-rest encryption. Keys live in RAM while unlocked.

### 2.9 First-run and update trust
Security depends on obtaining genuine, signed VM images and packages. Signature
verification, hash checks, downgrade protection, and rollback (spec §5 Etap 5,
§14) mitigate tampering *after* first install, but the initial trust root
(signing keys) must be obtained authentically.

### 2.10 Windows is not a first-release platform
The first supported platform is Linux (KVM/QEMU + libvirt). A future Windows port
(Hyper-V / WSL2) may have a different, weaker isolation profile and must be
re-evaluated against this document before it is relied upon (spec §4).

---

## 3. Correct expectations

- Aegis provides **unlinkability to the host**, layered isolation, disposable
  sessions, controlled networking, and normalized (not spoofed) fingerprints.
- Aegis does **not** provide anonymity, undetectability, protection after
  self-identification, or defense against host/hypervisor compromise, zero-days,
  or a global passive adversary.
- The correct mental model: *a genuinely separate environment per session that is
  hard to tie to your real machine* — not *an invisible browser*.
