# Aegis Private Browser — Architecture

Status: Stage 0 (foundations). This document describes the system architecture,
the Rust workspace, the privileged/unprivileged split, the session lifecycle, and
the browser-backend abstraction. It is grounded in the executive specification
(`promt.txt`, §3–§6, §10, §12).

Aegis makes **no** claim of being "undetectable" or "100% anonymous." The honest,
measurable property is **unlinkability to the host**: a website may observe that a
specific browser environment exists, but it should not be able to easily tie that
environment to your real computer. See [`privacy-model.md`](./privacy-model.md)
and [`threat-model.md`](./threat-model.md).

---

## 1. System overview — a Whonix-style split

Aegis manages disposable or persistent, encrypted browsing environments. Each
session runs across **two** virtual machines and reaches the Internet **only**
through a separate network gateway. This mirrors the Whonix Gateway/Workstation
split and the Qubes principle of isolating components into separate domains
(spec §3).

```
Host (user's machine, Linux + KVM/QEMU/libvirt)
│
├── Aegis Manager (unprivileged)
│   ├── Profiles UI (Tauri)            apps/manager-ui
│   ├── CLI (`aegis`)                  apps/cli
│   └── talks over a local, authenticated socket to ↓
│
├── aegis-daemon (small, privileged, NOT root-heavy)   crates/aegis-daemon
│   ├── VM controller           (libvirt/QEMU, disposable qcow2 overlays)
│   ├── Gateway controller      (nftables default-deny, tunnel, kill switch)
│   ├── Network auditor         (6-check preflight gate)
│   ├── Profile store           (isolated profiles, single-writer lock)
│   ├── Secure storage          (Argon2id + XChaCha20-Poly1305)
│   ├── Browser launcher        (BrowserBackend: Chromium MVP, Firefox later)
│   ├── Update client           (signed manifests, downgrade block, rollback)
│   └── Local security audit    (append-only, secret-free records)
│
├── Gateway VM
│   ├── nftables firewall (default-deny)
│   ├── Tor / VPN / SOCKS5 tunnel
│   ├── controlled/captured DNS
│   ├── IPv6 blocked outside the tunnel
│   └── kill switch
│
└── Browser VM
    ├── hardened, minimal Linux
    ├── the browser (hardened Chromium MVP)
    ├── an isolated profile (separate write layer)
    ├── NO access to host devices
    └── exactly ONE virtual NIC → to the Gateway VM only
```

### 1.1 The three structural guarantees (spec §3)

1. The Browser VM does **not** know the host's physical network interface.
2. The Browser VM does **not** know the host's real public IP.
3. The Browser VM has **no** alternative network route.

Everything else in this document exists to make those three statements true and to
keep them true even when something fails.

### 1.2 Data-flow, in one line

```
Web content  ─►  Browser VM  ─►  (one NIC)  ─►  Gateway VM  ─►  tunnel  ─►  Internet
                     ▲                              │
                     └── never a direct path ───────┘   (fail-closed: on any
                                                          break the kill switch
                                                          engages, never a
                                                          direct connection)
```

The Browser VM has a single virtual NIC attached to an isolated libvirt network
whose only other member is the Gateway VM's downstream NIC. The Gateway VM is the
sole holder of an upstream path (a second NIC on the host NAT network). There is
no route from the Browser VM to the host's real interface.

---

## 2. Component responsibilities

### 2.1 Aegis Manager (unprivileged UI + CLI)

The Manager is what the user interacts with. It runs **without privilege** and
performs **no** privileged operations itself. It renders the profiles view and the
diagnostics panel (spec §11) and issues requests to the daemon.

- **Profiles view** (spec §11): per-profile name, type (ephemeral/persistent),
  network mode (Tor/VPN/proxy), protection mode (Balanced/Strict), gateway state,
  visible public IP, profile age, disk usage, last launch.
- **"New private session"** button: one operation that creates a disposable VM,
  starts the gateway, verifies routing, launches the browser, and destroys the
  data on close.
- **Diagnostics panel**: public IP seen from the session, DNS/IPv6/WebRTC status,
  available devices, render mode, profile persistence, kill-switch activity. It
  uses the four-state badge (protection active / partial / unsafe / none) and
  **never** shows "100% anonymous" (spec §11, §16; enforced by
  `ProtectionStatus::label` in `crates/aegis-core/src/preflight.rs`).

Implemented in `apps/manager-ui` (Tauri) and `apps/cli` (`aegis`).

### 2.2 aegis-daemon (privileged orchestrator)

A **small** privileged system daemon (spec §4: "proces uprzywilejowany: mały,
oddzielny daemon systemowy"). It is the only component that touches libvirt,
nftables, and the on-disk profile volumes. It:

- wires the concrete controllers together (dependency injection);
- runs the fail-closed session state machine (§5 below);
- maps every error to a `FailureClass` and engages the kill switch for
  containment/isolation failures **before** returning the error;
- serves the IPC protocol over the local socket with authorization (§4 below);
- writes append-only, secret-free audit records (spec §11).

It is deliberately minimal so that its attack surface is small (spec §10: "daemon
uprzywilejowany posiada minimalny interfejs"). The VM-management logic does **not**
run as root beyond what libvirt requires.

### 2.3 Gateway VM

The gateway is the only component with an upstream path to the host network. Its
firewall is default-deny; only traffic through the configured tunnel is allowed
(spec §5). See `crates/aegis-core/src/gateway.rs` and `firewall/nftables/`.

### 2.4 Browser VM

A hardened, minimal Linux guest with a read-only root, the browser, an isolated
profile on a separate write layer, exactly one NIC, and no host devices (spec §4,
§10). Host-isolation guarantees are encoded as a machine-checkable
`IsolationPolicy` (`crates/aegis-core/src/vm.rs`).

---

## 3. The Rust workspace — crate map

The workspace is a **clean dependency DAG** built on **dependency inversion**:
every capability is a **trait** declared in `aegis-core`; every implementation
crate depends **only** on `aegis-core`; the daemon is the single place that wires
concrete implementations together. This keeps the graph acyclic and makes the
whole system unit-testable with in-memory fakes.

```
                         ┌──────────────────────────┐
                         │        aegis-core        │  contracts + domain model
                         │  (traits, policy types,  │  NO I/O, NO platform code
                         │   error taxonomy, ids)   │
                         └────────────┬─────────────┘
                                      │ every crate depends ONLY on aegis-core
        ┌───────────────┬────────────┼────────────┬───────────────┬───────────────┐
        ▼               ▼            ▼             ▼               ▼               ▼
 secure-storage   profile-store  vm-controller  gateway-      network-audit   browser-
 (SecureStore)    (Profile-      (VmController)  controller    (NetworkAuditor) launcher
                   Repository)                   (Gateway-                      (Browser-
        │               │            │           Controller)        │          Backend)
        │               │            │                │             │              │
        └──────┐        │            │      update-client           │              │
               │        │            │      (UpdateClient)          │              │
               │        │            │            │                 │              │
               ▼        ▼            ▼            ▼                 ▼              ▼
        ┌──────────────────────────────────────────────────────────────────────────┐
        │                              aegis-daemon                                  │
        │        wires concrete impls; runs the session state machine;              │
        │        maps errors → FailureClass → kill switch; serves IPC               │
        └───────────────────────────────────┬──────────────────────────────────────┘
                                             │ aegis-ipc (protocol + transport)
                    ┌────────────────────────┴───────────────────────┐
                    ▼                                                 ▼
              apps/manager-ui                                     apps/cli
              (Tauri UI, unprivileged)                            (`aegis`, unprivileged)
```

### 3.1 `aegis-core` — the contract crate

`aegis-core` is the vocabulary the rest of the workspace speaks. It contains **no
I/O and no platform code** — only types, invariants, and trait definitions.

| Module | What it defines |
|--------|-----------------|
| `error` | The fail-closed error taxonomy: `Error` and `FailureClass` (`requires_killswitch`). |
| `ids` | Strongly-typed, host-independent identifiers (`ProfileId`, `SessionId`, `VmId`, `InstanceId`). |
| `config` | `AppConfig`, storage `Paths`, `ImageRef`/`ImageSet`, `RenderMode`. |
| `network` | Tunnel modes (`NetworkMode` = Tor/VPN/Proxy), `DnsPolicy`, `Ipv6Policy`, `CredentialRef`. |
| `gateway` | `FirewallPolicy` (`fail_closed`, `validate`), `TunnelStatus`, `KillSwitchState`, `GatewayHealth`. |
| `vm` | `VmProvisionRequest` and the machine-checkable `IsolationPolicy` (twelve validated booleans). |
| `fingerprint` | `FingerprintPolicy` (Balanced/Strict) — normalization, **not** spoofing. |
| `permissions` | `PermissionPolicy` — per-profile/per-origin deny-default table; `Feature::is_hard_blocked`. |
| `profile` | `Profile`, `ProfileSpec`, `ProfileType` (ephemeral/persistent). |
| `session` | The fail-closed session state machine (`SessionState`). |
| `preflight` | The six-check connectivity gate; `ProtectionStatus` (four labels). |
| `secure` | Secret wrappers, sealed-blob types, KDF params (secret-safe, zeroizing). |
| `update` | Signed `UpdateManifest`, `Version` (downgrade check), `ApplyOutcome`. |
| `browser` | `BrowserBackend` request/response types and the forbidden-flag guard. |
| `events` | Structured, secret-free `AuditRecord`. |
| `traits` | The trait contracts every capability is expressed through. |

The traits in `traits.rs` are the interfaces (spec §4, §6):

| Trait | Implemented by | Spec |
|-------|----------------|------|
| `VmController` | `vm-controller` | §4, Etap 2 |
| `GatewayController` | `gateway-controller` | §5 |
| `BrowserBackend` | `browser-launcher` | §6 |
| `SecureStore` | `secure-storage` | §8, §10 |
| `ProfileRepository` | `profile-store` | §8 |
| `NetworkAuditor` | `network-audit` | §5 |
| `UpdateClient` | `update-client` | Etap 5, §14 |
| `AuditSink` | daemon-local sink | §11 |

`aegis-core` also exposes `self_check()`, a build-time assertion that the
compiled-in defaults still uphold the security model (hardened isolation by
default, valid fingerprint policies, hard-blocked device classes actually
blocked).

### 3.2 Implementation crates

Each implements one or more `aegis-core` traits and depends **only** on
`aegis-core` (plus third-party libraries). None of them depend on each other.

- **`secure-storage`** — `SecureStore`. Argon2id key derivation + XChaCha20-
  Poly1305 AEAD sealing; ephemeral RAM keys; zeroization. (spec §8, §10)
- **`profile-store`** — `ProfileRepository`. Ephemeral/persistent profiles with a
  single-writer lease so two sessions can never open one profile (spec §8).
- **`vm-controller`** — `VmController`. libvirt/QEMU lifecycle; enforces
  `IsolationPolicy`; provisions disposable qcow2 overlays; shreds them on destroy
  (spec §4, Etap 2).
- **`gateway-controller`** — `GatewayController`. Compiles `FirewallPolicy` into
  nftables (`firewall/nftables/`); manages Tor/VPN/proxy; kill switch (spec §5).
- **`network-audit`** — `NetworkAuditor`. Runs the six preflight checks and leak
  probes from inside the Browser VM via the daemon's guest channel (spec §5).
- **`browser-launcher`** — `BrowserBackend`. Renders `FingerprintPolicy` +
  `PermissionPolicy` into managed policies and a vetted command line; launches the
  browser (spec §6, §7).
- **`update-client`** — `UpdateClient`. Verifies ed25519-signed manifests, checks
  SHA-256 per artifact, enforces the downgrade block, rolls back on failure (spec
  Etap 5, §10, §14). See [`release-process.md`](./release-process.md).

### 3.3 IPC and daemon

- **`aegis-ipc`** — the request/response protocol and transport between the
  UI/CLI and the daemon (§4 below).
- **`aegis-daemon`** — the privileged orchestrator that owns the concrete
  implementations, runs the session state machine, and serves IPC.

### 3.4 Apps

- **`apps/cli`** — the `aegis` command-line client (a member of `default-members`,
  so the security-critical control plane can be verified with a quick `cargo
  check` without the webview toolchain).
- **`apps/manager-ui/src-tauri`** — the Tauri desktop UI. It is a workspace member
  but **excluded** from `default-members` (heavy webview dependencies), so the
  host-critical crates build and test fast (see `Cargo.toml`).

### 3.5 Why this is a DAG (dependency inversion)

Concrete controllers do not call each other. They implement contracts; the daemon
depends on the contracts and injects the implementations. The dependency arrows
therefore all point **inward** to `aegis-core` and then the daemon sits on top —
there is no cycle.

```
   caller (daemon)  ──depends-on──►  trait (aegis-core)  ◄──implements──  impl crate
```

Because callers depend on the abstraction rather than the concrete type, an
implementation can be swapped (real ↔ in-memory fake for tests; Chromium ↔
Firefox backend; libvirt ↔ another VMM) without touching the caller. The unit
tests in `aegis-core` prove the traits are object-safe and `Send + Sync`, so they
can be held as `Box<dyn Trait>` behind the daemon.

---

## 4. Privileged daemon / unprivileged UI split

Aegis separates the **UI** (unprivileged, large attack surface: it renders web-ish
content and user input) from a **small privileged daemon** (the only thing that may
touch libvirt, nftables, and profile keys). This is spec §4:

> proces uprzywilejowany: mały, oddzielny daemon systemowy;
> komunikacja UI–daemon: lokalne Unix socket z autoryzacją.

```
┌──────────────────────────┐        local socket        ┌──────────────────────────┐
│  Aegis Manager (UI/CLI)  │  ── request / response ──►  │       aegis-daemon       │
│  unprivileged            │  ◄── events / status ────   │  privileged, minimal     │
│  - renders profiles view │                             │  - libvirt / nftables    │
│  - renders diagnostics   │      AUTHORIZATION:         │  - profile keys          │
│  - NO privileged ops     │      peer-credential check  │  - session state machine │
└──────────────────────────┘      (uid/gid) on Unix      └──────────────────────────┘
```

### 4.1 Transport and authorization

- **Unix path (first-class platform):** a local Unix-domain socket at
  `paths.daemon_socket` (default `/run/aegis/daemon.sock`). The daemon authorizes
  callers by **peer credentials** (`SO_PEERCRED` uid/gid) — only the owning local
  user may drive it. Filesystem permissions on the socket are the first gate;
  peer-cred is the second.
- **Windows dev fallback:** a loopback endpoint plus a per-run token
  (Windows is a later target via Hyper-V/WSL2, not a first-release platform;
  spec §4). This path is for host-side development only and never carries the
  privileged VM runtime.
- **The gateway rejects host-initiated traffic outside this management channel**
  (`FirewallPolicy::reject_host_initiated`, spec §5) — the socket is the *only*
  sanctioned host↔system control path.

### 4.2 Why the split matters

If the UI process is compromised it still cannot, by itself, reconfigure the
firewall, disable isolation, or read a persistent profile's key: those live behind
the daemon's small, authorized interface. The daemon validates every request
(e.g. `VmProvisionRequest::validate` rejects any un-hardened `IsolationPolicy`
before a VM is ever defined) so a malformed or malicious request fails closed.

---

## 5. Session lifecycle state machine

A session is one Gateway VM + one Browser VM bound to a profile. The disposable
flow (spec §8) is:

> start → clone clean snapshot → random key in RAM → start gateway → start browser
> → session → close processes → wipe key → destroy qcow2 layer.

The state machine in `crates/aegis-core/src/session.rs` makes the ordering
explicit and, crucially, makes it **impossible** to reach a live browsing state
without passing preflight.

```
        ┌────────────┐
        │ Requested  │
        └─────┬──────┘
              ▼
        ┌──────────────┐   clone clean base snapshot, allocate RAM key,
        │ Provisioning │   provision Gateway + Browser VMs (validated
        └─────┬────────┘   IsolationPolicy)
              ▼
        ┌──────────────────┐   Gateway VM boots; tunnel (Tor/VPN/proxy)
        │ GatewayStarting  │   establishes
        └─────┬────────────┘
              ▼
        ┌────────────┐   run the SIX preflight checks (§5.1). No partial pass.
        │ Preflight  │
        └─────┬──────┘
              │  all six pass  ──────────────────────────────────►  ┌──────────┐
              │  (ProtectionStatus::Active)                          │ Browsing │
              │                                                      └────┬─────┘
              │  any check fails / Skipped ─────────┐                     │ user closes
              ▼                                     ▼                     ▼
        ┌────────────┐   any state may fail:  ┌──────────┐   teardown  ┌──────────┐
        │  Closing   │ ◄────────────────────  │  Failed  │ ──────────► │ Closing  │
        └─────┬──────┘   kill switch engaged   └──────────┘             └────┬─────┘
              ▼          (containment/isolation)                             ▼
        ┌────────────┐   close processes, wipe RAM key, shred the        ┌────────────┐
        │ Destroyed  │   qcow2 overlay (ephemeral); nothing left behind. │ Destroyed  │
        └────────────┘   TERMINAL.                                       └────────────┘
```

Enforced properties (from `SessionState::allowed_next`):

- **`GatewayStarting → Browsing` is forbidden.** `Browsing` is reachable *only*
  through `Preflight`. (`session::tests::cannot_skip_preflight_to_browsing`)
- **Every non-terminal state can transition to `Failed`.** `Failed` is what the
  daemon treats as a kill-switch event. (`session::tests::any_state_can_fail`)
- **`Destroyed` is terminal** with no successors.
- A `SessionSummary` is only `is_safe()` when it is `Browsing` **and**
  `ProtectionStatus::permits_browsing()` is true.

### 5.1 The six-check preflight gate (spec §5)

Before the first tab loads, the auditor runs a fixed checklist. If **any** check
fails — or is `Skipped` — the browser does not get Internet access. There is no
partial-pass path (`crates/aegis-core/src/preflight.rs`).

| Check (`CheckId`) | Question it answers |
|-------------------|---------------------|
| `gateway_ready` | Is the Gateway VM up and reachable on the management channel? |
| `tunnel_ready` | Is the tunnel (Tor/VPN/proxy) established? |
| `dns_route_verified` | Does DNS leave only through the intended route? |
| `public_ip_observed` | Was a public IP observed from inside the session — and is it *not* the host's real IP? |
| `webrtc_policy_loaded` | Is the WebRTC non-proxied-UDP block policy loaded? |
| `ipv6_policy_verified` | Is the IPv6 policy (block or tunnel-only) in effect? |

The aggregate maps to one of four `ProtectionStatus` values, and **only `Active`
permits browsing** (fail-closed):

- all pass → `Active` (protection active)
- gateway or tunnel missing → `None` (no protection)
- gateway + tunnel up but a leak-relevant check failed → `Unsafe` (unsafe
  configuration)
- (a non-fatal degradation of a non-containment item) → `Partial`

### 5.2 Fail-closed wiring

Every error carries a `FailureClass`. `NetworkContainment` and `Isolation` failures
return `true` from `requires_killswitch()`, so the daemon engages the kill switch
**before** surfacing the error. On tunnel loss the gateway's `TunnelState` becomes
`Failed` and `KillSwitchState::Engaged` cuts all traffic — the browser is never
allowed to fall back to a direct connection (spec §16).

---

## 6. The `BrowserBackend` abstraction (spec §6)

The engine choice is deliberately behind an abstraction so the MVP can ship a
hardened Chromium backend now and add a Firefox/Mullvad backend later **without
touching the daemon**. See
[ADR-0003](./adr/0003-chromium-mvp-then-firefox-backend.md).

```
                 ┌─────────────────────────────────────────────┐
                 │            trait BrowserBackend             │  (aegis-core)
                 │  id() / capabilities()                      │
                 │  render_policy(req) -> BackendPolicyBundle  │  PURE, synchronous
                 │  launch(req, bundle) -> BrowserHandle       │
                 │  is_running / terminate                     │
                 └───────────────┬───────────────┬─────────────┘
                                 │               │
                   implements ◄──┘               └──► implements
             ┌──────────────────────────┐   ┌──────────────────────────┐
             │  ChromiumBackend  (MVP)  │   │  FirefoxBackend (planned) │
             │  managed-policy JSON +   │   │  Firefox ESR + Tor/Mullvad│
             │  vetted command line;    │   │  hardening; pref.js;      │
             │  sandbox ON, Site        │   │  letterboxing, RFP        │
             │  Isolation ON            │   │                           │
             └──────────────────────────┘   └──────────────────────────┘
```

### 6.1 Pure policy rendering

`render_policy` is **synchronous and pure**: it turns a `BrowserLaunchRequest`
(profile, `FingerprintPolicy`, `PermissionPolicy`, proxy endpoint, render mode,
production flag) into a `BackendPolicyBundle` **without launching anything**. That
lets tests assert the exact generated flags/policies. For Chromium the bundle is a
set of managed-policy JSON documents plus a vetted command line; policies are
applied via the browser's managed-policy mechanism, **not** ad-hoc content scripts
(spec §6, §16). See `browser/policies/managed/`.

### 6.2 The forbidden-flag guard

`BackendPolicyBundle::assert_safe(production)` refuses a command line that contains
`--no-sandbox`, `--disable-web-security`, or `--disable-site-isolation-trials`, and
— in production builds — any `--remote-debugging*` flag (spec §10, §16). This is
the engineering guardrail behind those hard rules; it is covered by unit tests in
`crates/aegis-core/src/browser.rs`.

### 6.3 What both backends must preserve

- Renderer sandbox and Site Isolation stay **on** (spec §6, §10).
- The User-Agent keeps the **real engine version** (spec §6, §14) — no anomalies.
- The WebRTC policy blocks non-proxied UDP (`webrtc_policy_loaded` preflight).
- Fingerprint values are **normalized, stable within a session, and honest about
  the virtual environment** — never randomly spoofed (spec §7; see
  [`privacy-model.md`](./privacy-model.md) and
  [ADR-0002](./adr/0002-fingerprint-normalization-not-spoofing.md)).

`BackendCapabilities` advertises what a backend enforces (letterboxing, Site
Isolation, renderer sandbox, WebRTC policy) so the daemon can pick a backend that
satisfies the requested `ProtectionLevel`.

---

## 7. Platform note

The first-class platform is **Linux + KVM/QEMU/libvirt** with qcow2 disks, TAP +
nftables networking, and a Tauri/native Rust UI (spec §4). Windows is a later
target via Hyper-V or WSL2 and is not a first-release platform. The host-side Rust
workspace is cross-platform and its policy logic is verified with `cargo test` on
any OS; the VM/gateway runtime requires Linux.

---

## 8. Cross-references

- [`threat-model.md`](./threat-model.md) — assets, adversary tiers, attack surface.
- [`privacy-model.md`](./privacy-model.md) — the unlinkability property and
  fingerprint normalization.
- [`release-process.md`](./release-process.md) — signed images/packages, SBOM,
  downgrade protection, rollback.
- [`../SECURITY.md`](../SECURITY.md) — security policy and the agent hard-rules.
- [ADRs](./adr/) — the recorded architecture decisions.
