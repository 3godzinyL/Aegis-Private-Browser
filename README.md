<div align="center">

# 🛡️ Aegis Private Browser

**Disposable, encrypted browsing environments with a Whonix-style network split — built for _unlinkability to your real computer_, not empty "100% anonymous" promises.**

[![License: GPL-3.0](https://img.shields.io/badge/License-GPL--3.0--or--later-blue.svg)](LICENSE)
[![Rust 1.82+](https://img.shields.io/badge/Rust-1.82%2B-orange.svg?logo=rust)](rust-toolchain.toml)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows%20(dev)-6E56CF.svg?logo=linux&logoColor=white)](docs/architecture.md)
[![Tests](https://img.shields.io/badge/tests-398%20passing-brightgreen.svg)](docs/threat-model.md)
[![Made with Rust](https://img.shields.io/badge/Made%20with-Rust-000000.svg?logo=rust)](Cargo.toml)
[![PRs welcome](https://img.shields.io/badge/PRs-welcome-ff69b4.svg)](#-contributing)

<br/>

<img src="docs/images/new-session.png" alt="Aegis — New Private Session: platform selector, four safety tiers, advanced tuning, live preview" width="820"/>

<sub>The redesigned **New Private Session** dialog — pick a platform (Linux full-VM / Windows host), one of four safety tiers, then optionally fine-tune everything under **Advanced**. A **Preview** tab shows exactly what a site will see. Built-in **EN / PL** UI.</sub>

</div>

> [!NOTE]
> The badges above are **static** shields.io badges so they render on a fresh clone with no CI wired up.
> After you publish this repository, swap them for live badges (e.g. a GitHub Actions
> workflow badge for the real test count/status, `shields.io/github/license/<owner>/<repo>`,
> release/version badges, etc.). A `CI` workflow already lives in [`.github/workflows/ci.yml`](.github/workflows/ci.yml).

---

## What Aegis actually gives you

Aegis manages **disposable or persistent, encrypted browser environments**. Each private session runs
in its **own virtual machine** and can reach the Internet **only** through a separate, **fail-closed**
network gateway. If the tunnel drops, the kill switch cuts the browser off — it never silently falls
back to a direct connection.

The honest, measurable property is **unlinkability to the host**:

> A website may still observe that *"this browsing environment has some fingerprint."*
> It should **not** be able to tie that environment to your real computer, your everyday Chrome
> profile, your real IP, your physical GPU, or your host devices.

Aegis does **not** promise "100% anonymity," it does **not** try to defeat anti-fraud systems, and it
**cannot** protect you once you log into your own accounts or type in identifying data. Read the
honest boundaries in **[`docs/limitations.md`](docs/limitations.md)** before you rely on it.

---

## ✨ Features

- 🧱 **VM isolation** — the site runs in a Browser VM with no host GPU, camera, mic, USB, clipboard, or shared folders, and no knowledge of the host's physical NIC.
- 🌐 **Fail-closed networking** — one route out (Tor / VPN / SOCKS5 / HTTP) through a Gateway VM; `nftables` default-deny; DNS captured; IPv6 blocked; kill switch on any tunnel loss.
- 💨 **Disposable profiles** — an ephemeral session clones a clean, read-only base snapshot onto a throwaway encrypted overlay that is **shredded** at close. Nothing is recoverable afterwards.
- 🎭 **Fingerprint normalization, not spoofing** — values are normalized to a shared baseline and kept stable within a session, aiming for a large uniform anonymity set instead of a unique fake device.
- 🔐 **Encrypted persistent profiles** — Argon2id + XChaCha20-Poly1305, password-derived keys held only in RAM while unlocked.
- 🧩 **Unweakened engine** — Chromium sandbox and Site Isolation stay **on**; the real engine version stays in the User-Agent. We never ship `--no-sandbox` or `--disable-web-security`.
- ✅ **Six-check preflight gate** — the first tab never loads unless gateway, tunnel, DNS route, public IP, WebRTC policy, and IPv6 policy all pass.
- 🔏 **Signed images & updates** — ed25519-signed manifests, SHA-256 per artifact, downgrade protection, automatic rollback, SBOM.
- 🖥️ **Two front-ends** — a Tauri desktop UI and an `aegis` CLI over a small, authorized local socket to a privileged (but not root-heavy) daemon.
- 🧪 **Test-backed guarantees** — every protection is enforced in the type system and covered by automated tests (see the [threat model](docs/threat-model.md#7-protection--enforcement-mapping)).

---

## 🚦 Two ways to run

Aegis supports two postures. The **secure default** is full VM isolation; the host-browser mode is an
honest, clearly-labelled **reduced-protection** escape hatch for machines without a hypervisor.

| | 🏰 **Full VM isolation** _(default, `Enforcement::secure`)_ | 🪟 **Host-browser mode** _(reduced, `Enforcement::host_browser`)_ |
|---|---|---|
| **How it works** | Gateway VM + Browser VM (Whonix-style split) | Browser runs as a **host process**, routed through Tor/proxy on the host |
| **Host device isolation** | ✅ Full — no GPU/cam/mic/USB/clipboard/shared folders | ⚠️ None — the site executes on your real OS |
| **Network containment** | ✅ Gateway VM, `nftables` default-deny, kill switch | ⚠️ Host-side proxy/Tor only (`AEGIS_HOST_PROXY`) |
| **Fingerprint normalization** | ✅ Balanced / Strict | ➖ Reduced (host OS characteristics leak more) |
| **Requires** | Linux + KVM/QEMU/libvirt | Any host with a working proxy/Tor |
| **Isolation level reported** | `full VM isolation` | `host process (reduced)` |
| **Use it for** | The real thing | Trying Aegis / hosts without KVM (Windows dev target) |

> [!IMPORTANT]
> Host-browser mode does **not** provide VM isolation. The UI and CLI label it as *reduced protection*
> and never claim full anonymity in that mode. It needs Tor or a proxy — a VPN is only supported in full-VM mode
> (the Gateway VM routes it). Full setup is in **[`docs/INSTALL-linux.md`](docs/INSTALL-linux.md)**.

---

## 🗺️ Architecture

```mermaid
flowchart TD
    subgraph Host["🖥️  Host (Linux + KVM/QEMU/libvirt)"]
        UI["Aegis Manager<br/>Tauri UI + aegis CLI<br/><i>unprivileged</i>"]
        D["aegis-daemon<br/><i>small, privileged, NOT root-heavy</i><br/>vm · gateway · audit · profiles<br/>secure-storage · launcher · updates"]
        UI -- "local authorized socket<br/>(SO_PEERCRED)" --> D
    end

    subgraph GW["🌐  Gateway VM"]
        FW["nftables default-deny<br/>Tor / VPN / SOCKS5<br/>DNS capture · IPv6 block<br/>kill switch"]
    end

    subgraph BR["🧱  Browser VM"]
        CH["hardened Linux · read-only root<br/>hardened Chromium<br/>ONE NIC → Gateway only"]
    end

    D -- "libvirt / QEMU" --> GW
    D -- "libvirt / QEMU" --> BR
    BR -- "single virtual NIC" --> GW
    GW -- "tunnel only (fail-closed)" --> NET(["🌍 Internet"])
```

```
Web content ─► Browser VM ─► (one NIC) ─► Gateway VM ─► tunnel ─► Internet
                   ▲                          │
                   └──── never a direct path ─┘   (on any break the kill switch
                                                    engages — never a direct
                                                    connection)
```

The three structural guarantees: the Browser VM does **not** know the host's physical NIC, does **not**
know the host's real public IP, and has **no** alternative network route. Everything else exists to keep
those true even when something fails. Full detail: **[`docs/architecture.md`](docs/architecture.md)**.

---

## 🔄 How a private session works

1. **Provision** — clone the clean, read-only base snapshot onto a fresh disposable qcow2 overlay; allocate a random encryption key **in RAM**.
2. **Start the gateway** — boot the Gateway VM; establish the tunnel (Tor / VPN / SOCKS5 / HTTP).
3. **Preflight (the gate)** — run the **six** checks: `gateway_ready`, `tunnel_ready`, `dns_route_verified`, `public_ip_observed`, `webrtc_policy_loaded`, `ipv6_policy_verified`. **No partial pass.**
4. **Browse** — only if all six pass (`ProtectionStatus::Active`) does the Browser VM boot and the first tab get Internet. The session state machine makes it *impossible* to reach browsing without passing preflight.
5. **Watch** — the diagnostics panel shows public IP, DNS/IPv6/WebRTC status, devices, render mode, and kill-switch activity, using a four-state badge (protection active / partial / unsafe / none) — never "100% anonymous."
6. **Close & destroy** — terminate processes, wipe the RAM key, and `shred` the qcow2 overlay. An ephemeral session leaves **no** writable residue.

If anything on the containment or isolation path fails at any point, the error is classified and the
**kill switch engages before the error is even surfaced** (fail-closed).

---

## 🚀 Quickstart

> First-class platform is **Linux + KVM/QEMU/libvirt**. The host-side Rust workspace is cross-platform and
> its logic is fully verified with `cargo test` on any OS; the VM/gateway runtime requires Linux.

### Build & test the host-side control plane (any OS)

```sh
# Clone
git clone <your-repo-url> aegis-private-browser
cd aegis-private-browser

# Build & test the security-critical crates (Tauri UI is excluded from default-members)
cargo build --release
cargo test  --workspace

# Lint like CI does
cargo fmt --all -- --check
cargo clippy --workspace --all-targets
```

### Run the CLI

```sh
# The CLI talks to the daemon over the local authorized socket.
cargo run -p aegis-cli -- status
cargo run -p aegis-cli -- doctor                 # run the preflight self-test
cargo run -p aegis-cli -- profile create --name shopping --kind ephemeral --net tor --protection balanced
cargo run -p aegis-cli -- profile list
cargo run -p aegis-cli -- session start <profile-id>
cargo run -p aegis-cli -- diagnostics <session-id>
```

### Run the desktop UI

```sh
# The Tauri UI is a workspace member excluded from default-members (heavy webview deps).
cargo run -p aegis-manager-ui        # requires the platform webview + Tauri prerequisites
```

**Full VM setup on Linux (the real thing):** follow **[`docs/INSTALL-linux.md`](docs/INSTALL-linux.md)**.

---

## ⚙️ Configure your anonymity

Every profile is an explicit, honest tradeoff. Create one with `aegis profile create` (or the UI):

| Option | Values | What it controls |
|--------|--------|------------------|
| **`--kind`** (type) | `ephemeral` · `persistent` | Ephemeral is shredded at session end (unlinkable across sessions). Persistent lives in an encrypted, re-openable volume — convenient, but its sessions can be linked to each other. |
| **`--isolation`** | `vm` (default, full VM) · `host` (reduced host process) | VM split vs. reduced host-browser mode — see [Two ways to run](#-two-ways-to-run). The daemon-wide default posture is set with `aegis config enforcement`. |
| **`--net`** (network) | `tor` · `vpn` · `proxy` | **Tor** — strongest at hiding the public IP (default). **VPN** — better compatibility, operator sees your entry address (full-VM only). **Proxy** — SOCKS5 / HTTP CONNECT; accepted only after Aegis confirms DNS and required protocols actually traverse it. |
| **`--protection`** | `balanced` · `strict` | **Balanced** — virtual-backend WebGL, basic normalization, most sites work. **Strict** — restricted/disabled WebGL, no WebGPU, stronger Canvas limiting, letterboxing, standard fonts: more privacy, more breakage. |

Getting a reliable network/proxy configured (Tor, SOCKS5/HTTP, VPN) is covered end-to-end in
**[`docs/networks-and-proxies.md`](docs/networks-and-proxies.md)**.

```sh
# Toggle the containment posture (advanced). Relaxing isolation prints an honest warning.
aegis config enforcement                              # show current policy
aegis config enforcement --vm-isolation off --host-browser on   # switch to reduced host-browser mode
```

---

## 📁 Repository map

| Path | What lives here |
|------|-----------------|
| `apps/manager-ui/` | Tauri desktop UI (profiles view + diagnostics panel) |
| `apps/cli/` | The `aegis` command-line interface |
| `crates/aegis-core/` | Shared domain model, policy types, trait contracts (no I/O, no platform code) |
| `crates/secure-storage/` | Argon2id KDF + XChaCha20-Poly1305 AEAD sealing |
| `crates/profile-store/` | Ephemeral/persistent profiles, single-writer locking |
| `crates/vm-controller/` | libvirt/QEMU lifecycle, isolation-policy enforcement, disposable qcow2 overlays |
| `crates/gateway-controller/` | `nftables` compilation + tunnel + kill switch |
| `crates/network-audit/` | Six-check preflight + leak detection |
| `crates/browser-launcher/` | `BrowserBackend` implementations (Chromium MVP, Firefox later) |
| `crates/update-client/` | Signed update verification + rollback |
| `crates/aegis-ipc/` | UI/CLI ↔ daemon protocol and transport |
| `crates/aegis-daemon/` | Privileged orchestration daemon |
| `browser/` | Chromium managed policies, fingerprint-normalization patches, build |
| `images/` | Gateway + Browser VM build definitions (mkosi + debootstrap) |
| `firewall/` | `nftables` rulesets + leak-test harness |
| `packaging/` | Linux packaging (systemd units, sysusers/tmpfiles) + updater/signing |
| `tests/` | Integration, leak-harness, browser-api, network, destructive, red-team |
| `docs/` | Threat model, architecture, privacy model, release process, limitations, ADRs |

The whole workspace is a clean dependency DAG: every capability is a **trait in `aegis-core`**, every
implementation depends **only** on `aegis-core`, and the daemon wires the concrete parts together — so
everything is unit-testable with in-memory fakes.

---

## 🔒 Security model

Aegis is designed **fail-closed**: any error that could compromise network containment or host isolation
**severs connectivity** rather than degrading silently. This is not advisory prose — it is encoded in the
type system (`FailureClass::requires_killswitch`, the six-check preflight gate, and a session state
machine that forbids reaching `Browsing` without passing preflight).

- 📄 **[`docs/threat-model.md`](docs/threat-model.md)** — assets, adversary tiers, attack surface, protection→enforcement→test mapping.
- 📄 **[`docs/privacy-model.md`](docs/privacy-model.md)** — the unlinkability property and normalization-not-spoofing.
- 📄 **[`docs/limitations.md`](docs/limitations.md)** — the authoritative list of what Aegis does **not** protect against.
- 📄 **[`docs/security-acceptance-criteria.md`](docs/security-acceptance-criteria.md)** and **[`SECURITY.md`](SECURITY.md)** — acceptance criteria and the reporting policy / agent hard-rules.

> [!WARNING]
> Aegis provides **unlinkability to the host**, layered isolation, disposable sessions, controlled
> networking, and normalized fingerprints. It does **not** provide anonymity, undetectability, protection
> after you self-identify (log in, enter a real e-mail/phone), or defense against host/hypervisor
> compromise, zero-days, or a global passive adversary. Correct mental model: *a genuinely separate
> environment per session that is hard to tie to your real machine* — not *an invisible browser*.

---

## 🧭 Status / roadmap

Aegis is at **Stage 0 (foundations)**: the host-side control plane, policy engine, firewall rulesets,
image definitions, browser policy layer, and docs are in place and test-backed. The VM/gateway runtime
requires a Linux host with base images built and signed.

- [x] Threat model, data-flow, architecture, privacy model, ADRs
- [x] `aegis-core` contracts + fail-closed error taxonomy + session state machine
- [x] Fingerprint normalization policy (Balanced / Strict) — normalization, not spoofing
- [x] `nftables` default-deny gateway ruleset + kill switch + leak-test harness
- [x] Gateway + Browser VM image definitions (mkosi + debootstrap, reproducible)
- [x] Chromium managed policies + forbidden-flag guard
- [x] Signed updates: ed25519 manifests, SHA-256, downgrade block, rollback, SBOM
- [x] `aegis` CLI + Tauri UI over an authorized local socket
- [ ] End-to-end VM runtime bring-up on a Linux host (KVM/QEMU/libvirt)
- [ ] Firefox/Mullvad `BrowserBackend`
- [ ] Full leak/red-team suite against the live system
- [ ] External security audit before a stable release
- [ ] Windows target (Hyper-V / WSL2) — re-evaluated against `limitations.md`

---

## 🤝 Contributing

Contributions are welcome! Before opening a PR:

```sh
cargo fmt --all
cargo clippy --workspace --all-targets
cargo test  --workspace
```

Please keep every claim **honest** — no "undetectable," no "100% anonymous," no random spoofing, and
never weaken the Chromium sandbox or Site Isolation. Every new protection must be backed by an automated
test, and any Chromium modification must be described and covered by a regression test. See
[`SECURITY.md`](SECURITY.md) for the reporting policy and the full agent hard-rules.

---

## 📜 License

**GPL-3.0-or-later.** See [`LICENSE`](LICENSE).

<div align="center">

*Aegis is about unlinkability, not magic. Read [`docs/limitations.md`](docs/limitations.md) and stay honest.*

</div>
