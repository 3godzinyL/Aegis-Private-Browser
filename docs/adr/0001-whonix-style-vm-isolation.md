# ADR-0001: Whonix-style VM isolation (Gateway VM + Browser VM)

- Status: Accepted
- Date: 2026-07-22
- Deciders: Aegis Project
- Spec references: §2, §3, §4, §5, §16, §17

## Context

Aegis must make a browsing environment **unlinkable to the host**: a website may
observe that a specific browser environment exists, but must not be able to tie it
to the user's real computer, real IP, physical hardware, or host devices (spec §1,
§17). Achieving this requires cutting several layers of linkage *at once* — network,
hardware/OS, and browser data — because a leak in any single layer re-links the
environment to the host (spec §2).

Two structural risks dominate:

1. **Network linkage.** If the browser process can reach the host's real network
   interface, or learn the host's real public IP, or take an alternate route, the
   real IP leaks and the model collapses.
2. **Host-hardware/OS linkage.** If the page can see the host's fonts, GPU,
   cameras, sensors, clipboard, or filesystem, it can build a stable, host-tied
   fingerprint.

A purely in-process approach (a modified browser on the host, or a browser
extension) cannot enforce these boundaries: the browser still shares the host
kernel, network stack, devices, and filesystem, and a renderer compromise or a
misconfiguration can reach them.

## Decision

Adopt a **Whonix-style two-VM split** as the core isolation primitive (spec §3):

- A **Browser VM** — hardened, minimal Linux with a read-only root — runs the
  browser and the profile. It has **exactly one** virtual NIC, attached to an
  isolated network whose only other member is the Gateway.
- A **Gateway VM** — the *only* component with an upstream path — runs a default-
  deny firewall, the tunnel (Tor/VPN/proxy), controlled DNS, IPv6 blocking, and a
  kill switch.

This yields the three structural guarantees (spec §3), enforced by construction:

1. The Browser VM does not know the host's physical NIC.
2. The Browser VM does not know the host's real public IP.
3. The Browser VM has no alternative network route.

Host↔guest channels (clipboard, drag-and-drop, shared folders, disk automount,
USB/PCI passthrough, camera/mic, SSH agent, desktop-integration guest tools) are
**all disabled** and expressed as a single machine-checkable `IsolationPolicy` with
twelve validated booleans (`crates/aegis-core/src/vm.rs`). A VM cannot be
provisioned unless its policy is fully hardened
(`VmProvisionRequest::validate`). Disposable sessions run a throwaway qcow2 overlay
over a read-only base snapshot; the overlay is shredded on close (spec §4, §8).

This is the same design principle as Whonix (Workstation uses a dedicated Gateway
and does not know the real external IP) and Qubes (isolate components into separate
domains), applied to per-session disposable environments.

## Consequences

**Positive**

- Network containment is structural, not advisory: there is physically no route
  from the Browser VM to the host's real interface, and the firewall is
  default-deny with a kill switch (fail-closed, spec §5, §16).
- Host hardware/OS linkage is cut at the VM boundary: the guest sees a virtual
  environment with no host devices.
- The isolation guarantees are encoded as validated types, so they are testable and
  cannot silently regress (`vm::tests`).
- Each session is a genuinely separate environment, not "a tab with a swapped
  User-Agent" (spec §17).

**Negative / costs**

- Requires a hypervisor (first-class: Linux + KVM/QEMU/libvirt), which raises
  system requirements and rules out running on the host directly.
- Higher resource use (two VMs per session) and slower session startup than an
  in-process solution.
- The hypervisor and firmware become part of the trust base; a hypervisor/firmware
  compromise is explicitly **out of scope** (spec §2) and cannot be defended by this
  design.
- Windows is only a later target (via Hyper-V/WSL2), not a first-release platform
  (spec §4).

## Alternatives considered

- **Browser extension / in-page approach.** Rejected by spec §16 ("do not replace
  full isolation with a browser extension"): an extension shares the host's network,
  devices, and filesystem and cannot enforce network containment or host isolation.
- **Hardened browser on the bare host (no VM).** Reduces fingerprint entropy but
  still exposes the host network stack, real IP path, and host devices; a renderer
  compromise reaches the host. Insufficient for unlinkability.
- **Electron-style container for pages.** Rejected by spec §16 ("do not use Electron
  as the primary page container"); it is not a security boundary for untrusted web
  content.
- **Single VM (browser + networking together).** Simpler, but loses the Gateway/
  Workstation separation: the browser VM would know the real upstream and could take
  an alternate route. The two-VM split is what guarantees "no alternative route."

## Related

- [ADR-0005](0005-fail-closed-networking.md) — the fail-closed networking that the
  Gateway enforces.
- [ADR-0004](0004-privileged-daemon-and-local-socket.md) — the privileged daemon
  that provisions and controls the VMs.
- [`../architecture.md`](../architecture.md), [`../threat-model.md`](../threat-model.md).
