# ADR-0004: A small privileged daemon and an authorized local socket

- Status: Accepted
- Date: 2026-07-22
- Deciders: Aegis Project
- Spec references: §4, §5, §10, §11, §16

## Context

Aegis needs privileged operations: defining libvirt/QEMU domains, applying nftables
rules on the Gateway, mounting/shredding encrypted profile volumes, and holding
profile encryption keys. It also needs a user interface (a profiles view and a
diagnostics panel, spec §11) and a CLI.

The UI is, by nature, a large attack surface: it renders rich content and processes
user input, and (for Tauri) embeds a webview. Running such a process with the
privileges required to reconfigure the firewall or read profile keys would mean a UI
compromise is a full system compromise. The spec is explicit (spec §4):

> proces uprzywilejowany: mały, oddzielny daemon systemowy;
> komunikacja UI–daemon: lokalne Unix socket z autoryzacją.

and (spec §10): "proces zarządzający VM nie działa jako root; daemon uprzywilejowany
posiada minimalny interfejs."

## Decision

Split the system into two processes:

- **Unprivileged Manager (UI + CLI)** — `apps/manager-ui`, `apps/cli`. It performs
  **no** privileged operation itself; it renders state and issues requests.
- **Small privileged daemon** — `aegis-daemon`. It is the **only** component that
  touches libvirt, nftables, and profile keys. Its interface is deliberately minimal
  (a small, validated request set), and its VM-management logic does not run
  root-heavy (only what libvirt requires).

They communicate over a **local socket with authorization** (`aegis-ipc`):

- **Unix (first-class platform):** a Unix-domain socket at `paths.daemon_socket`
  (default `/run/aegis/daemon.sock`), authorized by **peer credentials**
  (`SO_PEERCRED` uid/gid) — only the owning local user may drive the daemon.
  Filesystem permissions on the socket are the first gate; peer-cred is the second.
- **Windows dev fallback:** a loopback endpoint plus a per-run token (Windows is a
  later target via Hyper-V/WSL2, not a first-release platform, spec §4); this path is
  for host-side development only and never carries the privileged VM runtime.

The daemon **validates every request** before acting (e.g.
`VmProvisionRequest::validate` rejects any un-hardened `IsolationPolicy`;
`FirewallPolicy::validate` rejects a non-`Drop` base policy), so a malformed or
hostile request fails closed. The Gateway additionally **rejects host-initiated
traffic outside the management channel** (`FirewallPolicy::reject_host_initiated`,
spec §5), so this socket is the single sanctioned host↔system control path. Audit
records written by the daemon must never contain secrets or host identifiers (spec
§11, `AuditSink`).

## Consequences

**Positive**

- Privilege is confined to a small, auditable daemon; a UI compromise cannot, by
  itself, reconfigure the firewall, disable isolation, or read a persistent profile
  key.
- The minimal, validated interface is easy to reason about and to fuzz (spec §13
  Etap 6 includes config-parser fuzzing).
- Peer-credential authorization ties control to the local owning user without a
  password prompt on every action, while filesystem permissions provide defense in
  depth.
- Aligns with the fail-closed principle: invalid privileged requests are rejected at
  the boundary.

**Negative / costs**

- Two processes and an IPC protocol add complexity versus a single privileged app.
- The socket and its permissions become a security-relevant surface: a local
  attacker running as the same user is inside the trust boundary (this is inherent to
  peer-cred and is documented as such).
- The Windows dev fallback (loopback + token) is weaker than Unix peer-cred and is
  therefore restricted to development, not production.

## Alternatives considered

- **Single privileged UI process.** Rejected by spec §4/§10 and on security grounds:
  it makes a large-attack-surface UI privileged, so any UI/webview bug is a full
  compromise.
- **setuid helper binaries invoked per action.** Fragile and hard to audit; env/argv
  handling around setuid is error-prone. A small long-lived daemon with a validated
  request set is cleaner and easier to test.
- **A network (TCP) control API.** Rejected: it would expose a privileged interface on
  a network surface (contrary to the "no networked management/debug endpoint" posture,
  spec §10) and complicate authorization. A local socket keeps control host-local.
- **D-Bus / system bus.** Reasonable on Linux, but adds a dependency and a broader
  surface than a single authorized Unix socket needs for a small request set; can be
  revisited without changing this decision's boundary.

## Related

- [ADR-0001](0001-whonix-style-vm-isolation.md) — what the daemon provisions and
  controls.
- [ADR-0005](0005-fail-closed-networking.md) — the firewall the daemon applies and
  the host-initiated-traffic rejection.
- [`../architecture.md`](../architecture.md) §4.
