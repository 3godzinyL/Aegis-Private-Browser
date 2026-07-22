# Linux packaging

Packages the **host-side** components of Aegis (the privileged `aegis-daemon`,
the `aegis` CLI, and the Tauri UI). The **VM base images** are shipped and
updated separately as signed qcow2 artifacts — see [`../../images`](../../images)
and [`../updater`](../updater).

## Privilege model (spec §10)

Aegis does **not** run as root. Installation creates a dedicated, unprivileged
`aegis` system user (see [`sysusers.d/aegis.conf`](sysusers.d/aegis.conf)) that is
a member of `libvirt`/`kvm` so it can drive `libvirtd` without host-wide
privileges. The daemon unit ([`aegis-daemon.service`](aegis-daemon.service))
applies a strong systemd sandbox: `ProtectSystem=strict`, a closed device policy
(only `/dev/kvm` and `/dev/net/tun`), a syscall allow-list, `NoNewPrivileges`,
`MemoryDenyWriteExecute`, and `LimitCORE=0` (no core dumps that could contain user
data).

## Control socket authorization (spec §4)

The UI/CLI talk to the daemon over a Unix socket at `/run/aegis/daemon.sock`,
created by [`aegis-daemon.socket`](aegis-daemon.socket) with mode `0660`
`root:aegis`. Only members of the `aegis` group can connect, and the daemon
**additionally** authorizes each connection by peer credentials (`SO_PEERCRED`).
Socket permissions are defense-in-depth, not the sole gate.

## Files

| File | Installed to | Purpose |
|------|--------------|---------|
| `aegis-daemon.service` | `/usr/lib/systemd/system/` | Hardened daemon unit |
| `aegis-daemon.socket` | `/usr/lib/systemd/system/` | Authorized control socket |
| `sysusers.d/aegis.conf` | `/usr/lib/sysusers.d/` | The `aegis` user/group |
| `tmpfiles.d/aegis.conf` | `/usr/lib/tmpfiles.d/` | Runtime (tmpfs) + state dirs |
| `config.example.toml` | `/etc/aegis/config.toml` | Default config (conffile) |

## Build

```sh
AEGIS_VERSION=0.1.0 ./build-deb.sh      # produces dist/aegis-private-browser_*.deb
```

The runtime directory `/run/aegis` **must be RAM-backed** — it holds disposable
qcow2 overlays and the in-RAM encryption keys of ephemeral sessions (spec §8).
On systemd systems `/run` is already tmpfs.

> A future AppImage/Flatpak target can wrap the UI, but the privileged daemon must
> remain a system service — an unprivileged sandbox cannot drive libvirt or load
> nftables rules.
