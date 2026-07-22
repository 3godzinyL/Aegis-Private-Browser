# Installing the full VM version of Aegis on Linux

This guide walks you through running the **real thing**: the full Whonix-style VM split
(**Gateway VM + Browser VM**) on Linux with KVM/QEMU/libvirt. Every step is a real, ordered
shell command with a short explanation, so you can copy-paste top to bottom.

> [!NOTE]
> This sets up the **default, fully-secure posture** (`Enforcement::secure`: VM isolation + Gateway VM).
> If you only want the reduced host-browser mode (no VM), you do not need most of this — see the
> [README](../README.md#-two-ways-to-run) and [`networks-and-proxies.md`](networks-and-proxies.md).
> Aegis provides **unlinkability to the host**, not "100% anonymity" — read
> [`limitations.md`](limitations.md) first.

---

## 0. Which Linux distribution?

Aegis's VM base images are **Debian-based**, so a Debian-family host is the smoothest path.

| Distro | Recommendation | Download |
|--------|----------------|----------|
| **Debian 12 (bookworm)** | ✅ **Primary** — the images are built on Debian bookworm | <https://www.debian.org/download> |
| **Ubuntu 24.04 LTS** | ✅ **Primary** — Debian-based, well-tested KVM/libvirt stack | <https://ubuntu.com/download> |
| **Kali Linux** | ✅ Works too (also Debian-based) — use it if you prefer it | <https://www.kali.org/get-kali/> |

Any of the three works. The commands below use `apt`, so they apply to all of them.

> [!IMPORTANT]
> You need a **64-bit x86 host with hardware virtualization** and enough RAM/disk to run two small VMs
> at once (plan for ~4 GB free RAM and ~15 GB free disk for images + overlays).

---

## 1. Enable and verify hardware virtualization (VT-x / AMD-V)

First make sure virtualization is enabled in your firmware (BIOS/UEFI: *Intel VT-x* / *AMD-V* /
*SVM Mode* — enable it, then reboot). Then verify from Linux:

```sh
# Count virtualization-capable CPU flags (vmx = Intel, svm = AMD). Non-zero = good.
egrep -c '(vmx|svm)' /proc/cpuinfo

# Confirm the KVM device exists (created once the kvm modules are loaded).
ls -l /dev/kvm

# Optional but recommended: install the checker and read its verdict.
sudo apt-get update
sudo apt-get install -y cpu-checker
kvm-ok        # should print: "KVM acceleration can be used"
```

### If your Linux host is itself a VM (nested virtualization)

Aegis runs VMs, so if you install it inside a VM you need **nested virtualization** enabled on the
*outer* hypervisor.

```sh
# Check whether nested KVM is on (Y = enabled). Use kvm_amd on AMD hosts.
cat /sys/module/kvm_intel/parameters/nested   2>/dev/null   # Intel
cat /sys/module/kvm_amd/parameters/nested     2>/dev/null   # AMD

# Enable it persistently on the OUTER Linux+KVM host, then reboot the guest:
echo 'options kvm_intel nested=1' | sudo tee /etc/modprobe.d/kvm-nested.conf   # Intel
# echo 'options kvm_amd nested=1' | sudo tee /etc/modprobe.d/kvm-nested.conf   # AMD
sudo modprobe -r kvm_intel && sudo modprobe kvm_intel                          # or kvm_amd
```

For **VirtualBox** as the outer hypervisor, see the [note at the end](#virtualbox-nested-virtualization-note).

---

## 2. Install the host packages

```sh
sudo apt-get update

# Virtualization + networking stack (KVM/QEMU, libvirt, virtual networking, firewall, Tor).
sudo apt-get install -y \
    qemu-kvm libvirt-daemon-system libvirt-clients bridge-utils \
    virtinst nftables tor \
    build-essential curl git

# Rust toolchain via rustup (the workspace pins stable / Rust 1.82+).
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
. "$HOME/.cargo/env"
rustup show        # confirm the stable toolchain is active
```

Start and enable the virtualization + Tor services:

```sh
sudo systemctl enable --now libvirtd
sudo systemctl enable --now tor
sudo systemctl status libvirtd --no-pager
```

---

## 3. Add your user to the libvirt / kvm groups

So you can drive libvirt without `sudo` on every command:

```sh
sudo usermod -aG libvirt,kvm "$USER"

# Group membership only takes effect in NEW sessions. Either log out/in, or:
newgrp libvirt          # start a subshell with the new group
# Verify:
id | tr ',' '\n' | grep -E 'libvirt|kvm'
```

Confirm libvirt works for your user and the default virtual network is active:

```sh
virsh -c qemu:///system list --all
virsh -c qemu:///system net-list --all
# If the default NAT network is inactive, bring it up:
sudo virsh net-start default 2>/dev/null || true
sudo virsh net-autostart default 2>/dev/null || true
```

---

## 4. Clone and build Aegis

```sh
git clone <your-repo-url> aegis-private-browser
cd aegis-private-browser

# Build the host-side control plane in release mode (daemon + CLI + crates).
cargo build --release

# Sanity-check: run the workspace tests.
cargo test --workspace
```

The release binaries land in `target/release/` (notably `aegis-daemon` and the `aegis` CLI).

---

## 5. Install the systemd units and the `aegis` system user

Aegis does **not** run as root. The packaging under [`packaging/linux/`](../packaging/linux/) creates a
dedicated, unprivileged `aegis` system user (member of `libvirt`/`kvm`), a hardened daemon unit, and an
authorized control socket. Install those files:

```sh
cd packaging/linux

# 5a. The unprivileged 'aegis' system user + group (sysusers).
sudo cp sysusers.d/aegis.conf /usr/lib/sysusers.d/aegis.conf
sudo systemd-sysusers                     # creates the 'aegis' user/group now

# 5b. Runtime (tmpfs) + state directories (tmpfiles).
sudo cp tmpfiles.d/aegis.conf /usr/lib/tmpfiles.d/aegis.conf
sudo systemd-tmpfiles --create            # creates /run/aegis, /var/lib/aegis, etc.

# 5c. The hardened daemon service + authorized control socket.
sudo cp aegis-daemon.service /usr/lib/systemd/system/aegis-daemon.service
sudo cp aegis-daemon.socket  /usr/lib/systemd/system/aegis-daemon.socket

# 5d. Install the daemon binary where the unit expects it.
sudo install -Dm755 ../../target/release/aegis-daemon /usr/libexec/aegis/aegis-daemon
# Install the CLI onto your PATH.
sudo install -Dm755 ../../target/release/aegis        /usr/local/bin/aegis
```

Add **your** user to the `aegis` group so the UI/CLI may connect to the control socket (the daemon also
verifies each connection by peer credentials — this is defense in depth, not the only gate):

```sh
sudo usermod -aG aegis "$USER"      # re-login afterwards for this to take effect
```

> The `/run/aegis` runtime directory **must** be RAM-backed — it holds disposable qcow2 overlays and the
> in-RAM encryption keys of ephemeral sessions. On systemd systems `/run` is already `tmpfs`.

---

## 6. Build and sign the VM base images

The Gateway and Browser base images are built from the definitions in [`images/`](../images/) and shipped
as **signed** qcow2 artifacts. Build them on this Linux host.

### 6a. Install the build tools

```sh
sudo apt-get install -y debootstrap qemu-utils squashfs-tools
# (Optional, preferred/declarative build path:)
sudo apt-get install -y mkosi
```

### 6b. Build both images

Using the debootstrap build scripts (run as root). For **byte-reproducible** builds, point `--mirror` at
a timestamped `snapshot.debian.org` archive:

```sh
cd ../../images     # repo-root/images

sudo ./gateway/build.sh --version 1.0.0 \
     --mirror https://snapshot.debian.org/archive/debian/20260701T000000Z/
sudo ./browser/build.sh --version 1.0.0 \
     --mirror https://snapshot.debian.org/archive/debian/20260701T000000Z/

# → images/<role>/mkosi.output/aegis-<role>_1.0.0.qcow2  (+ .qcow2.sha256)
```

> The preferred alternative is `mkosi` (declarative, reproducible):
> `cd images/gateway && mkosi --image-version=1.0.0 --force build` (and the same for `browser`).
> Both paths produce the same logical image.

### 6c. Generate a release key and sign the image manifest

The `update-client` verifies an **ed25519-signed** manifest before any image is used. Generate a keypair
(keep the **private** key offline), then sign a manifest describing the images:

```sh
cd ../packaging/updater      # repo-root/packaging/updater

# Create the ed25519 keypair; it prints the PUBLIC key hex for your config.
./generate-keys.sh ./release-keys
# → note the printed public-key hex; you'll paste it as update_verify_key in step 7.

# After you compose a manifest.json (see packaging/updater/README.md for the shape),
# sign it in place with the OFFLINE private key:
./sign-manifest.sh ./release-keys/aegis-release-ed25519.pem ./manifest.json

# Verify it the same way the daemon will (sanity check):
./verify-manifest.sh --hex <PUBLIC_KEY_HEX> ./manifest.json
```

Finally, place the verified images where the daemon reads them:

```sh
sudo install -Dm644 ../../images/gateway/mkosi.output/aegis-gateway_1.0.0.qcow2 \
     /var/lib/aegis/images/gateway-1.0.0.qcow2
sudo install -Dm644 ../../images/browser/mkosi.output/aegis-browser_1.0.0.qcow2 \
     /var/lib/aegis/images/browser-1.0.0.qcow2
sudo chown -R aegis:aegis /var/lib/aegis/images
```

---

## 7. Create the configuration

Install the example config and edit it to point at your signed images and your public verify key:

```sh
sudo install -Dm644 ../packaging/linux/config.example.toml /etc/aegis/config.toml
sudo nano /etc/aegis/config.toml
```

Minimum edits (see [`config.example.toml`](../packaging/linux/config.example.toml) for the full file):

```toml
default_protection = "balanced"        # balanced | strict
update_verify_key  = "<PUBLIC_KEY_HEX>"   # from step 6c — publish only the PUBLIC key

[default_network]
kind = "tor"                            # tor | vpn | proxy (Tor is the recommended default)

[paths]
runtime_dir = "/run/aegis"              # MUST be tmpfs / RAM-backed

[images.gateway]
path      = "/var/lib/aegis/images/gateway-1.0.0.qcow2"
signature = "/var/lib/aegis/images/gateway-1.0.0.qcow2.sig"
version   = "1.0.0"
sha256    = "<sha256 from aegis-gateway_1.0.0.qcow2.sha256>"

[images.browser]
path      = "/var/lib/aegis/images/browser-1.0.0.qcow2"
signature = "/var/lib/aegis/images/browser-1.0.0.qcow2.sig"
version   = "1.0.0"
sha256    = "<sha256 from aegis-browser_1.0.0.qcow2.sha256>"
```

---

## 8. Start the daemon

```sh
sudo systemctl daemon-reload

# Enable the authorized control socket + the hardened daemon service.
sudo systemctl enable --now aegis-daemon.socket
sudo systemctl enable --now aegis-daemon.service

# Confirm they're healthy.
systemctl status aegis-daemon.service --no-pager
journalctl -u aegis-daemon -e --no-pager
```

Verify the CLI can reach the daemon (remember to have re-logged in so your `aegis` group membership is
active):

```sh
aegis status        # shows platform, isolation level, enforcement, host-browser availability
aegis doctor        # asks the daemon to run its preflight self-test and print pass/fail
```

---

## 9. Launch your first private session

```sh
# 1) Create an ephemeral, Tor-routed, Balanced profile (the safest default).
aegis profile create --name test --kind ephemeral --net tor --protection balanced
aegis profile list                       # note the new profile id

# 2) Start a session for it (provisions the VMs, brings up the gateway,
#    runs the six-check preflight, then launches the browser only if all pass).
aegis session start <profile-id>
aegis session list                       # shows the protection badge

# 3) Watch the diagnostics (public IP, DNS/IPv6/WebRTC, devices, kill switch).
aegis diagnostics <session-id>

# 4) Tear it down — the disposable overlay is shredded, nothing is left behind.
aegis session stop <session-id>
```

If the six preflight checks do not all pass, the browser **does not** get Internet — that is fail-closed
by design, not a bug. See [`networks-and-proxies.md`](networks-and-proxies.md) to get a reliable tunnel.

---

## VirtualBox nested-virtualization note

If your Linux host runs **inside VirtualBox**, KVM inside it needs nested VT-x/AMD-V exposed by
VirtualBox:

- **GUI:** *Settings → System → Processor → ✅ "Enable Nested VT-x/AMD-V"* (VM must be powered off).
- **CLI (host running VirtualBox):**
  ```sh
  VBoxManage modifyvm "<YourVMName>" --nested-hw-virt on
  ```
- Nested VT-x/AMD-V requires a **VirtualBox 6.1+** and a host CPU that supports it. Performance is lower
  than bare metal; for the real deal, run Aegis on a physical Linux host or a Linux+KVM hypervisor.
- After enabling it, re-run the checks in [section 1](#if-your-linux-host-is-itself-a-vm-nested-virtualization):
  `egrep -c '(vmx|svm)' /proc/cpuinfo` should now be non-zero and `kvm-ok` should pass.

---

## Troubleshooting

| Symptom | Likely cause & fix |
|---------|--------------------|
| `kvm-ok` says acceleration cannot be used | VT-x/AMD-V disabled in firmware, or (in a VM) nested virtualization off. Enable it (§1), reboot, re-check. |
| `/dev/kvm` missing | KVM modules not loaded: `sudo modprobe kvm_intel` (or `kvm_amd`); ensure your CPU supports it. |
| `permission denied` on `virsh` / `/dev/kvm` | You're not in `libvirt`/`kvm` yet, or haven't re-logged in. `sudo usermod -aG libvirt,kvm "$USER"`, then log out/in (or `newgrp libvirt`). |
| `cannot reach the daemon socket at /run/aegis/daemon.sock` | Daemon/socket not running, or you're not in the `aegis` group. `sudo systemctl status aegis-daemon.socket aegis-daemon.service`; ensure you re-logged in after `usermod -aG aegis`. Override with `--socket` / `AEGIS_SOCKET` if you moved it. |
| `aegis-daemon` fails to start | Check `journalctl -u aegis-daemon -e`. Common causes: `/etc/aegis/config.toml` missing/invalid, image paths wrong, or `/var/lib/aegis` not owned by `aegis` (`sudo chown -R aegis:aegis /var/lib/aegis`). |
| Image rejected / update refused | The manifest signature, SHA-256, or version failed verification (fail-closed). Confirm `update_verify_key` matches the key you signed with (§6c) and the `sha256` in config matches the `.qcow2.sha256` file. |
| Preflight fails on `tunnel_ready` / `public_ip_observed` | The tunnel isn't up. For Tor, ensure `systemctl status tor` is active; see [`networks-and-proxies.md`](networks-and-proxies.md). |
| The default libvirt network is missing | `sudo virsh net-start default && sudo virsh net-autostart default`. |
| Nested VMs are extremely slow | Nested virtualization is inherently slower. Prefer a bare-metal Linux host or a Linux+KVM hypervisor over VirtualBox. |

---

### Next steps

- Get a rock-solid network/proxy: **[`networks-and-proxies.md`](networks-and-proxies.md)**
- Understand exactly what you're protected against: **[`threat-model.md`](threat-model.md)** and **[`limitations.md`](limitations.md)**
- How the pieces fit together: **[`architecture.md`](architecture.md)**
