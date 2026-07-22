#!/usr/bin/env bash
# Aegis Gateway VM — reproducible debootstrap build (spec §4, §5, §10; Etap 1).
#
# This is the debootstrap alternative to mkosi.conf for hosts without mkosi. It
# produces the SAME logical image: a minimal, headless Debian bookworm root with
# nftables + Tor, a default-deny firewall, DNS/TCP transparent redirect to Tor,
# a health-check that publishes tunnel/kill-switch state, IPv6 disabled, and no
# host integration. The result is converted to qcow2, hashed (SHA-256) and (in
# CI) signed. update-client verifies the hash+signature; vm-controller mounts the
# qcow2 read-only as a backing image with disposable overlays (see images/README.md).
#
# Runs on a Linux host as root. NOT meant to run on Windows — it is checked for
# correctness and documented here, and executed by the Linux release pipeline.
#
# Usage:
#   sudo ./build.sh [--version 1.0.0] [--mirror URL] [--out DIR]
#
# Reproducibility levers:
#   * SOURCE_DATE_EPOCH pins all mtimes.
#   * --mirror should point at a snapshot.debian.org timestamped archive in CI.
#   * The package set is fixed below; no interactive prompts (DEBIAN_FRONTEND).
set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
SUITE="bookworm"
ARCH="amd64"
VERSION="0.0.0-dev"
MIRROR="https://deb.debian.org/debian"
OUT_DIR="$(cd "$(dirname "$0")" && pwd)/mkosi.output"
HERE="$(cd "$(dirname "$0")" && pwd)"
FILES="${HERE}/files"
: "${SOURCE_DATE_EPOCH:=1735689600}"   # 2025-01-01T00:00:00Z, deterministic
export SOURCE_DATE_EPOCH
export DEBIAN_FRONTEND=noninteractive
export LC_ALL=C

while [ $# -gt 0 ]; do
  case "$1" in
    --version) VERSION="$2"; shift 2 ;;
    --mirror)  MIRROR="$2";  shift 2 ;;
    --out)     OUT_DIR="$2"; shift 2 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

# Minimal gateway package set. Explicitly excludes desktop / spice / xorg.
PACKAGES="systemd,systemd-sysv,udev,dbus-broker,nftables,tor,iproute2,iptables,ca-certificates,libcap2-bin,qemu-guest-agent,less"

if [ "$(id -u)" -ne 0 ]; then
  echo "must run as root (debootstrap + loop mounts)" >&2
  exit 1
fi
for tool in debootstrap qemu-img mksquashfs sha256sum; do
  command -v "$tool" >/dev/null 2>&1 || { echo "missing tool: $tool" >&2; exit 1; }
done

mkdir -p "$OUT_DIR"
ROOTFS="$(mktemp -d)"
trap 'rm -rf "$ROOTFS"' EXIT

echo "[gateway] debootstrap $SUITE ($ARCH) from $MIRROR"
debootstrap \
  --arch="$ARCH" \
  --variant=minbase \
  --include="$PACKAGES" \
  "$SUITE" "$ROOTFS" "$MIRROR"

# ---------------------------------------------------------------------------
# Overlay the curated /etc tree (units, torrc, nftables, sysctl, networkd).
# ---------------------------------------------------------------------------
echo "[gateway] overlaying files/"
cp -a "${FILES}/." "$ROOTFS/"

# ---------------------------------------------------------------------------
# In-chroot hardening + unit enablement (mirrors mkosi.postinst).
# ---------------------------------------------------------------------------
cat > "$ROOTFS/tmp/aegis-setup.sh" <<'CHROOT'
#!/bin/sh
set -eu
systemctl enable aegis-gateway-firewall.service
systemctl enable aegis-tor.service
systemctl enable aegis-healthcheck.service
systemctl enable systemd-networkd.service
systemctl enable qemu-guest-agent.service 2>/dev/null || true
systemctl disable tor.service 2>/dev/null || true
systemctl mask ssh.service sshd.service systemd-networkd-wait-online.service 2>/dev/null || true

# machine-id randomized per instance, not host-derived.
: > /etc/machine-id
rm -f /var/lib/dbus/machine-id 2>/dev/null || true
ln -sf /etc/machine-id /var/lib/dbus/machine-id

passwd -l root 2>/dev/null || true
# strip apt caches / docs for size + determinism
apt-get clean || true
rm -rf /var/lib/apt/lists/* /usr/share/doc/* /usr/share/man/* /var/log/* 2>/dev/null || true
CHROOT
chmod +x "$ROOTFS/tmp/aegis-setup.sh"
chroot "$ROOTFS" /tmp/aegis-setup.sh
rm -f "$ROOTFS/tmp/aegis-setup.sh"

# Normalize mtimes for reproducibility.
find "$ROOTFS" -newermt "@${SOURCE_DATE_EPOCH}" -not -type l \
  -exec touch --no-dereference --date="@${SOURCE_DATE_EPOCH}" {} + 2>/dev/null || true

# ---------------------------------------------------------------------------
# Pack: squashfs read-only root -> raw -> qcow2. vm-controller uses the qcow2 as
# a read-only backing image; the guest kernel mounts / read-only (see fstab in
# files/etc/fstab). Here we ship a squashfs the loader mounts ro.
# ---------------------------------------------------------------------------
RAW="${OUT_DIR}/aegis-gateway_${VERSION}.squashfs"
QCOW="${OUT_DIR}/aegis-gateway_${VERSION}.qcow2"
echo "[gateway] mksquashfs -> $RAW"
mksquashfs "$ROOTFS" "$RAW" -noappend -all-root -mkfs-time "$SOURCE_DATE_EPOCH" \
  -comp zstd -no-exports

echo "[gateway] qemu-img convert -> $QCOW"
qemu-img convert -f raw -O qcow2 -c "$RAW" "$QCOW"

# ---------------------------------------------------------------------------
# Hash. Signing is done by the release pipeline with the offline key (see
# images/README.md); here we emit the SHA-256 that goes into the signed manifest.
# ---------------------------------------------------------------------------
( cd "$OUT_DIR" && sha256sum "aegis-gateway_${VERSION}.qcow2" > "aegis-gateway_${VERSION}.qcow2.sha256" )
echo "[gateway] built $QCOW"
cat "${QCOW}.sha256"
