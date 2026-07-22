#!/usr/bin/env bash
# Aegis Browser VM — reproducible debootstrap build (spec §4, §6, §10; Etap 2).
#
# debootstrap alternative to mkosi.conf. Produces the same logical image: a
# minimal Debian bookworm root running Chromium in a single-app Wayland kiosk
# (cage), with ONE NIC to the gateway, read-only root + tmpfs for /home,/tmp,
# /var/downloads, seccomp/systemd sandboxing, a firstboot service that applies
# the managed Chromium policy and a per-session user-data-dir, and NO host
# integration (no spice-vdagent, no shared folders, no clipboard).
#
# Runs on a Linux host as root. Not for Windows — documented + correctness only.
#
# Usage: sudo ./build.sh [--version 1.0.0] [--mirror URL] [--out DIR]
set -euo pipefail

SUITE="bookworm"
ARCH="amd64"
VERSION="0.0.0-dev"
MIRROR="https://deb.debian.org/debian"
HERE="$(cd "$(dirname "$0")" && pwd)"
OUT_DIR="${HERE}/mkosi.output"
FILES="${HERE}/files"
: "${SOURCE_DATE_EPOCH:=1735689600}"
export SOURCE_DATE_EPOCH DEBIAN_FRONTEND=noninteractive LC_ALL=C

while [ $# -gt 0 ]; do
  case "$1" in
    --version) VERSION="$2"; shift 2 ;;
    --mirror)  MIRROR="$2";  shift 2 ;;
    --out)     OUT_DIR="$2"; shift 2 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

# Minimal browser package set. NO spice/xorg-desktop/vm-tools/samba/ssh.
PACKAGES="systemd,systemd-sysv,udev,dbus-broker,chromium,chromium-sandbox,cage,seatd,libgl1-mesa-dri,mesa-vulkan-drivers,fonts-dejavu-core,fonts-liberation2,fonts-noto-core,ca-certificates,iproute2,nftables,libseccomp2,qemu-guest-agent"

[ "$(id -u)" -eq 0 ] || { echo "must run as root" >&2; exit 1; }
for tool in debootstrap qemu-img mksquashfs sha256sum; do
  command -v "$tool" >/dev/null 2>&1 || { echo "missing tool: $tool" >&2; exit 1; }
done

mkdir -p "$OUT_DIR"
ROOTFS="$(mktemp -d)"
trap 'rm -rf "$ROOTFS"' EXIT

echo "[browser] debootstrap $SUITE ($ARCH) from $MIRROR"
debootstrap --arch="$ARCH" --variant=minbase --include="$PACKAGES" \
  "$SUITE" "$ROOTFS" "$MIRROR"

echo "[browser] overlaying files/"
cp -a "${FILES}/." "$ROOTFS/"

cat > "$ROOTFS/tmp/aegis-setup.sh" <<'CHROOT'
#!/bin/sh
set -eu
systemctl enable aegis-browser-firstboot.service
systemctl enable aegis-kiosk.service
systemctl enable systemd-networkd.service
systemctl enable qemu-guest-agent.service 2>/dev/null || true
systemctl set-default multi-user.target
for svc in spice-vdagent spice-vdagentd ssh sshd smbd nmbd NetworkManager open-vm-tools vboxadd systemd-networkd-wait-online; do
  systemctl mask "${svc}.service" 2>/dev/null || true
done
: > /etc/machine-id
rm -f /var/lib/dbus/machine-id 2>/dev/null || true
ln -sf /etc/machine-id /var/lib/dbus/machine-id
id aegis >/dev/null 2>&1 || useradd --system --create-home --home-dir /home/aegis --shell /usr/sbin/nologin aegis
passwd -l root 2>/dev/null || true
[ -e /usr/lib/chromium/chrome-sandbox ] && chmod 4755 /usr/lib/chromium/chrome-sandbox || true
apt-get clean || true
rm -rf /var/lib/apt/lists/* /usr/share/doc/* /usr/share/man/* /var/log/* 2>/dev/null || true
CHROOT
chmod +x "$ROOTFS/tmp/aegis-setup.sh"
chroot "$ROOTFS" /tmp/aegis-setup.sh
rm -f "$ROOTFS/tmp/aegis-setup.sh"

find "$ROOTFS" -newermt "@${SOURCE_DATE_EPOCH}" -not -type l \
  -exec touch --no-dereference --date="@${SOURCE_DATE_EPOCH}" {} + 2>/dev/null || true

RAW="${OUT_DIR}/aegis-browser_${VERSION}.squashfs"
QCOW="${OUT_DIR}/aegis-browser_${VERSION}.qcow2"
echo "[browser] mksquashfs -> $RAW"
mksquashfs "$ROOTFS" "$RAW" -noappend -all-root -mkfs-time "$SOURCE_DATE_EPOCH" \
  -comp zstd -no-exports
echo "[browser] qemu-img convert -> $QCOW"
qemu-img convert -f raw -O qcow2 -c "$RAW" "$QCOW"

( cd "$OUT_DIR" && sha256sum "aegis-browser_${VERSION}.qcow2" > "aegis-browser_${VERSION}.qcow2.sha256" )
echo "[browser] built $QCOW"
cat "${QCOW}.sha256"
