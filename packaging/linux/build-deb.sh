#!/usr/bin/env bash
# Build a Debian package for the Aegis host-side components (daemon + CLI + UI).
# The VM base images are shipped and updated separately as signed qcow2 artifacts
# (see packaging/updater and images/). This script only packages the host binaries
# plus the systemd/sysusers/tmpfiles units and default config.
set -euo pipefail

VERSION="${AEGIS_VERSION:-0.1.0}"
ARCH="${ARCH:-amd64}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

echo ">> building release binaries"
( cd "$ROOT" && cargo build --release -p aegis-daemon -p aegis-cli )

# --- filesystem layout ---
install -Dm0755 "$ROOT/target/release/aegis-daemon" "$STAGE/usr/libexec/aegis/aegis-daemon"
install -Dm0755 "$ROOT/target/release/aegis"        "$STAGE/usr/bin/aegis"

install -Dm0644 "$ROOT/packaging/linux/aegis-daemon.service" "$STAGE/usr/lib/systemd/system/aegis-daemon.service"
install -Dm0644 "$ROOT/packaging/linux/aegis-daemon.socket"  "$STAGE/usr/lib/systemd/system/aegis-daemon.socket"
install -Dm0644 "$ROOT/packaging/linux/sysusers.d/aegis.conf" "$STAGE/usr/lib/sysusers.d/aegis.conf"
install -Dm0644 "$ROOT/packaging/linux/tmpfiles.d/aegis.conf" "$STAGE/usr/lib/tmpfiles.d/aegis.conf"
install -Dm0644 "$ROOT/packaging/linux/config.example.toml"   "$STAGE/etc/aegis/config.toml"

# docs
for d in architecture threat-model privacy-model limitations release-process; do
  [[ -f "$ROOT/docs/$d.md" ]] && install -Dm0644 "$ROOT/docs/$d.md" "$STAGE/usr/share/doc/aegis/$d.md" || true
done

# --- control metadata ---
mkdir -p "$STAGE/DEBIAN"
cat > "$STAGE/DEBIAN/control" <<EOF
Package: aegis-private-browser
Version: $VERSION
Section: net
Priority: optional
Architecture: $ARCH
Depends: libvirt-daemon-system, qemu-system-x86, nftables, tor
Recommends: qemu-utils
Maintainer: The Aegis Project <security@example.invalid>
Description: Aegis Private Browser — isolated, fail-closed browsing environments
 Disposable and persistent encrypted browser environments with a Whonix-style
 network split. Each session runs in its own VM and reaches the Internet only
 through a separate, fail-closed gateway (Tor/VPN/proxy).
EOF

cat > "$STAGE/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e
systemd-sysusers /usr/lib/sysusers.d/aegis.conf || true
systemd-tmpfiles --create /usr/lib/tmpfiles.d/aegis.conf || true
systemctl daemon-reload || true
systemctl enable --now aegis-daemon.socket || true
echo "Add your desktop user to the 'aegis' group to use the app:  sudo usermod -aG aegis <user>"
EOF
chmod 0755 "$STAGE/DEBIAN/postinst"

cat > "$STAGE/DEBIAN/conffiles" <<EOF
/etc/aegis/config.toml
EOF

OUT="$ROOT/dist/aegis-private-browser_${VERSION}_${ARCH}.deb"
mkdir -p "$ROOT/dist"
dpkg-deb --build --root-owner-group "$STAGE" "$OUT"
echo ">> built $OUT"
