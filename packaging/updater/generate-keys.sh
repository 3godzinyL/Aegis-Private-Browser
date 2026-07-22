#!/usr/bin/env bash
# Generate the ed25519 release-signing keypair used to sign Aegis update and VM
# image manifests (spec Etap 5, §14). Keep the PRIVATE key offline; publish only
# the public key (hex) into the daemon config (`update_verify_key`).
set -euo pipefail

OUT_DIR="${1:-./release-keys}"
mkdir -p "$OUT_DIR"
chmod 700 "$OUT_DIR"

PRIV="$OUT_DIR/aegis-release-ed25519.pem"
PUB_HEX="$OUT_DIR/aegis-release-ed25519.pub.hex"

if [[ -e "$PRIV" ]]; then
  echo "refusing to overwrite existing private key: $PRIV" >&2
  exit 1
fi

# Private key (PKCS#8). openssl >= 1.1.1 supports ed25519.
openssl genpkey -algorithm ed25519 -out "$PRIV"
chmod 600 "$PRIV"

# Export the 32-byte raw public key as hex for the daemon config.
# The DER SubjectPublicKeyInfo ends with the 32 raw key bytes.
openssl pkey -in "$PRIV" -pubout -outform DER \
  | tail -c 32 \
  | xxd -p -c 32 \
  | tr -d '\n' > "$PUB_HEX"
echo >> "$PUB_HEX"

echo "Private key : $PRIV   (KEEP OFFLINE)"
echo "Public (hex): $(cat "$PUB_HEX")"
echo
echo "Put the hex value into /etc/aegis/config.toml as: update_verify_key = \"<hex>\""
