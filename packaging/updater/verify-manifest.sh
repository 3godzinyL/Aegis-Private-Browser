#!/usr/bin/env bash
# Verify an Aegis manifest signature against the ed25519 PUBLIC key.
# Mirrors update-client::verify (signature step). Uses the same canonicalization
# contract as sign-manifest.sh (jq -cS with signature emptied).
set -euo pipefail

usage() { echo "usage: $0 <public-key.pem|--hex <hex>> <manifest.json>" >&2; exit 1; }
[[ $# -ge 2 ]] || usage

TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT

if [[ "$1" == "--hex" ]]; then
  # Rebuild a PEM public key from the 32-byte raw hex.
  HEX="$2"; MANIFEST="$3"
  printf '%s' "$HEX" | xxd -r -p > "$TMP/raw.pub"
  # ed25519 SubjectPublicKeyInfo DER prefix (12 bytes) + 32 raw bytes.
  printf '\x30\x2a\x30\x05\x06\x03\x2b\x65\x70\x03\x21\x00' > "$TMP/spki.der"
  cat "$TMP/raw.pub" >> "$TMP/spki.der"
  openssl pkey -pubin -inform DER -in "$TMP/spki.der" -out "$TMP/pub.pem"
  PUB="$TMP/pub.pem"
else
  PUB="$1"; MANIFEST="$2"
fi

SIG_HEX="$(jq -r '.signature' "$MANIFEST")"
[[ -n "$SIG_HEX" && "$SIG_HEX" != "null" ]] || { echo "no signature in manifest" >&2; exit 1; }
printf '%s' "$SIG_HEX" | xxd -r -p > "$TMP/sig.bin"
jq -cS '.signature = ""' "$MANIFEST" > "$TMP/canonical.json"

if openssl pkeyutl -verify -pubin -inkey "$PUB" -rawin \
      -in "$TMP/canonical.json" -sigfile "$TMP/sig.bin" >/dev/null 2>&1; then
  echo "OK: signature valid"
else
  echo "FAIL: signature invalid" >&2
  exit 1
fi
