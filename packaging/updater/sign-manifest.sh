#!/usr/bin/env bash
# Sign an Aegis update/image manifest with the ed25519 release private key.
#
# CANONICALIZATION CONTRACT: the signature covers the manifest's canonical JSON
# with the `signature` field set to the empty string, serialized as compact JSON
# with lexicographically sorted keys (`jq -cS`). `update-client::signing_bytes`
# MUST produce byte-identical output (verified by the cross-tool test in
# tests/integration). Do not change one side without the other.
set -euo pipefail

usage() { echo "usage: $0 <private-key.pem> <manifest.json>" >&2; exit 1; }
[[ $# -eq 2 ]] || usage
PRIV="$1"; MANIFEST="$2"
command -v jq >/dev/null || { echo "jq is required" >&2; exit 1; }
command -v openssl >/dev/null || { echo "openssl is required" >&2; exit 1; }

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# 1. Canonical signing bytes: signature emptied, keys sorted, compact.
jq -cS '.signature = ""' "$MANIFEST" > "$TMP/canonical.json"

# 2. ed25519 signature over the raw bytes (ed25519 signs the message directly).
openssl pkeyutl -sign -inkey "$PRIV" -rawin -in "$TMP/canonical.json" -out "$TMP/sig.bin"

# 3. Hex-encode and splice back into the manifest.
SIG_HEX="$(xxd -p -c 64 "$TMP/sig.bin" | tr -d '\n')"
jq --arg sig "$SIG_HEX" '.signature = $sig' "$MANIFEST" > "$TMP/signed.json"
mv "$TMP/signed.json" "$MANIFEST"

echo "signed: $MANIFEST"
echo "sha256(manifest): $(sha256sum "$MANIFEST" | cut -d' ' -f1)"
