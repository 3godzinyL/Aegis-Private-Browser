# Aegis update & image signing

This directory holds the release-side tooling that pairs with the
[`update-client`](../../crates/update-client) crate to give Aegis signed,
downgrade-protected, rollback-safe updates (spec §5 Etap 5, §10, §14).

## Trust model

* A single **ed25519 release keypair** signs every update/image manifest.
* The **private key stays offline** (air-gapped signing host / HSM). Only the
  32-byte **public key (hex)** is shipped, in `/etc/aegis/config.toml` as
  `update_verify_key`.
* The daemon (via `update-client`) verifies:
  1. the manifest's ed25519 **signature** over the canonical bytes,
  2. **downgrade protection** — the new `version` must be strictly newer than the
     installed one,
  3. every artifact's **SHA-256**,
  before anything is written. A failed apply **rolls back** to the previous
  version.

## Canonicalization contract

The signature covers the manifest JSON with the `signature` field set to `""`,
serialized as **compact JSON with lexicographically sorted keys** (`jq -cS`).
`update-client::signing_bytes` produces byte-identical output; the cross-tool
test in [`tests/integration`](../../tests/integration) guards that they never
drift apart.

## Tooling

| Script | Purpose |
|--------|---------|
| `generate-keys.sh [out-dir]` | Create the ed25519 keypair; print the public hex for the config. |
| `sign-manifest.sh <priv.pem> <manifest.json>` | Sign a manifest in place. |
| `verify-manifest.sh <pub.pem\|--hex HEX> <manifest.json>` | Verify a manifest signature (mirrors the daemon). |

## Manifest shape

See `aegis_core::update::UpdateManifest`. Example:

```json
{
  "schema": 1,
  "version": { "major": 1, "minor": 2, "patch": 0 },
  "delta_base": null,
  "kind": "full",
  "artifacts": [
    { "kind": "browser-image", "location": "browser-1.2.0.qcow2",
      "sha256": "…", "size": 1234567 }
  ],
  "sbom": "sbom-1.2.0.cdx.json",
  "signature": ""
}
```

Sign with:

```sh
./sign-manifest.sh ./release-keys/aegis-release-ed25519.pem ./manifest.json
```
