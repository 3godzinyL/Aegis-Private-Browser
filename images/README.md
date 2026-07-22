# Aegis VM images

Reproducible, minimal, hardened VM base images for Aegis Private Browser. Two
roles, built from the definitions in this directory:

- **[`gateway/`](gateway/README.md)** — the network gateway: default-deny
  `nftables` firewall + Tor, two NICs (upstream + isolated downstream), kill
  switch, health probe. Spec §5, Etap 1.
- **[`browser/`](browser/README.md)** — the isolated Chromium workstation:
  read-only root, one NIC to the gateway, no host integration, sandboxed kiosk.
  Spec §6, Etap 2.

Both are built on a Linux host (KVM/QEMU/libvirt target). The build scripts are
not run on Windows; they are checked for correctness and documented here.

## Consistency with `aegis-core`

The images render the contracts in `crates/aegis-core`:

| aegis-core type | How the images honor it |
|---|---|
| `IsolationPolicy::hardened()` | No shared clipboard/DnD/folders/automount, no USB/PCI passthrough, no camera/mic, no host SSH agent, no desktop-integration guest tools, read-only root, random instance id, fresh NIC. spice-vdagent and desktop guest tools are **not installed**; `qemu-guest-agent` is locked to shutdown/fsfreeze RPCs only. |
| `GpuBackend::{VirtioGpu, Software}` | Browser uses virtio-gpu (`--use-gl=angle`) in Balanced, software (`--disable-gpu`) in Strict. No physical GPU passthrough, ever. |
| `DiskLayer { read_only_root, destroy_on_close, .. }` | Both images mount `/` read-only (`etc/fstab`) with tmpfs writable layers; `vm-controller` adds a disposable qcow2 overlay destroyed on close. |
| `gateway::FirewallPolicy` (Drop, block_direct_udp, redirect 5353/9040) | The gateway ruleset (`aegis-gateway.nft`) and `torrc` use exactly these ports and a default-deny policy. |
| `gateway::GatewayHealth` | `aegis-healthcheck` emits JSON of this exact shape. |
| `fingerprint::ProtectionLevel::{Balanced, Strict}` | Browser firstboot installs the matching managed policy; strict fails-closed. |
| `preflight::CheckId` | The gateway health + firewall + Tor state feed `gateway_ready`, `tunnel_ready`, `dns_route_verified`, `ipv6_policy_verified`; the browser launch flags + managed policy feed `webrtc_policy_loaded`. |

## Reproducible build

Each image can be built two interchangeable ways (both produce the same logical
image):

1. **mkosi** (preferred, declarative): `images/<role>/mkosi.conf` +
   `mkosi.postinst`. Run `mkosi --image-version=<v> --force build`.
2. **debootstrap** (fallback): `images/<role>/build.sh`.

Reproducibility levers, applied by both:

- **`SOURCE_DATE_EPOCH`** is fixed (default `1735689600` = 2025-01-01Z), pinning
  every mtime and the squashfs timestamp.
- **Package pinning:** point the mirror at a timestamped `snapshot.debian.org`
  archive in CI (`Mirror=` in `mkosi.conf` / `--mirror` for `build.sh`) so the
  exact package versions are frozen.
- **Fixed package set:** enumerated in the build definition; no interactive or
  network-varying selection (`DEBIAN_FRONTEND=noninteractive`, `LC_ALL=C`).
- **No host state:** `/etc/machine-id` is shipped empty (randomized per instance,
  never host-derived — see each image's `etc/machine-id.README`); no host keys,
  no host mirror config, no host user data are copied in.
- **Doc/man/apt-list stripping** for a deterministic, minimal tree.

Given the same `SOURCE_DATE_EPOCH` + snapshot mirror + definition revision, two
builds produce byte-identical qcow2 artifacts.

## Hashing + signing (verified by `update-client`)

Each built image is:

1. **Hashed** — SHA-256 over the qcow2 bytes (`build.sh` writes
   `<image>.qcow2.sha256`).
2. **Described** in a signed **`UpdateManifest`** (`aegis_core::update`):
   - `artifacts[]` with `kind = gateway-image | browser-image`, `location`,
     `sha256` (lowercase hex), and `size`.
   - a **detached ed25519 `signature`** over the canonical manifest bytes
     (everything except the `signature` field), produced with the project's
     **offline release key**.
   - an optional `sbom` reference (SPDX) for the release.
3. **Verified by `update-client`** on the host before use:
   - checks the ed25519 signature against the pinned public key (an **unsigned
     update is rejected**),
   - recomputes each artifact's SHA-256 and compares (a **corrupt artifact
     triggers rollback**),
   - enforces **downgrade protection** — the manifest `version` must be strictly
     newer than the installed one (`Version::is_newer_than`),
   - keeps the previous known-good image so a failed apply **rolls back**
     (`ApplyOutcome::RolledBack`).

Signing keys never live in the image or the build host's working tree; the
release pipeline signs with an offline/HSM-held key and publishes only the public
half, which the client pins.

### Release-pipeline sketch

```
build.sh / mkosi  →  aegis-<role>_<ver>.qcow2
                  →  sha256sum                              → .sha256
                  →  compose UpdateManifest (kind, location, sha256, size, sbom)
                  →  ed25519-sign canonical manifest (offline key)
                  →  publish {qcow2, manifest.json, sbom.spdx.json}
host: update-client → verify signature → verify sha256 → check newer → install
                    → on any failure: reject / rollback (fail-closed)
```

## Consumption by `vm-controller` (read-only backing + disposable overlay)

`vm-controller` never boots the base image directly. Per session it:

1. Uses the **verified** qcow2 as a **read-only backing image**.
2. Creates a **disposable qcow2 overlay** on top:
   `qemu-img create -f qcow2 -F qcow2 -b <backing> <overlay>` (the overlay lives
   on an encrypted/tmpfs-backed path for ephemeral sessions).
3. Defines a libvirt domain with:
   - a **fresh random domain UUID** (never the host SMBIOS UUID),
   - a **fresh virtual NIC** (new MAC) per instance
     (`IsolationPolicy.fresh_network_device`),
   - **no** shared folders / clipboard / USB / PCI passthrough / camera / mic
     (the hardened `IsolationPolicy`, asserted before provisioning),
   - the gateway domain wired to **two** networks (upstream NAT + isolated
     downstream); the browser domain wired to the **isolated** network only.
4. On session end, **shreds and removes** the overlay
   (`shred -u -z <overlay>`), leaving the backing image untouched, so an
   ephemeral session leaves no writable residue (`DestroyReport.is_clean`).

Because the root is read-only and every writable path inside the guest is tmpfs
(RAM-only), and the overlay is destroyed on close, an ephemeral session persists
nothing — satisfying the disposable-profile acceptance criteria (spec §8, §14).

## Directory layout

```
images/
├── README.md                ← this file (build + signing + consumption flow)
├── gateway/
│   ├── mkosi.conf           ← preferred build definition
│   ├── mkosi.postinst       ← image finalization (units, hardening, machine-id)
│   ├── build.sh             ← debootstrap alternative
│   ├── README.md
│   └── files/…              ← /etc + /usr tree overlaid into the image
└── browser/
    ├── mkosi.conf
    ├── mkosi.postinst
    ├── build.sh
    ├── README.md
    └── files/…
```
