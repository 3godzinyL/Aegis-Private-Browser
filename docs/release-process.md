# Aegis Private Browser — Release & Update Process

Status: Stage 0 (foundations). This document specifies how Aegis builds, signs,
distributes, and updates its artifacts, and the integrity rules the update client
enforces. It corresponds to the executive specification's **Etap 5 (updates and
integrity)**, **§10 (protection against browser compromise)**, and **§14
(acceptance criteria, "Aktualizacje")**.

The governing rule, restated: an update that is unsigned, older, or corrupt must
be **rejected**, and a failed apply must **roll back**. Every component must carry
an identifiable version and hash (spec §14).

---

## 1. Artifacts

A release publishes three kinds of artifact (`ArtifactKind` in
`crates/aegis-core/src/update.rs`):

| Kind | What it is |
|------|-----------|
| `gateway-image` | The signed Gateway VM base image (qcow2). |
| `browser-image` | The signed Browser VM base image (qcow2). |
| `app-package` | The host-side application package (daemon, UI, CLI). |

VM images are reproducible base snapshots. At runtime a disposable session runs a
throwaway qcow2 overlay on top of the read-only base; the base image itself is
never mutated (spec §4, §8).

---

## 2. The signed manifest

Every release is described by a single `UpdateManifest`
(`crates/aegis-core/src/update.rs`). Its fields:

```
UpdateManifest {
  schema:      u32,                 // manifest format version
  version:     Version,             // the product version this manifest publishes
  delta_base:  Option<Version>,     // required installed version for a delta
  kind:        Full | Delta,        // full replacement or binary delta
  artifacts:   Vec<Artifact>,       // each with kind, location, sha256, size
  sbom:        Option<String>,      // reference to the SBOM document
  signature:   String,             // detached ed25519 signature (hex)
}
```

Each `Artifact` carries its `kind`, download `location`, lowercase-hex **SHA-256**,
and `size`.

### 2.1 ed25519 manifest signing

- The manifest is signed with **ed25519** (`ed25519-dalek`). The signature is a
  detached signature over the **canonical serialization of every field except
  `signature` itself** (the `update-client` crate defines the canonicalization —
  the manifest is serialized with the `signature` field removed/empty, then
  signed).
- The public verification key is pinned in the host configuration
  (`AppConfig::update_verify_key`, hex ed25519) and ships with the application, not
  fetched at update time. The private signing key lives only in the release
  process, offline.
- **A manifest whose signature does not verify against the pinned key is
  rejected** before any artifact is downloaded or hashed. This is the acceptance
  criterion "an unsigned update is rejected" (spec §14).

### 2.2 SHA-256 artifact integrity

After the signature verifies, each artifact's bytes are hashed with **SHA-256**
(`sha2`) and compared against the `sha256` recorded in the manifest. Any mismatch
is an `Integrity` failure. Because the hashes are covered by the signed manifest,
tampering with either the artifact **or** its recorded hash is detected.

### 2.3 Signed VM images

VM base images are referenced from host config as `ImageRef { path, signature,
version, sha256 }` (`crates/aegis-core/src/config.rs`). Before a base image is used
to provision a VM, its detached signature and SHA-256 are verified — an image that
fails verification is never booted (spec §10: "weryfikacja podpisów obrazów VM").

---

## 3. Monotonic-version downgrade protection

`Version` is a totally-ordered `major.minor.patch` value. The client refuses any
version that is **not strictly newer** than the installed one:

```
manifest.version.is_newer_than(&installed.current)  // must be true, else reject
```

A downgrade — an attempt to install an older, possibly-vulnerable version — is an
`Integrity` failure and is rejected (spec §10 "blokada downgrade'u"; §14 "an older
version is rejected"). Because the version is inside the signed manifest, an
attacker cannot rewrite it to bypass the check without breaking the signature.

Unit tests: `update::tests::version_ordering_and_parse`,
`update::tests::manifest_roundtrips`.

---

## 4. Delta vs full updates

`UpdateKind` selects the update shape (spec Etap 5: "aktualizacje delta albo
pełne"):

- **`Full`** — a complete artifact replacement. Always applicable.
- **`Delta`** — a binary delta against a specific base version named in
  `delta_base`. A delta is only applicable when the installed version **equals**
  its `delta_base`; otherwise the client falls back to (or requests) a full update.
  The delta is applied, and the reconstructed artifact is verified against the
  signed SHA-256 exactly as a full artifact would be — so a delta cannot smuggle in
  bytes the manifest did not authorize.

---

## 5. Verify → apply → automatic rollback

The `UpdateClient` trait (`crates/aegis-core/src/traits.rs`) has three steps:

```
check_for_update(info) -> Option<UpdateManifest>
verify(manifest, info) -> VerifiedArtifact     // signature + hashes + downgrade
apply(verified)        -> ApplyOutcome           // Applied | RolledBack
```

1. **check** — is there a newer, structurally valid manifest?
2. **verify** — ed25519 signature valid → every artifact SHA-256 matches → version
   strictly newer. Only then is a `VerifiedArtifact` produced. Any failure here
   returns an `Integrity` error and nothing is installed.
3. **apply** — the new version is staged and activated. If activation fails (bad
   write, failed post-install health check, interrupted apply), the client
   **automatically rolls back** to the previous version and returns
   `ApplyOutcome::RolledBack`; the previous version remains intact (spec §10
   "automatyczny rollback"; §14 "a corrupt update triggers rollback").

Applying is transactional with respect to the *active* version: the previous
version is retained until the new one is verified healthy, so a failed or corrupt
update never leaves the system unbootable.

---

## 6. SBOM generation and dependency scanning

Every release records what it is made of (spec §10 "SBOM dla każdej wersji";
Etap 5 "generowanie SBOM", "skan zależności").

### 6.1 SBOM

- An SBOM is generated for each release with **`cargo-sbom`** (and/or
  **`cargo-auditable`** to embed dependency metadata directly into the shipped
  binaries so the exact dependency set can be recovered from the artifact itself).
- The SBOM document is referenced from the manifest's `sbom` field, so a consumer
  can tie a running version to its bill of materials.

### 6.2 Dependency scanning

- **`cargo-deny`** runs in CI and gates releases: it checks for known-vulnerable
  advisories (RustSec), disallowed or duplicate dependencies, and license policy
  (the workspace is `GPL-3.0-or-later`). A release must pass `cargo-deny` before it
  can be signed.
- The workspace also forbids `unsafe_code` (`[workspace.lints.rust] unsafe_code =
  "forbid"` in `Cargo.toml`) and treats Clippy findings as warnings across all
  crates, shrinking the class of defects that can ship.

---

## 7. No remote debugging in production; reproducibility

These are release-blocking requirements (spec §10, §16).

### 7.1 No remote debugging in production builds

- Production browser builds must not expose remote debugging or a DevTools
  Protocol endpoint on a network interface (spec §10: "brak zdalnego debugowania w
  buildach produkcyjnych", "brak DevTools Protocol wystawionego na interfejs
  sieciowy").
- This is enforced in code: `BackendPolicyBundle::assert_safe(production=true)`
  rejects any `--remote-debugging*` flag (and `--no-sandbox` /
  `--disable-web-security` unconditionally). See
  `crates/aegis-core/src/browser.rs`.
- Core dumps that could contain user data are disabled in production (spec §10:
  "wyłączone core dumpy zawierające dane użytkownika").

### 7.2 Reproducibility & traceability

- **Every component carries an identifiable version and hash** (spec §14). The
  signed manifest ties each artifact to a version and a SHA-256; `cargo-auditable`
  ties each binary to its dependency set.
- Builds should be **reproducible**: pinned toolchain (`rust-version = "1.82"` in
  `Cargo.toml`), a committed `Cargo.lock`, and deterministic image builds
  (`images/gateway`, `images/browser`) so that a given source revision yields
  byte-identical artifacts that independent parties can re-derive and whose hashes
  match the signed manifest.
- Every Chromium modification is described and covered by a regression test (spec
  §16: "każdą modyfikację Chromium opisać i objąć testem regresji"); see
  `browser/chromium-patches/` and the `tests/browser-api` suite.

---

## 8. Release checklist (acceptance criteria, spec §14)

A build is not releasable until all of these hold:

- [ ] All workspace tests pass (`cargo test --workspace`), `cargo fmt --check`,
      `cargo clippy` clean.
- [ ] `cargo-deny` passes (advisories, bans, licenses).
- [ ] SBOM generated and referenced from the manifest.
- [ ] Each artifact has a recorded SHA-256 and size; VM images have detached
      signatures.
- [ ] The manifest is ed25519-signed with the release key; the signature verifies
      against the pinned public key.
- [ ] The new `version` is strictly newer than the previous release (monotonic).
- [ ] **An unsigned update is rejected.**
- [ ] **An older version is rejected.**
- [ ] **A corrupted update triggers rollback.**
- [ ] Production build exposes no remote debugging / networked DevTools endpoint;
      `assert_safe` passes for the production command line.
- [ ] Core dumps containing user data are disabled.

---

## 9. Cross-references

- [`architecture.md`](./architecture.md) — the daemon, the `update-client` crate,
  and the `BrowserBackend` guard.
- [`threat-model.md`](./threat-model.md) — supply chain as asset A9.
- [`../SECURITY.md`](../SECURITY.md) — supported versions and reporting.
