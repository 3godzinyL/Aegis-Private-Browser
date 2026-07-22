//! update-client — signed update verification + application for Aegis.
//!
//! This crate provides [`SignedUpdateClient`], the concrete implementation of
//! [`aegis_core::traits::UpdateClient`] (spec §5 Etap 5, §10, §14). It:
//!
//! 1. fetches a JSON [`UpdateManifest`] from a pluggable [`Transport`],
//! 2. verifies its detached **ed25519** signature over the *canonical* manifest
//!    bytes ([`signing_bytes`]) against a configured verifying key,
//! 3. enforces **downgrade protection** (`Version::is_newer_than`),
//! 4. fetches every artifact and checks its **SHA-256** against the manifest,
//! 5. applies the verified artifacts atomically with a backup, rolling back on
//!    any failure so the previously-installed version stays intact.
//!
//! Every failure in the verification path is reported as
//! [`aegis_core::Error::Integrity`] so callers can apply fail-closed semantics
//! ([`aegis_core::FailureClass::Integrity`]).
//!
//! ## Transports
//!
//! [`Transport`] abstracts *where bytes come from* so the verification and
//! rollback logic is fully testable without a network or VMs:
//!
//! * [`FileTransport`] — reads locations relative to a base directory.
//! * [`UreqTransport`] — blocking HTTP(S) via `ureq` on a blocking task,
//!   behind the `ureq-transport` feature (enabled by default).
//! * [`MockTransport`] — an in-memory map, for tests.
//!
//! ## Security notes
//!
//! * Signatures, keys and artifact bytes are **never logged**. Diagnostics log
//!   only versions, locations and hash-mismatch facts.
//! * The signing key is a *verifying* (public) key; no private key ever lives in
//!   this crate.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use aegis_core::traits::UpdateClient;
use aegis_core::update::{ApplyOutcome, Artifact, UpdateManifest, VerifiedArtifact, VersionInfo};
use aegis_core::{Error, Result};
use async_trait::async_trait;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

/// A source of bytes for manifests and artifacts.
///
/// A `location` is an opaque, transport-relative string taken from the manifest
/// base or from an [`Artifact::location`]. Implementations resolve it however is
/// appropriate (a path under a base directory, a URL joined to a base URL, a key
/// into a map). Any failure to obtain the bytes is an
/// [`aegis_core::Error::System`] (transport/IO), *not* an integrity failure —
/// integrity is decided by this crate after the bytes are in hand.
#[async_trait]
pub trait Transport: Send + Sync {
    /// Fetch the full bytes at `location`.
    async fn fetch(&self, location: &str) -> Result<Vec<u8>>;
}

/// Reads locations as paths relative to a base directory.
#[derive(Debug, Clone)]
pub struct FileTransport {
    base: PathBuf,
}

impl FileTransport {
    /// Create a transport rooted at `base`.
    #[must_use]
    pub fn new(base: impl Into<PathBuf>) -> Self {
        Self { base: base.into() }
    }

    /// Resolve a location against the base directory, rejecting any location
    /// that would escape the base (absolute paths or `..` components).
    fn resolve(&self, location: &str) -> Result<PathBuf> {
        let rel = Path::new(location);
        if rel.is_absolute() {
            return Err(Error::System(format!(
                "file transport: absolute location rejected: {location}"
            )));
        }
        for comp in rel.components() {
            if matches!(comp, std::path::Component::ParentDir) {
                return Err(Error::System(format!(
                    "file transport: parent-dir escape rejected: {location}"
                )));
            }
        }
        Ok(self.base.join(rel))
    }
}

#[async_trait]
impl Transport for FileTransport {
    async fn fetch(&self, location: &str) -> Result<Vec<u8>> {
        let path = self.resolve(location)?;
        tokio::fs::read(&path)
            .await
            .map_err(|e| Error::System(format!("file transport: read {}: {e}", path.display())))
    }
}

/// An in-memory transport for tests: maps a location string to its bytes.
#[derive(Debug, Clone, Default)]
pub struct MockTransport {
    entries: BTreeMap<String, Vec<u8>>,
}

impl MockTransport {
    /// An empty transport.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert (or replace) the bytes served at `location`. Chainable.
    #[must_use]
    pub fn with(mut self, location: impl Into<String>, bytes: impl Into<Vec<u8>>) -> Self {
        self.entries.insert(location.into(), bytes.into());
        self
    }

    /// Insert (or replace) the bytes served at `location`.
    pub fn insert(&mut self, location: impl Into<String>, bytes: impl Into<Vec<u8>>) {
        self.entries.insert(location.into(), bytes.into());
    }

    /// Remove a location so a fetch of it fails (used to simulate outages).
    pub fn remove(&mut self, location: &str) {
        self.entries.remove(location);
    }
}

#[async_trait]
impl Transport for MockTransport {
    async fn fetch(&self, location: &str) -> Result<Vec<u8>> {
        self.entries
            .get(location)
            .cloned()
            .ok_or_else(|| Error::System(format!("mock transport: no entry for {location}")))
    }
}

/// A blocking HTTP(S) transport backed by `ureq`.
///
/// The blocking request runs on a dedicated blocking task
/// ([`tokio::task::spawn_blocking`]) so it never stalls the async runtime.
/// Locations are resolved by joining them onto the configured base URL: a
/// location that is already absolute (`http://…`/`https://…`) is used as-is,
/// otherwise it is appended to the base (a `/` is inserted if needed).
#[cfg(feature = "ureq-transport")]
#[derive(Debug, Clone)]
pub struct UreqTransport {
    base_url: String,
    /// Cap on a downloaded body, to bound memory. Defaults to 512 MiB.
    max_bytes: u64,
}

#[cfg(feature = "ureq-transport")]
impl UreqTransport {
    /// Default maximum body size (512 MiB).
    pub const DEFAULT_MAX_BYTES: u64 = 512 * 1024 * 1024;

    /// Create a transport that resolves relative locations against `base_url`.
    #[must_use]
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
            max_bytes: Self::DEFAULT_MAX_BYTES,
        }
    }

    /// Override the maximum body size accepted for a single fetch.
    #[must_use]
    pub fn with_max_bytes(mut self, max_bytes: u64) -> Self {
        self.max_bytes = max_bytes;
        self
    }

    fn resolve_url(&self, location: &str) -> String {
        if location.starts_with("http://") || location.starts_with("https://") {
            return location.to_string();
        }
        let base = self.base_url.trim_end_matches('/');
        let loc = location.trim_start_matches('/');
        format!("{base}/{loc}")
    }
}

#[cfg(feature = "ureq-transport")]
#[async_trait]
impl Transport for UreqTransport {
    async fn fetch(&self, location: &str) -> Result<Vec<u8>> {
        let url = self.resolve_url(location);
        let max_bytes = self.max_bytes;
        tokio::task::spawn_blocking(move || -> Result<Vec<u8>> {
            let resp = ureq::get(&url)
                .call()
                .map_err(|e| Error::System(format!("ureq transport: request failed: {e}")))?;
            use std::io::Read as _;
            let mut buf = Vec::new();
            let mut reader = resp.into_reader().take(max_bytes.saturating_add(1));
            reader
                .read_to_end(&mut buf)
                .map_err(|e| Error::System(format!("ureq transport: read body: {e}")))?;
            if buf.len() as u64 > max_bytes {
                return Err(Error::System(format!(
                    "ureq transport: body exceeds {max_bytes} bytes"
                )));
            }
            Ok(buf)
        })
        .await
        .map_err(|e| Error::System(format!("ureq transport: task join: {e}")))?
    }
}

/// The canonical bytes a signature is computed over.
///
/// This is the deterministic JSON serialization of `manifest` with the
/// `signature` field cleared to the empty string, and with **object keys sorted
/// lexicographically** (guaranteed because `serde_json::Value::Object` is
/// BTreeMap-backed when the `preserve_order` feature is off). Producing the
/// signing bytes therefore never depends on Rust struct field order.
///
/// This helper is pure and infallible for any manifest that serializes to JSON
/// (which every valid [`UpdateManifest`] does); on the impossible event of a
/// serialization error it returns an empty vector, which no signature can match.
#[must_use]
pub fn signing_bytes(manifest: &UpdateManifest) -> Vec<u8> {
    let mut unsigned = manifest.clone();
    unsigned.signature = String::new();
    // Round-trip through Value so keys are emitted in sorted (canonical) order.
    // On the (unreachable-for-a-valid-manifest) serialization error, fall back to
    // an empty vector that no signature can match.
    serde_json::to_value(&unsigned)
        .and_then(|v| serde_json::to_vec(&v))
        .unwrap_or_default()
}

/// Lowercase hex SHA-256 of `bytes`.
fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

/// A signed-manifest update client (spec §5 Etap 5, §10, §14).
///
/// Constructed with:
/// * a **base location** for the manifest (interpreted by the transport),
/// * an **ed25519 verifying key** in hex, and
/// * an `Arc<dyn Transport>` supplying the bytes.
pub struct SignedUpdateClient {
    base_location: String,
    verifying_key: VerifyingKey,
    transport: Arc<dyn Transport>,
    /// Where verified artifacts are installed by [`SignedUpdateClient::apply`].
    install_dir: Option<PathBuf>,
}

impl std::fmt::Debug for SignedUpdateClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Deliberately omit the key bytes from Debug output.
        f.debug_struct("SignedUpdateClient")
            .field("base_location", &self.base_location)
            .field("install_dir", &self.install_dir)
            .finish_non_exhaustive()
    }
}

impl SignedUpdateClient {
    /// Create a client from a hex-encoded ed25519 verifying key.
    ///
    /// # Errors
    /// Returns [`Error::Config`] if the key is not 32 valid hex-encoded bytes or
    /// is not a valid ed25519 point.
    pub fn new(
        base_location: impl Into<String>,
        verifying_key_hex: &str,
        transport: Arc<dyn Transport>,
    ) -> Result<Self> {
        let key = parse_verifying_key(verifying_key_hex)?;
        Ok(Self {
            base_location: base_location.into(),
            verifying_key: key,
            transport,
            install_dir: None,
        })
    }

    /// Set the directory verified artifacts are installed into by [`Self::apply`].
    ///
    /// If unset, `apply` treats each [`Artifact::location`] as a filesystem path
    /// to write in place (still with backup + rollback).
    #[must_use]
    pub fn with_install_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.install_dir = Some(dir.into());
        self
    }

    /// The manifest's location this client fetches from.
    #[must_use]
    pub fn base_location(&self) -> &str {
        &self.base_location
    }

    /// Fetch and parse the manifest from the base location.
    async fn fetch_manifest(&self) -> Result<UpdateManifest> {
        let bytes = self.transport.fetch(&self.base_location).await?;
        serde_json::from_slice(&bytes)
            .map_err(|e| Error::Integrity(format!("manifest is not valid JSON: {e}")))
    }

    /// Verify the ed25519 signature over the canonical manifest bytes.
    fn verify_signature(&self, manifest: &UpdateManifest) -> Result<()> {
        let sig_bytes = hex::decode(manifest.signature.trim())
            .map_err(|_| Error::Integrity("signature is not valid hex".into()))?;
        let sig_arr: [u8; Signature::BYTE_SIZE] = sig_bytes
            .as_slice()
            .try_into()
            .map_err(|_| Error::Integrity("signature has wrong length".into()))?;
        let signature = Signature::from_bytes(&sig_arr);
        let msg = signing_bytes(manifest);
        self.verifying_key
            .verify(&msg, &signature)
            .map_err(|_| Error::Integrity("manifest signature verification failed".into()))
    }

    /// Resolve an artifact's absolute install path.
    fn install_path(&self, artifact: &Artifact) -> Result<PathBuf> {
        let loc = Path::new(&artifact.location);
        match &self.install_dir {
            Some(dir) => {
                // Only the final file name is used under the install dir.
                let name = loc.file_name().ok_or_else(|| {
                    Error::System(format!(
                        "artifact location has no file name: {}",
                        artifact.location
                    ))
                })?;
                Ok(dir.join(name))
            }
            None => Ok(loc.to_path_buf()),
        }
    }
}

/// Parse a hex ed25519 verifying key, mapping any failure to [`Error::Config`].
fn parse_verifying_key(hex_key: &str) -> Result<VerifyingKey> {
    let raw = hex::decode(hex_key.trim())
        .map_err(|_| Error::Config("verifying key is not valid hex".into()))?;
    let arr: [u8; 32] = raw
        .as_slice()
        .try_into()
        .map_err(|_| Error::Config("verifying key must be 32 bytes".into()))?;
    VerifyingKey::from_bytes(&arr)
        .map_err(|_| Error::Config("verifying key is not a valid ed25519 point".into()))
}

#[async_trait]
impl UpdateClient for SignedUpdateClient {
    async fn check_for_update(&self, info: &VersionInfo) -> Result<Option<UpdateManifest>> {
        let manifest = self.fetch_manifest().await?;

        // Signature must be valid regardless of version.
        self.verify_signature(&manifest)?;

        if !manifest.version.is_newer_than(&info.current) {
            // Not newer (older or equal): nothing to offer. This is not an error.
            tracing::debug!(
                current = %info.current,
                offered = %manifest.version,
                "no newer update available"
            );
            return Ok(None);
        }
        tracing::info!(
            current = %info.current,
            offered = %manifest.version,
            "newer signed update available"
        );
        Ok(Some(manifest))
    }

    async fn verify(
        &self,
        manifest: &UpdateManifest,
        info: &VersionInfo,
    ) -> Result<VerifiedArtifact> {
        // (1) Signature.
        self.verify_signature(manifest)?;

        // (2) Downgrade protection: must be strictly newer.
        if !manifest.version.is_newer_than(&info.current) {
            return Err(Error::Integrity(format!(
                "downgrade rejected: offered {} is not newer than installed {}",
                manifest.version, info.current
            )));
        }

        // (3) Fetch each artifact and check its SHA-256.
        for artifact in &manifest.artifacts {
            let bytes = self.transport.fetch(&artifact.location).await?;
            let got = sha256_hex(&bytes);
            let want = artifact.sha256.trim().to_ascii_lowercase();
            if got != want {
                return Err(Error::Integrity(format!(
                    "artifact hash mismatch for {}: expected {want}, got {got}",
                    artifact.location
                )));
            }
        }

        Ok(VerifiedArtifact {
            version: manifest.version,
            artifacts: manifest.artifacts.clone(),
        })
    }

    async fn apply(&self, verified: &VerifiedArtifact) -> Result<ApplyOutcome> {
        // Records enough to restore every artifact we touch.
        struct Backup {
            /// Final install path.
            target: PathBuf,
            /// Where the previous file was moved to (None if there was none).
            backup: Option<PathBuf>,
            /// Whether we successfully wrote the new file (for cleanup on abort).
            wrote_new: bool,
        }

        let mut backups: Vec<Backup> = Vec::new();

        // Attempt to install every artifact, tracking state so we can roll back.
        let result: Result<()> = async {
            for artifact in &verified.artifacts {
                let target = self.install_path(artifact)?;
                if let Some(parent) = target.parent() {
                    tokio::fs::create_dir_all(parent).await.map_err(|e| {
                        Error::System(format!("apply: create dir {}: {e}", parent.display()))
                    })?;
                }

                // Back up any existing file at the target.
                let mut record = Backup {
                    target: target.clone(),
                    backup: None,
                    wrote_new: false,
                };
                if tokio::fs::try_exists(&target).await.unwrap_or(false) {
                    let backup_path = backup_path_for(&target);
                    tokio::fs::rename(&target, &backup_path)
                        .await
                        .map_err(|e| {
                            Error::System(format!("apply: back up {}: {e}", target.display()))
                        })?;
                    record.backup = Some(backup_path);
                }
                backups.push(record);

                // Fetch fresh bytes and re-verify the hash before installing,
                // so a transport that changed under us cannot slip an unverified
                // artifact into place.
                let bytes = self.transport.fetch(&artifact.location).await?;
                let got = sha256_hex(&bytes);
                if got != artifact.sha256.trim().to_ascii_lowercase() {
                    return Err(Error::Integrity(format!(
                        "apply: artifact hash mismatch for {}",
                        artifact.location
                    )));
                }

                // Write atomically: temp file in the same dir, then rename.
                let tmp = tmp_path_for(&target);
                tokio::fs::write(&tmp, &bytes).await.map_err(|e| {
                    Error::System(format!("apply: write temp {}: {e}", tmp.display()))
                })?;
                tokio::fs::rename(&tmp, &target).await.map_err(|e| {
                    Error::System(format!("apply: install {}: {e}", target.display()))
                })?;
                if let Some(last) = backups.last_mut() {
                    last.wrote_new = true;
                }
            }
            Ok(())
        }
        .await;

        match result {
            Ok(()) => {
                // Success: remove backups; failure to clean up is not fatal.
                for record in &backups {
                    if let Some(b) = &record.backup {
                        let _ = tokio::fs::remove_file(b).await;
                    }
                }
                tracing::info!(version = %verified.version, "update applied");
                Ok(ApplyOutcome::Applied)
            }
            Err(e) => {
                tracing::warn!(
                    version = %verified.version,
                    error = %e,
                    "update apply failed; rolling back"
                );
                // Roll back in reverse order.
                for record in backups.iter().rev() {
                    if record.wrote_new {
                        let _ = tokio::fs::remove_file(&record.target).await;
                    }
                    if let Some(b) = &record.backup {
                        // Restore the previous file. Best-effort; if this fails
                        // the outcome is still RolledBack but we surface a log.
                        if let Err(re) = tokio::fs::rename(b, &record.target).await {
                            tracing::error!(
                                target = %record.target.display(),
                                error = %re,
                                "rollback: failed to restore backup"
                            );
                        }
                    }
                }
                Ok(ApplyOutcome::RolledBack)
            }
        }
    }
}

/// Sibling backup path for `target` (`<name>.aegis-bak`).
fn backup_path_for(target: &Path) -> PathBuf {
    let mut name = target
        .file_name()
        .map(|n| n.to_os_string())
        .unwrap_or_default();
    name.push(".aegis-bak");
    target.with_file_name(name)
}

/// Sibling temp path for `target` (`<name>.aegis-tmp`).
fn tmp_path_for(target: &Path) -> PathBuf {
    let mut name = target
        .file_name()
        .map(|n| n.to_os_string())
        .unwrap_or_default();
    name.push(".aegis-tmp");
    target.with_file_name(name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_core::update::{Artifact, ArtifactKind, UpdateKind, Version};
    use ed25519_dalek::{Signer, SigningKey};
    use rand::rngs::OsRng;

    const MANIFEST_LOC: &str = "manifest.json";

    /// Build a signed manifest for `version` whose single artifact serves
    /// `artifact_bytes` at `art_loc`. Returns (manifest, signing key).
    fn signed_manifest(
        signing_key: &SigningKey,
        version: Version,
        art_loc: &str,
        artifact_bytes: &[u8],
    ) -> UpdateManifest {
        let mut manifest = UpdateManifest {
            schema: 1,
            version,
            delta_base: None,
            kind: UpdateKind::Full,
            artifacts: vec![Artifact {
                kind: ArtifactKind::AppPackage,
                location: art_loc.into(),
                sha256: sha256_hex(artifact_bytes),
                size: artifact_bytes.len() as u64,
            }],
            sbom: None,
            signature: String::new(),
        };
        let sig = signing_key.sign(&signing_bytes(&manifest));
        manifest.signature = hex::encode(sig.to_bytes());
        manifest
    }

    fn key_hex(sk: &SigningKey) -> String {
        hex::encode(sk.verifying_key().to_bytes())
    }

    fn client(vk_hex: &str, transport: MockTransport) -> SignedUpdateClient {
        SignedUpdateClient::new(MANIFEST_LOC, vk_hex, Arc::new(transport)).unwrap()
    }

    #[test]
    fn signing_bytes_ignores_signature_field_and_is_stable() {
        let sk = SigningKey::generate(&mut OsRng);
        let m1 = signed_manifest(&sk, Version::new(1, 2, 3), "app.pkg", b"payload");
        // Same manifest with a garbage signature must produce identical bytes.
        let mut m2 = m1.clone();
        m2.signature = "deadbeef".into();
        assert_eq!(signing_bytes(&m1), signing_bytes(&m2));
        // And is stable across calls.
        assert_eq!(signing_bytes(&m1), signing_bytes(&m1));
    }

    #[test]
    fn signing_bytes_has_sorted_keys() {
        let sk = SigningKey::generate(&mut OsRng);
        let m = signed_manifest(&sk, Version::new(1, 0, 0), "app.pkg", b"x");
        let text = String::from_utf8(signing_bytes(&m)).unwrap();
        // Canonical order: "artifacts" precedes "kind" precedes "schema" ...
        let a = text.find("\"artifacts\"").unwrap();
        let k = text.find("\"kind\"").unwrap();
        let s = text.find("\"schema\"").unwrap();
        let v = text.find("\"version\"").unwrap();
        assert!(a < k && k < s && s < v, "keys not sorted: {text}");
        // Signature is present but empty.
        assert!(text.contains("\"signature\":\"\""));
    }

    #[test]
    fn bad_verifying_key_rejected() {
        let t = Arc::new(MockTransport::new());
        // Not hex.
        assert!(SignedUpdateClient::new("m", "not-hex", t.clone()).is_err());
        // Valid hex but wrong length.
        assert!(SignedUpdateClient::new("m", "00", t.clone()).is_err());
        assert!(SignedUpdateClient::new("m", &"ab".repeat(31), t.clone()).is_err());
        assert!(SignedUpdateClient::new("m", &"ab".repeat(33), t.clone()).is_err());
        // Odd number of hex digits.
        assert!(SignedUpdateClient::new("m", "abc", t.clone()).is_err());
        // A real, generated key IS accepted.
        let sk = SigningKey::generate(&mut OsRng);
        assert!(SignedUpdateClient::new("m", &key_hex(&sk), t).is_ok());
    }

    #[tokio::test]
    async fn valid_signed_manifest_verifies() {
        let sk = SigningKey::generate(&mut OsRng);
        let art = b"the artifact bytes";
        let manifest = signed_manifest(&sk, Version::new(1, 1, 0), "app-1.1.0.pkg", art);
        let transport = MockTransport::new()
            .with(MANIFEST_LOC, serde_json::to_vec(&manifest).unwrap())
            .with("app-1.1.0.pkg", art.to_vec());
        let c = client(&key_hex(&sk), transport);

        let info = VersionInfo {
            current: Version::new(1, 0, 0),
        };
        // check_for_update returns Some (newer).
        let checked = c.check_for_update(&info).await.unwrap();
        assert_eq!(
            checked.as_ref().map(|m| m.version),
            Some(Version::new(1, 1, 0))
        );

        // verify returns the artifact set.
        let verified = c.verify(&manifest, &info).await.unwrap();
        assert_eq!(verified.version, Version::new(1, 1, 0));
        assert_eq!(verified.artifacts.len(), 1);
    }

    #[tokio::test]
    async fn tampered_manifest_breaks_signature() {
        let sk = SigningKey::generate(&mut OsRng);
        let art = b"payload";
        let mut manifest = signed_manifest(&sk, Version::new(2, 0, 0), "a.pkg", art);
        // Tamper with a signed field (version) but keep the old signature.
        manifest.version = Version::new(3, 0, 0);
        let transport = MockTransport::new()
            .with(MANIFEST_LOC, serde_json::to_vec(&manifest).unwrap())
            .with("a.pkg", art.to_vec());
        let c = client(&key_hex(&sk), transport);
        let info = VersionInfo {
            current: Version::new(1, 0, 0),
        };

        let err = c.verify(&manifest, &info).await.unwrap_err();
        assert_eq!(err.class(), aegis_core::FailureClass::Integrity);
        // check_for_update also rejects (signature checked before version gate).
        let err2 = c.check_for_update(&info).await.unwrap_err();
        assert_eq!(err2.class(), aegis_core::FailureClass::Integrity);
    }

    #[tokio::test]
    async fn wrong_key_rejected() {
        let sk = SigningKey::generate(&mut OsRng);
        let other = SigningKey::generate(&mut OsRng);
        let art = b"payload";
        let manifest = signed_manifest(&sk, Version::new(2, 0, 0), "a.pkg", art);
        let transport = MockTransport::new()
            .with(MANIFEST_LOC, serde_json::to_vec(&manifest).unwrap())
            .with("a.pkg", art.to_vec());
        // Configure with the WRONG verifying key.
        let c = client(&key_hex(&other), transport);
        let info = VersionInfo {
            current: Version::new(1, 0, 0),
        };
        let err = c.verify(&manifest, &info).await.unwrap_err();
        assert_eq!(err.class(), aegis_core::FailureClass::Integrity);
    }

    #[tokio::test]
    async fn downgrade_and_equal_rejected() {
        let sk = SigningKey::generate(&mut OsRng);
        let art = b"payload";
        let info = VersionInfo {
            current: Version::new(2, 0, 0),
        };

        // Equal version.
        let equal = signed_manifest(&sk, Version::new(2, 0, 0), "a.pkg", art);
        let t_equal = MockTransport::new()
            .with(MANIFEST_LOC, serde_json::to_vec(&equal).unwrap())
            .with("a.pkg", art.to_vec());
        let c_equal = client(&key_hex(&sk), t_equal);
        let err = c_equal.verify(&equal, &info).await.unwrap_err();
        assert_eq!(err.class(), aegis_core::FailureClass::Integrity);
        assert!(format!("{err}").contains("downgrade"));
        // check_for_update returns Ok(None), NOT an error.
        assert!(c_equal.check_for_update(&info).await.unwrap().is_none());

        // Older version.
        let older = signed_manifest(&sk, Version::new(1, 9, 9), "a.pkg", art);
        let t_older = MockTransport::new()
            .with(MANIFEST_LOC, serde_json::to_vec(&older).unwrap())
            .with("a.pkg", art.to_vec());
        let c_older = client(&key_hex(&sk), t_older);
        assert!(c_older.verify(&older, &info).await.is_err());
        assert!(c_older.check_for_update(&info).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn artifact_hash_mismatch_rejected() {
        let sk = SigningKey::generate(&mut OsRng);
        let art = b"the real bytes";
        let manifest = signed_manifest(&sk, Version::new(1, 1, 0), "a.pkg", art);
        // Serve DIFFERENT bytes than the ones the manifest was built from.
        let transport = MockTransport::new()
            .with(MANIFEST_LOC, serde_json::to_vec(&manifest).unwrap())
            .with("a.pkg", b"TAMPERED bytes".to_vec());
        let c = client(&key_hex(&sk), transport);
        let info = VersionInfo {
            current: Version::new(1, 0, 0),
        };
        let err = c.verify(&manifest, &info).await.unwrap_err();
        assert_eq!(err.class(), aegis_core::FailureClass::Integrity);
        assert!(format!("{err}").contains("hash mismatch"));
    }

    #[tokio::test]
    async fn missing_artifact_is_system_error() {
        let sk = SigningKey::generate(&mut OsRng);
        let art = b"bytes";
        let manifest = signed_manifest(&sk, Version::new(1, 1, 0), "a.pkg", art);
        // Manifest present, artifact absent.
        let transport =
            MockTransport::new().with(MANIFEST_LOC, serde_json::to_vec(&manifest).unwrap());
        let c = client(&key_hex(&sk), transport);
        let info = VersionInfo {
            current: Version::new(1, 0, 0),
        };
        let err = c.verify(&manifest, &info).await.unwrap_err();
        assert_eq!(err.class(), aegis_core::FailureClass::System);
    }

    #[tokio::test]
    async fn apply_installs_and_replaces_atomically() {
        let sk = SigningKey::generate(&mut OsRng);
        let dir = tempfile::tempdir().unwrap();
        let install = dir.path().join("install");
        std::fs::create_dir_all(&install).unwrap();
        // Pre-existing (old) file at the target.
        let target = install.join("app.pkg");
        std::fs::write(&target, b"OLD VERSION").unwrap();

        let new_bytes = b"NEW VERSION 1.1.0";
        let manifest = signed_manifest(&sk, Version::new(1, 1, 0), "app.pkg", new_bytes);
        let transport = MockTransport::new()
            .with(MANIFEST_LOC, serde_json::to_vec(&manifest).unwrap())
            .with("app.pkg", new_bytes.to_vec());
        let c = client(&key_hex(&sk), transport).with_install_dir(&install);
        let info = VersionInfo {
            current: Version::new(1, 0, 0),
        };

        let verified = c.verify(&manifest, &info).await.unwrap();
        let outcome = c.apply(&verified).await.unwrap();
        assert_eq!(outcome, ApplyOutcome::Applied);
        assert_eq!(std::fs::read(&target).unwrap(), new_bytes);
        // No backup / temp files left behind.
        assert!(!backup_path_for(&target).exists());
        assert!(!tmp_path_for(&target).exists());
    }

    /// A transport that serves correct bytes for the first artifact and then
    /// fails on a later location, to simulate a mid-apply failure.
    #[derive(Debug)]
    struct FlakyTransport {
        good: MockTransport,
        fail_location: String,
    }

    #[async_trait]
    impl Transport for FlakyTransport {
        async fn fetch(&self, location: &str) -> Result<Vec<u8>> {
            if location == self.fail_location {
                return Err(Error::System("simulated transport failure".into()));
            }
            self.good.fetch(location).await
        }
    }

    #[tokio::test]
    async fn apply_rolls_back_on_failure_leaving_previous_intact() {
        let sk = SigningKey::generate(&mut OsRng);
        let dir = tempfile::tempdir().unwrap();
        let install = dir.path().join("install");
        std::fs::create_dir_all(&install).unwrap();

        // Two pre-existing files.
        let target_a = install.join("a.pkg");
        let target_b = install.join("b.pkg");
        std::fs::write(&target_a, b"OLD A").unwrap();
        std::fs::write(&target_b, b"OLD B").unwrap();

        let new_a = b"NEW A";
        let new_b = b"NEW B";
        // Build a two-artifact signed manifest.
        let mut manifest = UpdateManifest {
            schema: 1,
            version: Version::new(2, 0, 0),
            delta_base: None,
            kind: UpdateKind::Full,
            artifacts: vec![
                Artifact {
                    kind: ArtifactKind::AppPackage,
                    location: "a.pkg".into(),
                    sha256: sha256_hex(new_a),
                    size: new_a.len() as u64,
                },
                Artifact {
                    kind: ArtifactKind::AppPackage,
                    location: "b.pkg".into(),
                    sha256: sha256_hex(new_b),
                    size: new_b.len() as u64,
                },
            ],
            sbom: None,
            signature: String::new(),
        };
        let sig = sk.sign(&signing_bytes(&manifest));
        manifest.signature = hex::encode(sig.to_bytes());

        let good = MockTransport::new()
            .with(MANIFEST_LOC, serde_json::to_vec(&manifest).unwrap())
            .with("a.pkg", new_a.to_vec())
            .with("b.pkg", new_b.to_vec());
        // verify() uses `good` (all fetches succeed); apply() uses a flaky one
        // that fails on the SECOND artifact after the first is already swapped.
        let verify_client =
            SignedUpdateClient::new(MANIFEST_LOC, &key_hex(&sk), Arc::new(good.clone())).unwrap();
        let info = VersionInfo {
            current: Version::new(1, 0, 0),
        };
        let verified = verify_client.verify(&manifest, &info).await.unwrap();

        let flaky = FlakyTransport {
            good,
            fail_location: "b.pkg".into(),
        };
        let apply_client = SignedUpdateClient::new(MANIFEST_LOC, &key_hex(&sk), Arc::new(flaky))
            .unwrap()
            .with_install_dir(&install);

        let outcome = apply_client.apply(&verified).await.unwrap();
        assert_eq!(outcome, ApplyOutcome::RolledBack);

        // Both previous versions must be intact.
        assert_eq!(std::fs::read(&target_a).unwrap(), b"OLD A");
        assert_eq!(std::fs::read(&target_b).unwrap(), b"OLD B");
        // No stray backup/temp files.
        assert!(!backup_path_for(&target_a).exists());
        assert!(!tmp_path_for(&target_a).exists());
        assert!(!backup_path_for(&target_b).exists());
        assert!(!tmp_path_for(&target_b).exists());
    }

    #[tokio::test]
    async fn apply_rolls_back_and_restores_when_no_previous_file() {
        // If the target did not exist before, rollback must remove the new file.
        let sk = SigningKey::generate(&mut OsRng);
        let dir = tempfile::tempdir().unwrap();
        let install = dir.path().join("install");
        std::fs::create_dir_all(&install).unwrap();

        let new_a = b"NEW A";
        let new_b = b"NEW B";
        let mut manifest = UpdateManifest {
            schema: 1,
            version: Version::new(2, 0, 0),
            delta_base: None,
            kind: UpdateKind::Full,
            artifacts: vec![
                Artifact {
                    kind: ArtifactKind::AppPackage,
                    location: "a.pkg".into(),
                    sha256: sha256_hex(new_a),
                    size: new_a.len() as u64,
                },
                Artifact {
                    kind: ArtifactKind::AppPackage,
                    location: "b.pkg".into(),
                    sha256: sha256_hex(new_b),
                    size: new_b.len() as u64,
                },
            ],
            sbom: None,
            signature: String::new(),
        };
        let sig = sk.sign(&signing_bytes(&manifest));
        manifest.signature = hex::encode(sig.to_bytes());

        let good = MockTransport::new()
            .with(MANIFEST_LOC, serde_json::to_vec(&manifest).unwrap())
            .with("a.pkg", new_a.to_vec())
            .with("b.pkg", new_b.to_vec());
        let info = VersionInfo {
            current: Version::new(1, 0, 0),
        };
        let verified = SignedUpdateClient::new(MANIFEST_LOC, &key_hex(&sk), Arc::new(good.clone()))
            .unwrap()
            .verify(&manifest, &info)
            .await
            .unwrap();

        let flaky = FlakyTransport {
            good,
            fail_location: "b.pkg".into(),
        };
        let apply_client = SignedUpdateClient::new(MANIFEST_LOC, &key_hex(&sk), Arc::new(flaky))
            .unwrap()
            .with_install_dir(&install);
        let outcome = apply_client.apply(&verified).await.unwrap();
        assert_eq!(outcome, ApplyOutcome::RolledBack);

        // The first artifact was written then removed on rollback; neither
        // target should exist now.
        assert!(!install.join("a.pkg").exists());
        assert!(!install.join("b.pkg").exists());
    }

    #[tokio::test]
    async fn file_transport_reads_and_rejects_escape() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("m.json"), b"hello").unwrap();
        let t = FileTransport::new(dir.path());
        assert_eq!(t.fetch("m.json").await.unwrap(), b"hello");
        // Escapes are rejected.
        assert!(t.fetch("../secret").await.is_err());
        assert!(t.fetch("sub/../../secret").await.is_err());
    }

    #[tokio::test]
    async fn malformed_manifest_json_is_integrity_error() {
        let sk = SigningKey::generate(&mut OsRng);
        let transport = MockTransport::new().with(MANIFEST_LOC, b"{ not json".to_vec());
        let c = client(&key_hex(&sk), transport);
        let info = VersionInfo {
            current: Version::new(1, 0, 0),
        };
        let err = c.check_for_update(&info).await.unwrap_err();
        assert_eq!(err.class(), aegis_core::FailureClass::Integrity);
    }
}
