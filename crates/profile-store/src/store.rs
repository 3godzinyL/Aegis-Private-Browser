//! The file-backed [`ProfileRepository`] implementation.

use crate::shred::{OverwriteShredder, Shredder};
use aegis_core::profile::{Profile, ProfilePatch, ProfileSpec, StorageUsage};
use aegis_core::traits::{ProfileLease, ProfileRepository};
use aegis_core::{Error, ProfileId, Result};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use rand::RngCore;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// The filename holding a profile's serialized metadata inside its directory.
const META_FILE: &str = "profile.json";
/// The filename holding the single-writer lock token inside a profile directory.
const LOCK_FILE: &str = "profile.lock";
/// The subdirectory reserved for the profile's own writable data (browser
/// state, downloads, the encrypted volume for persistent profiles). It is kept
/// per-profile so profile A's data is never mixed with profile B's (spec §8:
/// "osobna baza ustawień dla każdego profilu").
const DATA_DIR: &str = "data";

/// A profile repository that persists each profile as a directory under a common
/// root, with metadata stored as **plain JSON**.
///
/// ## Why plain JSON is safe here
///
/// A [`Profile`] holds *no plaintext secrets*. Network credentials appear only
/// as [`aegis_core::network::CredentialRef`] handles that point into
/// `secure-storage`; permission grants, protection level, and names are not
/// sensitive. The genuinely sensitive per-profile data (browsing state, the
/// persistent profile's key material) lives inside the profile's `data/`
/// subdirectory as an **encrypted volume**, which this store never inspects. The
/// metadata JSON is therefore safe to write in the clear (spec §8, §16).
///
/// ## Layout
///
/// ```text
/// <root>/
///   <profile-id>/
///     profile.json   # metadata (this store owns it)
///     profile.lock   # single-writer lock token, present only while held
///     data/          # the profile's own encrypted volume / browser state
/// ```
///
/// ## Concurrency
///
/// A per-store async mutex serializes metadata mutations within one process so
/// concurrent `create`/`update`/`delete` calls cannot interleave a read-modify-
/// write. The *cross-session* single-writer guarantee (spec §8: "brak możliwości
/// współdzielenia profilu przez dwie jednoczesne instancje") is enforced by the
/// on-disk lock file created with `O_CREATE|O_EXCL` semantics — see
/// [`ProfileRepository::acquire_lock`].
pub struct FileProfileStore {
    root: PathBuf,
    shredder: Arc<dyn Shredder>,
    /// Serializes metadata read-modify-write within this process.
    write_guard: tokio::sync::Mutex<()>,
}

impl std::fmt::Debug for FileProfileStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileProfileStore")
            .field("root", &self.root)
            .finish_non_exhaustive()
    }
}

impl FileProfileStore {
    /// Create a store rooted at `root`, using the default overwrite shredder.
    ///
    /// The root directory is created lazily on first write; construction does no
    /// I/O so it is cheap and infallible.
    #[must_use]
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self::with_shredder(root, Arc::new(OverwriteShredder::new(1)))
    }

    /// Create a store with a custom [`Shredder`] (used to inject a no-overwrite
    /// or platform-specific shredder, and for tests).
    #[must_use]
    pub fn with_shredder(root: impl Into<PathBuf>, shredder: Arc<dyn Shredder>) -> Self {
        Self {
            root: root.into(),
            shredder,
            write_guard: tokio::sync::Mutex::new(()),
        }
    }

    /// The root directory this store manages.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Directory holding a given profile's files.
    fn profile_dir(&self, id: &ProfileId) -> PathBuf {
        self.root.join(id.to_string())
    }

    /// Path to a profile's metadata file.
    fn meta_path(&self, id: &ProfileId) -> PathBuf {
        self.profile_dir(id).join(META_FILE)
    }

    /// Path to a profile's lock file.
    fn lock_path(&self, id: &ProfileId) -> PathBuf {
        self.profile_dir(id).join(LOCK_FILE)
    }

    /// Path to a profile's private data subdirectory.
    fn data_dir(&self, id: &ProfileId) -> PathBuf {
        self.profile_dir(id).join(DATA_DIR)
    }

    /// The isolated writable data directory for `id`. Callers (the daemon) point
    /// the browser VM's writable overlay / encrypted volume here. It is created
    /// with the profile and is distinct per profile.
    #[must_use]
    pub fn profile_data_dir(&self, id: &ProfileId) -> PathBuf {
        self.data_dir(id)
    }

    /// Read a profile's metadata from disk, without recomputing derived fields.
    async fn read_meta(&self, id: &ProfileId) -> Result<Profile> {
        let path = self.meta_path(id);
        let bytes = match tokio::fs::read(&path).await {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(Error::NotFound(format!("profile {id}")));
            }
            Err(e) => return Err(e.into()),
        };
        let profile: Profile = serde_json::from_slice(&bytes)
            .map_err(|e| Error::Config(format!("corrupt profile metadata for {id}: {e}")))?;
        Ok(profile)
    }

    /// Atomically write a profile's metadata: write to a temp file in the same
    /// directory, then rename over the target so a crash never leaves a
    /// half-written metadata file.
    async fn write_meta(&self, profile: &Profile) -> Result<()> {
        let dir = self.profile_dir(&profile.id);
        tokio::fs::create_dir_all(&dir).await?;
        let json = serde_json::to_vec_pretty(profile)?;
        let final_path = self.meta_path(&profile.id);
        // Unique temp name so parallel writers (should not happen, but be safe)
        // do not clobber each other's temp file.
        let tmp_path = dir.join(format!(".{}.tmp", uuid::Uuid::new_v4().simple()));
        tokio::fs::write(&tmp_path, &json).await?;
        // Rename is atomic on the same filesystem on both Unix and Windows.
        match tokio::fs::rename(&tmp_path, &final_path).await {
            Ok(()) => Ok(()),
            Err(e) => {
                // Best-effort cleanup of the temp file; ignore its error.
                let _ = tokio::fs::remove_file(&tmp_path).await;
                Err(e.into())
            }
        }
    }

    /// Whether the lock file currently exists for `id`.
    async fn is_locked(&self, id: &ProfileId) -> Result<bool> {
        match tokio::fs::metadata(self.lock_path(id)).await {
            Ok(_) => Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e.into()),
        }
    }

    /// Recursively sum the byte size of every regular file under `dir`. Returns
    /// zero if the directory does not exist.
    async fn dir_size(dir: &Path) -> Result<u64> {
        let mut total: u64 = 0;
        let mut stack = vec![dir.to_path_buf()];
        while let Some(current) = stack.pop() {
            let mut rd = match tokio::fs::read_dir(&current).await {
                Ok(rd) => rd,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => return Err(e.into()),
            };
            while let Some(entry) = rd.next_entry().await? {
                let ft = entry.file_type().await?;
                if ft.is_dir() {
                    stack.push(entry.path());
                } else if ft.is_file() {
                    // symlink_metadata avoids following links out of the tree.
                    match tokio::fs::symlink_metadata(entry.path()).await {
                        Ok(m) => total = total.saturating_add(m.len()),
                        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                        Err(e) => return Err(e.into()),
                    }
                }
            }
        }
        Ok(total)
    }

    /// Load a profile and refresh its derived fields (`storage`, `locked`) from
    /// the current on-disk state.
    async fn load_refreshed(&self, id: &ProfileId) -> Result<Profile> {
        let mut profile = self.read_meta(id).await?;
        profile.storage = StorageUsage {
            bytes: Self::dir_size(&self.profile_dir(id)).await?,
        };
        profile.locked = self.is_locked(id).await?;
        Ok(profile)
    }

    /// Apply a patch to a spec, then validate the result.
    fn apply_patch(spec: &mut ProfileSpec, patch: ProfilePatch) -> Result<()> {
        if let Some(name) = patch.name {
            spec.name = name;
        }
        if let Some(network) = patch.network {
            spec.network = network;
        }
        if let Some(protection) = patch.protection {
            spec.protection = protection;
        }
        if let Some(permissions) = patch.permissions {
            spec.permissions = permissions;
        }
        spec.validate()
    }

    /// Generate a fresh random lock token (32 hex chars of CSPRNG output).
    fn new_token() -> String {
        let mut bytes = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
}

#[async_trait]
impl ProfileRepository for FileProfileStore {
    async fn create(&self, spec: ProfileSpec) -> Result<Profile> {
        spec.validate()?;
        let _guard = self.write_guard.lock().await;

        let id = ProfileId::new();
        let dir = self.profile_dir(&id);
        // A freshly generated UUID collision is effectively impossible, but guard
        // anyway: refuse to reuse an existing directory.
        if tokio::fs::metadata(&dir).await.is_ok() {
            return Err(Error::Internal(format!(
                "profile dir already exists for {id}"
            )));
        }

        // Create the isolated per-profile data directory up front so callers can
        // immediately target it, and so isolation holds from creation time.
        tokio::fs::create_dir_all(self.data_dir(&id)).await?;

        let profile = Profile {
            id,
            spec,
            created_at: Utc::now(),
            last_launched: None,
            storage: StorageUsage::default(),
            locked: false,
        };
        self.write_meta(&profile).await?;

        // Return with refreshed derived fields (storage of the empty dir, etc.).
        self.load_refreshed(&id).await
    }

    async fn get(&self, id: &ProfileId) -> Result<Profile> {
        self.load_refreshed(id).await
    }

    async fn list(&self) -> Result<Vec<Profile>> {
        let mut out = Vec::new();
        let mut rd = match tokio::fs::read_dir(&self.root).await {
            Ok(rd) => rd,
            // No root yet => no profiles.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
            Err(e) => return Err(e.into()),
        };
        while let Some(entry) = rd.next_entry().await? {
            if !entry.file_type().await?.is_dir() {
                continue;
            }
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            // Directory name must parse as a ProfileId; skip anything else.
            let Ok(id) = name.parse::<ProfileId>() else {
                continue;
            };
            // Skip directories with no (or corrupt) metadata rather than failing
            // the whole listing.
            match self.load_refreshed(&id).await {
                Ok(p) => out.push(p),
                Err(Error::NotFound(_)) => continue,
                Err(e) => return Err(e),
            }
        }
        // Stable ordering: newest first, then by id for determinism.
        out.sort_by(|a, b| {
            b.created_at
                .cmp(&a.created_at)
                .then_with(|| a.id.to_string().cmp(&b.id.to_string()))
        });
        Ok(out)
    }

    async fn update(&self, id: &ProfileId, patch: ProfilePatch) -> Result<Profile> {
        let _guard = self.write_guard.lock().await;
        let mut profile = self.read_meta(id).await?;
        if !patch.is_empty() {
            Self::apply_patch(&mut profile.spec, patch)?;
            self.write_meta(&profile).await?;
        }
        self.load_refreshed(id).await
    }

    async fn delete(&self, id: &ProfileId) -> Result<()> {
        let _guard = self.write_guard.lock().await;
        let dir = self.profile_dir(id);
        // Fail-closed on a missing profile: report NotFound rather than silently
        // succeeding, so callers cannot mistake a typo for a successful wipe.
        if tokio::fs::metadata(&dir).await.is_err() {
            return Err(Error::NotFound(format!("profile {id}")));
        }
        // Shred and remove the whole profile directory (metadata, lock, and the
        // encrypted data volume). Ephemeral and persistent alike leave nothing
        // recoverable (spec §8).
        self.shredder.shred_dir(&dir).await?;
        Ok(())
    }

    async fn acquire_lock(&self, id: &ProfileId) -> Result<ProfileLease> {
        // The profile must exist to be locked.
        if tokio::fs::metadata(self.profile_dir(id)).await.is_err() {
            return Err(Error::NotFound(format!("profile {id}")));
        }
        let token = Self::new_token();
        let path = self.lock_path(id);
        // O_CREATE|O_EXCL: create_new fails if the file already exists, giving us
        // an atomic test-and-set for the single-writer lock (spec §8).
        match tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .await
        {
            Ok(mut file) => {
                use tokio::io::AsyncWriteExt;
                file.write_all(token.as_bytes()).await?;
                file.flush().await?;
                Ok(ProfileLease {
                    profile: *id,
                    token,
                })
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                Err(Error::Busy(format!("profile {id} is already locked")))
            }
            Err(e) => Err(e.into()),
        }
    }

    async fn release_lock(&self, lease: &ProfileLease) -> Result<()> {
        let path = self.lock_path(&lease.profile);
        let held = match tokio::fs::read(&path).await {
            Ok(bytes) => bytes,
            // No lock file: nothing to release. Report a precondition rather than
            // erroring hard, but do not remove anything.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(Error::Precondition(format!(
                    "profile {} is not locked",
                    lease.profile
                )));
            }
            Err(e) => return Err(e.into()),
        };
        // Only the holder of the matching token may release the lock. A mismatch
        // means someone else owns it — refuse (do NOT steal the lock).
        if held != lease.token.as_bytes() {
            return Err(Error::Precondition(format!(
                "lock token mismatch for profile {}",
                lease.profile
            )));
        }
        tokio::fs::remove_file(&path).await?;
        Ok(())
    }

    async fn touch_launch(&self, id: &ProfileId, at: DateTime<Utc>) -> Result<()> {
        let _guard = self.write_guard.lock().await;
        let mut profile = self.read_meta(id).await?;
        profile.last_launched = Some(at);
        self.write_meta(&profile).await?;
        Ok(())
    }
}
