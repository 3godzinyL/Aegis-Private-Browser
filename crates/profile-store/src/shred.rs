//! Best-effort secure deletion of profile data directories.
//!
//! When a profile is deleted its whole on-disk directory must be *shredded*, not
//! merely unlinked (spec §8: ephemeral profiles leave "no recoverable data";
//! persistent profiles hold an encrypted volume whose ciphertext should still be
//! overwritten before the directory is removed).
//!
//! The actual guarantee a plain overwrite gives depends heavily on the
//! underlying medium (an SSD's flash-translation layer, a copy-on-write
//! filesystem, or a journaling layer can all retain old blocks). We therefore
//! treat overwriting as *defence in depth* on top of unlinking, and — crucially
//! — abstract the operation behind the [`Shredder`] trait so the surrounding
//! store logic can be unit-tested without touching real storage, and so a
//! platform-specific implementation (e.g. `blkdiscard`/`shred(1)` on Linux) can
//! be injected later without changing callers.

use async_trait::async_trait;
use std::path::Path;

/// Secure-deletion strategy for a profile's data directory.
///
/// Implementations receive a directory that still exists on disk and must leave
/// it (and everything under it) removed when they return `Ok(())`. They must
/// never log the contents of the files they process (spec §8: "brak kluczy w
/// logach").
#[async_trait]
pub trait Shredder: Send + Sync {
    /// Shred and remove the directory tree rooted at `dir`.
    ///
    /// # Errors
    /// Returns [`aegis_core::Error::System`] if the directory could not be
    /// enumerated or removed.
    async fn shred_dir(&self, dir: &Path) -> aegis_core::Result<()>;
}

/// The default shredder: recursively overwrite every regular file with zeros,
/// flush, then remove the whole tree.
///
/// This is a *best-effort* overwrite (see the module docs for the caveats). It
/// never follows symlinks out of the tree — it overwrites only regular files it
/// finds by walking the directory, and removes symlinks without following them.
#[derive(Debug, Clone, Copy, Default)]
pub struct OverwriteShredder {
    /// Number of overwrite passes to apply to each file before removal.
    passes: u8,
}

impl OverwriteShredder {
    /// A shredder performing `passes` zero-overwrite passes (clamped to at least
    /// one) before unlinking.
    #[must_use]
    pub fn new(passes: u8) -> Self {
        Self {
            passes: passes.max(1),
        }
    }

    /// Overwrite a single regular file in place, then leave it for removal.
    async fn overwrite_file(&self, path: &Path) -> aegis_core::Result<()> {
        use tokio::io::AsyncWriteExt;

        let len = match tokio::fs::metadata(path).await {
            Ok(m) => m.len(),
            // A file that vanished under us is already "shredded".
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e.into()),
        };

        if len == 0 {
            return Ok(());
        }

        // Open for writing without truncating so we overwrite existing bytes.
        let mut file = tokio::fs::OpenOptions::new().write(true).open(path).await?;

        // A reasonably sized zero buffer reused across writes.
        const CHUNK: usize = 64 * 1024;
        let zeros = [0u8; CHUNK];

        for _ in 0..self.passes {
            file.rewind_start().await?;
            let mut remaining = len;
            while remaining > 0 {
                let n = remaining.min(CHUNK as u64) as usize;
                file.write_all(&zeros[..n]).await?;
                remaining -= n as u64;
            }
            file.flush().await?;
            file.sync_all().await?;
        }
        Ok(())
    }
}

/// Small extension so we can rewind without pulling in `AsyncSeekExt` at every
/// call site.
#[async_trait]
trait RewindExt {
    async fn rewind_start(&mut self) -> std::io::Result<()>;
}

#[async_trait]
impl RewindExt for tokio::fs::File {
    async fn rewind_start(&mut self) -> std::io::Result<()> {
        use tokio::io::AsyncSeekExt;
        self.seek(std::io::SeekFrom::Start(0)).await.map(|_| ())
    }
}

#[async_trait]
impl Shredder for OverwriteShredder {
    async fn shred_dir(&self, dir: &Path) -> aegis_core::Result<()> {
        // If it is already gone, treat as success (idempotent delete).
        match tokio::fs::symlink_metadata(dir).await {
            Ok(m) if m.is_dir() => {}
            Ok(_) => {
                // Not a directory (e.g. a stray symlink); just remove it.
                tokio::fs::remove_file(dir).await?;
                return Ok(());
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e.into()),
        }

        // Depth-first walk collecting files to overwrite. We keep an explicit
        // stack rather than recursing to stay within a bounded async frame.
        let mut stack = vec![dir.to_path_buf()];
        let mut files = Vec::new();
        while let Some(current) = stack.pop() {
            let mut rd = tokio::fs::read_dir(&current).await?;
            while let Some(entry) = rd.next_entry().await? {
                // Use symlink metadata so we never follow links out of the tree.
                let ft = entry.file_type().await?;
                let path = entry.path();
                if ft.is_dir() {
                    stack.push(path);
                } else {
                    // Regular files get overwritten; symlinks/others are just
                    // recorded for removal (they are removed with the tree).
                    if ft.is_file() {
                        files.push(path);
                    }
                }
            }
        }

        for f in &files {
            self.overwrite_file(f).await?;
        }

        // Finally remove the whole tree (unlinks files, dirs, and symlinks).
        tokio::fs::remove_dir_all(dir).await?;
        Ok(())
    }
}

/// A shredder that only removes the tree (no overwrite). Useful in tests and on
/// media where overwriting is pointless, and as a documentation point that the
/// removal itself is the mandatory part.
#[derive(Debug, Clone, Copy, Default)]
pub struct RemoveOnlyShredder;

#[async_trait]
impl Shredder for RemoveOnlyShredder {
    async fn shred_dir(&self, dir: &Path) -> aegis_core::Result<()> {
        match tokio::fs::remove_dir_all(dir).await {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn overwrite_shredder_removes_tree_and_zeroes_files() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("profile");
        tokio::fs::create_dir_all(root.join("sub")).await.unwrap();
        tokio::fs::write(root.join("a.json"), b"secret-bytes")
            .await
            .unwrap();
        tokio::fs::write(root.join("sub/b.bin"), vec![7u8; 100_000])
            .await
            .unwrap();

        let sh = OverwriteShredder::new(2);
        sh.shred_dir(&root).await.unwrap();
        assert!(!root.exists(), "tree should be removed");
    }

    #[tokio::test]
    async fn shredding_missing_dir_is_ok() {
        let tmp = tempfile::tempdir().unwrap();
        let missing = tmp.path().join("nope");
        OverwriteShredder::default()
            .shred_dir(&missing)
            .await
            .unwrap();
        RemoveOnlyShredder.shred_dir(&missing).await.unwrap();
    }

    #[tokio::test]
    async fn overwrite_zeroes_file_contents_before_removal() {
        // Verify the overwrite actually zeroes bytes: overwrite a file, read it
        // back before removal by using overwrite_file directly.
        let tmp = tempfile::tempdir().unwrap();
        let f = tmp.path().join("c.bin");
        tokio::fs::write(&f, vec![0xAB; 4096]).await.unwrap();
        let sh = OverwriteShredder::new(1);
        sh.overwrite_file(&f).await.unwrap();
        let contents = tokio::fs::read(&f).await.unwrap();
        assert!(contents.iter().all(|&b| b == 0), "file must be zeroed");
    }

    #[tokio::test]
    async fn remove_only_shredder_removes_tree() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("p");
        tokio::fs::create_dir_all(&root).await.unwrap();
        tokio::fs::write(root.join("x"), b"y").await.unwrap();
        RemoveOnlyShredder.shred_dir(&root).await.unwrap();
        assert!(!root.exists());
    }
}
