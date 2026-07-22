//! # profile-store
//!
//! The concrete [`aegis_core::traits::ProfileRepository`] for **Aegis Private
//! Browser**: a file-backed store that persists each profile as a directory of
//! plain-JSON metadata under a common root (spec §8, §11).
//!
//! ## What is (and is not) stored in the clear
//!
//! A profile holds **no plaintext secrets**. Network credentials are only ever
//! [`aegis_core::network::CredentialRef`] handles into `secure-storage`; the
//! remaining metadata (name, ephemeral/persistent kind, network mode, protection
//! level, permission table) is not sensitive. It is therefore written as plain
//! JSON. The sensitive per-profile data — browsing state and, for persistent
//! profiles, the password-protected encrypted volume — lives in the profile's
//! own `data/` subdirectory, which this crate creates and shreds but never reads
//! (spec §8, §16). Nothing here logs keys or credentials.
//!
//! ## Single-writer locking (spec §8)
//!
//! No two sessions may share a profile. [`FileProfileStore`] enforces this with
//! an on-disk lock file created using `O_CREATE|O_EXCL` semantics: the first
//! [`acquire_lock`](aegis_core::traits::ProfileRepository::acquire_lock) wins and
//! receives a [`aegis_core::traits::ProfileLease`] carrying a random token; a
//! second concurrent acquire fails with [`aegis_core::Error::Busy`]. The lock is
//! removed by [`release_lock`](aegis_core::traits::ProfileRepository::release_lock)
//! only when the presented token matches.
//!
//! ## Portability
//!
//! The implementation uses only `tokio::fs` and standard, cross-platform
//! filesystem operations, so it compiles and runs identically on Windows, macOS,
//! and Linux. Secure deletion is abstracted behind the [`Shredder`] trait so a
//! platform-specific strategy can be injected without changing callers.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod shred;
mod store;

pub use shred::{OverwriteShredder, RemoveOnlyShredder, Shredder};
pub use store::FileProfileStore;
