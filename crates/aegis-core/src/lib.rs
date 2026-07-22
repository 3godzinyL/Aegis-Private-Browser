//! # aegis-core
//!
//! The shared domain model, policy types, and trait contracts for **Aegis
//! Private Browser** — a manager for disposable/persistent, encrypted browser
//! environments built on a Whonix-style split (Gateway VM + Browser VM).
//!
//! This crate contains **no I/O and no platform code**. It is the vocabulary the
//! rest of the workspace speaks:
//!
//! * [`error`] — the fail-closed error taxonomy ([`FailureClass`]).
//! * [`ids`] — strongly-typed, host-independent identifiers.
//! * [`config`] — application config, storage paths, image references.
//! * [`network`] — tunnel modes (Tor/VPN/Proxy), DNS and IPv6 policy.
//! * [`gateway`] — firewall policy, tunnel/kill-switch state, gateway health.
//! * [`vm`] — VM provisioning + the machine-checkable [`vm::IsolationPolicy`].
//! * [`fingerprint`] — normalization policy (Balanced/Strict), *not* spoofing.
//! * [`permissions`] — the per-profile/per-origin permission table.
//! * [`profile`] — ephemeral/persistent profiles.
//! * [`session`] — the fail-closed session state machine.
//! * [`preflight`] — the six-check connectivity gate and protection status.
//! * [`secure`] — secret wrappers and sealed-blob types.
//! * [`update`] — signed manifests, versions, downgrade protection.
//! * [`browser`] — [`traits::BrowserBackend`] request/response types.
//! * [`events`] — structured, secret-free audit records.
//! * [`traits`] — the contracts every capability is expressed through.
//!
//! ## Design invariants
//!
//! 1. **Fail-closed:** any error whose [`Error::class`] requires it must sever
//!    connectivity, never fall back to a direct connection.
//! 2. **Unlinkability, not spoofing:** fingerprint values are *normalized to a
//!    shared baseline* and kept *stable within a session*.
//! 3. **Dependency inversion:** capabilities are traits; implementations are
//!    injected, so the workspace forms a clean DAG and is fully unit-testable.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod browser;
pub mod config;
pub mod error;
pub mod events;
pub mod fingerprint;
pub mod gateway;
pub mod health;
pub mod ids;
pub mod network;
pub mod permissions;
pub mod preflight;
pub mod preview;
pub mod profile;
pub mod secure;
pub mod session;
pub mod traits;
pub mod update;
pub mod vm;

// Convenience re-exports of the most-used items.
pub use error::{Error, FailureClass, Result};
pub use ids::{InstanceId, ProfileId, SessionId, VmId};

/// The crate version, for surfacing in diagnostics and audit records.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// A single place to assert the cross-cutting invariants a build must uphold.
///
/// This is used by higher layers (and the integration tests) as a cheap
/// self-check that the compiled-in defaults have not drifted away from the
/// security model — e.g. that the default permission table still blocks USB, or
/// that the strict fingerprint policy still disables WebGPU.
#[must_use]
pub fn self_check() -> Vec<&'static str> {
    let mut problems = Vec::new();

    // Isolation policy default must be fully hardened.
    if !vm::IsolationPolicy::default().is_hardened() {
        problems.push("default IsolationPolicy is not fully hardened");
    }
    // Both protection levels must produce valid fingerprint policies.
    if fingerprint::FingerprintPolicy::balanced()
        .validate()
        .is_some()
    {
        problems.push("balanced fingerprint policy is invalid");
    }
    if fingerprint::FingerprintPolicy::strict()
        .validate()
        .is_some()
    {
        problems.push("strict fingerprint policy is invalid");
    }
    // The secure permission default must block hard-blocked device classes.
    let perms = permissions::PermissionPolicy::secure_default();
    for f in permissions::Feature::all() {
        if f.is_hard_blocked()
            && perms.effective("https://example", *f) != permissions::PermissionState::Block
        {
            problems.push("hard-blocked device class is not blocked by default");
        }
    }
    problems
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn self_check_passes_for_defaults() {
        assert!(
            self_check().is_empty(),
            "self-check found: {:?}",
            self_check()
        );
    }

    #[test]
    fn version_is_nonempty() {
        assert!(!VERSION.is_empty());
    }
}
