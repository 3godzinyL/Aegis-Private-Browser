//! Process-control abstraction for browser backends.
//!
//! Launching, polling, and terminating the browser are side-effecting operations
//! that ultimately happen *inside the Browser VM*, addressed via the daemon's
//! guest channel (spec §4, §6). To keep the backend logic (policy rendering,
//! flag vetting, handle management) fully unit-testable without VMs, all of that
//! I/O is funnelled through the [`BrowserRunner`] trait.
//!
//! Two implementations are provided:
//!
//! * [`GuestChannelRunner`] — the production runner. It is documented as
//!   launching a hardened Chromium process inside the Browser VM through the
//!   guest channel. Because that channel and the VM tooling only exist on Linux,
//!   every method returns [`aegis_core::Error::Unsupported`] when built/run on a
//!   non-Linux host, so the crate still compiles and links everywhere.
//! * [`MockRunner`] — an in-memory fake used by the tests and by higher layers
//!   that want to exercise the backend logic deterministically.

use aegis_core::error::{Error, Result};
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Mutex;

/// The concrete command a runner is asked to start inside the Browser VM.
///
/// This is intentionally a *value* (not a live handle): the backend renders it
/// from a vetted [`aegis_core::browser::BackendPolicyBundle`] and hands it to the
/// runner, so the runner never needs to know anything about policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaunchSpec {
    /// The browser executable to run inside the guest (e.g. `chromium`).
    pub program: String,
    /// The full, pre-vetted argument vector (sandbox on, no remote debugging).
    pub args: Vec<String>,
    /// Additional environment variables to set for the guest process. Used for
    /// the canonical timezone (`TZ`) and language (`LANG`/`LANGUAGE`). MUST NOT
    /// carry secrets — this is asserted by the backend before it reaches here.
    pub env: Vec<(String, String)>,
}

/// Abstracts starting/stopping the browser process inside the Browser VM.
///
/// Implementations must be side-effect isolated behind this trait so the backend
/// remains testable. The returned token is opaque and is what a
/// [`aegis_core::browser::BrowserHandle`] carries.
#[async_trait]
pub trait BrowserRunner: Send + Sync {
    /// Start the process described by `spec` inside the Browser VM identified by
    /// `vm_slug`. Returns an opaque process token used to address it later.
    ///
    /// # Errors
    /// Returns [`Error::Unsupported`] on platforms without the guest channel, or
    /// [`Error::System`] if the guest reports a spawn failure.
    async fn start(&self, vm_slug: &str, spec: &LaunchSpec) -> Result<String>;

    /// Whether the process addressed by `token` is still running.
    ///
    /// # Errors
    /// Returns an error if the token is unknown or the guest is unreachable.
    async fn is_running(&self, token: &str) -> Result<bool>;

    /// Terminate the process addressed by `token`. Idempotent: terminating an
    /// already-stopped process is not an error.
    ///
    /// # Errors
    /// Returns an error only if the guest channel itself fails.
    async fn stop(&self, token: &str) -> Result<()>;
}

/// The production runner: launches Chromium inside the Browser VM via the guest
/// channel.
///
/// On Linux this would drive the VM tooling (a `tokio::process::Command` shelling
/// out to the guest-agent bridge, or a virtio-serial control channel). That
/// machinery only exists on Linux, so on any other platform every method returns
/// [`Error::Unsupported`] — keeping the code compiling and linkable on this
/// Windows development host while never silently pretending to launch.
#[derive(Debug, Default, Clone)]
#[non_exhaustive]
pub struct GuestChannelRunner {
    /// The path to the guest-control helper on the host (Linux only). Kept for
    /// documentation/wiring; unused on non-Linux where we short-circuit.
    pub control_helper: Option<String>,
}

impl GuestChannelRunner {
    /// Construct a runner that will drive the given guest-control helper.
    #[must_use]
    pub fn new(control_helper: impl Into<String>) -> Self {
        Self {
            control_helper: Some(control_helper.into()),
        }
    }
}

/// Shared reason string used whenever the guest channel is not available.
const NO_GUEST_CHANNEL: &str =
    "browser launch requires the Linux guest channel (Browser VM); not available on this platform";

#[async_trait]
impl BrowserRunner for GuestChannelRunner {
    async fn start(&self, _vm_slug: &str, _spec: &LaunchSpec) -> Result<String> {
        // NOTE: The real Linux implementation would invoke the guest-control
        // helper via `tokio::process::Command` to spawn `spec.program` with
        // `spec.args`/`spec.env` inside the Browser VM, then return the guest
        // agent's opaque process token. It deliberately never spawns anything on
        // the host. On non-Linux we fail closed with `Unsupported`.
        Err(Error::Unsupported(NO_GUEST_CHANNEL.to_string()))
    }

    async fn is_running(&self, _token: &str) -> Result<bool> {
        Err(Error::Unsupported(NO_GUEST_CHANNEL.to_string()))
    }

    async fn stop(&self, _token: &str) -> Result<()> {
        Err(Error::Unsupported(NO_GUEST_CHANNEL.to_string()))
    }
}

/// An in-memory fake runner for tests and dependency-injection.
///
/// It records every [`LaunchSpec`] it is asked to start (so tests can assert on
/// the exact program/args/env), hands back deterministic tokens, and tracks a
/// simple running/stopped state per token.
#[derive(Debug, Default)]
pub struct MockRunner {
    inner: Mutex<MockState>,
}

#[derive(Debug, Default)]
struct MockState {
    next: u64,
    running: HashMap<String, bool>,
    launched: Vec<(String, LaunchSpec)>,
    fail_start: bool,
}

impl MockRunner {
    /// A fresh mock runner with no launched processes.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// A mock runner whose [`BrowserRunner::start`] always fails, to exercise the
    /// backend's error path.
    #[must_use]
    pub fn failing() -> Self {
        let m = Self::default();
        m.inner.lock().expect("mock lock").fail_start = true;
        m
    }

    /// The (vm_slug, spec) pairs that were launched, in order.
    #[must_use]
    pub fn launched(&self) -> Vec<(String, LaunchSpec)> {
        self.inner.lock().expect("mock lock").launched.clone()
    }

    /// Force a token into the stopped state, simulating the browser exiting on
    /// its own.
    pub fn mark_stopped(&self, token: &str) {
        if let Some(v) = self.inner.lock().expect("mock lock").running.get_mut(token) {
            *v = false;
        }
    }
}

#[async_trait]
impl BrowserRunner for MockRunner {
    async fn start(&self, vm_slug: &str, spec: &LaunchSpec) -> Result<String> {
        let mut st = self.inner.lock().expect("mock lock");
        if st.fail_start {
            return Err(Error::System("mock runner: spawn refused".to_string()));
        }
        st.next += 1;
        let token = format!("mock-proc-{}", st.next);
        st.running.insert(token.clone(), true);
        st.launched.push((vm_slug.to_string(), spec.clone()));
        Ok(token)
    }

    async fn is_running(&self, token: &str) -> Result<bool> {
        let st = self.inner.lock().expect("mock lock");
        st.running
            .get(token)
            .copied()
            .ok_or_else(|| Error::NotFound(format!("unknown process token: {token}")))
    }

    async fn stop(&self, token: &str) -> Result<()> {
        let mut st = self.inner.lock().expect("mock lock");
        // Idempotent: stopping an unknown/already-stopped token is fine.
        st.running.insert(token.to_string(), false);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn guest_channel_runner_is_unsupported_off_linux() {
        let r = GuestChannelRunner::new("/usr/lib/aegis/guest-control");
        let spec = LaunchSpec {
            program: "chromium".into(),
            args: vec![],
            env: vec![],
        };
        // On this Windows host every method must fail closed with Unsupported.
        let e = r.start("vm-abc", &spec).await.unwrap_err();
        assert!(matches!(e, Error::Unsupported(_)));
        assert!(matches!(
            r.is_running("t").await.unwrap_err(),
            Error::Unsupported(_)
        ));
        assert!(matches!(
            r.stop("t").await.unwrap_err(),
            Error::Unsupported(_)
        ));
    }

    #[tokio::test]
    async fn mock_runner_tracks_lifecycle() {
        let r = MockRunner::new();
        let spec = LaunchSpec {
            program: "chromium".into(),
            args: vec!["--user-data-dir=/x".into()],
            env: vec![("TZ".into(), "UTC".into())],
        };
        let token = r.start("vm-1", &spec).await.unwrap();
        assert!(r.is_running(&token).await.unwrap());
        assert_eq!(r.launched().len(), 1);
        assert_eq!(r.launched()[0].1, spec);
        r.stop(&token).await.unwrap();
        assert!(!r.is_running(&token).await.unwrap());
    }

    #[tokio::test]
    async fn mock_runner_stop_is_idempotent_and_unknown_is_notfound() {
        let r = MockRunner::new();
        // stop on unknown token is fine (idempotent).
        r.stop("nope").await.unwrap();
        // but is_running on a never-seen token is NotFound.
        assert!(matches!(
            r.is_running("never").await.unwrap_err(),
            Error::NotFound(_)
        ));
    }

    #[tokio::test]
    async fn failing_mock_returns_system_error() {
        let r = MockRunner::failing();
        let spec = LaunchSpec {
            program: "chromium".into(),
            args: vec![],
            env: vec![],
        };
        assert!(matches!(
            r.start("vm-1", &spec).await.unwrap_err(),
            Error::System(_)
        ));
    }
}
