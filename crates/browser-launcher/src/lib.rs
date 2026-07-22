//! # browser-launcher
//!
//! [`aegis_core::traits::BrowserBackend`] implementations for **Aegis Private
//! Browser** (spec §6, §7, §16).
//!
//! * [`ChromiumBackend`] — the MVP. A hardened Chromium backend whose
//!   `render_policy` is a **pure** function producing the
//!   exact managed-policy JSON and command line, so every containment/privacy
//!   guarantee is asserted by a unit test rather than trusted by inspection:
//!   the sandbox is kept, Site Isolation is kept, all traffic is forced through
//!   the gateway proxy, WebRTC non-proxied UDP is blocked, sync/telemetry are
//!   disabled, and remote debugging is forbidden in production builds.
//! * [`FirefoxBackend`] — a planned Firefox/Mullvad backend (spec §6 Variant A).
//!   It advertises letterboxing, can render arkenfox-style preferences, and
//!   currently fails closed with [`aegis_core::Error::Unsupported`] on launch.
//!
//! The actual process control (launching Chromium inside the Browser VM via the
//! daemon's guest channel) is abstracted behind the [`BrowserRunner`] trait so
//! the backend logic is fully testable without VMs. The production
//! [`GuestChannelRunner`] returns [`aegis_core::Error::Unsupported`] on non-Linux
//! hosts, keeping the crate compiling and linkable everywhere.
//!
//! For hosts without a hypervisor (Windows/macOS), [`HostBrowserRunner`] launches
//! a real Chromium-family browser directly on the host OS — the reduced-protection
//! [`aegis_core::config::IsolationLevel::HostProcess`] path. It only execs the
//! already-hardened command line the backend renders and never adds a weakening
//! flag.
//!
//! ## Fail-closed
//!
//! Every fallible boundary follows the project's fail-closed rule
//! ([`aegis_core::FailureClass`]): a malformed fingerprint policy, a forbidden
//! command-line flag, or a caller-tampered bundle is rejected before anything is
//! launched. Secrets (e.g. proxy credentials) are never rendered into the
//! command line or logged.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod chromium;
pub mod firefox;
pub mod host_runner;
pub mod runner;

pub use chromium::{render_chromium_policy, ChromiumBackend, MANAGED_POLICY_FILE};
pub use firefox::{FirefoxBackend, PREFS_FILE};
pub use host_runner::{
    resolve_browser_binary, search_default_browser, HostBrowserRunner, ResolverEnv, SystemEnv,
    BROWSER_BIN_ENV,
};
pub use runner::{BrowserRunner, GuestChannelRunner, LaunchSpec, MockRunner};

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_core::browser::BrowserBackendId;
    use aegis_core::traits::BrowserBackend;

    #[test]
    fn backends_report_expected_ids() {
        let chromium = ChromiumBackend::new(MockRunner::new(), "chromium", "vm-1");
        assert_eq!(chromium.id(), BrowserBackendId::Chromium);
        assert!(chromium.capabilities().site_isolation);
        assert!(chromium.capabilities().renderer_sandbox);

        let firefox = FirefoxBackend::new();
        assert_eq!(firefox.id(), BrowserBackendId::Firefox);
        assert!(firefox.capabilities().letterboxing);
    }

    // Compile-time proof the backends are usable as trait objects (as the daemon
    // uses them).
    #[test]
    fn backends_are_object_safe() {
        let _boxed: Vec<Box<dyn BrowserBackend>> = vec![
            Box::new(ChromiumBackend::new(MockRunner::new(), "chromium", "vm-1")),
            Box::new(FirefoxBackend::new()),
        ];
    }
}
