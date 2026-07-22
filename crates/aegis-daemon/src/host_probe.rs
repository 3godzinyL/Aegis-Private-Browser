//! The reduced, fail-closed network preflight for the host-browser mode.
//!
//! In the full-VM model the orchestrator runs a rich connectivity checklist
//! inside the gateway/browser VMs. The reduced [`IsolationLevel::HostProcess`]
//! mode has no gateway VM: the browser runs on the host and is routed through a
//! host-side proxy (Tor's SOCKS port or a user proxy). The *only* containment
//! guarantee we can offer there is that the proxy is actually listening before
//! we launch — if it is not, launching would leak the connection onto the real
//! OS's default route. So this preflight fails closed on an unreachable proxy.
//!
//! [`IsolationLevel::HostProcess`]: aegis_core::config::IsolationLevel::HostProcess
//!
//! The probe is expressed as the [`HostNetworkProbe`] trait so the orchestrator
//! is testable without a live proxy: the production [`TcpHostProbe`] does a real
//! TCP connect with a timeout, and tests inject a mock.

use aegis_core::Result;
use async_trait::async_trait;
use std::time::Duration;

/// A reduced, fail-closed reachability check for the host-browser proxy.
///
/// The single method confirms a TCP listener is accepting connections at
/// `host:port`. It returns `Ok(true)` when the proxy is reachable, `Ok(false)`
/// when it is definitively not, and `Err` only for a probe fault that prevents a
/// determination (which the caller also treats as fail-closed).
#[async_trait]
pub trait HostNetworkProbe: Send + Sync {
    /// Whether a TCP listener is accepting connections at `host:port` within the
    /// probe's timeout.
    ///
    /// # Errors
    /// Returns an error only if the probe itself could not run (e.g. the address
    /// could not be resolved); an unreachable-but-well-formed target is
    /// `Ok(false)`, not an error.
    async fn proxy_reachable(&self, host: &str, port: u16) -> Result<bool>;
}

/// The production probe: a real TCP connect with a bounded timeout.
#[derive(Debug, Clone, Copy)]
pub struct TcpHostProbe {
    /// How long to wait for the TCP handshake before declaring the proxy
    /// unreachable.
    timeout: Duration,
}

impl TcpHostProbe {
    /// A probe with the given connect timeout.
    #[must_use]
    pub const fn new(timeout: Duration) -> Self {
        Self { timeout }
    }
}

impl Default for TcpHostProbe {
    fn default() -> Self {
        // A short, fail-fast timeout: a local proxy answers in milliseconds; a
        // couple of seconds is generous while keeping a missing proxy snappy.
        Self::new(Duration::from_secs(2))
    }
}

#[async_trait]
impl HostNetworkProbe for TcpHostProbe {
    async fn proxy_reachable(&self, host: &str, port: u16) -> Result<bool> {
        // A well-formed but unreachable target must be Ok(false), not Err, so the
        // caller can report a clean "proxy not listening" fail-closed rather than
        // a probe fault. A timeout or refused connection both mean "not there".
        let target = format!("{host}:{port}");
        match tokio::time::timeout(self.timeout, tokio::net::TcpStream::connect(&target)).await {
            Ok(Ok(_stream)) => Ok(true),
            // Connection refused / host unreachable / etc.: definitively not there.
            Ok(Err(_)) => Ok(false),
            // Timed out waiting for the handshake: treat as not listening.
            Err(_elapsed) => Ok(false),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn unreachable_target_is_ok_false_not_error() {
        // Port 1 on loopback has no listener; a real connect fails fast and must
        // be reported as Ok(false) (fail-closed), never as an Err.
        let probe = TcpHostProbe::new(Duration::from_millis(300));
        let reachable = probe.proxy_reachable("127.0.0.1", 1).await.unwrap();
        assert!(!reachable, "no listener on 127.0.0.1:1");
    }

    #[tokio::test]
    async fn reachable_target_is_ok_true() {
        // Bind an ephemeral loopback listener and confirm the probe sees it.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let probe = TcpHostProbe::default();
        let reachable = probe
            .proxy_reachable(&addr.ip().to_string(), addr.port())
            .await
            .unwrap();
        assert!(reachable, "listener at {addr} should be reachable");
    }
}
