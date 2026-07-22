//! The measurement abstraction the auditor uses to observe the live network.
//!
//! Every concrete probe the preflight checklist depends on is funnelled through
//! the [`Probe`] trait so that:
//!
//! * the [`SystemProbe`] can perform the measurement inside the Linux Gateway /
//!   Browser VM (and refuse, fail-closed, everywhere else — including this
//!   Windows build machine); and
//! * tests can inject a [`MockProbe`] and drive every branch of the checklist —
//!   happy path, single failures, and adversarial leak scenarios (spec §15) —
//!   with no VM, no root, and no network.
//!
//! Rules of the road:
//!
//! * Probes never log the real host IP, the observed exit IP, or any tunnel
//!   credential. The network path is kept free of anything that could leak an
//!   identifier into logs (crate-level fail-closed note, spec §11, §16).
//! * A probe returns `Ok(bool)` / `Ok(Option<..>)` for a *measurement that ran*
//!   and `Err(..)` only when the measurement itself could not be performed. The
//!   auditor turns both a `false` measurement and an `Err` into a failing check
//!   (fail-closed) — a probe error is never propagated out of the checklist.

use aegis_core::preflight::IpObservation;
use aegis_core::traits::PreflightContext;
use aegis_core::{Error, Result};

/// Performs the concrete network measurements the preflight checklist needs.
///
/// Implementations must be `Send + Sync` so the auditor can hold one behind a
/// trait object and share it across async tasks.
///
/// Each method answers exactly one question about the live session. The
/// [`PreflightContext`] carries the endpoints and expected policies but no
/// secret material; probes must not log the values they read.
#[async_trait::async_trait]
pub trait Probe: Send + Sync {
    /// Whether the Gateway VM is up and reachable on the management channel
    /// (`ctx.gateway_address`). Fail-closed: unreachable ⇒ `Ok(false)`.
    async fn gateway_reachable(&self, ctx: &PreflightContext) -> Result<bool>;

    /// Whether the outbound tunnel (Tor / VPN / proxy, `ctx.mode_label`) is
    /// fully established.
    async fn tunnel_up(&self, ctx: &PreflightContext) -> Result<bool>;

    /// Whether DNS resolves **only** through the intended route — i.e. no query
    /// escapes the gateway on plain UDP/TCP port 53, and (spec §15) no answer
    /// arrives over IPv6 outside the tunnel. `true` means "verified no leak".
    async fn dns_route_ok(&self, ctx: &PreflightContext) -> Result<bool>;

    /// Observe the session's apparent public IP from *inside* the VM.
    ///
    /// Returns `Ok(None)` when no exit IP could be observed at all (treated as a
    /// failure by the auditor). The returned [`IpObservation`] carries whether
    /// the observation was made through the tunnel and whether it differs from
    /// the host's real IP; the auditor enforces that both hold.
    async fn observe_public_ip(&self, ctx: &PreflightContext) -> Result<Option<IpObservation>>;

    /// Whether IPv6 is contained per `ctx.ipv6` — either dropped at the gateway
    /// (`Block`) or confirmed to route only through the tunnel. `true` means the
    /// IPv6 policy is verified in effect and no v6 leak is possible.
    async fn ipv6_blocked(&self, ctx: &PreflightContext) -> Result<bool>;
}

/// The production probe: performs measurements from inside the Linux VMs.
///
/// On non-Linux hosts (including this Windows build machine) every measurement
/// returns [`Error::Unsupported`]. The live probes rely on Linux-only tooling
/// and kernel interfaces that exist only inside the Gateway / Browser VM, so
/// returning an error keeps the fail-closed contract — we never pretend a leak
/// check passed on a platform where it could not run. The auditor maps that
/// error to a failing check, so a `SystemProbe` off-Linux blocks browsing
/// rather than permitting it.
///
/// The Linux implementation is intentionally left as an integration surface:
/// the daemon injects the guest channel through which these probes actually
/// talk to the VMs. This crate ships the trait, the fail-closed off-Linux
/// behaviour, and the fully-testable checklist logic on top of [`MockProbe`].
#[derive(Debug, Default, Clone)]
pub struct SystemProbe;

impl SystemProbe {
    /// Construct a system probe.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// The single place that produces the off-Linux fail-closed error, so the
    /// message stays consistent and free of any host identifier.
    #[cfg(not(target_os = "linux"))]
    fn unsupported(what: &str) -> Error {
        Error::Unsupported(format!(
            "network probe '{what}' is only available inside the Linux Aegis VMs"
        ))
    }
}

#[async_trait::async_trait]
impl Probe for SystemProbe {
    #[cfg(not(target_os = "linux"))]
    async fn gateway_reachable(&self, _ctx: &PreflightContext) -> Result<bool> {
        Err(Self::unsupported("gateway_reachable"))
    }

    #[cfg(not(target_os = "linux"))]
    async fn tunnel_up(&self, _ctx: &PreflightContext) -> Result<bool> {
        Err(Self::unsupported("tunnel_up"))
    }

    #[cfg(not(target_os = "linux"))]
    async fn dns_route_ok(&self, _ctx: &PreflightContext) -> Result<bool> {
        Err(Self::unsupported("dns_route_ok"))
    }

    #[cfg(not(target_os = "linux"))]
    async fn observe_public_ip(&self, _ctx: &PreflightContext) -> Result<Option<IpObservation>> {
        Err(Self::unsupported("observe_public_ip"))
    }

    #[cfg(not(target_os = "linux"))]
    async fn ipv6_blocked(&self, _ctx: &PreflightContext) -> Result<bool> {
        Err(Self::unsupported("ipv6_blocked"))
    }

    // On Linux the same fail-closed default applies until the daemon wires the
    // guest channel in a later stage: an unimplemented live probe must *fail*
    // the check, never silently pass it. Returning `Unsupported` is fail-closed
    // (the auditor turns it into a `Fail`), so browsing stays blocked rather
    // than being permitted by an unmeasured guarantee.
    #[cfg(target_os = "linux")]
    async fn gateway_reachable(&self, _ctx: &PreflightContext) -> Result<bool> {
        Err(Error::Unsupported(
            "live gateway_reachable probe not yet wired to the guest channel".into(),
        ))
    }

    #[cfg(target_os = "linux")]
    async fn tunnel_up(&self, _ctx: &PreflightContext) -> Result<bool> {
        Err(Error::Unsupported(
            "live tunnel_up probe not yet wired to the guest channel".into(),
        ))
    }

    #[cfg(target_os = "linux")]
    async fn dns_route_ok(&self, _ctx: &PreflightContext) -> Result<bool> {
        Err(Error::Unsupported(
            "live dns_route_ok probe not yet wired to the guest channel".into(),
        ))
    }

    #[cfg(target_os = "linux")]
    async fn observe_public_ip(&self, _ctx: &PreflightContext) -> Result<Option<IpObservation>> {
        Err(Error::Unsupported(
            "live observe_public_ip probe not yet wired to the guest channel".into(),
        ))
    }

    #[cfg(target_os = "linux")]
    async fn ipv6_blocked(&self, _ctx: &PreflightContext) -> Result<bool> {
        Err(Error::Unsupported(
            "live ipv6_blocked probe not yet wired to the guest channel".into(),
        ))
    }
}

/// A fully-configurable in-memory probe for unit tests.
///
/// Each field controls one measurement. A field of type `Result<..>` lets a
/// test model either a measured outcome (`Ok(false)` — a clean "no", such as a
/// verified DNS leak) or a probe that could not run at all (`Err(..)`); the
/// auditor must treat both as a failing check.
///
/// The default is the **all-pass** configuration (a healthy, leak-free session
/// whose observed IP is through the tunnel and differs from the host), so a
/// test only needs to override the one dimension it wants to break.
///
/// Not `Clone`: [`aegis_core::Error`] is not `Clone`, and the fields may hold
/// errors. Each probe call rebuilds an equivalent error instead (see the
/// module's `rebuild_error`).
#[derive(Debug)]
pub struct MockProbe {
    /// Outcome of [`Probe::gateway_reachable`].
    pub gateway_reachable: Result<bool>,
    /// Outcome of [`Probe::tunnel_up`].
    pub tunnel_up: Result<bool>,
    /// Outcome of [`Probe::dns_route_ok`].
    pub dns_route_ok: Result<bool>,
    /// Outcome of [`Probe::observe_public_ip`].
    pub observe_public_ip: Result<Option<IpObservation>>,
    /// Outcome of [`Probe::ipv6_blocked`].
    pub ipv6_blocked: Result<bool>,
}

impl MockProbe {
    /// A probe where every measurement succeeds and no leak is present.
    ///
    /// The observed IP is through the tunnel and differs from the host, so the
    /// `PublicIpObserved` check passes when compared against any host IP.
    #[must_use]
    pub fn all_pass() -> Self {
        Self {
            gateway_reachable: Ok(true),
            tunnel_up: Ok(true),
            dns_route_ok: Ok(true),
            observe_public_ip: Ok(Some(IpObservation {
                ip: "198.51.100.7".into(),
                via_tunnel: true,
                differs_from_host: true,
            })),
            ipv6_blocked: Ok(true),
        }
    }

    /// Convenience: set the public-IP observation.
    #[must_use]
    pub fn with_observation(mut self, obs: Option<IpObservation>) -> Self {
        self.observe_public_ip = Ok(obs);
        self
    }
}

impl Default for MockProbe {
    fn default() -> Self {
        Self::all_pass()
    }
}

/// Clone a `Result<T>` for a probe whose fields hold error variants.
///
/// `aegis_core::Error` is not `Clone`, so each accessor rebuilds an equivalent
/// error (preserving the variant and message) rather than deriving `Clone`.
fn clone_bool(r: &Result<bool>) -> Result<bool> {
    match r {
        Ok(v) => Ok(*v),
        Err(e) => Err(rebuild_error(e)),
    }
}

fn clone_obs(r: &Result<Option<IpObservation>>) -> Result<Option<IpObservation>> {
    match r {
        Ok(v) => Ok(v.clone()),
        Err(e) => Err(rebuild_error(e)),
    }
}

/// Reconstruct an equivalent [`Error`] (same class + message) from a reference.
///
/// Used only by [`MockProbe`] so its stored error fields can be returned from
/// each `&self` probe call. Preserves the fail-closed classification so tests
/// exercise the same code path the real errors would.
fn rebuild_error(e: &Error) -> Error {
    let msg = e.to_string();
    match e {
        Error::NetworkContainment(_) => Error::NetworkContainment(msg),
        Error::Isolation(_) => Error::Isolation(msg),
        Error::Preflight { check, detail } => Error::Preflight {
            check: check.clone(),
            detail: detail.clone(),
        },
        Error::Crypto(_) => Error::Crypto(msg),
        Error::Integrity(_) => Error::Integrity(msg),
        Error::Config(_) => Error::Config(msg),
        Error::Precondition(_) => Error::Precondition(msg),
        Error::NotFound(_) => Error::NotFound(msg),
        Error::Busy(_) => Error::Busy(msg),
        Error::Unsupported(_) => Error::Unsupported(msg),
        Error::System(_) => Error::System(msg),
        Error::Internal(_) => Error::Internal(msg),
        // `Error` is `#[non_exhaustive]`; map anything new to a fail-closed
        // system error so the mock still compiles against future variants.
        _ => Error::System(msg),
    }
}

#[async_trait::async_trait]
impl Probe for MockProbe {
    async fn gateway_reachable(&self, _ctx: &PreflightContext) -> Result<bool> {
        clone_bool(&self.gateway_reachable)
    }
    async fn tunnel_up(&self, _ctx: &PreflightContext) -> Result<bool> {
        clone_bool(&self.tunnel_up)
    }
    async fn dns_route_ok(&self, _ctx: &PreflightContext) -> Result<bool> {
        clone_bool(&self.dns_route_ok)
    }
    async fn observe_public_ip(&self, _ctx: &PreflightContext) -> Result<Option<IpObservation>> {
        clone_obs(&self.observe_public_ip)
    }
    async fn ipv6_blocked(&self, _ctx: &PreflightContext) -> Result<bool> {
        clone_bool(&self.ipv6_blocked)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_core::network::{DnsPolicy, Ipv6Policy};
    use aegis_core::SessionId;

    fn ctx() -> PreflightContext {
        PreflightContext {
            session: SessionId::new(),
            gateway_address: "10.152.152.10".into(),
            mode_label: "Tor".into(),
            dns: DnsPolicy::tor(),
            ipv6: Ipv6Policy::Block,
            webrtc_policy_installed: true,
            host_public_ip: Some("203.0.113.9".into()),
        }
    }

    #[tokio::test]
    async fn mock_all_pass_reports_healthy_session() {
        let p = MockProbe::all_pass();
        let c = ctx();
        assert!(p.gateway_reachable(&c).await.unwrap());
        assert!(p.tunnel_up(&c).await.unwrap());
        assert!(p.dns_route_ok(&c).await.unwrap());
        assert!(p.ipv6_blocked(&c).await.unwrap());
        let obs = p.observe_public_ip(&c).await.unwrap().unwrap();
        assert!(obs.via_tunnel && obs.differs_from_host);
    }

    #[tokio::test]
    async fn mock_preserves_error_variant_and_class() {
        let p = MockProbe {
            gateway_reachable: Err(Error::System("probe channel down".into())),
            ..MockProbe::all_pass()
        };
        let err = p.gateway_reachable(&ctx()).await.unwrap_err();
        assert!(matches!(err, Error::System(_)));
        assert_eq!(err.class(), aegis_core::FailureClass::System);
    }

    #[cfg(not(target_os = "linux"))]
    #[tokio::test]
    async fn system_probe_is_unsupported_off_linux() {
        let p = SystemProbe::new();
        let c = ctx();
        assert!(matches!(
            p.gateway_reachable(&c).await.unwrap_err(),
            Error::Unsupported(_)
        ));
        assert!(matches!(
            p.dns_route_ok(&c).await.unwrap_err(),
            Error::Unsupported(_)
        ));
        assert!(matches!(
            p.observe_public_ip(&c).await.unwrap_err(),
            Error::Unsupported(_)
        ));
        assert!(matches!(
            p.tunnel_up(&c).await.unwrap_err(),
            Error::Unsupported(_)
        ));
        assert!(matches!(
            p.ipv6_blocked(&c).await.unwrap_err(),
            Error::Unsupported(_)
        ));
    }
}
