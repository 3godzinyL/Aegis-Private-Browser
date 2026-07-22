//! # network-audit
//!
//! The preflight connectivity checklist and leak detection for **Aegis Private
//! Browser** (spec §5, §15). Before the first tab is allowed to load, the
//! [`Auditor`] runs the six mandatory checks
//! ([`aegis_core::preflight::CheckId`]); if *any* check fails, the browser does
//! not get internet access. There is no partial-pass path to a live session —
//! the checklist is **fail-closed**.
//!
//! ## Shape
//!
//! * [`Probe`] — the measurement abstraction (one method per concrete probe).
//!   [`SystemProbe`] performs the measurement inside the Linux VMs (and returns
//!   [`aegis_core::Error::Unsupported`] off-Linux); [`MockProbe`] drives every
//!   branch in tests.
//! * [`Auditor`] — implements [`aegis_core::traits::NetworkAuditor`]. It maps
//!   each [`CheckId`] to the right probe and turns the result into a
//!   [`CheckReport`]. A probe *error* becomes a **`Fail`** report (fail-closed),
//!   never a propagated `Err`.
//!
//! ## Fail-closed contract
//!
//! `run_check` and `run_preflight` return `Ok(..)` for a checklist that *ran* —
//! including one where every check failed. They only return `Err(..)` for a
//! caller-side programming fault. A failing or unmeasurable probe always lands
//! as a `Fail` [`CheckReport`], so the aggregate
//! [`aegis_core::preflight::ProtectionStatus`] can never be `Active` unless all
//! six guarantees were positively measured.
//!
//! Secrets, keys, credentials, the real host IP, and the observed exit IP are
//! **never** logged (spec §11, §16).

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod probe;

pub use probe::{MockProbe, Probe, SystemProbe};

use aegis_core::preflight::{CheckId, CheckReport, ConnectivityChecklist, IpObservation};
use aegis_core::traits::{NetworkAuditor, PreflightContext};
use aegis_core::Result;
use async_trait::async_trait;

/// Runs the preflight connectivity checklist on top of a [`Probe`].
///
/// The auditor owns no I/O of its own: it delegates each measurement to the
/// injected probe and applies the fail-closed decision logic. Construct it with
/// a [`SystemProbe`] in production (Linux VMs) or a [`MockProbe`] in tests.
///
/// `P` is the probe type. Using a generic (rather than a boxed trait object)
/// keeps the type transparent to callers and lets the daemon pick the concrete
/// probe at wiring time.
#[derive(Debug, Clone, Default)]
pub struct Auditor<P: Probe> {
    probe: P,
}

impl<P: Probe> Auditor<P> {
    /// Construct an auditor over the given probe.
    #[must_use]
    pub fn new(probe: P) -> Self {
        Self { probe }
    }

    /// Borrow the underlying probe (useful in tests).
    #[must_use]
    pub fn probe(&self) -> &P {
        &self.probe
    }

    /// Map a boolean probe result into a pass/fail report, folding a probe
    /// error into a `Fail` (fail-closed). `on_true` / `on_false` supply the
    /// (secret-free) detail strings.
    fn boolean_report(
        id: CheckId,
        result: Result<bool>,
        on_true: &str,
        on_false: &str,
    ) -> CheckReport {
        match result {
            Ok(true) => CheckReport::pass(id, on_true),
            Ok(false) => CheckReport::fail(id, on_false),
            // A probe that could not run is treated exactly like a failed
            // measurement. The error message is a generic class label, never the
            // underlying detail, so nothing sensitive reaches the report.
            Err(e) => CheckReport::fail(
                id,
                format!("probe could not verify this guarantee ({})", e.class()),
            ),
        }
    }

    /// The `GatewayReady` check.
    async fn check_gateway(&self, ctx: &PreflightContext) -> CheckReport {
        Self::boolean_report(
            CheckId::GatewayReady,
            self.probe.gateway_reachable(ctx).await,
            "gateway VM is reachable on the management channel",
            "gateway VM is not reachable",
        )
    }

    /// The `TunnelReady` check.
    async fn check_tunnel(&self, ctx: &PreflightContext) -> CheckReport {
        Self::boolean_report(
            CheckId::TunnelReady,
            self.probe.tunnel_up(ctx).await,
            "outbound tunnel is established",
            "outbound tunnel is not established",
        )
    }

    /// The `DnsRouteVerified` check — verifies DNS leaves only through the
    /// intended route (no plaintext port-53 escape, no IPv6 leak; spec §15).
    async fn check_dns(&self, ctx: &PreflightContext) -> CheckReport {
        Self::boolean_report(
            CheckId::DnsRouteVerified,
            self.probe.dns_route_ok(ctx).await,
            "DNS resolves only through the intended route",
            "DNS route unverified — possible leak outside the tunnel",
        )
    }

    /// The `WebrtcPolicyLoaded` check — presence comes from the context, not a
    /// probe (the daemon installs the browser policy document; spec §5 WebRTC).
    fn check_webrtc(ctx: &PreflightContext) -> CheckReport {
        if ctx.webrtc_policy_installed {
            CheckReport::pass(
                CheckId::WebrtcPolicyLoaded,
                "WebRTC policy blocking non-proxied UDP is installed",
            )
        } else {
            CheckReport::fail(
                CheckId::WebrtcPolicyLoaded,
                "WebRTC policy is not installed — host interface could leak via WebRTC",
            )
        }
    }

    /// The `Ipv6PolicyVerified` check.
    async fn check_ipv6(&self, ctx: &PreflightContext) -> CheckReport {
        Self::boolean_report(
            CheckId::Ipv6PolicyVerified,
            self.probe.ipv6_blocked(ctx).await,
            "IPv6 policy is verified in effect",
            "IPv6 policy is not verified — possible v6 leak",
        )
    }

    /// The `PublicIpObserved` check plus the observation it produced.
    ///
    /// Passes only when an observation was made **and** it was `via_tunnel`
    /// **and** it `differs_from_host` (compared against `ctx.host_public_ip`
    /// when known). Any other case — no observation, direct observation, or an
    /// exit IP equal to the host — is a `Fail` (fail-closed). The observation is
    /// returned even on failure so the checklist can surface it (redacted).
    async fn check_public_ip(
        &self,
        ctx: &PreflightContext,
    ) -> (CheckReport, Option<IpObservation>) {
        match self.probe.observe_public_ip(ctx).await {
            Ok(Some(obs)) => {
                // Cross-check against the known host IP if we have one; an exit
                // IP equal to the host means traffic escaped the tunnel.
                let matches_host = ctx
                    .host_public_ip
                    .as_deref()
                    .is_some_and(|host| host == obs.ip);
                let differs = obs.differs_from_host && !matches_host;

                let report = if obs.via_tunnel && differs {
                    CheckReport::pass(
                        CheckId::PublicIpObserved,
                        "public IP observed through the tunnel and differs from host",
                    )
                } else if !obs.via_tunnel {
                    CheckReport::fail(
                        CheckId::PublicIpObserved,
                        "public IP was not observed through the tunnel",
                    )
                } else {
                    CheckReport::fail(
                        CheckId::PublicIpObserved,
                        "observed public IP matches the host — traffic escaped the tunnel",
                    )
                };
                (report, Some(obs))
            }
            Ok(None) => (
                CheckReport::fail(
                    CheckId::PublicIpObserved,
                    "no public IP could be observed from inside the session",
                ),
                None,
            ),
            Err(e) => (
                CheckReport::fail(
                    CheckId::PublicIpObserved,
                    format!("public IP could not be observed ({})", e.class()),
                ),
                None,
            ),
        }
    }
}

#[async_trait]
impl<P: Probe> NetworkAuditor for Auditor<P> {
    async fn run_preflight(&self, ctx: &PreflightContext) -> Result<ConnectivityChecklist> {
        // Run all six checks in the fixed execution order (spec §5).
        let gateway = self.check_gateway(ctx).await;
        let tunnel = self.check_tunnel(ctx).await;
        let dns = self.check_dns(ctx).await;
        let (public_ip, observed_ip) = self.check_public_ip(ctx).await;
        let webrtc = Self::check_webrtc(ctx);
        let ipv6 = self.check_ipv6(ctx).await;

        let mut checklist =
            ConnectivityChecklist::new(vec![gateway, tunnel, dns, public_ip, webrtc, ipv6]);
        checklist.observed_ip = observed_ip;
        Ok(checklist)
    }

    async fn run_check(&self, id: CheckId, ctx: &PreflightContext) -> Result<CheckReport> {
        let report = match id {
            CheckId::GatewayReady => self.check_gateway(ctx).await,
            CheckId::TunnelReady => self.check_tunnel(ctx).await,
            CheckId::DnsRouteVerified => self.check_dns(ctx).await,
            CheckId::PublicIpObserved => self.check_public_ip(ctx).await.0,
            CheckId::WebrtcPolicyLoaded => Self::check_webrtc(ctx),
            CheckId::Ipv6PolicyVerified => self.check_ipv6(ctx).await,
        };
        Ok(report)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_core::network::{DnsPolicy, Ipv6Policy};
    use aegis_core::preflight::{CheckOutcome, ProtectionStatus};
    use aegis_core::{Error, SessionId};

    /// A healthy context: Tor mode, IPv6 blocked, WebRTC policy installed, and a
    /// known host IP that differs from the mock's observed exit IP.
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

    fn outcome(cl: &ConnectivityChecklist, id: CheckId) -> CheckOutcome {
        cl.report(id).expect("report present").outcome
    }

    // ---- Happy path -------------------------------------------------------

    #[tokio::test]
    async fn all_pass_is_active_and_permits_browsing() {
        let auditor = Auditor::new(MockProbe::all_pass());
        let cl = auditor.run_preflight(&ctx()).await.unwrap();

        assert_eq!(cl.reports.len(), 6);
        assert!(cl.all_passed());
        assert_eq!(cl.status(), ProtectionStatus::Active);
        assert!(cl.permits_browsing());
        // The observed IP is threaded through onto the checklist.
        let obs = cl.observed_ip.expect("observation recorded");
        assert!(obs.via_tunnel && obs.differs_from_host);
    }

    #[tokio::test]
    async fn preflight_runs_checks_in_spec_order() {
        let auditor = Auditor::new(MockProbe::all_pass());
        let cl = auditor.run_preflight(&ctx()).await.unwrap();
        let ids: Vec<CheckId> = cl.reports.iter().map(|r| r.id).collect();
        assert_eq!(ids, CheckId::all().to_vec());
    }

    // ---- Gateway down => None, not permitted ------------------------------

    #[tokio::test]
    async fn gateway_down_is_none_and_not_permitted() {
        let probe = MockProbe {
            gateway_reachable: Ok(false),
            ..MockProbe::all_pass()
        };
        let cl = Auditor::new(probe).run_preflight(&ctx()).await.unwrap();
        assert_eq!(outcome(&cl, CheckId::GatewayReady), CheckOutcome::Fail);
        assert_eq!(cl.status(), ProtectionStatus::None);
        assert!(!cl.permits_browsing());
    }

    #[tokio::test]
    async fn tunnel_down_is_none_and_not_permitted() {
        let probe = MockProbe {
            tunnel_up: Ok(false),
            ..MockProbe::all_pass()
        };
        let cl = Auditor::new(probe).run_preflight(&ctx()).await.unwrap();
        assert_eq!(outcome(&cl, CheckId::TunnelReady), CheckOutcome::Fail);
        assert_eq!(cl.status(), ProtectionStatus::None);
        assert!(!cl.permits_browsing());
    }

    // ---- DNS leak => Unsafe, not permitted --------------------------------

    #[tokio::test]
    async fn dns_leak_is_unsafe_and_not_permitted() {
        let probe = MockProbe {
            dns_route_ok: Ok(false),
            ..MockProbe::all_pass()
        };
        let cl = Auditor::new(probe).run_preflight(&ctx()).await.unwrap();
        assert_eq!(outcome(&cl, CheckId::DnsRouteVerified), CheckOutcome::Fail);
        // Gateway + tunnel are up, so a leak-relevant failure is Unsafe.
        assert_eq!(cl.status(), ProtectionStatus::Unsafe);
        assert!(!cl.permits_browsing());
    }

    // ---- Observed IP equal to host => PublicIpObserved fails => Unsafe -----

    #[tokio::test]
    async fn observed_ip_equal_to_host_fails_public_ip_and_is_unsafe() {
        let mut c = ctx();
        c.host_public_ip = Some("203.0.113.55".into());
        // The mock claims differs_from_host = true, but the observed ip equals
        // the host ip — the auditor must catch the contradiction and fail.
        let probe = MockProbe::all_pass().with_observation(Some(IpObservation {
            ip: "203.0.113.55".into(),
            via_tunnel: true,
            differs_from_host: true,
        }));
        let cl = Auditor::new(probe).run_preflight(&c).await.unwrap();
        assert_eq!(outcome(&cl, CheckId::PublicIpObserved), CheckOutcome::Fail);
        assert_eq!(cl.status(), ProtectionStatus::Unsafe);
        assert!(!cl.permits_browsing());
    }

    #[tokio::test]
    async fn public_ip_not_via_tunnel_fails() {
        let probe = MockProbe::all_pass().with_observation(Some(IpObservation {
            ip: "198.51.100.7".into(),
            via_tunnel: false,
            differs_from_host: true,
        }));
        let cl = Auditor::new(probe).run_preflight(&ctx()).await.unwrap();
        assert_eq!(outcome(&cl, CheckId::PublicIpObserved), CheckOutcome::Fail);
        assert!(!cl.permits_browsing());
    }

    #[tokio::test]
    async fn public_ip_differs_flag_false_fails() {
        let probe = MockProbe::all_pass().with_observation(Some(IpObservation {
            ip: "198.51.100.7".into(),
            via_tunnel: true,
            differs_from_host: false,
        }));
        let cl = Auditor::new(probe).run_preflight(&ctx()).await.unwrap();
        assert_eq!(outcome(&cl, CheckId::PublicIpObserved), CheckOutcome::Fail);
    }

    #[tokio::test]
    async fn no_observation_fails_public_ip() {
        let probe = MockProbe::all_pass().with_observation(None);
        let cl = Auditor::new(probe).run_preflight(&ctx()).await.unwrap();
        assert_eq!(outcome(&cl, CheckId::PublicIpObserved), CheckOutcome::Fail);
        assert!(cl.observed_ip.is_none());
        assert!(!cl.permits_browsing());
    }

    // ---- WebRTC policy presence comes from context ------------------------

    #[tokio::test]
    async fn missing_webrtc_policy_blocks_browsing() {
        let mut c = ctx();
        c.webrtc_policy_installed = false;
        let cl = Auditor::new(MockProbe::all_pass())
            .run_preflight(&c)
            .await
            .unwrap();
        assert_eq!(
            outcome(&cl, CheckId::WebrtcPolicyLoaded),
            CheckOutcome::Fail
        );
        assert_eq!(cl.status(), ProtectionStatus::Unsafe);
        assert!(!cl.permits_browsing());
    }

    // ---- IPv6 leak --------------------------------------------------------

    #[tokio::test]
    async fn ipv6_not_verified_blocks_browsing() {
        let probe = MockProbe {
            ipv6_blocked: Ok(false),
            ..MockProbe::all_pass()
        };
        let cl = Auditor::new(probe).run_preflight(&ctx()).await.unwrap();
        assert_eq!(
            outcome(&cl, CheckId::Ipv6PolicyVerified),
            CheckOutcome::Fail
        );
        assert_eq!(cl.status(), ProtectionStatus::Unsafe);
        assert!(!cl.permits_browsing());
    }

    // ---- Probe error => Fail (fail-closed), never a propagated Err --------

    #[tokio::test]
    async fn probe_error_becomes_fail_not_err() {
        let probe = MockProbe {
            dns_route_ok: Err(Error::System("resolver channel closed".into())),
            ..MockProbe::all_pass()
        };
        // Must be Ok(checklist) — the error is folded into a Fail, not propagated.
        let cl = Auditor::new(probe).run_preflight(&ctx()).await.unwrap();
        assert_eq!(outcome(&cl, CheckId::DnsRouteVerified), CheckOutcome::Fail);
        assert!(!cl.permits_browsing());
        // And the detail does not leak the underlying error message.
        let detail = &cl.report(CheckId::DnsRouteVerified).unwrap().detail;
        assert!(!detail.contains("resolver channel closed"));
    }

    #[tokio::test]
    async fn public_ip_probe_error_becomes_fail() {
        let probe = MockProbe {
            observe_public_ip: Err(Error::NetworkContainment("observe failed".into())),
            ..MockProbe::all_pass()
        };
        let cl = Auditor::new(probe).run_preflight(&ctx()).await.unwrap();
        assert_eq!(outcome(&cl, CheckId::PublicIpObserved), CheckOutcome::Fail);
        assert!(cl.observed_ip.is_none());
        assert!(!cl.permits_browsing());
    }

    // ---- Each single failure blocks browsing ------------------------------

    #[tokio::test]
    async fn each_single_failure_blocks_browsing() {
        // GatewayReady
        for id in CheckId::all() {
            let mut probe = MockProbe::all_pass();
            let mut c = ctx();
            match id {
                CheckId::GatewayReady => probe.gateway_reachable = Ok(false),
                CheckId::TunnelReady => probe.tunnel_up = Ok(false),
                CheckId::DnsRouteVerified => probe.dns_route_ok = Ok(false),
                CheckId::PublicIpObserved => {
                    probe.observe_public_ip = Ok(Some(IpObservation {
                        ip: "203.0.113.9".into(), // equals host => fail
                        via_tunnel: true,
                        differs_from_host: true,
                    }))
                }
                CheckId::WebrtcPolicyLoaded => c.webrtc_policy_installed = false,
                CheckId::Ipv6PolicyVerified => probe.ipv6_blocked = Ok(false),
            }
            let cl = Auditor::new(probe).run_preflight(&c).await.unwrap();
            assert_eq!(
                outcome(&cl, id),
                CheckOutcome::Fail,
                "check {id} should have failed"
            );
            assert!(
                !cl.permits_browsing(),
                "a single failure of {id} must block browsing"
            );
        }
    }

    // ---- run_check parity -------------------------------------------------

    #[tokio::test]
    async fn run_check_matches_preflight_reports() {
        let auditor = Auditor::new(MockProbe::all_pass());
        let c = ctx();
        let cl = auditor.run_preflight(&c).await.unwrap();
        for id in CheckId::all() {
            let single = auditor.run_check(id, &c).await.unwrap();
            let from_list = cl.report(id).unwrap();
            assert_eq!(single.id, from_list.id);
            assert_eq!(
                single.outcome, from_list.outcome,
                "outcome mismatch for {id}"
            );
        }
    }

    #[tokio::test]
    async fn run_check_gateway_error_is_fail_not_err() {
        let probe = MockProbe {
            gateway_reachable: Err(Error::Unsupported("no channel".into())),
            ..MockProbe::all_pass()
        };
        let auditor = Auditor::new(probe);
        let report = auditor
            .run_check(CheckId::GatewayReady, &ctx())
            .await
            .unwrap();
        assert_eq!(report.outcome, CheckOutcome::Fail);
    }

    // ---- Host IP unknown: rely on the probe's differs_from_host flag ------

    #[tokio::test]
    async fn unknown_host_ip_trusts_observation_flag() {
        let mut c = ctx();
        c.host_public_ip = None;
        // No host IP to cross-check; the observation flag alone decides.
        let cl = Auditor::new(MockProbe::all_pass())
            .run_preflight(&c)
            .await
            .unwrap();
        assert_eq!(outcome(&cl, CheckId::PublicIpObserved), CheckOutcome::Pass);
        assert!(cl.permits_browsing());
    }
}
