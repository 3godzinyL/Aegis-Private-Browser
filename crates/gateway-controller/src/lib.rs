//! # gateway-controller
//!
//! The concrete [`aegis_core::traits::GatewayController`] for Aegis: it owns the
//! Gateway VM's **nftables firewall**, the **tunnel backend** (Tor / VPN /
//! proxy), and the **kill switch** (spec §5, §10, Etap 1).
//!
//! ## Design
//!
//! * All firewall logic is a [pure function][render::render_nftables] that emits
//!   a complete default-deny ruleset; the controller merely feeds it to
//!   `nft -f -`. Tests assert the security properties against the rendered
//!   `String`, no kernel required.
//! * Every privileged action goes through the [`CommandRunner`] trait. The
//!   production [`SystemRunner`] shells out with [`tokio::process::Command`] on
//!   Linux and returns [`Error::Unsupported`] elsewhere, so the crate compiles
//!   and its logic is testable on any host (including this Windows machine).
//!   Tests inject a [`MockRunner`].
//!
//! ## Fail-closed behaviour
//!
//! The controller is fail-closed by construction:
//!
//! * [`NftGatewayController::apply_firewall`] validates the policy *before*
//!   touching the host and refuses an unsafe one.
//! * **Any error on the network path engages the kill switch.** `configure`,
//!   `apply_firewall`, and `tunnel_status` all funnel failures through
//!   `NftGatewayController::fail_closed`, which swaps in the total-block
//!   [kill-switch ruleset][render::render_killswitch] before returning the
//!   error — traffic is cut first, the caller is told second.
//! * [`NftGatewayController::release_killswitch`] re-applies the normal ruleset
//!   **only after** the stored configuration re-validates.
//! * [`NftGatewayController::health`] reports *not ready* whenever the tunnel is
//!   not up, so a downstream orchestrator never opens a tab over a dead tunnel.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod mock;
pub mod render;
pub mod runner;

pub use mock::{MockResponse, MockRunner};
pub use render::{render_killswitch, render_nftables, TABLE};
pub use runner::{Command, CommandOutput, CommandRunner, SystemRunner};

use aegis_core::gateway::{
    FirewallPolicy, GatewayConfig, GatewayHealth, KillSwitchState, TunnelState, TunnelStatus,
};
use aegis_core::network::NetworkMode;
use aegis_core::traits::GatewayController;
use aegis_core::{Error, Result};
use std::sync::Mutex;

/// The program used to load nftables rulesets.
const NFT: &str = "nft";

/// Internal, mutex-guarded controller state.
#[derive(Debug)]
struct State {
    /// The last successfully-validated configuration (needed to re-arm safely).
    config: Option<GatewayConfig>,
    /// The last successfully-validated firewall policy.
    firewall: Option<FirewallPolicy>,
    /// Whether a firewall ruleset has been applied at all.
    firewall_applied: bool,
    /// Current kill-switch state.
    killswitch: KillSwitchState,
}

impl Default for State {
    fn default() -> Self {
        // The kill switch starts `Armed`, but there is no Aegis ruleset loaded
        // until `apply_firewall` runs, so the gateway carries no traffic yet.
        Self {
            config: None,
            firewall: None,
            firewall_applied: false,
            killswitch: KillSwitchState::Armed,
        }
    }
}

/// nftables-backed gateway controller.
///
/// Construct it with a [`CommandRunner`]: [`SystemRunner`] in production, or a
/// [`MockRunner`] in tests.
#[derive(Debug)]
pub struct NftGatewayController<R: CommandRunner> {
    runner: R,
    state: Mutex<State>,
}

impl<R: CommandRunner> NftGatewayController<R> {
    /// Build a controller over `runner`. The kill switch starts `Armed`
    /// (traffic is only actually permitted once a validated firewall is
    /// applied; until then the gateway has no Aegis ruleset at all).
    #[must_use]
    pub fn new(runner: R) -> Self {
        Self {
            runner,
            state: Mutex::new(State::default()),
        }
    }

    /// Borrow the underlying runner (useful for assertions in tests).
    pub fn runner(&self) -> &R {
        &self.runner
    }

    /// Feed a rendered ruleset to `nft -f -`.
    ///
    /// A spawn failure or a non-zero exit is a network-path error, so callers
    /// wrap this in [`Self::fail_closed`].
    async fn load_ruleset(&self, ruleset: &str) -> Result<()> {
        let out = self
            .runner
            .run(&Command::new(NFT, &["-f", "-"]).with_stdin(ruleset))
            .await?;
        if !out.success() {
            // Never log the ruleset itself; the stderr from nft is safe.
            return Err(Error::System(format!(
                "nft load failed (code {:?}): {}",
                out.code,
                out.stderr.trim()
            )));
        }
        Ok(())
    }

    /// The fail-closed hinge: engage the kill switch, then return `err`.
    ///
    /// Called on **every** network-path error. Traffic is cut before the error
    /// propagates. If loading the kill-switch ruleset *also* fails we still
    /// return the original error (the tunnel/firewall was already down; the host
    /// is in the safest state we can reach) but mark the switch `Engaged` so the
    /// recorded state reflects that connectivity is not permitted.
    async fn fail_closed(&self, err: Error) -> Error {
        // Best-effort: try to cut traffic. Ignore a secondary failure — we are
        // already returning an error and the state is set to Engaged regardless.
        let _ = self.load_ruleset(&render_killswitch()).await;
        {
            let mut st = self.state.lock().unwrap();
            st.killswitch = KillSwitchState::Engaged;
            st.firewall_applied = false;
        }
        err
    }

    /// Start (or select) the tunnel backend for `cfg` via the runner.
    ///
    /// Tor uses a `systemctl start tor` unit; VPN and proxy backends are brought
    /// up through their respective managers. This never inlines any credential —
    /// only a [`aegis_core::network::CredentialRef`] id ever appears, and it is
    /// resolved elsewhere by secure-storage.
    async fn start_backend(&self, cfg: &GatewayConfig) -> Result<()> {
        let cmd = match &cfg.mode {
            NetworkMode::Tor(_) => Command::new("systemctl", &["restart", "tor@default"]),
            NetworkMode::Vpn(vpn) => {
                // Bring the tunnel up by protocol. The endpoint is public info;
                // keys live behind `vpn.credentials_ref` and are applied by the
                // unit/config, not passed on the command line.
                match vpn.protocol {
                    aegis_core::network::VpnProtocol::WireGuard => {
                        Command::new("systemctl", &["restart", "wg-quick@aegis"])
                    }
                    aegis_core::network::VpnProtocol::OpenVpn => {
                        Command::new("systemctl", &["restart", "openvpn@aegis"])
                    }
                }
            }
            NetworkMode::Proxy(_) => {
                // The proxy backend is a local redsocks-style transparent proxy.
                Command::new("systemctl", &["restart", "aegis-proxy"])
            }
        };
        let out = self.runner.run(&cmd).await?;
        if !out.success() {
            return Err(Error::System(format!(
                "backend start failed (code {:?}): {}",
                out.code,
                out.stderr.trim()
            )));
        }
        Ok(())
    }

    /// Probe the backend and map its output to a [`TunnelStatus`].
    ///
    /// For Tor we query the bootstrap phase; anything not fully bootstrapped is
    /// reported as `Connecting` (with a percentage) or `Down`. A probe that
    /// cannot run at all is a network-path error handled by the caller.
    async fn probe_status(&self, mode: &NetworkMode) -> Result<TunnelStatus> {
        match mode {
            NetworkMode::Tor(_) => {
                let out = self
                    .runner
                    .run(&Command::new("tor-bootstrap", &["--status"]))
                    .await?;
                if !out.success() {
                    return Ok(TunnelStatus {
                        state: TunnelState::Failed,
                        bootstrap_percent: None,
                        detail: Some("tor bootstrap probe failed".into()),
                    });
                }
                Ok(parse_tor_bootstrap(&out.stdout))
            }
            NetworkMode::Vpn(_) | NetworkMode::Proxy(_) => {
                // A generic reachability probe: exit 0 => up.
                let out = self
                    .runner
                    .run(&Command::new("tunnel-probe", &["--check"]))
                    .await?;
                if out.success() {
                    Ok(TunnelStatus::up())
                } else {
                    Ok(TunnelStatus {
                        state: TunnelState::Failed,
                        bootstrap_percent: None,
                        detail: Some("tunnel probe reported failure".into()),
                    })
                }
            }
        }
    }
}

/// Parse a Tor bootstrap status line into a [`TunnelStatus`].
///
/// Accepts either a bare integer percentage (`"100"`) or a line containing
/// `PROGRESS=NN` (as emitted by `GETINFO status/bootstrap-phase`). `100` maps to
/// `Up`; `1..=99` to `Connecting`; `0`/unparseable to `Down`.
fn parse_tor_bootstrap(stdout: &str) -> TunnelStatus {
    let pct = stdout
        .split_whitespace()
        .find_map(|tok| {
            tok.strip_prefix("PROGRESS=")
                .or(Some(tok))
                .and_then(|v| v.parse::<u8>().ok())
        })
        .unwrap_or(0)
        .min(100);
    let state = match pct {
        100 => TunnelState::Up,
        1..=99 => TunnelState::Connecting,
        _ => TunnelState::Down,
    };
    TunnelStatus {
        state,
        bootstrap_percent: Some(pct),
        detail: None,
    }
}

#[async_trait::async_trait]
impl<R: CommandRunner> GatewayController for NftGatewayController<R> {
    async fn configure(&self, cfg: &GatewayConfig) -> Result<()> {
        // Start/select the backend. Any failure cuts traffic first.
        if let Err(e) = self.start_backend(cfg).await {
            return Err(self.fail_closed(e).await);
        }
        // Persist the validated config so release_killswitch can re-validate.
        {
            let mut st = self.state.lock().unwrap();
            st.config = Some(cfg.clone());
        }
        Ok(())
    }

    async fn apply_firewall(&self, policy: &FirewallPolicy) -> Result<()> {
        // Validate BEFORE touching the host — reject an unsafe policy outright.
        if let Some(reason) = policy.validate() {
            return Err(Error::Config(format!("unsafe firewall policy: {reason}")));
        }
        // We need a config for the downstream CIDR / redirect wiring.
        let cfg = {
            let st = self.state.lock().unwrap();
            st.config.clone()
        };
        let Some(cfg) = cfg else {
            return Err(Error::Precondition(
                "configure() must run before apply_firewall()".into(),
            ));
        };

        let ruleset = render_nftables(policy, &cfg);
        if let Err(e) = self.load_ruleset(&ruleset).await {
            // Firewall load failure on the network path: fail closed.
            return Err(self.fail_closed(e).await);
        }
        {
            let mut st = self.state.lock().unwrap();
            st.firewall = Some(policy.clone());
            st.firewall_applied = true;
            st.killswitch = KillSwitchState::Armed;
        }
        Ok(())
    }

    async fn tunnel_status(&self) -> Result<TunnelStatus> {
        let mode = {
            let st = self.state.lock().unwrap();
            st.config.as_ref().map(|c| c.mode.clone())
        };
        let Some(mode) = mode else {
            return Err(Error::Precondition("gateway not configured".into()));
        };
        match self.probe_status(&mode).await {
            Ok(status) => {
                // A tunnel that has failed is a containment breach: cut traffic.
                if status.state == TunnelState::Failed {
                    let err = Error::NetworkContainment("tunnel reported Failed".into());
                    // Engage the kill switch but still surface the status to the
                    // caller (health() relies on reading a Failed status).
                    let _ = self.fail_closed(err).await;
                }
                Ok(status)
            }
            Err(e) => Err(self.fail_closed(e).await),
        }
    }

    async fn engage_killswitch(&self) -> Result<()> {
        // Load the total-block ruleset. If even that fails, we still mark the
        // switch Engaged: the safest recorded state.
        let result = self.load_ruleset(&render_killswitch()).await;
        {
            let mut st = self.state.lock().unwrap();
            st.killswitch = KillSwitchState::Engaged;
            st.firewall_applied = false;
        }
        result
    }

    async fn release_killswitch(&self) -> Result<()> {
        // Re-arm ONLY after the stored config + firewall re-validate.
        let (cfg, policy) = {
            let st = self.state.lock().unwrap();
            (st.config.clone(), st.firewall.clone())
        };
        let Some(cfg) = cfg else {
            return Err(Error::Precondition(
                "cannot release kill switch: no validated configuration".into(),
            ));
        };
        let Some(policy) = policy else {
            return Err(Error::Precondition(
                "cannot release kill switch: no validated firewall policy".into(),
            ));
        };
        if let Some(reason) = policy.validate() {
            // Stored policy no longer validates: stay engaged, fail closed.
            return Err(self
                .fail_closed(Error::Config(format!(
                    "stored firewall policy no longer valid: {reason}"
                )))
                .await);
        }
        let ruleset = render_nftables(&policy, &cfg);
        if let Err(e) = self.load_ruleset(&ruleset).await {
            return Err(self.fail_closed(e).await);
        }
        {
            let mut st = self.state.lock().unwrap();
            st.killswitch = KillSwitchState::Armed;
            st.firewall_applied = true;
        }
        Ok(())
    }

    async fn killswitch_state(&self) -> Result<KillSwitchState> {
        Ok(self.state.lock().unwrap().killswitch)
    }

    async fn health(&self) -> Result<GatewayHealth> {
        let (configured, firewall_applied, killswitch) = {
            let st = self.state.lock().unwrap();
            (st.config.is_some(), st.firewall_applied, st.killswitch)
        };

        // Determine tunnel status without engaging the kill switch here: health
        // is a read-only diagnostic. We still report a Failed/Down tunnel.
        let tunnel = if configured {
            let mode = {
                let st = self.state.lock().unwrap();
                st.config.as_ref().map(|c| c.mode.clone())
            };
            match mode {
                Some(m) => self.probe_status(&m).await.unwrap_or(TunnelStatus {
                    state: TunnelState::Failed,
                    bootstrap_percent: None,
                    detail: Some("status probe errored".into()),
                }),
                None => TunnelStatus {
                    state: TunnelState::Down,
                    bootstrap_percent: None,
                    detail: None,
                },
            }
        } else {
            TunnelStatus {
                state: TunnelState::Down,
                bootstrap_percent: None,
                detail: Some("not configured".into()),
            }
        };

        // Per fail-closed: the gateway is only "up" for readiness purposes when
        // it is configured AND the kill switch permits traffic. `is_ready()`
        // (checked by the orchestrator) additionally requires the tunnel up and
        // the firewall applied, so a Failed/Down tunnel => not ready.
        let health = GatewayHealth {
            gateway_up: configured && killswitch.allows_traffic(),
            firewall_applied,
            tunnel,
            killswitch,
        };
        Ok(health)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_core::gateway::DefaultPolicy;
    use aegis_core::network::{DnsPolicy, Ipv6Policy, NetworkMode, TorConfig};

    fn tor_cfg() -> GatewayConfig {
        GatewayConfig {
            mode: NetworkMode::Tor(TorConfig::default()),
            dns: DnsPolicy::tor(),
            ipv6: Ipv6Policy::Block,
            downstream_cidr: "10.152.152.0/24".into(),
            gateway_address: "10.152.152.1".into(),
        }
    }

    /// A mock where every backend command and probe succeeds and Tor is fully
    /// bootstrapped.
    fn healthy_mock() -> MockRunner {
        MockRunner::new()
            .with("tor-bootstrap", MockResponse::stdout("100"))
            .with("tunnel-probe", MockResponse::ok())
    }

    // ---- pure render properties (spec §5) -------------------------------

    #[test]
    fn fail_closed_policy_validates_and_render_has_all_properties() {
        let cfg = tor_cfg();
        let policy = FirewallPolicy::fail_closed(&cfg);
        assert!(
            policy.validate().is_none(),
            "fail_closed policy must validate"
        );

        let ruleset = render_nftables(&policy, &cfg);
        assert!(ruleset.contains("policy drop"), "must default-drop");
        // DNS redirect to Tor DNSPort.
        assert!(
            ruleset.contains("redirect to :5353"),
            "DNS redirect present"
        );
        // Direct UDP blocked.
        assert!(
            ruleset.contains("meta l4proto udp drop"),
            "direct UDP dropped"
        );
        // IPv6 dropped.
        assert!(ruleset.contains("meta nfproto ipv6 drop"), "IPv6 dropped");
    }

    #[test]
    fn killswitch_ruleset_is_drop_all() {
        let ks = render_killswitch();
        assert_eq!(ks.matches("policy drop;").count(), 3);
        assert!(!ks.contains("accept"));
        assert!(!ks.contains("redirect"));
    }

    // ---- controller behaviour (MockRunner) ------------------------------

    #[tokio::test]
    async fn configure_then_apply_firewall_arms_and_loads_ruleset() {
        let ctl = NftGatewayController::new(healthy_mock());
        let cfg = tor_cfg();
        ctl.configure(&cfg).await.unwrap();
        ctl.apply_firewall(&FirewallPolicy::fail_closed(&cfg))
            .await
            .unwrap();

        assert_eq!(
            ctl.killswitch_state().await.unwrap(),
            KillSwitchState::Armed
        );
        // The ruleset fed to nft is the rendered default-deny one.
        let stdin = ctl.runner().last_stdin_for("nft").unwrap();
        assert!(stdin.contains("policy drop"));
        assert!(stdin.contains("redirect to :5353"));
    }

    #[tokio::test]
    async fn apply_firewall_rejects_unsafe_policy_without_touching_host() {
        let ctl = NftGatewayController::new(healthy_mock());
        ctl.configure(&tor_cfg()).await.unwrap();
        let mut bad = FirewallPolicy::fail_closed(&tor_cfg());
        bad.default_policy = DefaultPolicy::Accept; // unsafe
        let err = ctl.apply_firewall(&bad).await.unwrap_err();
        assert!(matches!(err, Error::Config(_)));
        assert_eq!(err.class(), aegis_core::FailureClass::Configuration);
        // nft was never invoked for an unsafe policy.
        assert!(!ctl.runner().ran_program("nft"));
    }

    #[tokio::test]
    async fn apply_firewall_requires_prior_configure() {
        let ctl = NftGatewayController::new(healthy_mock());
        let err = ctl
            .apply_firewall(&FirewallPolicy::fail_closed(&tor_cfg()))
            .await
            .unwrap_err();
        assert!(matches!(err, Error::Precondition(_)));
    }

    #[tokio::test]
    async fn engage_killswitch_sets_engaged_and_health_not_ready() {
        let ctl = NftGatewayController::new(healthy_mock());
        let cfg = tor_cfg();
        ctl.configure(&cfg).await.unwrap();
        ctl.apply_firewall(&FirewallPolicy::fail_closed(&cfg))
            .await
            .unwrap();

        ctl.engage_killswitch().await.unwrap();
        assert_eq!(
            ctl.killswitch_state().await.unwrap(),
            KillSwitchState::Engaged
        );

        // The ruleset last loaded is the total block.
        let stdin = ctl.runner().last_stdin_for("nft").unwrap();
        assert!(!stdin.contains("accept"));

        let health = ctl.health().await.unwrap();
        assert!(!health.is_ready(), "engaged kill switch => not ready");
    }

    #[tokio::test]
    async fn release_killswitch_re_arms_after_revalidation() {
        let ctl = NftGatewayController::new(healthy_mock());
        let cfg = tor_cfg();
        ctl.configure(&cfg).await.unwrap();
        ctl.apply_firewall(&FirewallPolicy::fail_closed(&cfg))
            .await
            .unwrap();
        ctl.engage_killswitch().await.unwrap();
        assert_eq!(
            ctl.killswitch_state().await.unwrap(),
            KillSwitchState::Engaged
        );

        ctl.release_killswitch().await.unwrap();
        assert_eq!(
            ctl.killswitch_state().await.unwrap(),
            KillSwitchState::Armed
        );
        // Re-applied the normal (non-block) ruleset.
        let stdin = ctl.runner().last_stdin_for("nft").unwrap();
        assert!(stdin.contains("policy drop"));
        assert!(stdin.contains("redirect to :5353"));
    }

    #[tokio::test]
    async fn release_killswitch_refuses_without_config() {
        let ctl = NftGatewayController::new(healthy_mock());
        let err = ctl.release_killswitch().await.unwrap_err();
        assert!(matches!(err, Error::Precondition(_)));
    }

    #[tokio::test]
    async fn healthy_gateway_is_ready() {
        let ctl = NftGatewayController::new(healthy_mock());
        let cfg = tor_cfg();
        ctl.configure(&cfg).await.unwrap();
        ctl.apply_firewall(&FirewallPolicy::fail_closed(&cfg))
            .await
            .unwrap();
        let health = ctl.health().await.unwrap();
        assert!(health.gateway_up);
        assert!(health.firewall_applied);
        assert_eq!(health.tunnel.state, TunnelState::Up);
        assert!(health.is_ready());
    }

    #[tokio::test]
    async fn failed_tunnel_status_makes_health_not_ready_and_engages() {
        // Tor bootstrap probe fails => Failed status.
        let mock = MockRunner::new().with(
            "tor-bootstrap",
            MockResponse::failure(1, "not bootstrapped"),
        );
        let ctl = NftGatewayController::new(mock);
        let cfg = tor_cfg();
        ctl.configure(&cfg).await.unwrap();
        ctl.apply_firewall(&FirewallPolicy::fail_closed(&cfg))
            .await
            .unwrap();

        // tunnel_status reports Failed AND engages the kill switch (fail-closed).
        let status = ctl.tunnel_status().await.unwrap();
        assert_eq!(status.state, TunnelState::Failed);
        assert_eq!(
            ctl.killswitch_state().await.unwrap(),
            KillSwitchState::Engaged
        );

        let health = ctl.health().await.unwrap();
        assert!(!health.is_ready(), "failed tunnel => not ready");
    }

    #[tokio::test]
    async fn health_reports_not_ready_when_tunnel_down_even_if_armed() {
        // Tor at 40%: still Connecting, not Up.
        let mock = MockRunner::new().with("tor-bootstrap", MockResponse::stdout("40"));
        let ctl = NftGatewayController::new(mock);
        let cfg = tor_cfg();
        ctl.configure(&cfg).await.unwrap();
        ctl.apply_firewall(&FirewallPolicy::fail_closed(&cfg))
            .await
            .unwrap();
        let health = ctl.health().await.unwrap();
        assert_eq!(health.tunnel.state, TunnelState::Connecting);
        assert!(!health.is_ready(), "connecting tunnel => not ready");
    }

    #[tokio::test]
    async fn configure_backend_failure_engages_killswitch() {
        // systemctl (Tor unit start) fails as if the process errored.
        let mock = MockRunner::new().with("systemctl", MockResponse::Error("no such unit".into()));
        let ctl = NftGatewayController::new(mock);
        let err = ctl.configure(&tor_cfg()).await.unwrap_err();
        assert!(matches!(err, Error::System(_)));
        // Fail-closed: the kill switch was engaged on the network-path error.
        assert_eq!(
            ctl.killswitch_state().await.unwrap(),
            KillSwitchState::Engaged
        );
    }

    #[tokio::test]
    async fn apply_firewall_nft_failure_engages_killswitch() {
        // Backend ok, but nft load returns non-zero.
        let mock = MockRunner::new()
            .with("tor-bootstrap", MockResponse::stdout("100"))
            .with("nft", MockResponse::failure(1, "syntax error"));
        let ctl = NftGatewayController::new(mock);
        ctl.configure(&tor_cfg()).await.unwrap();
        let err = ctl
            .apply_firewall(&FirewallPolicy::fail_closed(&tor_cfg()))
            .await
            .unwrap_err();
        assert!(matches!(err, Error::System(_)));
        assert_eq!(
            ctl.killswitch_state().await.unwrap(),
            KillSwitchState::Engaged
        );
    }

    #[tokio::test]
    async fn tunnel_status_maps_bootstrap_percentages() {
        for (out, expect) in [
            ("100", TunnelState::Up),
            ("50", TunnelState::Connecting),
            ("0", TunnelState::Down),
            ("PROGRESS=100", TunnelState::Up),
            ("PROGRESS=25", TunnelState::Connecting),
        ] {
            let mock = MockRunner::new().with("tor-bootstrap", MockResponse::stdout(out));
            let ctl = NftGatewayController::new(mock);
            ctl.configure(&tor_cfg()).await.unwrap();
            let status = ctl.tunnel_status().await.unwrap();
            assert_eq!(status.state, expect, "input {out}");
        }
    }

    #[tokio::test]
    async fn tunnel_status_requires_configuration() {
        let ctl = NftGatewayController::new(healthy_mock());
        let err = ctl.tunnel_status().await.unwrap_err();
        assert!(matches!(err, Error::Precondition(_)));
    }

    #[tokio::test]
    async fn controller_is_usable_as_trait_object() {
        let ctl: Box<dyn GatewayController> = Box::new(NftGatewayController::new(healthy_mock()));
        assert_eq!(
            ctl.killswitch_state().await.unwrap(),
            KillSwitchState::Armed
        );
    }
}
