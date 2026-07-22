//! The privileged orchestrator: the fail-closed session lifecycle state machine
//! (spec §3, §5, §8, Etap 3).
//!
//! [`Orchestrator`] holds each capability as an `Arc<dyn …>` trait object so the
//! *same* orchestrator drives both the production wiring (libvirt/nftables/…) and
//! the fully-mocked integration tests. It implements the session state machine
//! from [`aegis_core::session::SessionState`]
//! (`Requested → Provisioning → GatewayStarting → Preflight → Browsing → Closing
//! → Destroyed`, plus `Failed`) and enforces the allowed transitions.
//!
//! ## Fail-closed rule
//!
//! Every network/isolation failure funnels through `Orchestrator::fail_closed`,
//! which engages the gateway kill switch and records a `Critical`
//! `EventKind::FailClosed` audit event *before* propagating the error. If
//! preflight does not permit browsing, the session never reaches `Browsing`: the
//! kill switch engages, both VMs are torn down (overlays shredded), the profile
//! lock is released, and a [`aegis_core::FailureClass::NetworkContainment`] error
//! is returned. There is no partial-pass path to a live session.

use crate::host_probe::HostNetworkProbe;
use aegis_core::browser::{BrowserHandle, BrowserLaunchRequest};
use aegis_core::config::{AppConfig, Enforcement, IsolationLevel};
use aegis_core::events::{AuditRecord, EventKind, Severity};
use aegis_core::gateway::{FirewallPolicy, GatewayConfig};
use aegis_core::ids::{InstanceId, SessionId, VmId};
use aegis_core::network::NetworkMode;
use aegis_core::preflight::ProtectionStatus;
use aegis_core::secure::SecretKey;
use aegis_core::session::{SessionState, SessionSummary};
use aegis_core::traits::{
    AuditSink, BrowserBackend, GatewayController, NetworkAuditor, PreflightContext, ProfileLease,
    ProfileRepository, SecureStore, ShutdownMode, UpdateClient, VmController,
};
use aegis_core::vm::{
    DiskLayer, GpuBackend, IsolationPolicy, VmProvisionRequest, VmResources, VmRole,
};
use aegis_core::{Error, ProfileId, Result};
use aegis_ipc::StatusDto;
use chrono::Utc;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};

/// The set of injected capabilities the orchestrator drives. Every field is a
/// trait object so production and test wiring share one code path.
pub struct Capabilities {
    /// VM lifecycle (libvirt/QEMU in production).
    pub vm: Arc<dyn VmController>,
    /// Gateway firewall / tunnel / kill switch (nftables in production).
    pub gateway: Arc<dyn GatewayController>,
    /// Preflight connectivity checklist.
    pub auditor: Arc<dyn NetworkAuditor>,
    /// Browser backend for the full-VM path (hardened Chromium via the guest
    /// channel in production).
    pub browser: Arc<dyn BrowserBackend>,
    /// Browser backend for the reduced host-process path, **Chromium engine**
    /// (hardened Chromium via [`browser_launcher::HostBrowserRunner`], launched
    /// directly on the host). Present only when a host Chromium/Edge browser could
    /// be located; `None` disables the Chromium host-browser mode.
    pub host_browser: Option<Arc<dyn BrowserBackend>>,
    /// The resolved host Chromium executable path, surfaced in the status
    /// snapshot. `None` when no host Chromium browser was located.
    pub host_browser_path: Option<String>,
    /// Browser backend for the reduced host-process path, **Firefox / Tor-Browser
    /// engine** (hardened Firefox via [`browser_launcher::HostBrowserRunner`],
    /// launched directly on the host). Present only when a Firefox / Tor Browser
    /// binary could be located; `None` disables the Firefox host-browser mode.
    pub host_browser_firefox: Option<Arc<dyn BrowserBackend>>,
    /// The resolved host Firefox / Tor-Browser executable path. `None` when none
    /// was located.
    pub host_browser_firefox_path: Option<String>,
    /// Reduced, fail-closed reachability probe for the host-mode proxy.
    pub host_probe: Arc<dyn HostNetworkProbe>,
    /// Profile storage + single-writer lock.
    pub profiles: Arc<dyn ProfileRepository>,
    /// Secure sealing / key generation (ephemeral RAM keys).
    pub secure: Arc<dyn SecureStore>,
    /// Signed update verification/application.
    pub updates: Arc<dyn UpdateClient>,
    /// Append-only, secret-free audit sink.
    pub audit: Arc<dyn AuditSink>,
}

impl std::fmt::Debug for Capabilities {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Trait objects are opaque; print only a stable, secret-free marker.
        f.debug_struct("Capabilities").finish_non_exhaustive()
    }
}

/// A resolved host-mode proxy: the full endpoint the browser is pointed at
/// (`--proxy-server`) plus the bare host/port used for the reachability probe.
#[derive(Debug, Clone, PartialEq, Eq)]
struct HostProxy {
    /// The proxy endpoint given to the browser (e.g. `socks5h://127.0.0.1:9050`).
    endpoint: String,
    /// The host component to TCP-probe.
    probe_host: String,
    /// The port component to TCP-probe.
    probe_port: u16,
}

impl HostProxy {
    /// Parse a `scheme://host:port` endpoint into a [`HostProxy`], keeping the
    /// endpoint verbatim and extracting the host/port for the probe.
    ///
    /// # Errors
    /// Returns [`Error::Config`] if the endpoint has no `host:port` authority or
    /// the port is not a valid `u16`.
    fn parse(endpoint: &str) -> Result<Self> {
        // Strip an optional `scheme://` prefix, then split the trailing :port.
        let authority = endpoint.split("://").last().unwrap_or(endpoint);
        let (host, port) = authority.rsplit_once(':').ok_or_else(|| {
            Error::Config(format!("host proxy '{endpoint}' is missing a host:port"))
        })?;
        let port: u16 = port
            .parse()
            .map_err(|_| Error::Config(format!("host proxy '{endpoint}' has an invalid port")))?;
        if host.is_empty() {
            return Err(Error::Config(format!(
                "host proxy '{endpoint}' is missing a host"
            )));
        }
        Ok(Self {
            endpoint: endpoint.to_string(),
            probe_host: host.to_string(),
            probe_port: port,
        })
    }
}

/// Which browser backend a running session is driven by. This selects the
/// teardown path (VM destroy vs. host process kill + user-data-dir removal).
#[derive(Clone)]
enum SessionMode {
    /// The full-VM path: gateway + browser VMs.
    FullVm,
    /// The reduced host-process path: browser runs on the host through a proxy.
    HostProcess {
        /// The host-side user-data dir. Removed on teardown for ephemeral
        /// sessions so no residue is left on the real OS.
        user_data_dir: std::path::PathBuf,
        /// Whether the profile is ephemeral (its user-data dir is disposable).
        ephemeral: bool,
        /// Which host engine launched the process, so teardown terminates via the
        /// matching backend (Chromium vs. Firefox).
        engine: aegis_core::browser::BrowserBackendId,
    },
}

/// Live state of a session the orchestrator is tracking.
struct SessionEntry {
    profile: ProfileId,
    state: SessionState,
    /// The single-writer profile lease held for this session.
    lease: ProfileLease,
    /// Which backend drives this session (selects the teardown path).
    mode: SessionMode,
    /// Gateway VM id (once provisioned).
    gateway_vm: Option<VmId>,
    /// Browser VM id (once provisioned).
    browser_vm: Option<VmId>,
    /// The running browser handle (once launched).
    browser_handle: Option<BrowserHandle>,
    /// Aggregate protection status from the last preflight.
    protection: ProtectionStatus,
    /// The observed public IP, if preflight produced one.
    public_ip: Option<String>,
    /// The ephemeral RAM key protecting this session's disposable overlays. It
    /// lives only in memory and is dropped (zeroized) on teardown.
    _ram_key: SecretKey,
}

impl SessionEntry {
    fn summary(&self, id: SessionId) -> SessionSummary {
        SessionSummary {
            id,
            profile: self.profile,
            state: self.state,
            protection: self.protection,
            public_ip: self.public_ip.clone(),
        }
    }
}

/// The privileged orchestrator.
///
/// Cheap to `clone` where needed via `Arc`; the session table is shared behind a
/// mutex. Construct with [`Orchestrator::new`].
pub struct Orchestrator {
    caps: Capabilities,
    config: AppConfig,
    /// The live containment policy. Initialized from `config.enforcement` and
    /// mutable at runtime via [`Orchestrator::set_enforcement`]; every session
    /// start reads the *current* value so a policy change takes effect for the
    /// next session without restarting the daemon.
    enforcement: RwLock<Enforcement>,
    sessions: Mutex<HashMap<SessionId, SessionEntry>>,
}

impl std::fmt::Debug for Orchestrator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let tracked = self.sessions.lock().map(|t| t.len()).unwrap_or(0);
        f.debug_struct("Orchestrator")
            .field("tracked_sessions", &tracked)
            .finish_non_exhaustive()
    }
}

impl Orchestrator {
    /// Build an orchestrator from injected [`Capabilities`] and the app config.
    /// The live enforcement policy is initialized from `config.enforcement`.
    #[must_use]
    pub fn new(caps: Capabilities, config: AppConfig) -> Self {
        let enforcement = config.enforcement;
        Self {
            caps,
            config,
            enforcement: RwLock::new(enforcement),
            sessions: Mutex::new(HashMap::new()),
        }
    }

    /// The application configuration.
    #[must_use]
    pub fn config(&self) -> &AppConfig {
        &self.config
    }

    // --- enforcement policy + status -------------------------------------

    /// The current containment [`Enforcement`] policy.
    ///
    /// Falls back to the fully-secure posture if the lock is poisoned, so a
    /// read never relaxes containment.
    #[must_use]
    pub fn get_enforcement(&self) -> Enforcement {
        self.enforcement
            .read()
            .map(|g| *g)
            .unwrap_or_else(|_| Enforcement::secure())
    }

    /// Replace the current containment [`Enforcement`] policy. The new policy
    /// governs the *next* session started; sessions already running are
    /// unaffected.
    ///
    /// # Errors
    /// Returns [`Error::Internal`] if the policy lock is poisoned.
    pub fn set_enforcement(&self, enforcement: Enforcement) -> Result<Enforcement> {
        let mut guard = self
            .enforcement
            .write()
            .map_err(|_| Error::Internal("enforcement lock poisoned".into()))?;
        *guard = enforcement;
        Ok(*guard)
    }

    /// A status snapshot: version, host platform, the isolation level the
    /// current policy yields, the policy itself, and host-browser availability.
    #[must_use]
    pub fn status(&self) -> StatusDto {
        let enforcement = self.get_enforcement();
        StatusDto {
            version: aegis_core::VERSION.to_string(),
            platform: std::env::consts::OS.to_string(),
            isolation_level: enforcement.isolation_level(),
            enforcement,
            host_browser_available: self.caps.host_browser.is_some(),
            host_browser_path: self.caps.host_browser_path.clone(),
        }
    }

    /// Borrow the injected profile repository (used by the IPC handler for the
    /// profile CRUD operations, which are not part of the session machine).
    #[must_use]
    pub fn profiles(&self) -> &Arc<dyn ProfileRepository> {
        &self.caps.profiles
    }

    /// Borrow the injected update client.
    #[must_use]
    pub fn updates(&self) -> &Arc<dyn UpdateClient> {
        &self.caps.updates
    }

    // --- audit helpers ----------------------------------------------------

    /// Record an audit event, tolerating a sink failure (auditing must never
    /// itself abort a teardown). A sink error is only logged, never propagated.
    fn audit(&self, record: AuditRecord) {
        if let Err(e) = self.caps.audit.record(&record) {
            tracing::error!(error = %e, "audit sink write failed");
        }
    }

    /// Record a session-state transition event.
    fn audit_state(&self, session: SessionId, profile: ProfileId, state: SessionState) {
        let name = serde_json::to_value(state)
            .ok()
            .and_then(|v| v.as_str().map(str::to_owned))
            .unwrap_or_else(|| format!("{state:?}"));
        self.audit(
            AuditRecord::new(
                Utc::now(),
                Severity::Info,
                EventKind::SessionState { state: name },
            )
            .with_session(session)
            .with_profile(profile),
        );
    }

    // --- state-machine transition ----------------------------------------

    /// Move a tracked session to `next`, enforcing the allowed transition and
    /// auditing it. Returns [`Error::Internal`] on an illegal transition (a
    /// programming fault) — but note that fail paths still transition to `Failed`
    /// which is always reachable.
    fn transition(&self, id: SessionId, next: SessionState) -> Result<()> {
        let profile = {
            let mut table = self.lock_sessions()?;
            let entry = table
                .get_mut(&id)
                .ok_or_else(|| Error::NotFound(format!("session {id}")))?;
            if !entry.state.can_transition_to(next) {
                return Err(Error::Internal(format!(
                    "illegal session transition {:?} -> {:?}",
                    entry.state, next
                )));
            }
            entry.state = next;
            entry.profile
        };
        self.audit_state(id, profile, next);
        Ok(())
    }

    fn lock_sessions(&self) -> Result<std::sync::MutexGuard<'_, HashMap<SessionId, SessionEntry>>> {
        self.sessions
            .lock()
            .map_err(|_| Error::Internal("session table lock poisoned".into()))
    }

    // --- fail-closed hinge ------------------------------------------------

    /// The central fail-closed helper.
    ///
    /// For any error whose class [`requires_killswitch`](Error::requires_killswitch)
    /// (network-containment or isolation), engage the gateway kill switch and
    /// record a `Critical` [`EventKind::FailClosed`] audit event before returning
    /// the error unchanged. Non-containment errors pass through untouched.
    ///
    /// The kill-switch engage is best-effort: even if it fails, the original
    /// error is still returned (the caller is already tearing down) and the
    /// failure is logged.
    async fn fail_closed(&self, session: Option<SessionId>, err: Error) -> Error {
        if !err.requires_killswitch() {
            return err;
        }
        let class = err.class();
        // Cut traffic first. A secondary failure here does not change the outcome.
        if let Err(ks_err) = self.caps.gateway.engage_killswitch().await {
            tracing::error!(error = %ks_err, "fail-closed: kill switch engage failed");
        }
        let mut record = AuditRecord::new(
            Utc::now(),
            Severity::Critical,
            EventKind::FailClosed {
                class,
                // The error's Display is secret-free by the workspace contract.
                reason: err.to_string(),
            },
        );
        if let Some(id) = session {
            let profile = self
                .lock_sessions()
                .ok()
                .and_then(|t| t.get(&id).map(|e| e.profile));
            record = record.with_session(id);
            if let Some(p) = profile {
                record = record.with_profile(p);
            }
        }
        // Also record a kill-switch event for the diagnostics timeline.
        self.audit(record);
        self.audit(AuditRecord::new(
            Utc::now(),
            Severity::Critical,
            EventKind::KillSwitch {
                state: "engaged".into(),
            },
        ));
        err
    }

    // --- provisioning helpers --------------------------------------------

    /// Build a provision request for one VM of the session.
    fn provision_request(&self, role: VmRole) -> VmProvisionRequest {
        let (backing, resources) = match role {
            VmRole::Gateway => (self.gateway_base_image(), VmResources::gateway()),
            VmRole::Browser => (self.browser_base_image(), VmResources::browser()),
        };
        let instance = InstanceId::new();
        // Disposable overlay lives under the runtime dir (RAM-backed in
        // production). Read-only base + destroy-on-close overlay = disposable.
        let overlay = self
            .config
            .paths
            .runtime_dir
            .join(format!("{}-overlay.qcow2", instance.slug()))
            .to_string_lossy()
            .into_owned();
        VmProvisionRequest {
            instance_id: instance,
            role,
            resources,
            disk: DiskLayer {
                backing_image: backing,
                overlay_path: overlay,
                destroy_on_close: true,
                read_only_root: true,
            },
            gpu: GpuBackend::VirtioGpu,
            isolation: IsolationPolicy::hardened(),
            isolated_network: format!("{}-net", self.config.network_prefix),
        }
    }

    fn gateway_base_image(&self) -> String {
        self.config
            .images
            .as_ref()
            .map(|s| s.gateway.path.to_string_lossy().into_owned())
            .unwrap_or_else(|| {
                self.config
                    .paths
                    .images_dir
                    .join("gateway-base.qcow2")
                    .to_string_lossy()
                    .into_owned()
            })
    }

    fn browser_base_image(&self) -> String {
        self.config
            .images
            .as_ref()
            .map(|s| s.browser.path.to_string_lossy().into_owned())
            .unwrap_or_else(|| {
                self.config
                    .paths
                    .images_dir
                    .join("browser-base.qcow2")
                    .to_string_lossy()
                    .into_owned()
            })
    }

    /// The gateway configuration derived from a profile's network settings.
    fn gateway_config(&self, network: &aegis_core::network::NetworkConfig) -> GatewayConfig {
        GatewayConfig {
            mode: network.mode.clone(),
            dns: network.dns.clone(),
            ipv6: network.ipv6,
            downstream_cidr: "10.152.152.0/24".into(),
            gateway_address: "10.152.152.1".into(),
        }
    }

    // --- public API: session lifecycle -----------------------------------

    /// Start a session for `profile_id`.
    ///
    /// Drives `Requested → Provisioning → GatewayStarting → Preflight →
    /// Browsing`. Acquires the profile single-writer lock first (a `Busy` refusal
    /// is propagated). If preflight does not permit browsing, fails closed: the
    /// kill switch engages, both VMs are destroyed (overlays shredded), the lock
    /// is released, a `Critical` `FailClosed` event is recorded, and a
    /// [`aegis_core::FailureClass::NetworkContainment`] error is returned.
    ///
    /// # Errors
    /// Returns [`Error::Busy`] if the profile is already in use, or a
    /// containment/isolation/system error from any provisioning step.
    pub async fn start_session(&self, profile_id: ProfileId) -> Result<SessionSummary> {
        // Fetch the profile (also proves it exists) before taking the lock.
        let profile = self.caps.profiles.get(&profile_id).await?;

        // Decide the containment mode from the PROFILE's per-profile isolation
        // level, gated by the CURRENT global enforcement policy. A profile that
        // asks for the reduced host-process mode is honoured only when the global
        // `allow_host_browser` safety gate permits it; otherwise the request is
        // refused up front (no lock taken, no teardown needed). The global
        // enforcement is thus the SAFETY GATE, while the profile drives the
        // effective per-session mode.
        let enforcement = self.get_enforcement();
        let host_mode = match profile.spec.isolation {
            IsolationLevel::FullVm => false,
            IsolationLevel::HostProcess => {
                if !enforcement.allow_host_browser {
                    return Err(Error::Config(
                        "host-browser mode is disabled; enable it in advanced settings / config \
                         (config enforcement --host-browser on) before starting a host-isolation \
                         profile"
                            .into(),
                    ));
                }
                // The requested engine's host backend must be wired; if the
                // matching browser was not found, fail with a clear message naming
                // the missing browser (before any lock is taken).
                self.host_backend_for(profile.spec.browser)?;
                true
            }
        };

        // 1. Single-writer lock (spec §8). Busy => refuse, no teardown needed.
        let lease = self.caps.profiles.acquire_lock(&profile_id).await?;

        // From here on, any early return must release the lock. Run the guarded
        // body and, on error, tear down whatever was created.
        let session_id = SessionId::new();

        // Ephemeral RAM key for the disposable overlays (spec §8: random key in
        // RAM). Generating it must not leave the lock dangling.
        let ram_key = match self.caps.secure.generate_key() {
            Ok(k) => k,
            Err(e) => {
                let _ = self.caps.profiles.release_lock(&lease).await;
                return Err(e);
            }
        };

        // Register the session in `Requested`.
        {
            let mut table = self.lock_sessions()?;
            table.insert(
                session_id,
                SessionEntry {
                    profile: profile_id,
                    state: SessionState::Requested,
                    lease: lease.clone(),
                    mode: SessionMode::FullVm,
                    gateway_vm: None,
                    browser_vm: None,
                    browser_handle: None,
                    protection: ProtectionStatus::None,
                    public_ip: None,
                    _ram_key: ram_key,
                },
            );
        }
        self.audit_state(session_id, profile_id, SessionState::Requested);

        let driven = if host_mode {
            self.drive_start_host(session_id, &profile).await
        } else {
            self.drive_start(session_id, &profile).await
        };
        match driven {
            Ok(summary) => Ok(summary),
            Err(e) => {
                // Fail-closed teardown: engage kill switch (if containment),
                // destroy VMs, release lock, drop key. Preserve the original error.
                let err = self.fail_closed(Some(session_id), e).await;
                self.teardown(session_id, /*mark_failed=*/ true).await;
                Err(err)
            }
        }
    }

    /// The guarded happy-path body of [`Self::start_session`]. Any error here is
    /// caught by the caller, which performs the fail-closed teardown.
    async fn drive_start(
        &self,
        session_id: SessionId,
        profile: &aegis_core::profile::Profile,
    ) -> Result<SessionSummary> {
        // 2. Provision gateway + browser VMs.
        self.transition(session_id, SessionState::Provisioning)?;

        let gw_req = self.provision_request(VmRole::Gateway);
        let gw_handle = self.caps.vm.provision(&gw_req).await?;
        self.set_vm(session_id, VmRole::Gateway, gw_handle.id)?;

        let br_req = self.provision_request(VmRole::Browser);
        let br_handle = self.caps.vm.provision(&br_req).await?;
        self.set_vm(session_id, VmRole::Browser, br_handle.id)?;

        // 3. Configure gateway + apply fail-closed firewall.
        self.transition(session_id, SessionState::GatewayStarting)?;
        let gw_cfg = self.gateway_config(&profile.spec.network);
        self.caps.gateway.configure(&gw_cfg).await?;
        self.caps
            .gateway
            .apply_firewall(&FirewallPolicy::fail_closed(&gw_cfg))
            .await?;

        // 4. Start both VMs.
        self.caps.vm.start(&gw_handle.id).await?;
        self.caps.vm.start(&br_handle.id).await?;

        // 5. Preflight connectivity checklist (spec §5).
        self.transition(session_id, SessionState::Preflight)?;
        let ctx = PreflightContext {
            session: session_id,
            gateway_address: gw_cfg.gateway_address.clone(),
            mode_label: gw_cfg.mode.label().to_string(),
            dns: gw_cfg.dns.clone(),
            ipv6: gw_cfg.ipv6,
            // The daemon installs the browser WebRTC policy as part of launch;
            // for preflight it is treated as installed (rendered below), matching
            // the Chromium backend's non-proxied-UDP block.
            webrtc_policy_installed: true,
            host_public_ip: None,
        };
        let checklist = self.caps.auditor.run_preflight(&ctx).await?;

        // Record each check outcome for the diagnostics timeline.
        for report in &checklist.reports {
            let outcome = serde_json::to_value(report.outcome)
                .ok()
                .and_then(|v| v.as_str().map(str::to_owned))
                .unwrap_or_default();
            self.audit(
                AuditRecord::new(
                    Utc::now(),
                    if report.outcome.is_pass() {
                        Severity::Info
                    } else {
                        Severity::Warning
                    },
                    EventKind::PreflightCheck {
                        check: report.id.as_str().to_string(),
                        outcome,
                    },
                )
                .with_session(session_id)
                .with_profile(profile.id),
            );
        }

        // Record the aggregate protection status + observed IP onto the session.
        {
            let mut table = self.lock_sessions()?;
            if let Some(entry) = table.get_mut(&session_id) {
                entry.protection = checklist.status();
                entry.public_ip = checklist.observed_ip.as_ref().map(|o| o.ip.clone());
            }
        }

        // 6. FAIL CLOSED if the checklist does not permit browsing.
        if !checklist.permits_browsing() {
            let failing = checklist
                .failures()
                .iter()
                .map(|c| c.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            return Err(Error::NetworkContainment(format!(
                "preflight did not permit browsing; failing checks: [{failing}]"
            )));
        }

        // 7. Only now: render the browser policy, assert it is safe, and launch.
        self.transition(session_id, SessionState::Browsing)?;
        let launch_req = self.browser_launch_request(session_id, profile, &gw_cfg);
        // render_policy internally calls assert_safe; do it explicitly too so a
        // tampered/forbidden flag is caught before any launch.
        let bundle = self.caps.browser.render_policy(&launch_req)?;
        bundle.assert_safe(launch_req.production)?;
        let handle = self.caps.browser.launch(&launch_req, &bundle).await?;
        self.set_browser_handle(session_id, handle)?;

        // Best-effort: record the launch timestamp on the profile.
        let _ = self
            .caps
            .profiles
            .touch_launch(&profile.id, Utc::now())
            .await;

        let summary = {
            let table = self.lock_sessions()?;
            table
                .get(&session_id)
                .map(|e| e.summary(session_id))
                .ok_or_else(|| Error::Internal("session vanished during start".into()))?
        };
        Ok(summary)
    }

    /// Select the host-process backend for a browser engine, returning a clear
    /// [`Error::Config`] naming the missing browser if that engine's binary was
    /// not located at wiring time.
    fn host_backend_for(
        &self,
        engine: aegis_core::browser::BrowserBackendId,
    ) -> Result<&Arc<dyn BrowserBackend>> {
        use aegis_core::browser::BrowserBackendId;
        match engine {
            BrowserBackendId::Chromium => self.caps.host_browser.as_ref().ok_or_else(|| {
                Error::Config(
                    "this profile requests the Chromium engine in host mode, but no host \
                     Chromium/Edge browser was located; install Chrome/Chromium/Edge or set \
                     AEGIS_BROWSER_BIN"
                        .into(),
                )
            }),
            BrowserBackendId::Firefox => self.caps.host_browser_firefox.as_ref().ok_or_else(|| {
                Error::Config(
                    "this profile requests the Firefox engine in host mode, but no host Firefox / \
                     Tor Browser was located; install Firefox / the Tor Browser bundle or set \
                     AEGIS_FIREFOX_BIN"
                        .into(),
                )
            }),
        }
    }

    /// The guarded happy-path body for the reduced **host-process** mode.
    ///
    /// There is NO VM and NO gateway VM. The browser runs directly on the host,
    /// routed through a host-side proxy determined from the profile's network
    /// mode. Before launching we run a reduced, fail-closed preflight: a plain
    /// TCP reachability probe of the proxy. If the proxy is not listening we
    /// refuse to launch (returning [`Error::NetworkContainment`]) rather than let
    /// the browser fall back to the host's default route. Any error here is
    /// caught by the caller, which performs the fail-closed teardown.
    async fn drive_start_host(
        &self,
        session_id: SessionId,
        profile: &aegis_core::profile::Profile,
    ) -> Result<SessionSummary> {
        // Pick the host backend from the PROFILE's requested engine. If that
        // engine's binary was not found at wiring time, fail with a clear
        // Error::Config naming the missing browser.
        let engine = profile.spec.browser;
        let backend = self.host_backend_for(engine)?;

        // 1. Determine the proxy from the profile's network mode (no gateway VM).
        let proxy = self.host_proxy_endpoint(&profile.spec.network.mode)?;

        // The session state machine still walks Requested → Provisioning →
        // GatewayStarting → Preflight → Browsing. In host mode these steps do NOT
        // provision a VM or a gateway VM; they represent "preparing the host
        // launch". Walking them keeps the state machine (and its audit trail)
        // consistent across both modes.
        self.transition(session_id, SessionState::Provisioning)?;
        self.transition(session_id, SessionState::GatewayStarting)?;

        // 2. Reduced, fail-closed preflight: confirm the proxy is listening.
        self.transition(session_id, SessionState::Preflight)?;
        let reachable = self
            .caps
            .host_probe
            .proxy_reachable(&proxy.probe_host, proxy.probe_port)
            .await?;
        if !reachable {
            // Fail closed: NO browser, network-containment error. The caller's
            // fail_closed hinge records the Critical FailClosed audit event.
            return Err(Error::NetworkContainment(format!(
                "host-mode proxy at {}:{} is not reachable; refusing to launch the host browser \
                 (it would leak onto the host's default route)",
                proxy.probe_host, proxy.probe_port
            )));
        }

        // Record that the reduced-protection preflight passed for diagnostics.
        self.audit(
            AuditRecord::new(
                Utc::now(),
                Severity::Info,
                EventKind::PreflightCheck {
                    check: "host_proxy_reachable".into(),
                    outcome: "pass".into(),
                },
            )
            .with_session(session_id)
            .with_profile(profile.id),
        );

        // In host mode the "protection" is host-process-only; mark it Partial so
        // the UI never shows full protection, and record a NON-tunnel status.
        {
            let mut table = self.lock_sessions()?;
            if let Some(entry) = table.get_mut(&session_id) {
                entry.protection = ProtectionStatus::Partial;
            }
        }

        // 3. Host user-data-dir: fresh per session under runtime_dir/host-profiles.
        let user_data_dir = self
            .config
            .paths
            .runtime_dir
            .join("host-profiles")
            .join(profile.id.to_string());
        let ephemeral = profile.spec.kind.is_ephemeral();
        // Record the mode so teardown terminates the host process and (for
        // ephemeral) removes the user-data dir.
        {
            let mut table = self.lock_sessions()?;
            if let Some(entry) = table.get_mut(&session_id) {
                entry.mode = SessionMode::HostProcess {
                    user_data_dir: user_data_dir.clone(),
                    ephemeral,
                    engine,
                };
            }
        }

        // 4. Render the hardened Chromium policy with the host proxy + host dir,
        //    assert it is safe, and launch on the host.
        self.transition(session_id, SessionState::Browsing)?;
        let launch_req = BrowserLaunchRequest {
            session: session_id,
            profile: profile.id,
            user_data_dir,
            fingerprint: profile.spec.protection.policy(),
            permissions: profile.spec.permissions.clone(),
            proxy_endpoint: proxy.endpoint,
            render_mode: aegis_core::config::RenderMode::Software,
            production: true,
        };
        let bundle = backend.render_policy(&launch_req)?;
        bundle.assert_safe(launch_req.production)?;
        let handle = backend.launch(&launch_req, &bundle).await?;
        self.set_browser_handle(session_id, handle)?;

        // Diagnostics: note the reduced isolation level explicitly (spec §11).
        self.audit(
            AuditRecord::new(
                Utc::now(),
                Severity::Warning,
                EventKind::SessionState {
                    state: format!(
                        "host-process browsing (reduced protection: {})",
                        IsolationLevel::HostProcess.label()
                    ),
                },
            )
            .with_session(session_id)
            .with_profile(profile.id),
        );

        let _ = self
            .caps
            .profiles
            .touch_launch(&profile.id, Utc::now())
            .await;

        let summary = {
            let table = self.lock_sessions()?;
            table
                .get(&session_id)
                .map(|e| e.summary(session_id))
                .ok_or_else(|| Error::Internal("session vanished during host start".into()))?
        };
        Ok(summary)
    }

    /// Resolve the host-mode proxy from a profile's [`NetworkMode`].
    ///
    /// * `Tor` → `socks5h://127.0.0.1:9050` (overridable via `AEGIS_HOST_PROXY`,
    ///   e.g. `socks5h://127.0.0.1:9150` for the Tor Browser bundle).
    /// * `Proxy(cfg)` → the configured `host:port` as a SOCKS5h/HTTP endpoint.
    /// * `Vpn` → [`Error::Unsupported`] (host mode needs Tor or a proxy).
    fn host_proxy_endpoint(&self, mode: &NetworkMode) -> Result<HostProxy> {
        match mode {
            NetworkMode::Tor(_) => {
                let endpoint = std::env::var("AEGIS_HOST_PROXY")
                    .ok()
                    .filter(|s| !s.trim().is_empty())
                    .unwrap_or_else(|| "socks5h://127.0.0.1:9050".to_string());
                HostProxy::parse(&endpoint)
            }
            NetworkMode::Proxy(cfg) => {
                let scheme = match cfg.protocol {
                    aegis_core::network::ProxyProtocol::Socks5 => "socks5h",
                    aegis_core::network::ProxyProtocol::HttpConnect => "http",
                };
                HostProxy::parse(&format!("{}://{}:{}", scheme, cfg.host, cfg.port))
            }
            NetworkMode::Vpn(_) => Err(Error::Unsupported(
                "host mode needs Tor or a proxy, not a VPN".into(),
            )),
        }
    }

    fn browser_launch_request(
        &self,
        session_id: SessionId,
        profile: &aegis_core::profile::Profile,
        gw_cfg: &GatewayConfig,
    ) -> BrowserLaunchRequest {
        BrowserLaunchRequest {
            session: session_id,
            profile: profile.id,
            // Guest-side user-data dir, never a host path.
            user_data_dir: std::path::PathBuf::from("/home/user/.aegis/profile"),
            fingerprint: profile.spec.protection.policy(),
            permissions: profile.spec.permissions.clone(),
            // Route everything through the gateway's downstream address. Tor uses
            // its SOCKS port; otherwise the transparent proxy on the gateway.
            proxy_endpoint: match &gw_cfg.mode {
                aegis_core::network::NetworkMode::Tor(_) => {
                    format!("socks5://{}:9050", gw_cfg.gateway_address)
                }
                _ => format!("socks5://{}:1080", gw_cfg.gateway_address),
            },
            render_mode: aegis_core::config::RenderMode::Software,
            production: true,
        }
    }

    /// Stop (tear down) a running session: terminate the browser, destroy both
    /// VMs (shredding overlays), release the profile lock, and drop the RAM key.
    ///
    /// # Errors
    /// Returns [`Error::NotFound`] if the session is unknown.
    pub async fn stop_session(&self, session_id: SessionId) -> Result<SessionSummary> {
        // Refuse an unknown session up front.
        {
            let table = self.lock_sessions()?;
            if !table.contains_key(&session_id) {
                return Err(Error::NotFound(format!("session {session_id}")));
            }
        }
        // Transition to Closing (from Browsing or any earlier state).
        let _ = self.transition(session_id, SessionState::Closing);
        self.teardown(session_id, /*mark_failed=*/ false).await;
        // Return the final summary (Destroyed) if still tracked; else synthesize.
        let summary = {
            let table = self.lock_sessions()?;
            table.get(&session_id).map(|e| e.summary(session_id))
        };
        summary.ok_or_else(|| Error::NotFound(format!("session {session_id}")))
    }

    /// Tear down whatever was created for a session: terminate the browser,
    /// destroy both VMs (shredding ephemeral overlays), release the profile lock,
    /// and drop the ephemeral key. Best-effort and idempotent — every step
    /// tolerates a failure so teardown always completes and never leaves traffic
    /// permitted. Ends in `Destroyed` (or `Failed` if `mark_failed`).
    async fn teardown(&self, session_id: SessionId, mark_failed: bool) {
        // Snapshot the resources to release without holding the lock across await.
        let (browser_handle, gateway_vm, browser_vm, lease, profile, mode) = {
            let mut table = match self.lock_sessions() {
                Ok(t) => t,
                Err(_) => return,
            };
            let Some(entry) = table.get_mut(&session_id) else {
                return;
            };
            (
                entry.browser_handle.take(),
                entry.gateway_vm,
                entry.browser_vm,
                entry.lease.clone(),
                entry.profile,
                entry.mode.clone(),
            )
        };

        // 1. Terminate the browser process, choosing the backend that launched it
        //    (host process vs. VM guest channel).
        if let Some(handle) = &browser_handle {
            let backend = match &mode {
                SessionMode::HostProcess { engine, .. } => self.host_backend_for(*engine).ok(),
                SessionMode::FullVm => Some(&self.caps.browser),
            };
            match backend {
                Some(backend) => {
                    if let Err(e) = backend.terminate(handle).await {
                        tracing::warn!(error = %e, "teardown: browser terminate failed");
                    }
                }
                None => tracing::warn!("teardown: no host browser backend to terminate handle"),
            }
        }

        // 1b. Host mode: remove the ephemeral host user-data dir so no residue is
        //     left on the real OS. Best-effort; a failure is logged, not fatal.
        if let SessionMode::HostProcess {
            user_data_dir,
            ephemeral: true,
            ..
        } = &mode
        {
            if let Err(e) = tokio::fs::remove_dir_all(user_data_dir).await {
                if e.kind() != std::io::ErrorKind::NotFound {
                    tracing::warn!(error = %e, "teardown: host user-data-dir removal failed");
                }
            }
        }

        // 2. Destroy both VMs (shreds ephemeral overlays; forced power-off first).
        //    In host mode there are none, so this loop is a no-op.
        for (role, vm) in [(VmRole::Browser, browser_vm), (VmRole::Gateway, gateway_vm)] {
            if let Some(id) = vm {
                let _ = self.caps.vm.shutdown(&id, ShutdownMode::Forced).await;
                match self.caps.vm.destroy(&id).await {
                    Ok(report) => {
                        if !report.overlay_shredded {
                            tracing::error!(
                                role = ?role,
                                "teardown: overlay was not shredded"
                            );
                        }
                        self.audit(
                            AuditRecord::new(
                                Utc::now(),
                                Severity::Info,
                                EventKind::Vm {
                                    role: match role {
                                        VmRole::Gateway => "gateway".into(),
                                        VmRole::Browser => "browser".into(),
                                    },
                                    state: "destroyed".into(),
                                },
                            )
                            .with_session(session_id)
                            .with_profile(profile),
                        );
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, role = ?role, "teardown: VM destroy failed")
                    }
                }
            }
        }

        // 3. Release the profile single-writer lock.
        if let Err(e) = self.caps.profiles.release_lock(&lease).await {
            tracing::warn!(error = %e, "teardown: profile lock release failed");
        }

        // 4. Final state. The entry (and its RAM key) is retained in the
        //    terminal state so stop_session can return a summary and the
        //    diagnostics timeline stays complete; the key is dropped/zeroized
        //    when the entry is removed or the daemon exits. All live VM/browser
        //    references are cleared here.
        let final_state = if mark_failed {
            SessionState::Failed
        } else {
            SessionState::Destroyed
        };
        self.audit_state(session_id, profile, final_state);
        if let Ok(mut table) = self.lock_sessions() {
            if let Some(entry) = table.get_mut(&session_id) {
                entry.state = final_state;
                entry.browser_handle = None;
                entry.gateway_vm = None;
                entry.browser_vm = None;
            }
        }
    }

    // --- small setters used by drive_start --------------------------------

    fn set_vm(&self, id: SessionId, role: VmRole, vm: VmId) -> Result<()> {
        let mut table = self.lock_sessions()?;
        let entry = table
            .get_mut(&id)
            .ok_or_else(|| Error::Internal("session vanished".into()))?;
        match role {
            VmRole::Gateway => entry.gateway_vm = Some(vm),
            VmRole::Browser => entry.browser_vm = Some(vm),
        }
        Ok(())
    }

    fn set_browser_handle(&self, id: SessionId, handle: BrowserHandle) -> Result<()> {
        let mut table = self.lock_sessions()?;
        let entry = table
            .get_mut(&id)
            .ok_or_else(|| Error::Internal("session vanished".into()))?;
        entry.browser_handle = Some(handle);
        Ok(())
    }

    // --- read-only views used by the IPC handler -------------------------

    /// A summary of every tracked session.
    #[must_use]
    pub fn list_sessions(&self) -> Vec<SessionSummary> {
        self.lock_sessions()
            .map(|t| t.iter().map(|(id, e)| e.summary(*id)).collect())
            .unwrap_or_default()
    }

    /// The current state of a session, if tracked (used by tests).
    #[must_use]
    pub fn session_state(&self, id: SessionId) -> Option<SessionState> {
        self.lock_sessions()
            .ok()
            .and_then(|t| t.get(&id).map(|e| e.state))
    }
}
