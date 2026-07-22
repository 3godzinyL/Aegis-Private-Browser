//! Integration proof for the Aegis daemon orchestrator, built entirely from
//! MOCKS so it runs green on any host (including this Windows machine).
//!
//! Covered (spec §3, §5, §8, Etap 3):
//!
//! 1. **Happy path** — `start_session` drives `Requested → … → Browsing` with all
//!    preflight checks passing, and `stop_session` tears down (overlays shredded,
//!    profile lock released).
//! 2. **Fail-closed** — a `MockProbe` that fails `DnsRouteVerified` makes
//!    `start_session` refuse to reach `Browsing`, engages the kill switch, records
//!    a `Critical` `FailClosed` audit event, and still tears down cleanly.
//! 3. **Concurrency** — a second concurrent start on the same *persistent* profile
//!    returns `Busy`.
//! 4. **RequestHandler** — `ListProfiles` / `CreateProfile` / `StartSession` map to
//!    the right `Response` variants.

use aegis_core::config::{AppConfig, Enforcement, IsolationLevel};
use aegis_core::events::{EventKind, Severity};
use aegis_core::gateway::KillSwitchState;
use aegis_core::ids::ProfileId;
use aegis_core::network::NetworkConfig;
use aegis_core::profile::{ProfileSpec, ProfileType};
use aegis_core::session::SessionState;
use aegis_core::traits::{
    AuditSink, BrowserBackend, GatewayController, NetworkAuditor, ProfileRepository, SecureStore,
    UpdateClient, VmController,
};
use aegis_core::FailureClass;
use aegis_daemon::{Capabilities, DaemonHandler, HostNetworkProbe, MemoryAuditSink, Orchestrator};
use aegis_ipc::{Request, RequestHandler, Response};
use async_trait::async_trait;
use std::sync::{Arc, Mutex};

use browser_launcher::{ChromiumBackend, FirefoxBackend};
use gateway_controller::NftGatewayController;
use network_audit::{Auditor, MockProbe};
use profile_store::FileProfileStore;
use secure_storage::SecureStorage;
use update_client::{MockTransport, SignedUpdateClient};
use vm_controller::LibvirtController;

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;

/// Everything a test needs to inspect after building an orchestrator.
struct Harness {
    orch: Arc<Orchestrator>,
    audit: Arc<MemoryAuditSink>,
    gateway: Arc<NftGatewayController<gateway_controller::MockRunner>>,
    profiles: Arc<FileProfileStore>,
    _tempdir: tempfile::TempDir,
}

/// A mock [`HostNetworkProbe`] for the host-mode tests: a fixed reachability
/// verdict plus a record of the (host, port) it was asked about.
#[derive(Debug)]
struct MockHostProbe {
    reachable: bool,
    seen: Mutex<Vec<(String, u16)>>,
}

impl MockHostProbe {
    fn new(reachable: bool) -> Self {
        Self {
            reachable,
            seen: Mutex::new(Vec::new()),
        }
    }
}

#[async_trait]
impl HostNetworkProbe for MockHostProbe {
    async fn proxy_reachable(&self, host: &str, port: u16) -> aegis_core::Result<bool> {
        self.seen.lock().unwrap().push((host.to_string(), port));
        Ok(self.reachable)
    }
}

/// Build a fully-mocked orchestrator. `probe` selects the VM-preflight outcome.
/// The host-browser mode is wired with a stub host backend and a reachable host
/// probe by default; [`build_harness_with`] overrides those for host-mode tests.
fn build_harness(probe: MockProbe) -> Harness {
    build_harness_with(probe, true, true)
}

/// Build a mocked orchestrator, choosing whether a host browser backend is
/// present and whether the host proxy probe reports reachable.
fn build_harness_with(probe: MockProbe, host_browser: bool, host_reachable: bool) -> Harness {
    let tempdir = tempfile::tempdir().unwrap();

    // Profile store rooted in a temp dir.
    let profiles = Arc::new(FileProfileStore::new(tempdir.path().join("profiles")));

    // VM controller over a MockRunner where every virsh/qemu-img call succeeds.
    let vm: Arc<dyn VmController> = Arc::new(LibvirtController::with_runner(Arc::new(
        vm_controller::MockRunner::new(),
    )));

    // Gateway controller over a MockRunner tuned so Tor is fully bootstrapped and
    // every backend/probe command succeeds. Keep a typed Arc so tests can read the
    // kill-switch state, and hand a dyn clone to the orchestrator.
    let gw_mock = gateway_controller::MockRunner::new()
        .with(
            "tor-bootstrap",
            gateway_controller::MockResponse::stdout("100"),
        )
        .with("tunnel-probe", gateway_controller::MockResponse::ok());
    let gateway_typed = Arc::new(NftGatewayController::new(gw_mock));
    let gateway: Arc<dyn GatewayController> = gateway_typed.clone();

    // Auditor over the supplied probe.
    let auditor: Arc<dyn NetworkAuditor> = Arc::new(Auditor::new(probe));

    // Browser backend over its own MockRunner.
    let browser: Arc<dyn BrowserBackend> = Arc::new(ChromiumBackend::new(
        browser_launcher::MockRunner::new(),
        "chromium",
        "vm-browser",
    ));

    // Host-mode browser backend over a MockRunner (no real host process): drives
    // the reduced HostProcess launch/teardown path deterministically.
    let host_browser: Option<Arc<dyn BrowserBackend>> = if host_browser {
        Some(Arc::new(ChromiumBackend::new(
            browser_launcher::MockRunner::new(),
            "chromium",
            "host",
        )))
    } else {
        None
    };
    let host_browser_path = if host_browser.is_some() {
        Some("/mock/chrome".to_string())
    } else {
        None
    };

    // Host-mode Firefox backend over a MockRunner. Present whenever the Chromium
    // host backend is (the two engines are resolved independently in production,
    // but the host-mode tests want both engines available).
    let host_browser_firefox: Option<Arc<dyn BrowserBackend>> = if host_browser.is_some() {
        Some(Arc::new(FirefoxBackend::with_runner(
            browser_launcher::MockRunner::new(),
            "firefox",
            "host",
        )))
    } else {
        None
    };
    let host_browser_firefox_path = if host_browser_firefox.is_some() {
        Some("/mock/firefox".to_string())
    } else {
        None
    };
    let host_probe: Arc<dyn HostNetworkProbe> = Arc::new(MockHostProbe::new(host_reachable));

    // Secure storage (OS CSPRNG is fine in tests).
    let secure: Arc<dyn SecureStore> = Arc::new(SecureStorage::new());

    // Update client over a mock transport (unused by session tests, present for
    // completeness of the wiring).
    let sk = SigningKey::generate(&mut OsRng);
    let vk_hex = hex::encode(sk.verifying_key().to_bytes());
    let updates: Arc<dyn UpdateClient> = Arc::new(
        SignedUpdateClient::new("manifest.json", &vk_hex, Arc::new(MockTransport::new())).unwrap(),
    );

    // In-memory audit sink.
    let audit_sink = Arc::new(MemoryAuditSink::new());
    let audit: Arc<dyn AuditSink> = audit_sink.clone();

    let caps = Capabilities {
        vm,
        gateway,
        auditor,
        browser,
        host_browser,
        host_browser_path,
        host_browser_firefox,
        host_browser_firefox_path,
        host_probe,
        profiles: profiles.clone(),
        secure,
        updates,
        audit,
    };
    // Point the config's runtime/images dirs into the temp dir so overlay paths
    // are writable and shredding operates on real temp files.
    let mut config = AppConfig::default();
    config.paths.profiles_dir = tempdir.path().join("profiles");
    config.paths.images_dir = tempdir.path().join("images");
    config.paths.runtime_dir = tempdir.path().join("runtime");
    config.paths.audit_log = tempdir.path().join("audit.jsonl");
    std::fs::create_dir_all(&config.paths.runtime_dir).unwrap();

    let orch = Arc::new(Orchestrator::new(caps, config));

    Harness {
        orch,
        audit: audit_sink,
        gateway: gateway_typed,
        profiles,
        _tempdir: tempdir,
    }
}

async fn make_profile(profiles: &FileProfileStore, kind: ProfileType) -> ProfileId {
    make_profile_with(profiles, kind, IsolationLevel::FullVm).await
}

/// Create a profile pinned to a specific per-profile isolation level. The
/// orchestrator now selects the run mode from this value (gated by the global
/// `allow_host_browser` safety toggle), so host-mode tests build a `HostProcess`
/// profile while VM-mode tests build a `FullVm` one.
async fn make_profile_with(
    profiles: &FileProfileStore,
    kind: ProfileType,
    isolation: IsolationLevel,
) -> ProfileId {
    make_profile_engine(
        profiles,
        kind,
        isolation,
        aegis_core::browser::BrowserBackendId::Chromium,
    )
    .await
}

/// Create a profile pinned to a specific isolation level AND browser engine, so
/// the host-mode tests can drive either the Chromium or Firefox host backend.
async fn make_profile_engine(
    profiles: &FileProfileStore,
    kind: ProfileType,
    isolation: IsolationLevel,
    browser: aegis_core::browser::BrowserBackendId,
) -> ProfileId {
    let spec = ProfileSpec {
        name: "integration".into(),
        kind,
        network: NetworkConfig::default(),
        protection: aegis_core::fingerprint::ProtectionLevel::Balanced,
        isolation,
        browser,
        fingerprint: None,
        permissions: Default::default(),
    };
    profiles.create(spec).await.unwrap().id
}

/// (1) Happy path: start reaches Browsing, stop tears down cleanly.
#[tokio::test]
async fn happy_path_start_reaches_browsing_and_stop_tears_down() {
    let h = build_harness(MockProbe::all_pass());
    let profile_id = make_profile(&h.profiles, ProfileType::Persistent).await;

    let summary = h.orch.start_session(profile_id).await.expect("start ok");
    assert_eq!(summary.state, SessionState::Browsing, "must reach Browsing");
    assert!(summary.protection.permits_browsing());
    assert_eq!(
        h.orch.session_state(summary.id),
        Some(SessionState::Browsing)
    );

    // Kill switch is armed (traffic permitted) while browsing.
    assert_eq!(
        h.gateway.killswitch_state().await.unwrap(),
        KillSwitchState::Armed
    );

    // The profile is locked while the session holds it.
    let locked = h.profiles.get(&profile_id).await.unwrap();
    assert!(locked.locked, "profile must be locked during a session");

    // Tear down.
    let final_summary = h.orch.stop_session(summary.id).await.expect("stop ok");
    assert_eq!(final_summary.state, SessionState::Destroyed);
    assert_eq!(
        h.orch.session_state(summary.id),
        Some(SessionState::Destroyed)
    );

    // Profile lock released.
    let after = h.profiles.get(&profile_id).await.unwrap();
    assert!(!after.locked, "profile lock must be released on teardown");

    // The audit trail contains the Browsing and Destroyed lifecycle events.
    let states: Vec<String> = h
        .audit
        .records()
        .into_iter()
        .filter_map(|r| match r.kind {
            EventKind::SessionState { state } => Some(state),
            _ => None,
        })
        .collect();
    assert!(states.iter().any(|s| s == "browsing"), "states: {states:?}");
    assert!(
        states.iter().any(|s| s == "destroyed"),
        "states: {states:?}"
    );

    // No Critical fail-closed event on the happy path.
    assert!(
        !h.audit
            .records()
            .iter()
            .any(|r| matches!(r.kind, EventKind::FailClosed { .. })),
        "happy path must not record a FailClosed event"
    );
}

/// (2) Fail-closed: a failing DNS route blocks Browsing, engages the kill switch,
/// records a Critical FailClosed audit event, and still tears down.
#[tokio::test]
async fn fail_closed_when_dns_route_fails() {
    let probe = MockProbe {
        dns_route_ok: Ok(false),
        ..MockProbe::all_pass()
    };
    let h = build_harness(probe);
    let profile_id = make_profile(&h.profiles, ProfileType::Persistent).await;

    let err = h
        .orch
        .start_session(profile_id)
        .await
        .expect_err("start must fail closed");
    assert_eq!(
        err.class(),
        FailureClass::NetworkContainment,
        "must be a network-containment failure"
    );
    assert!(err.requires_killswitch());

    // Kill switch is engaged (traffic cut).
    assert_eq!(
        h.gateway.killswitch_state().await.unwrap(),
        KillSwitchState::Engaged
    );

    // A Critical FailClosed audit event was recorded with the right class.
    let fail_closed = h.audit.records().into_iter().find_map(|r| match r.kind {
        EventKind::FailClosed { class, .. } if r.severity == Severity::Critical => Some(class),
        _ => None,
    });
    assert_eq!(
        fail_closed,
        Some(FailureClass::NetworkContainment),
        "expected a Critical FailClosed event"
    );

    // The session ended in Failed and the profile lock was released.
    let after = h.profiles.get(&profile_id).await.unwrap();
    assert!(
        !after.locked,
        "profile lock must be released after fail-closed teardown"
    );

    // The session was never left in Browsing.
    assert!(
        h.orch
            .list_sessions()
            .iter()
            .all(|s| s.state != SessionState::Browsing),
        "no session may be in Browsing after a fail-closed start"
    );
}

/// (3) Concurrency: a second start on the same persistent profile returns Busy
/// while the first session holds the single-writer lock.
#[tokio::test]
async fn second_concurrent_start_on_persistent_profile_is_busy() {
    let h = build_harness(MockProbe::all_pass());
    let profile_id = make_profile(&h.profiles, ProfileType::Persistent).await;

    // First session succeeds and holds the lock.
    let first = h
        .orch
        .start_session(profile_id)
        .await
        .expect("first start ok");
    assert_eq!(first.state, SessionState::Browsing);

    // Second start on the SAME profile must be refused as Busy.
    let err = h
        .orch
        .start_session(profile_id)
        .await
        .expect_err("second start must be refused");
    assert_eq!(err.class(), FailureClass::Precondition);
    assert!(
        matches!(err, aegis_core::Error::Busy(_)),
        "expected Busy, got {err:?}"
    );

    // Cleanup releases the lock; a subsequent start then succeeds again.
    h.orch.stop_session(first.id).await.unwrap();
    let third = h
        .orch
        .start_session(profile_id)
        .await
        .expect("re-start after release ok");
    assert_eq!(third.state, SessionState::Browsing);
    h.orch.stop_session(third.id).await.unwrap();
}

/// (4) RequestHandler maps the core operations to the right responses.
#[tokio::test]
async fn request_handler_maps_operations() {
    let h = build_harness(MockProbe::all_pass());
    let handler = DaemonHandler::new(Arc::clone(&h.orch));

    // ListProfiles on an empty store => Profiles([]).
    match handler.handle(Request::ListProfiles).await {
        Response::Profiles(ps) => assert!(ps.is_empty(), "no profiles yet"),
        other => panic!("expected Profiles, got {other:?}"),
    }

    // CreateProfile => Profile(..).
    let spec = ProfileSpec::ephemeral("via-handler");
    let created = match handler.handle(Request::CreateProfile(spec)).await {
        Response::Profile(p) => p,
        other => panic!("expected Profile, got {other:?}"),
    };

    // ListProfiles now returns the created profile.
    match handler.handle(Request::ListProfiles).await {
        Response::Profiles(ps) => assert_eq!(ps.len(), 1),
        other => panic!("expected Profiles, got {other:?}"),
    }

    // StartSession => Session(summary in Browsing).
    let start_req = aegis_core::session::SessionRequest {
        profile: created.id,
        unlock_ref: None,
    };
    let session_id = match handler.handle(Request::StartSession(start_req)).await {
        Response::Session(s) => {
            assert_eq!(s.state, SessionState::Browsing);
            assert_eq!(s.profile, created.id);
            s.id
        }
        other => panic!("expected Session, got {other:?}"),
    };

    // ListSessions reflects the running session.
    match handler.handle(Request::ListSessions).await {
        Response::Sessions(ss) => assert!(ss.iter().any(|s| s.id == session_id)),
        other => panic!("expected Sessions, got {other:?}"),
    }

    // StopSession => Session(Destroyed).
    match handler.handle(Request::StopSession(session_id)).await {
        Response::Session(s) => assert_eq!(s.state, SessionState::Destroyed),
        other => panic!("expected Session, got {other:?}"),
    }
}

/// Extra: an ephemeral profile also gets locked/released (single-writer applies
/// to both kinds), and a fail-closed teardown never leaves the kill switch armed.
#[tokio::test]
async fn ephemeral_profile_start_stop_roundtrip() {
    let h = build_harness(MockProbe::all_pass());
    let profile_id = make_profile(&h.profiles, ProfileType::Ephemeral).await;
    let summary = h.orch.start_session(profile_id).await.expect("start ok");
    assert_eq!(summary.state, SessionState::Browsing);
    h.orch.stop_session(summary.id).await.expect("stop ok");
    let after = h.profiles.get(&profile_id).await.unwrap();
    assert!(!after.locked);
}

// --- host-browser (reduced HostProcess) mode --------------------------------

/// Host mode with a REACHABLE proxy reaches Browsing without provisioning any VM,
/// and the status reports HostProcess isolation.
#[tokio::test]
async fn host_mode_with_reachable_proxy_reaches_browsing() {
    let h = build_harness_with(
        MockProbe::all_pass(),
        /*host_browser=*/ true,
        /*reachable=*/ true,
    );
    // Open the global host-browser safety gate at runtime (the profile drives
    // the effective mode; enforcement only permits it).
    h.orch
        .set_enforcement(Enforcement::host_browser())
        .expect("set enforcement");
    assert_eq!(
        h.orch.status().isolation_level,
        IsolationLevel::HostProcess,
        "status must report reduced HostProcess isolation"
    );

    // A HostProcess profile drives the reduced host-process run mode.
    let profile_id = make_profile_with(
        &h.profiles,
        ProfileType::Ephemeral,
        IsolationLevel::HostProcess,
    )
    .await;
    let summary = h
        .orch
        .start_session(profile_id)
        .await
        .expect("host start ok");
    assert_eq!(
        summary.state,
        SessionState::Browsing,
        "host mode must reach Browsing when the proxy is reachable"
    );

    // No Critical FailClosed event on the reachable host path.
    assert!(
        !h.audit
            .records()
            .iter()
            .any(|r| matches!(r.kind, EventKind::FailClosed { .. })),
        "reachable host path must not fail closed"
    );

    // Teardown: host process terminated, profile lock released.
    let final_summary = h.orch.stop_session(summary.id).await.expect("host stop ok");
    assert_eq!(final_summary.state, SessionState::Destroyed);
    let after = h.profiles.get(&profile_id).await.unwrap();
    assert!(
        !after.locked,
        "profile lock must be released on host teardown"
    );
}

/// Host mode with a **Firefox** profile drives the Firefox host backend, reaches
/// Browsing, and writes a `user.js` into the host user-data dir whose prefs route
/// through the SOCKS proxy (proving the engine was selected from `spec.browser`).
#[tokio::test]
async fn host_mode_firefox_profile_writes_user_js_with_socks_proxy() {
    let h = build_harness_with(
        MockProbe::all_pass(),
        /*host_browser=*/ true,
        /*reachable=*/ true,
    );
    h.orch
        .set_enforcement(Enforcement::host_browser())
        .expect("set enforcement");

    // A HostProcess profile that requests the Firefox engine.
    let profile_id = make_profile_engine(
        &h.profiles,
        ProfileType::Ephemeral,
        IsolationLevel::HostProcess,
        aegis_core::browser::BrowserBackendId::Firefox,
    )
    .await;

    let summary = h
        .orch
        .start_session(profile_id)
        .await
        .expect("firefox host start ok");
    assert_eq!(
        summary.state,
        SessionState::Browsing,
        "firefox host mode must reach Browsing"
    );

    // Before launch the backend wrote user.js into the host user-data dir
    // (runtime_dir/host-profiles/<profile_id>). Its prefs must contain the SOCKS
    // proxy routing (port parsed from the Tor host endpoint, 9050) and WebRTC off.
    let user_js_path = h
        .orch
        .config()
        .paths
        .runtime_dir
        .join("host-profiles")
        .join(profile_id.to_string())
        .join("user.js");
    let user_js = std::fs::read_to_string(&user_js_path)
        .unwrap_or_else(|e| panic!("user.js at {} must exist: {e}", user_js_path.display()));
    assert!(
        user_js.contains(r#"user_pref("network.proxy.type", 1);"#),
        "user.js must enable manual proxy: {user_js}"
    );
    assert!(
        user_js.contains(r#"user_pref("network.proxy.socks_port", 9050);"#),
        "user.js must route through the SOCKS proxy port: {user_js}"
    );
    assert!(
        user_js.contains(r#"user_pref("media.peerconnection.enabled", false);"#),
        "user.js must disable WebRTC: {user_js}"
    );
    assert!(
        user_js.contains(r#"user_pref("privacy.resistFingerprinting", true);"#),
        "user.js must enable resistFingerprinting: {user_js}"
    );

    // Teardown succeeds via the Firefox backend and removes the ephemeral dir.
    let final_summary = h
        .orch
        .stop_session(summary.id)
        .await
        .expect("firefox host stop ok");
    assert_eq!(final_summary.state, SessionState::Destroyed);
    let after = h.profiles.get(&profile_id).await.unwrap();
    assert!(
        !after.locked,
        "profile lock must be released on host teardown"
    );
}

/// A Firefox host profile is refused with a clear Config error naming the missing
/// browser when the Firefox engine's binary was not located at wiring time.
#[tokio::test]
async fn host_mode_firefox_missing_binary_fails_with_named_config_error() {
    // Build a harness with NO host browsers wired at all.
    let h = build_harness_with(
        MockProbe::all_pass(),
        /*host_browser=*/ false,
        /*reachable=*/ true,
    );
    h.orch
        .set_enforcement(Enforcement::host_browser())
        .expect("set enforcement");

    let profile_id = make_profile_engine(
        &h.profiles,
        ProfileType::Ephemeral,
        IsolationLevel::HostProcess,
        aegis_core::browser::BrowserBackendId::Firefox,
    )
    .await;
    let err = h
        .orch
        .start_session(profile_id)
        .await
        .expect_err("missing firefox must be refused");
    assert_eq!(err.class(), FailureClass::Configuration);
    assert!(
        err.to_string().contains("Firefox"),
        "error must name the missing Firefox browser, got: {err}"
    );
    // Refused before any lock was taken.
    let after = h.profiles.get(&profile_id).await.unwrap();
    assert!(!after.locked, "a refused start must not hold the lock");
}

/// Host mode with an UNREACHABLE proxy fails closed: no Browsing, a Critical
/// FailClosed audit event, and the lock released.
#[tokio::test]
async fn host_mode_with_unreachable_proxy_fails_closed() {
    let h = build_harness_with(
        MockProbe::all_pass(),
        /*host_browser=*/ true,
        /*reachable=*/ false,
    );
    h.orch
        .set_enforcement(Enforcement::host_browser())
        .expect("set enforcement");

    let profile_id = make_profile_with(
        &h.profiles,
        ProfileType::Ephemeral,
        IsolationLevel::HostProcess,
    )
    .await;
    let err = h
        .orch
        .start_session(profile_id)
        .await
        .expect_err("unreachable proxy must fail closed");
    assert_eq!(
        err.class(),
        FailureClass::NetworkContainment,
        "unreachable host proxy is a network-containment failure"
    );

    // A Critical FailClosed audit event with the network-containment class.
    let fail_closed = h.audit.records().into_iter().find_map(|r| match r.kind {
        EventKind::FailClosed { class, .. } if r.severity == Severity::Critical => Some(class),
        _ => None,
    });
    assert_eq!(fail_closed, Some(FailureClass::NetworkContainment));

    // Never reached Browsing; lock released.
    assert!(
        h.orch
            .list_sessions()
            .iter()
            .all(|s| s.state != SessionState::Browsing),
        "no session may be Browsing after a fail-closed host start"
    );
    let after = h.profiles.get(&profile_id).await.unwrap();
    assert!(!after.locked);
}

/// A HostProcess profile is refused up front when the global `allow_host_browser`
/// safety gate is closed (the default secure posture). The refusal is a
/// Configuration error and no session is left tracked/Browsing.
#[tokio::test]
async fn host_profile_refused_when_host_browser_disabled() {
    let h = build_harness(MockProbe::all_pass());
    // Default enforcement keeps allow_host_browser = false (the safety gate).
    assert!(!h.orch.get_enforcement().allow_host_browser);

    let profile_id = make_profile_with(
        &h.profiles,
        ProfileType::Ephemeral,
        IsolationLevel::HostProcess,
    )
    .await;
    let err = h
        .orch
        .start_session(profile_id)
        .await
        .expect_err("host profile must be refused when host-browser is disabled");
    assert_eq!(err.class(), FailureClass::Configuration);
    assert!(
        err.to_string().contains("host-browser mode is disabled"),
        "expected a clear disabled message, got: {err}"
    );

    // The profile lock must not be held (refused before any lock was taken).
    let after = h.profiles.get(&profile_id).await.unwrap();
    assert!(!after.locked, "a refused start must not hold the lock");
    assert!(
        h.orch
            .list_sessions()
            .iter()
            .all(|s| s.state != SessionState::Browsing),
        "a refused host profile must never reach Browsing"
    );
}

/// A FullVm profile ignores the host-browser gate and always uses the VM path,
/// reaching Browsing even when `allow_host_browser` happens to be enabled.
#[tokio::test]
async fn fullvm_profile_uses_vm_path_regardless_of_gate() {
    let h = build_harness(MockProbe::all_pass());
    // Even with the host-browser gate open, a FullVm profile takes the VM path.
    h.orch
        .set_enforcement(Enforcement::host_browser())
        .expect("set enforcement");

    let profile_id =
        make_profile_with(&h.profiles, ProfileType::Persistent, IsolationLevel::FullVm).await;
    let summary = h
        .orch
        .start_session(profile_id)
        .await
        .expect("full-vm start ok");
    assert_eq!(summary.state, SessionState::Browsing);

    // The VM path provisions gateway + browser VMs, so a gateway/vm destroy
    // event appears on teardown (the host path never touches a VM).
    let final_summary = h.orch.stop_session(summary.id).await.expect("stop ok");
    assert_eq!(final_summary.state, SessionState::Destroyed);
    let vm_events = h
        .audit
        .records()
        .into_iter()
        .filter(|r| matches!(r.kind, EventKind::Vm { .. }))
        .count();
    assert!(
        vm_events >= 1,
        "the VM path must destroy at least one VM on teardown"
    );
}

/// set_enforcement then get_enforcement round-trips, and status reports the host
/// platform string.
#[tokio::test]
async fn set_then_get_enforcement_round_trips_and_status_reports_platform() {
    let h = build_harness(MockProbe::all_pass());
    // Default is the secure posture.
    assert!(h.orch.get_enforcement().is_full_isolation());

    let applied = h
        .orch
        .set_enforcement(Enforcement::host_browser())
        .expect("set");
    assert_eq!(applied, Enforcement::host_browser());
    assert_eq!(h.orch.get_enforcement(), Enforcement::host_browser());

    let status = h.orch.status();
    assert_eq!(status.platform, std::env::consts::OS);
    assert_eq!(status.version, aegis_core::VERSION);
    assert_eq!(status.isolation_level, IsolationLevel::HostProcess);
    assert!(status.host_browser_available);
    assert_eq!(status.host_browser_path.as_deref(), Some("/mock/chrome"));
}

/// The set/get enforcement operations also round-trip through the RequestHandler.
#[tokio::test]
async fn request_handler_get_set_enforcement_and_status() {
    let h = build_harness(MockProbe::all_pass());
    let handler = DaemonHandler::new(Arc::clone(&h.orch));

    // GetEnforcement returns the initial secure posture.
    match handler.handle(Request::GetEnforcement).await {
        Response::Enforcement(e) => assert!(e.is_full_isolation()),
        other => panic!("expected Enforcement, got {other:?}"),
    }

    // SetEnforcement to host-browser and read it back.
    match handler
        .handle(Request::SetEnforcement(Enforcement::host_browser()))
        .await
    {
        Response::Enforcement(e) => assert_eq!(e, Enforcement::host_browser()),
        other => panic!("expected Enforcement, got {other:?}"),
    }

    // GetStatus reflects the change.
    match handler.handle(Request::GetStatus).await {
        Response::Status(s) => {
            assert_eq!(s.isolation_level, IsolationLevel::HostProcess);
            assert_eq!(s.platform, std::env::consts::OS);
        }
        other => panic!("expected Status, got {other:?}"),
    }
}
