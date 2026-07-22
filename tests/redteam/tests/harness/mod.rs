//! Shared mock-wired [`Orchestrator`] builder for the red-team scenarios.
//!
//! This mirrors `crates/aegis-daemon/tests/integration.rs` so the end-to-end
//! scenarios drive the *real* orchestrator over entirely in-memory mocks — no
//! VMs, no root, no network — and therefore run green on this Windows machine.
//!
//! Each integration-test file includes this module with `mod harness;`. Because
//! integration tests each compile as their own crate, a helper that a particular
//! file does not use would trip `dead_code`; everything here is marked
//! `#![allow(dead_code)]` at the module root for that reason.

#![allow(dead_code)]

use std::sync::Arc;

use aegis_core::config::AppConfig;
use aegis_core::ids::ProfileId;
use aegis_core::network::NetworkConfig;
use aegis_core::profile::{ProfileSpec, ProfileType};
use aegis_core::traits::{
    AuditSink, BrowserBackend, GatewayController, NetworkAuditor, ProfileRepository, SecureStore,
    UpdateClient, VmController,
};
use aegis_daemon::{Capabilities, HostNetworkProbe, MemoryAuditSink, Orchestrator, TcpHostProbe};

use browser_launcher::ChromiumBackend;
use gateway_controller::{MockResponse, NftGatewayController};
use network_audit::{Auditor, MockProbe};
use profile_store::FileProfileStore;
use secure_storage::SecureStorage;
use update_client::{MockTransport, SignedUpdateClient};
use vm_controller::LibvirtController;

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;

/// Everything a red-team test needs to inspect after building an orchestrator.
pub struct Harness {
    /// The mock-wired orchestrator under test.
    pub orch: Arc<Orchestrator>,
    /// The in-memory audit sink (assert `FailClosed` / lifecycle events).
    pub audit: Arc<MemoryAuditSink>,
    /// Typed gateway controller (read kill-switch state directly).
    pub gateway: Arc<NftGatewayController<gateway_controller::MockRunner>>,
    /// The profile store (create profiles, inspect locks).
    pub profiles: Arc<FileProfileStore>,
    _tempdir: tempfile::TempDir,
}

/// How the gateway's underlying command runner should behave.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum GatewayMock {
    /// Every backend command and probe succeeds; Tor fully bootstrapped.
    Healthy,
    /// `nft` load fails: the firewall/kill-switch ruleset cannot be applied, so
    /// there is no working kill switch (spec §15.16).
    NftBroken,
}

/// Build a fully-mocked orchestrator. `probe` selects the preflight outcome and
/// `gw` selects whether the gateway's nft/kill-switch path works.
pub fn build_harness(probe: MockProbe, gw: GatewayMock) -> Harness {
    let tempdir = tempfile::tempdir().unwrap();

    // Profile store rooted in a temp dir.
    let profiles = Arc::new(FileProfileStore::new(tempdir.path().join("profiles")));

    // VM controller over a MockRunner where every virsh/qemu-img call succeeds.
    let vm: Arc<dyn VmController> = Arc::new(LibvirtController::with_runner(Arc::new(
        vm_controller::MockRunner::new(),
    )));

    // Gateway controller over a MockRunner. In the healthy configuration every
    // backend/probe command succeeds and Tor is fully bootstrapped. In the
    // NftBroken configuration the `nft` program returns a non-zero exit, so
    // apply_firewall (and the kill-switch load) fails — modelling a host whose
    // kill switch cannot be armed (spec §15.16).
    let mut gw_mock = gateway_controller::MockRunner::new()
        .with("tor-bootstrap", MockResponse::stdout("100"))
        .with("tunnel-probe", MockResponse::ok());
    if gw == GatewayMock::NftBroken {
        gw_mock = gw_mock.with("nft", MockResponse::failure(1, "nft: permission denied"));
    }
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

    // Secure storage (OS CSPRNG is fine in tests).
    let secure: Arc<dyn SecureStore> = Arc::new(SecureStorage::new());

    // Update client over a mock transport (present for wiring completeness).
    let sk = SigningKey::generate(&mut OsRng);
    let vk_hex = hex::encode(sk.verifying_key().to_bytes());
    let updates: Arc<dyn UpdateClient> = Arc::new(
        SignedUpdateClient::new("manifest.json", &vk_hex, Arc::new(MockTransport::new())).unwrap(),
    );

    // In-memory audit sink.
    let audit_sink = Arc::new(MemoryAuditSink::new());
    let audit: Arc<dyn AuditSink> = audit_sink.clone();

    // The red-team scenarios exercise the full-VM path (default secure
    // enforcement), so the host-browser fields are never reached. Wire a
    // disabled host browser and a (never-consulted) real probe for completeness.
    let host_probe: Arc<dyn HostNetworkProbe> = Arc::new(TcpHostProbe::default());

    let caps = Capabilities {
        vm,
        gateway,
        auditor,
        browser,
        host_browser: None,
        host_browser_path: None,
        host_browser_firefox: None,
        host_browser_firefox_path: None,
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

/// Convenience: a healthy gateway with the caller-supplied preflight probe.
pub fn harness_with_probe(probe: MockProbe) -> Harness {
    build_harness(probe, GatewayMock::Healthy)
}

/// Create a profile of the given kind in the store and return its id.
pub async fn make_profile(profiles: &FileProfileStore, kind: ProfileType) -> ProfileId {
    let spec = ProfileSpec {
        name: "redteam".into(),
        kind,
        network: NetworkConfig::default(),
        protection: aegis_core::fingerprint::ProtectionLevel::Balanced,
        isolation: aegis_core::config::IsolationLevel::FullVm,
        browser: aegis_core::browser::BrowserBackendId::Chromium,
        fingerprint: None,
        permissions: Default::default(),
    };
    profiles.create(spec).await.unwrap().id
}

/// Whether the audit trail recorded a `Critical` `FailClosed` event of the given
/// failure class. Used across the network scenarios (spec §15).
pub fn recorded_critical_fail_closed(
    audit: &MemoryAuditSink,
    class: aegis_core::FailureClass,
) -> bool {
    use aegis_core::events::{EventKind, Severity};
    audit.records().into_iter().any(|r| {
        r.severity == Severity::Critical
            && matches!(r.kind, EventKind::FailClosed { class: c, .. } if c == class)
    })
}

/// The set of session-state names that appear in the audit trail (e.g.
/// `"browsing"`, `"destroyed"`, `"failed"`).
pub fn recorded_states(audit: &MemoryAuditSink) -> Vec<String> {
    use aegis_core::events::EventKind;
    audit
        .records()
        .into_iter()
        .filter_map(|r| match r.kind {
            EventKind::SessionState { state } => Some(state),
            _ => None,
        })
        .collect()
}
