//! Red-team + acceptance: profile isolation and disposable teardown.
//!
//! * §15.15 — two sessions try to open the same *persistent* profile: the second
//!   start must be refused as `Busy` (the single-writer lock, spec §8).
//! * §14 — profile A's data directory is separate from profile B's
//!   ([`profile_store::FileProfileStore`]).
//! * §14 — a disposable (ephemeral) VM leaves no write layer: the vm-controller's
//!   `destroy` returns a clean [`DestroyReport`] (overlay shredded + domain
//!   undefined) driven by a [`vm_controller::MockRunner`].

mod harness;

use std::io::Write as _;
use std::sync::Arc;

use aegis_core::ids::InstanceId;
use aegis_core::profile::ProfileType;
use aegis_core::session::SessionState;
use aegis_core::traits::{ProfileRepository, ShutdownMode, VmController};
use aegis_core::vm::{
    DiskLayer, GpuBackend, IsolationPolicy, VmProvisionRequest, VmResources, VmRole,
};
use aegis_core::{Error, FailureClass};

use harness::{build_harness, make_profile, GatewayMock};
use network_audit::MockProbe;
use profile_store::FileProfileStore;
use vm_controller::{CommandOutput, LibvirtController, MockRunner};

// ---------------------------------------------------------------------------
// §15.15 — two sessions opening the same persistent profile.
// ---------------------------------------------------------------------------

/// §15.15: while a first session holds a persistent profile, a second
/// `start_session` on the same profile is refused as `Busy` (Precondition). When
/// the first releases, a fresh start succeeds again.
#[tokio::test]
async fn s15_15_two_sessions_one_persistent_profile_is_busy() {
    let h = build_harness(MockProbe::all_pass(), GatewayMock::Healthy);
    let profile_id = make_profile(&h.profiles, ProfileType::Persistent).await;

    // First session takes the single-writer lock and reaches Browsing.
    let first = h
        .orch
        .start_session(profile_id)
        .await
        .expect("§15.15: first start ok");
    assert_eq!(first.state, SessionState::Browsing);
    assert!(
        h.profiles.get(&profile_id).await.unwrap().locked,
        "§15.15: profile must be locked while the first session holds it"
    );

    // Second concurrent start on the SAME profile is refused.
    let err = h
        .orch
        .start_session(profile_id)
        .await
        .expect_err("§15.15: second start on the same profile must be refused");
    assert_eq!(err.class(), FailureClass::Precondition);
    assert!(
        matches!(err, Error::Busy(_)),
        "§15.15: expected Busy, got {err:?}"
    );

    // Releasing the first lets a subsequent start succeed again.
    h.orch.stop_session(first.id).await.expect("stop ok");
    assert!(!h.profiles.get(&profile_id).await.unwrap().locked);
    let third = h
        .orch
        .start_session(profile_id)
        .await
        .expect("§15.15: re-start after release ok");
    assert_eq!(third.state, SessionState::Browsing);
    h.orch.stop_session(third.id).await.unwrap();
}

/// §15.15 at the store level: the on-disk single-writer lock is atomic — a second
/// `acquire_lock` on a held profile returns `Busy`, and only the token holder can
/// release it.
#[tokio::test]
async fn s15_15_profile_lock_is_single_writer() {
    let dir = tempfile::tempdir().unwrap();
    let store = FileProfileStore::new(dir.path().join("profiles"));
    let profile = store
        .create(aegis_core::profile::ProfileSpec::ephemeral("locktest"))
        .await
        .unwrap();

    let lease = store
        .acquire_lock(&profile.id)
        .await
        .expect("first lock ok");
    let err = store
        .acquire_lock(&profile.id)
        .await
        .expect_err("§15.15: second acquire must be Busy");
    assert!(matches!(err, Error::Busy(_)));

    // Release with the real lease, then re-acquire succeeds.
    store.release_lock(&lease).await.expect("release ok");
    let _lease2 = store
        .acquire_lock(&profile.id)
        .await
        .expect("re-acquire ok");
}

// ---------------------------------------------------------------------------
// §14 — profile A's data is never mixed with profile B's.
// ---------------------------------------------------------------------------

/// §14 "profil A nie widzi żadnych danych profilu B": each profile gets its own,
/// distinct writable `data/` directory under the store root. Writing into A's
/// data dir does not appear anywhere under B's, and the two paths are disjoint.
#[tokio::test]
async fn acceptance_profile_data_dirs_are_isolated() {
    let dir = tempfile::tempdir().unwrap();
    let store = FileProfileStore::new(dir.path().join("profiles"));

    let a = store
        .create(aegis_core::profile::ProfileSpec::ephemeral("profile-a"))
        .await
        .unwrap();
    let b = store
        .create(aegis_core::profile::ProfileSpec::ephemeral("profile-b"))
        .await
        .unwrap();

    let dir_a = store.profile_data_dir(&a.id);
    let dir_b = store.profile_data_dir(&b.id);

    // The isolated data directories are distinct and neither contains the other.
    assert_ne!(dir_a, dir_b, "§14: profile data dirs must differ");
    assert!(
        !dir_a.starts_with(&dir_b),
        "§14: A's data must not live under B"
    );
    assert!(
        !dir_b.starts_with(&dir_a),
        "§14: B's data must not live under A"
    );
    assert!(
        dir_a.exists() && dir_b.exists(),
        "§14: both data dirs are created"
    );

    // Baseline storage accounting before A writes anything.
    let a_before = store.get(&a.id).await.unwrap().storage.bytes;
    let b_before = store.get(&b.id).await.unwrap().storage.bytes;

    // Write A-only browsing residue; it must never surface under B.
    let secret = dir_a.join("cookies.sqlite");
    {
        let mut f = std::fs::File::create(&secret).unwrap();
        f.write_all(b"profile-A cookies that must never appear under B")
            .unwrap();
    }
    assert!(
        !dir_b.join("cookies.sqlite").exists(),
        "§14: B cannot see A's cookies"
    );

    // A's accounted storage grew by A's write; B's is unchanged — the write is
    // fully contained to A and never leaks into B's isolated tree.
    let a_after = store.get(&a.id).await.unwrap().storage.bytes;
    let b_after = store.get(&b.id).await.unwrap().storage.bytes;
    assert!(
        a_after > a_before,
        "§14: A's own storage must grow with A's write"
    );
    assert_eq!(
        b_after, b_before,
        "§14: B's storage must not change when A writes — no shared/leaked bytes"
    );
}

// ---------------------------------------------------------------------------
// §14 — a disposable VM leaves no write layer after teardown.
// ---------------------------------------------------------------------------

/// §14 "disposable VM po zamknięciu nie pozostawia warstwy zapisu": destroying an
/// ephemeral (`destroy_on_close`) VM shreds its writable qcow2 overlay and
/// undefines the domain, yielding a clean [`DestroyReport`]. Driven over a
/// [`vm_controller::MockRunner`]; a real temp overlay proves the file is removed.
#[tokio::test]
async fn acceptance_disposable_vm_leaves_no_write_layer() {
    // A real temp overlay so we can assert it is gone afterwards.
    let dir = tempfile::tempdir().unwrap();
    let overlay = dir.path().join("browser-overlay.qcow2");
    {
        let mut f = std::fs::File::create(&overlay).unwrap();
        f.write_all(b"writable residue that must not survive")
            .unwrap();
    }
    assert!(overlay.exists());
    let overlay_str = overlay.to_string_lossy().into_owned();

    let mock = Arc::new(MockRunner::new());
    let ctrl = LibvirtController::with_runner(mock.clone());

    let req = VmProvisionRequest {
        instance_id: InstanceId::new(),
        role: VmRole::Browser,
        resources: VmResources::browser(),
        disk: DiskLayer {
            backing_image: "/img/browser-base.qcow2".into(),
            overlay_path: overlay_str,
            destroy_on_close: true,
            read_only_root: true,
        },
        gpu: GpuBackend::VirtioGpu,
        isolation: IsolationPolicy::hardened(),
        isolated_network: "aegis-net-redteam".into(),
    };
    let handle = ctrl.provision(&req).await.expect("provision ok");

    // Forced power-off then destroy, as the orchestrator's teardown does.
    ctrl.shutdown(&handle.id, ShutdownMode::Forced)
        .await
        .unwrap();
    let report = ctrl.destroy(&handle.id).await.expect("destroy ok");

    // The report must be clean: overlay shredded AND domain undefined.
    assert!(report.overlay_shredded, "§14: overlay must be shredded");
    assert!(report.domain_undefined, "§14: domain must be undefined");
    assert!(
        report.is_clean(),
        "§14: DestroyReport must be clean: {report:?}"
    );

    // The writable overlay file is physically gone (no write layer left behind).
    assert!(
        !overlay.exists(),
        "§14: disposable overlay must not survive teardown"
    );

    // And `virsh undefine` was actually issued.
    assert!(
        mock.any_arg_contains("virsh", "undefine")
            || mock.was_called_with("virsh", &["undefine", &handle.domain_name]),
        "§14: teardown must undefine the libvirt domain"
    );
}

/// §14: if the domain cannot be undefined (a stuck domain), the report is NOT
/// clean — the acceptance criterion is only met when the write layer is truly
/// gone. Proves the clean-report assertion above is load-bearing, not vacuous.
#[tokio::test]
async fn acceptance_unclean_teardown_is_reported() {
    let dir = tempfile::tempdir().unwrap();
    let overlay = dir.path().join("overlay.qcow2");
    std::fs::write(&overlay, b"x").unwrap();
    let overlay_str = overlay.to_string_lossy().into_owned();

    // `virsh undefine` fails; everything else succeeds.
    let mock = Arc::new(MockRunner::with_responder(|program, args| {
        if program == "virsh" && args.first().map(String::as_str) == Some("undefine") {
            Ok(CommandOutput::err(1, "domain is still active"))
        } else {
            Ok(CommandOutput::ok(""))
        }
    }));
    let ctrl = LibvirtController::with_runner(mock);

    let req = VmProvisionRequest {
        instance_id: InstanceId::new(),
        role: VmRole::Browser,
        resources: VmResources::browser(),
        disk: DiskLayer {
            backing_image: "/img/browser-base.qcow2".into(),
            overlay_path: overlay_str,
            destroy_on_close: true,
            read_only_root: true,
        },
        gpu: GpuBackend::VirtioGpu,
        isolation: IsolationPolicy::hardened(),
        isolated_network: "aegis-net-redteam".into(),
    };
    let handle = ctrl.provision(&req).await.unwrap();
    let report = ctrl.destroy(&handle.id).await.unwrap();

    assert!(
        !report.domain_undefined,
        "§14: undefine failure must be reported"
    );
    assert!(
        !report.is_clean(),
        "§14: an unclean teardown must not report clean"
    );
    // The overlay is still shredded best-effort even when undefine failed.
    assert!(report.overlay_shredded);
}
