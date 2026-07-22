//! End-to-end tests for [`profile_store::FileProfileStore`] against a real
//! temporary directory. These exercise the required scenarios from the task
//! spec (§8): create->get->list roundtrip, patch persistence, delete, the
//! single-writer lock (double acquire => Busy, release then re-acquire),
//! per-profile data isolation, and ephemeral vs persistent persistence.

use aegis_core::fingerprint::ProtectionLevel;
use aegis_core::network::{NetworkConfig, NetworkMode, ProxyConfig, ProxyProtocol};
use aegis_core::permissions::{Feature, PermissionPolicy, PermissionState};
use aegis_core::profile::{ProfilePatch, ProfileSpec, ProfileType};
use aegis_core::traits::ProfileRepository;
use aegis_core::{Error, ProfileId};
use chrono::Utc;
use profile_store::FileProfileStore;

fn ephemeral_spec(name: &str) -> ProfileSpec {
    ProfileSpec::ephemeral(name)
}

fn persistent_spec(name: &str) -> ProfileSpec {
    let mut spec = ProfileSpec::ephemeral(name);
    spec.kind = ProfileType::Persistent;
    spec
}

#[tokio::test]
async fn create_get_list_roundtrip() {
    let tmp = tempfile::tempdir().unwrap();
    let store = FileProfileStore::new(tmp.path());

    let created = store.create(ephemeral_spec("shopping")).await.unwrap();
    assert_eq!(created.spec.name, "shopping");
    assert!(!created.locked);
    assert_eq!(created.last_launched, None);

    let fetched = store.get(&created.id).await.unwrap();
    assert_eq!(fetched.id, created.id);
    assert_eq!(fetched.spec, created.spec);
    assert_eq!(fetched.created_at, created.created_at);

    let list = store.list().await.unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].id, created.id);
}

#[tokio::test]
async fn list_returns_all_profiles_newest_first() {
    let tmp = tempfile::tempdir().unwrap();
    let store = FileProfileStore::new(tmp.path());

    let a = store.create(ephemeral_spec("a")).await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    let b = store.create(ephemeral_spec("b")).await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    let c = store.create(ephemeral_spec("c")).await.unwrap();

    let ids: Vec<_> = store
        .list()
        .await
        .unwrap()
        .into_iter()
        .map(|p| p.id)
        .collect();
    assert_eq!(ids.len(), 3);
    assert_eq!(ids, vec![c.id, b.id, a.id], "newest first");
}

#[tokio::test]
async fn get_missing_profile_is_not_found() {
    let tmp = tempfile::tempdir().unwrap();
    let store = FileProfileStore::new(tmp.path());
    let err = store.get(&ProfileId::new()).await.unwrap_err();
    assert!(matches!(err, Error::NotFound(_)), "got {err:?}");
}

#[tokio::test]
async fn list_on_empty_root_is_empty() {
    let tmp = tempfile::tempdir().unwrap();
    // Point at a subdir that does not exist yet.
    let store = FileProfileStore::new(tmp.path().join("nonexistent"));
    assert!(store.list().await.unwrap().is_empty());
}

#[tokio::test]
async fn update_patch_persists() {
    let tmp = tempfile::tempdir().unwrap();
    let store = FileProfileStore::new(tmp.path());
    let created = store.create(ephemeral_spec("old-name")).await.unwrap();

    // Build a patch that changes name, protection, network, and permissions.
    let mut perms = PermissionPolicy::secure_default();
    perms
        .defaults
        .insert(Feature::Notifications, PermissionState::Ask);

    let patch = ProfilePatch {
        name: Some("new-name".into()),
        network: Some(NetworkConfig::from_mode(NetworkMode::Proxy(ProxyConfig {
            protocol: ProxyProtocol::Socks5,
            host: "10.0.0.1".into(),
            port: 1080,
            credentials_ref: None,
            remote_dns: true,
        }))),
        protection: Some(ProtectionLevel::Strict),
        permissions: Some(perms.clone()),
    };

    let updated = store.update(&created.id, patch).await.unwrap();
    assert_eq!(updated.spec.name, "new-name");
    assert_eq!(updated.spec.protection, ProtectionLevel::Strict);
    assert_eq!(updated.spec.network.mode.label(), "Proxy");
    assert_eq!(
        updated
            .spec
            .permissions
            .defaults
            .get(&Feature::Notifications),
        Some(&PermissionState::Ask)
    );

    // Persisted across a fresh store instance pointed at the same root.
    let store2 = FileProfileStore::new(tmp.path());
    let reloaded = store2.get(&created.id).await.unwrap();
    assert_eq!(reloaded.spec.name, "new-name");
    assert_eq!(reloaded.spec.protection, ProtectionLevel::Strict);
    assert_eq!(reloaded.spec.network.mode.label(), "Proxy");
}

#[tokio::test]
async fn empty_patch_is_noop_but_returns_profile() {
    let tmp = tempfile::tempdir().unwrap();
    let store = FileProfileStore::new(tmp.path());
    let created = store.create(ephemeral_spec("x")).await.unwrap();
    let updated = store
        .update(&created.id, ProfilePatch::default())
        .await
        .unwrap();
    assert_eq!(updated.spec, created.spec);
}

#[tokio::test]
async fn update_rejects_invalid_patch() {
    let tmp = tempfile::tempdir().unwrap();
    let store = FileProfileStore::new(tmp.path());
    let created = store.create(ephemeral_spec("x")).await.unwrap();

    // A blank name is invalid; the patch must be rejected and NOT persisted.
    let patch = ProfilePatch {
        name: Some("   ".into()),
        ..Default::default()
    };
    let err = store.update(&created.id, patch).await.unwrap_err();
    assert!(matches!(err, Error::Config(_)), "got {err:?}");

    // Original name is intact.
    let reloaded = store.get(&created.id).await.unwrap();
    assert_eq!(reloaded.spec.name, "x");
}

#[tokio::test]
async fn update_missing_profile_is_not_found() {
    let tmp = tempfile::tempdir().unwrap();
    let store = FileProfileStore::new(tmp.path());
    let err = store
        .update(&ProfileId::new(), ProfilePatch::default())
        .await
        .unwrap_err();
    assert!(matches!(err, Error::NotFound(_)), "got {err:?}");
}

#[tokio::test]
async fn create_rejects_invalid_spec() {
    let tmp = tempfile::tempdir().unwrap();
    let store = FileProfileStore::new(tmp.path());
    let mut spec = ephemeral_spec("ok");
    spec.name = "   ".into();
    let err = store.create(spec).await.unwrap_err();
    assert!(matches!(err, Error::Config(_)), "got {err:?}");
    // Nothing was persisted.
    assert!(store.list().await.unwrap().is_empty());
}

#[tokio::test]
async fn delete_removes_profile_and_data() {
    let tmp = tempfile::tempdir().unwrap();
    let store = FileProfileStore::new(tmp.path());
    let created = store.create(ephemeral_spec("temp")).await.unwrap();

    // Drop some data into the profile's data dir to prove it is shredded too.
    let data_dir = store.profile_data_dir(&created.id);
    tokio::fs::write(data_dir.join("state.bin"), b"browser-state")
        .await
        .unwrap();

    store.delete(&created.id).await.unwrap();

    // Directory is gone.
    assert!(!tmp.path().join(created.id.to_string()).exists());
    // And get now reports NotFound.
    let err = store.get(&created.id).await.unwrap_err();
    assert!(matches!(err, Error::NotFound(_)), "got {err:?}");
    assert!(store.list().await.unwrap().is_empty());
}

#[tokio::test]
async fn delete_missing_profile_is_not_found() {
    let tmp = tempfile::tempdir().unwrap();
    let store = FileProfileStore::new(tmp.path());
    let err = store.delete(&ProfileId::new()).await.unwrap_err();
    assert!(matches!(err, Error::NotFound(_)), "got {err:?}");
}

#[tokio::test]
async fn acquire_lock_twice_is_busy() {
    let tmp = tempfile::tempdir().unwrap();
    let store = FileProfileStore::new(tmp.path());
    let created = store.create(ephemeral_spec("locked")).await.unwrap();

    let lease = store.acquire_lock(&created.id).await.unwrap();
    assert_eq!(lease.profile, created.id);
    assert!(!lease.token.is_empty());

    // Second acquire must fail Busy.
    let err = store.acquire_lock(&created.id).await.unwrap_err();
    assert!(matches!(err, Error::Busy(_)), "got {err:?}");

    // The lock is reflected in the returned profile.
    let p = store.get(&created.id).await.unwrap();
    assert!(p.locked);
    assert!(!p.can_open());
    let listed = store.list().await.unwrap();
    assert!(listed.iter().find(|x| x.id == created.id).unwrap().locked);
}

#[tokio::test]
async fn release_then_reacquire_works() {
    let tmp = tempfile::tempdir().unwrap();
    let store = FileProfileStore::new(tmp.path());
    let created = store.create(ephemeral_spec("relock")).await.unwrap();

    let lease = store.acquire_lock(&created.id).await.unwrap();
    store.release_lock(&lease).await.unwrap();

    // Unlocked in metadata again.
    assert!(!store.get(&created.id).await.unwrap().locked);

    // And we can lock once more.
    let lease2 = store.acquire_lock(&created.id).await.unwrap();
    assert_ne!(lease.token, lease2.token, "fresh token per acquisition");
    store.release_lock(&lease2).await.unwrap();
}

#[tokio::test]
async fn release_with_wrong_token_is_refused() {
    let tmp = tempfile::tempdir().unwrap();
    let store = FileProfileStore::new(tmp.path());
    let created = store.create(ephemeral_spec("guard")).await.unwrap();

    let lease = store.acquire_lock(&created.id).await.unwrap();

    // An impostor lease with a different token must not be able to release.
    let impostor = aegis_core::traits::ProfileLease {
        profile: created.id,
        token: "deadbeefdeadbeefdeadbeefdeadbeef".into(),
    };
    let err = store.release_lock(&impostor).await.unwrap_err();
    assert!(matches!(err, Error::Precondition(_)), "got {err:?}");

    // The real lock is still held: still Busy, still marked locked.
    assert!(store.get(&created.id).await.unwrap().locked);
    assert!(matches!(
        store.acquire_lock(&created.id).await.unwrap_err(),
        Error::Busy(_)
    ));

    // The rightful holder can still release.
    store.release_lock(&lease).await.unwrap();
    assert!(!store.get(&created.id).await.unwrap().locked);
}

#[tokio::test]
async fn release_when_not_locked_is_precondition() {
    let tmp = tempfile::tempdir().unwrap();
    let store = FileProfileStore::new(tmp.path());
    let created = store.create(ephemeral_spec("nolock")).await.unwrap();
    let bogus = aegis_core::traits::ProfileLease {
        profile: created.id,
        token: "aaaa".into(),
    };
    let err = store.release_lock(&bogus).await.unwrap_err();
    assert!(matches!(err, Error::Precondition(_)), "got {err:?}");
}

#[tokio::test]
async fn acquire_lock_on_missing_profile_is_not_found() {
    let tmp = tempfile::tempdir().unwrap();
    let store = FileProfileStore::new(tmp.path());
    let err = store.acquire_lock(&ProfileId::new()).await.unwrap_err();
    assert!(matches!(err, Error::NotFound(_)), "got {err:?}");
}

#[tokio::test]
async fn profile_data_dirs_are_isolated() {
    let tmp = tempfile::tempdir().unwrap();
    let store = FileProfileStore::new(tmp.path());

    let a = store.create(ephemeral_spec("A")).await.unwrap();
    let b = store.create(ephemeral_spec("B")).await.unwrap();

    let dir_a = store.profile_data_dir(&a.id);
    let dir_b = store.profile_data_dir(&b.id);
    assert_ne!(dir_a, dir_b, "each profile gets its own data dir");

    // Writing into A must not be visible from B's directory.
    tokio::fs::write(dir_a.join("secret_a.txt"), b"A-only")
        .await
        .unwrap();
    tokio::fs::write(dir_b.join("secret_b.txt"), b"B-only")
        .await
        .unwrap();

    assert!(dir_a.join("secret_a.txt").exists());
    assert!(!dir_a.join("secret_b.txt").exists());
    assert!(dir_b.join("secret_b.txt").exists());
    assert!(!dir_b.join("secret_a.txt").exists());

    // Neither directory is a subpath of the other.
    assert!(!dir_a.starts_with(&dir_b));
    assert!(!dir_b.starts_with(&dir_a));

    // Deleting A leaves B untouched.
    store.delete(&a.id).await.unwrap();
    assert!(!dir_a.exists());
    assert!(dir_b.join("secret_b.txt").exists());
    assert_eq!(store.list().await.unwrap().len(), 1);
}

#[tokio::test]
async fn ephemeral_vs_persistent_kind_persists() {
    let tmp = tempfile::tempdir().unwrap();
    let store = FileProfileStore::new(tmp.path());

    let eph = store.create(ephemeral_spec("throwaway")).await.unwrap();
    let per = store.create(persistent_spec("keeper")).await.unwrap();

    assert_eq!(eph.spec.kind, ProfileType::Ephemeral);
    assert_eq!(per.spec.kind, ProfileType::Persistent);

    // Reload from a fresh store to prove the kind is on disk.
    let store2 = FileProfileStore::new(tmp.path());
    assert_eq!(
        store2.get(&eph.id).await.unwrap().spec.kind,
        ProfileType::Ephemeral
    );
    assert_eq!(
        store2.get(&per.id).await.unwrap().spec.kind,
        ProfileType::Persistent
    );
}

#[tokio::test]
async fn touch_launch_records_timestamp() {
    let tmp = tempfile::tempdir().unwrap();
    let store = FileProfileStore::new(tmp.path());
    let created = store.create(ephemeral_spec("run")).await.unwrap();
    assert_eq!(created.last_launched, None);

    let at = Utc::now();
    store.touch_launch(&created.id, at).await.unwrap();

    let reloaded = store.get(&created.id).await.unwrap();
    assert_eq!(reloaded.last_launched, Some(at));

    // Persisted across a fresh store.
    let store2 = FileProfileStore::new(tmp.path());
    assert_eq!(
        store2.get(&created.id).await.unwrap().last_launched,
        Some(at)
    );
}

#[tokio::test]
async fn touch_launch_missing_profile_is_not_found() {
    let tmp = tempfile::tempdir().unwrap();
    let store = FileProfileStore::new(tmp.path());
    let err = store
        .touch_launch(&ProfileId::new(), Utc::now())
        .await
        .unwrap_err();
    assert!(matches!(err, Error::NotFound(_)), "got {err:?}");
}

#[tokio::test]
async fn storage_usage_reflects_data_dir_size() {
    let tmp = tempfile::tempdir().unwrap();
    let store = FileProfileStore::new(tmp.path());
    let created = store.create(ephemeral_spec("sized")).await.unwrap();

    // Empty (aside from small metadata) at first.
    let before = store.get(&created.id).await.unwrap().storage.bytes;

    let payload = vec![0u8; 50_000];
    tokio::fs::write(store.profile_data_dir(&created.id).join("blob"), &payload)
        .await
        .unwrap();

    let after = store.get(&created.id).await.unwrap().storage.bytes;
    assert!(after >= before + 50_000, "before={before} after={after}");
}

#[tokio::test]
async fn corrupt_metadata_is_reported_not_paniced() {
    let tmp = tempfile::tempdir().unwrap();
    let store = FileProfileStore::new(tmp.path());
    let created = store.create(ephemeral_spec("bad")).await.unwrap();

    // Corrupt the metadata file directly.
    let meta = tmp.path().join(created.id.to_string()).join("profile.json");
    tokio::fs::write(&meta, b"{ this is not valid json")
        .await
        .unwrap();

    let err = store.get(&created.id).await.unwrap_err();
    assert!(matches!(err, Error::Config(_)), "got {err:?}");

    // A corrupt profile is skipped by list() rather than failing the whole call.
    // (It errors with Config, which list treats as fatal only for non-NotFound;
    // here we assert list surfaces the error so operators notice.)
    let list_res = store.list().await;
    assert!(list_res.is_err());
}
