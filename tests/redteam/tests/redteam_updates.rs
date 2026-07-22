//! Acceptance (spec §14 "Aktualizacje"): signed-update verification, downgrade
//! protection, and corrupt-artifact rollback — proven at the integration level
//! against [`update_client::SignedUpdateClient`] with a [`MockTransport`] and an
//! in-test ed25519 keypair.
//!
//! Every verification-path failure is an `Integrity` error (fail-closed): an
//! unsigned/tampered manifest, a wrong key, an older version, or a hash mismatch
//! all refuse the update. A mid-apply failure rolls back so the previously
//! installed version stays intact.

use std::sync::Arc;

use aegis_core::traits::UpdateClient;
use aegis_core::update::{
    ApplyOutcome, Artifact, ArtifactKind, UpdateKind, UpdateManifest, Version, VersionInfo,
};
use aegis_core::FailureClass;

use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::OsRng;
use update_client::{signing_bytes, MockTransport, SignedUpdateClient};

const MANIFEST_LOC: &str = "manifest.json";

/// Lowercase hex SHA-256 (FIPS 180-4), implemented locally so this test crate
/// needs no extra dependency. It is self-validating: the update client
/// independently recomputes the hash during `verify`, so
/// `acceptance_valid_signed_update_verifies` would fail if this digest were wrong.
fn sha256_hex(bytes: &[u8]) -> String {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    let mut msg = bytes.to_vec();
    let bitlen = (bytes.len() as u64) * 8;
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bitlen.to_be_bytes());

    for chunk in msg.chunks_exact(64) {
        let mut w = [0u32; 64];
        for (i, wi) in w.iter_mut().enumerate().take(16) {
            *wi = u32::from_be_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1],
                chunk[i * 4 + 2],
                chunk[i * 4 + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let mut v = h;
        for i in 0..64 {
            let s1 = v[4].rotate_right(6) ^ v[4].rotate_right(11) ^ v[4].rotate_right(25);
            let ch = (v[4] & v[5]) ^ ((!v[4]) & v[6]);
            let t1 = v[7]
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = v[0].rotate_right(2) ^ v[0].rotate_right(13) ^ v[0].rotate_right(22);
            let maj = (v[0] & v[1]) ^ (v[0] & v[2]) ^ (v[1] & v[2]);
            let t2 = s0.wrapping_add(maj);
            v[7] = v[6];
            v[6] = v[5];
            v[5] = v[4];
            v[4] = v[3].wrapping_add(t1);
            v[3] = v[2];
            v[2] = v[1];
            v[1] = v[0];
            v[0] = t1.wrapping_add(t2);
        }
        for i in 0..8 {
            h[i] = h[i].wrapping_add(v[i]);
        }
    }
    let mut out = String::with_capacity(64);
    for word in h {
        out.push_str(&format!("{word:08x}"));
    }
    out
}

/// Build a signed single-artifact manifest for `version`.
fn signed_manifest(
    sk: &SigningKey,
    version: Version,
    art_loc: &str,
    artifact_bytes: &[u8],
) -> UpdateManifest {
    let mut manifest = UpdateManifest {
        schema: 1,
        version,
        delta_base: None,
        kind: UpdateKind::Full,
        artifacts: vec![Artifact {
            kind: ArtifactKind::AppPackage,
            location: art_loc.into(),
            sha256: sha256_hex(artifact_bytes),
            size: artifact_bytes.len() as u64,
        }],
        sbom: None,
        signature: String::new(),
    };
    let sig = sk.sign(&signing_bytes(&manifest));
    manifest.signature = hex::encode(sig.to_bytes());
    manifest
}

fn key_hex(sk: &SigningKey) -> String {
    hex::encode(sk.verifying_key().to_bytes())
}

fn client(vk_hex: &str, transport: MockTransport) -> SignedUpdateClient {
    SignedUpdateClient::new(MANIFEST_LOC, vk_hex, Arc::new(transport)).unwrap()
}

// ---------------------------------------------------------------------------
// §14 — a valid signed, newer update verifies (happy path + digest self-check).
// ---------------------------------------------------------------------------

/// §14: a correctly signed, newer manifest whose artifact hash matches verifies
/// and reports the artifact set. This also self-validates the local SHA-256
/// helper: the client independently recomputes the hash, so a wrong digest here
/// would fail this test.
#[tokio::test]
async fn acceptance_valid_signed_update_verifies() {
    let sk = SigningKey::generate(&mut OsRng);
    let art = b"aegis app package v1.1.0";
    let manifest = signed_manifest(&sk, Version::new(1, 1, 0), "app-1.1.0.pkg", art);
    let transport = MockTransport::new()
        .with(MANIFEST_LOC, serde_json::to_vec(&manifest).unwrap())
        .with("app-1.1.0.pkg", art.to_vec());
    let c = client(&key_hex(&sk), transport);
    let info = VersionInfo {
        current: Version::new(1, 0, 0),
    };

    let offered = c.check_for_update(&info).await.unwrap();
    assert_eq!(offered.map(|m| m.version), Some(Version::new(1, 1, 0)));

    let verified = c
        .verify(&manifest, &info)
        .await
        .expect("§14: valid update verifies");
    assert_eq!(verified.version, Version::new(1, 1, 0));
    assert_eq!(verified.artifacts.len(), 1);
}

// ---------------------------------------------------------------------------
// §14 — unsigned / tampered manifest rejected.
// ---------------------------------------------------------------------------

/// §14 "niepodpisana aktualizacja zostaje odrzucona": a manifest with an empty
/// signature, or one whose signed fields were tampered after signing, is rejected
/// as an `Integrity` failure.
#[tokio::test]
async fn acceptance_unsigned_and_tampered_manifest_rejected() {
    let sk = SigningKey::generate(&mut OsRng);
    let art = b"payload";
    let info = VersionInfo {
        current: Version::new(1, 0, 0),
    };

    // (a) Unsigned: clear the signature entirely.
    let mut unsigned = signed_manifest(&sk, Version::new(2, 0, 0), "a.pkg", art);
    unsigned.signature = String::new();
    let t = MockTransport::new()
        .with(MANIFEST_LOC, serde_json::to_vec(&unsigned).unwrap())
        .with("a.pkg", art.to_vec());
    let c = client(&key_hex(&sk), t);
    let err = c
        .verify(&unsigned, &info)
        .await
        .expect_err("§14: unsigned rejected");
    assert_eq!(err.class(), FailureClass::Integrity);

    // (b) Tampered: bump the version after signing, keep the old signature.
    let mut tampered = signed_manifest(&sk, Version::new(2, 0, 0), "a.pkg", art);
    tampered.version = Version::new(3, 0, 0);
    let t2 = MockTransport::new()
        .with(MANIFEST_LOC, serde_json::to_vec(&tampered).unwrap())
        .with("a.pkg", art.to_vec());
    let c2 = client(&key_hex(&sk), t2);
    let err2 = c2
        .verify(&tampered, &info)
        .await
        .expect_err("§14: tampered rejected");
    assert_eq!(err2.class(), FailureClass::Integrity);
    // check_for_update also refuses (signature is checked before the version gate).
    let err3 = c2
        .check_for_update(&info)
        .await
        .expect_err("§14: tampered check refused");
    assert_eq!(err3.class(), FailureClass::Integrity);
}

/// §14: a manifest signed by the *wrong* key is rejected (an attacker cannot
/// substitute their own signing key).
#[tokio::test]
async fn acceptance_wrong_key_rejected() {
    let real = SigningKey::generate(&mut OsRng);
    let attacker = SigningKey::generate(&mut OsRng);
    let art = b"payload";
    let manifest = signed_manifest(&attacker, Version::new(2, 0, 0), "a.pkg", art);
    let t = MockTransport::new()
        .with(MANIFEST_LOC, serde_json::to_vec(&manifest).unwrap())
        .with("a.pkg", art.to_vec());
    // Client trusts only the REAL key.
    let c = client(&key_hex(&real), t);
    let info = VersionInfo {
        current: Version::new(1, 0, 0),
    };
    let err = c
        .verify(&manifest, &info)
        .await
        .expect_err("§14: wrong key rejected");
    assert_eq!(err.class(), FailureClass::Integrity);
}

// ---------------------------------------------------------------------------
// §14 — downgrade rejected.
// ---------------------------------------------------------------------------

/// §14 "starsza wersja zostaje odrzucona": an older or equal signed manifest is
/// refused by `verify` (downgrade protection), and `check_for_update` reports no
/// update (Ok(None), not an error).
#[tokio::test]
async fn acceptance_downgrade_rejected() {
    let sk = SigningKey::generate(&mut OsRng);
    let art = b"payload";
    let info = VersionInfo {
        current: Version::new(2, 0, 0),
    };

    for older in [Version::new(1, 9, 9), Version::new(2, 0, 0)] {
        let manifest = signed_manifest(&sk, older, "a.pkg", art);
        let t = MockTransport::new()
            .with(MANIFEST_LOC, serde_json::to_vec(&manifest).unwrap())
            .with("a.pkg", art.to_vec());
        let c = client(&key_hex(&sk), t);

        let err = c
            .verify(&manifest, &info)
            .await
            .expect_err("§14: downgrade/equal must be rejected");
        assert_eq!(err.class(), FailureClass::Integrity);
        assert!(
            err.to_string().contains("downgrade"),
            "§14: the reason must name the downgrade"
        );

        // check_for_update returns Ok(None), never an error, for a non-newer one.
        assert!(
            c.check_for_update(&info).await.unwrap().is_none(),
            "§14: no update is offered for a non-newer version"
        );
    }
}

// ---------------------------------------------------------------------------
// §14 — corrupt artifact => rejected on verify, rolled back on apply.
// ---------------------------------------------------------------------------

/// §14: an artifact whose bytes do not match the manifest hash is rejected at
/// verify time as an `Integrity` failure.
#[tokio::test]
async fn acceptance_corrupt_artifact_rejected_on_verify() {
    let sk = SigningKey::generate(&mut OsRng);
    let art = b"the real bytes";
    let manifest = signed_manifest(&sk, Version::new(1, 1, 0), "a.pkg", art);
    // Serve DIFFERENT bytes than the manifest was built from.
    let transport = MockTransport::new()
        .with(MANIFEST_LOC, serde_json::to_vec(&manifest).unwrap())
        .with("a.pkg", b"CORRUPTED".to_vec());
    let c = client(&key_hex(&sk), transport);
    let info = VersionInfo {
        current: Version::new(1, 0, 0),
    };
    let err = c
        .verify(&manifest, &info)
        .await
        .expect_err("§14: corrupt artifact rejected");
    assert_eq!(err.class(), FailureClass::Integrity);
    assert!(err.to_string().contains("hash mismatch"));
}

/// §14 "uszkodzona aktualizacja powoduje rollback": a two-artifact update whose
/// second artifact becomes unavailable/corrupt mid-apply rolls back, leaving both
/// previously installed files intact.
///
/// The apply transport is missing `b.pkg`, so after `a.pkg` is swapped in the
/// fetch of `b.pkg` fails and the client restores the prior state. `verify` runs
/// against a fully-good transport first, mirroring update-client's own rollback
/// test but wired at the integration level.
#[tokio::test]
async fn acceptance_corrupt_artifact_triggers_rollback() {
    let sk = SigningKey::generate(&mut OsRng);
    let dir = tempfile::tempdir().unwrap();
    let install = dir.path().join("install");
    std::fs::create_dir_all(&install).unwrap();

    // Two pre-existing (old) files.
    let target_a = install.join("a.pkg");
    let target_b = install.join("b.pkg");
    std::fs::write(&target_a, b"OLD A").unwrap();
    std::fs::write(&target_b, b"OLD B").unwrap();

    let new_a = b"NEW A";
    let new_b = b"NEW B";
    let mut manifest = UpdateManifest {
        schema: 1,
        version: Version::new(2, 0, 0),
        delta_base: None,
        kind: UpdateKind::Full,
        artifacts: vec![
            Artifact {
                kind: ArtifactKind::AppPackage,
                location: "a.pkg".into(),
                sha256: sha256_hex(new_a),
                size: new_a.len() as u64,
            },
            Artifact {
                kind: ArtifactKind::AppPackage,
                location: "b.pkg".into(),
                sha256: sha256_hex(new_b),
                size: new_b.len() as u64,
            },
        ],
        sbom: None,
        signature: String::new(),
    };
    manifest.signature = hex::encode(sk.sign(&signing_bytes(&manifest)).to_bytes());

    // Fully-good transport for verify.
    let good = MockTransport::new()
        .with(MANIFEST_LOC, serde_json::to_vec(&manifest).unwrap())
        .with("a.pkg", new_a.to_vec())
        .with("b.pkg", new_b.to_vec());
    let info = VersionInfo {
        current: Version::new(1, 0, 0),
    };
    let verified = SignedUpdateClient::new(MANIFEST_LOC, &key_hex(&sk), Arc::new(good.clone()))
        .unwrap()
        .verify(&manifest, &info)
        .await
        .expect("§14: verify ok before apply");

    // Apply transport is missing `b.pkg`: fetching it mid-apply fails, forcing a
    // rollback after `a.pkg` was already swapped in.
    let apply_transport = MockTransport::new()
        .with(MANIFEST_LOC, serde_json::to_vec(&manifest).unwrap())
        .with("a.pkg", new_a.to_vec());
    let apply_client =
        SignedUpdateClient::new(MANIFEST_LOC, &key_hex(&sk), Arc::new(apply_transport))
            .unwrap()
            .with_install_dir(&install);

    let outcome = apply_client
        .apply(&verified)
        .await
        .expect("apply returns an outcome");
    assert_eq!(
        outcome,
        ApplyOutcome::RolledBack,
        "§14: a corrupt/unavailable artifact must roll back"
    );

    // Both previous versions are intact — the failed update did not damage them.
    assert_eq!(
        std::fs::read(&target_a).unwrap(),
        b"OLD A",
        "§14: A restored"
    );
    assert_eq!(
        std::fs::read(&target_b).unwrap(),
        b"OLD B",
        "§14: B restored"
    );
}
