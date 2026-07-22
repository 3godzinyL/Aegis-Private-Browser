//! Acceptance-criteria table tests (spec §14, §16, §17).
//!
//! These assert the cross-cutting honesty and self-consistency invariants the
//! product must uphold:
//!
//! * `aegis_core::self_check()` finds no drift in the compiled-in security
//!   defaults (isolation hardened, fingerprint policies valid, hard-blocked
//!   device classes blocked).
//! * No `ProtectionStatus` label ever claims "100% anonymous" / "undetectable"
//!   (spec §16 "nie reklamować produktu jako «niewykrywalnego»", §17).
//! * `permits_browsing()` is true only for the fully-`Active` state (fail-closed).

use aegis_core::preflight::ProtectionStatus;

// ---------------------------------------------------------------------------
// §14/§16 — compiled-in security defaults have not drifted.
// ---------------------------------------------------------------------------

/// §14: the workspace self-check reports no problems. If any default (isolation
/// policy, fingerprint policy, hard-blocked device class) had drifted from the
/// security model, this would list it.
#[test]
fn acceptance_self_check_is_empty() {
    let problems = aegis_core::self_check();
    assert!(
        problems.is_empty(),
        "§14: self_check must report no problems, found: {problems:?}"
    );
}

// ---------------------------------------------------------------------------
// §16/§17 — never advertise "undetectable" / "100% anonymous".
// ---------------------------------------------------------------------------

/// §16/§17: no protection-status label may claim absolute anonymity or
/// undetectability. The UI badges are honest ("protection active", "partial
/// protection", "unsafe configuration", "no protection").
#[test]
fn acceptance_labels_never_claim_undetectable() {
    // Forbidden marketing phrases the product must never surface (spec §16, §17).
    const FORBIDDEN: [&str; 6] = [
        "100% anonymous",
        "100%",
        "undetectable",
        "untraceable",
        "unfingerprintable",
        "anonymous",
    ];

    let statuses = [
        ProtectionStatus::Active,
        ProtectionStatus::Partial,
        ProtectionStatus::Unsafe,
        ProtectionStatus::None,
    ];
    for status in statuses {
        let label = status.label().to_ascii_lowercase();
        for bad in FORBIDDEN {
            assert!(
                !label.contains(&bad.to_ascii_lowercase()),
                "§16/§17: label {:?} must not contain forbidden phrase {:?}",
                status.label(),
                bad
            );
        }
    }

    // Positive check: the four labels are exactly the honest, expected strings.
    assert_eq!(ProtectionStatus::Active.label(), "protection active");
    assert_eq!(ProtectionStatus::Partial.label(), "partial protection");
    assert_eq!(ProtectionStatus::Unsafe.label(), "unsafe configuration");
    assert_eq!(ProtectionStatus::None.label(), "no protection");
}

/// §14 (fail-closed): only the fully-`Active` status permits browsing; every
/// degraded/none state refuses it. This is the invariant the orchestrator relies
/// on to never open a tab over an incompletely-verified session.
#[test]
fn acceptance_only_active_permits_browsing() {
    assert!(
        ProtectionStatus::Active.permits_browsing(),
        "§14: Active permits"
    );
    for status in [
        ProtectionStatus::Partial,
        ProtectionStatus::Unsafe,
        ProtectionStatus::None,
    ] {
        assert!(
            !status.permits_browsing(),
            "§14: {status:?} must not permit browsing"
        );
    }
}

/// §17: the realistic-result note — the product exposes a *stable, uniform*
/// environment, not a fabricated unique one. We assert the two normalization
/// policies validate and that neither pretends to have hardware the VM lacks
/// (WebGPU stays off; Strict never exposes a full WebGL backend). This encodes
/// the §17 "measurable protection, not cosmetics" position as a test.
#[test]
fn acceptance_normalization_is_uniform_not_fabricated() {
    use aegis_core::fingerprint::{FingerprintPolicy, WebGlMode};

    let balanced = FingerprintPolicy::balanced();
    let strict = FingerprintPolicy::strict();
    assert!(balanced.validate().is_none(), "§17: balanced policy valid");
    assert!(strict.validate().is_none(), "§17: strict policy valid");

    // No fabricated GPU capabilities: WebGPU is off in both levels, and Strict
    // does not claim a full WebGL backend.
    assert!(!balanced.webgpu_enabled && !strict.webgpu_enabled);
    assert_ne!(
        strict.webgl,
        WebGlMode::VirtualBackend,
        "§17: Strict must not expose a full WebGL backend"
    );

    // Device APIs are blocked in every level (no host devices are advertised).
    assert!(balanced.block_device_apis && strict.block_device_apis);
}
