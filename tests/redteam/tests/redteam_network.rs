//! Red-team: the network containment scenarios (spec §15.1, §15.2, §15.3,
//! §15.16) driven end-to-end through the real [`Orchestrator`] over mocks.
//!
//! Every scenario proves the same fail-closed invariant from a different angle:
//! when a network guarantee cannot be upheld the session **never reaches
//! Browsing**, the kill switch engages, and a `Critical` `FailClosed` event is
//! recorded — "awaria ma zawsze kończyć się blokadą, nigdy połączeniem bez
//! ochrony" (spec §16).

mod harness;

use aegis_core::gateway::KillSwitchState;
use aegis_core::preflight::IpObservation;
use aegis_core::profile::ProfileType;
use aegis_core::session::SessionState;
use aegis_core::traits::{GatewayController, ProfileRepository};
use aegis_core::FailureClass;
use harness::{
    build_harness, harness_with_probe, make_profile, recorded_critical_fail_closed,
    recorded_states, GatewayMock,
};
use network_audit::MockProbe;

// ---------------------------------------------------------------------------
// §15.1 — tunnel/VPN drop during page load.
// ---------------------------------------------------------------------------

/// §15.1: the tunnel is down at preflight (`TunnelReady` fails). The session must
/// fail closed: never Browsing, kill switch engaged, Critical FailClosed
/// recorded, profile lock released, teardown clean.
#[tokio::test]
async fn s15_1_tunnel_drop_fails_closed_and_never_browses() {
    let probe = MockProbe {
        tunnel_up: Ok(false),
        ..MockProbe::all_pass()
    };
    let h = harness_with_probe(probe);
    let profile_id = make_profile(&h.profiles, ProfileType::Persistent).await;

    let err = h
        .orch
        .start_session(profile_id)
        .await
        .expect_err("§15.1: tunnel-down start must fail closed");
    assert_eq!(err.class(), FailureClass::NetworkContainment);
    assert!(err.requires_killswitch());

    // Kill switch engaged, traffic cut.
    assert_eq!(
        h.gateway.killswitch_state().await.unwrap(),
        KillSwitchState::Engaged,
        "§15.1: kill switch must engage on tunnel drop"
    );

    // A Critical FailClosed(NetworkContainment) event was recorded.
    assert!(
        recorded_critical_fail_closed(&h.audit, FailureClass::NetworkContainment),
        "§15.1: expected a Critical FailClosed(NetworkContainment) audit event"
    );

    // Never reached Browsing; ended in a terminal, non-Browsing state.
    assert!(
        h.orch
            .list_sessions()
            .iter()
            .all(|s| s.state != SessionState::Browsing),
        "§15.1: no session may be in Browsing after a tunnel-drop start"
    );
    let states = recorded_states(&h.audit);
    assert!(
        !states.iter().any(|s| s == "browsing"),
        "§15.1: 'browsing' state must never be recorded; states: {states:?}"
    );
    assert!(
        states.iter().any(|s| s == "failed"),
        "§15.1: session must end Failed; states: {states:?}"
    );

    // Teardown was clean: the single-writer lock was released.
    let after = h.profiles.get(&profile_id).await.unwrap();
    assert!(!after.locked, "§15.1: profile lock must be released");
}

/// §15.1 variant: the exit IP observed equals the host IP (traffic escaped the
/// tunnel mid-load). `PublicIpObserved` fails → fail closed.
#[tokio::test]
async fn s15_1_observed_ip_equals_host_fails_closed() {
    let probe = MockProbe::all_pass().with_observation(Some(IpObservation {
        ip: "203.0.113.9".into(),
        via_tunnel: false, // not through the tunnel: a leak
        differs_from_host: false,
    }));
    let h = harness_with_probe(probe);
    let profile_id = make_profile(&h.profiles, ProfileType::Ephemeral).await;

    let err = h
        .orch
        .start_session(profile_id)
        .await
        .expect_err("§15.1: a leaked direct IP must fail closed");
    assert_eq!(err.class(), FailureClass::NetworkContainment);
    assert_eq!(
        h.gateway.killswitch_state().await.unwrap(),
        KillSwitchState::Engaged
    );
    assert!(recorded_critical_fail_closed(
        &h.audit,
        FailureClass::NetworkContainment
    ));
}

// ---------------------------------------------------------------------------
// §15.2 — gateway restart / gateway unreachable.
// ---------------------------------------------------------------------------

/// §15.2: the gateway VM is unreachable at preflight (`GatewayReady` fails), as
/// happens transiently while the gateway restarts. Must fail closed, kill switch
/// engaged, never Browsing.
#[tokio::test]
async fn s15_2_gateway_restart_engages_killswitch() {
    let probe = MockProbe {
        gateway_reachable: Ok(false),
        ..MockProbe::all_pass()
    };
    let h = harness_with_probe(probe);
    let profile_id = make_profile(&h.profiles, ProfileType::Persistent).await;

    let err = h
        .orch
        .start_session(profile_id)
        .await
        .expect_err("§15.2: gateway-down start must fail closed");
    assert_eq!(err.class(), FailureClass::NetworkContainment);
    assert_eq!(
        h.gateway.killswitch_state().await.unwrap(),
        KillSwitchState::Engaged,
        "§15.2: kill switch must engage when the gateway is unreachable"
    );
    assert!(recorded_critical_fail_closed(
        &h.audit,
        FailureClass::NetworkContainment
    ));
    assert!(h
        .orch
        .list_sessions()
        .iter()
        .all(|s| s.state != SessionState::Browsing));
    // Lock released on teardown.
    assert!(!h.profiles.get(&profile_id).await.unwrap().locked);
}

// ---------------------------------------------------------------------------
// §15.3 — bad DNS (route unverified / DNS answer over IPv6 outside the tunnel).
// ---------------------------------------------------------------------------

/// §15.3: DNS route verification fails (a possible plaintext/IPv6 DNS leak). The
/// aggregate becomes `Unsafe` (gateway+tunnel up but a leak-relevant check
/// failed), browsing is refused, and the orchestrator fails closed.
#[tokio::test]
async fn s15_3_bad_dns_is_unsafe_and_refuses_browsing() {
    let probe = MockProbe {
        dns_route_ok: Ok(false),
        ..MockProbe::all_pass()
    };
    let h = harness_with_probe(probe);
    let profile_id = make_profile(&h.profiles, ProfileType::Persistent).await;

    let err = h
        .orch
        .start_session(profile_id)
        .await
        .expect_err("§15.3: unverified DNS route must refuse browsing");
    assert_eq!(err.class(), FailureClass::NetworkContainment);

    // The failing-check list surfaced in the error mentions the DNS route.
    assert!(
        err.to_string().contains("dns_route_verified"),
        "§15.3: the DNS route check should be named in the failure; got: {err}"
    );

    assert_eq!(
        h.gateway.killswitch_state().await.unwrap(),
        KillSwitchState::Engaged
    );
    assert!(recorded_critical_fail_closed(
        &h.audit,
        FailureClass::NetworkContainment
    ));
    assert!(h
        .orch
        .list_sessions()
        .iter()
        .all(|s| s.state != SessionState::Browsing));
}

/// §15.3/§15.4 combined at the checklist level: an IPv6 policy that is not
/// verified in effect (a possible v6 DNS/route leak) also refuses browsing.
#[tokio::test]
async fn s15_3_ipv6_unverified_refuses_browsing() {
    let probe = MockProbe {
        ipv6_blocked: Ok(false),
        ..MockProbe::all_pass()
    };
    let h = harness_with_probe(probe);
    let profile_id = make_profile(&h.profiles, ProfileType::Ephemeral).await;

    let err = h
        .orch
        .start_session(profile_id)
        .await
        .expect_err("§15.3/§15.4: unverified IPv6 must refuse browsing");
    assert_eq!(err.class(), FailureClass::NetworkContainment);
    assert_eq!(
        h.gateway.killswitch_state().await.unwrap(),
        KillSwitchState::Engaged
    );
    assert!(recorded_critical_fail_closed(
        &h.audit,
        FailureClass::NetworkContainment
    ));
}

// ---------------------------------------------------------------------------
// §15.16 — start without a working kill switch.
// ---------------------------------------------------------------------------

/// §15.16: the host cannot arm the kill switch (the `nft` firewall load fails).
/// The start must be refused before Browsing, the gateway must record the kill
/// switch as `Engaged` (the safest recorded state), and no session reaches
/// Browsing. There is no path to a live session without a working kill switch.
#[tokio::test]
async fn s15_16_start_without_working_killswitch_is_refused() {
    // Preflight would pass, but the firewall/kill-switch nft load fails, so the
    // orchestrator can never apply the fail-closed firewall.
    let h = build_harness(MockProbe::all_pass(), GatewayMock::NftBroken);
    let profile_id = make_profile(&h.profiles, ProfileType::Persistent).await;

    let err = h
        .orch
        .start_session(profile_id)
        .await
        .expect_err("§15.16: start must be refused when the kill switch cannot be armed");
    // The nft failure surfaces as a System error (tooling failure).
    assert_eq!(
        err.class(),
        FailureClass::System,
        "§15.16: a broken firewall path is a system/tooling failure"
    );

    // The gateway itself marks the kill switch Engaged on any network-path error,
    // even when the block-ruleset load also failed: the safest recorded state.
    assert_eq!(
        h.gateway.killswitch_state().await.unwrap(),
        KillSwitchState::Engaged,
        "§15.16: gateway must record the kill switch as Engaged, never Armed, on failure"
    );

    // Never reached Browsing; ended Failed.
    let states = recorded_states(&h.audit);
    assert!(
        !states.iter().any(|s| s == "browsing"),
        "§15.16: must never reach Browsing without a working kill switch; states: {states:?}"
    );
    assert!(h
        .orch
        .list_sessions()
        .iter()
        .all(|s| s.state != SessionState::Browsing),);

    // Teardown still released the profile lock.
    assert!(!h.profiles.get(&profile_id).await.unwrap().locked);
}

/// Control: with a healthy gateway and an all-pass probe the same start *does*
/// reach Browsing and the kill switch stays Armed — proving the fail-closed
/// refusals above are caused by the injected fault, not by the harness always
/// refusing.
#[tokio::test]
async fn control_healthy_start_reaches_browsing() {
    let h = build_harness(MockProbe::all_pass(), GatewayMock::Healthy);
    let profile_id = make_profile(&h.profiles, ProfileType::Persistent).await;

    let summary = h
        .orch
        .start_session(profile_id)
        .await
        .expect("healthy start ok");
    assert_eq!(summary.state, SessionState::Browsing);
    assert_eq!(
        h.gateway.killswitch_state().await.unwrap(),
        KillSwitchState::Armed
    );
    // No FailClosed on the happy path.
    assert!(!recorded_critical_fail_closed(
        &h.audit,
        FailureClass::NetworkContainment
    ));
    h.orch.stop_session(summary.id).await.expect("stop ok");
    assert!(!h.profiles.get(&profile_id).await.unwrap().locked);
}
