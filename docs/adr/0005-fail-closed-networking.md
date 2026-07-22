# ADR-0005: Fail-closed networking (default-deny, kill switch, six-check preflight)

- Status: Accepted
- Date: 2026-07-22
- Deciders: Aegis Project
- Spec references: §2, §5, §10, §11, §14, §15, §16

## Context

The single most linkable identifier is the host's real public IP; one leak collapses
the entire unlinkability model (spec §2). Leaks can happen many ways: the tunnel
(Tor/VPN/proxy) drops mid-session, DNS queries escape the intended route, IPv6
bypasses an IPv4-only tunnel, WebRTC opens non-proxied UDP and reveals local/public
IPs, or a session simply opens before any protection is active.

A "best effort" networking posture — try the tunnel, but fall back to a direct
connection if it fails — is exactly the failure mode Aegis must never have. The spec
is categorical (spec §16):

> awaria ma zawsze kończyć się blokadą, nigdy połączeniem bez ochrony.
> (a failure must always end in a block, never a connection without protection.)

and priority (spec §16): **no leak before compatibility.**

## Decision

Make the network path **fail-closed** end to end, enforced in the type system, in the
firewall, and in the session gate.

1. **Default-deny firewall on the Gateway.** The only acceptable base policy is
   `DefaultPolicy::Drop`; `FirewallPolicy::validate` rejects `Accept`. Only traffic
   through the configured tunnel is allowed; direct (non-tunnel) UDP is blocked; IPv6
   is blocked (or tunnel-only); DNS is captured/redirected; host-initiated traffic
   outside the management channel is rejected (`crates/aegis-core/src/gateway.rs`,
   `firewall/nftables/`; spec §5).
2. **Single route.** The Browser VM has exactly one NIC to the Gateway and no
   alternate route (ADR-0001), so there is nowhere for traffic to fall back *to*.
3. **Kill switch.** On tunnel loss the tunnel state becomes `Failed` and
   `KillSwitchState::Engaged` cuts all traffic immediately; the browser is never
   allowed a direct connection (spec §5, §10).
4. **Typed failure classification.** Every error carries a `FailureClass`.
   `NetworkContainment` and `Isolation` return `true` from `requires_killswitch()`, so
   the daemon engages the kill switch **before** surfacing the error
   (`crates/aegis-core/src/error.rs`).
5. **Six-check preflight gate.** Before the first tab loads, the auditor runs
   `gateway_ready`, `tunnel_ready`, `dns_route_verified`, `public_ip_observed`,
   `webrtc_policy_loaded`, `ipv6_policy_verified`. If **any** check fails — or is
   `Skipped` — the browser gets no Internet access. Only `ProtectionStatus::Active`
   permits browsing; there is no partial-pass path (`crates/aegis-core/src/preflight.rs`;
   spec §5, §11).
6. **State machine.** `GatewayStarting → Browsing` is forbidden; `Browsing` is
   reachable only through `Preflight`; any state can transition to `Failed`, which the
   daemon treats as a kill-switch event (`crates/aegis-core/src/session.rs`).

Each control is confirmed by an automated test (spec §16), including red-team
scenarios (spec §15): tunnel stop mid-load, gateway restart, bad DNS, DNS-over-IPv6,
WebRTC STUN, non-proxied UDP, and running without a working kill switch
(`tests/network`, `tests/destructive`, `firewall/tests`).

## Consequences

**Positive**

- A dropped tunnel, an escaped DNS query, an IPv6 path, or a WebRTC UDP attempt
  results in **no traffic**, not a leaked direct connection — the core acceptance
  criteria (spec §14): disabling the gateway instantly cuts the Browser VM; no packet
  leaves via the host's physical interface without a tunnel; DNS does not escape;
  WebRTC reveals no host interface; no IPv6 leak; no fallback to a direct connection.
- Fail-closed is machine-checkable: the firewall default, the kill-switch classes, and
  the preflight gate are typed and unit-tested, so they cannot silently regress.
- The diagnostics panel can show an honest four-state status (active / partial /
  unsafe / none) instead of a false "protected" (spec §11).

**Negative / costs**

- **Availability cost.** When containment cannot be verified, the user has *no*
  Internet in that session by design — a deliberate trade of availability for safety.
- Transient tunnel hiccups can engage the kill switch and require a re-check before
  browsing resumes; this can feel abrupt but is the intended behavior.
- Some sites break under Strict WebRTC/DNS handling; the resolution is to inform the
  user and let them step down to Balanced — never to weaken containment for a site
  (spec §16 "no leak before compatibility").

## Alternatives considered

- **Best-effort / fail-open networking** (fall back to direct on tunnel failure).
  Rejected outright by spec §16 — this is precisely the leak Aegis exists to prevent.
- **Warn-but-continue on a failed check.** Rejected: a partial-pass path to a live
  session defeats the gate; `Skipped`/`Fail` must block (fail-closed).
- **Application-level proxying only (no gateway firewall).** Rejected: a
  proxy-unaware app, a misconfigured API, WebRTC, or IPv6 can bypass an app-level
  proxy; only a default-deny firewall on a separate Gateway with a single downstream
  route can guarantee containment.
- **Trusting the tunnel client's own kill switch.** Insufficient: it is inside the
  same failure domain. Aegis enforces the kill switch at the Gateway firewall, outside
  the browser and tunnel client.

## Related

- [ADR-0001](0001-whonix-style-vm-isolation.md) — the single-route two-VM split.
- [ADR-0004](0004-privileged-daemon-and-local-socket.md) — the daemon that applies the
  firewall and rejects host-initiated traffic.
- [`../architecture.md`](../architecture.md) §5, [`../threat-model.md`](../threat-model.md) §6.
