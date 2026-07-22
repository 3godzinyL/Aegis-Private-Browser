# Aegis Private Browser — Security Acceptance Criteria

Status: Stage 0 (foundations).

This is spec §14 restated as a verifiable checklist. **The product cannot be
considered ready until every item passes** (spec §14). Design priority is
fail-closed and no-leak-before-compatibility (spec §16): a failure must always end
in a block, never a connection without protection.

Legend:
- **Test type**: `unit` = existing `cargo test` in `crates/aegis-core`;
  `network`/`leak`/`browser-api`/`destructive`/`integration` = the corresponding
  harness under `tests/` (built in Stages 1–6, spec §15 red-team scenarios).
- **Status**: `[ ]` = to be verified against the running system;
  `[x]` = already asserted by an existing unit test in `aegis-core`.

---

## Network (spec §14 — Sieć)

| # | Criterion | Verifying test | Test type | Status |
|---|-----------|----------------|-----------|--------|
| N1 | Disabling the Gateway immediately cuts the Browser VM | Gateway-failure red-team; `gateway::tests::health_requires_everything` | destructive / unit | [x] unit |
| N2 | No Browser VM packet leaves via the host's physical interface without the tunnel | Egress leak harness (single-NIC, default-drop) | leak / network | [ ] |
| N3 | DNS does not escape the Gateway | `dns_route_verified` probe; `network::tests::tor_default_captures_dns_and_blocks_plain`, `proxy_dns_always_blocks_plaintext` | network / unit | [x] unit |
| N4 | WebRTC does not reveal the host interface | `webrtc_policy_loaded`; STUN/local-candidate red-team | network / browser-api | [ ] |
| N5 | No IPv6 leak | `ipv6_policy_verified`; IPv6-DNS-answer red-team | network | [ ] |
| N6 | No emergency fallback to a direct connection | Kill-switch/fail-closed harness; `error::tests::killswitch_classes` | destructive / unit | [x] unit |

---

## Host (spec §14 — Host)

| # | Criterion | Verifying test | Test type | Status |
|---|-----------|----------------|-----------|--------|
| H1 | The page does not receive a host device list | Device-enumeration probe; `permissions::tests::defaults_block_dangerous_devices`; `fingerprint::tests::device_apis_are_always_blocked` | browser-api / unit | [x] unit |
| H2 | No host fonts | Font-enumeration red-team (`StandardSet`) | browser-api | [ ] |
| H3 | No physical camera or microphone | `getUserMedia` probe; `IsolationPolicy` no-camera-mic; `permissions::tests::defaults_block_dangerous_devices` | browser-api / unit | [x] unit |
| H4 | No physical GPU passthrough | `vm::tests::any_weakening_is_rejected` (`no_pci_passthrough`); WebGL renderer-string probe | unit / browser-api | [x] unit |
| H5 | No file paths containing the host username | File-dialog / File System Access path probe (`ConfinedToVm`) | browser-api / integration | [ ] |
| H6 | No shared installation identifiers | `IsolationPolicy.random_instance_id`; cross-session id-uniqueness test | unit / integration | [x] unit (policy) |

---

## Profiles (spec §14 — Profile)

| # | Criterion | Verifying test | Test type | Status |
|---|-----------|----------------|-----------|--------|
| P1 | Profile A sees none of profile B's data | Cross-profile isolation harness | integration | [ ] |
| P2 | A disposable VM leaves no write layer after close | `vm::tests::destroy_report_clean_only_when_both`; disposable-destruction red-team | unit / destructive | [x] unit |
| P3 | No shared cache | Cross-profile cache-isolation test | integration | [ ] |
| P4 | No shared service workers | Cross-profile service-worker test | integration | [ ] |
| P5 | No shared history | Cross-profile history test | integration | [ ] |
| P6 | No automatic export of data to the host | Download-quarantine test (`PermissionState::Quarantine`) | integration / browser-api | [ ] |
| P7 | One profile cannot be opened by two concurrent sessions | `profile::tests::locked_profile_cannot_open`; two-sessions-one-profile red-team | unit / integration | [x] unit |

---

## Browser (spec §14 — Przeglądarka)

| # | Criterion | Verifying test | Test type | Status |
|---|-----------|----------------|-----------|--------|
| B1 | The sandbox works (never `--no-sandbox`) | Sandbox-active integration check | integration | [ ] |
| B2 | Site Isolation works | Site-Isolation integration check | integration | [ ] |
| B3 | User-Agent version matches the engine version | UA-vs-engine consistency test | browser-api | [ ] |
| B4 | API values stay stable within a session | Cross-context stability probe (Canvas/WebGL/Audio in main/iframe/worker) | browser-api | [ ] |
| B5 | Worker and iframe see no contradictory properties | Same-value cross-context test | browser-api | [ ] |
| B6 | Normalization does not break Web Platform Tests unacceptably | WPT regression budget; `fingerprint::tests::levels_produce_valid_policies` | browser-api / unit | [x] unit (policy valid) |

---

## Updates (spec §14 — Aktualizacje)

| # | Criterion | Verifying test | Test type | Status |
|---|-----------|----------------|-----------|--------|
| U1 | An unsigned update is rejected | Signature-verification test | integration | [ ] |
| U2 | An older version is rejected (downgrade block) | `update::tests::version_ordering_and_parse`; downgrade-reject test | unit / integration | [x] unit |
| U3 | A corrupt update triggers rollback | Corrupt-artifact rollback test (`ApplyOutcome::RolledBack`) | integration | [ ] |
| U4 | Every component has an identifiable version and hash | `update::tests::manifest_roundtrips` (per-artifact SHA-256); SBOM presence check | unit / integration | [x] unit |

---

## Meta-criteria (spec §16)

| # | Criterion | Verifying test | Status |
|---|-----------|----------------|--------|
| M1 | Every protection is confirmed by an automated test | This checklist; CI gate over `tests/` suites | [ ] |
| M2 | Each Chromium modification is documented and covered by a regression test | `browser/chromium-patches` + patch-regression suite | [ ] |
| M3 | The UI never claims "100% anonymous" / "undetectable" | `ProtectionStatus::label` (four labels only); doc/UI review | [x] unit (labels) |
| M4 | Any failure ends in a block, never an unprotected connection | `error::tests::killswitch_classes`; fail-closed harness | [x] unit |

---

## Red-team scenarios that gate release (spec §15)

Each of the following must be automated and must result in a **block**, not a
degraded connection, before stable release: VPN stop mid-load; gateway restart;
bad DNS; DNS answer over IPv6; WebRTC STUN attempt; UDP outside the proxy; media
device read; font enumeration; Canvas in iframe/worker/main window; browser
restart in the same session; disposable-VM destruction during write; malicious
downloaded file; attempt to open a host file; renderer crash + crash-dump read;
two sessions opening the same profile; attempt to launch with no working kill
switch.
