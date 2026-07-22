# Aegis test suites

Aegis follows the spec rule *"każdą ochronę potwierdzić testem automatycznym"*
(every protection is confirmed by an automated test, §16). Tests live at three
levels:

1. **Unit tests inside each crate** — the bulk of the guarantees. Run with
   `cargo test --workspace` (238+ tests, all green).
2. **Workspace integration tests** in this directory — cross-crate flows driven
   through the daemon `Orchestrator` with mock controllers.
3. **Host/VM harnesses** (`firewall/tests`, image self-tests) that require a
   Linux host with `nft`/`ip netns` or a running VM; guarded to be safe to read
   and no-op where the tooling is absent.

## Layout

| Dir | Scope |
|-----|-------|
| `integration/` | End-to-end session lifecycle & IPC through the daemon with mocks. |
| `leak-harness/` | Network-leak scenarios (WebRTC/DNS/IPv6/UDP) as black-box + `netns` checks. |
| `browser-api/` | Browser-API normalization checks (Canvas/WebGL/fonts/timezone stability across contexts). |
| `network/` | Preflight-gate and fail-closed transitions. |
| `destructive/` | Disposable-VM destruction, crash/kill during write, double-open. |

## Red-team scenario coverage (spec §15)

| # | Scenario | Where verified |
|---|----------|----------------|
| 1 | VPN stops while a page loads | `gateway-controller` fail-closed tests; `firewall/tests/leak-scenarios.sh`; `network/` |
| 2 | Gateway restart | `gateway-controller` killswitch tests; daemon fail-closed integration test |
| 3 | Wrong DNS | `network-audit` `dns_route_ok` fail → `Unsafe`; `network/` |
| 4 | DNS answer over IPv6 | `firewall/nftables/ipv6-block.nft`; `firewall/tests` |
| 5 | WebRTC STUN attempt | `browser-launcher` WebRTC-flag test; `leak-harness/` |
| 6 | Open UDP outside proxy | `firewall` `block_direct_udp`; `firewall/tests`; `leak-harness/` |
| 7 | Read media devices | `browser-launcher` managed-policy test (capture=false, guards=block) |
| 8 | Enumerate fonts | `browser/chromium-patches` RT-FONTS; `browser-api/` |
| 9 | Canvas in iframe/worker/main | `browser/chromium-patches` RT-CANVAS; `browser-api/` |
| 10 | Restart browser in same session | daemon session integration test |
| 11 | Destroy disposable VM during write | `destructive/`; `vm-controller` destroy/shred test |
| 12 | Malicious downloaded file | permission table `Downloads=Quarantine`; `browser-api/` |
| 13 | Open a host file | permission `FileSystemAccess=ConfinedToVm`; image read-only-root |
| 14 | Renderer crash + read crash dump | `docs/security-acceptance-criteria.md`; image `LimitCORE=0` / no user-data core dumps |
| 15 | Two sessions open one profile | `profile-store` lock test; daemon `Busy` integration test |
| 16 | Start without a working kill switch | daemon preflight gate: no `Browsing` unless checklist permits |

## Acceptance criteria (spec §14)

See [`../docs/security-acceptance-criteria.md`](../docs/security-acceptance-criteria.md)
for the full Network / Host / Profiles / Browser / Updates checklist and the test
that verifies each row.

## Running

```sh
cargo test --workspace            # unit + workspace integration tests (cross-platform)
bash firewall/tests/leak-scenarios.sh   # firewall harness (Linux; static checks run anywhere)
```
