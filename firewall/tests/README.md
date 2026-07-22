# Firewall leak-scenario tests

Automated red-team checks for the Gateway VM firewall, covering the network
scenarios from `promt.txt` §15 and the acceptance criteria in §14/§16. These
tests assert that the nftables rulesets in [`../nftables/`](../nftables/) actually
enforce the fail-closed policy — they are the "każdą ochronę potwierdzić testem
automatycznym" (§16) requirement for the network layer.

## What is asserted

The harness maps directly to the spec's red-team list:

| Scenario (promt.txt) | What the test checks | Where enforced |
| --- | --- | --- |
| §15 zatrzymanie VPN / restart Gateway | kill switch drops **all** traffic; no established-state shortcut | `killswitch.nft` |
| §15 odpowiedź DNS przez IPv6 | every IPv6 chain is `policy drop`, so a DNS answer over v6 cannot traverse the gateway | `ipv6-block.nft` |
| §15 próba otwarcia UDP poza proxy | browser-subnet UDP is dropped (only DNS/53 is redirected, everything else blocked) | `gateway.nft` (`block_direct_udp`) |
| §16 brak awaryjnego powrotu do bezpośredniego połączenia | there is **no** accept rule routing the browser subnet straight out the upstream NIC; base policy is drop | `gateway.nft` |
| §5 przechwytywanie DNS | DNS (udp/tcp 53) is redirected into Tor's DNSPort/TransPort | `nat-tor.nft` |

These pair with the declarative `FirewallPolicy` in
`crates/aegis-core/src/gateway.rs`, whose unit tests assert the *policy* is
fail-closed; this harness asserts the *rendered nftables* enforce it.

## Running

```sh
firewall/tests/leak-scenarios.sh
```

The script is **safe to read and safe to run**. It auto-detects what the host
can do and degrades gracefully:

* **No `nft` installed** — skips syntax checks and live tests, runs static text
  assertions against the `.nft` files so a ruleset regression still fails CI.
* **`nft` present, not root** — additionally runs `nft -c -f` syntax validation.
* **Root + `ip netns` available** — additionally runs live tests inside a
  throwaway network namespace (Part B). The host's real firewall is **never**
  touched; the namespace is deleted on exit (trap on EXIT/INT/TERM).

Useful environment variables:

| Var | Effect |
| --- | --- |
| `VERBOSE=1` | echo every command before running it |
| `FORCE_STATIC=1` | skip live netns tests even if root (useful in constrained CI) |

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | all runnable assertions passed (skips are reported, not failures) |
| `1` | at least one assertion FAILED — treat as a leak / regression |
| `2` | environment problem prevented the harness from running at all |

## Structure

* **Part A — static assertions.** Always run. Parse the ruleset text (and run
  `nft -c` when available) to confirm each policy is present: default-drop on
  every chain, loopback + established allowed, direct UDP dropped, DNS/TCP
  redirected to Tor, IPv6 fully dropped, kill switch total, no direct fallback.
* **Part B — live packet tests.** Only when root + `ip netns` + `nft` are all
  present. Loads each real ruleset into an isolated namespace with a dummy
  upstream interface and asserts the loaded tables have the expected policies
  and rules. Nothing leaves the namespace.

## Notes for CI

On a typical Linux CI runner without `NET_ADMIN`, Part B is skipped and Part A
runs fully — that is the intended baseline and is enough to catch ruleset
regressions. To exercise Part B, run the job in a privileged container or a VM
with `CAP_NET_ADMIN` and the `nftables` + `iproute2` packages installed.

On non-Linux developers' machines (macOS/Windows) `nft`/`ip` are absent; the
harness still runs Part A's text assertions under Git Bash / WSL and reports the
rest as skipped.
