//! # aegis-redteam-tests
//!
//! Red-team scenario (spec §15) and acceptance-criteria (spec §14) integration
//! tests for the Aegis Private Browser workspace.
//!
//! The runnable tests live under `tests/` (one file per theme). This library
//! crate deliberately contains **no runtime code and no external dependencies**:
//! all of the Aegis crates are declared as `dev-dependencies` so they are only
//! pulled in when the integration tests are compiled (`cargo test`), which keeps
//! a plain `cargo build`/`cargo check` of this member fast and dependency-free.
//! The shared mock-wired `Orchestrator` builder that the end-to-end scenarios
//! reuse lives in `tests/harness/mod.rs`, mirroring
//! `crates/aegis-daemon/tests/integration.rs`.
//!
//! ## What is proven here
//!
//! * §15.1 / §15.2 tunnel & gateway drop → fail-closed kill switch, no Browsing.
//! * §15.3 bad DNS → checklist Unsafe, browsing refused.
//! * §15.4 IPv6 leak, §15.6 direct UDP outside the proxy → firewall drops.
//! * §15.5 WebRTC STUN, §15.7 media devices → Chromium policy forces the block.
//! * §15.15 two sessions / one persistent profile → second start is Busy.
//! * §15.16 start without a working kill switch → refused, fail-closed.
//! * §14 profile isolation, disposable teardown, signed/downgrade/rollback
//!   updates, and the "never advertised as undetectable" honesty invariant.

#![forbid(unsafe_code)]

/// The spec version these tests were written against, surfaced for traceability.
pub const SPEC: &str = "Aegis Private Browser — promt.txt §14 (acceptance) + §15 (red-team)";
