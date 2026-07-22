//! # aegis-daemon (library)
//!
//! The privileged orchestrator that ties the Aegis workspace together (spec §3,
//! §5, §8, Etap 3). The binary (`aegis-daemon`) is a thin `main` over this
//! library so the whole integration surface can be unit- and integration-tested
//! with in-memory mocks.
//!
//! * [`Orchestrator`] — holds each capability as an `Arc<dyn …>` trait object and
//!   runs the fail-closed session lifecycle state machine
//!   ([`aegis_core::session::SessionState`]).
//! * [`Capabilities`] — the injected set of trait objects (VM, gateway, auditor,
//!   browser, profiles, secure store, updates, audit sink).
//! * [`DaemonHandler`] — the [`aegis_ipc::RequestHandler`] mapping every request
//!   to an orchestrator op.
//! * [`FileAuditSink`] / [`MemoryAuditSink`] — the append-only, secret-free audit
//!   sinks (production / test).
//! * [`load_config`] — TOML config loading with a safe default fallback.
//!
//! ## Fail-closed
//!
//! Any error whose [`aegis_core::Error::requires_killswitch`] is true engages the
//! gateway kill switch and records a `Critical`
//! [`aegis_core::events::EventKind::FailClosed`] audit event before propagating.
//! If preflight does not permit browsing, the session never reaches `Browsing`.
//!
//! ## Platform note (development)
//!
//! On non-Linux hosts the daemon still starts and serves IPC, but the privileged
//! system operations (libvirt, nftables, the guest channel) return
//! [`aegis_core::Error::Unsupported`] at runtime — so `start_session` fails
//! closed rather than pretending to provision anything. This keeps the workspace
//! buildable and the integration tests (which use mocks) green on Windows.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod audit;
pub mod config;
pub mod handler;
pub mod host_probe;
pub mod orchestrator;

pub use audit::{FileAuditSink, MemoryAuditSink};
pub use config::load_config;
pub use handler::DaemonHandler;
pub use host_probe::{HostNetworkProbe, TcpHostProbe};
pub use orchestrator::{Capabilities, Orchestrator};
