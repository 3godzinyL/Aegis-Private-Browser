//! # aegis-ipc
//!
//! The request/response protocol and transport that connect the Aegis UI/CLI to
//! the privileged Aegis daemon (spec §3, §4).
//!
//! The daemon is the only component that touches privileged system state
//! (libvirt, nftables, secure storage). Every unprivileged front-end talks to it
//! through this crate:
//!
//! * [`Request`] / [`Response`] — the serde-serializable command surface. Every
//!   response variant carries the matching [`aegis_core`] payload, plus a
//!   [`Response::Error`] carrying a message and a [`aegis_core::FailureClass`].
//! * [`frame`] — a portable, length-prefixed (u32 big-endian length + JSON body)
//!   async framing layer that works over *any* [`tokio::io::AsyncRead`] /
//!   [`tokio::io::AsyncWrite`] pair, including [`tokio::io::duplex`] for tests.
//! * [`RequestHandler`] — the trait the daemon implements to service requests.
//! * [`serve_connection`] — drive one framed connection against a handler.
//! * [`IpcClient`] — an async client over any framed stream, with a
//!   `call(req) -> Response` method.
//! * [`transport`] — the concrete listeners/streams. On **unix** a
//!   `UnixListener`/`UnixStream` with `SO_PEERCRED` peer-credential authorization
//!   (only the daemon's own uid, or a configured allowed uid, may connect). On
//!   **non-unix** (Windows development only) a loopback TCP transport on
//!   `127.0.0.1` guarded by a shared-token handshake read from a file.
//!
//! ## Security posture
//!
//! * Fail-closed: framing rejects oversized/malformed frames rather than
//!   attempting to recover ([`frame::MAX_FRAME_LEN`]); authorization failures
//!   drop the connection.
//! * No secrets are logged: the protocol carries only [`aegis_core`] domain
//!   payloads (which are secret-free by construction — passwords live behind a
//!   [`aegis_core::network::CredentialRef`]), and the transport never logs token
//!   bytes or peer credentials beyond a coarse uid for authorization decisions.
//! * The loopback-TCP transport is **development only** and is documented as such
//!   on `transport::TcpDevListener`; production deployments use the Unix socket.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod frame;
pub mod protocol;
pub mod transport;

mod client;
mod server;

pub use client::IpcClient;
pub use frame::{read_frame, write_frame, FrameError, MAX_FRAME_LEN};
pub use protocol::{Request, Response, StatusDto};
pub use server::{serve, serve_connection, RequestHandler};
