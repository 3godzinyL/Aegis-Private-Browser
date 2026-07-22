//! Concrete transports (spec §4: "lokalne Unix socket z autoryzacją").
//!
//! Two implementations, selected at compile time:
//!
//! * **unix** (the `unix` module): a `UnixListener`/`UnixStream` pair. Every accepted
//!   connection is authorized by reading its peer credentials (`SO_PEERCRED`)
//!   and comparing the peer uid against an [`AuthPolicy`]. Only the daemon's own
//!   uid, or an explicitly-configured allowed uid, may talk to the daemon.
//!   Unauthorized connections are closed immediately (fail-closed).
//!
//! * **non-unix** (the `tcp` module, compiled on Windows for development): a loopback TCP
//!   listener bound to `127.0.0.1` (never a routable interface), guarded by a
//!   shared-token handshake. The token is read from a file that the daemon and
//!   the front-end both have access to; on connect, the client sends the token
//!   as the first frame and the server compares it in constant time before
//!   accepting any request. **This transport is development-only** — it does not
//!   provide the kernel-enforced peer authentication of a Unix socket and must
//!   not be used in a production deployment.
//!
//! Both expose the same shape: a `*Listener` implementing the `Listener` trait (so it
//! plugs straight into [`crate::serve`]) and a `connect` function returning a
//! ready [`crate::IpcClient`].

/// Who is allowed to connect to the daemon socket.
///
/// The policy is evaluated against the peer's uid (unix) after reading
/// `SO_PEERCRED`. It always permits the daemon's own uid; an optional additional
/// uid may be configured (e.g. a dedicated `aegis` service account talking to a
/// root-owned daemon).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthPolicy {
    /// The uid of the daemon process itself. Always allowed.
    pub self_uid: u32,
    /// An additional allowed uid, if configured.
    pub allowed_uid: Option<u32>,
}

impl AuthPolicy {
    /// A policy allowing only the given (daemon) uid.
    #[must_use]
    pub const fn same_uid(self_uid: u32) -> Self {
        Self {
            self_uid,
            allowed_uid: None,
        }
    }

    /// A policy allowing the daemon uid plus one extra uid.
    #[must_use]
    pub const fn with_allowed(self_uid: u32, allowed_uid: u32) -> Self {
        Self {
            self_uid,
            allowed_uid: Some(allowed_uid),
        }
    }

    /// Whether a peer with the given uid is authorized.
    #[must_use]
    pub fn permits(&self, peer_uid: u32) -> bool {
        peer_uid == self.self_uid || self.allowed_uid == Some(peer_uid)
    }
}

// ---------------------------------------------------------------------------
// unix transport
// ---------------------------------------------------------------------------

/// Unix-domain socket transport with `SO_PEERCRED` authorization.
#[cfg(unix)]
pub mod unix {
    use super::AuthPolicy;
    use crate::client::IpcClient;
    use crate::server::Listener;
    use async_trait::async_trait;
    use std::path::{Path, PathBuf};
    use tokio::net::{UnixListener, UnixStream};

    /// A Unix-domain socket listener that authorizes each connection by peer uid.
    #[derive(Debug)]
    pub struct UnixSocketListener {
        listener: UnixListener,
        policy: AuthPolicy,
        path: PathBuf,
    }

    impl UnixSocketListener {
        /// Bind a new listening socket at `path` with the given [`AuthPolicy`].
        ///
        /// Any stale socket file at `path` is removed first. The socket is left
        /// with default permissions; callers that need tighter filesystem
        /// permissions should set the parent directory mode and/or `umask`
        /// before binding (belt-and-braces on top of the peer-cred check).
        ///
        /// # Errors
        /// Returns [`aegis_core::Error::System`] if binding fails.
        pub fn bind(path: impl AsRef<Path>, policy: AuthPolicy) -> aegis_core::Result<Self> {
            let path = path.as_ref().to_path_buf();
            // Remove a stale socket so bind() does not fail with EADDRINUSE.
            if path.exists() {
                let _ = std::fs::remove_file(&path);
            }
            let listener = UnixListener::bind(&path)
                .map_err(|e| aegis_core::Error::System(format!("bind unix socket: {e}")))?;
            Ok(Self {
                listener,
                policy,
                path,
            })
        }

        /// The bound socket path.
        #[must_use]
        pub fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for UnixSocketListener {
        fn drop(&mut self) {
            // Best-effort cleanup of the socket file.
            let _ = std::fs::remove_file(&self.path);
        }
    }

    #[async_trait]
    impl Listener for UnixSocketListener {
        type Conn = UnixStream;

        async fn accept(&self) -> aegis_core::Result<Self::Conn> {
            loop {
                let (stream, _addr) = self
                    .listener
                    .accept()
                    .await
                    .map_err(|e| aegis_core::Error::System(format!("accept: {e}")))?;

                match peer_uid(&stream) {
                    Ok(uid) if self.policy.permits(uid) => return Ok(stream),
                    Ok(uid) => {
                        // Log only the coarse uid decision, never any payload.
                        tracing::warn!(peer_uid = uid, "ipc: rejected unauthorized peer");
                        drop(stream); // fail-closed: refuse and wait for the next
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "ipc: could not read peer credentials");
                        drop(stream);
                    }
                }
            }
        }
    }

    /// Read the peer's uid from a connected [`UnixStream`] via `SO_PEERCRED`.
    ///
    /// Uses `nix`'s safe `getsockopt` wrapper, borrowing the socket via `AsFd`
    /// — no `unsafe` and no raw-fd juggling, so the crate's
    /// `#![forbid(unsafe_code)]` holds.
    ///
    /// `SO_PEERCRED` is a Linux/Android facility (the project's target platform,
    /// spec §4). On other unix variants (macOS/BSD) it is unavailable, so this
    /// returns [`aegis_core::Error::Unsupported`] — and, because peer
    /// authorization cannot be performed there, the caller (fail-closed) drops
    /// the connection.
    ///
    /// # Errors
    /// Returns [`aegis_core::Error::System`] if the credential cannot be read, or
    /// [`aegis_core::Error::Unsupported`] on a unix platform without
    /// `SO_PEERCRED`.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    pub fn peer_uid(stream: &UnixStream) -> aegis_core::Result<u32> {
        let cred = nix::sys::socket::getsockopt(stream, nix::sys::socket::sockopt::PeerCredentials)
            .map_err(|e| aegis_core::Error::System(format!("SO_PEERCRED: {e}")))?;
        Ok(cred.uid())
    }

    /// Fallback for unix platforms without `SO_PEERCRED` (macOS/BSD): peer-uid
    /// authorization is unsupported, so this always fails closed.
    ///
    /// # Errors
    /// Always returns [`aegis_core::Error::Unsupported`].
    #[cfg(all(unix, not(any(target_os = "linux", target_os = "android"))))]
    pub fn peer_uid(_stream: &UnixStream) -> aegis_core::Result<u32> {
        Err(aegis_core::Error::Unsupported(
            "SO_PEERCRED peer authorization is only implemented on Linux".into(),
        ))
    }

    /// Connect to the daemon's Unix socket, returning a ready [`IpcClient`].
    ///
    /// # Errors
    /// Returns [`aegis_core::Error::System`] if the socket cannot be reached.
    pub async fn connect(path: impl AsRef<Path>) -> aegis_core::Result<IpcClient<UnixStream>> {
        let stream = UnixStream::connect(path.as_ref())
            .await
            .map_err(|e| aegis_core::Error::System(format!("connect unix socket: {e}")))?;
        Ok(IpcClient::new(stream))
    }
}

// ---------------------------------------------------------------------------
// non-unix (Windows dev) transport
// ---------------------------------------------------------------------------

/// Loopback-TCP + shared-token transport for **development on non-unix hosts**.
///
/// This module is compiled only on non-unix targets. It is a stand-in for the
/// Unix socket so the workspace builds and can be exercised on a Windows
/// developer machine. It offers *no* kernel-enforced peer authentication; the
/// only gate is a shared secret token. **Do not ship this in production.**
#[cfg(not(unix))]
pub mod tcp {
    use crate::client::IpcClient;
    use crate::frame::{read_frame, write_frame};
    use crate::server::Listener;
    use async_trait::async_trait;
    use serde::{Deserialize, Serialize};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::path::Path;
    use tokio::net::{TcpListener, TcpStream};

    /// The maximum accepted token length, to bound the handshake frame.
    const MAX_TOKEN_LEN: usize = 512;

    /// The handshake message exchanged before any [`crate::Request`].
    #[derive(Debug, Clone, Serialize, Deserialize)]
    struct Handshake {
        token: String,
    }

    /// The server's handshake acknowledgement.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    struct HandshakeAck {
        ok: bool,
    }

    /// Read a shared token from a file, trimming trailing whitespace/newline.
    ///
    /// The token itself is never logged.
    ///
    /// # Errors
    /// Returns [`aegis_core::Error::System`] if the file cannot be read, or
    /// [`aegis_core::Error::Config`] if it is empty or too long.
    pub fn read_token(path: impl AsRef<Path>) -> aegis_core::Result<String> {
        let raw = std::fs::read_to_string(path.as_ref())
            .map_err(|e| aegis_core::Error::System(format!("read token file: {e}")))?;
        let token = raw.trim().to_string();
        if token.is_empty() {
            return Err(aegis_core::Error::Config("token file is empty".into()));
        }
        if token.len() > MAX_TOKEN_LEN {
            return Err(aegis_core::Error::Config("token is too long".into()));
        }
        Ok(token)
    }

    /// Constant-time comparison of two tokens (avoids timing side-channels).
    fn tokens_match(a: &str, b: &str) -> bool {
        let a = a.as_bytes();
        let b = b.as_bytes();
        // Length check is not secret (both are local files), but fold it in.
        let mut diff = (a.len() ^ b.len()) as u8;
        let n = a.len().max(b.len());
        for i in 0..n {
            let x = a.get(i).copied().unwrap_or(0);
            let y = b.get(i).copied().unwrap_or(0);
            diff |= x ^ y;
        }
        diff == 0
    }

    /// A loopback-TCP listener guarded by a shared token (development only).
    #[derive(Debug)]
    pub struct TcpDevListener {
        listener: TcpListener,
        token: String,
    }

    impl TcpDevListener {
        /// Bind a loopback listener on `127.0.0.1:port` (port 0 = ephemeral).
        ///
        /// # Errors
        /// Returns [`aegis_core::Error::System`] if binding fails.
        pub async fn bind(port: u16, token: String) -> aegis_core::Result<Self> {
            let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
            let listener = TcpListener::bind(addr)
                .await
                .map_err(|e| aegis_core::Error::System(format!("bind loopback tcp: {e}")))?;
            Ok(Self { listener, token })
        }

        /// The actual bound address (useful when binding to port 0).
        ///
        /// # Errors
        /// Returns [`aegis_core::Error::System`] if the address cannot be read.
        pub fn local_addr(&self) -> aegis_core::Result<SocketAddr> {
            self.listener
                .local_addr()
                .map_err(|e| aegis_core::Error::System(format!("local_addr: {e}")))
        }

        /// Perform the server side of the token handshake on a fresh stream.
        async fn authorize(&self, stream: &mut TcpStream) -> aegis_core::Result<bool> {
            let hs: Handshake = read_frame(stream).await.map_err(aegis_core::Error::from)?;
            let ok = tokens_match(&hs.token, &self.token);
            write_frame(stream, &HandshakeAck { ok })
                .await
                .map_err(aegis_core::Error::from)?;
            Ok(ok)
        }
    }

    #[async_trait]
    impl Listener for TcpDevListener {
        type Conn = TcpStream;

        async fn accept(&self) -> aegis_core::Result<Self::Conn> {
            loop {
                let (mut stream, peer) = self
                    .listener
                    .accept()
                    .await
                    .map_err(|e| aegis_core::Error::System(format!("accept: {e}")))?;
                // Refuse anything that is not loopback (defence in depth).
                if !peer.ip().is_loopback() {
                    tracing::warn!("ipc(tcp-dev): rejected non-loopback peer");
                    continue;
                }
                match self.authorize(&mut stream).await {
                    Ok(true) => return Ok(stream),
                    Ok(false) => {
                        tracing::warn!("ipc(tcp-dev): rejected bad token");
                        // Fail-closed: drop and wait for the next connection.
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "ipc(tcp-dev): handshake failed");
                    }
                }
            }
        }
    }

    /// Connect to a loopback-TCP dev daemon, performing the token handshake.
    ///
    /// # Errors
    /// Returns [`aegis_core::Error::System`] on a connection/handshake I/O fault,
    /// or [`aegis_core::Error::Precondition`] if the server rejects the token.
    pub async fn connect(
        addr: SocketAddr,
        token: String,
    ) -> aegis_core::Result<IpcClient<TcpStream>> {
        let mut stream = TcpStream::connect(addr)
            .await
            .map_err(|e| aegis_core::Error::System(format!("connect loopback tcp: {e}")))?;
        write_frame(&mut stream, &Handshake { token })
            .await
            .map_err(aegis_core::Error::from)?;
        let ack: HandshakeAck = read_frame(&mut stream)
            .await
            .map_err(aegis_core::Error::from)?;
        if !ack.ok {
            return Err(aegis_core::Error::Precondition(
                "ipc token handshake rejected".into(),
            ));
        }
        Ok(IpcClient::new(stream))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_policy_same_uid() {
        let p = AuthPolicy::same_uid(1000);
        assert!(p.permits(1000));
        assert!(!p.permits(0));
        assert!(!p.permits(1001));
    }

    #[test]
    fn auth_policy_with_extra_allowed_uid() {
        let p = AuthPolicy::with_allowed(0, 1000);
        assert!(p.permits(0)); // daemon (root)
        assert!(p.permits(1000)); // configured service account
        assert!(!p.permits(1001));
    }
}
