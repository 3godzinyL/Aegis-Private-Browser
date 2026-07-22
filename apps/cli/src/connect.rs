//! Connecting the CLI to the daemon.
//!
//! Two transports, selected at compile time (mirroring `aegis_ipc::transport`):
//!
//! * **unix** — dial the daemon's `UnixListener` at the configured socket path.
//!   The kernel enforces peer-credential authorization on the daemon side; the
//!   client just connects.
//! * **non-unix (Windows dev only)** — dial a loopback-TCP endpoint and perform
//!   the shared-token handshake. The token is read from a file (never logged).
//!
//! Both return a boxed [`Call`] object so `main` can issue requests without
//! caring which transport it got. The token bytes are never logged or printed.

use crate::cli::GlobalArgs;
use aegis_core::Result;
use aegis_ipc::{Request, Response};

/// A minimal object-safe view over an [`aegis_ipc::IpcClient`]: send one request,
/// await one response. Boxed so `main` is transport-agnostic.
///
/// `#[async_trait]` on the trait *definition* desugars `call` into a boxed
/// future so the trait is dyn-compatible and can be used as `Box<dyn Call>`.
#[async_trait::async_trait]
pub trait Call: Send {
    /// Send a request and await the daemon's reply.
    async fn call(&mut self, req: Request) -> Result<Response>;
}

/// Default runtime directory used to derive socket / token paths when the user
/// does not override them. Mirrors [`aegis_core::config::Paths`] defaults on
/// unix; on non-unix hosts it is the OS temp dir (development only).
#[must_use]
pub fn default_runtime_dir() -> std::path::PathBuf {
    #[cfg(unix)]
    {
        std::path::PathBuf::from("/run/aegis")
    }
    #[cfg(not(unix))]
    {
        std::env::temp_dir().join("aegis")
    }
}

// ---------------------------------------------------------------------------
// unix
// ---------------------------------------------------------------------------

#[cfg(unix)]
mod imp {
    use super::{default_runtime_dir, Call, GlobalArgs};
    use aegis_core::Result;
    use aegis_ipc::transport::unix;
    use aegis_ipc::{IpcClient, Request, Response};
    use tokio::net::UnixStream;

    /// Wrapper implementing [`Call`] over a Unix-socket client.
    struct UnixCall(IpcClient<UnixStream>);

    #[async_trait::async_trait]
    impl Call for UnixCall {
        async fn call(&mut self, req: Request) -> Result<Response> {
            self.0
                .call(req)
                .await
                .map_err(|e| aegis_core::Error::System(format!("ipc: {e}")))
        }
    }

    /// Resolve the socket path: explicit `--socket`, else the default under the
    /// runtime dir (`/run/aegis/daemon.sock`).
    #[must_use]
    pub fn socket_path(args: &GlobalArgs) -> std::path::PathBuf {
        args.socket
            .clone()
            .unwrap_or_else(|| default_runtime_dir().join("daemon.sock"))
    }

    /// Connect over the Unix socket.
    ///
    /// # Errors
    /// Returns [`aegis_core::Error::System`] if the socket cannot be reached.
    pub async fn connect(args: &GlobalArgs) -> Result<Box<dyn Call>> {
        let path = socket_path(args);
        let client = unix::connect(&path).await.map_err(|_| {
            aegis_core::Error::System(format!(
                "cannot reach the daemon socket at {} (is aegis-daemon running? \
                 set --socket / AEGIS_SOCKET)",
                path.display()
            ))
        })?;
        Ok(Box::new(UnixCall(client)))
    }
}

// ---------------------------------------------------------------------------
// non-unix (Windows dev)
// ---------------------------------------------------------------------------

#[cfg(not(unix))]
mod imp {
    use super::{default_runtime_dir, Call, GlobalArgs};
    use aegis_core::Result;
    use aegis_ipc::transport::tcp;
    use aegis_ipc::{IpcClient, Request, Response};
    use std::net::{SocketAddr, ToSocketAddrs};
    use tokio::net::TcpStream;

    /// The default loopback endpoint for the Windows dev transport.
    const DEFAULT_ENDPOINT: &str = "127.0.0.1:7690";

    /// Wrapper implementing [`Call`] over the loopback-TCP dev client.
    struct TcpCall(IpcClient<TcpStream>);

    #[async_trait::async_trait]
    impl Call for TcpCall {
        async fn call(&mut self, req: Request) -> Result<Response> {
            self.0
                .call(req)
                .await
                .map_err(|e| aegis_core::Error::System(format!("ipc: {e}")))
        }
    }

    /// Resolve the loopback endpoint: explicit `--endpoint`, else the default.
    ///
    /// # Errors
    /// Returns [`aegis_core::Error::Config`] if the endpoint cannot be parsed,
    /// or [`aegis_core::Error::Precondition`] if it is not a loopback address
    /// (the dev transport must never bind a routable interface).
    pub fn endpoint_addr(args: &GlobalArgs) -> Result<SocketAddr> {
        let raw = args
            .endpoint
            .clone()
            .unwrap_or_else(|| DEFAULT_ENDPOINT.to_string());
        let addr = raw
            .to_socket_addrs()
            .map_err(|e| aegis_core::Error::Config(format!("invalid endpoint '{raw}': {e}")))?
            .next()
            .ok_or_else(|| {
                aegis_core::Error::Config(format!("endpoint '{raw}' resolved to nothing"))
            })?;
        if !addr.ip().is_loopback() {
            return Err(aegis_core::Error::Precondition(
                "the development endpoint must be a loopback address (127.0.0.1/::1)".into(),
            ));
        }
        Ok(addr)
    }

    /// Resolve the token-file path: explicit `--token-file`, else the default
    /// under the runtime dir (`<runtime>/ipc.token`).
    #[must_use]
    pub fn token_path(args: &GlobalArgs) -> std::path::PathBuf {
        args.token_file
            .clone()
            .unwrap_or_else(|| default_runtime_dir().join("ipc.token"))
    }

    /// Connect over the loopback-TCP dev transport, performing the token
    /// handshake. The token is read from a file and never logged.
    ///
    /// # Errors
    /// Returns an error if the token cannot be read, the endpoint is invalid, or
    /// the connection/handshake fails.
    pub async fn connect(args: &GlobalArgs) -> Result<Box<dyn Call>> {
        let addr = endpoint_addr(args)?;
        let token_path = token_path(args);
        // read_token never logs the token bytes; it only surfaces path errors.
        // We report the path (not the underlying nested Error) so the message
        // stays single-classed and actionable.
        let token = tcp::read_token(&token_path).map_err(|_| {
            aegis_core::Error::System(format!(
                "cannot read the dev IPC token at {} (is aegis-daemon running? \
                 set --token-file / AEGIS_TOKEN_FILE)",
                token_path.display()
            ))
        })?;
        let client = tcp::connect(addr, token).await.map_err(|_| {
            aegis_core::Error::System(format!(
                "cannot reach the dev daemon at {addr} (is aegis-daemon running? \
                 set --endpoint / AEGIS_ENDPOINT)"
            ))
        })?;
        Ok(Box::new(TcpCall(client)))
    }
}

pub use imp::connect;

// These path/endpoint resolvers are exercised by this module's own tests; the
// re-export keeps them reachable as `connect::…` without widening the public API
// beyond what the tests need.
#[cfg(not(unix))]
#[cfg_attr(not(test), allow(unused_imports))]
pub use imp::{endpoint_addr, token_path};

#[cfg(unix)]
#[cfg_attr(not(test), allow(unused_imports))]
pub use imp::socket_path;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_runtime_dir_is_nonempty() {
        assert!(!default_runtime_dir().as_os_str().is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn socket_path_prefers_explicit_flag() {
        assert!(socket_path(&GlobalArgs::default()).ends_with("daemon.sock"));
        let args = GlobalArgs {
            socket: Some(std::path::PathBuf::from("/tmp/custom.sock")),
            ..Default::default()
        };
        assert_eq!(
            socket_path(&args),
            std::path::PathBuf::from("/tmp/custom.sock")
        );
    }

    #[cfg(not(unix))]
    #[test]
    fn endpoint_defaults_to_loopback() {
        let args = GlobalArgs::default();
        let addr = endpoint_addr(&args).expect("default endpoint");
        assert!(addr.ip().is_loopback());
    }

    #[cfg(not(unix))]
    #[test]
    fn endpoint_rejects_non_loopback() {
        let args = GlobalArgs {
            endpoint: Some("8.8.8.8:7690".into()),
            ..Default::default()
        };
        assert!(endpoint_addr(&args).is_err());
    }

    #[cfg(not(unix))]
    #[test]
    fn token_path_prefers_explicit_flag() {
        assert!(token_path(&GlobalArgs::default()).ends_with("ipc.token"));
        let args = GlobalArgs {
            token_file: Some(std::path::PathBuf::from("C:/tmp/tok")),
            ..Default::default()
        };
        assert_eq!(token_path(&args), std::path::PathBuf::from("C:/tmp/tok"));
    }
}
