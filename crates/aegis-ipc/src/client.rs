//! The client side: [`IpcClient`], a thin async request/response wrapper over
//! any connected, framed stream.
//!
//! The client is transport-agnostic — it holds a stream implementing
//! [`AsyncRead`] + [`AsyncWrite`] and speaks the [`crate::frame`] protocol over
//! it. The concrete constructors that dial a Unix socket or the loopback-TCP dev
//! transport live in [`crate::transport`]; this type is what they return.
//!
//! It is deliberately **single-connection, request/response** (call writes one
//! frame, then reads exactly one frame). That matches the daemon's one-response
//! -per-request contract and keeps the client trivially correct: there is no
//! pipelining or out-of-order matching to get wrong.

use crate::frame::{read_frame, write_frame, FrameError};
use crate::protocol::{Request, Response};
use tokio::io::{AsyncRead, AsyncWrite};

/// An IPC client over a single connected, framed stream.
#[derive(Debug)]
pub struct IpcClient<S> {
    stream: S,
}

impl<S> IpcClient<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    /// Wrap an already-connected stream.
    ///
    /// For the Unix socket or TCP dev transport, prefer the connecting
    /// constructors in [`crate::transport`], which perform the handshake first
    /// and hand back a ready [`IpcClient`].
    pub fn new(stream: S) -> Self {
        Self { stream }
    }

    /// Send a request and await its response.
    ///
    /// # Errors
    /// Returns a [`FrameError`] if the request cannot be written, the connection
    /// closes before a reply arrives ([`FrameError::Closed`]), or the reply frame
    /// is malformed/oversized. A [`Response::Error`] is **not** a transport error:
    /// it is returned as `Ok(Response::Error { .. })` so the caller inspects the
    /// fail-closed class.
    pub async fn call(&mut self, req: Request) -> Result<Response, FrameError> {
        write_frame(&mut self.stream, &req).await?;
        read_frame(&mut self.stream).await
    }

    /// Consume the client and return the underlying stream.
    pub fn into_inner(self) -> S {
        self.stream
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::serve_connection;
    use crate::server::RequestHandler;
    use async_trait::async_trait;

    struct EchoOk;
    #[async_trait]
    impl RequestHandler for EchoOk {
        async fn handle(&self, _req: Request) -> Response {
            Response::Ok
        }
    }

    #[tokio::test]
    async fn call_returns_response() {
        let (client_end, server_end) = tokio::io::duplex(4096);
        let server = tokio::spawn(async move {
            serve_connection(server_end, &EchoOk).await.unwrap();
        });
        let mut client = IpcClient::new(client_end);
        let resp = client.call(Request::ListSessions).await.unwrap();
        assert_eq!(resp, Response::Ok);
        drop(client);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn call_on_closed_connection_is_closed_error() {
        let (client_end, server_end) = tokio::io::duplex(4096);
        drop(server_end); // no server; peer half closed
        let mut client = IpcClient::new(client_end);
        let err = client.call(Request::ListSessions).await.unwrap_err();
        // Either the write fails (broken pipe -> Io) or the read hits EOF
        // (Closed); both are acceptable "peer gone" signals.
        assert!(
            matches!(err, FrameError::Closed | FrameError::Io(_)),
            "got {err:?}"
        );
    }
}
