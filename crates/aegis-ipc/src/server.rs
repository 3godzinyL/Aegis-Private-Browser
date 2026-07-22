//! The server side: the [`RequestHandler`] contract and the connection/accept
//! loops that drive it.
//!
//! [`serve_connection`] is the portable core: it reads framed [`Request`]s from
//! any [`AsyncRead`] + [`AsyncWrite`] stream, dispatches each to a
//! [`RequestHandler`], and writes the framed [`Response`] back. It is used by the
//! Unix and TCP transports as well as directly over [`tokio::io::duplex`] in
//! tests.
//!
//! [`serve`] adapts an accept loop: a [`Listener`] that yields authorized,
//! already-authenticated connections, each of which is serviced on its own task.

use crate::frame::{read_frame, write_frame, FrameError};
use crate::protocol::{Request, Response};
use async_trait::async_trait;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};

/// Services requests for the daemon.
///
/// Implementors translate a [`Request`] into a [`Response`], mapping their own
/// errors through [`Response::from_error`] so the fail-closed
/// [`aegis_core::FailureClass`] is preserved on the wire. `handle` must never
/// panic and must never include secret material in a [`Response::Error`]
/// message.
#[async_trait]
pub trait RequestHandler: Send + Sync {
    /// Handle a single request and produce the response to send back.
    async fn handle(&self, req: Request) -> Response;
}

/// A source of already-authorized connections for [`serve`].
///
/// The transport layer is responsible for authorization (peer-credential check
/// on unix, token handshake on TCP) *before* yielding a stream here, so the
/// generic serve loop only ever sees trusted connections.
#[async_trait]
pub trait Listener: Send {
    /// The connection type yielded by this listener.
    type Conn: AsyncRead + AsyncWrite + Send + Unpin + 'static;

    /// Accept the next authorized connection.
    ///
    /// # Errors
    /// Returns an [`aegis_core::Error`] if the underlying accept fails. A
    /// connection that fails authorization is dropped internally and does not
    /// surface as an error (the loop simply moves on).
    async fn accept(&self) -> aegis_core::Result<Self::Conn>;
}

/// Drive a single framed connection against `handler` until the peer closes it.
///
/// Reads requests and writes responses in lock-step (one response per request).
/// Returns `Ok(())` on a clean close. Any framing fault (oversized/malformed
/// frame, I/O error) ends the connection and is returned as an error so the
/// caller can log it; the connection is not kept alive in an ambiguous state
/// (fail-closed).
///
/// # Errors
/// Returns the [`FrameError`] that terminated the connection, except a clean
/// close which yields `Ok(())`.
pub async fn serve_connection<S, H>(mut stream: S, handler: &H) -> Result<(), FrameError>
where
    S: AsyncRead + AsyncWrite + Unpin,
    H: RequestHandler + ?Sized,
{
    loop {
        let req: Request = match read_frame(&mut stream).await {
            Ok(req) => req,
            Err(FrameError::Closed) => return Ok(()),
            Err(e) => return Err(e),
        };
        let resp = handler.handle(req).await;
        write_frame(&mut stream, &resp).await?;
    }
}

/// Accept connections from `listener` and service each on its own task until the
/// listener stops yielding connections.
///
/// The handler is shared across connections via an [`Arc`]. Per-connection
/// framing faults are logged (without secrets) and do not tear down the loop —
/// one misbehaving client cannot deny service to others.
///
/// # Errors
/// Returns an error only if the *accept* call itself fails (e.g. the listening
/// socket was removed). Normal per-connection errors are handled internally.
pub async fn serve<L, H>(listener: L, handler: Arc<H>) -> aegis_core::Result<()>
where
    L: Listener,
    H: RequestHandler + 'static,
{
    loop {
        let conn = match listener.accept().await {
            Ok(conn) => conn,
            Err(e) => {
                // An accept failure is fatal for this listener; surface it.
                tracing::error!(error = %e, "ipc accept failed; stopping serve loop");
                return Err(e);
            }
        };
        let handler = Arc::clone(&handler);
        tokio::spawn(async move {
            if let Err(e) = serve_connection(conn, handler.as_ref()).await {
                // Never log request/response bodies — only the coarse cause.
                tracing::warn!(error = %e, "ipc connection ended with error");
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::IpcClient;
    use aegis_core::ids::{ProfileId, SessionId};
    use aegis_core::preflight::{CheckId, CheckReport, ConnectivityChecklist};
    use aegis_core::profile::{Profile, ProfileSpec, StorageUsage};
    use aegis_core::{Error, FailureClass};
    use chrono::Utc;

    /// A handler returning canned responses, and recording what it saw.
    struct CannedHandler {
        seen: tokio::sync::Mutex<Vec<&'static str>>,
    }

    impl CannedHandler {
        fn new() -> Self {
            Self {
                seen: tokio::sync::Mutex::new(Vec::new()),
            }
        }
        fn profile() -> Profile {
            Profile {
                id: ProfileId::from_uuid(uuid::Uuid::nil()),
                spec: ProfileSpec::ephemeral("canned"),
                created_at: Utc::now(),
                last_launched: None,
                storage: StorageUsage::default(),
                locked: false,
            }
        }
    }

    #[async_trait]
    impl RequestHandler for CannedHandler {
        async fn handle(&self, req: Request) -> Response {
            self.seen.lock().await.push(req.op_name());
            match req {
                Request::ListProfiles => Response::Profiles(vec![Self::profile()]),
                Request::DeleteProfile(_) => Response::Ok,
                Request::Doctor => Response::Doctor(ConnectivityChecklist::new(
                    CheckId::all()
                        .into_iter()
                        .map(|id| CheckReport::pass(id, "ok"))
                        .collect(),
                )),
                Request::GetDiagnostics(_) => {
                    Response::from_error(&Error::NotFound("no such session".into()))
                }
                Request::StartSession(_) => {
                    // Simulate a fail-closed containment error.
                    Response::from_error(&Error::NetworkContainment("tunnel down".into()))
                }
                other => Response::from_error(&Error::Unsupported(other.op_name().into())),
            }
        }
    }

    #[tokio::test]
    async fn full_client_server_roundtrip_over_duplex() {
        let (client_end, server_end) = tokio::io::duplex(64 * 1024);
        let handler = Arc::new(CannedHandler::new());
        let server_handler = Arc::clone(&handler);
        let server = tokio::spawn(async move {
            serve_connection(server_end, server_handler.as_ref())
                .await
                .unwrap();
        });

        let mut client = IpcClient::new(client_end);

        // 1. ListProfiles -> Profiles
        let resp = client.call(Request::ListProfiles).await.unwrap();
        match resp {
            Response::Profiles(ps) => assert_eq!(ps.len(), 1),
            other => panic!("expected Profiles, got {other:?}"),
        }

        // 2. Doctor -> Doctor(checklist all pass)
        let resp = client.call(Request::Doctor).await.unwrap();
        match resp {
            Response::Doctor(cl) => assert!(cl.all_passed()),
            other => panic!("expected Doctor, got {other:?}"),
        }

        // 3. DeleteProfile -> Ok
        let resp = client
            .call(Request::DeleteProfile(ProfileId::new()))
            .await
            .unwrap();
        assert_eq!(resp, Response::Ok);

        // 4. StartSession -> Error with NetworkContainment class preserved.
        let resp = client
            .call(Request::StartSession(aegis_core::session::SessionRequest {
                profile: ProfileId::new(),
                unlock_ref: None,
            }))
            .await
            .unwrap();
        assert_eq!(resp.error_class(), Some(FailureClass::NetworkContainment));

        // 5. GetDiagnostics -> Error NotFound (Precondition class).
        let resp = client
            .call(Request::GetDiagnostics(SessionId::new()))
            .await
            .unwrap();
        assert_eq!(resp.error_class(), Some(FailureClass::Precondition));

        // Closing the client ends the server loop cleanly.
        drop(client);
        server.await.unwrap();

        let seen = handler.seen.lock().await.clone();
        assert_eq!(
            seen,
            vec![
                "list-profiles",
                "doctor",
                "delete-profile",
                "start-session",
                "get-diagnostics"
            ]
        );
    }

    #[tokio::test]
    async fn server_rejects_oversized_frame() {
        use tokio::io::AsyncWriteExt;
        let (mut raw_client, server_end) = tokio::io::duplex(64);
        let handler = CannedHandler::new();
        let server = tokio::spawn(async move { serve_connection(server_end, &handler).await });

        // Send a bogus, oversized length prefix directly (bypassing the client).
        let bogus = (crate::frame::MAX_FRAME_LEN as u32) + 10;
        raw_client.write_all(&bogus.to_be_bytes()).await.unwrap();
        raw_client.flush().await.unwrap();

        let result = server.await.unwrap();
        assert!(
            matches!(result, Err(FrameError::TooLarge { .. })),
            "expected TooLarge, got {result:?}"
        );
    }

    #[tokio::test]
    async fn server_rejects_malformed_request_frame() {
        use tokio::io::AsyncWriteExt;
        let (mut raw_client, server_end) = tokio::io::duplex(1024);
        let handler = CannedHandler::new();
        let server = tokio::spawn(async move { serve_connection(server_end, &handler).await });

        // A validly-framed body that is not a Request.
        let junk = br#"{"op":"not-a-real-op"}"#;
        raw_client
            .write_all(&(junk.len() as u32).to_be_bytes())
            .await
            .unwrap();
        raw_client.write_all(junk).await.unwrap();
        raw_client.flush().await.unwrap();

        let result = server.await.unwrap();
        assert!(
            matches!(result, Err(FrameError::Decode(_))),
            "expected Decode, got {result:?}"
        );
    }

    #[tokio::test]
    async fn serve_loop_services_multiple_connections() {
        use tokio::sync::mpsc;

        // A mock Listener backed by an mpsc channel of duplex server ends.
        struct ChanListener {
            rx: tokio::sync::Mutex<mpsc::Receiver<tokio::io::DuplexStream>>,
        }
        #[async_trait]
        impl Listener for ChanListener {
            type Conn = tokio::io::DuplexStream;
            async fn accept(&self) -> aegis_core::Result<Self::Conn> {
                self.rx
                    .lock()
                    .await
                    .recv()
                    .await
                    .ok_or_else(|| Error::System("listener closed".into()))
            }
        }

        let (tx, rx) = mpsc::channel(4);
        let listener = ChanListener {
            rx: tokio::sync::Mutex::new(rx),
        };
        let handler = Arc::new(CannedHandler::new());
        let serve_task = tokio::spawn(serve(listener, Arc::clone(&handler)));

        // Two independent clients.
        for _ in 0..2 {
            let (client_end, server_end) = tokio::io::duplex(16 * 1024);
            tx.send(server_end).await.unwrap();
            let mut client = IpcClient::new(client_end);
            let resp = client.call(Request::ListProfiles).await.unwrap();
            assert!(matches!(resp, Response::Profiles(_)));
        }

        // Dropping the sender ends accept() -> serve returns Err(listener closed).
        drop(tx);
        let result = serve_task.await.unwrap();
        assert!(result.is_err());
    }
}
