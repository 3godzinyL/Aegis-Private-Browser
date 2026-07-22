//! Length-prefixed JSON framing over any async byte stream.
//!
//! Wire format of a single frame:
//!
//! ```text
//! +-----------------------------+-------------------------------+
//! | u32 big-endian body length  | body: `len` bytes of UTF-8 JSON |
//! +-----------------------------+-------------------------------+
//! ```
//!
//! The helpers work over *any* [`AsyncRead`] / [`AsyncWrite`], which is what lets
//! the same code path be exercised over a real Unix socket, a loopback TCP
//! stream, or an in-memory [`tokio::io::duplex`] pipe in tests.
//!
//! Robustness / fail-closed rules:
//!
//! * A declared length greater than [`MAX_FRAME_LEN`] is rejected *before* any
//!   allocation, so a hostile or corrupt peer cannot make us allocate gigabytes.
//! * A body that is not valid UTF-8 JSON for the requested type is a
//!   [`FrameError::Decode`]; the caller treats a decode error as a protocol
//!   violation and drops the connection.
//! * A clean EOF at a frame boundary is surfaced as [`FrameError::Closed`] so the
//!   server loop can exit normally.

use serde::de::DeserializeOwned;
use serde::Serialize;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// The maximum accepted frame body size (16 MiB).
///
/// IPC payloads are small (profile lists, checklists, manifests); this ceiling
/// is far above any legitimate message yet small enough to bound memory use per
/// connection. Frames declaring a larger length are rejected without allocating.
pub const MAX_FRAME_LEN: usize = 16 * 1024 * 1024;

/// Errors that can occur while reading or writing a frame.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum FrameError {
    /// The underlying stream reached EOF cleanly at a frame boundary.
    #[error("connection closed")]
    Closed,

    /// The peer declared a body length exceeding [`MAX_FRAME_LEN`].
    #[error("frame too large: {len} bytes (max {max})")]
    TooLarge {
        /// The declared length.
        len: usize,
        /// The configured maximum.
        max: usize,
    },

    /// An I/O error occurred on the transport.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// The body could not be (de)serialized as JSON.
    #[error("frame decode error: {0}")]
    Decode(String),
}

impl FrameError {
    /// Whether the error is a clean end-of-stream (as opposed to a fault).
    #[must_use]
    pub const fn is_closed(&self) -> bool {
        matches!(self, Self::Closed)
    }
}

/// Map a [`FrameError`] into the workspace error taxonomy.
///
/// A closed connection is a benign `System` condition; a decode error or an
/// oversized frame is a `System`-class protocol fault (never a containment
/// class, since framing sits below the security policy).
impl From<FrameError> for aegis_core::Error {
    fn from(e: FrameError) -> Self {
        match e {
            FrameError::Closed => aegis_core::Error::System("connection closed".into()),
            FrameError::TooLarge { len, max } => {
                aegis_core::Error::System(format!("oversized frame: {len} > {max}"))
            }
            FrameError::Io(err) => aegis_core::Error::System(format!("io: {err}")),
            FrameError::Decode(msg) => aegis_core::Error::System(format!("decode: {msg}")),
        }
    }
}

/// Read one length-prefixed JSON frame and deserialize it as `T`.
///
/// # Errors
/// * [`FrameError::Closed`] on a clean EOF at the frame boundary.
/// * [`FrameError::TooLarge`] if the declared length exceeds [`MAX_FRAME_LEN`].
/// * [`FrameError::Io`] on any transport error (including a truncated body).
/// * [`FrameError::Decode`] if the body is not valid JSON for `T`.
pub async fn read_frame<R, T>(reader: &mut R) -> Result<T, FrameError>
where
    R: AsyncRead + Unpin,
    T: DeserializeOwned,
{
    let mut len_buf = [0u8; 4];
    // Distinguish a clean close (no bytes at all) from a truncated header.
    match reader.read_exact(&mut len_buf).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Err(FrameError::Closed),
        Err(e) => return Err(FrameError::Io(e)),
    }

    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_FRAME_LEN {
        return Err(FrameError::TooLarge {
            len,
            max: MAX_FRAME_LEN,
        });
    }

    let mut body = vec![0u8; len];
    reader.read_exact(&mut body).await.map_err(|e| {
        // A truncated body after a valid header is a hard I/O fault.
        FrameError::Io(e)
    })?;

    serde_json::from_slice::<T>(&body).map_err(|e| FrameError::Decode(e.to_string()))
}

/// Serialize `value` as JSON and write it as a single length-prefixed frame.
///
/// The buffer is flushed before returning so callers do not have to.
///
/// # Errors
/// * [`FrameError::Decode`] if the value cannot be serialized to JSON.
/// * [`FrameError::TooLarge`] if the serialized body exceeds [`MAX_FRAME_LEN`].
/// * [`FrameError::Io`] on any transport write error.
pub async fn write_frame<W, T>(writer: &mut W, value: &T) -> Result<(), FrameError>
where
    W: AsyncWrite + Unpin,
    T: Serialize,
{
    let body = serde_json::to_vec(value).map_err(|e| FrameError::Decode(e.to_string()))?;
    if body.len() > MAX_FRAME_LEN {
        return Err(FrameError::TooLarge {
            len: body.len(),
            max: MAX_FRAME_LEN,
        });
    }
    // u32 length prefix — bounded above by MAX_FRAME_LEN, so the cast is exact.
    let len = body.len() as u32;
    writer.write_all(&len.to_be_bytes()).await?;
    writer.write_all(&body).await?;
    writer.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};
    use tokio::io::AsyncWriteExt;

    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    struct Msg {
        n: u32,
        text: String,
        blob: Vec<u8>,
    }

    #[tokio::test]
    async fn frame_roundtrip_small() {
        let (mut a, mut b) = tokio::io::duplex(64 * 1024);
        let msg = Msg {
            n: 7,
            text: "hello".into(),
            blob: vec![1, 2, 3],
        };
        write_frame(&mut a, &msg).await.unwrap();
        let back: Msg = read_frame(&mut b).await.unwrap();
        assert_eq!(msg, back);
    }

    #[tokio::test]
    async fn frame_roundtrip_large_body() {
        // ~1 MiB body to exercise multi-read reassembly.
        let (mut a, mut b) = tokio::io::duplex(2 * 1024 * 1024);
        let msg = Msg {
            n: 42,
            text: "x".repeat(1000),
            blob: vec![0xAB; 1_000_000],
        };
        let writer = tokio::spawn(async move {
            write_frame(&mut a, &msg).await.unwrap();
            msg
        });
        let back: Msg = read_frame(&mut b).await.unwrap();
        let original = writer.await.unwrap();
        assert_eq!(original, back);
        assert_eq!(back.blob.len(), 1_000_000);
    }

    #[tokio::test]
    async fn multiple_frames_in_sequence() {
        let (mut a, mut b) = tokio::io::duplex(64 * 1024);
        for i in 0..5u32 {
            let m = Msg {
                n: i,
                text: format!("m{i}"),
                blob: vec![],
            };
            write_frame(&mut a, &m).await.unwrap();
        }
        for i in 0..5u32 {
            let got: Msg = read_frame(&mut b).await.unwrap();
            assert_eq!(got.n, i);
        }
    }

    #[tokio::test]
    async fn clean_eof_is_closed() {
        let (a, mut b) = tokio::io::duplex(64);
        drop(a); // close the write half without sending anything
        let err = read_frame::<_, Msg>(&mut b).await.unwrap_err();
        assert!(err.is_closed(), "expected Closed, got {err:?}");
    }

    #[tokio::test]
    async fn oversized_length_prefix_is_rejected_without_reading_body() {
        let (mut a, mut b) = tokio::io::duplex(64);
        // Declare a body far larger than MAX_FRAME_LEN, then send nothing.
        let bogus_len = (MAX_FRAME_LEN as u32) + 1;
        a.write_all(&bogus_len.to_be_bytes()).await.unwrap();
        a.flush().await.unwrap();
        let err = read_frame::<_, Msg>(&mut b).await.unwrap_err();
        match err {
            FrameError::TooLarge { len, max } => {
                assert_eq!(len, bogus_len as usize);
                assert_eq!(max, MAX_FRAME_LEN);
            }
            other => panic!("expected TooLarge, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn malformed_json_body_is_decode_error() {
        let (mut a, mut b) = tokio::io::duplex(1024);
        let junk = b"this is not json";
        let len = junk.len() as u32;
        a.write_all(&len.to_be_bytes()).await.unwrap();
        a.write_all(junk).await.unwrap();
        a.flush().await.unwrap();
        let err = read_frame::<_, Msg>(&mut b).await.unwrap_err();
        assert!(matches!(err, FrameError::Decode(_)), "got {err:?}");
    }

    #[tokio::test]
    async fn truncated_body_is_io_error() {
        let (mut a, mut b) = tokio::io::duplex(1024);
        // Declare 100 bytes, send only 10, then close.
        a.write_all(&100u32.to_be_bytes()).await.unwrap();
        a.write_all(&[0u8; 10]).await.unwrap();
        a.flush().await.unwrap();
        drop(a);
        let err = read_frame::<_, Msg>(&mut b).await.unwrap_err();
        assert!(matches!(err, FrameError::Io(_)), "got {err:?}");
    }

    #[tokio::test]
    async fn frame_error_maps_to_system_class() {
        let e: aegis_core::Error = FrameError::TooLarge {
            len: 999,
            max: MAX_FRAME_LEN,
        }
        .into();
        assert_eq!(e.class(), aegis_core::FailureClass::System);
    }
}
