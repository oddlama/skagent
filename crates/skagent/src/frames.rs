//! A size limit for agent messages.
//!
//! ssh-agent-lib reads the 4-byte length of a message and buffers until the
//! whole message arrived, however long it claims to be (up to 4 GiB). Over a
//! forwarded agent the bytes come from another machine, so a hostile host
//! could make the agent buffer gigabytes per connection. [`BoundedStream`]
//! follows the message boundaries as the bytes go by and fails the read as
//! soon as a length above [`MAX_MESSAGE_LEN`] arrives, like OpenSSH's
//! ssh-agent does (`AGENT_MAX_LEN`). The library then drops the connection.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Longest message accepted, without its length prefix (OpenSSH:
/// `AGENT_MAX_LEN`).
pub const MAX_MESSAGE_LEN: u32 = 256 * 1024;

/// Bytes in a message's length prefix.
const LENGTH_PREFIX: usize = 4;

/// A stream that refuses agent messages longer than [`MAX_MESSAGE_LEN`].
/// Bytes pass through unchanged; writes aren't looked at.
#[derive(Debug)]
pub struct BoundedStream<S> {
    inner: S,
    /// The length prefix of the next message, as far as it arrived.
    prefix: [u8; LENGTH_PREFIX],
    prefix_len: usize,
    /// Bytes of the current message still to come.
    remaining: u32,
    /// Set once a message was too long; every later read fails too.
    refused: bool,
}

impl<S> BoundedStream<S> {
    /// Wraps `inner`, which must be at the start of a message.
    #[must_use]
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            prefix: [0; LENGTH_PREFIX],
            prefix_len: 0,
            remaining: 0,
            refused: false,
        }
    }

    /// The wrapped stream.
    #[must_use]
    pub fn get_ref(&self) -> &S {
        &self.inner
    }

    /// Follows the message boundaries through `bytes`, which were just read.
    fn scan(&mut self, mut bytes: &[u8]) -> io::Result<()> {
        while !bytes.is_empty() {
            if self.remaining > 0 {
                let available = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
                let taken = self.remaining.min(available);
                self.remaining = self.remaining.saturating_sub(taken);
                let taken = usize::try_from(taken).unwrap_or(bytes.len());
                bytes = bytes.get(taken..).unwrap_or_default();
                continue;
            }
            let Some((&byte, rest)) = bytes.split_first() else {
                break;
            };
            bytes = rest;
            if let Some(slot) = self.prefix.get_mut(self.prefix_len) {
                *slot = byte;
            }
            self.prefix_len = self.prefix_len.saturating_add(1);
            if self.prefix_len == LENGTH_PREFIX {
                self.prefix_len = 0;
                let length = u32::from_be_bytes(self.prefix);
                if length > MAX_MESSAGE_LEN {
                    self.refused = true;
                    tracing::warn!(
                        length,
                        limit = MAX_MESSAGE_LEN,
                        "refused an agent message longer than allowed, closing the connection"
                    );
                    return Err(too_long());
                }
                self.remaining = length;
            }
        }
        Ok(())
    }
}

fn too_long() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("agent message longer than {MAX_MESSAGE_LEN} bytes"),
    )
}

impl<S: AsyncRead + Unpin> AsyncRead for BoundedStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.refused {
            return Poll::Ready(Err(too_long()));
        }
        let before = buf.filled().len();
        ready!(Pin::new(&mut this.inner).poll_read(context, buf))?;
        let scanned = buf
            .filled()
            .get(before..)
            .map_or(Ok(()), |new| this.scan(new));
        if scanned.is_err() {
            // Nothing of the refused message reaches the reader.
            buf.set_filled(before);
        }
        Poll::Ready(scanned)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for BoundedStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(context, bytes)
    }

    fn poll_flush(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(context)
    }

    fn poll_shutdown(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(context)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffers: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write_vectored(context, buffers)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}
