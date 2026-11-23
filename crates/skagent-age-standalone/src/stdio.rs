//! The age client's end of the plugin: standard input and output, read and
//! written through their descriptors.
//!
//! `std::io::Stdin` and `Stdout` keep what passes in buffers of their own
//! for as long as the process lives. A PIN comes in here and a file key
//! goes out, so this reader wipes what it handed out, and this writer keeps
//! nothing.

use std::io::{self, BufRead, Read, Write};

use zeroize::Zeroize as _;

/// Bytes read from the age client at once.
const BUFFER_BYTES: usize = 4096;

/// A buffered reader that wipes what was read from it: once a caller
/// consumed bytes, they are zeros here.
pub struct ClientInput<R> {
    source: R,
    buffer: Box<[u8; BUFFER_BYTES]>,
    /// What of `buffer` is still to be read.
    start: usize,
    end: usize,
}

impl<R> std::fmt::Debug for ClientInput<R> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // What it holds may be a PIN on its way.
        formatter
            .debug_struct("ClientInput")
            .finish_non_exhaustive()
    }
}

impl<R: Read> ClientInput<R> {
    /// Reads from `source`.
    pub fn new(source: R) -> Self {
        Self {
            source,
            buffer: Box::new([0; BUFFER_BYTES]),
            start: 0,
            end: 0,
        }
    }

    /// All of the reader's buffer, for tests: nothing that was consumed is
    /// left in it.
    #[must_use]
    pub fn buffer(&self) -> &[u8] {
        self.buffer.as_slice()
    }
}

impl ClientInput<Stdin> {
    /// Reads the process's standard input.
    #[must_use]
    pub fn stdin() -> Self {
        Self::new(Stdin)
    }
}

impl<R: Read> BufRead for ClientInput<R> {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        if self.start >= self.end {
            self.start = 0;
            self.end = 0;
            let read = self.source.read(self.buffer.as_mut_slice())?;
            self.end = read.min(BUFFER_BYTES);
        }
        Ok(self.buffer.get(self.start..self.end).unwrap_or_default())
    }

    fn consume(&mut self, amount: usize) {
        let consumed = self.start.saturating_add(amount).min(self.end);
        if let Some(read) = self.buffer.get_mut(self.start..consumed) {
            read.zeroize();
        }
        self.start = consumed;
    }
}

impl<R: Read> Read for ClientInput<R> {
    fn read(&mut self, into: &mut [u8]) -> io::Result<usize> {
        let available = self.fill_buf()?;
        let count = available.len().min(into.len());
        if let (Some(from), Some(to)) = (available.get(..count), into.get_mut(..count)) {
            to.copy_from_slice(from);
        }
        self.consume(count);
        Ok(count)
    }
}

impl<R> Drop for ClientInput<R> {
    fn drop(&mut self) {
        self.buffer.zeroize();
    }
}

/// The process's standard input, read through its descriptor.
#[derive(Debug, Clone, Copy)]
pub struct Stdin;

impl Read for Stdin {
    fn read(&mut self, into: &mut [u8]) -> io::Result<usize> {
        loop {
            match rustix::io::read(rustix::stdio::stdin(), &mut *into) {
                Err(rustix::io::Errno::INTR) => {}
                read => return read.map_err(io::Error::from),
            }
        }
    }
}

/// The process's standard output, written through its descriptor: every
/// write goes out at once and nothing of it is kept.
#[derive(Debug, Clone, Copy)]
pub struct ClientOutput;

impl Write for ClientOutput {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        loop {
            match rustix::io::write(rustix::stdio::stdout(), bytes) {
                Err(rustix::io::Errno::INTR) => {}
                written => return written.map_err(io::Error::from),
            }
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
