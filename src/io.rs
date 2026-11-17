//! A small `Write` helper with nothing specific to the wire protocol or the
//! daemon: `server::write_response` serializes once into a [`ByteCounter`]
//! to measure a value's encoded size, then once more into a buffer
//! allocated at exactly that size, so the real pass never reallocates — a
//! `Vec` that grows while being filled frees an unwiped copy of its earlier
//! contents at each reallocation, which matters for anything carrying a
//! secret.

use std::io::Write;

/// A `Write` that only counts, for sizing a buffer before filling it.
pub(crate) struct ByteCounter(pub(crate) usize);

impl Write for ByteCounter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0 += buf.len();
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
