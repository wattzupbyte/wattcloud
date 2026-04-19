// Buffered chunk writer: accumulates bytes and flushes at exact chunk boundaries.
//
// Port of `/byo/src/streaming/ChunkWriter.ts`.
//
// Purpose: some storage providers (e.g. S3 multipart, Dropbox upload sessions)
// require each uploaded part to be an exact multiple of a fixed chunk size.
// V7 frames arrive at arbitrary sizes (the frame overhead adds 32 bytes per
// 512 KiB plaintext chunk). `ChunkWriter` absorbs the mismatch by accumulating
// frames until the buffer is full, then flushing one exact chunk.
//
// The depth-1 pipelining from the TypeScript version (fire-without-await) does
// not apply in synchronous Rust — callers that need overlapped I/O should
// arrange that at the platform layer (e.g. spawning a Tokio task around each
// `put_chunk` call). Here the flush callback is synchronous and blocking.
//
// Security: the buffer is zeroed on each flush after the `put_chunk` callback
// returns. The callback receives a direct slice reference (no copy), so the
// ciphertext bytes are visible only during the synchronous callback duration.

use crate::error::{CryptoError, SdkError};

/// Accumulates bytes and flushes them to a callback in fixed-size chunks.
///
/// # Usage
///
/// ```rust,ignore
/// let mut cw = ChunkWriter::new(128 * 1024 * 1024)?; // 128 MiB Dropbox parts
/// for frame in v7_frames {
///     cw.write(&frame, |idx, part| provider.upload_part(idx, part))?;
/// }
/// cw.finish(|idx, part| provider.upload_part(idx, part))?;
/// ```
pub struct ChunkWriter {
    buf: Vec<u8>,
    /// Number of bytes currently in `buf`.
    used: usize,
    /// Total bytes flushed so far (excludes pending bytes in `buf`).
    bytes_flushed: usize,
    /// Monotonically increasing index passed to each `put_chunk` call.
    chunk_index: usize,
    /// Size at which to flush a chunk.
    flush_at: usize,
}

impl ChunkWriter {
    /// Create a new writer that flushes once `flush_at` bytes have been
    /// accumulated.
    ///
    /// Returns `Err` if `flush_at` is zero.
    pub fn new(flush_at: usize) -> Result<Self, SdkError> {
        if flush_at == 0 {
            return Err(SdkError::Crypto(CryptoError::InvalidFormat(
                "ChunkWriter: flush_at must be non-zero".into(),
            )));
        }
        Ok(Self {
            buf: vec![0u8; flush_at],
            used: 0,
            bytes_flushed: 0,
            chunk_index: 0,
            flush_at,
        })
    }

    /// Append `bytes` to the buffer, flushing complete chunks via `put_chunk`.
    ///
    /// `put_chunk(chunk_index, data)` is called once per full chunk in order.
    /// Returns the first error returned by `put_chunk`, leaving the writer in
    /// an indeterminate state (the caller should abort the upload).
    pub fn write<F>(&mut self, bytes: &[u8], mut put_chunk: F) -> Result<(), SdkError>
    where
        F: FnMut(usize, &[u8]) -> Result<(), SdkError>,
    {
        let mut offset = 0usize;
        while offset < bytes.len() {
            let room = self.flush_at - self.used;
            let take = (bytes.len() - offset).min(room);
            // Both slice bounds are safe by construction (take ≤ room, take ≤ remaining bytes),
            // but we use .get() per project convention to avoid any direct indexing panics.
            let dst = self.buf.get_mut(self.used..self.used + take).ok_or_else(|| {
                SdkError::Crypto(CryptoError::InvalidFormat(
                    "ChunkWriter: write destination out of range".into(),
                ))
            })?;
            let src = bytes.get(offset..offset + take).ok_or_else(|| {
                SdkError::Crypto(CryptoError::InvalidFormat(
                    "ChunkWriter: write source out of range".into(),
                ))
            })?;
            dst.copy_from_slice(src);
            self.used += take;
            offset += take;
            if self.used == self.flush_at {
                self.flush(&mut put_chunk)?;
            }
        }
        Ok(())
    }

    /// Flush any remaining bytes as a final (possibly shorter-than-flush_at) chunk.
    ///
    /// Must be called after all `write` calls. If the buffer is empty, no call
    /// to `put_chunk` is made.
    pub fn finish<F>(&mut self, mut put_chunk: F) -> Result<(), SdkError>
    where
        F: FnMut(usize, &[u8]) -> Result<(), SdkError>,
    {
        if self.used > 0 {
            self.flush(&mut put_chunk)?;
        }
        Ok(())
    }

    /// Total bytes flushed so far (does not include pending bytes in the buffer).
    pub fn bytes_flushed(&self) -> usize {
        self.bytes_flushed
    }

    /// Emit the used portion of the buffer via `put_chunk`, then zero it and reset.
    ///
    /// `put_chunk` receives a direct reference into the buffer (no copy). The
    /// callback is synchronous and cannot retain the slice past its return, so
    /// we zero the buffer immediately after the callback returns — this is the
    /// only site where ciphertext bytes exist in `self.buf`.
    fn flush<F>(&mut self, put_chunk: &mut F) -> Result<(), SdkError>
    where
        F: FnMut(usize, &[u8]) -> Result<(), SdkError>,
    {
        let used = self.used;
        let idx = self.chunk_index;

        // Call the callback with a reference into the live buffer slice.
        // NLL borrow ends when `result` is bound (before the `fill(0)` below).
        let result = {
            let data = self.buf.get(..used).ok_or_else(|| {
                SdkError::Crypto(CryptoError::InvalidFormat(
                    "ChunkWriter: flush buffer index out of range".into(),
                ))
            })?;
            put_chunk(idx, data)
        };

        // Zero the used portion now that the callback has returned and can no
        // longer hold the reference. This matches the documented invariant.
        if let Some(slice) = self.buf.get_mut(..used) {
            slice.fill(0);
        }

        self.bytes_flushed += used;
        self.used = 0;
        self.chunk_index += 1;

        result
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn collecting_writer(flush_at: usize) -> (ChunkWriter, Vec<(usize, Vec<u8>)>) {
        (ChunkWriter::new(flush_at).unwrap(), Vec::new())
    }

    #[test]
    fn write_less_than_flush_at_does_not_flush() {
        let (mut cw, mut chunks) = collecting_writer(4);
        cw.write(&[1, 2], |idx, data| {
            chunks.push((idx, data.to_vec()));
            Ok(())
        })
        .unwrap();
        assert!(chunks.is_empty(), "no flush before buffer full");
        assert_eq!(cw.bytes_flushed(), 0);
    }

    #[test]
    fn write_exact_flush_at_flushes_once() {
        let (mut cw, mut chunks) = collecting_writer(4);
        cw.write(&[1, 2, 3, 4], |idx, data| {
            chunks.push((idx, data.to_vec()));
            Ok(())
        })
        .unwrap();
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0], (0, vec![1, 2, 3, 4]));
        assert_eq!(cw.bytes_flushed(), 4);
    }

    #[test]
    fn write_across_boundary_flushes_correctly() {
        let (mut cw, mut chunks) = collecting_writer(4);
        // Write 6 bytes: first full chunk (4) + 2 pending
        cw.write(&[1, 2, 3, 4, 5, 6], |idx, data| {
            chunks.push((idx, data.to_vec()));
            Ok(())
        })
        .unwrap();
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0], (0, vec![1, 2, 3, 4]));

        // Finish flushes remaining 2 bytes
        cw.finish(|idx, data| {
            chunks.push((idx, data.to_vec()));
            Ok(())
        })
        .unwrap();
        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks[1], (1, vec![5, 6]));
        assert_eq!(cw.bytes_flushed(), 6);
    }

    #[test]
    fn multiple_full_chunks_sequentially() {
        let (mut cw, mut chunks) = collecting_writer(4);
        // Write 12 bytes = 3 full chunks of 4
        for byte_val in 0u8..12 {
            cw.write(&[byte_val], |idx, data| {
                chunks.push((idx, data.to_vec()));
                Ok(())
            })
            .unwrap();
        }
        assert_eq!(chunks.len(), 3);
        assert_eq!(chunks[0].0, 0);
        assert_eq!(chunks[1].0, 1);
        assert_eq!(chunks[2].0, 2);
    }

    #[test]
    fn finish_on_empty_buffer_does_not_flush() {
        let (mut cw, mut chunks) = collecting_writer(4);
        cw.write(&[1, 2, 3, 4], |idx, data| {
            chunks.push((idx, data.to_vec()));
            Ok(())
        })
        .unwrap();
        // Buffer is empty after write; finish should not add another chunk
        cw.finish(|idx, data| {
            chunks.push((idx, data.to_vec()));
            Ok(())
        })
        .unwrap();
        assert_eq!(chunks.len(), 1);
    }

    #[test]
    fn finish_on_no_data_does_nothing() {
        let (mut cw, mut chunks) = collecting_writer(4);
        cw.finish(|idx, data| {
            chunks.push((idx, data.to_vec()));
            Ok(())
        })
        .unwrap();
        assert!(chunks.is_empty());
    }

    #[test]
    fn chunk_indices_are_sequential() {
        let (mut cw, mut indices) = collecting_writer(2);
        cw.write(&[0u8; 8], |idx, _| {
            indices.push((idx, vec![]));
            Ok(())
        })
        .unwrap();
        assert_eq!(indices.iter().map(|(i, _)| *i).collect::<Vec<_>>(), vec![0, 1, 2, 3]);
    }

    #[test]
    fn error_from_put_chunk_propagates() {
        let mut cw = ChunkWriter::new(4).unwrap();
        let result = cw.write(&[1, 2, 3, 4], |_, _| {
            Err(SdkError::Storage("disk full".into()))
        });
        assert!(result.is_err());
    }
}
