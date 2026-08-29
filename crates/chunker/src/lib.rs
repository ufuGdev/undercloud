// SPDX-License-Identifier: Apache-2.0
//! Bounded-memory streaming chunker with a fixed-size channel for backpressure.
mod error;

pub use error::ChunkerError;

use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::sync::mpsc;

pub const DEFAULT_CHUNK_SIZE: usize = 6 * 1024 * 1024;
const CHANNEL_CAPACITY: usize = 4;

/// Emits fixed-size chunks with bounded backpressure; rejects a zero chunk size.
pub async fn chunk_stream<R>(
    mut reader: R,
    chunk_size: usize,
) -> Result<mpsc::Receiver<Result<Vec<u8>, ChunkerError>>, ChunkerError>
where
    R: AsyncRead + Unpin + Send + 'static,
{
    if chunk_size == 0 {
        return Err(ChunkerError::InvalidChunkSize(0));
    }

    let (tx, rx) = mpsc::channel(CHANNEL_CAPACITY);

    tokio::spawn(async move {
        loop {
            let mut buf = vec![0u8; chunk_size];
            let mut filled = 0usize;

            while filled < chunk_size {
                match reader.read(&mut buf[filled..]).await {
                    Ok(0) => break,
                    Ok(n) => filled += n,
                    Err(e) => {
                        let _ = tx.send(Err(ChunkerError::Io(e))).await;
                        return;
                    }
                }
            }

            if filled == 0 {
                break;
            }

            buf.truncate(filled);
            if tx.send(Ok(buf)).await.is_err() {
                return; // receiver dropped
            }

            if filled < chunk_size {
                break; // short read = end of stream
            }
        }
    });

    Ok(rx)
}
