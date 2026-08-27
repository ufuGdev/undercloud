// SPDX-License-Identifier: Apache-2.0
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ChunkerError {
    #[error("I/O error while reading source stream: {0}")]
    Io(#[from] std::io::Error),
    #[error("chunk size of {0} bytes is invalid: it must be at least 1 byte")]
    InvalidChunkSize(usize),
}
