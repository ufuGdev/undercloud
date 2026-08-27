// SPDX-License-Identifier: Apache-2.0
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum FormatError {
    #[error("invalid magic bytes")]
    InvalidMagic,
    #[error("unsupported format version: {0}")]
    UnsupportedVersion(u16),
    #[error("input truncated")]
    Truncated,
    #[error("unknown critical field: {0}")]
    UnknownCriticalField(u16),
}
