// SPDX-License-Identifier: Apache-2.0
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("incorrect password or corrupted key envelope")]
    UnwrapFailed,
    #[error("authentication failed: chunk or manifest content or identity does not match")]
    AuthenticationFailed,
    #[error("invalid key material length")]
    InvalidKeyLength,
}
