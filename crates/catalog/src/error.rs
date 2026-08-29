// SPDX-License-Identifier: Apache-2.0
//! Catalog errors expose structural details without SQL parameters or row data.
use thiserror::Error;

/// Errors returned by `crates/catalog`'s public API.
#[derive(Debug, Error)]
pub enum CatalogError {
    /// A SQLite error without a more specific catalog variant.
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),

    /// A migration failed and its transaction was rolled back.
    #[error("migration {version} failed: {source}")]
    MigrationFailed {
        version: u32,
        source: rusqlite::Error,
    },

    /// The database schema is newer than this crate supports.
    #[error(
        "catalog schema version {found} is newer than the {max_supported} this build supports"
    )]
    UnsupportedSchemaVersion { found: u32, max_supported: u32 },

    /// A query expected to find exactly one row (e.g. the single `vaults` row) found none.
    #[error("not found")]
    NotFound,

    /// A field envelope was too short to contain its header.
    #[error("field envelope truncated")]
    Truncated,

    /// A field envelope used an unsupported version.
    #[error("unsupported field envelope version: {found}")]
    UnsupportedFieldEnvelopeVersion { found: u16 },

    /// A `crates/crypto` operation (field encryption/decryption) failed.
    #[error("encryption error: {0}")]
    Encryption(#[from] undercloud_crypto::CryptoError),

    /// The catalog executor could not start or accept jobs.
    #[error("catalog executor is unavailable")]
    ExecutorUnavailable,

    /// A catalog-file filesystem operation failed.
    #[error("catalog file I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("catalog invariant violation")]
    InvariantViolation,

    #[error("invalid catalog state")]
    InvalidState,
}

impl CatalogError {
    /// Returns whether the error is a uniqueness constraint violation.
    pub fn is_unique_violation(&self) -> bool {
        matches!(
            self,
            CatalogError::Sqlite(rusqlite::Error::SqliteFailure(e, _))
                if e.code == rusqlite::ErrorCode::ConstraintViolation
        )
    }
}
