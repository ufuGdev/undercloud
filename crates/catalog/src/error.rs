// SPDX-License-Identifier: Apache-2.0
//! `CatalogError`: the single error type for every fallible `crates/catalog` operation; no variant's `Display` message includes a bound SQL parameter or row data, only structural information safe to log or surface.
use thiserror::Error;

/// Errors returned by `crates/catalog`'s public API.
#[derive(Debug, Error)]
pub enum CatalogError {
    /// A `rusqlite`-reported error not covered by a more specific variant below (e.g. a constraint violation, a connection error).
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),

    /// A migration's SQL failed to apply; its transaction is rolled back by SQLite before this error is constructed, so `PRAGMA user_version` is left exactly as it was before this migration started (ADR-003 "Migrations").
    #[error("migration {version} failed: {source}")]
    MigrationFailed {
        version: u32,
        source: rusqlite::Error,
    },

    /// `PRAGMA user_version` on open was greater than this crate's target schema version (written by a newer build); refused outright rather than guessing which of the newer schema's assumptions still hold.
    #[error(
        "catalog schema version {found} is newer than the {max_supported} this build supports"
    )]
    UnsupportedSchemaVersion { found: u32, max_supported: u32 },

    /// A query expected to find exactly one row (e.g. the single `vaults` row) found none.
    #[error("not found")]
    NotFound,

    /// A `FieldEnvelope` blob was shorter than the fixed 26-byte header it must contain before any ciphertext; rejected before any AEAD call is attempted.
    #[error("field envelope truncated")]
    Truncated,

    /// A `FieldEnvelope`'s `envelope_version` did not match the one version this crate currently supports.
    #[error("unsupported field envelope version: {found}")]
    UnsupportedFieldEnvelopeVersion { found: u16 },

    /// A `crates/crypto` operation (field encryption/decryption) failed.
    #[error("encryption error: {0}")]
    Encryption(#[from] undercloud_crypto::CryptoError),

    /// The `CatalogExecutor` background thread could not be started, or is no longer accepting/answering jobs (e.g. it panicked) — the actor-thread machinery failing outright, not a SQLite error (ADR-003 "Concurrency").
    #[error("catalog executor is unavailable")]
    ExecutorUnavailable,

    /// A filesystem operation on the catalog file itself failed (e.g. metadata, Unix permission bits) — distinct from `Sqlite`, since these are plain `std::io::Error`s from outside `rusqlite`.
    #[error("catalog file I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("catalog invariant violation")]
    InvariantViolation,

    #[error("invalid catalog state")]
    InvalidState,
}

impl CatalogError {
    /// True for a UNIQUE/PRIMARY KEY constraint violation reported by SQLite (e.g. two concurrent uploads racing on an idempotency key), false for any other failure.
    pub fn is_unique_violation(&self) -> bool {
        matches!(
            self,
            CatalogError::Sqlite(rusqlite::Error::SqliteFailure(e, _))
                if e.code == rusqlite::ErrorCode::ConstraintViolation
        )
    }
}
