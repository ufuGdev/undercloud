// SPDX-License-Identifier: Apache-2.0
//! Locked catalog handle; unlock is the only path to full catalog access.
use std::path::Path;

use rusqlite::{params, types::Type, Error as SqliteError};
use uuid::Uuid;

use undercloud_crypto::{CatalogFieldSubkey, PasswordEnvelope};

use crate::error::CatalogError;
use crate::executor::{CatalogExecutor, CatalogExecutorHandle};
use crate::open_and_migrate;
use crate::unlocked::UnlockedCatalog;

/// Provides bootstrap-only catalog access until unlock.
#[derive(Debug, Clone)]
pub struct CatalogBootstrap {
    executor: CatalogExecutorHandle,
}

/// Maps an empty single-row lookup to `CatalogError::NotFound`.
fn no_rows_to_not_found(err: SqliteError) -> CatalogError {
    match err {
        SqliteError::QueryReturnedNoRows => CatalogError::NotFound,
        other => CatalogError::Sqlite(other),
    }
}

/// Reports incompatible stored values as `InvalidColumnType`.
fn invalid_column(column: &str, expected: Type) -> CatalogError {
    CatalogError::Sqlite(SqliteError::InvalidColumnType(
        0,
        column.to_string(),
        expected,
    ))
}

fn u16_from_i64(value: i64, column: &str) -> Result<u16, CatalogError> {
    u16::try_from(value).map_err(|_| invalid_column(column, Type::Integer))
}

fn u32_from_i64(value: i64, column: &str) -> Result<u32, CatalogError> {
    u32::try_from(value).map_err(|_| invalid_column(column, Type::Integer))
}

/// Stores creation time as a non-sensitive millisecond Unix timestamp.
fn now_timestamp() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};

    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .to_string()
}

impl CatalogBootstrap {
    /// Opens the catalog and applies migrations on the executor thread.
    pub async fn open(path: &Path) -> Result<Self, CatalogError> {
        let path = path.to_path_buf();
        let executor = tokio::task::spawn_blocking(move || {
            CatalogExecutor::spawn(move || open_and_migrate(&path))
        })
        .await
        .map_err(|_| CatalogError::ExecutorUnavailable)??;
        Ok(Self { executor })
    }

    /// Reads the catalog format version.
    pub async fn catalog_format_version(&self) -> Result<u16, CatalogError> {
        self.executor
            .call(|conn| {
                let version: i64 = conn
                    .query_row(
                        "SELECT catalog_format_version FROM vaults LIMIT 1",
                        [],
                        |row| row.get(0),
                    )
                    .map_err(no_rows_to_not_found)?;
                u16_from_i64(version, "catalog_format_version")
            })
            .await
    }

    /// Reads `vaults.id`. `NotFound` if no vault has been created yet.
    pub async fn vault_id(&self) -> Result<Uuid, CatalogError> {
        self.executor
            .call(|conn| {
                let id_text: String = conn
                    .query_row("SELECT id FROM vaults LIMIT 1", [], |row| row.get(0))
                    .map_err(no_rows_to_not_found)?;
                Uuid::parse_str(&id_text).map_err(|_| invalid_column("id", Type::Text))
            })
            .await
    }

    /// Loads the authenticated password envelope from the bootstrap tables.
    pub async fn password_envelope(&self) -> Result<PasswordEnvelope, CatalogError> {
        self.executor
            .call(|conn| {
                let row = conn.query_row(
                    "SELECT v.id, k.envelope_version, k.salt, k.m_cost, k.t_cost, k.p_cost, \
                     k.nonce, k.ciphertext \
                     FROM key_envelopes k JOIN vaults v ON v.id = k.vault_id \
                     LIMIT 1",
                    [],
                    |row| {
                        let vault_id_text: String = row.get(0)?;
                        let envelope_version: i64 = row.get(1)?;
                        let salt: Vec<u8> = row.get(2)?;
                        let m_cost: i64 = row.get(3)?;
                        let t_cost: i64 = row.get(4)?;
                        let p_cost: i64 = row.get(5)?;
                        let nonce: Vec<u8> = row.get(6)?;
                        let ciphertext: Vec<u8> = row.get(7)?;
                        Ok((
                            vault_id_text,
                            envelope_version,
                            salt,
                            m_cost,
                            t_cost,
                            p_cost,
                            nonce,
                            ciphertext,
                        ))
                    },
                );

                let (
                    vault_id_text,
                    envelope_version,
                    salt,
                    m_cost,
                    t_cost,
                    p_cost,
                    nonce,
                    ciphertext,
                ) = row.map_err(no_rows_to_not_found)?;

                let vault_id = Uuid::parse_str(&vault_id_text)
                    .map_err(|_| invalid_column("vault_id", Type::Text))?;
                let envelope_version = u16_from_i64(envelope_version, "envelope_version")?;
                let salt: [u8; 16] = salt
                    .try_into()
                    .map_err(|_| invalid_column("salt", Type::Blob))?;
                let m_cost = u32_from_i64(m_cost, "m_cost")?;
                let t_cost = u32_from_i64(t_cost, "t_cost")?;
                let p_cost = u32_from_i64(p_cost, "p_cost")?;
                let nonce: [u8; 24] = nonce
                    .try_into()
                    .map_err(|_| invalid_column("nonce", Type::Blob))?;

                Ok(PasswordEnvelope {
                    vault_id,
                    envelope_version,
                    salt,
                    m_cost,
                    t_cost,
                    p_cost,
                    nonce,
                    ciphertext,
                })
            })
            .await
    }

    /// Creates the initial vault and password-envelope rows atomically.
    pub async fn create_vault(
        &self,
        vault_id: Uuid,
        catalog_format_version: u16,
        password_envelope: &PasswordEnvelope,
    ) -> Result<(), CatalogError> {
        let vault_id_text = vault_id.to_string();
        let catalog_format_version = i64::from(catalog_format_version);
        let created_at = now_timestamp();
        let envelope = password_envelope.clone();

        self.executor
            .call(move |conn| {
                let tx = conn.transaction()?;

                tx.execute(
                    "INSERT INTO vaults (id, created_at, catalog_format_version) \
                     VALUES (?1, ?2, ?3)",
                    params![vault_id_text, created_at, catalog_format_version],
                )?;

                tx.execute(
                    "INSERT INTO key_envelopes \
                     (vault_id, envelope_version, salt, m_cost, t_cost, p_cost, nonce, ciphertext) \
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                    params![
                        vault_id_text,
                        i64::from(envelope.envelope_version),
                        envelope.salt.to_vec(),
                        i64::from(envelope.m_cost),
                        i64::from(envelope.t_cost),
                        i64::from(envelope.p_cost),
                        envelope.nonce.to_vec(),
                        envelope.ciphertext,
                    ],
                )?;

                tx.commit()?;
                Ok(())
            })
            .await
    }

    /// Unlocks the catalog with the supplied field subkey.
    pub async fn unlock(
        self,
        catalog_field_subkey: CatalogFieldSubkey,
    ) -> Result<UnlockedCatalog, CatalogError> {
        let vault_id = self.vault_id().await?;
        Ok(UnlockedCatalog::new(
            self.executor,
            vault_id,
            catalog_field_subkey,
        ))
    }
}

#[cfg(test)]
impl CatalogBootstrap {
    /// Runs a test closure against the production-configured executor connection.
    pub(crate) async fn call_raw_for_test<F, T>(&self, f: F) -> Result<T, CatalogError>
    where
        F: FnOnce(&mut rusqlite::Connection) -> Result<T, CatalogError> + Send + 'static,
        T: Send + 'static,
    {
        self.executor.call(f).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Use the production executor connection to verify foreign-key enforcement.
    #[tokio::test]
    async fn foreign_key_violation_is_rejected_on_the_real_executor_connection() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("catalog.sqlite3");

        let bootstrap = CatalogBootstrap::open(&path)
            .await
            .expect("open must succeed");

        // This invalid vault ID must trigger a foreign-key violation.
        let result = bootstrap
            .call_raw_for_test(|conn| {
                conn.execute(
                    "INSERT INTO storage_targets \
                     (id, vault_id, provider_kind, config_envelope, display_order, created_at) \
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    params![
                        Uuid::new_v4().to_string(),
                        Uuid::new_v4().to_string(), // bogus vault_id
                        "local",
                        vec![0u8; 4],
                        0i64,
                        "0",
                    ],
                )
                .map_err(CatalogError::from)
            })
            .await;

        assert!(
            result.is_err(),
            "insert with a bogus foreign key must be rejected"
        );
        match result.unwrap_err() {
            CatalogError::Sqlite(SqliteError::SqliteFailure(err, _)) => {
                assert_eq!(
                    err.code,
                    rusqlite::ErrorCode::ConstraintViolation,
                    "expected a constraint-violation error"
                );
            }
            other => panic!("expected Sqlite(SqliteFailure(ConstraintViolation)), got {other:?}"),
        }
    }
}
