// SPDX-License-Identifier: Apache-2.0
//! Runs schema migrations tracked by `PRAGMA user_version`.
use rusqlite::Connection;

use crate::error::CatalogError;

/// This crate's current target schema version. Bump when adding a new entry to [`MIGRATIONS`].
pub(crate) const CURRENT_SCHEMA_VERSION: u32 = 10;

/// Ordered migrations applied in transactions up to the current schema version.
pub(crate) const MIGRATIONS: &[(u32, &str)] = &[
    (1, include_str!("0001_initial.sql")),
    (2, include_str!("0002_replica_uniqueness.sql")),
    (3, include_str!("0003_oauth_application_profile.sql")),
    (4, include_str!("0004_indexes.sql")),
    (5, include_str!("0005_backfill_current_version.sql")),
    (6, include_str!("0006_activity_and_target_names.sql")),
    (7, include_str!("0007_deletion_lifecycle.sql")),
    (8, include_str!("0008_sync_job_objects.sql")),
    (9, include_str!("0009_recovery_freshness.sql")),
    (10, include_str!("0010_health_observation_latest_index.sql")),
];

/// Applies pending migrations and leaves current databases unchanged.
pub(crate) fn run(conn: &mut Connection) -> Result<(), CatalogError> {
    run_with(conn, MIGRATIONS, CURRENT_SCHEMA_VERSION)
}

/// Test-only migration runner for injecting a failing migration.
#[cfg(test)]
pub(crate) fn run_migrations_for_test(
    conn: &mut Connection,
    migrations: &[(u32, &str)],
    target_version: u32,
) -> Result<(), CatalogError> {
    run_with(conn, migrations, target_version)
}

fn run_with(
    conn: &mut Connection,
    migrations: &[(u32, &str)],
    target_version: u32,
) -> Result<(), CatalogError> {
    let current_version: u32 = conn.pragma_query_value(None, "user_version", |row| row.get(0))?;

    if current_version == target_version {
        return Ok(());
    }

    if current_version > target_version {
        // Reject databases written by a newer schema version.
        return Err(CatalogError::UnsupportedSchemaVersion {
            found: current_version,
            max_supported: target_version,
        });
    }

    for (version, sql) in migrations {
        if *version <= current_version {
            continue;
        }

        // Advance the schema version only after each migration succeeds.
        let tx = conn.transaction()?;

        execute_migration(&tx, *version, sql).map_err(|source| CatalogError::MigrationFailed {
            version: *version,
            source,
        })?;

        tx.pragma_update(None, "user_version", version)
            .map_err(|source| CatalogError::MigrationFailed {
                version: *version,
                source,
            })?;

        tx.commit()
            .map_err(|source| CatalogError::MigrationFailed {
                version: *version,
                source,
            })?;
    }

    Ok(())
}

fn execute_migration(
    tx: &rusqlite::Transaction<'_>,
    version: u32,
    sql: &str,
) -> Result<(), rusqlite::Error> {
    if !matches!(version, 6 | 7 | 9) {
        return tx.execute_batch(sql);
    }
    for statement in sql.split(';').map(str::trim).filter(|s| !s.is_empty()) {
        if let Err(source) = tx.execute_batch(statement) {
            if !expected_duplicate_column(version, statement, &source) {
                return Err(source);
            }
        }
    }
    Ok(())
}

fn expected_duplicate_column(version: u32, statement: &str, source: &rusqlite::Error) -> bool {
    if !statement.starts_with("ALTER TABLE") {
        return false;
    }
    let message = source.to_string();
    match version {
        6 => message.contains("duplicate column name: display_name_envelope"),
        7 => message.contains("duplicate column name: lifecycle_state"),
        9 => [
            "duplicate column name: recovery_generation",
            "duplicate column name: recovery_export_generation",
            "duplicate column name: recovery_exported_at",
        ]
        .iter()
        .any(|column| message.contains(column)),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Ensures a failed migration leaves the schema version unchanged.
    #[test]
    fn migration_failure_leaves_user_version_unchanged_and_file_still_opens() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("catalog.sqlite3");

        let broken_migrations: &[(u32, &str)] = &[
            (1, include_str!("0001_initial.sql")),
            (2, "THIS IS NOT VALID SQL AT ALL;"),
        ];

        {
            let mut conn = Connection::open(&path).unwrap();
            let result = run_migrations_for_test(&mut conn, broken_migrations, 2);
            assert!(
                matches!(
                    result,
                    Err(CatalogError::MigrationFailed { version: 2, .. })
                ),
                "expected MigrationFailed{{version: 2}}, got {result:?}"
            );

            let version: u32 = conn
                .pragma_query_value(None, "user_version", |row| row.get(0))
                .unwrap();
            assert_eq!(
                version, 1,
                "migration 1 succeeded and must have advanced user_version to 1; \
                 migration 2's failure must not have moved it further"
            );
        }

        let mut conn = Connection::open(&path).unwrap();
        let result = run_with(&mut conn, MIGRATIONS, CURRENT_SCHEMA_VERSION);
        assert!(
            result.is_ok(),
            "file must still open and migrate successfully afterward with the working set"
        );
    }

    #[test]
    fn partially_executed_migration_is_rolled_back_and_not_recorded() {
        let mut conn = Connection::open_in_memory().unwrap();
        let migrations = &[(1, "CREATE TABLE partial (id INTEGER); INVALID SQL;")];

        let result = run_migrations_for_test(&mut conn, migrations, 1);

        assert!(matches!(
            result,
            Err(CatalogError::MigrationFailed { version: 1, .. })
        ));
        let version: u32 = conn
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap();
        assert_eq!(version, 0);
        assert!(matches!(
            conn.query_row(
                "SELECT 1 FROM sqlite_master WHERE name = 'partial'",
                [],
                |row| row.get::<_, i32>(0)
            ),
            Err(rusqlite::Error::QueryReturnedNoRows)
        ));
    }

    #[test]
    fn expected_duplicate_does_not_hide_later_migration_failure() {
        let mut conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE storage_targets (id INTEGER, display_name_envelope BLOB);",
        )
        .unwrap();
        let migrations = &[(
            6,
            "ALTER TABLE storage_targets ADD COLUMN display_name_envelope BLOB; INVALID SQL;",
        )];

        let result = run_migrations_for_test(&mut conn, migrations, 6);

        assert!(matches!(
            result,
            Err(CatalogError::MigrationFailed { version: 6, .. })
        ));
        let version: u32 = conn
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap();
        assert_eq!(version, 0);
    }

    /// Verifies migration 4 indexes are used by their motivating queries.
    #[test]
    fn migration_indexes_are_used_by_hot_queries() {
        let mut conn = Connection::open_in_memory().unwrap();
        run_with(&mut conn, MIGRATIONS, CURRENT_SCHEMA_VERSION).unwrap();

        let cases: &[(&str, &str)] = &[
            (
                "SELECT * FROM replicas WHERE file_version_id = 'x'",
                "idx_replicas_file_version",
            ),
            (
                "SELECT * FROM health_observations WHERE file_version_id = 'x'",
                "idx_health_observations_file_version",
            ),
            (
                "SELECT * FROM repair_jobs WHERE file_version_id = 'x'",
                "idx_repair_jobs_file_version",
            ),
            (
                "SELECT * FROM sync_jobs WHERE vault_id = 'x' ORDER BY created_at",
                "idx_sync_jobs_vault_created",
            ),
            (
                "SELECT * FROM logical_files WHERE folder_id = 'x'",
                "idx_logical_files_folder",
            ),
            (
                "SELECT * FROM file_versions WHERE logical_file_id = 'x'",
                "idx_file_versions_logical_file",
            ),
            (
                "SELECT * FROM storage_targets WHERE vault_id = 'x'",
                "idx_storage_targets_vault",
            ),
            (
                "SELECT id FROM health_observations WHERE file_version_id = 'x' ORDER BY observed_at DESC, id DESC LIMIT 1",
                "idx_health_observations_file_version_latest",
            ),
        ];

        for (sql, expected_index) in cases {
            let plan: String = conn
                .query_row(&format!("EXPLAIN QUERY PLAN {sql}"), [], |row| row.get(3))
                .unwrap();
            assert!(
                plan.contains(expected_index),
                "query must use index {expected_index}, plan was: {plan}"
            );
        }
    }
}
