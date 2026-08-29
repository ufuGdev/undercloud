// SPDX-License-Identifier: Apache-2.0
//! Integration tests for catalog bootstrap and connection durability.
use uuid::Uuid;

use undercloud_catalog::{CatalogBootstrap, CatalogError};
use undercloud_crypto::{generate_master_key, wrap_master_key, PasswordEnvelope};

fn sample_password_envelope(vault_id: Uuid) -> PasswordEnvelope {
    let master_key = generate_master_key();
    wrap_master_key(vault_id, "correct horse battery staple", &master_key)
        .expect("wrapping a freshly generated master key must succeed")
}

#[tokio::test]
async fn migrations_apply_cleanly_on_a_fresh_file_backed_db() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("catalog.sqlite3");

    let bootstrap = CatalogBootstrap::open(&path).await;
    assert!(
        bootstrap.is_ok(),
        "opening a fresh catalog must apply migrations without error"
    );

    let bootstrap = bootstrap.expect("checked above");
    assert!(matches!(
        bootstrap.vault_id().await,
        Err(CatalogError::NotFound)
    ));
}

#[tokio::test]
async fn reopening_an_already_migrated_db_is_idempotent() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("catalog.sqlite3");

    let vault_id = Uuid::new_v4();
    let envelope = sample_password_envelope(vault_id);

    {
        let bootstrap = CatalogBootstrap::open(&path)
            .await
            .expect("first open must succeed");
        bootstrap
            .create_vault(vault_id, 1, &envelope)
            .await
            .expect("create_vault must succeed");
    }

    let bootstrap = CatalogBootstrap::open(&path)
        .await
        .expect("re-open of an already-migrated db must succeed");

    let reopened_vault_id = bootstrap
        .vault_id()
        .await
        .expect("vault row must survive reopen");
    assert_eq!(reopened_vault_id, vault_id);

    let reopened_envelope = bootstrap
        .password_envelope()
        .await
        .expect("key_envelopes row must survive reopen");
    assert_eq!(reopened_envelope.vault_id, envelope.vault_id);
    assert_eq!(
        reopened_envelope.envelope_version,
        envelope.envelope_version
    );
    assert_eq!(reopened_envelope.salt, envelope.salt);
    assert_eq!(reopened_envelope.m_cost, envelope.m_cost);
    assert_eq!(reopened_envelope.t_cost, envelope.t_cost);
    assert_eq!(reopened_envelope.p_cost, envelope.p_cost);
    assert_eq!(reopened_envelope.nonce, envelope.nonce);
    assert_eq!(reopened_envelope.ciphertext, envelope.ciphertext);

    let format_version = bootstrap
        .catalog_format_version()
        .await
        .expect("catalog_format_version must survive reopen");
    assert_eq!(format_version, 1);
}

#[tokio::test]
async fn user_version_newer_than_target_is_rejected() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("catalog.sqlite3");

    // Reject databases written by a newer schema version.
    {
        let conn = rusqlite::Connection::open(&path).expect("raw open");
        conn.pragma_update(None, "user_version", 999_999)
            .expect("set user_version");
    }

    let result = CatalogBootstrap::open(&path).await;
    match result {
        Err(CatalogError::UnsupportedSchemaVersion {
            found,
            max_supported,
        }) => {
            assert_eq!(found, 999_999);
            assert_eq!(max_supported, 10);
        }
        other => panic!("expected UnsupportedSchemaVersion, got {other:?}"),
    }
}

#[cfg(unix)]
#[tokio::test]
async fn unix_file_permissions_are_0600_after_creation() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("catalog.sqlite3");

    let _bootstrap = CatalogBootstrap::open(&path)
        .await
        .expect("open must succeed");

    let metadata = std::fs::metadata(&path).expect("stat catalog file");
    let mode = metadata.permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "catalog file must be mode 0600, got {mode:o}");
}
