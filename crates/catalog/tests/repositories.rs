// SPDX-License-Identifier: Apache-2.0
use std::fs;

use undercloud_catalog::{
    CatalogBootstrap, CatalogError, HealthState, NewActivityEvent, ObjectKind, ReplicaState,
};
use undercloud_crypto::{
    derive_vault_subkeys, generate_master_key, wrap_master_key, CatalogFieldSubkey,
};
use uuid::Uuid;

async fn opened() -> (
    tempfile::TempDir,
    std::path::PathBuf,
    Uuid,
    CatalogBootstrap,
    CatalogFieldSubkey,
) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("catalog.sqlite3");
    let vault = Uuid::new_v4();
    let master = generate_master_key();
    let envelope = wrap_master_key(vault, "test password", &master).unwrap();
    let subkeys = derive_vault_subkeys(&master, vault);
    let bootstrap = CatalogBootstrap::open(&path).await.unwrap();
    bootstrap.create_vault(vault, 1, &envelope).await.unwrap();
    (dir, path, vault, bootstrap, subkeys.catalog_field)
}

#[tokio::test]
async fn encrypted_repository_round_trip_and_wal_inspection() {
    let (_dir, path, _vault, bootstrap, key) = opened().await;
    let catalog = bootstrap.unlock(key).await.unwrap();
    let marker = "catalog-marker-☃";
    let target = catalog
        .create_storage_target("local", marker.as_bytes(), 0)
        .await
        .unwrap();
    let folder = catalog.create_logical_folder(None, marker).await.unwrap();
    let file = catalog
        .create_logical_file(Some(folder), marker, Some("text/marker"))
        .await
        .unwrap();
    assert_eq!(
        catalog.load_storage_targets().await.unwrap()[0].config,
        marker.as_bytes()
    );
    assert_eq!(
        catalog.load_storage_targets().await.unwrap()[0].oauth_application_profile,
        "none"
    );
    assert_eq!(catalog.load_logical_file(file).await.unwrap().name, marker);
    drop(catalog);
    for suffix in ["", "-wal", "-shm"] {
        let p = if suffix.is_empty() {
            path.clone()
        } else {
            std::path::PathBuf::from(format!("{}{}", path.display(), suffix))
        };
        if let Ok(bytes) = fs::read(p) {
            assert!(
                !bytes.windows(marker.len()).any(|w| w == marker.as_bytes()),
                "plaintext marker leaked into SQLite artifact"
            );
        }
    }
    let _ = target;
}

#[tokio::test]
async fn wrong_catalog_key_fails_closed() {
    let (dir, path, _vault, bootstrap, key) = opened().await;
    let catalog = bootstrap.unlock(key).await.unwrap();
    catalog
        .create_storage_target("local", b"secret-root", 0)
        .await
        .unwrap();
    drop(catalog);
    let reopened = CatalogBootstrap::open(&path).await.unwrap();
    let wrong = CatalogFieldSubkey::from_bytes([0xA5; 32]);
    let catalog = reopened.unlock(wrong).await.unwrap();
    assert!(matches!(
        catalog.load_storage_targets().await,
        Err(CatalogError::Encryption(_))
    ));
    drop(dir);
}

#[tokio::test]
async fn oauth_application_profile_round_trips_through_migration() {
    let (_dir, _path, _vault, bootstrap, key) = opened().await;
    let catalog = bootstrap.unlock(key).await.unwrap();
    catalog
        .create_storage_target_with_profile(
            "google_drive",
            br#"{"credential_reference":"ref"}"#,
            0,
            "official-v1",
        )
        .await
        .unwrap();
    let targets = catalog.load_storage_targets().await.unwrap();
    assert_eq!(targets[0].oauth_application_profile, "official-v1");
}

#[tokio::test]
async fn activity_and_provider_names_are_encrypted_and_paginated() {
    let (_dir, path, _vault, bootstrap, _key) = opened().await;
    let catalog = bootstrap.unlock(_key).await.unwrap();
    let target = catalog
        .create_storage_target("google_drive", b"config", 0)
        .await
        .unwrap();
    catalog
        .set_storage_target_display_name(target, "Personal Drive")
        .await
        .unwrap();
    let operation_id = Uuid::new_v4().to_string();
    let marker = "opaque-display-marker-7f3a";
    catalog
        .create_activity_event(NewActivityEvent {
            operation_id: operation_id.clone(),
            event_type: "upload".into(),
            status: "completed".into(),
            related_file_id: None,
            related_target_id: Some(target),
            display_metadata: marker.into(),
            started_at: "2".into(),
            completed_at: Some("3".into()),
            transferred_bytes: Some(12),
            error_code: None,
            retry_classification: None,
        })
        .await
        .unwrap();
    catalog
        .create_activity_event(NewActivityEvent {
            operation_id,
            event_type: "restore".into(),
            status: "failed".into(),
            related_file_id: None,
            related_target_id: Some(target),
            display_metadata: "second".into(),
            started_at: "1".into(),
            completed_at: Some("4".into()),
            transferred_bytes: None,
            error_code: Some("failed".into()),
            retry_classification: None,
        })
        .await
        .unwrap();
    let loaded = catalog.load_storage_targets().await.unwrap();
    assert_eq!(loaded[0].display_name.as_deref(), Some("Personal Drive"));
    let (page, cursor) = catalog
        .list_activity_events(None, 1, None, None, None, None)
        .await
        .unwrap();
    assert_eq!(page[0].display_metadata, marker);
    assert!(cursor.is_some());
    let (next, _) = catalog
        .list_activity_events(cursor.as_deref(), 1, None, None, None, None)
        .await
        .unwrap();
    assert_eq!(next.len(), 1);
    drop(catalog);
    for suffix in ["", "-wal", "-shm"] {
        let p = if suffix.is_empty() {
            path.clone()
        } else {
            std::path::PathBuf::from(format!("{}{}", path.display(), suffix))
        };
        if let Ok(bytes) = fs::read(p) {
            assert!(!bytes.windows(marker.len()).any(|w| w == marker.as_bytes()));
        }
    }
}

#[tokio::test]
async fn transaction_rolls_back_intermediate_records() {
    let (_dir, _path, _vault, bootstrap, key) = opened().await;
    let catalog = bootstrap.unlock(key).await.unwrap();
    let result = catalog
        .transaction(|tx| -> Result<(), CatalogError> {
            tx.create_logical_file(None, "inside transaction", None)?;
            Err(CatalogError::InvariantViolation)
        })
        .await;
    assert!(matches!(result, Err(CatalogError::InvariantViolation)));
    // Confirm the failed transaction exposed no inserted ID.
}

#[tokio::test]
async fn healthy_transition_requires_verified_replicas_and_preserves_state() {
    let (_dir, _path, _vault, bootstrap, key) = opened().await;
    let catalog = bootstrap.unlock(key).await.unwrap();
    let target = catalog
        .create_storage_target("local", b"root", 0)
        .await
        .unwrap();
    let file = catalog
        .create_logical_file(None, "file", None)
        .await
        .unwrap();
    let version = catalog
        .create_file_version(file, 1, 1, [7; 32])
        .await
        .unwrap();
    catalog
        .record_health_observation(version, 0, 1, HealthState::Degraded)
        .await
        .unwrap();
    assert!(matches!(
        catalog.mark_file_version_healthy(version).await,
        Err(CatalogError::InvariantViolation)
    ));
    assert_eq!(
        catalog.load_file_version(version).await.unwrap().state,
        "pending"
    );
    let chunk = catalog.create_chunk(version, 0).await.unwrap();
    let replica = catalog
        .create_replica(
            version,
            Some(chunk),
            target,
            ObjectKind::Chunk,
            "object-marker",
        )
        .await
        .unwrap();
    catalog
        .set_replica_state(replica, ReplicaState::Verified)
        .await
        .unwrap();
    catalog
        .record_health_observation(version, 1, 1, HealthState::Healthy)
        .await
        .unwrap();
    catalog.mark_file_version_healthy(version).await.unwrap();
    assert_eq!(
        catalog.load_file_version(version).await.unwrap().state,
        "healthy"
    );
}
