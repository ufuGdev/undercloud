// SPDX-License-Identifier: Apache-2.0
use tokio::sync::mpsc;
use undercloud_core::{CancellationToken, FileHealth, UndercloudCore};

#[tokio::test]
async fn vertical_slice_survives_restart_loss_restore_and_repair() {
    let temp = tempfile::tempdir().unwrap();
    let catalog = temp.path().join("catalog.sqlite3");
    let root_a = temp.path().join("target-a");
    let root_b = temp.path().join("target-b");
    let replacement = temp.path().join("target-replacement");
    std::fs::create_dir_all(&root_a).unwrap();
    std::fs::create_dir_all(&root_b).unwrap();
    std::fs::create_dir_all(&replacement).unwrap();
    let source = temp.path().join("source.bin");
    let original: Vec<u8> = (0..(undercloud_chunker::DEFAULT_CHUNK_SIZE * 2 + 791))
        .map(|i| (i as u8).wrapping_mul(31))
        .collect();
    std::fs::write(&source, &original).unwrap();

    let core = UndercloudCore::new(&catalog);
    let mut session = core
        .create_vault("correct horse battery staple")
        .await
        .unwrap();
    let target_a = session.add_local_provider(&root_a).await.unwrap();
    let target_b = session.add_local_provider(&root_b).await.unwrap();
    println!("vault created; two targets registered");

    let (progress_tx, mut progress_rx) = mpsc::channel(8);
    let upload = session
        .upload_file(
            tokio::fs::File::open(&source).await.unwrap(),
            Some(original.len() as u64),
            "unicode-名.bin",
            None,
            "vertical-slice-upload",
            progress_tx,
        )
        .await
        .unwrap();
    let mut last = 0;
    while let Some(progress) = progress_rx.recv().await {
        assert!(progress.bytes_processed >= last);
        last = progress.bytes_processed;
    }
    assert_eq!(last, original.len() as u64);
    assert_eq!(
        session.health(upload.file_version_id).await.unwrap(),
        FileHealth::Healthy
    );
    println!("file uploaded; replica health 2/2");
    session.lock();
    drop(core);
    println!("core dropped");

    let restarted = UndercloudCore::new(&catalog);
    let locked = restarted.open_vault().await.unwrap();
    let mut session = locked.unlock("correct horse battery staple").await.unwrap();
    let restored = temp.path().join("restored.bin");
    session
        .restore_file(
            upload.file_version_id,
            &restored,
            CancellationToken::default(),
        )
        .await
        .unwrap();
    assert_eq!(std::fs::read(&restored).unwrap(), original);
    println!("vault reopened; exact restore verified");

    assert!(session.remove_local_provider(target_a).await.is_err());
    assert!(session
        .storage_target_ids()
        .await
        .unwrap()
        .contains(&target_a));

    session.disconnect_provider(target_a);
    assert_eq!(
        session.health(upload.file_version_id).await.unwrap(),
        FileHealth::Degraded
    );
    let degraded = temp.path().join("restored-degraded.bin");
    session
        .restore_file(
            upload.file_version_id,
            &degraded,
            CancellationToken::default(),
        )
        .await
        .unwrap();
    assert_eq!(std::fs::read(&degraded).unwrap(), original);
    println!("one target removed; degraded restore verified");

    session.add_local_provider(&replacement).await.unwrap();
    let health = session
        .repair_automatically(upload.file_version_id)
        .await
        .unwrap();
    assert_eq!(health, FileHealth::Healthy);
    assert_eq!(
        session.health(upload.file_version_id).await.unwrap(),
        FileHealth::Healthy
    );
    println!("repair completed; final health 2/2");
    let _ = target_b;
}

/// A source replica whose bytes no longer authenticate must abort the repair with an authentication error (corruption never copied to the replacement target) and must not leave the repair job stuck "running".
#[tokio::test]
async fn repair_refuses_to_propagate_corrupted_source_replica() {
    let temp = tempfile::tempdir().unwrap();
    let catalog = temp.path().join("catalog.sqlite3");
    let root_a = temp.path().join("target-a");
    let root_b = temp.path().join("target-b");
    let replacement = temp.path().join("target-replacement");
    for dir in [&root_a, &root_b, &replacement] {
        std::fs::create_dir_all(dir).unwrap();
    }
    let source = temp.path().join("source.bin");
    let original: Vec<u8> = (0..50_000).map(|i| (i as u8).wrapping_mul(17)).collect();
    std::fs::write(&source, &original).unwrap();

    let core = UndercloudCore::new(&catalog);
    let mut session = core
        .create_vault("correct horse battery staple")
        .await
        .unwrap();
    session.add_local_provider(&root_a).await.unwrap();
    session.add_local_provider(&root_b).await.unwrap();

    let upload = session
        .upload_file(
            tokio::fs::File::open(&source).await.unwrap(),
            Some(original.len() as u64),
            "corrupt-me.bin",
            None,
            "corruption-repair-upload",
            mpsc::channel(1).0,
        )
        .await
        .unwrap();

    // Flip one byte inside a chunk's ciphertext on BOTH targets so the repair's chosen source is guaranteed corrupted; size stays identical, so only AEAD can catch this.
    for root in [&root_a, &root_b] {
        let chunk_path = std::fs::read_dir(root)
            .unwrap()
            .map(|e| e.unwrap().path())
            .find(|p| std::fs::read(p).unwrap().starts_with(b"UCLD"))
            .expect("uploaded vault must contain at least one chunk object");
        let mut bytes = std::fs::read(&chunk_path).unwrap();
        assert!(bytes.len() > 80, "chunk envelope must have payload");
        bytes[80] ^= 0x01;
        std::fs::write(&chunk_path, &bytes).unwrap();
    }

    session.add_local_provider(&replacement).await.unwrap();
    let result = session.repair_automatically(upload.file_version_id).await;
    assert!(
        matches!(result, Err(undercloud_core::CoreError::Authentication)),
        "repair must fail with Authentication on a corrupted source replica, got {result:?}"
    );
}

/// When the second target starts failing part way through an upload, the catalog commit must land no rows and every blob already written to the healthy target must be deleted again — no orphans; a later retry with both targets healthy then succeeds.
#[tokio::test]
async fn failed_upload_leaves_no_catalog_rows_and_no_orphan_blobs() {
    let temp = tempfile::tempdir().unwrap();
    let catalog = temp.path().join("catalog.sqlite3");
    let root_a = temp.path().join("target-a");
    let root_b = temp.path().join("target-b");
    std::fs::create_dir_all(&root_a).unwrap();
    std::fs::create_dir_all(&root_b).unwrap();
    let source = temp.path().join("source.bin");
    // More than one chunk so replication has real work before the sabotage takes effect.
    let original: Vec<u8> = (0..(undercloud_chunker::DEFAULT_CHUNK_SIZE + 1234))
        .map(|i| (i as u8).wrapping_mul(29))
        .collect();
    std::fs::write(&source, &original).unwrap();

    let core = UndercloudCore::new(&catalog);
    let mut session = core
        .create_vault("correct horse battery staple")
        .await
        .unwrap();
    session.add_local_provider(&root_a).await.unwrap();
    session.add_local_provider(&root_b).await.unwrap();

    // Sabotage target B: replace its directory with a plain file so its very next write fails deterministically.
    std::fs::remove_dir_all(&root_b).unwrap();
    std::fs::write(&root_b, b"not a directory anymore").unwrap();

    let generation_before_failure = session.recovery_freshness().await.unwrap().generation;

    let (progress_tx, _progress_rx) = mpsc::channel(8);
    let result = session
        .upload_file(
            tokio::fs::File::open(&source).await.unwrap(),
            Some(original.len() as u64),
            "doomed.bin",
            None,
            "orphan-test-upload",
            progress_tx,
        )
        .await;
    assert!(result.is_err(), "upload must fail once target B is broken");
    assert_eq!(
        session.recovery_freshness().await.unwrap().generation,
        generation_before_failure,
        "failed upload must not change recovery freshness"
    );

    // No logical files were committed...
    assert!(
        session.list_files().await.unwrap().is_empty(),
        "a failed upload must not leave committed file rows"
    );
    // ...and the healthy target holds zero leftover blobs.
    let leftovers: Vec<_> = std::fs::read_dir(&root_a)
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert!(
        leftovers.is_empty(),
        "healthy target must have all uploaded blobs rolled back, found {:?}",
        leftovers.iter().map(|e| e.file_name()).collect::<Vec<_>>()
    );

    // Restore target B and retry: must succeed cleanly.
    std::fs::remove_file(&root_b).unwrap();
    std::fs::create_dir_all(&root_b).unwrap();
    let (progress_tx, _progress_rx) = mpsc::channel(8);
    let retry = session
        .upload_file(
            tokio::fs::File::open(&source).await.unwrap(),
            Some(original.len() as u64),
            "doomed.bin",
            None,
            "orphan-test-upload",
            progress_tx,
        )
        .await
        .expect("retry with healthy targets must succeed");
    assert_eq!(
        session.health(retry.file_version_id).await.unwrap(),
        FileHealth::Healthy
    );
}

#[tokio::test]
async fn a_cloned_session_is_independently_usable() {
    let temp = tempfile::tempdir().unwrap();
    let catalog = temp.path().join("catalog.sqlite3");
    let root_a = temp.path().join("target-a");
    std::fs::create_dir_all(&root_a).unwrap();

    let core = UndercloudCore::new(&catalog);
    let mut session = core
        .create_vault("correct horse battery staple")
        .await
        .unwrap();
    session.add_local_provider(&root_a).await.unwrap();

    let cloned = session.clone();
    let files_from_original = session.list_files().await.unwrap();
    let files_from_clone = cloned.list_files().await.unwrap();
    assert_eq!(files_from_original, files_from_clone);
}

#[tokio::test]
async fn health_required_replica_count_matches_connected_target_count() {
    let temp = tempfile::tempdir().unwrap();
    let catalog = temp.path().join("catalog.sqlite3");
    let root_a = temp.path().join("target-a");
    let root_b = temp.path().join("target-b");
    std::fs::create_dir_all(&root_a).unwrap();
    std::fs::create_dir_all(&root_b).unwrap();
    let source = temp.path().join("source.bin");
    std::fs::write(&source, b"one target then two").unwrap();

    let core = UndercloudCore::new(&catalog);
    let mut session = core
        .create_vault("correct horse battery staple")
        .await
        .unwrap();
    session.add_local_provider(&root_a).await.unwrap();

    let generation_before_upload = session.recovery_freshness().await.unwrap().generation;
    let (progress_tx, mut progress_rx) = mpsc::channel(8);
    let upload = session
        .upload_file(
            tokio::fs::File::open(&source).await.unwrap(),
            Some(20),
            "solo.bin",
            None,
            "required-count-solo",
            progress_tx,
        )
        .await
        .unwrap();
    assert_eq!(
        session.recovery_freshness().await.unwrap().generation,
        generation_before_upload + 1,
        "successful upload must advance recovery freshness"
    );
    while progress_rx.recv().await.is_some() {}
    // One connected target: one verified replica already meets the (now dynamic) requirement.
    assert_eq!(
        session.health(upload.file_version_id).await.unwrap(),
        FileHealth::Healthy
    );

    session.add_local_provider(&root_b).await.unwrap();
    // Never copied to the new target: now under-replicated (1 chunk + manifest = 2 verified, required = (1+1)*2 = 4).
    assert_eq!(
        session.health(upload.file_version_id).await.unwrap(),
        FileHealth::Degraded
    );
}

#[tokio::test]
async fn upload_succeeds_with_a_single_connected_target() {
    let temp = tempfile::tempdir().unwrap();
    let catalog = temp.path().join("catalog.sqlite3");
    let root_a = temp.path().join("target-a");
    std::fs::create_dir_all(&root_a).unwrap();
    let source = temp.path().join("source.bin");
    let original = b"encrypted even without a mirror".to_vec();
    std::fs::write(&source, &original).unwrap();

    let core = UndercloudCore::new(&catalog);
    let mut session = core
        .create_vault("correct horse battery staple")
        .await
        .unwrap();
    session.add_local_provider(&root_a).await.unwrap();

    let (progress_tx, mut progress_rx) = mpsc::channel(8);
    let upload = session
        .upload_file(
            tokio::fs::File::open(&source).await.unwrap(),
            Some(original.len() as u64),
            "solo-upload.bin",
            None,
            "solo-target-upload",
            progress_tx,
        )
        .await
        .unwrap();
    while progress_rx.recv().await.is_some() {}

    assert_eq!(
        session.health(upload.file_version_id).await.unwrap(),
        FileHealth::Healthy
    );

    let restored = temp.path().join("restored-solo.bin");
    session
        .restore_file(
            upload.file_version_id,
            &restored,
            CancellationToken::default(),
        )
        .await
        .unwrap();
    assert_eq!(std::fs::read(&restored).unwrap(), original);
}

#[tokio::test]
async fn cancelled_upload_does_not_change_recovery_freshness() {
    let temp = tempfile::tempdir().unwrap();
    let catalog = temp.path().join("catalog.sqlite3");
    let root = temp.path().join("target");
    std::fs::create_dir_all(&root).unwrap();
    let source = temp.path().join("source.bin");
    std::fs::write(&source, b"cancelled upload").unwrap();

    let core = UndercloudCore::new(&catalog);
    let mut session = core
        .create_vault("correct horse battery staple")
        .await
        .unwrap();
    session.add_local_provider(&root).await.unwrap();

    let generation_before_cancel = session.recovery_freshness().await.unwrap().generation;
    let cancel = CancellationToken::new();
    cancel.cancel();
    let (progress_tx, _progress_rx) = mpsc::channel(8);
    let result = session
        .upload_file_with_cancel(
            tokio::fs::File::open(&source).await.unwrap(),
            Some(16),
            "cancelled.bin",
            None,
            "cancelled-upload",
            progress_tx,
            cancel,
        )
        .await;

    assert!(result.is_err());
    assert_eq!(
        session.recovery_freshness().await.unwrap().generation,
        generation_before_cancel,
        "cancelled upload must not change recovery freshness"
    );
}

#[tokio::test]
async fn single_target_going_offline_is_unrecoverable_not_a_crash() {
    let temp = tempfile::tempdir().unwrap();
    let catalog = temp.path().join("catalog.sqlite3");
    let root_a = temp.path().join("target-a");
    let replacement = temp.path().join("target-replacement");
    std::fs::create_dir_all(&root_a).unwrap();
    std::fs::create_dir_all(&replacement).unwrap();
    let source = temp.path().join("source.bin");
    std::fs::write(&source, b"only one copy exists").unwrap();

    let core = UndercloudCore::new(&catalog);
    let mut session = core
        .create_vault("correct horse battery staple")
        .await
        .unwrap();
    let target_a = session.add_local_provider(&root_a).await.unwrap();

    let (progress_tx, mut progress_rx) = mpsc::channel(8);
    let upload = session
        .upload_file(
            tokio::fs::File::open(&source).await.unwrap(),
            Some(20),
            "solo-then-offline.bin",
            None,
            "solo-offline-upload",
            progress_tx,
        )
        .await
        .unwrap();
    while progress_rx.recv().await.is_some() {}
    assert_eq!(
        session.health(upload.file_version_id).await.unwrap(),
        FileHealth::Healthy
    );

    session.disconnect_provider(target_a);
    assert_eq!(
        session.health(upload.file_version_id).await.unwrap(),
        FileHealth::Unrecoverable
    );

    session.add_local_provider(&replacement).await.unwrap();
    let outcome = session.repair_automatically(upload.file_version_id).await;
    assert!(
        outcome.is_err(),
        "repair must fail cleanly when there is no verified source replica left, not hang or panic"
    );
}

/// Reproduces the real-world "2 storage accounts connected, repair still says provider_unavailable"
/// report: both targets are connected from the start (no 1->2 transition involved), one target
/// goes offline just long enough for a health check to demote its replica to Missing, then comes
/// back online before the user clicks Repair. Repair must find the reconnected target as a valid
/// destination, not report provider_unavailable.
#[tokio::test]
async fn repair_recovers_after_a_target_flaps_offline_during_a_health_check() {
    let temp = tempfile::tempdir().unwrap();
    let catalog = temp.path().join("catalog.sqlite3");
    let root_a = temp.path().join("target-a");
    let root_b = temp.path().join("target-b");
    std::fs::create_dir_all(&root_a).unwrap();
    std::fs::create_dir_all(&root_b).unwrap();
    let source = temp.path().join("source.bin");
    std::fs::write(&source, b"flaky connection regression").unwrap();

    let core = UndercloudCore::new(&catalog);
    let mut session = core
        .create_vault("correct horse battery staple")
        .await
        .unwrap();
    let _target_a = session.add_local_provider(&root_a).await.unwrap();
    let target_b = session.add_local_provider(&root_b).await.unwrap();

    let (progress_tx, mut progress_rx) = mpsc::channel(8);
    let upload = session
        .upload_file(
            tokio::fs::File::open(&source).await.unwrap(),
            Some(28),
            "flaky.bin",
            None,
            "flaky-upload",
            progress_tx,
        )
        .await
        .unwrap();
    while progress_rx.recv().await.is_some() {}
    assert_eq!(
        session.health(upload.file_version_id).await.unwrap(),
        FileHealth::Healthy
    );

    // Target B flaps offline; a health check running in that window must demote its replica
    // instead of crashing, and the file must read as still-recoverable (Degraded), not Unrecoverable.
    session.disconnect_provider(target_b);
    assert_eq!(
        session.health(upload.file_version_id).await.unwrap(),
        FileHealth::Degraded
    );

    // Target B comes back before the user clicks Repair.
    session
        .reconnect_local_provider(target_b, &root_b)
        .await
        .unwrap();
    let outcome = session.repair_automatically(upload.file_version_id).await;
    assert_eq!(
        outcome.unwrap(),
        FileHealth::Healthy,
        "repair must use the reconnected target as the destination, not report provider_unavailable"
    );
}

/// Reproduces the real-world "2 storage accounts connected, repair still says provider_unavailable"
/// report in its exact form: the file is already fully verified on both connected targets (nothing
/// to move), yet the user clicks Repair anyway. Must report Healthy, not fail with provider_unavailable.
#[tokio::test]
async fn repair_on_an_already_fully_protected_file_reports_healthy_instead_of_erroring() {
    let temp = tempfile::tempdir().unwrap();
    let catalog = temp.path().join("catalog.sqlite3");
    let root_a = temp.path().join("target-a");
    let root_b = temp.path().join("target-b");
    std::fs::create_dir_all(&root_a).unwrap();
    std::fs::create_dir_all(&root_b).unwrap();
    let source = temp.path().join("source.bin");
    std::fs::write(&source, b"already fully protected regression").unwrap();

    let core = UndercloudCore::new(&catalog);
    let mut session = core
        .create_vault("correct horse battery staple")
        .await
        .unwrap();
    session.add_local_provider(&root_a).await.unwrap();
    session.add_local_provider(&root_b).await.unwrap();

    let (progress_tx, mut progress_rx) = mpsc::channel(8);
    let upload = session
        .upload_file(
            tokio::fs::File::open(&source).await.unwrap(),
            Some(35),
            "already-protected.bin",
            None,
            "already-protected-upload",
            progress_tx,
        )
        .await
        .unwrap();
    while progress_rx.recv().await.is_some() {}
    assert_eq!(
        session.health(upload.file_version_id).await.unwrap(),
        FileHealth::Healthy
    );

    let outcome = session.repair_automatically(upload.file_version_id).await;
    assert_eq!(
        outcome.unwrap(),
        FileHealth::Healthy,
        "clicking repair on an already fully replicated file must report Healthy, not provider_unavailable"
    );
}

#[tokio::test]
async fn connecting_a_second_target_automatically_backfills_existing_files() {
    let temp = tempfile::tempdir().unwrap();
    let catalog = temp.path().join("catalog.sqlite3");
    let root_a = temp.path().join("target-a");
    let root_b = temp.path().join("target-b");
    std::fs::create_dir_all(&root_a).unwrap();
    std::fs::create_dir_all(&root_b).unwrap();
    let source = temp.path().join("source.bin");
    let original = b"backfill me once a second target exists".to_vec();
    std::fs::write(&source, &original).unwrap();

    let core = UndercloudCore::new(&catalog);
    let mut session = core
        .create_vault("correct horse battery staple")
        .await
        .unwrap();
    session.add_local_provider(&root_a).await.unwrap();

    let (progress_tx, mut progress_rx) = mpsc::channel(8);
    let upload = session
        .upload_file(
            tokio::fs::File::open(&source).await.unwrap(),
            Some(original.len() as u64),
            "backfill-me.bin",
            None,
            "backfill-upload",
            progress_tx,
        )
        .await
        .unwrap();
    while progress_rx.recv().await.is_some() {}
    assert_eq!(
        session.health(upload.file_version_id).await.unwrap(),
        FileHealth::Healthy
    );

    session.add_local_provider(&root_b).await.unwrap();

    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        if session.health(upload.file_version_id).await.unwrap() == FileHealth::Healthy {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "backfill did not bring the file back to Healthy within 10s"
        );
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }

    let restored = temp.path().join("restored-backfilled.bin");
    session
        .restore_file(
            upload.file_version_id,
            &restored,
            CancellationToken::default(),
        )
        .await
        .unwrap();
    assert_eq!(std::fs::read(&restored).unwrap(), original);
}

/// Reopening a database with a pre-fix `current_version_id = NULL` row must run migration 5 and backfill it, restoring `list_files()` visibility.
#[tokio::test]
async fn migration_backfills_current_version_id_for_pre_existing_null_rows() {
    let temp = tempfile::tempdir().unwrap();
    let catalog = temp.path().join("catalog.sqlite3");
    let root_a = temp.path().join("target-a");
    std::fs::create_dir_all(&root_a).unwrap();
    let source = temp.path().join("source.bin");
    let original = b"pre-existing file with a null current_version_id".to_vec();
    std::fs::write(&source, &original).unwrap();

    let core = UndercloudCore::new(&catalog);
    let mut session = core
        .create_vault("correct horse battery staple")
        .await
        .unwrap();
    session.add_local_provider(&root_a).await.unwrap();

    let (progress_tx, mut progress_rx) = mpsc::channel(8);
    let upload = session
        .upload_file(
            tokio::fs::File::open(&source).await.unwrap(),
            Some(original.len() as u64),
            "pre-existing.bin",
            None,
            "backfill-migration-upload",
            progress_tx,
        )
        .await
        .unwrap();
    while progress_rx.recv().await.is_some() {}

    session.lock();
    drop(core);

    // Roll the on-disk state back to pre-migration-5: null the column and rewind the schema version stamp.
    {
        let conn = rusqlite::Connection::open(&catalog).unwrap();
        conn.execute("UPDATE logical_files SET current_version_id = NULL", [])
            .unwrap();
        conn.pragma_update(None, "user_version", 4).unwrap();
    }

    let restarted = UndercloudCore::new(&catalog);
    let locked = restarted.open_vault().await.unwrap();
    let session = locked.unlock("correct horse battery staple").await.unwrap();

    let files = session.list_files().await.unwrap();
    let file = files
        .iter()
        .find(|f| f.file_version_id == Some(upload.file_version_id))
        .expect("migration 5 must have backfilled current_version_id so list_files finds the file");
    assert_eq!(file.health, Some(FileHealth::Healthy));
}

#[tokio::test]
async fn trash_restore_and_partial_permanent_delete_are_restart_safe() {
    let temp = tempfile::tempdir().unwrap();
    let catalog = temp.path().join("catalog.sqlite3");
    let root_a = temp.path().join("target-a");
    let root_b = temp.path().join("target-b");
    std::fs::create_dir_all(&root_a).unwrap();
    std::fs::create_dir_all(&root_b).unwrap();
    let source = temp.path().join("source.bin");
    std::fs::write(&source, b"trash regression").unwrap();
    let core = UndercloudCore::new(&catalog);
    let mut session = core
        .create_vault("correct horse battery staple")
        .await
        .unwrap();
    let _target_a = session.add_local_provider(&root_a).await.unwrap();
    let target_b = session.add_local_provider(&root_b).await.unwrap();
    let (tx, mut rx) = mpsc::channel(8);
    let upload = session
        .upload_file(
            tokio::fs::File::open(&source).await.unwrap(),
            Some(16),
            "trash.txt",
            None,
            "trash-test",
            tx,
        )
        .await
        .unwrap();
    while rx.recv().await.is_some() {}
    session
        .move_file_to_trash(upload.logical_file_id, "trash-op", None)
        .await
        .unwrap();
    assert!(session
        .list_files()
        .await
        .unwrap()
        .iter()
        .all(|file| file.logical_file_id != upload.logical_file_id));
    assert_eq!(session.list_trash().await.unwrap().len(), 1);
    session
        .restore_file_from_trash(upload.logical_file_id, "restore-trash-op")
        .await
        .unwrap();
    assert!(session
        .list_files()
        .await
        .unwrap()
        .iter()
        .any(|file| file.logical_file_id == upload.logical_file_id));
    session
        .move_file_to_trash(upload.logical_file_id, "trash-op-2", None)
        .await
        .unwrap();
    session.disconnect_provider(target_b);
    let incomplete = session
        .permanently_delete_file(
            upload.logical_file_id,
            "delete-op",
            CancellationToken::new(),
        )
        .await
        .unwrap();
    assert!(!incomplete.completed);
    let duplicate = session
        .permanently_delete_file(
            upload.logical_file_id,
            "delete-op-duplicate",
            CancellationToken::new(),
        )
        .await
        .unwrap();
    assert!(!duplicate.completed);
    assert!(session
        .restore_file_from_trash(upload.logical_file_id, "restore-after-delete")
        .await
        .is_err());
    session
        .reconnect_local_provider(target_b, &root_b)
        .await
        .unwrap();
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(3);
    while !session.list_trash().await.unwrap().is_empty() && tokio::time::Instant::now() < deadline
    {
        session
            .reconcile_deletions(CancellationToken::new())
            .await
            .unwrap();
        tokio::task::yield_now().await;
    }
    assert!(session.list_trash().await.unwrap().is_empty());
    assert_eq!(std::fs::read_dir(&root_a).unwrap().count(), 0);
    assert_eq!(std::fs::read_dir(&root_b).unwrap().count(), 0);
}
