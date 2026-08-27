use std::path::Path;

use tempfile::tempdir;
use tokio::io::AsyncReadExt;
use tokio::sync::mpsc;
use undercloud_core::{FileHealth, UndercloudCore};

#[tokio::test]
async fn recovery_kit_rebuilds_a_fresh_profile_and_restores_remote_data() {
    let dir = tempdir().unwrap();
    let original_db = dir.path().join("original.sqlite");
    let kit = dir.path().join("vault.ucrk");
    let recovered_db = dir.path().join("recovered.sqlite");
    let root_a = dir.path().join("provider-a");
    let root_b = dir.path().join("provider-b");
    tokio::fs::create_dir_all(&root_a).await.unwrap();
    tokio::fs::create_dir_all(&root_b).await.unwrap();
    let source = (0..(undercloud_chunker::DEFAULT_CHUNK_SIZE * 2 + 17))
        .map(|i| (i % 251) as u8)
        .collect::<Vec<_>>();

    let core = UndercloudCore::new(&original_db);
    let mut session = core.create_vault("vault-password").await.unwrap();
    session.add_local_provider(&root_a).await.unwrap();
    session.add_local_provider(&root_b).await.unwrap();
    let (progress, _) = mpsc::channel(4);
    let uploaded = session
        .upload_file(
            tokio::io::BufReader::new(std::io::Cursor::new(source.clone())),
            Some(source.len() as u64),
            "recovery-test.bin",
            None,
            "recovery-upload",
            progress,
        )
        .await
        .unwrap();
    assert_eq!(
        session.health(uploaded.file_version_id).await.unwrap(),
        FileHealth::Healthy
    );
    core.export_recovery_kit(&session, &kit, "recovery-passphrase")
        .await
        .unwrap();
    assert!(core
        .export_recovery_kit(&session, &kit, "recovery-passphrase")
        .await
        .is_err());
    let original_kit = tokio::fs::read(&kit).await.unwrap();
    let kit_text = String::from_utf8_lossy(&original_kit);
    assert!(!kit_text.contains("recovery-test.bin"));
    assert!(!kit_text.contains(root_a.to_string_lossy().as_ref()));
    assert!(!kit_text.contains(root_b.to_string_lossy().as_ref()));
    let rejected = |name: &str| dir.path().join(name);
    assert!(UndercloudCore::new(rejected("wrong.sqlite"))
        .import_recovery_kit(&kit, &rejected("wrong.sqlite"), "wrong-passphrase")
        .await
        .is_err());
    let mut modified = original_kit.clone();
    let middle = modified.len() / 2;
    modified[middle] ^= 0x40;
    let modified_path = rejected("modified.ucrk");
    tokio::fs::write(&modified_path, modified).await.unwrap();
    assert!(UndercloudCore::new(rejected("modified.sqlite"))
        .import_recovery_kit(
            &modified_path,
            &rejected("modified.sqlite"),
            "recovery-passphrase",
        )
        .await
        .is_err());
    let truncated_path = rejected("truncated.ucrk");
    tokio::fs::write(&truncated_path, &original_kit[..original_kit.len() - 7])
        .await
        .unwrap();
    assert!(UndercloudCore::new(rejected("truncated.sqlite"))
        .import_recovery_kit(
            &truncated_path,
            &rejected("truncated.sqlite"),
            "recovery-passphrase",
        )
        .await
        .is_err());
    let mut unsupported = original_kit.clone();
    unsupported[4..6].copy_from_slice(&99u16.to_be_bytes());
    let digest = blake3::hash(&unsupported[..unsupported.len() - 32]);
    let end = unsupported.len() - 32;
    unsupported[end..].copy_from_slice(digest.as_bytes());
    let unsupported_path = rejected("unsupported.ucrk");
    tokio::fs::write(&unsupported_path, unsupported)
        .await
        .unwrap();
    assert!(UndercloudCore::new(rejected("unsupported.sqlite"))
        .import_recovery_kit(
            &unsupported_path,
            &rejected("unsupported.sqlite"),
            "recovery-passphrase",
        )
        .await
        .is_err());
    let mut stale = original_kit.clone();
    stale[22..30].copy_from_slice(&0u64.to_be_bytes());
    let digest = blake3::hash(&stale[..stale.len() - 32]);
    let end = stale.len() - 32;
    stale[end..].copy_from_slice(digest.as_bytes());
    let stale_path = rejected("stale.ucrk");
    tokio::fs::write(&stale_path, stale).await.unwrap();
    assert!(UndercloudCore::new(rejected("stale.sqlite"))
        .import_recovery_kit(
            &stale_path,
            &rejected("stale.sqlite"),
            "recovery-passphrase",
        )
        .await
        .is_err());
    session.lock();
    drop(core);

    let fresh = UndercloudCore::new(&recovered_db);
    let recovered = fresh
        .import_recovery_kit(&kit, &recovered_db, "recovery-passphrase")
        .await
        .unwrap();
    let targets = recovered.storage_target_ids().await.unwrap();
    assert_eq!(targets.len(), 2);
    recovered.lock();
    drop(fresh);
    let reopened = UndercloudCore::new(&recovered_db);
    let mut recovered = reopened
        .open_vault()
        .await
        .unwrap()
        .unlock("recovery-passphrase")
        .await
        .unwrap();
    recovered
        .reconnect_local_provider(targets[0], &root_a)
        .await
        .unwrap();
    recovered
        .reconnect_local_provider(targets[1], &root_b)
        .await
        .unwrap();
    assert_eq!(
        recovered
            .verify_recovered_health(uploaded.file_version_id)
            .await
            .unwrap(),
        FileHealth::Healthy
    );
    let restored = dir.path().join("restored.bin");
    recovered
        .restore_file(
            uploaded.file_version_id,
            Path::new(&restored),
            Default::default(),
        )
        .await
        .unwrap();
    let mut bytes = Vec::new();
    tokio::fs::File::open(restored)
        .await
        .unwrap()
        .read_to_end(&mut bytes)
        .await
        .unwrap();
    assert_eq!(bytes, source);
    recovered.disconnect_provider(targets[1]);
    assert_eq!(
        recovered
            .verify_recovered_health(uploaded.file_version_id)
            .await
            .unwrap(),
        FileHealth::Degraded
    );
}
