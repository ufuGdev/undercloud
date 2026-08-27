// SPDX-License-Identifier: Apache-2.0
use undercloud_core::{UndercloudCore, VaultStatus};

#[tokio::test]
async fn vault_reopens_and_password_change_preserves_identity() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault.sqlite3");
    let core = UndercloudCore::new(&path);
    let session = core.create_vault("old password").await.unwrap();
    let vault_id = session.vault_id();
    assert_eq!(session.status(), VaultStatus::Unlocked);
    session.lock();

    let locked = core.open_vault().await.unwrap();
    assert_eq!(locked.status(), VaultStatus::Locked);
    assert!(locked.unlock("wrong password").await.is_err());
    let mut session = locked.unlock("old password").await.unwrap();
    session
        .change_password("old password", "new password")
        .await
        .unwrap();
    session.lock();

    let locked = core.open_vault().await.unwrap();
    assert!(locked.unlock("old password").await.is_err());
    let session = core
        .open_vault()
        .await
        .unwrap()
        .unlock("new password")
        .await
        .unwrap();
    assert_eq!(session.vault_id(), vault_id);
}

#[tokio::test]
async fn removing_local_provider_persists_across_restart() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault.multi.ext.sqlite3");
    let root = dir.path().join("provider");
    tokio::fs::create_dir_all(&root).await.unwrap();
    let core = UndercloudCore::new(&path);
    let mut session = core
        .create_vault("provider-removal-password")
        .await
        .unwrap();
    let target = session.add_local_provider(&root).await.unwrap();
    assert_eq!(session.storage_target_ids().await.unwrap(), vec![target]);
    session.remove_local_provider(target).await.unwrap();
    assert!(session.storage_target_ids().await.unwrap().is_empty());
    session.lock();

    let restarted = UndercloudCore::new(&path);
    let session = restarted
        .open_vault()
        .await
        .unwrap()
        .unlock("provider-removal-password")
        .await
        .unwrap();
    assert!(session.storage_target_ids().await.unwrap().is_empty());
}
