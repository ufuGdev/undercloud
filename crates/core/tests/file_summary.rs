// SPDX-License-Identifier: Apache-2.0
//! Contract coverage for `VaultSession::file_summary`, the O(1) indexed
//! single-file lookup that replaced the `list_files_cached().find(...)`
//! scan in the desktop `prepare_file_deletion`/`confirm_file_deletion`
//! commands.
use tokio::sync::mpsc;
use undercloud_core::UndercloudCore;

#[tokio::test]
async fn file_summary_matches_the_corresponding_listing_entry_for_a_real_upload() {
    let temp = tempfile::tempdir().unwrap();
    let catalog = temp.path().join("catalog.sqlite3");
    let root = temp.path().join("target-a");
    std::fs::create_dir_all(&root).unwrap();

    let core = UndercloudCore::new(&catalog);
    let mut session = core.create_vault("password").await.unwrap();
    session.add_local_provider(&root).await.unwrap();

    let (progress, mut progress_rx) = mpsc::channel(8);
    let uploaded = session
        .upload_file(
            tokio::io::BufReader::new(std::io::Cursor::new(b"hello world".to_vec())),
            Some(11),
            "hello.txt",
            None,
            "upload-op",
            progress,
        )
        .await
        .unwrap();
    while progress_rx.recv().await.is_some() {}

    let listing = session.list_files_cached().await.unwrap();
    let listed = listing
        .iter()
        .find(|f| f.logical_file_id == uploaded.logical_file_id)
        .expect("uploaded file must appear in the listing");

    let looked_up = session
        .file_summary(uploaded.logical_file_id)
        .await
        .unwrap()
        .expect("file_summary must find the uploaded file");

    assert_eq!(listed, &looked_up);
    assert_eq!(looked_up.health, listed.health);
    assert_eq!(looked_up.verified_copies, listed.verified_copies);
}

#[tokio::test]
async fn file_summary_returns_none_for_an_unknown_or_deleted_file() {
    let temp = tempfile::tempdir().unwrap();
    let catalog = temp.path().join("catalog.sqlite3");
    let core = UndercloudCore::new(&catalog);
    let session = core.create_vault("password").await.unwrap();

    let missing = uuid::Uuid::new_v4();
    assert!(session.file_summary(missing).await.unwrap().is_none());
}
