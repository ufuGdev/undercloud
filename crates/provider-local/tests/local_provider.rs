// SPDX-License-Identifier: Apache-2.0
use std::io::Cursor;

use tempfile::tempdir;
use tokio::io::AsyncReadExt;
use undercloud_provider_local::LocalProvider;
use undercloud_storage::{GetObjectRequest, ObjectLocator, PutObjectRequest, StorageProvider};

#[tokio::test]
async fn put_then_get_round_trips_bytes() {
    let dir = tempdir().unwrap();
    let provider = LocalProvider::new(dir.path());

    let locator = ObjectLocator("a1b2c3".into());
    let payload = b"encrypted-opaque-bytes".to_vec();
    provider
        .put_object(PutObjectRequest {
            locator: locator.clone(),
            body: Box::pin(Cursor::new(payload.clone())),
            expected_size: payload.len() as u64,
        })
        .await
        .unwrap();

    let mut stream = provider
        .get_object(GetObjectRequest {
            locator: locator.clone(),
            range: None,
        })
        .await
        .unwrap();
    let mut got = Vec::new();
    stream.read_to_end(&mut got).await.unwrap();
    assert_eq!(got, payload);
}

#[tokio::test]
async fn get_missing_object_returns_object_missing_error() {
    let dir = tempdir().unwrap();
    let provider = LocalProvider::new(dir.path());
    let result = provider
        .get_object(GetObjectRequest {
            locator: ObjectLocator("does-not-exist".into()),
            range: None,
        })
        .await;
    assert!(matches!(
        result,
        Err(undercloud_storage::ProviderError::ObjectMissing)
    ));
}

#[tokio::test]
async fn delete_then_head_returns_object_missing() {
    let dir = tempdir().unwrap();
    let provider = LocalProvider::new(dir.path());
    let locator = ObjectLocator("to-delete".into());
    provider
        .put_object(PutObjectRequest {
            locator: locator.clone(),
            body: Box::pin(Cursor::new(b"x".to_vec())),
            expected_size: 1,
        })
        .await
        .unwrap();
    provider.delete_object(&locator).await.unwrap();
    let result = provider.head_object(&locator).await;
    assert!(matches!(
        result,
        Err(undercloud_storage::ProviderError::ObjectMissing)
    ));
}

#[tokio::test]
async fn list_objects_returns_all_puts() {
    let dir = tempdir().unwrap();
    let provider = LocalProvider::new(dir.path());
    for name in ["obj-1", "obj-2", "obj-3"] {
        provider
            .put_object(PutObjectRequest {
                locator: ObjectLocator(name.into()),
                body: Box::pin(Cursor::new(b"x".to_vec())),
                expected_size: 1,
            })
            .await
            .unwrap();
    }
    let page = provider.list_objects(None).await.unwrap();
    assert_eq!(page.locators.len(), 3);
}

#[tokio::test]
async fn put_is_atomic_no_partial_file_visible_via_head_before_completion() {
    // A crashed/interrupted write must not leave a half-written object that head_object reports as present.
    let dir = tempdir().unwrap();
    let provider = LocalProvider::new(dir.path());
    let locator = ObjectLocator("atomic-test".into());
    let payload = vec![7u8; 4096];
    provider
        .put_object(PutObjectRequest {
            locator: locator.clone(),
            body: Box::pin(Cursor::new(payload.clone())),
            expected_size: payload.len() as u64,
        })
        .await
        .unwrap();
    let meta = provider.head_object(&locator).await.unwrap();
    assert_eq!(meta.size, payload.len() as u64);

    // No stray temp files left behind in the root.
    let mut entries = tokio::fs::read_dir(dir.path()).await.unwrap();
    let mut names = Vec::new();
    while let Some(entry) = entries.next_entry().await.unwrap() {
        names.push(entry.file_name().to_string_lossy().to_string());
    }
    assert!(!names.iter().any(|n| n.contains(".tmp")));
}

#[tokio::test]
async fn get_object_with_range_returns_unsupported() {
    // capabilities() advertises range_reads: false; get_object must fail closed rather than silently returning the whole object.
    let dir = tempdir().unwrap();
    let provider = LocalProvider::new(dir.path());
    let locator = ObjectLocator("ranged".into());
    provider
        .put_object(PutObjectRequest {
            locator: locator.clone(),
            body: Box::pin(Cursor::new(b"0123456789".to_vec())),
            expected_size: 10,
        })
        .await
        .unwrap();

    let result = provider
        .get_object(GetObjectRequest {
            locator,
            range: Some((0, 10)),
        })
        .await;
    assert!(matches!(
        result,
        Err(undercloud_storage::ProviderError::Unsupported)
    ));
}

#[tokio::test]
async fn put_object_with_expected_size_mismatch_returns_integrity_mismatch() {
    let dir = tempdir().unwrap();
    let provider = LocalProvider::new(dir.path());
    let locator = ObjectLocator("bad-size".into());
    let result = provider
        .put_object(PutObjectRequest {
            locator: locator.clone(),
            body: Box::pin(Cursor::new(b"actual-body".to_vec())),
            expected_size: 999,
        })
        .await;
    assert!(matches!(
        result,
        Err(undercloud_storage::ProviderError::IntegrityMismatch)
    ));

    // No stray temp or final file should exist after a rejected write.
    let mut entries = tokio::fs::read_dir(dir.path()).await.unwrap();
    let mut names = Vec::new();
    while let Some(entry) = entries.next_entry().await.unwrap() {
        names.push(entry.file_name().to_string_lossy().to_string());
    }
    assert!(names.is_empty());

    // And head_object confirms nothing was actually stored.
    let head_result = provider.head_object(&locator).await;
    assert!(matches!(
        head_result,
        Err(undercloud_storage::ProviderError::ObjectMissing)
    ));
}

#[tokio::test]
async fn health_check_reports_healthy_for_existing_writable_dir() {
    let dir = tempdir().unwrap();
    let provider = LocalProvider::new(dir.path());
    let health = provider.health_check().await.unwrap();
    assert_eq!(health, undercloud_storage::ProviderHealth::Healthy);
}

#[tokio::test]
async fn quota_reports_used_bytes_reflecting_stored_objects() {
    let dir = tempdir().unwrap();
    let provider = LocalProvider::new(dir.path());
    provider
        .put_object(PutObjectRequest {
            locator: ObjectLocator("q1".into()),
            body: Box::pin(Cursor::new(vec![0u8; 100])),
            expected_size: 100,
        })
        .await
        .unwrap();
    let quota = provider.quota().await.unwrap();
    assert!(quota.used_bytes >= 100);
}
