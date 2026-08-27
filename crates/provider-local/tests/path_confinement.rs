// SPDX-License-Identifier: Apache-2.0
use std::io::Cursor;

use tempfile::tempdir;
use undercloud_provider_local::LocalProvider;
use undercloud_storage::{
    GetObjectRequest, ObjectLocator, ProviderError, PutObjectRequest, StorageProvider,
};

fn locator(s: &str) -> ObjectLocator {
    ObjectLocator(s.to_string())
}

async fn put_ok(provider: &LocalProvider, loc: &ObjectLocator, body: &[u8]) {
    provider
        .put_object(PutObjectRequest {
            locator: loc.clone(),
            body: Box::pin(Cursor::new(body.to_vec())),
            expected_size: body.len() as u64,
        })
        .await
        .unwrap();
}

// --- Malicious locators must be rejected on every entry point ---

const MALICIOUS_LOCATORS: &[&str] = &[
    "../escape",
    "../../escape",
    "..",
    ".",
    "/etc/passwd",
    "a/../../etc/passwd",
    "sub/dir",
    "sub\\dir",
    "C:\\Windows\\System32",
    "\\\\server\\share",
    "",
    "a/b",
];

#[tokio::test]
async fn malicious_locators_rejected_by_put_object() {
    let dir = tempdir().unwrap();
    let provider = LocalProvider::new(dir.path());
    for bad in MALICIOUS_LOCATORS {
        let result = provider
            .put_object(PutObjectRequest {
                locator: locator(bad),
                body: Box::pin(Cursor::new(b"x".to_vec())),
                expected_size: 1,
            })
            .await;
        assert!(
            matches!(result, Err(ProviderError::InvalidLocator)),
            "locator {bad:?} should have been rejected, got {result:?}"
        );
    }
    // Nothing should have escaped the root: confirm no file exists outside it.
    assert!(!std::path::Path::new("/tmp/escape").exists());
}

#[tokio::test]
async fn malicious_locators_rejected_by_get_object() {
    let dir = tempdir().unwrap();
    let provider = LocalProvider::new(dir.path());
    for bad in MALICIOUS_LOCATORS {
        let result = provider
            .get_object(GetObjectRequest {
                locator: locator(bad),
                range: None,
            })
            .await;
        assert!(matches!(result, Err(ProviderError::InvalidLocator)));
    }
}

#[tokio::test]
async fn malicious_locators_rejected_by_head_object() {
    let dir = tempdir().unwrap();
    let provider = LocalProvider::new(dir.path());
    for bad in MALICIOUS_LOCATORS {
        let result = provider.head_object(&locator(bad)).await;
        assert!(matches!(result, Err(ProviderError::InvalidLocator)));
    }
}

#[tokio::test]
async fn malicious_locators_rejected_by_delete_object() {
    let dir = tempdir().unwrap();
    let provider = LocalProvider::new(dir.path());
    for bad in MALICIOUS_LOCATORS {
        let result = provider.delete_object(&locator(bad)).await;
        assert!(matches!(result, Err(ProviderError::InvalidLocator)));
    }
}

#[tokio::test]
async fn traversal_locator_cannot_read_file_outside_root() {
    let dir = tempdir().unwrap();
    // Plant a secret file as a SIBLING of root (outside it).
    let secret_path = dir
        .path()
        .parent()
        .unwrap()
        .join(format!("kat-hardening-secret-{}.txt", uuid::Uuid::new_v4()));
    std::fs::write(&secret_path, b"top secret plaintext, must never be read").unwrap();

    let root = dir.path().join("vault-root");
    std::fs::create_dir_all(&root).unwrap();
    let provider = LocalProvider::new(&root);

    let relative_escape = format!("../{}", secret_path.file_name().unwrap().to_string_lossy());
    let result = provider
        .get_object(GetObjectRequest {
            locator: locator(&relative_escape),
            range: None,
        })
        .await;
    assert!(matches!(result, Err(ProviderError::InvalidLocator)));

    std::fs::remove_file(&secret_path).ok();
}

#[tokio::test]
async fn traversal_locator_cannot_overwrite_or_delete_file_outside_root() {
    let dir = tempdir().unwrap();
    let victim_path = dir
        .path()
        .parent()
        .unwrap()
        .join(format!("kat-hardening-victim-{}.txt", uuid::Uuid::new_v4()));
    std::fs::write(&victim_path, b"original content").unwrap();

    let root = dir.path().join("vault-root");
    std::fs::create_dir_all(&root).unwrap();
    let provider = LocalProvider::new(&root);

    let relative_escape = format!("../{}", victim_path.file_name().unwrap().to_string_lossy());

    let put_result = provider
        .put_object(PutObjectRequest {
            locator: locator(&relative_escape),
            body: Box::pin(Cursor::new(b"overwritten!".to_vec())),
            expected_size: 12,
        })
        .await;
    assert!(matches!(put_result, Err(ProviderError::InvalidLocator)));

    let delete_result = provider.delete_object(&locator(&relative_escape)).await;
    assert!(matches!(delete_result, Err(ProviderError::InvalidLocator)));

    // Victim file must be untouched.
    let content = std::fs::read(&victim_path).unwrap();
    assert_eq!(content, b"original content");
    std::fs::remove_file(&victim_path).ok();
}

// --- Symlink escapes ---

#[cfg(unix)]
#[tokio::test]
async fn symlink_in_root_pointing_outside_is_not_followed_for_read() {
    use std::os::unix::fs::symlink;

    let dir = tempdir().unwrap();
    let secret_path = dir.path().parent().unwrap().join(format!(
        "kat-hardening-symlink-target-{}.txt",
        uuid::Uuid::new_v4()
    ));
    std::fs::write(&secret_path, b"secret behind a symlink").unwrap();

    let root = dir.path().join("vault-root");
    std::fs::create_dir_all(&root).unwrap();
    symlink(&secret_path, root.join("innocent-looking-object")).unwrap();

    let provider = LocalProvider::new(&root);
    let result = provider
        .get_object(GetObjectRequest {
            locator: locator("innocent-looking-object"),
            range: None,
        })
        .await;
    assert!(matches!(result, Err(ProviderError::InvalidLocator)));

    let head_result = provider
        .head_object(&locator("innocent-looking-object"))
        .await;
    assert!(matches!(head_result, Err(ProviderError::InvalidLocator)));

    std::fs::remove_file(&secret_path).ok();
}

#[cfg(unix)]
#[tokio::test]
async fn symlink_in_root_is_excluded_from_list_and_quota() {
    use std::os::unix::fs::symlink;

    let dir = tempdir().unwrap();
    let outside_target = dir.path().parent().unwrap().join(format!(
        "kat-hardening-list-target-{}.txt",
        uuid::Uuid::new_v4()
    ));
    std::fs::write(&outside_target, vec![0u8; 100_000]).unwrap();

    let root = dir.path().join("vault-root");
    std::fs::create_dir_all(&root).unwrap();
    symlink(&outside_target, root.join("symlinked-object")).unwrap();

    let provider = LocalProvider::new(&root);
    put_ok(&provider, &locator("real-object"), b"real content").await;

    let page = provider.list_objects(None).await.unwrap();
    assert_eq!(page.locators.len(), 1);
    assert_eq!(page.locators[0], locator("real-object"));

    let quota = provider.quota().await.unwrap();
    assert!(
        quota.used_bytes < 100_000,
        "quota must not count bytes through a symlink: {}",
        quota.used_bytes
    );

    std::fs::remove_file(&outside_target).ok();
}

// --- A safe, ordinary locator must still work end to end ---

#[tokio::test]
async fn well_formed_locator_still_round_trips() {
    let dir = tempdir().unwrap();
    let provider = LocalProvider::new(dir.path());
    let loc = locator(&format!("chunk-{}", uuid::Uuid::new_v4()));
    put_ok(&provider, &loc, b"perfectly normal opaque object bytes").await;
    let mut stream = provider
        .get_object(GetObjectRequest {
            locator: loc,
            range: None,
        })
        .await
        .unwrap();
    use tokio::io::AsyncReadExt;
    let mut got = Vec::new();
    stream.read_to_end(&mut got).await.unwrap();
    assert_eq!(got, b"perfectly normal opaque object bytes");
}

// --- Length bound must leave room for tmp_path's ".{uuid_v4}.tmp" suffix ---

#[tokio::test]
async fn locator_between_200_and_255_bytes_is_rejected_by_validate_locator_not_io_error() {
    let dir = tempdir().unwrap();
    let provider = LocalProvider::new(dir.path());
    // 220 bytes: too long for the 200-byte bound, but would pass an old 255-byte bound and blow past NAME_MAX once tmp_path appends its 41-byte suffix, surfacing as a raw Io(ENAMETOOLONG) instead of a clean InvalidLocator rejection.
    let long_name: String = "a".repeat(220);
    let result = provider
        .put_object(PutObjectRequest {
            locator: locator(&long_name),
            body: Box::pin(Cursor::new(b"x".to_vec())),
            expected_size: 1,
        })
        .await;
    assert!(
        matches!(result, Err(ProviderError::InvalidLocator)),
        "220-byte locator should be rejected as InvalidLocator, got {result:?}"
    );
}

#[tokio::test]
async fn locator_comfortably_under_new_bound_still_round_trips() {
    let dir = tempdir().unwrap();
    let provider = LocalProvider::new(dir.path());
    let name: String = "b".repeat(100);
    let loc = locator(&name);
    put_ok(&provider, &loc, b"still works fine").await;
    let mut stream = provider
        .get_object(GetObjectRequest {
            locator: loc,
            range: None,
        })
        .await
        .unwrap();
    use tokio::io::AsyncReadExt;
    let mut got = Vec::new();
    stream.read_to_end(&mut got).await.unwrap();
    assert_eq!(got, b"still works fine");
}

// --- The ".tmp" locator namespace is reserved for put_object's in-flight temp files and must never be independently storable ---

#[tokio::test]
async fn locator_ending_in_dot_tmp_is_rejected_by_put_object() {
    // list_objects/quota hide put_object's own in-flight "<locator>.{uuid}.tmp" files by skipping ".tmp"-suffixed entries; without this rejection a locator like "backup.tmp" would be storable but never listed or counted.
    let dir = tempdir().unwrap();
    let provider = LocalProvider::new(dir.path());
    let result = provider
        .put_object(PutObjectRequest {
            locator: locator("backup.tmp"),
            body: Box::pin(Cursor::new(b"x".to_vec())),
            expected_size: 1,
        })
        .await;
    assert!(
        matches!(result, Err(ProviderError::InvalidLocator)),
        "locator ending in .tmp should have been rejected, got {result:?}"
    );
}

#[tokio::test]
async fn everything_put_object_accepts_is_returned_by_list_objects() {
    // General form of the ".tmp" bug above: assert list_objects returns exactly the set of locators put_object accepted, no more, no less.
    let dir = tempdir().unwrap();
    let provider = LocalProvider::new(dir.path());

    let put_locators = [
        locator("alpha-object"),
        locator("beta-object.bin"),
        locator("gamma_object-123"),
    ];
    for loc in &put_locators {
        put_ok(&provider, loc, b"some object content").await;
    }

    let page = provider.list_objects(None).await.unwrap();
    let mut listed: Vec<String> = page.locators.iter().map(|l| l.0.clone()).collect();
    listed.sort();
    let mut expected: Vec<String> = put_locators.iter().map(|l| l.0.clone()).collect();
    expected.sort();
    assert_eq!(
        listed, expected,
        "list_objects must return exactly the set of locators put_object accepted"
    );
}
