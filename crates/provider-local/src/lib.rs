// SPDX-License-Identifier: Apache-2.0
//! Local-directory `StorageProvider` implementation, used for testing and the first vertical slice.
use std::path::{Path, PathBuf};
use std::pin::Pin;

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use undercloud_storage::{
    GetObjectRequest, ObjectLocator, ObjectMetadata, ObjectPage, ObjectReceipt, ObjectStream,
    PageCursor, ProviderCapabilities, ProviderError, ProviderHealth, PutObjectRequest, QuotaInfo,
    QuotaState, StorageProvider,
};

pub struct LocalProvider {
    root: PathBuf,
}

impl LocalProvider {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    fn object_path(&self, locator: &ObjectLocator) -> PathBuf {
        self.root.join(&locator.0)
    }

    fn tmp_path(&self, locator: &ObjectLocator) -> PathBuf {
        // Random suffix so concurrent put_object calls for the same locator write to distinct temp files instead of corrupting each other.
        self.root
            .join(format!("{}.{}.tmp", locator.0, uuid::Uuid::new_v4()))
    }
}

fn io_err_to_provider_err(err: std::io::Error) -> ProviderError {
    if err.kind() == std::io::ErrorKind::NotFound {
        ProviderError::ObjectMissing
    } else {
        ProviderError::Io(err)
    }
}

/// Validates a locator is a single safe path component before joining onto the storage root; runs unconditionally (not just debug_assert!) since a malformed/malicious ObjectLocator is untrusted input, not an internal invariant.
fn validate_locator(locator: &ObjectLocator) -> Result<(), ProviderError> {
    let s = &locator.0;
    // 200 leaves headroom under typical NAME_MAX (255) for tmp_path's appended ".{uuid_v4}.tmp" suffix (41 bytes), so an accepted locator also works as a temp filename.
    if s.is_empty() || s.len() > 200 || s == "." || s == ".." {
        return Err(ProviderError::InvalidLocator);
    }
    // list_objects/quota skip entries ending in ".tmp" (put_object's own in-flight temp suffix), so reserve that namespace here to avoid a storable-but-unlistable object.
    if s.ends_with(".tmp") {
        return Err(ProviderError::InvalidLocator);
    }
    let safe_charset = s
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.');
    if !safe_charset {
        return Err(ProviderError::InvalidLocator);
    }
    // Defense in depth: also confirm the platform path parser sees exactly one Normal, non-traversal component.
    let mut components = Path::new(s.as_str()).components();
    match (components.next(), components.next()) {
        (Some(std::path::Component::Normal(_)), None) => Ok(()),
        _ => Err(ProviderError::InvalidLocator),
    }
}

/// Confirms `path` is not a symlink before use; a symlink planted inside the validated root could otherwise point anywhere on the filesystem, bypassing validate_locator entirely since it only inspects the locator string, not the resulting filesystem entry.
async fn check_no_symlink(path: &Path) -> Result<(), ProviderError> {
    match tokio::fs::symlink_metadata(path).await {
        Ok(meta) if meta.file_type().is_symlink() => Err(ProviderError::InvalidLocator),
        Ok(_) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(ProviderError::Io(e)),
    }
}

#[async_trait]
impl StorageProvider for LocalProvider {
    #[tracing::instrument(
        skip_all,
        fields(
            subsystem = "provider",
            provider_type = "local",
            operation = "capabilities"
        )
    )]
    async fn capabilities(&self) -> Result<ProviderCapabilities, ProviderError> {
        Ok(ProviderCapabilities {
            range_reads: false,
            multipart_upload: false,
            atomic_rename: true,
            conditional_writes: false,
            native_checksums: false,
            server_side_copy: false,
            quota_reporting: true,
            max_object_size_bytes: None,
            case_sensitive: true,
            rate_limit_hint_per_sec: None,
        })
    }

    #[tracing::instrument(
        skip_all,
        fields(
            subsystem = "provider",
            provider_type = "local",
            operation = "put_object"
        )
    )]
    async fn put_object(
        &self,
        mut request: PutObjectRequest,
    ) -> Result<ObjectReceipt, ProviderError> {
        validate_locator(&request.locator)?;
        tokio::fs::create_dir_all(&self.root)
            .await
            .map_err(ProviderError::Io)?;
        let final_path = self.object_path(&request.locator);
        let tmp = self.tmp_path(&request.locator);
        check_no_symlink(&final_path).await?;
        check_no_symlink(&tmp).await?;

        // `create_new` makes the check-and-open one exclusive operation: a
        // replacement symlink cannot be planted between a metadata check and
        // opening the temporary file.
        let mut file = tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)
            .await
            .map_err(ProviderError::Io)?;

        // Stream the body to the temp file instead of buffering it; nothing here needs the whole object in RAM.
        let mut written: u64 = 0;
        let mut buf = vec![0u8; 64 * 1024];
        let write_result: Result<(), ProviderError> = async {
            loop {
                let n = request
                    .body
                    .read(&mut buf)
                    .await
                    .map_err(ProviderError::Io)?;
                if n == 0 {
                    break;
                }
                written += n as u64;
                if written > request.expected_size {
                    // Oversized body: stop early rather than spool an unbounded stream to disk.
                    return Err(ProviderError::IntegrityMismatch);
                }
                file.write_all(&buf[..n]).await.map_err(ProviderError::Io)?;
            }
            if written != request.expected_size {
                return Err(ProviderError::IntegrityMismatch);
            }
            file.flush().await.map_err(ProviderError::Io)?;
            file.sync_all().await.map_err(ProviderError::Io)?;
            Ok(())
        }
        .await;

        match write_result {
            Ok(()) => {}
            Err(e) => {
                let _ = tokio::fs::remove_file(&tmp).await;
                return Err(e);
            }
        }

        drop(file);

        tokio::fs::rename(&tmp, &final_path)
            .await
            .map_err(ProviderError::Io)?;

        Ok(ObjectReceipt {
            locator: request.locator,
            size: written,
            etag: None,
        })
    }

    #[tracing::instrument(
        skip_all,
        fields(
            subsystem = "provider",
            provider_type = "local",
            operation = "get_object"
        )
    )]
    async fn get_object(&self, request: GetObjectRequest) -> Result<ObjectStream, ProviderError> {
        if request.range.is_some() {
            // capabilities() reports range_reads: false; silently returning the whole object would be fail-open.
            return Err(ProviderError::Unsupported);
        }
        validate_locator(&request.locator)?;
        let path = self.object_path(&request.locator);
        check_no_symlink(&path).await?;
        let file = tokio::fs::File::open(&path)
            .await
            .map_err(io_err_to_provider_err)?;
        Ok(Box::pin(file) as Pin<Box<dyn tokio::io::AsyncRead + Send>>)
    }

    #[tracing::instrument(
        skip_all,
        fields(
            subsystem = "provider",
            provider_type = "local",
            operation = "head_object"
        )
    )]
    async fn head_object(&self, locator: &ObjectLocator) -> Result<ObjectMetadata, ProviderError> {
        validate_locator(locator)?;
        let path = self.object_path(locator);
        check_no_symlink(&path).await?;
        let metadata = tokio::fs::metadata(&path)
            .await
            .map_err(io_err_to_provider_err)?;
        Ok(ObjectMetadata {
            size: metadata.len(),
            etag: None,
        })
    }

    #[tracing::instrument(
        skip_all,
        fields(
            subsystem = "provider",
            provider_type = "local",
            operation = "delete_object"
        )
    )]
    async fn delete_object(&self, locator: &ObjectLocator) -> Result<(), ProviderError> {
        validate_locator(locator)?;
        let path = self.object_path(locator);
        check_no_symlink(&path).await?;
        tokio::fs::remove_file(&path)
            .await
            .map_err(io_err_to_provider_err)?;
        Ok(())
    }

    #[tracing::instrument(
        skip_all,
        fields(
            subsystem = "provider",
            provider_type = "local",
            operation = "list_objects"
        )
    )]
    async fn list_objects(&self, _cursor: Option<PageCursor>) -> Result<ObjectPage, ProviderError> {
        tokio::fs::create_dir_all(&self.root)
            .await
            .map_err(ProviderError::Io)?;
        let mut entries = tokio::fs::read_dir(&self.root)
            .await
            .map_err(ProviderError::Io)?;
        let mut locators = Vec::new();
        while let Some(entry) = entries.next_entry().await.map_err(ProviderError::Io)? {
            let name = entry.file_name().to_string_lossy().to_string();
            let is_symlink = entry
                .file_type()
                .await
                .map(|t| t.is_symlink())
                .unwrap_or(true);
            if !name.ends_with(".tmp") && !is_symlink {
                locators.push(ObjectLocator(name));
            }
        }
        Ok(ObjectPage {
            locators,
            next_cursor: None,
        })
    }

    #[tracing::instrument(
        skip_all,
        fields(subsystem = "provider", provider_type = "local", operation = "quota")
    )]
    async fn quota(&self) -> Result<QuotaInfo, ProviderError> {
        tokio::fs::create_dir_all(&self.root)
            .await
            .map_err(ProviderError::Io)?;
        let mut entries = tokio::fs::read_dir(&self.root)
            .await
            .map_err(ProviderError::Io)?;
        let mut used_bytes = 0u64;
        while let Some(entry) = entries.next_entry().await.map_err(ProviderError::Io)? {
            let name = entry.file_name().to_string_lossy().to_string();
            let is_symlink = entry
                .file_type()
                .await
                .map(|t| t.is_symlink())
                .unwrap_or(true);
            if !name.ends_with(".tmp") && !is_symlink {
                if let Ok(metadata) = entry.metadata().await {
                    used_bytes += metadata.len();
                }
            }
        }
        Ok(QuotaInfo {
            used_bytes,
            total_bytes: None,
            state: QuotaState::Known,
        })
    }

    #[tracing::instrument(
        skip_all,
        fields(
            subsystem = "provider",
            provider_type = "local",
            operation = "health_check"
        )
    )]
    async fn health_check(&self) -> Result<ProviderHealth, ProviderError> {
        match tokio::fs::create_dir_all(&self.root).await {
            Ok(()) => Ok(ProviderHealth::Healthy),
            Err(e) => Ok(ProviderHealth::Unreachable {
                reason: e.kind().to_string(),
            }),
        }
    }
}
