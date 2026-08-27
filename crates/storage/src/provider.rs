// SPDX-License-Identifier: Apache-2.0
use std::pin::Pin;

use async_trait::async_trait;
use tokio::io::AsyncRead;

use crate::error::ProviderError;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ObjectLocator(pub String);

#[derive(Debug, Clone, Default)]
pub struct ProviderCapabilities {
    pub range_reads: bool,
    pub multipart_upload: bool,
    pub atomic_rename: bool,
    pub conditional_writes: bool,
    pub native_checksums: bool,
    pub server_side_copy: bool,
    pub quota_reporting: bool,
    pub max_object_size_bytes: Option<u64>,
    pub case_sensitive: bool,
    pub rate_limit_hint_per_sec: Option<u32>,
}

pub struct PutObjectRequest {
    pub locator: ObjectLocator,
    pub body: Pin<Box<dyn AsyncRead + Send + Sync>>,
    pub expected_size: u64,
}

pub struct GetObjectRequest {
    pub locator: ObjectLocator,
    pub range: Option<(u64, u64)>,
}

#[derive(Debug, Clone)]
pub struct ObjectReceipt {
    pub locator: ObjectLocator,
    pub size: u64,
    pub etag: Option<String>,
}

pub type ObjectStream = Pin<Box<dyn AsyncRead + Send>>;

#[derive(Debug, Clone)]
pub struct ObjectMetadata {
    pub size: u64,
    pub etag: Option<String>,
}

#[derive(Debug, Clone)]
pub struct PageCursor(pub String);

#[derive(Debug, Clone)]
pub struct ObjectPage {
    pub locators: Vec<ObjectLocator>,
    pub next_cursor: Option<PageCursor>,
}

#[derive(Debug, Clone)]
pub struct QuotaInfo {
    pub used_bytes: u64,
    pub total_bytes: Option<u64>,
    pub state: QuotaState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuotaState {
    Known,
    Unknown,
    Unsupported,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProviderHealth {
    Healthy,
    Degraded { reason: String },
    Unreachable { reason: String },
}

#[async_trait]
pub trait StorageProvider: Send + Sync {
    async fn capabilities(&self) -> Result<ProviderCapabilities, ProviderError>;
    async fn put_object(&self, request: PutObjectRequest) -> Result<ObjectReceipt, ProviderError>;
    async fn get_object(&self, request: GetObjectRequest) -> Result<ObjectStream, ProviderError>;
    async fn head_object(&self, locator: &ObjectLocator) -> Result<ObjectMetadata, ProviderError>;
    async fn delete_object(&self, locator: &ObjectLocator) -> Result<(), ProviderError>;
    async fn list_objects(&self, cursor: Option<PageCursor>) -> Result<ObjectPage, ProviderError>;
    async fn quota(&self) -> Result<QuotaInfo, ProviderError>;
    async fn health_check(&self) -> Result<ProviderHealth, ProviderError>;
}
