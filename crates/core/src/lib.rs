// SPDX-License-Identifier: Apache-2.0
//! Application-facing vault orchestration for the first real vertical slice.
use std::collections::HashMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

use futures_util::stream::{StreamExt, TryStreamExt};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use uuid::Uuid;

pub use undercloud_catalog::ActivityEventRecord;
use undercloud_catalog::{
    CatalogBootstrap, CatalogError, HealthState, JobKind, ObjectKind, ReplicaState, UnlockedCatalog,
};
pub use undercloud_catalog::{NewActivityEvent, RecoveryFreshnessRecord};
use undercloud_chunker::{chunk_stream, DEFAULT_CHUNK_SIZE};
use undercloud_credentials::{CredentialError, CredentialStore, OsKeyringCredentialStore};
use undercloud_crypto::{
    decrypt_chunk, decrypt_manifest, derive_vault_subkeys, encrypt_chunk, encrypt_manifest,
    generate_dek, generate_manifest_key, unwrap_dek, unwrap_manifest_key, wrap_dek,
    wrap_manifest_key, ChunkIdentity, ContentHasher, MasterKey, PasswordEnvelope, VaultSubkeys,
};
use undercloud_format::{
    parse_chunk_envelope, parse_manifest_body, parse_manifest_envelope, serialize_chunk_envelope,
    serialize_manifest_body, serialize_manifest_envelope, ChunkEnvelope, ManifestBody,
    ManifestEnvelope, CHUNK_FORMAT_VERSION, MANIFEST_FORMAT_VERSION,
};
use undercloud_provider_cloud::{
    authorize as authorize_cloud, CloudProviderConfig, CloudProviderKind, DropboxProvider,
    GoogleDriveProvider, OAuthApplicationRegistry, OAuthCancellation, OAuthFlow, OAuthToken,
    OneDriveProvider,
};
use undercloud_provider_local::LocalProvider;
use undercloud_storage::{
    GetObjectRequest, ObjectLocator, ProviderHealth, PutObjectRequest, QuotaState, StorageProvider,
};

pub use undercloud_storage::ProviderError;

mod recovery;

#[derive(Debug, thiserror::Error)]
pub enum CoreError {
    #[error("catalog operation failed: {0}")]
    Catalog(#[from] CatalogError),
    #[error("cryptographic authentication failed")]
    Authentication,
    #[error("format validation failed")]
    Format(#[from] undercloud_format::FormatError),
    #[error("chunking failed")]
    Chunking(#[from] undercloud_chunker::ChunkerError),
    #[error("provider operation failed")]
    Provider(#[from] ProviderError),
    #[error("provider health check failed")]
    ProviderHealthCheck(ProviderError),
    #[error("oauth token exchange was rejected")]
    OAuthTokenExchangeRejected {
        status: u16,
        kind: undercloud_provider_cloud::TokenExchangeKind,
    },
    #[error("oauth token response was invalid")]
    OAuthTokenResponseInvalid,
    #[error("oauth token endpoint was unreachable")]
    OAuthTokenEndpointUnavailable,
    #[error("I/O operation failed")]
    Io(#[from] std::io::Error),
    #[error("vault is locked")]
    Locked,
    #[error("vault is already configured for that provider")]
    DuplicateProvider,
    #[error("required provider is unavailable")]
    ProviderUnavailable,
    #[error("destination already exists")]
    DestinationExists,
    #[error("file cannot be restored from available replicas")]
    Unrecoverable,
    #[error("invalid lifecycle or job transition")]
    InvalidTransition,
    #[error("operation cancelled")]
    Cancelled,
    #[error("recovery kit format is unsupported")]
    UnsupportedRecoveryVersion,
    #[error("recovery kit metadata is stale")]
    StaleRecoverySnapshot,
    #[error("recovery kit is invalid")]
    InvalidRecoveryKit,
    #[error("recovery kit destination already exists")]
    RecoveryDestinationExists,
    #[error("credential store unavailable")]
    CredentialStore,
    #[error("provider configuration is invalid")]
    InvalidProviderConfiguration,
    #[error("provider is not configured in this build")]
    ProviderNotConfigured,
    #[error("no vault exists at that location")]
    VaultNotFound,
}

const MAX_REMOTE_OBJECT_BYTES: u64 = 64 * 1024 * 1024;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VerifyOutcome {
    Verified,
    Missing,
    Corrupt,
    Unavailable,
}
type VerifyFuture<'a> =
    std::pin::Pin<Box<dyn std::future::Future<Output = (Uuid, VerifyOutcome)> + Send + 'a>>;

fn credential_error(_err: CredentialError) -> CoreError {
    CoreError::CredentialStore
}

fn auth<E>(_err: E) -> CoreError {
    CoreError::Authentication
}
fn password_ok(password: &str) -> bool {
    password.chars().count() >= 8
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultStatus {
    Locked,
    Unlocked,
}
pub trait VaultStatusSource {
    fn vault_status(&self) -> VaultStatus;
}

#[derive(Clone)]
pub struct UndercloudCore {
    catalog_path: PathBuf,
    credential_store: Arc<dyn CredentialStore>,
}
impl UndercloudCore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            catalog_path: path.into(),
            credential_store: Arc::new(OsKeyringCredentialStore::new("undercloud")),
        }
    }
    pub fn with_credential_store(
        path: impl Into<PathBuf>,
        credential_store: Arc<dyn CredentialStore>,
    ) -> Self {
        Self {
            catalog_path: path.into(),
            credential_store,
        }
    }
    pub async fn create_vault(&self, password: &str) -> Result<VaultSession, CoreError> {
        create_vault_with_store(
            &self.catalog_path,
            password,
            Arc::clone(&self.credential_store),
        )
        .await
    }
    pub async fn open_vault(&self) -> Result<LockedVault, CoreError> {
        open_vault_with_store(&self.catalog_path, Arc::clone(&self.credential_store)).await
    }
    pub async fn export_recovery_kit(
        &self,
        session: &VaultSession,
        destination: &Path,
        passphrase: &str,
    ) -> Result<(), CoreError> {
        let freshness = session.catalog.recovery_freshness().await?;
        recovery::export(session, destination, passphrase).await?;
        session
            .catalog
            .record_recovery_export(freshness.generation, &deletion_timestamp())
            .await?;
        Ok(())
    }
    pub async fn import_recovery_kit(
        &self,
        kit: &Path,
        destination: &Path,
        passphrase: &str,
    ) -> Result<VaultSession, CoreError> {
        recovery::import(kit, destination, passphrase).await
    }
}

pub struct LockedVault {
    bootstrap: CatalogBootstrap,
    credential_store: Arc<dyn CredentialStore>,
}
impl fmt::Debug for LockedVault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LockedVault")
            .field("path", &"<redacted>")
            .field("status", &VaultStatus::Locked)
            .finish()
    }
}
impl LockedVault {
    pub async fn vault_id(&self) -> Result<Uuid, CoreError> {
        self.bootstrap.vault_id().await.map_err(Into::into)
    }

    pub async fn unlock(&self, password: &str) -> Result<VaultSession, CoreError> {
        unlock_vault(
            LockedVault {
                bootstrap: self.bootstrap.clone(),
                credential_store: Arc::clone(&self.credential_store),
            },
            password,
        )
        .await
    }
    pub fn status(&self) -> VaultStatus {
        VaultStatus::Locked
    }
}
impl VaultStatusSource for LockedVault {
    fn vault_status(&self) -> VaultStatus {
        VaultStatus::Locked
    }
}

pub struct CancellationToken(Arc<AtomicBool>);
impl CancellationToken {
    pub fn new() -> Self {
        Self(Arc::new(AtomicBool::new(false)))
    }
    pub fn cancel(&self) {
        self.0.store(true, Ordering::Release);
    }
    fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}
impl Clone for CancellationToken {
    fn clone(&self) -> Self {
        Self(Arc::clone(&self.0))
    }
}
impl Default for CancellationToken {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UploadProgress {
    pub bytes_processed: u64,
    pub total_bytes: Option<u64>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UploadResult {
    pub file_version_id: Uuid,
    pub logical_file_id: Uuid,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileHealth {
    Healthy,
    Degraded,
    AtRisk,
    Unrecoverable,
    // Never constructed anywhere in this crate today; apps/desktop/src-tauri/src/commands.rs still maps a status string for it, so this is a live but currently unreachable frontend branch, not a bug.
    ProviderUnavailable,
    HealthCheckTimedOut,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileSummary {
    pub logical_file_id: Uuid,
    pub name: String,
    pub mime: Option<String>,
    pub file_version_id: Option<Uuid>,
    pub size_bytes: Option<u64>,
    pub health: Option<FileHealth>,
    pub health_current: bool,
    pub verified_copies: u32,
    pub required_copies: u32,
    pub last_verified_at: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtectionTargetSummary {
    pub target_id: Uuid,
    pub complete: bool,
    pub corrupt: bool,
    pub pending: bool,
    pub verified_objects: u32,
    pub expected_objects: u32,
    pub last_verified_at: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtectionMap {
    pub file_version_id: Uuid,
    pub verified_copies: u32,
    pub required_copies: u32,
    pub last_verified_at: Option<String>,
    pub targets: Vec<ProtectionTargetSummary>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderSummary {
    pub id: Uuid,
    pub kind: String,
    pub connected: bool,
    pub health: &'static str,
    pub used_bytes: Option<u64>,
    pub total_bytes: Option<u64>,
    pub quota_known: bool,
    pub display_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrashFileSummary {
    pub file: FileSummary,
    pub deletion_id: Uuid,
    pub state: String,
    pub purge_after: Option<String>,
    pub retry_classification: Option<String>,
    pub replica_count: u32,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeletionOutcome {
    pub deletion_id: Uuid,
    pub completed: bool,
}

#[derive(Clone)]
pub struct VaultSession {
    pub(crate) vault_id: Uuid,
    pub(crate) master_key: MasterKey,
    pub(crate) subkeys: VaultSubkeys,
    pub(crate) catalog: UnlockedCatalog,
    pub(crate) envelope: PasswordEnvelope,
    pub(crate) providers: HashMap<Uuid, Arc<dyn StorageProvider>>,
    pub(crate) roots: HashMap<Uuid, PathBuf>,
    pub(crate) credential_store: Arc<dyn CredentialStore>,
    pub(crate) oauth_flow: OAuthFlow,
    pub(crate) oauth_registry: OAuthApplicationRegistry,
    pub(crate) background_cancel: CancellationToken,
    pub(crate) repair_lock: Arc<tokio::sync::Mutex<()>>,
}
impl fmt::Debug for VaultSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VaultSession")
            .field("vault_id", &self.vault_id)
            .field("master_key", &"<redacted>")
            .field("subkeys", &"<redacted>")
            .field("providers", &self.providers.len())
            .finish()
    }
}
impl VaultSession {
    async fn protection_map_for_version(&self, version: Uuid) -> Result<ProtectionMap, CoreError> {
        let file_version = self.catalog.load_file_version(version).await?;
        let chunks = self.catalog.list_chunks(version).await?;
        let replicas = self.catalog.list_replicas(version).await?;
        let targets = self.catalog.load_storage_targets().await?;
        let expected_objects = file_version.chunk_count.saturating_add(1);
        let mut summaries = Vec::with_capacity(targets.len());
        for target in targets {
            let target_replicas: Vec<_> = replicas
                .iter()
                .filter(|replica| replica.storage_target_id == target.id)
                .collect();
            let verified_objects = target_replicas
                .iter()
                .filter(|replica| replica.state == ReplicaState::Verified)
                .count() as u32;
            let corrupt = target_replicas
                .iter()
                .any(|replica| replica.state == ReplicaState::Corrupt);
            let pending = target_replicas
                .iter()
                .any(|replica| replica.state == ReplicaState::Pending);
            let manifest_verified = target_replicas.iter().any(|replica| {
                replica.object_kind == ObjectKind::Manifest
                    && replica.state == ReplicaState::Verified
            });
            let chunk_verified = chunks.iter().all(|chunk| {
                target_replicas.iter().any(|replica| {
                    replica.object_kind == ObjectKind::Chunk
                        && replica.chunk_id == Some(chunk.id)
                        && replica.state == ReplicaState::Verified
                })
            });
            let last_verified_at = if manifest_verified && chunk_verified {
                let timestamps: Vec<_> = target_replicas
                    .iter()
                    .filter(|replica| replica.state == ReplicaState::Verified)
                    .filter_map(|replica| replica.last_verified_at.as_ref())
                    .cloned()
                    .collect();
                (timestamps.len() == expected_objects as usize)
                    .then(|| timestamps.into_iter().min())
                    .flatten()
            } else {
                None
            };
            summaries.push(ProtectionTargetSummary {
                target_id: target.id,
                complete: manifest_verified && chunk_verified,
                corrupt,
                pending,
                verified_objects,
                expected_objects,
                last_verified_at,
            });
        }
        let verified_copies = summaries.iter().filter(|target| target.complete).count() as u32;
        let required_copies = summaries.len().clamp(1, 2) as u32;
        let last_verified_at = summaries
            .iter()
            .filter_map(|target| target.last_verified_at.as_ref())
            .min()
            .cloned();
        Ok(ProtectionMap {
            file_version_id: version,
            verified_copies,
            required_copies,
            last_verified_at,
            targets: summaries,
        })
    }

    pub async fn protection_map(&self, version: Uuid) -> Result<ProtectionMap, CoreError> {
        self.protection_map_for_version(version).await
    }

    pub fn status(&self) -> VaultStatus {
        let _ = &self.master_key;
        VaultStatus::Unlocked
    }
    pub fn vault_id(&self) -> Uuid {
        self.vault_id
    }
    pub fn lock(self) {}
    pub async fn change_password(&mut self, current: &str, new: &str) -> Result<(), CoreError> {
        if !password_ok(new) {
            return Err(CoreError::Authentication);
        }
        let master = undercloud_crypto::unwrap_master_key(self.vault_id, current, &self.envelope)
            .map_err(auth)?;
        let replacement =
            undercloud_crypto::wrap_master_key(self.vault_id, new, &master).map_err(auth)?;
        self.catalog.replace_password_envelope(&replacement).await?;
        self.catalog.bump_recovery_generation().await?;
        self.envelope = replacement;
        Ok(())
    }
    pub async fn add_local_provider(&mut self, root: impl AsRef<Path>) -> Result<Uuid, CoreError> {
        let canonical = tokio::fs::canonicalize(root.as_ref())
            .await
            .map_err(|_| CoreError::ProviderUnavailable)?;
        if self.roots.values().any(|p| p == &canonical) {
            return Err(CoreError::DuplicateProvider);
        }
        let provider = Arc::new(LocalProvider::new(&canonical));
        provider.health_check().await?;
        let id = self
            .catalog
            .create_storage_target(
                "local",
                canonical.to_string_lossy().as_bytes(),
                self.providers.len() as i64,
            )
            .await?;
        self.providers.insert(id, provider);
        self.catalog.bump_recovery_generation().await?;
        self.roots.insert(id, canonical);
        spawn_backfill_if_needed(self);
        Ok(id)
    }

    pub async fn authorize_cloud_provider(
        &self,
        kind: CloudProviderKind,
        cancel: &OAuthCancellation,
    ) -> Result<OAuthToken, CoreError> {
        let application =
            self.oauth_registry
                .resolve(kind.key_name())
                .map_err(|error| match error {
                    undercloud_provider_cloud::OAuthError::NotConfigured => {
                        CoreError::ProviderNotConfigured
                    }
                    _ => CoreError::InvalidProviderConfiguration,
                })?;
        authorize_cloud(kind, &application, &self.oauth_flow, cancel)
            .await
            .map_err(|error| match error {
                undercloud_provider_cloud::OAuthError::NotConfigured => {
                    CoreError::ProviderNotConfigured
                }
                undercloud_provider_cloud::OAuthError::InvalidConfiguration => {
                    CoreError::InvalidProviderConfiguration
                }
                undercloud_provider_cloud::OAuthError::Denied
                | undercloud_provider_cloud::OAuthError::InvalidCallback
                | undercloud_provider_cloud::OAuthError::MissingScope => {
                    CoreError::Provider(ProviderError::PermissionDenied)
                }
                undercloud_provider_cloud::OAuthError::TokenExchangeRejected { status, kind } => {
                    CoreError::OAuthTokenExchangeRejected { status, kind }
                }
                undercloud_provider_cloud::OAuthError::TokenExchangeMalformed => {
                    CoreError::OAuthTokenResponseInvalid
                }
                undercloud_provider_cloud::OAuthError::TokenExchangeNetwork => {
                    CoreError::OAuthTokenEndpointUnavailable
                }
                undercloud_provider_cloud::OAuthError::Revoked
                | undercloud_provider_cloud::OAuthError::RefreshFailed => {
                    CoreError::Provider(ProviderError::AuthenticationRequired)
                }
                _ => CoreError::Provider(ProviderError::TemporarilyUnavailable),
            })
    }

    pub async fn add_cloud_provider(
        &mut self,
        mut config: CloudProviderConfig,
        token: OAuthToken,
    ) -> Result<Uuid, CoreError> {
        if config.oauth_profile == "official-v1" && config.client_id.is_empty() {
            let application = self
                .oauth_registry
                .resolve(config.kind.key_name())
                .map_err(|_| CoreError::ProviderNotConfigured)?;
            config.client_id = application.client_id;
            config.redirect_strategy = application.redirect_strategy;
        }
        config
            .validate()
            .map_err(|_| CoreError::InvalidProviderConfiguration)?;
        let provider: Arc<dyn StorageProvider> = match config.kind {
            CloudProviderKind::GoogleDrive => Arc::new(
                GoogleDriveProvider::connect(
                    config.clone(),
                    Arc::clone(&self.credential_store),
                    self.oauth_flow.clone(),
                    token,
                )
                .await?,
            ),
            CloudProviderKind::OneDrive => Arc::new(
                OneDriveProvider::connect(
                    config.clone(),
                    Arc::clone(&self.credential_store),
                    self.oauth_flow.clone(),
                    token,
                )
                .await?,
            ),
            CloudProviderKind::Dropbox => Arc::new(
                DropboxProvider::connect(
                    config.clone(),
                    Arc::clone(&self.credential_store),
                    self.oauth_flow.clone(),
                    token,
                )
                .await?,
            ),
        };
        if let Err(error) = provider.health_check().await {
            let _ = self
                .credential_store
                .delete_oauth(&config.credential_reference);
            return Err(CoreError::ProviderHealthCheck(error));
        }
        let mut persisted_config = config.clone();
        if persisted_config.oauth_profile == "official-v1" {
            persisted_config.client_id.clear();
        }
        let bytes = match serde_json::to_vec(&persisted_config) {
            Ok(bytes) => bytes,
            Err(_) => {
                let _ = self
                    .credential_store
                    .delete_oauth(&config.credential_reference);
                return Err(CoreError::InvalidProviderConfiguration);
            }
        };
        let id = match self
            .catalog
            .create_storage_target_with_profile(
                config.kind.as_str(),
                &bytes,
                self.providers.len() as i64,
                &config.oauth_profile,
            )
            .await
        {
            Ok(id) => id,
            Err(error) => {
                let _ = self
                    .credential_store
                    .delete_oauth(&config.credential_reference);
                return Err(error.into());
            }
        };
        let matching_kind_count = self
            .catalog
            .load_storage_targets()
            .await?
            .iter()
            .filter(|target| target.provider_kind == config.kind.as_str())
            .count();
        let default_name = if let Some(display_name) = config
            .display_name
            .as_deref()
            .filter(|name| !name.trim().is_empty())
        {
            display_name.to_owned()
        } else if let Some(email) = config.account_email.as_deref() {
            email
                .split('@')
                .next()
                .filter(|value| !value.is_empty())
                .unwrap_or(config.kind.as_str())
                .to_owned()
        } else {
            friendly_provider_name(config.kind.as_str(), matching_kind_count)
        };
        let _ = self
            .catalog
            .set_storage_target_display_name(id, &default_name)
            .await;
        self.providers.insert(id, provider);
        self.catalog.bump_recovery_generation().await?;
        spawn_backfill_if_needed(self);
        Ok(id)
    }

    pub fn official_cloud_provider_config(
        &self,
        kind: CloudProviderKind,
        credential_reference: String,
    ) -> Result<CloudProviderConfig, CoreError> {
        let application =
            self.oauth_registry
                .resolve(kind.key_name())
                .map_err(|error| match error {
                    undercloud_provider_cloud::OAuthError::NotConfigured => {
                        CoreError::ProviderNotConfigured
                    }
                    _ => CoreError::InvalidProviderConfiguration,
                })?;
        Ok(CloudProviderConfig::from_application(
            kind,
            &application,
            credential_reference,
        ))
    }

    pub async fn remove_cloud_provider(
        &mut self,
        target_id: Uuid,
        revoke: bool,
    ) -> Result<(), CoreError> {
        let target = self
            .catalog
            .load_storage_targets()
            .await?
            .into_iter()
            .find(|target| {
                target.id == target_id
                    && matches!(
                        target.provider_kind.as_str(),
                        "google_drive" | "onedrive" | "dropbox"
                    )
            })
            .ok_or(CoreError::InvalidProviderConfiguration)?;
        self.ensure_provider_retirement_safe(target_id).await?;
        let config: CloudProviderConfig = serde_json::from_slice(&target.config)
            .map_err(|_| CoreError::InvalidProviderConfiguration)?;
        if revoke {
            if let Ok(token) = self
                .credential_store
                .get_oauth(&config.credential_reference)
            {
                let _ = self
                    .oauth_flow
                    .revoke(&config.oauth_config(), &token.access_token)
                    .await;
            }
        }
        self.credential_store
            .delete_oauth(&config.credential_reference)
            .map_err(credential_error)?;
        self.catalog.delete_storage_target(target_id).await?;
        self.catalog.bump_recovery_generation().await?;
        self.providers.remove(&target_id);
        Ok(())
    }
    pub async fn reconnect_local_provider(
        &mut self,
        target: Uuid,
        root: impl AsRef<Path>,
    ) -> Result<(), CoreError> {
        let canonical = tokio::fs::canonicalize(root.as_ref())
            .await
            .map_err(|_| CoreError::ProviderUnavailable)?;
        if self
            .roots
            .iter()
            .any(|(id, p)| *id != target && *p == canonical)
        {
            return Err(CoreError::DuplicateProvider);
        }
        let provider = Arc::new(LocalProvider::new(&canonical));
        provider.health_check().await?;
        let known = self
            .catalog
            .load_storage_targets()
            .await?
            .into_iter()
            .any(|t| t.id == target);
        if !known {
            return Err(CoreError::Catalog(CatalogError::InvariantViolation));
        }
        self.providers.insert(target, provider);
        self.roots.insert(target, canonical);
        Ok(())
    }
    pub fn disconnect_provider(&mut self, target: Uuid) {
        self.providers.remove(&target);
        self.roots.remove(&target);
    }
    pub async fn remove_local_provider(&mut self, target: Uuid) -> Result<(), CoreError> {
        self.ensure_provider_retirement_safe(target).await?;
        self.catalog.delete_storage_target(target).await?;
        self.catalog.bump_recovery_generation().await?;
        self.disconnect_provider(target);
        Ok(())
    }
    async fn ensure_provider_retirement_safe(&self, target: Uuid) -> Result<(), CoreError> {
        for file in self.catalog.list_logical_files().await? {
            let Some(version) = file.current_version_id else {
                continue;
            };
            let replicas = self.catalog.list_replicas(version).await?;
            if replicas
                .iter()
                .any(|replica| replica.storage_target_id == target)
            {
                return Err(CoreError::InvalidTransition);
            }
            if replicas
                .iter()
                .filter(|replica| {
                    replica.storage_target_id != target && replica.state == ReplicaState::Verified
                })
                .count()
                == 0
            {
                return Err(CoreError::InvalidTransition);
            }
        }
        Ok(())
    }
    pub async fn storage_target_ids(&self) -> Result<Vec<Uuid>, CoreError> {
        Ok(self
            .catalog
            .load_storage_targets()
            .await?
            .into_iter()
            .map(|t| t.id)
            .collect())
    }

    pub async fn rename_provider(&self, target: Uuid, name: &str) -> Result<(), CoreError> {
        self.catalog
            .set_storage_target_display_name(target, name)
            .await?;
        self.catalog.bump_recovery_generation().await?;
        Ok(())
    }

    pub async fn record_activity(&self, event: NewActivityEvent) -> Result<Uuid, CoreError> {
        self.catalog
            .create_activity_event(event)
            .await
            .map_err(Into::into)
    }

    pub async fn activity_events(
        &self,
        cursor: Option<&str>,
        page_size: u32,
        event_type: Option<&str>,
        status: Option<&str>,
        started_after: Option<&str>,
        started_before: Option<&str>,
    ) -> Result<(Vec<ActivityEventRecord>, Option<String>), CoreError> {
        self.catalog
            .list_activity_events(
                cursor,
                page_size,
                event_type,
                status,
                started_after,
                started_before,
            )
            .await
            .map_err(Into::into)
    }
    pub async fn recovery_freshness(&self) -> Result<RecoveryFreshnessRecord, CoreError> {
        self.catalog.recovery_freshness().await.map_err(Into::into)
    }

    pub async fn provider_summaries(&self) -> Result<Vec<ProviderSummary>, CoreError> {
        let targets = self.catalog.load_storage_targets().await?;
        let mut kind_ordinals = HashMap::<String, usize>::new();
        let futures = targets.into_iter().map(|target| {
            let provider = self.providers.get(&target.id).cloned();
            let kind = target.provider_kind.clone();
            let ordinal = {
                let count = kind_ordinals.entry(kind.clone()).or_insert(0);
                *count += 1;
                *count
            };
            async move {
                let kind = target.provider_kind;
                let display_name = target
                    .display_name
                    .unwrap_or_else(|| friendly_provider_name(&kind, ordinal));
                let Some(provider) = provider else {
                    return Ok::<ProviderSummary, CoreError>(ProviderSummary {
                        id: target.id,
                        kind,
                        connected: false,
                        health: "unavailable",
                        used_bytes: None,
                        total_bytes: None,
                        quota_known: false,
                        display_name,
                    });
                };
                let (health_result, quota_result) = tokio::join!(
                    tokio::time::timeout(
                        std::time::Duration::from_secs(5),
                        provider.health_check()
                    ),
                    tokio::time::timeout(std::time::Duration::from_secs(5), provider.quota()),
                );
                let health = match health_result {
                    Ok(Ok(ProviderHealth::Healthy)) => "healthy",
                    Ok(Ok(ProviderHealth::Degraded { .. })) => "degraded",
                    Ok(Ok(ProviderHealth::Unreachable { .. })) | Ok(Err(_)) | Err(_) => {
                        "unavailable"
                    }
                };
                let quota = quota_result.ok().and_then(Result::ok);
                Ok(ProviderSummary {
                    id: target.id,
                    kind,
                    connected: health != "unavailable",
                    health,
                    used_bytes: quota.as_ref().map(|q| q.used_bytes),
                    total_bytes: quota.as_ref().and_then(|q| q.total_bytes),
                    quota_known: quota.as_ref().is_some_and(|q| q.state == QuotaState::Known),
                    display_name,
                })
            }
        });
        futures_util::future::join_all(futures)
            .await
            .into_iter()
            .collect()
    }
    pub async fn list_files(&self) -> Result<Vec<FileSummary>, CoreError> {
        let logical_files = self.catalog.list_logical_files().await?;
        // Each file's health check does its own network round trips, so check several files concurrently (order preserved by `buffered`).
        futures_util::stream::iter(logical_files.into_iter().map(|file| async move {
            let health = match file.current_version_id {
                Some(version) => Some(
                    match tokio::time::timeout(
                        std::time::Duration::from_secs(5),
                        health(self, version),
                    )
                    .await
                    {
                        Ok(result) => result?,
                        Err(_) => FileHealth::HealthCheckTimedOut,
                    },
                ),
                None => None,
            };
            let size_bytes = match file.current_version_id {
                Some(version) => Some(self.catalog.load_file_version(version).await?.file_size),
                None => None,
            };
            let protection = match file.current_version_id {
                Some(version) => self.protection_map_for_version(version).await?,
                None => ProtectionMap {
                    file_version_id: Uuid::nil(),
                    verified_copies: 0,
                    required_copies: 0,
                    last_verified_at: None,
                    targets: Vec::new(),
                },
            };
            Ok::<FileSummary, CoreError>(FileSummary {
                logical_file_id: file.id,
                name: file.name,
                mime: file.mime,
                file_version_id: file.current_version_id,
                size_bytes,
                health,
                health_current: true,
                verified_copies: protection.verified_copies,
                required_copies: protection.required_copies,
                last_verified_at: protection.last_verified_at,
            })
        }))
        .buffered(LIST_FILES_CONCURRENCY)
        .try_collect()
        .await
    }

    /// Returns catalog metadata and the last durable health observation without remote I/O.
    pub async fn list_files_cached(&self) -> Result<Vec<FileSummary>, CoreError> {
        let logical_files = self.catalog.list_logical_files().await?;
        let mut summaries = Vec::with_capacity(logical_files.len());
        for file in logical_files {
            let health = if let Some(version) = file.current_version_id {
                self.catalog
                    .list_health_observations(version)
                    .await?
                    .last()
                    .map(|observation| match observation.health_state {
                        HealthState::Healthy => FileHealth::Healthy,
                        HealthState::Degraded => FileHealth::Degraded,
                        HealthState::AtRisk => FileHealth::AtRisk,
                        HealthState::Unrecoverable => FileHealth::Unrecoverable,
                    })
            } else {
                None
            };
            let size_bytes = match file.current_version_id {
                Some(version) => Some(self.catalog.load_file_version(version).await?.file_size),
                None => None,
            };
            let protection = match file.current_version_id {
                Some(version) => self.protection_map_for_version(version).await?,
                None => ProtectionMap {
                    file_version_id: Uuid::nil(),
                    verified_copies: 0,
                    required_copies: 0,
                    last_verified_at: None,
                    targets: Vec::new(),
                },
            };
            summaries.push(FileSummary {
                logical_file_id: file.id,
                name: file.name,
                mime: file.mime,
                file_version_id: file.current_version_id,
                size_bytes,
                health,
                health_current: false,
                verified_copies: protection.verified_copies,
                required_copies: protection.required_copies,
                last_verified_at: protection.last_verified_at,
            });
        }
        Ok(summaries)
    }
    pub async fn list_trash(&self) -> Result<Vec<TrashFileSummary>, CoreError> {
        let files = self.catalog.list_trashed_files().await?;
        let jobs = self.catalog.list_deletion_jobs().await?;
        let mut out = Vec::new();
        for file in files {
            let Some(job) = jobs
                .iter()
                .filter(|job| job.logical_file_id == file.id)
                .max_by_key(|job| (&job.updated_at, &job.id))
            else {
                continue;
            };
            let health = None;
            let size = match file.current_version_id {
                Some(version) => Some(self.catalog.load_file_version(version).await?.file_size),
                None => None,
            };
            let replica_count = self.catalog.count_file_replicas(file.id).await?;
            out.push(TrashFileSummary {
                file: FileSummary {
                    logical_file_id: file.id,
                    name: file.name,
                    mime: file.mime,
                    file_version_id: file.current_version_id,
                    size_bytes: size,
                    health,
                    health_current: false,
                    verified_copies: 0,
                    required_copies: 0,
                    last_verified_at: None,
                },
                deletion_id: job.id,
                state: job.state.clone(),
                purge_after: job.purge_after.clone(),
                retry_classification: job.retry_classification.clone(),
                replica_count,
            });
        }
        Ok(out)
    }

    pub async fn count_file_replicas(&self, logical_file_id: Uuid) -> Result<u32, CoreError> {
        let file = self.catalog.load_logical_file(logical_file_id).await?;
        let Some(version_id) = file.current_version_id else {
            return Ok(0);
        };
        Ok(self.catalog.count_file_replicas(version_id).await?)
    }
    pub async fn move_file_to_trash(
        &self,
        file: Uuid,
        operation_id: &str,
        purge_after: Option<String>,
    ) -> Result<Uuid, CoreError> {
        let deletion = Uuid::new_v4();
        self.catalog
            .move_file_to_trash(file, deletion, operation_id, purge_after.as_deref())
            .await?;
        self.catalog.bump_recovery_generation().await?;
        self.record_activity(NewActivityEvent {
            operation_id: operation_id.to_owned(),
            event_type: "file_trash".into(),
            status: "completed".into(),
            related_file_id: Some(file),
            related_target_id: None,
            display_metadata: "File moved to Trash".into(),
            started_at: deletion_timestamp(),
            completed_at: Some(deletion_timestamp()),
            transferred_bytes: None,
            error_code: None,
            retry_classification: None,
        })
        .await?;
        Ok(deletion)
    }
    pub async fn restore_file_from_trash(
        &self,
        file: Uuid,
        operation_id: &str,
    ) -> Result<(), CoreError> {
        self.catalog.restore_file_from_trash(file).await?;
        self.catalog.bump_recovery_generation().await?;
        self.record_activity(NewActivityEvent {
            operation_id: operation_id.to_owned(),
            event_type: "file_restore_from_trash".into(),
            status: "completed".into(),
            related_file_id: Some(file),
            related_target_id: None,
            display_metadata: "File restored from Trash".into(),
            started_at: deletion_timestamp(),
            completed_at: Some(deletion_timestamp()),
            transferred_bytes: None,
            error_code: None,
            retry_classification: None,
        })
        .await?;
        Ok(())
    }
    pub async fn permanently_delete_file(
        &self,
        file: Uuid,
        operation_id: &str,
        cancel: CancellationToken,
    ) -> Result<DeletionOutcome, CoreError> {
        let deletion = self
            .catalog
            .list_deletion_jobs()
            .await?
            .into_iter()
            .find(|job| job.logical_file_id == file && job.mode == "permanent")
            .map(|job| job.id)
            .unwrap_or_else(Uuid::new_v4);
        let already_planned = self.catalog.load_deletion_job(deletion).await.is_ok();
        if !already_planned {
            self.catalog
                .plan_permanent_deletion(file, deletion, operation_id)
                .await?;
        }
        self.record_activity(NewActivityEvent {
            operation_id: operation_id.to_owned(),
            event_type: "file_delete_permanent_requested".into(),
            status: "started".into(),
            related_file_id: Some(file),
            related_target_id: None,
            display_metadata: "Permanent file deletion requested".into(),
            started_at: deletion_timestamp(),
            completed_at: None,
            transferred_bytes: None,
            error_code: None,
            retry_classification: None,
        })
        .await?;
        self.execute_deletion(deletion, cancel).await
    }

    pub async fn reconcile_deletions(&self, cancel: CancellationToken) -> Result<(), CoreError> {
        let now = deletion_timestamp();
        for job in self.catalog.list_deletion_jobs().await? {
            let due = job
                .purge_after
                .as_deref()
                .is_some_and(|at| at <= now.as_str());
            if job.state == "deleting"
                || job.state == "delete_incomplete"
                || (matches!(job.state.as_str(), "trashed" | "purge_scheduled") && due)
            {
                let _ = self
                    .purge_deletion_job(job.id, "automatic-purge", cancel.clone())
                    .await;
            }
        }
        Ok(())
    }
    pub fn spawn_deletion_reconciliation(&self) {
        let session = self.clone();
        let cancel = self.background_cancel.clone();
        tokio::spawn(async move {
            loop {
                let _ = session.reconcile_deletions(cancel.clone()).await;
                tokio::select! {
                    _ = tokio::time::sleep(std::time::Duration::from_secs(60)) => {}
                    _ = wait_for_cancel(cancel.clone()) => break,
                }
            }
        });
    }
    pub async fn purge_deletion_job(
        &self,
        deletion: Uuid,
        operation_id: &str,
        cancel: CancellationToken,
    ) -> Result<DeletionOutcome, CoreError> {
        let job = self.catalog.load_deletion_job(deletion).await?;
        let mut execution_id = deletion;
        if matches!(job.state.as_str(), "trashed" | "purge_scheduled") {
            execution_id = Uuid::new_v4();
            self.catalog
                .plan_permanent_deletion(job.logical_file_id, execution_id, operation_id)
                .await?;
        }
        self.execute_deletion(execution_id, cancel).await
    }
    pub async fn execute_deletion(
        &self,
        deletion: Uuid,
        cancel: CancellationToken,
    ) -> Result<DeletionOutcome, CoreError> {
        let job = self.catalog.load_deletion_job(deletion).await?;
        if job.state == "purge_planned" {
            self.catalog
                .destroy_file_keys_and_start_deletion(deletion)
                .await?;
        }
        if cancel.is_cancelled() {
            self.catalog
                .set_deletion_job_state(deletion, "delete_incomplete", Some("cancelled"), None)
                .await?;
            return Ok(DeletionOutcome {
                deletion_id: deletion,
                completed: false,
            });
        }
        let items = self.catalog.list_deletion_items(deletion).await?;
        let now = deletion_timestamp();
        let pending: Vec<_> = items
            .into_iter()
            .filter(|item| item.state != "deleted" && item.state != "shared")
            .filter(|item| {
                item.next_retry_at
                    .as_deref()
                    .is_none_or(|at| at <= now.as_str())
            })
            .collect();
        // Each item is an independent provider round trip (delete_object); running them one at a
        // time made permanent deletion take seconds per replica object on real cloud providers, so
        // process a bounded batch concurrently instead, same as repair_replicas does for copies.
        futures_util::stream::iter(pending.into_iter().map(Ok::<_, CoreError>))
            .try_for_each_concurrent(Some(DELETE_ITEM_CONCURRENCY), |item| {
                let cancel = cancel.clone();
                async move {
                    if cancel.is_cancelled() {
                        return Ok(());
                    }
                    let Some(provider) = self.providers.get(&item.storage_target_id) else {
                        self.catalog
                            .set_deletion_item_result(
                                item.id,
                                "pending",
                                Some("provider_unavailable"),
                                item.retry_count.saturating_add(1),
                                Some(&retry_timestamp(item.retry_count)),
                            )
                            .await?;
                        return Ok(());
                    };
                    if self.catalog.is_deletion_item_shared(item.id).await? {
                        self.catalog
                            .set_deletion_item_result(
                                item.id,
                                "shared",
                                Some("shared_reference"),
                                item.retry_count,
                                None,
                            )
                            .await?;
                        return Ok(());
                    }
                    let result = provider
                        .delete_object(&ObjectLocator(item.locator.clone()))
                        .await;
                    match result {
                        Ok(()) | Err(ProviderError::ObjectMissing) => {
                            self.catalog
                                .set_deletion_item_result(
                                    item.id,
                                    "deleted",
                                    Some("deleted"),
                                    item.retry_count,
                                    None,
                                )
                                .await?;
                        }
                        Err(ProviderError::AuthenticationRequired) => {
                            self.catalog
                                .set_deletion_item_result(
                                    item.id,
                                    "blocked",
                                    Some("reauthorization_required"),
                                    item.retry_count,
                                    None,
                                )
                                .await?;
                        }
                        Err(ProviderError::PermissionDenied) => {
                            self.catalog
                                .set_deletion_item_result(
                                    item.id,
                                    "blocked",
                                    Some("permission_required"),
                                    item.retry_count,
                                    None,
                                )
                                .await?;
                        }
                        Err(error) => {
                            let retry = error.is_retryable();
                            self.catalog
                                .set_deletion_item_result(
                                    item.id,
                                    if retry { "pending" } else { "blocked" },
                                    Some(if retry {
                                        "retry_scheduled"
                                    } else {
                                        "provider_rejected"
                                    }),
                                    item.retry_count.saturating_add(1),
                                    retry.then(|| retry_timestamp(item.retry_count)).as_deref(),
                                )
                                .await?;
                        }
                    }
                    Ok(())
                }
            })
            .await?;
        if cancel.is_cancelled() {
            self.catalog
                .set_deletion_job_state(deletion, "delete_incomplete", Some("cancelled"), None)
                .await?;
            return Ok(DeletionOutcome {
                deletion_id: deletion,
                completed: false,
            });
        }
        let completed = self.catalog.complete_deletion_if_ready(deletion).await?;
        if completed {
            self.catalog.bump_recovery_generation().await?;
        }
        self.record_activity(NewActivityEvent {
            operation_id: job.operation_id,
            event_type: if completed {
                "file_delete_completed"
            } else {
                "file_delete_incomplete"
            }
            .into(),
            status: if completed { "completed" } else { "failed" }.into(),
            related_file_id: Some(job.logical_file_id),
            related_target_id: None,
            display_metadata: if completed {
                "File permanently deleted"
            } else {
                "File deletion requires retry"
            }
            .into(),
            started_at: deletion_timestamp(),
            completed_at: Some(deletion_timestamp()),
            transferred_bytes: None,
            error_code: None,
            retry_classification: if completed {
                None
            } else {
                Some("provider_cleanup_pending".into())
            },
        })
        .await?;
        Ok(DeletionOutcome {
            deletion_id: deletion,
            completed,
        })
    }
    pub async fn verify_recovered_health(&self, version: Uuid) -> Result<FileHealth, CoreError> {
        health(self, version).await
    }
    #[tracing::instrument(
        skip_all,
        fields(subsystem = "core", operation = "upload", stage = "start")
    )]
    pub async fn upload_file<R>(
        &self,
        source: R,
        source_size_hint: Option<u64>,
        logical_name: &str,
        folder_id: Option<Uuid>,
        idempotency_key: &str,
        progress: mpsc::Sender<UploadProgress>,
    ) -> Result<UploadResult, CoreError>
    where
        R: AsyncRead + Unpin + Send + 'static,
    {
        let result = upload_file(
            self,
            source,
            source_size_hint,
            logical_name,
            folder_id,
            idempotency_key,
            progress,
            CancellationToken::new(),
        )
        .await;
        if result.is_ok() {
            self.catalog.bump_recovery_generation().await?;
        }
        result
    }
    pub async fn upload_file_with_cancel<R>(
        &self,
        source: R,
        source_size_hint: Option<u64>,
        logical_name: &str,
        folder_id: Option<Uuid>,
        idempotency_key: &str,
        progress: mpsc::Sender<UploadProgress>,
        cancel: CancellationToken,
    ) -> Result<UploadResult, CoreError>
    where
        R: AsyncRead + Unpin + Send + 'static,
    {
        let result = upload_file(
            self,
            source,
            source_size_hint,
            logical_name,
            folder_id,
            idempotency_key,
            progress,
            cancel,
        )
        .await;
        if result.is_ok() {
            self.catalog.bump_recovery_generation().await?;
        }
        result
    }
    #[tracing::instrument(
        skip_all,
        fields(subsystem = "core", operation = "restore", stage = "start")
    )]
    pub async fn restore_file(
        &self,
        version: Uuid,
        destination: &Path,
        cancel: CancellationToken,
    ) -> Result<(), CoreError> {
        restore_file(self, version, destination, cancel).await
    }
    #[tracing::instrument(
        skip_all,
        fields(subsystem = "core", operation = "health", stage = "start")
    )]
    pub async fn health(&self, version: Uuid) -> Result<FileHealth, CoreError> {
        health(self, version).await
    }
    #[tracing::instrument(
        skip_all,
        fields(subsystem = "core", operation = "repair", stage = "start")
    )]
    pub async fn repair_automatically(&self, version: Uuid) -> Result<FileHealth, CoreError> {
        let _repair_guard = self.repair_lock.lock().await;
        self.catalog
            .ensure_version_active(version)
            .await
            .map_err(|_| CoreError::InvalidTransition)?;
        let replicas = self.catalog.list_replicas(version).await?;
        for replica in replicas
            .iter()
            .filter(|r| r.state == ReplicaState::Verified)
        {
            let Some(provider) = self.providers.get(&replica.storage_target_id) else {
                continue;
            };
            if let Err(error) = provider
                .head_object(&ObjectLocator(replica.locator.clone()))
                .await
            {
                if is_definitive_missing(&error) {
                    self.catalog
                        .set_replica_state(replica.id, ReplicaState::Missing)
                        .await?;
                }
            }
        }
        let replicas = self.catalog.list_replicas(version).await?;
        let file_version = self.catalog.load_file_version(version).await?;
        let file_size = file_version.file_size;
        let required_objects = file_version.chunk_count.saturating_add(1) as usize;
        let mut verified_counts: std::collections::HashMap<Uuid, usize> =
            std::collections::HashMap::new();
        for r in replicas
            .iter()
            .filter(|r| r.state == ReplicaState::Verified)
        {
            *verified_counts.entry(r.storage_target_id).or_insert(0) += 1;
        }
        // A target only "already has" this file if every object (chunk + manifest) is verified on
        // it; a target with some verified objects from an interrupted backfill still needs repair
        // and must stay eligible as a destination, not be excluded like a fully-replicated target.
        let verified_targets: std::collections::HashSet<Uuid> = verified_counts
            .into_iter()
            .filter(|&(_, count)| count >= required_objects)
            .map(|(id, _)| id)
            .collect();
        let preferred_targets: std::collections::HashSet<Uuid> = replicas
            .iter()
            .filter(|r| r.state != ReplicaState::Verified)
            .map(|r| r.storage_target_id)
            .collect();
        let source = replicas
            .iter()
            .find(|r| {
                r.state == ReplicaState::Verified
                    && self.providers.contains_key(&r.storage_target_id)
                    && verified_targets.contains(&r.storage_target_id)
            })
            .map(|r| r.storage_target_id)
            .ok_or(CoreError::Unrecoverable)?;
        // If every currently connected target already holds a full copy of this file, there is
        // nothing for repair to move. Report the real health from already-known catalog state
        // instead of erroring -- and deliberately without re-verifying every object's AEAD tag
        // over the network like health() does, since that turns a no-op repair click into a full,
        // slow, request-per-chunk integrity scan of a file nothing is actually wrong with.
        if self
            .providers
            .keys()
            .all(|id| *id == source || verified_targets.contains(id))
        {
            let target_count = self.storage_target_ids().await?.len();
            let required = required_replicas(required_objects as u32, target_count);
            let verified = u32::try_from(
                replicas
                    .iter()
                    .filter(|r| r.state == ReplicaState::Verified)
                    .count(),
            )
            .unwrap_or(u32::MAX);
            tracing::warn!(
                subsystem = "core",
                operation = "repair",
                stage = "already_covered",
                version = %version,
                verified,
                required,
                target_count,
                connected = self.providers.len(),
                "repair no-op: reporting health from catalog state"
            );
            return record_health_state(self, version, verified, required).await;
        }
        let summaries = self.provider_summaries().await?;
        let needs_reauthorization = summaries
            .iter()
            .any(|p| !self.providers.contains_key(&p.id) && p.kind != "local");
        let candidates: Vec<_> = summaries
            .into_iter()
            .filter(|p| {
                self.providers.contains_key(&p.id)
                    && p.id != source
                    && !verified_targets.contains(&p.id)
                    && !p
                        .total_bytes
                        .zip(p.used_bytes)
                        .and_then(|(total, used)| total.checked_sub(used))
                        .is_some_and(|available| p.quota_known && available < file_size)
            })
            .collect();
        if candidates.is_empty() {
            tracing::warn!(
                subsystem = "core",
                operation = "repair",
                stage = "no_destination",
                source = %source,
                connected_targets = self.providers.len(),
                needs_reauthorization,
                "no eligible repair destination found"
            );
        }
        let destination = candidates
            .into_iter()
            .min_by_key(|p| {
                (
                    if preferred_targets.contains(&p.id) {
                        0u8
                    } else {
                        1u8
                    },
                    if p.quota_known { 0u8 } else { 1u8 },
                    p.id,
                )
            })
            .map(|p| p.id)
            .ok_or(if needs_reauthorization {
                CoreError::Provider(ProviderError::AuthenticationRequired)
            } else {
                CoreError::ProviderUnavailable
            })?;
        repair_to_target(self, version, destination).await
    }
    pub fn cancel_background_work(&self) {
        self.background_cancel.cancel();
    }
}

fn is_definitive_missing(error: &ProviderError) -> bool {
    matches!(error, ProviderError::ObjectMissing)
}

#[cfg(test)]
mod provider_health_tests {
    use super::*;

    #[test]
    fn only_object_missing_is_definitive_replica_loss() {
        assert!(is_definitive_missing(&ProviderError::ObjectMissing));
        assert!(!is_definitive_missing(
            &ProviderError::TemporarilyUnavailable
        ));
        assert!(!is_definitive_missing(
            &ProviderError::AuthenticationRequired
        ));
        assert!(!is_definitive_missing(&ProviderError::RateLimited));
        assert!(!is_definitive_missing(&ProviderError::RequestRejected {
            status: 500,
            message: None,
        }));
        assert!(!is_definitive_missing(&ProviderError::Io(
            std::io::Error::new(std::io::ErrorKind::TimedOut, "timeout",)
        )));
    }
}

fn friendly_provider_name(kind: &str, ordinal: usize) -> String {
    let label = match kind {
        "google_drive" => "Google Drive",
        "onedrive" => "OneDrive",
        "dropbox" => "Dropbox",
        _ => "Storage",
    };
    format!("{label} {ordinal}")
}

fn required_replicas(object_count: u32, target_count: usize) -> u32 {
    object_count.saturating_mul(target_count.clamp(1, 2) as u32)
}

fn is_healthy(verified: u32, required: u32) -> bool {
    verified >= required
}

fn deletion_timestamp() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .to_string()
}

async fn wait_for_cancel(cancel: CancellationToken) {
    while !cancel.is_cancelled() {
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
}
fn retry_timestamp(retry_count: u32) -> String {
    let delay = 1_000u64.saturating_mul(2u64.saturating_pow(retry_count.min(8)));
    let now = deletion_timestamp().parse::<u64>().unwrap_or_default();
    now.saturating_add(delay.min(15 * 60 * 1000)).to_string()
}
impl VaultStatusSource for VaultSession {
    fn vault_status(&self) -> VaultStatus {
        VaultStatus::Unlocked
    }
}

#[tracing::instrument(
    skip_all,
    fields(subsystem = "core", operation = "vault_create", stage = "start")
)]
pub async fn create_vault(path: &Path, password: &str) -> Result<VaultSession, CoreError> {
    create_vault_with_store(
        path,
        password,
        Arc::new(OsKeyringCredentialStore::new("undercloud")),
    )
    .await
}

async fn create_vault_with_store(
    path: &Path,
    password: &str,
    credential_store: Arc<dyn CredentialStore>,
) -> Result<VaultSession, CoreError> {
    if !password_ok(password) || path.exists() {
        return Err(CoreError::Authentication);
    }
    let vault_id = Uuid::new_v4();
    let master_key = undercloud_crypto::generate_master_key();
    let envelope =
        undercloud_crypto::wrap_master_key(vault_id, password, &master_key).map_err(auth)?;
    let bootstrap = CatalogBootstrap::open(path).await?;
    bootstrap.create_vault(vault_id, 1, &envelope).await?;
    let subkeys = derive_vault_subkeys(&master_key, vault_id);
    let catalog = bootstrap.unlock(subkeys.catalog_field.clone()).await?;
    Ok(VaultSession {
        vault_id,
        master_key,
        subkeys,
        catalog,
        envelope,
        providers: HashMap::new(),
        roots: HashMap::new(),
        credential_store,
        oauth_flow: OAuthFlow::new(),
        oauth_registry: OAuthApplicationRegistry::official(),
        background_cancel: CancellationToken::new(),
        repair_lock: Arc::new(tokio::sync::Mutex::new(())),
    })
}
#[tracing::instrument(
    skip_all,
    fields(subsystem = "core", operation = "vault_open", stage = "start")
)]
pub async fn open_vault(path: &Path) -> Result<LockedVault, CoreError> {
    open_vault_with_store(path, Arc::new(OsKeyringCredentialStore::new("undercloud"))).await
}

async fn open_vault_with_store(
    path: &Path,
    credential_store: Arc<dyn CredentialStore>,
) -> Result<LockedVault, CoreError> {
    // CatalogBootstrap::open creates the file if missing (needed by create_vault_with_store), so guard here or a missing vault silently becomes an empty one.
    if !path.exists() {
        return Err(CoreError::VaultNotFound);
    }
    Ok(LockedVault {
        bootstrap: CatalogBootstrap::open(path).await?,
        credential_store,
    })
}
#[tracing::instrument(
    skip_all,
    fields(subsystem = "core", operation = "vault_unlock", stage = "start")
)]
pub async fn unlock_vault(handle: LockedVault, password: &str) -> Result<VaultSession, CoreError> {
    let vault_id = handle.bootstrap.vault_id().await?;
    let envelope = handle.bootstrap.password_envelope().await?;
    let master_key =
        undercloud_crypto::unwrap_master_key(vault_id, password, &envelope).map_err(auth)?;
    let subkeys = derive_vault_subkeys(&master_key, vault_id);
    let catalog = handle
        .bootstrap
        .unlock(subkeys.catalog_field.clone())
        .await?;
    let mut session = VaultSession {
        vault_id,
        master_key,
        subkeys,
        catalog,
        envelope,
        providers: HashMap::new(),
        roots: HashMap::new(),
        credential_store: Arc::clone(&handle.credential_store),
        oauth_flow: OAuthFlow::new(),
        oauth_registry: OAuthApplicationRegistry::official(),
        background_cancel: CancellationToken::new(),
        repair_lock: Arc::new(tokio::sync::Mutex::new(())),
    };
    for target in session.catalog.load_storage_targets().await? {
        if target.provider_kind == "local" {
            let Ok(path) = String::from_utf8(target.config.clone()) else {
                continue;
            };
            let Ok(canonical) = tokio::fs::canonicalize(&path).await else {
                continue;
            };
            let provider = Arc::new(LocalProvider::new(&canonical));
            if provider.health_check().await.is_ok() {
                session.providers.insert(target.id, provider);
                session.roots.insert(target.id, canonical);
            }
        } else if matches!(
            target.provider_kind.as_str(),
            "google_drive" | "onedrive" | "dropbox"
        ) {
            let Ok(mut config) = serde_json::from_slice::<CloudProviderConfig>(&target.config)
            else {
                continue;
            };
            if target.oauth_application_profile != "none"
                && target.oauth_application_profile != config.oauth_profile
            {
                continue;
            }
            if config.oauth_profile == "official-v1" && config.client_id.is_empty() {
                let Ok(application) = session.oauth_registry.resolve(config.kind.key_name()) else {
                    continue;
                };
                config.client_id = application.client_id;
                config.redirect_strategy = application.redirect_strategy;
            }
            let Ok(stored) = session
                .credential_store
                .get_oauth(&config.credential_reference)
            else {
                continue;
            };
            let token = OAuthToken {
                access_token: stored.access_token.clone(),
                refresh_token: stored.refresh_token.clone(),
                expires_at_unix: stored.expires_at_unix,
            };
            let provider = match config.kind {
                CloudProviderKind::GoogleDrive => GoogleDriveProvider::connect(
                    config,
                    Arc::clone(&session.credential_store),
                    session.oauth_flow.clone(),
                    token,
                )
                .await
                .map(|provider| Arc::new(provider) as Arc<dyn StorageProvider>),
                CloudProviderKind::OneDrive => OneDriveProvider::connect(
                    config,
                    Arc::clone(&session.credential_store),
                    session.oauth_flow.clone(),
                    token,
                )
                .await
                .map(|provider| Arc::new(provider) as Arc<dyn StorageProvider>),
                CloudProviderKind::Dropbox => DropboxProvider::connect(
                    config,
                    Arc::clone(&session.credential_store),
                    session.oauth_flow.clone(),
                    token,
                )
                .await
                .map(|provider| Arc::new(provider) as Arc<dyn StorageProvider>),
            };
            if let Ok(provider) = provider {
                let health = tokio::time::timeout(
                    std::time::Duration::from_secs(15),
                    provider.health_check(),
                )
                .await;
                if matches!(health, Ok(Ok(_))) {
                    session.providers.insert(target.id, provider);
                }
            }
        }
    }
    for job in session.catalog.list_sync_jobs().await? {
        if matches!(job.state.as_str(), "pending" | "running" | "failed") {
            for object in session.catalog.list_sync_job_objects(job.id).await? {
                if let Some(provider) = session.providers.get(&object.storage_target_id) {
                    if provider
                        .delete_object(&ObjectLocator(object.locator.clone()))
                        .await
                        .is_ok()
                    {
                        let _ = session
                            .catalog
                            .mark_sync_job_object_deleted(object.id)
                            .await;
                    }
                }
            }
            session.catalog.set_sync_job_state(job.id, "failed").await?;
        }
    }
    spawn_backfill_if_needed(&session);
    Ok(session)
}

fn locator() -> ObjectLocator {
    ObjectLocator(Uuid::new_v4().simple().to_string())
}
async fn put(
    provider: &Arc<dyn StorageProvider>,
    locator: ObjectLocator,
    bytes: Vec<u8>,
) -> Result<ObjectLocator, CoreError> {
    let expected = bytes.len() as u64;
    let body =
        Box::pin(std::io::Cursor::new(bytes)) as std::pin::Pin<Box<dyn AsyncRead + Send + Sync>>;
    let receipt = provider
        .put_object(PutObjectRequest {
            locator,
            body,
            expected_size: expected,
        })
        .await?;
    Ok(receipt.locator)
}
async fn put_cancelled(
    provider: &Arc<dyn StorageProvider>,
    locator: ObjectLocator,
    bytes: Vec<u8>,
    cancel: &CancellationToken,
) -> Result<ObjectLocator, CoreError> {
    if cancel.is_cancelled() {
        return Err(CoreError::Cancelled);
    }
    put(provider, locator, bytes).await
}
async fn read(
    provider: &Arc<dyn StorageProvider>,
    locator: &ObjectLocator,
) -> Result<Vec<u8>, CoreError> {
    let expected_size = provider.head_object(locator).await?.size;
    if expected_size > MAX_REMOTE_OBJECT_BYTES {
        return Err(CoreError::Provider(ProviderError::IntegrityMismatch));
    }
    let r = provider
        .get_object(GetObjectRequest {
            locator: locator.clone(),
            range: None,
        })
        .await?;
    let mut b = Vec::new();
    r.take(expected_size.saturating_add(1))
        .read_to_end(&mut b)
        .await?;
    if b.len() as u64 != expected_size {
        return Err(CoreError::Provider(ProviderError::IntegrityMismatch));
    }
    Ok(b)
}

fn validate_restore_destination(destination: &Path) -> Result<(), CoreError> {
    let name = destination.file_name().ok_or_else(|| {
        CoreError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "invalid restore filename",
        ))
    })?;
    let name = name.to_str().ok_or_else(|| {
        CoreError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "invalid restore filename",
        ))
    })?;
    if name.is_empty()
        || name == "."
        || name == ".."
        || name
            .chars()
            .any(|c| c == '/' || c == '\\' || c.is_control())
        || name.contains(':')
    {
        return Err(CoreError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "invalid restore filename",
        )));
    }
    let mut components = Path::new(name).components();
    if !matches!(
        (components.next(), components.next()),
        (Some(std::path::Component::Normal(_)), None)
    ) {
        return Err(CoreError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "invalid restore filename",
        )));
    }
    Ok(())
}
async fn authenticated_manifest(
    session: &VaultSession,
    version: Uuid,
    key: &undercloud_crypto::ManifestKey,
    replicas: &[undercloud_catalog::ReplicaRecord],
    expected: &undercloud_catalog::FileVersionRecord,
) -> Result<undercloud_format::ManifestBody, CoreError> {
    for rep in replicas
        .iter()
        .filter(|r| r.object_kind == ObjectKind::Manifest && r.state == ReplicaState::Verified)
    {
        let Some(provider) = session.providers.get(&rep.storage_target_id) else {
            continue;
        };
        let Ok(bytes) = read(provider, &ObjectLocator(rep.locator.clone())).await else {
            continue;
        };
        let Ok(env) = parse_manifest_envelope(&bytes) else {
            continue;
        };
        if env.vault_id != session.vault_id || env.file_version_id != version {
            continue;
        }
        let Ok(plain) = decrypt_manifest(
            key,
            &undercloud_crypto::ManifestIdentity {
                format_version: env.format_version,
                vault_id: session.vault_id,
                file_version_id: version,
            },
            &undercloud_crypto::EncryptedManifest {
                nonce: env.nonce,
                ciphertext: env.ciphertext,
            },
        )
        .map_err(crypto_err) else {
            continue;
        };
        let Ok(body) = parse_manifest_body(&plain) else {
            continue;
        };
        if body.file_size == expected.file_size
            && body.chunk_count == expected.chunk_count
            && body.content_hash.as_slice() == expected.content_hash.as_slice()
        {
            return Ok(body);
        }
    }
    Err(CoreError::Unrecoverable)
}
fn crypto_err<E>(_e: E) -> CoreError {
    CoreError::Authentication
}

async fn upload_file<R>(
    session: &VaultSession,
    source: R,
    source_size_hint: Option<u64>,
    logical_name: &str,
    folder_id: Option<Uuid>,
    key: &str,
    progress: mpsc::Sender<UploadProgress>,
    cancel: CancellationToken,
) -> Result<UploadResult, CoreError>
where
    R: AsyncRead + Unpin + Send + 'static,
{
    let mut targets: Vec<Uuid> = session.providers.keys().copied().collect();
    if targets.is_empty() {
        return Err(CoreError::ProviderUnavailable);
    }
    targets.truncate(2);
    // Reserve the idempotency key first: the UNIQUE constraint on sync_jobs.idempotency_key closes the race a plain look-then-insert cannot, and the pending/running row it creates lets startup crash-recovery find and fail an upload interrupted mid-flight (the only thing that makes it retryable via reclaim_failed_sync_job below).
    let job_id = match session
        .catalog
        .find_sync_job_by_idempotency_key(key)
        .await?
    {
        Some(existing) => {
            if let Some(v) = existing.file_version_id {
                let f = session.catalog.load_file_version(v).await?;
                return Ok(UploadResult {
                    file_version_id: v,
                    logical_file_id: f.logical_file_id,
                });
            }
            if matches!(existing.state.as_str(), "pending" | "running") {
                return Err(CoreError::InvalidTransition);
            }
            // Previous attempt failed outright with no committed file version: reclaim it for this retry (the state='failed' guard inside reclaim makes this a compare-and-swap, so two racing retries can't both win).
            if !session.catalog.reclaim_failed_sync_job(existing.id).await? {
                return Err(CoreError::InvalidTransition);
            }
            existing.id
        }
        None => match session
            .catalog
            .create_sync_job(None, JobKind::Upload, key)
            .await
        {
            Ok(id) => id,
            Err(e) if e.is_unique_violation() => return Err(CoreError::InvalidTransition),
            Err(e) => return Err(e.into()),
        },
    };

    // ---- Prepare phase (memory only): mint every identifier/wrapped key up front so replication needs no catalog writes, and the catalog is only touched in the final commit transaction, so a failure mid-upload leaves no orphaned rows.
    let version = Uuid::new_v4();
    let dek = generate_dek();
    let manifest_key = generate_manifest_key();
    let wrapped_dek = wrap_dek(
        &session.subkeys.file_key_wrap,
        session.vault_id,
        version,
        &dek,
    )
    .map_err(crypto_err)?;
    let wrapped_manifest = wrap_manifest_key(
        &session.subkeys.file_key_wrap,
        session.vault_id,
        version,
        &manifest_key,
    )
    .map_err(crypto_err)?;

    session
        .catalog
        .set_sync_job_state(job_id, "running")
        .await?;

    // ---- Replicate phase (providers only, no catalog writes): tracks every object written so it can be deleted on later failure, compensating for remote storage's lack of transactionality.
    let mut uploaded: Vec<UploadedObject> = Vec::new();
    let replicated = replicate_upload(
        session,
        source,
        &targets,
        job_id,
        version,
        &dek,
        &manifest_key,
        progress,
        source_size_hint,
        &mut uploaded,
        &cancel,
    )
    .await;

    let (total, chunk_ids, hash) = match replicated {
        Ok(ok) => ok,
        Err(e) => {
            cleanup_uploaded(&session.catalog, &session.providers, job_id, &uploaded).await;
            let _ = session.catalog.set_sync_job_state(job_id, "failed").await;
            return Err(e);
        }
    };

    let index = u32::try_from(chunk_ids.len()).map_err(|_| CoreError::Unrecoverable)?;

    // ---- Commit phase (single catalog transaction): either every row for this upload lands at once, or none do. Uses live-connected count (not health()/repair()'s registered count) since upload only ever targets connected providers.
    let required = required_replicas(index.saturating_add(1), targets.len());
    let name_owned = logical_name.to_owned();
    let uploaded_for_commit = uploaded.clone();
    let commit: Result<Uuid, _> = session
        .catalog
        .transaction(move |tx| {
            // The logical-file row is created here, so its id comes from the transaction method itself.
            let actual_file = tx.create_logical_file(folder_id, &name_owned, None)?;
            tx.create_file_version(version, actual_file, total, index, hash)?;
            tx.set_current_version(actual_file, version)?;
            tx.store_wrapped_file_keys(version, &wrapped_dek, &wrapped_manifest)?;
            for (i, chunk_id) in chunk_ids.iter().enumerate() {
                tx.create_chunk(
                    version,
                    *chunk_id,
                    u32::try_from(i).map_err(|_| CatalogError::InvariantViolation)?,
                )?;
            }
            for obj in uploaded_for_commit.iter() {
                let chunk_id = match (obj.kind, obj.chunk_index) {
                    (ObjectKind::Chunk, Some(i)) => Some(
                        chunk_ids
                            .get(usize::try_from(i).map_err(|_| CatalogError::InvariantViolation)?)
                            .copied()
                            .ok_or(CatalogError::InvariantViolation)?,
                    ),
                    (ObjectKind::Chunk, None) | (ObjectKind::Manifest, Some(_)) => {
                        return Err(CatalogError::InvariantViolation);
                    }
                    (ObjectKind::Manifest, None) => None,
                };
                tx.create_replica_verified(
                    version,
                    chunk_id,
                    obj.target,
                    obj.kind,
                    Uuid::new_v4(),
                    &obj.locator.0,
                )?;
            }
            tx.mark_sync_job_completed(job_id, version)?;
            tx.record_health_observation(version, required, required, HealthState::Healthy)?;
            tx.mark_file_version_healthy(version)?;
            Ok(actual_file)
        })
        .await;

    match commit {
        Ok(actual_file) => Ok(UploadResult {
            file_version_id: version,
            logical_file_id: actual_file,
        }),
        Err(e) => {
            // Commit failed (e.g. disk full): blobs must not linger on the providers, and the reserved job must not stay "running" forever.
            cleanup_uploaded(&session.catalog, &session.providers, job_id, &uploaded).await;
            let _ = session.catalog.set_sync_job_state(job_id, "failed").await;
            Err(e.into())
        }
    }
}

/// One object successfully written to one storage target during replication, awaiting its catalog row in the commit phase.
#[derive(Clone)]
struct UploadedObject {
    tracking_id: Option<Uuid>,
    target: Uuid,
    locator: ObjectLocator,
    kind: ObjectKind,
    chunk_index: Option<u32>,
}

async fn delete_best_effort(
    providers: &HashMap<Uuid, Arc<dyn StorageProvider>>,
    objects: &[UploadedObject],
) {
    for obj in objects {
        if let Some(provider) = providers.get(&obj.target) {
            let _ = provider.delete_object(&obj.locator).await;
        }
    }
}

async fn cleanup_uploaded(
    catalog: &UnlockedCatalog,
    providers: &HashMap<Uuid, Arc<dyn StorageProvider>>,
    job: Uuid,
    objects: &[UploadedObject],
) {
    delete_best_effort(providers, objects).await;
    for object in objects {
        if let Some(id) = object.tracking_id {
            let _ = catalog.mark_sync_job_object_deleted(id).await;
        }
    }
    let _ = catalog.set_sync_job_state(job, "failed").await;
}

/// Streams `source` through the chunker, encrypts each chunk, and replicates every object (chunks + manifest) to all targets; no catalog writes happen here, and each successful write is appended to `uploaded` so a later failure can compensate.
#[allow(clippy::too_many_arguments)]
async fn replicate_upload<R>(
    session: &VaultSession,
    source: R,
    targets: &[Uuid],
    job_id: Uuid,
    version: Uuid,
    dek: &undercloud_crypto::DataEncryptionKey,
    manifest_key: &undercloud_crypto::ManifestKey,
    progress: mpsc::Sender<UploadProgress>,
    source_size_hint: Option<u64>,
    uploaded: &mut Vec<UploadedObject>,
    cancel: &CancellationToken,
) -> Result<(u64, Vec<Uuid>, [u8; 32]), CoreError>
where
    R: AsyncRead + Unpin + Send + 'static,
{
    let mut rx = chunk_stream(source, DEFAULT_CHUNK_SIZE).await?;
    let mut chunk_ids = Vec::new();
    let mut total = 0u64;
    let mut index = 0u32;
    let mut hasher = ContentHasher::new(&session.subkeys.content_hash);
    while let Some(item) = rx.recv().await {
        if cancel.is_cancelled() {
            return Err(CoreError::Cancelled);
        }
        let plaintext = item?;
        total += plaintext.len() as u64;
        hasher.update(&plaintext);
        let encrypted = encrypt_chunk(
            dek,
            &ChunkIdentity {
                format_version: CHUNK_FORMAT_VERSION,
                vault_id: session.vault_id,
                file_version_id: version,
                chunk_index: u64::from(index),
            },
            &plaintext,
        )
        .map_err(crypto_err)?;
        let bytes = serialize_chunk_envelope(&ChunkEnvelope {
            format_version: CHUNK_FORMAT_VERSION,
            vault_id: session.vault_id,
            file_version_id: version,
            chunk_index: u64::from(index),
            nonce: encrypted.nonce,
            ciphertext: encrypted.ciphertext,
        });
        let chunk_id = Uuid::new_v4();
        // Puts to each target run concurrently (independent locators, independent providers); every successful one
        // is still recorded even if a sibling target fails, so `uploaded` stays complete for rollback.
        let mut pending = Vec::with_capacity(targets.len());
        for target in targets {
            let loc = locator();
            let tracking_id = session
                .catalog
                .record_sync_job_object(job_id, *target, ObjectKind::Chunk, Some(index), &loc.0)
                .await?;
            pending.push((*target, loc, tracking_id));
        }
        let target_results = futures_util::future::join_all(pending.into_iter().map(
            |(target, loc, tracking_id)| {
                let bytes = bytes.clone();
                async move {
                    let provider = session
                        .providers
                        .get(&target)
                        .ok_or(CoreError::ProviderUnavailable)?;
                    let expected_len = bytes.len() as u64;
                    let stored_locator = put_cancelled(provider, loc, bytes, cancel).await?;
                    if provider.head_object(&stored_locator).await?.size != expected_len {
                        return Err(CoreError::Provider(ProviderError::IntegrityMismatch));
                    }
                    Ok::<UploadedObject, CoreError>(UploadedObject {
                        tracking_id: Some(tracking_id),
                        target,
                        locator: stored_locator,
                        kind: ObjectKind::Chunk,
                        chunk_index: Some(index),
                    })
                }
            },
        ))
        .await;
        let mut first_err = None;
        for result in target_results {
            match result {
                Ok(object) => {
                    uploaded.push(object);
                }
                Err(err) => {
                    first_err.get_or_insert(err);
                }
            };
        }
        if let Some(err) = first_err {
            return Err(err);
        }
        chunk_ids.push(chunk_id);
        let _ = progress
            .send(UploadProgress {
                bytes_processed: total,
                total_bytes: source_size_hint,
            })
            .await;
        index += 1;
    }
    let hash = hasher.finalize();

    let manifest_encrypted = encrypt_manifest(
        manifest_key,
        &undercloud_crypto::ManifestIdentity {
            format_version: MANIFEST_FORMAT_VERSION,
            vault_id: session.vault_id,
            file_version_id: version,
        },
        &serialize_manifest_body(&ManifestBody {
            file_size: total,
            chunk_count: index,
            content_hash: hash,
        }),
    )
    .map_err(crypto_err)?;
    let manifest = serialize_manifest_envelope(&ManifestEnvelope {
        format_version: MANIFEST_FORMAT_VERSION,
        vault_id: session.vault_id,
        file_version_id: version,
        nonce: manifest_encrypted.nonce,
        ciphertext: manifest_encrypted.ciphertext,
    });
    for target in targets {
        if cancel.is_cancelled() {
            return Err(CoreError::Cancelled);
        }
        let provider = session
            .providers
            .get(target)
            .ok_or(CoreError::ProviderUnavailable)?;
        let loc = locator();
        let tracking_id = session
            .catalog
            .record_sync_job_object(job_id, *target, ObjectKind::Manifest, None, &loc.0)
            .await?;
        let stored_locator = put_cancelled(provider, loc, manifest.clone(), cancel).await?;
        if provider.head_object(&stored_locator).await?.size != manifest.len() as u64 {
            return Err(CoreError::Provider(ProviderError::IntegrityMismatch));
        }
        uploaded.push(UploadedObject {
            tracking_id: Some(tracking_id),
            target: *target,
            locator: stored_locator,
            kind: ObjectKind::Manifest,
            chunk_index: None,
        });
    }

    Ok((total, chunk_ids, hash))
}

const RESTORE_FETCH_CONCURRENCY: usize = 6;

async fn restore_file(
    session: &VaultSession,
    version: Uuid,
    destination: &Path,
    cancel: CancellationToken,
) -> Result<(), CoreError> {
    session
        .catalog
        .ensure_version_active(version)
        .await
        .map_err(|_| CoreError::InvalidTransition)?;
    validate_restore_destination(destination)?;
    if destination.exists() {
        return Err(CoreError::DestinationExists);
    }
    let v = session.catalog.load_file_version(version).await?;
    let (wd, wm) = session.catalog.load_wrapped_file_keys(version).await?;
    let dek = unwrap_dek(
        &session.subkeys.file_key_wrap,
        session.vault_id,
        version,
        &wd,
    )
    .map_err(crypto_err)?;
    let mk = unwrap_manifest_key(
        &session.subkeys.file_key_wrap,
        session.vault_id,
        version,
        &wm,
    )
    .map_err(crypto_err)?;
    let reps = session.catalog.list_replicas(version).await?;
    let _body = authenticated_manifest(session, version, &mk, &reps, &v).await?;
    let parent = destination
        .parent()
        .ok_or(CoreError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "destination has no parent",
        )))?;
    tokio::fs::create_dir_all(parent).await?;
    let tmp = destination.with_file_name(format!(
        ".{}.{}.tmp",
        destination
            .file_name()
            .unwrap_or_default()
            .to_string_lossy(),
        Uuid::new_v4()
    ));
    let result = async {
        let mut out = tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)
            .await?;
        let chunks = session.catalog.list_chunks(version).await?;
        let mut hash = ContentHasher::new(&session.subkeys.content_hash);
        // Per-request provider latency dominates over bandwidth, so fetch chunks concurrently (order preserved by `buffered`).
        let reps_ref = &reps;
        let dek_ref = &dek;
        let cancel_ref = &cancel;
        let mut fetches = futures_util::stream::iter(chunks.into_iter().map(move |c| async move {
            if cancel_ref.is_cancelled() {
                return Err(CoreError::Cancelled);
            }
            let mut accepted = None;
            for rep in reps_ref.iter().filter(|r| {
                r.chunk_id == Some(c.id)
                    && r.state == ReplicaState::Verified
                    && session.providers.contains_key(&r.storage_target_id)
            }) {
                let attempt = async {
                    let p = session
                        .providers
                        .get(&rep.storage_target_id)
                        .ok_or(CoreError::ProviderUnavailable)?;
                    let b = read(p, &ObjectLocator(rep.locator.clone())).await?;
                    let env = parse_chunk_envelope(&b)?;
                    if env.vault_id != session.vault_id
                        || env.file_version_id != version
                        || env.chunk_index != u64::from(c.chunk_index)
                    {
                        return Err(CoreError::Authentication);
                    }
                    decrypt_chunk(
                        dek_ref,
                        &ChunkIdentity {
                            format_version: env.format_version,
                            vault_id: session.vault_id,
                            file_version_id: version,
                            chunk_index: u64::from(c.chunk_index),
                        },
                        &undercloud_crypto::EncryptedChunk {
                            nonce: env.nonce,
                            ciphertext: env.ciphertext,
                        },
                    )
                    .map_err(crypto_err)
                }
                .await;
                if let Ok(pt) = attempt {
                    accepted = Some(pt);
                    break;
                }
            }
            accepted.ok_or(CoreError::Unrecoverable)
        }))
        .buffered(RESTORE_FETCH_CONCURRENCY);
        while let Some(pt) = fetches.next().await {
            let pt = pt?;
            hash.update(&pt);
            out.write_all(&pt).await?;
        }
        out.flush().await?;
        out.sync_all().await?;
        if hash.finalize() != v.content_hash.as_slice() {
            return Err(CoreError::Authentication);
        };
        drop(out);
        // hard_link is an atomic create-if-absent publication on supported local
        // filesystems. Unlike rename, it cannot clobber a file created in the
        // validation-to-publication window.
        tokio::fs::hard_link(&tmp, destination).await?;
        // Publication already succeeded; inability to remove our private temp
        // must not turn a successful restore into a reported failure.
        let _ = tokio::fs::remove_file(&tmp).await;
        Ok(())
    }
    .await;
    if result.is_err() {
        let _ = tokio::fs::remove_file(&tmp).await;
    }
    result
}

/// Fires only on the 1→2 target transition; runs fully detached, never holding the Tauri command lock.
fn spawn_backfill_if_needed(session: &VaultSession) {
    // Fires only on the exact 1->2 transition, not every subsequent connect (2->3, ...),
    // otherwise it races an in-flight manual repair for the same file version.
    if session.providers.len() != 2 {
        return;
    }
    let session = session.clone();
    tokio::spawn(async move {
        let Ok(logical_files) = session.catalog.list_logical_files().await else {
            return;
        };
        for file in logical_files {
            if session.background_cancel.is_cancelled() {
                return;
            }
            let Some(version) = file.current_version_id else {
                continue;
            };
            let _ = session.repair_automatically(version).await;
        }
    });
}

const HEALTH_VERIFY_CONCURRENCY: usize = 6;
const LIST_FILES_CONCURRENCY: usize = 6;

async fn health(session: &VaultSession, version: Uuid) -> Result<FileHealth, CoreError> {
    session
        .catalog
        .ensure_version_active(version)
        .await
        .map_err(|_| CoreError::InvalidTransition)?;
    let v = session.catalog.load_file_version(version).await?;
    let (wd, wm) = session.catalog.load_wrapped_file_keys(version).await?;
    let dek = unwrap_dek(
        &session.subkeys.file_key_wrap,
        session.vault_id,
        version,
        &wd,
    )
    .map_err(crypto_err)?;
    let mk = unwrap_manifest_key(
        &session.subkeys.file_key_wrap,
        session.vault_id,
        version,
        &wm,
    )
    .map_err(crypto_err)?;
    let chunks = session.catalog.list_chunks(version).await?;
    let reps = session.catalog.list_replicas(version).await?;
    // Each replica's verification is a full content fetch + decrypt against its provider, so verify replicas concurrently.
    let (v_ref, chunks_ref, dek_ref, mk_ref) = (&v, &chunks, &dek, &mk);
    let mut verify_futures: Vec<VerifyFuture<'_>> = Vec::new();
    for r in &reps {
        verify_futures.push(Box::pin(async move {
            let outcome = match session.providers.get(&r.storage_target_id) {
                Some(p) => {
                    verify_replica(session, version, v_ref, r, chunks_ref, dek_ref, mk_ref, p).await
                }
                None => VerifyOutcome::Unavailable,
            };
            (r.id, outcome)
        }));
    }
    let outcomes = futures_util::stream::iter(verify_futures)
        .buffer_unordered(HEALTH_VERIFY_CONCURRENCY)
        .collect::<Vec<_>>()
        .await;
    let mut verified = 0u32;
    for (replica_id, outcome) in outcomes {
        match outcome {
            VerifyOutcome::Verified => {
                verified += 1;
                session
                    .catalog
                    .set_replica_state(replica_id, ReplicaState::Verified)
                    .await?;
            }
            VerifyOutcome::Missing => {
                session
                    .catalog
                    .set_replica_state(replica_id, ReplicaState::Missing)
                    .await?
            }
            VerifyOutcome::Corrupt => {
                session
                    .catalog
                    .set_replica_state(replica_id, ReplicaState::Corrupt)
                    .await?
            }
            VerifyOutcome::Unavailable => {}
        }
    }
    // Registered target count, not live-connected: a disconnected target must still count toward the requirement.
    let target_count = session.storage_target_ids().await?.len();
    let required = required_replicas(v.chunk_count.saturating_add(1), target_count);
    record_health_state(session, version, verified, required).await
}

async fn record_health_state(
    session: &VaultSession,
    version: Uuid,
    verified: u32,
    required: u32,
) -> Result<FileHealth, CoreError> {
    if is_healthy(verified, required) {
        session
            .catalog
            .record_health_observation(version, verified, required, HealthState::Healthy)
            .await?;
        session.catalog.mark_file_version_healthy(version).await?;
        Ok(FileHealth::Healthy)
    } else if verified.saturating_mul(2) >= required {
        session
            .catalog
            .record_health_observation(version, verified, required, HealthState::Degraded)
            .await?;
        Ok(FileHealth::Degraded)
    } else if verified > 0 {
        session
            .catalog
            .record_health_observation(version, verified, required, HealthState::AtRisk)
            .await?;
        Ok(FileHealth::AtRisk)
    } else {
        session
            .catalog
            .record_health_observation(version, verified, required, HealthState::Unrecoverable)
            .await?;
        Ok(FileHealth::Unrecoverable)
    }
}

async fn verify_replica(
    session: &VaultSession,
    version: Uuid,
    expected: &undercloud_catalog::FileVersionRecord,
    replica: &undercloud_catalog::ReplicaRecord,
    chunks: &[undercloud_catalog::ChunkRecord],
    dek: &undercloud_crypto::DataEncryptionKey,
    manifest_key: &undercloud_crypto::ManifestKey,
    provider: &Arc<dyn StorageProvider>,
) -> VerifyOutcome {
    let bytes = match read(provider, &ObjectLocator(replica.locator.clone())).await {
        Ok(bytes) => bytes,
        Err(CoreError::Provider(ProviderError::ObjectMissing)) => return VerifyOutcome::Missing,
        Err(_) => return VerifyOutcome::Unavailable,
    };
    if replica.object_kind == ObjectKind::Manifest {
        verify_manifest_replica(session, version, expected, manifest_key, &bytes)
    } else {
        verify_chunk_replica(session, version, replica, chunks, dek, &bytes)
    }
}

fn verify_manifest_replica(
    session: &VaultSession,
    version: Uuid,
    expected: &undercloud_catalog::FileVersionRecord,
    manifest_key: &undercloud_crypto::ManifestKey,
    bytes: &[u8],
) -> VerifyOutcome {
    let Ok(env) = parse_manifest_envelope(bytes) else {
        return VerifyOutcome::Corrupt;
    };
    if env.vault_id != session.vault_id || env.file_version_id != version {
        return VerifyOutcome::Corrupt;
    }
    let Ok(plain) = decrypt_manifest(
        manifest_key,
        &undercloud_crypto::ManifestIdentity {
            format_version: env.format_version,
            vault_id: session.vault_id,
            file_version_id: version,
        },
        &undercloud_crypto::EncryptedManifest {
            nonce: env.nonce,
            ciphertext: env.ciphertext,
        },
    ) else {
        return VerifyOutcome::Corrupt;
    };
    let Ok(body) = parse_manifest_body(&plain) else {
        return VerifyOutcome::Corrupt;
    };
    if body.file_size == expected.file_size
        && body.chunk_count == expected.chunk_count
        && body.content_hash.as_slice() == expected.content_hash.as_slice()
    {
        VerifyOutcome::Verified
    } else {
        VerifyOutcome::Corrupt
    }
}

fn verify_chunk_replica(
    session: &VaultSession,
    version: Uuid,
    replica: &undercloud_catalog::ReplicaRecord,
    chunks: &[undercloud_catalog::ChunkRecord],
    dek: &undercloud_crypto::DataEncryptionKey,
    bytes: &[u8],
) -> VerifyOutcome {
    let Some(chunk) = chunks.iter().find(|c| Some(c.id) == replica.chunk_id) else {
        return VerifyOutcome::Corrupt;
    };
    let Ok(env) = parse_chunk_envelope(bytes) else {
        return VerifyOutcome::Corrupt;
    };
    if env.vault_id != session.vault_id
        || env.file_version_id != version
        || env.chunk_index != u64::from(chunk.chunk_index)
    {
        return VerifyOutcome::Corrupt;
    }
    match decrypt_chunk(
        dek,
        &ChunkIdentity {
            format_version: env.format_version,
            vault_id: session.vault_id,
            file_version_id: version,
            chunk_index: u64::from(chunk.chunk_index),
        },
        &undercloud_crypto::EncryptedChunk {
            nonce: env.nonce,
            ciphertext: env.ciphertext,
        },
    ) {
        Ok(_) => VerifyOutcome::Verified,
        Err(_) => VerifyOutcome::Corrupt,
    }
}

async fn repair_to_target(
    session: &VaultSession,
    version: Uuid,
    replacement: Uuid,
) -> Result<FileHealth, CoreError> {
    session
        .catalog
        .ensure_version_active(version)
        .await
        .map_err(|_| CoreError::InvalidTransition)?;
    let v = session.catalog.load_file_version(version).await?;
    let reps = session.catalog.list_replicas(version).await?;
    let required_objects = v.chunk_count.saturating_add(1) as usize;
    let mut verified_counts = std::collections::HashMap::<Uuid, usize>::new();
    for replica in reps.iter().filter(|r| r.state == ReplicaState::Verified) {
        *verified_counts
            .entry(replica.storage_target_id)
            .or_default() += 1;
    }
    let source = reps
        .iter()
        .find(|r| {
            r.state == ReplicaState::Verified
                && session.providers.contains_key(&r.storage_target_id)
                && verified_counts
                    .get(&r.storage_target_id)
                    .is_some_and(|count| *count >= required_objects)
        })
        .map(|r| r.storage_target_id)
        .ok_or(CoreError::Unrecoverable)?;
    if source == replacement {
        return Err(CoreError::InvalidTransition);
    }
    let repair_job = session
        .catalog
        .create_repair_job(version, replacement, source)
        .await?;
    session
        .catalog
        .set_repair_job_state(repair_job, "running")
        .await?;
    let outcome = repair_replicas(session, version, source, replacement, &reps).await;
    if outcome.is_err() {
        // Never leave a repair job stuck reporting "running" after its work aborted midway.
        let _ = session
            .catalog
            .set_repair_job_state(repair_job, "failed")
            .await;
    }
    let () = outcome?;
    // Same as health(): count registered targets, not connected ones.
    let target_count = session.storage_target_ids().await?.len();
    let required = required_replicas(v.chunk_count.saturating_add(1), target_count);
    session
        .catalog
        .record_health_observation(version, required, required, HealthState::Healthy)
        .await?;
    session.catalog.mark_file_version_healthy(version).await?;
    session
        .catalog
        .set_repair_job_state(repair_job, "completed")
        .await?;
    session.catalog.bump_recovery_generation().await?;
    Ok(FileHealth::Healthy)
}

const REPAIR_FETCH_CONCURRENCY: usize = 6;
const DELETE_ITEM_CONCURRENCY: usize = 6;

/// Copies every AEAD-authenticated object of `version` from the source target to the replacement target, verifying each copy end-to-end.
async fn repair_replicas(
    session: &VaultSession,
    version: Uuid,
    source: Uuid,
    replacement: Uuid,
    reps: &[undercloud_catalog::ReplicaRecord],
) -> Result<(), CoreError> {
    let src = session
        .providers
        .get(&source)
        .ok_or(CoreError::Unrecoverable)?;
    let target = session
        .providers
        .get(&replacement)
        .ok_or(CoreError::ProviderUnavailable)?;
    // Unwrap the file's keys exactly once, up front — they are the same for every replica of this file version.
    let (wrapped_dek, wrapped_manifest) = session.catalog.load_wrapped_file_keys(version).await?;
    let dek = unwrap_dek(
        &session.subkeys.file_key_wrap,
        session.vault_id,
        version,
        &wrapped_dek,
    )
    .map_err(crypto_err)?;
    let manifest_key = unwrap_manifest_key(
        &session.subkeys.file_key_wrap,
        session.vault_id,
        version,
        &wrapped_manifest,
    )
    .map_err(crypto_err)?;
    let dek_ref = &dek;
    let manifest_key_ref = &manifest_key;
    let candidates = reps
        .iter()
        .filter(|r| r.storage_target_id == source && r.state == ReplicaState::Verified)
        .map(Ok::<_, CoreError>);
    // Each replica's copy is a read-verify-write-readback pipeline dominated by provider round trips, not CPU, so
    // run several replicas' pipelines concurrently instead of paying that latency once per replica in series.
    futures_util::stream::iter(candidates)
        .try_for_each_concurrent(Some(REPAIR_FETCH_CONCURRENCY), |r| async move {
            let loc = ObjectLocator(r.locator.clone());
            let bytes = read(src, &loc).await?;
            if r.object_kind == ObjectKind::Manifest {
                let e = parse_manifest_envelope(&bytes)?;
                if e.vault_id != session.vault_id || e.file_version_id != version {
                    return Err(CoreError::Authentication);
                }
                let _ = decrypt_manifest(
                    manifest_key_ref,
                    &undercloud_crypto::ManifestIdentity {
                        format_version: e.format_version,
                        vault_id: session.vault_id,
                        file_version_id: version,
                    },
                    &undercloud_crypto::EncryptedManifest {
                        nonce: e.nonce,
                        ciphertext: e.ciphertext,
                    },
                )
                .map_err(crypto_err)?;
            } else {
                let e = parse_chunk_envelope(&bytes)?;
                if e.vault_id != session.vault_id || e.file_version_id != version {
                    return Err(CoreError::Authentication);
                }
                let _ = decrypt_chunk(
                    dek_ref,
                    &ChunkIdentity {
                        format_version: e.format_version,
                        vault_id: session.vault_id,
                        file_version_id: version,
                        chunk_index: e.chunk_index,
                    },
                    &undercloud_crypto::EncryptedChunk {
                        nonce: e.nonce,
                        ciphertext: e.ciphertext,
                    },
                )
                .map_err(crypto_err)?;
            }
            let destination_locator = reps
                .iter()
                .find(|existing| {
                    existing.storage_target_id == replacement
                        && existing.chunk_id == r.chunk_id
                        && existing.object_kind == r.object_kind
                })
                .map(|existing| ObjectLocator(existing.locator.clone()))
                .unwrap_or_else(locator);
            let stored_locator = put(target, destination_locator, bytes.clone()).await?;
            // Size-only checks cannot see silent corruption; read the replica back and require it to match, byte for byte, the AEAD-verified bytes just written.
            let stored = read(target, &stored_locator).await?;
            if stored != bytes {
                return Err(CoreError::Authentication);
            }
            let rep = session
                .catalog
                .create_replica(
                    version,
                    r.chunk_id,
                    replacement,
                    r.object_kind,
                    &stored_locator.0,
                )
                .await?;
            session
                .catalog
                .update_replica_locator(rep, &stored_locator.0)
                .await?;
            session
                .catalog
                .set_replica_state(rep, ReplicaState::Verified)
                .await?;
            Ok(())
        })
        .await?;
    if session.roots.contains_key(&replacement) {
        let known = session
            .catalog
            .list_storage_target_locators(replacement)
            .await?
            .into_iter()
            .collect::<std::collections::HashSet<_>>();
        let page = target.list_objects(None).await?;
        for object in page.locators {
            let looks_like_undercloud_object =
                object.0.len() == 32 && object.0.chars().all(|c| c.is_ascii_hexdigit());
            if looks_like_undercloud_object && !known.contains(&object.0) {
                let _ = target.delete_object(&object).await;
            }
        }
    }
    Ok(())
}

pub fn vault_status<T: VaultStatusSource>(value: &T) -> VaultStatus {
    value.vault_status()
}
