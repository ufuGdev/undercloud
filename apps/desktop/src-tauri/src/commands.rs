use crate::observability;
use crate::vault_library::{self, LibraryInfo};
use serde::Serialize;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use tauri::{AppHandle, Manager, State};
use tokio::sync::Mutex;
use undercloud_core::{
    CancellationToken, CoreError, FileHealth, FileSummary, LockedVault, NewActivityEvent,
    ProviderError, ProviderSummary, TrashFileSummary, UndercloudCore, VaultSession,
};
use undercloud_provider_cloud::{CloudProviderKind, OAuthCancellation};
use uuid::Uuid;

fn activity_now() -> String {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .to_string()
}

fn command_span(command: &'static str, operation_id: &str) -> tracing::Span {
    tracing::info_span!("tauri_command", subsystem = "tauri", command_name = command, operation_id = %operation_id, stage = "entry")
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultInitializationEvent {
    pub stage: String,
    pub detail: String,
    pub operation_id: String,
    pub provider_index: Option<usize>,
    pub provider_total: Option<usize>,
    pub error: Option<String>,
}

fn emit_initialization(
    app: &AppHandle,
    operation_id: &str,
    stage: &str,
    detail: &str,
    error: Option<String>,
) {
    let _ = tauri::Emitter::emit(
        app,
        "vault-initialization",
        VaultInitializationEvent {
            stage: stage.to_owned(),
            detail: detail.to_owned(),
            operation_id: operation_id.to_owned(),
            provider_index: None,
            provider_total: None,
            error,
        },
    );
}

fn library_paths(app: &AppHandle) -> Result<(PathBuf, PathBuf), CommandError> {
    let config = app.path().app_config_dir().map_err(|_| CommandError {
        code: "vault_library_unavailable",
        detail: None,
    })?;
    let data = app.path().app_data_dir().map_err(|_| CommandError {
        code: "vault_library_unavailable",
        detail: None,
    })?;
    Ok((config, data))
}

fn library_info(app: &AppHandle) -> Result<LibraryInfo, CommandError> {
    let (config, data) = library_paths(app)?;
    let root = vault_library::load_root(&config, &data).map_err(|_| CommandError {
        code: "vault_library_unavailable",
        detail: None,
    })?;
    Ok(LibraryInfo {
        root: root.to_string_lossy().into_owned(),
        vaults: vault_library::discover(&root),
    })
}

#[tauri::command]
pub fn vault_library_info(
    app: AppHandle,
    operation_id: String,
) -> Result<LibraryInfo, CommandError> {
    let _span = command_span("vault_library_info", &operation_id);
    library_info(&app)
}

#[tauri::command]
pub fn set_vault_library_location(
    app: AppHandle,
    root: String,
    operation_id: String,
) -> Result<LibraryInfo, CommandError> {
    let _span = command_span("set_vault_library_location", &operation_id);
    let candidate = vault_library::validate_root(Path::new(&root))
        .map_err(|code| CommandError { code, detail: None })?;
    let probe = candidate.join(format!(".undercloud-write-{}", Uuid::new_v4()));
    std::fs::write(&probe, b"undercloud").map_err(|_| CommandError {
        code: "vault_library_not_writable",
        detail: None,
    })?;
    std::fs::remove_file(&probe).map_err(|_| CommandError {
        code: "vault_library_not_writable",
        detail: None,
    })?;
    let (config, _) = library_paths(&app)?;
    vault_library::save_root(&config, &candidate).map_err(|_| CommandError {
        code: "vault_library_unavailable",
        detail: None,
    })?;
    library_info(&app)
}

#[tauri::command]
pub fn reset_vault_library_location(
    app: AppHandle,
    operation_id: String,
) -> Result<LibraryInfo, CommandError> {
    let _span = command_span("reset_vault_library_location", &operation_id);
    let (config, _) = library_paths(&app)?;
    let preference = vault_library::preference_path(&config);
    match std::fs::remove_file(preference) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => {
            return Err(CommandError {
                code: "vault_library_unavailable",
                detail: None,
            })
        }
    }
    library_info(&app)
}

#[tauri::command]
pub fn open_vault_library_folder(app: AppHandle, operation_id: String) -> Result<(), CommandError> {
    let _span = command_span("open_vault_library_folder", &operation_id);
    let info = library_info(&app)?;
    std::fs::create_dir_all(&info.root).map_err(|_| CommandError {
        code: "vault_library_open_failed",
        detail: None,
    })?;
    tauri_plugin_opener::OpenerExt::opener(&app)
        .open_path(info.root, None::<&str>)
        .map_err(|_| CommandError {
            code: "vault_library_open_failed",
            detail: None,
        })
}

#[tauri::command]
pub fn rename_vault(
    app: AppHandle,
    catalog_path: String,
    name: String,
    operation_id: String,
) -> Result<LibraryInfo, CommandError> {
    let _span = command_span("rename_vault", &operation_id);
    let name = name.trim();
    if name.is_empty() || name.len() > 80 || name.contains(['\n', '\r']) {
        return Err(CommandError {
            code: "invalid_vault_name",
            detail: None,
        });
    }
    let (config, data) = library_paths(&app)?;
    let root = vault_library::load_root(&config, &data)
        .map_err(|_| CommandError {
            code: "vault_library_unavailable",
            detail: None,
        })?
        .canonicalize()
        .map_err(|_| CommandError {
            code: "vault_library_unavailable",
            detail: None,
        })?;
    let catalog = PathBuf::from(catalog_path)
        .canonicalize()
        .map_err(|_| CommandError {
            code: "vault_not_found",
            detail: None,
        })?;
    let parent = catalog.parent().ok_or(CommandError {
        code: "invalid_vault_path",
        detail: None,
    })?;
    let relative = parent.strip_prefix(&root).map_err(|_| CommandError {
        code: "invalid_vault_path",
        detail: None,
    })?;
    if relative.components().count() != 1
        || catalog.file_name() != Some(std::ffi::OsStr::new("vault.sqlite3"))
        || relative
            .to_str()
            .and_then(|value| Uuid::parse_str(value).ok())
            .is_none()
    {
        return Err(CommandError {
            code: "invalid_vault_path",
            detail: None,
        });
    }
    let metadata = parent.join("vault-name");
    let temp = parent.join(format!(".vault-name-{}", Uuid::new_v4()));
    std::fs::write(&temp, name).map_err(|_| CommandError {
        code: "vault_name_write_failed",
        detail: None,
    })?;
    std::fs::rename(temp, metadata).map_err(|_| CommandError {
        code: "vault_name_write_failed",
        detail: None,
    })?;
    library_info(&app)
}

#[tauri::command]
pub async fn move_vault_to_library(
    app: AppHandle,
    state: State<'_, AppState>,
    source_path: String,
    operation_id: String,
) -> Result<String, CommandError> {
    let _span = command_span("move_vault_to_library", &operation_id);
    begin_exclusive(&state)?;
    let source = PathBuf::from(&source_path);
    let result = async {
        if !source.is_file() {
            return Err(CommandError {
                code: "vault_not_found",
                detail: None,
            });
        }
        let (config, data) = library_paths(&app)?;
        let root = vault_library::load_root(&config, &data).map_err(|_| CommandError {
            code: "vault_library_unavailable",
            detail: None,
        })?;
        std::fs::create_dir_all(&root).map_err(|_| CommandError {
            code: "vault_library_unavailable",
            detail: None,
        })?;
        let mut vault = state.vault.lock().await;
        let current = vault.take().ok_or(CommandError {
            code: "locked",
            detail: None,
        })?;
        let locked = match current {
            VaultState::Locked(value) => value,
            other => {
                *vault = Some(other);
                return Err(CommandError {
                    code: "vault_must_be_locked",
                    detail: None,
                });
            }
        };
        let vault_id = locked.vault_id().await.map_err(command_error)?;
        drop(locked);
        drop(vault);
        let final_dir = root.join(vault_id.to_string());
        if final_dir.exists() {
            return Err(CommandError {
                code: "vault_already_exists",
                detail: None,
            });
        }
        let staging_dir = root.join(format!(".moving-{}", Uuid::new_v4()));
        std::fs::create_dir(&staging_dir).map_err(|_| CommandError {
            code: "vault_library_unavailable",
            detail: None,
        })?;
        let target = staging_dir.join("vault.sqlite3");
        if let Err(error) = std::fs::copy(&source, &target) {
            let _ = std::fs::remove_dir_all(&staging_dir);
            return Err(CommandError {
                code: if error.kind() == std::io::ErrorKind::PermissionDenied {
                    "vault_library_not_writable"
                } else {
                    "vault_library_unavailable"
                },
                detail: None,
            });
        }
        for suffix in ["-wal", "-shm"] {
            let sidecar = PathBuf::from(format!("{}{}", source.display(), suffix));
            if sidecar.is_file() {
                std::fs::copy(
                    &sidecar,
                    staging_dir.join(format!("vault.sqlite3{}", suffix)),
                )
                .map_err(|_| CommandError {
                    code: "vault_library_unavailable",
                    detail: None,
                })?;
            }
        }
        let staging_core = UndercloudCore::new(&target);
        let staging_locked = staging_core.open_vault().await.map_err(command_error)?;
        drop(staging_locked);
        std::fs::rename(&staging_dir, &final_dir).map_err(|_| CommandError {
            code: "vault_library_unavailable",
            detail: None,
        })?;
        let name = source
            .file_stem()
            .and_then(|value| value.to_str())
            .filter(|value| !value.trim().is_empty())
            .unwrap_or("Personal vault");
        let _ = std::fs::write(final_dir.join("vault-name"), name);
        let new_path = final_dir.join("vault.sqlite3");
        let new_core = UndercloudCore::new(&new_path);
        let new_locked = new_core.open_vault().await.map_err(command_error)?;
        *state.core.lock().await = new_core;
        *state.vault.lock().await = Some(VaultState::Locked(new_locked));
        for suffix in ["", "-wal", "-shm"] {
            let path = if suffix.is_empty() {
                source.clone()
            } else {
                PathBuf::from(format!("{}{}", source.display(), suffix))
            };
            if path.is_file() {
                let _ = std::fs::remove_file(path);
            }
        }
        Ok(new_path.to_string_lossy().into_owned())
    }
    .await;
    end_exclusive(&state);
    result
}

#[derive(Debug, serde::Serialize)]
pub struct PickerResult {
    pub path: Option<String>,
}

#[tauri::command]
pub async fn pick_file(save: bool, operation_id: String) -> Result<PickerResult, CommandError> {
    let _span = command_span("pick_file", &operation_id);
    let result = tokio::task::spawn_blocking(move || {
        let dialog = rfd::FileDialog::new();
        if save {
            dialog.save_file()
        } else {
            dialog.pick_file()
        }
    })
    .await
    .map_err(|_| CommandError {
        code: "dialog_unavailable",
        detail: None,
    })?;
    Ok(PickerResult {
        path: result.map(|p| p.to_string_lossy().into_owned()),
    })
}

#[tauri::command]
pub async fn pick_folder(operation_id: String) -> Result<PickerResult, CommandError> {
    let _span = command_span("pick_folder", &operation_id);
    let result = tokio::task::spawn_blocking(|| rfd::FileDialog::new().pick_folder())
        .await
        .map_err(|_| CommandError {
            code: "dialog_unavailable",
            detail: None,
        })?;
    Ok(PickerResult {
        path: result.map(|p| p.to_string_lossy().into_owned()),
    })
}

#[derive(Debug)]
pub struct CommandError {
    pub code: &'static str,
    pub detail: Option<String>,
}

impl serde::Serialize for CommandError {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut out = serializer.serialize_struct("CommandError", 4)?;
        out.serialize_field("code", self.code)?;
        out.serialize_field("message", safe_command_message(self.code))?;
        let incident_id = self
            .detail
            .as_deref()
            .and_then(|value| value.strip_prefix("incident_id:"))
            .unwrap_or("generated");
        let incident_id = if incident_id == "generated" {
            Uuid::new_v4().to_string()
        } else {
            incident_id.to_owned()
        };
        out.serialize_field("incident_id", &incident_id)?;
        out.serialize_field(
            "retryable",
            &matches!(
                self.code,
                "provider_unavailable"
                    | "provider_temporarily_unavailable"
                    | "io_error"
                    | "provider_error"
            ),
        )?;
        out.end()
    }
}

fn safe_command_message(code: &str) -> &'static str {
    match code {
        "authentication_failed" => "The password was not accepted.",
        "locked" => "Unlock the vault to continue.",
        "provider_unavailable" => "A storage provider is unavailable.",
        "credential_store_unavailable" => "The system credential store is unavailable.",
        _ => "Undercloud could not complete that operation.",
    }
}

fn command_error(error: CoreError) -> CommandError {
    let code = match error {
        CoreError::Locked => "locked",
        CoreError::Authentication => "authentication_failed",
        CoreError::DestinationExists | CoreError::RecoveryDestinationExists => "destination_exists",
        CoreError::ProviderUnavailable => "provider_unavailable",
        CoreError::ProviderHealthCheck(_) => "provider_health_check_failed",
        CoreError::OAuthTokenExchangeRejected { kind, .. } => match kind {
            undercloud_provider_cloud::TokenExchangeKind::InvalidGrant => "oauth_invalid_grant",
            undercloud_provider_cloud::TokenExchangeKind::InvalidClient => "oauth_invalid_client",
            undercloud_provider_cloud::TokenExchangeKind::UnauthorizedClient => {
                "oauth_unauthorized_client"
            }
            undercloud_provider_cloud::TokenExchangeKind::InvalidRequest => "oauth_invalid_request",
            undercloud_provider_cloud::TokenExchangeKind::RedirectUri => {
                "oauth_redirect_uri_mismatch"
            }
            undercloud_provider_cloud::TokenExchangeKind::Pkce => "oauth_pkce_rejected",
            undercloud_provider_cloud::TokenExchangeKind::AuthorizationCode => {
                "oauth_code_rejected"
            }
            undercloud_provider_cloud::TokenExchangeKind::ClientId => "oauth_client_id_rejected",
            undercloud_provider_cloud::TokenExchangeKind::Policy => "oauth_policy_blocked",
            undercloud_provider_cloud::TokenExchangeKind::Other => "oauth_rejected",
        },
        CoreError::OAuthTokenResponseInvalid => "oauth_response_invalid",
        CoreError::OAuthTokenEndpointUnavailable => "oauth_endpoint_unreachable",
        CoreError::DuplicateProvider => "duplicate_provider",
        CoreError::Unrecoverable => "unrecoverable",
        CoreError::UnsupportedRecoveryVersion => "unsupported_recovery_version",
        CoreError::StaleRecoverySnapshot => "stale_recovery_snapshot",
        CoreError::InvalidRecoveryKit => "invalid_recovery_kit",
        CoreError::InvalidTransition => "invalid_transition",
        CoreError::Cancelled => "cancelled",
        CoreError::Catalog(_) => "catalog_error",
        CoreError::Format(_) => "format_error",
        CoreError::Chunking(_) => "chunking_error",
        CoreError::Provider(ProviderError::AuthenticationRequired) => {
            "provider_authentication_required"
        }
        CoreError::Provider(ProviderError::PermissionDenied) => "provider_permission_denied",
        CoreError::Provider(ProviderError::TemporarilyUnavailable) => {
            "provider_temporarily_unavailable"
        }
        CoreError::Provider(ProviderError::RequestRejected { .. }) => "provider_request_rejected",
        CoreError::Provider(ProviderError::ObjectMissing) => "provider_object_missing",
        CoreError::Provider(ProviderError::IntegrityMismatch) => "provider_integrity_mismatch",
        CoreError::Provider(ProviderError::InvalidLocator) => "provider_invalid_locator",
        CoreError::Provider(ProviderError::Io(_)) => "provider_io_error",
        CoreError::Provider(_) => "provider_error",
        CoreError::Io(_) => "io_error",
        CoreError::CredentialStore => "credential_store_unavailable",
        CoreError::InvalidProviderConfiguration => "invalid_provider_configuration",
        CoreError::ProviderNotConfigured => "provider_not_configured",
        CoreError::VaultNotFound => "vault_not_found",
    };
    let incident_id = Uuid::new_v4();
    match code {
        "authentication_failed"
        | "locked"
        | "destination_exists"
        | "duplicate_provider"
        | "invalid_transition"
        | "unsupported_recovery_version"
        | "stale_recovery_snapshot"
        | "invalid_recovery_kit"
        | "cancelled"
        | "provider_authentication_required"
        | "provider_permission_denied" => {
            tracing::warn!(target: "undercloud.command", subsystem="tauri", operation="command", incident_id=%incident_id, stage="complete", outcome="rejected", error_code=code)
        }
        _ => {
            tracing::error!(target: "undercloud.command", subsystem="tauri", operation="command", incident_id=%incident_id, stage="complete", outcome="failure", error_code=code)
        }
    }
    CommandError {
        code,
        detail: Some(format!("incident_id:{incident_id}")),
    }
}

#[tauri::command]
pub fn page_view(page: String, operation_id: String) {
    let _span = command_span("page_view", &operation_id);
    tracing::info!(target: "undercloud.navigation", subsystem="ui", operation="page_view", operation_id=%operation_id, page=%page, stage="entered", outcome="complete", "Page opened");
}

#[tauri::command]
pub fn logging_status(app: AppHandle, operation_id: String) -> observability::LoggingStatus {
    let _span = command_span("logging_status", &operation_id);
    observability::status(&app)
}

#[tauri::command]
pub fn open_log_folder(app: AppHandle, operation_id: String) -> Result<(), CommandError> {
    let _span = command_span("open_log_folder", &operation_id);
    tauri_plugin_opener::OpenerExt::opener(&app)
        .open_path(
            observability::log_directory(&app).display().to_string(),
            None::<&str>,
        )
        .map_err(|_| CommandError {
            code: "logs_open_failed",
            detail: None,
        })
}

#[derive(Debug, Serialize)]
pub struct Status {
    pub state: &'static str,
    pub vault_id: Option<String>,
}
#[derive(Debug, Serialize)]
pub struct FileDto {
    pub logical_file_id: String,
    pub name: String,
    pub mime: Option<String>,
    pub file_version_id: Option<String>,
    pub size_bytes: Option<u64>,
    pub health: Option<&'static str>,
    pub health_current: bool,
    pub verified_copies: u32,
    pub required_copies: u32,
    pub last_verified_at: Option<String>,
}
#[derive(Debug, Serialize)]
pub struct ProviderDto {
    pub id: String,
    pub kind: String,
    pub connected: bool,
    pub health: &'static str,
    pub used_bytes: Option<u64>,
    pub total_bytes: Option<u64>,
    pub quota_known: bool,
    pub display_name: String,
}

#[derive(Debug, Serialize)]
pub struct RecoveryFreshnessDto {
    pub generation: u64,
    pub exported_generation: Option<u64>,
    pub exported_at: Option<String>,
    pub state: String,
}

#[tauri::command]
pub async fn recovery_freshness(
    state: State<'_, AppState>,
    operation_id: String,
) -> Result<RecoveryFreshnessDto, CommandError> {
    let _span = command_span("recovery_freshness", &operation_id);
    let session = begin_session(&state).await?;
    let result = session
        .recovery_freshness()
        .await
        .map(|value| RecoveryFreshnessDto {
            state: match value.exported_generation {
                None => "never_created",
                Some(exported) if exported == value.generation => "current",
                Some(_) => "outdated",
            }
            .into(),
            generation: value.generation,
            exported_generation: value.exported_generation,
            exported_at: value.exported_at,
        })
        .map_err(command_error);
    end_session(&state, session).await;
    result
}

#[derive(Debug, Serialize)]
pub struct ActivityDto {
    pub id: String,
    pub operation_id: String,
    pub event_type: String,
    pub status: String,
    pub related_file_id: Option<String>,
    pub related_target_id: Option<String>,
    pub display_metadata: String,
    pub started_at: String,
    pub completed_at: Option<String>,
    pub transferred_bytes: Option<u64>,
    pub error_code: Option<String>,
    pub retry_classification: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CloudProviderInput {
    pub kind: String,
}

fn cloud_kind(value: &str) -> Result<CloudProviderKind, CommandError> {
    match value {
        "google_drive" => Ok(CloudProviderKind::GoogleDrive),
        "onedrive" => Ok(CloudProviderKind::OneDrive),
        "dropbox" => Ok(CloudProviderKind::Dropbox),
        _ => Err(CommandError {
            code: "invalid_provider_configuration",
            detail: None,
        }),
    }
}

#[tauri::command]
pub async fn add_local_provider(
    state: State<'_, AppState>,
    root: String,
    operation_id: String,
) -> Result<String, CommandError> {
    let _span = command_span("add_local_provider", &operation_id);
    let mut session = begin_session(&state).await?;
    let result = session
        .add_local_provider(root)
        .await
        .map_err(command_error);
    end_session(&state, session).await;
    result.map(|id| id.to_string())
}

#[tauri::command]
pub async fn remove_provider(
    state: State<'_, AppState>,
    target: String,
    operation_id: String,
) -> Result<(), CommandError> {
    let _span = command_span("remove_provider", &operation_id);
    let id = parse_id(&target)?;
    let mut session = begin_session(&state).await?;
    let kind = session
        .provider_summaries()
        .await
        .map_err(command_error)?
        .into_iter()
        .find(|provider| provider.id == id)
        .map(|provider| provider.kind);
    let result = match kind.as_deref() {
        Some("google_drive") | Some("onedrive") | Some("dropbox") => {
            session.remove_cloud_provider(id, false).await
        }
        Some(_) => session.remove_local_provider(id).await,
        None => Err(undercloud_core::CoreError::InvalidProviderConfiguration),
    };
    end_session(&state, session).await;
    result.map_err(command_error)
}
#[derive(Debug, Clone, Serialize)]
pub struct ProgressDto {
    pub bytes_processed: u64,
    pub total_bytes: Option<u64>,
}

#[derive(Clone)]
struct DeletionChallenge {
    vault_id: Uuid,
    file_id: Uuid,
    mode: String,
    expected_confirmation: String,
    state: String,
    current_version_id: Option<Uuid>,
    purge_after: Option<String>,
    expires_at: std::time::Instant,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FileDeletionChallengeDto {
    pub challenge_id: String,
    pub file_id: String,
    pub mode: String,
    pub display_name: String,
    pub state: String,
    pub current_version_id: Option<String>,
    pub expected_confirmation: String,
    pub expires_at_unix_ms: u128,
    pub operation_id: String,
    pub replica_count: u32,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TrashFileDto {
    pub file: FileDto,
    pub deletion_id: String,
    pub state: String,
    pub purge_after: Option<String>,
    pub retry_classification: Option<String>,
    pub replica_count: u32,
}

enum VaultState {
    Locked(LockedVault),
    Unlocked(Box<VaultSession>),
}
pub struct AppState {
    core: Mutex<UndercloudCore>,
    vault: Mutex<Option<VaultState>>,
    restore_cancel: Mutex<Option<CancellationToken>>,
    upload_cancel: Mutex<Option<CancellationToken>>,
    oauth_cancel: Mutex<Option<OAuthCancellation>>,
    active_vault_id: Mutex<Option<Uuid>>,
    deletion_challenges: Mutex<HashMap<Uuid, DeletionChallenge>>,
    completed_deletions: Mutex<HashMap<Uuid, bool>>,
    operation_active: AtomicBool,
}
impl Default for AppState {
    fn default() -> Self {
        Self {
            core: Mutex::new(UndercloudCore::new("vault.sqlite")),
            vault: Mutex::new(None),
            restore_cancel: Mutex::new(None),
            upload_cancel: Mutex::new(None),
            oauth_cancel: Mutex::new(None),
            active_vault_id: Mutex::new(None),
            deletion_challenges: Mutex::new(HashMap::new()),
            completed_deletions: Mutex::new(HashMap::new()),
            operation_active: AtomicBool::new(false),
        }
    }
}

async fn begin_session(state: &AppState) -> Result<VaultSession, CommandError> {
    state
        .operation_active
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .map_err(|_| CommandError {
            code: "operation_in_progress",
            detail: None,
        })?;
    let mut vault = state.vault.lock().await;
    let result = match vault.take() {
        Some(VaultState::Unlocked(session)) => Ok(*session),
        Some(other) => {
            *vault = Some(other);
            state.operation_active.store(false, Ordering::Release);
            Err(CommandError {
                code: "locked",
                detail: None,
            })
        }
        None => {
            state.operation_active.store(false, Ordering::Release);
            Err(CommandError {
                code: "locked",
                detail: None,
            })
        }
    };
    drop(vault);
    if let Ok(session) = &result {
        *state.active_vault_id.lock().await = Some(session.vault_id());
    }
    result
}

async fn end_session(state: &AppState, session: VaultSession) {
    let mut vault = state.vault.lock().await;
    *vault = Some(VaultState::Unlocked(Box::new(session)));
    state.operation_active.store(false, Ordering::Release);
}

fn begin_exclusive(state: &AppState) -> Result<(), CommandError> {
    state
        .operation_active
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .map(|_| ())
        .map_err(|_| CommandError {
            code: "operation_in_progress",
            detail: None,
        })
}

fn end_exclusive(state: &AppState) {
    state.operation_active.store(false, Ordering::Release);
}

struct ExclusiveGuard<'a>(&'a AppState);

impl<'a> ExclusiveGuard<'a> {
    fn acquire(state: &'a AppState) -> Result<Self, CommandError> {
        begin_exclusive(state)?;
        Ok(Self(state))
    }
}

impl Drop for ExclusiveGuard<'_> {
    fn drop(&mut self) {
        end_exclusive(self.0);
    }
}

fn cancel_displaced_session(vault: &mut Option<VaultState>) {
    if let Some(VaultState::Unlocked(displaced)) = vault.take() {
        displaced.cancel_background_work();
    }
}

fn health_name(health: FileHealth) -> &'static str {
    match health {
        FileHealth::Healthy => "healthy",
        FileHealth::Degraded => "degraded",
        FileHealth::AtRisk => "at_risk",
        FileHealth::Unrecoverable => "unrecoverable",
        FileHealth::ProviderUnavailable => "provider_unavailable",
        FileHealth::HealthCheckTimedOut => "health_check_timeout",
    }
}
fn status_of(vault: Option<&VaultState>) -> Status {
    match vault {
        Some(VaultState::Unlocked(session)) => Status {
            state: "unlocked",
            vault_id: Some(session.vault_id().to_string()),
        },
        Some(VaultState::Locked(_)) | None => Status {
            state: "locked",
            vault_id: None,
        },
    }
}
async fn current_status(state: &AppState) -> Status {
    let vault = state.vault.lock().await;
    if let Some(status) = vault.as_ref().map(|value| status_of(Some(value))) {
        return status;
    }
    drop(vault);
    let active = *state.active_vault_id.lock().await;
    Status {
        state: if active.is_some() {
            "unlocked"
        } else {
            "locked"
        },
        vault_id: active.map(|id| id.to_string()),
    }
}
fn parse_id(value: &str) -> Result<Uuid, CommandError> {
    Uuid::parse_str(value).map_err(|_| CommandError {
        code: "invalid_id",
        detail: None,
    })
}

// file_name comes from the user-controlled catalog logical name, so reject traversal/absolute values (e.g. "../../evil.sh") before joining onto a destination directory.
fn validate_restore_file_name(file_name: &str) -> Result<(), CommandError> {
    let mut components = Path::new(file_name).components();
    match (components.next(), components.next()) {
        (Some(std::path::Component::Normal(_)), None) => Ok(()),
        _ => Err(CommandError {
            code: "invalid_file_name",
            detail: None,
        }),
    }
}

#[tauri::command]
pub async fn create_vault(
    app: AppHandle,
    state: State<'_, AppState>,
    catalog_path: String,
    password: String,
    name: String,
    operation_id: String,
) -> Result<Status, CommandError> {
    let _span = command_span("create_vault", &operation_id);
    let name = name.trim();
    if name.is_empty() || name.len() > 80 || name.contains(['\n', '\r']) {
        return Err(CommandError {
            code: "invalid_vault_name",
            detail: None,
        });
    }
    let _exclusive = ExclusiveGuard::acquire(&state)?;
    let (catalog, staging) = if catalog_path.trim().is_empty() {
        let (_, data) = library_paths(&app)?;
        let root =
            vault_library::load_root(&library_paths(&app)?.0, &data).map_err(|_| CommandError {
                code: "vault_library_unavailable",
                detail: None,
            })?;
        if root.exists() {
            vault_library::validate_root(&root)
                .map_err(|code| CommandError { code, detail: None })?;
        }
        std::fs::create_dir_all(&root).map_err(|_| CommandError {
            code: "vault_library_unavailable",
            detail: None,
        })?;
        let staging_dir = root.join(format!(".creating-{}", Uuid::new_v4()));
        std::fs::create_dir(&staging_dir).map_err(|_| CommandError {
            code: "vault_library_unavailable",
            detail: None,
        })?;
        (staging_dir.join("vault.sqlite3"), Some(staging_dir))
    } else {
        (PathBuf::from(&catalog_path), None)
    };
    let core = UndercloudCore::new(catalog);
    let result = core.create_vault(&password).await.map_err(command_error);
    let session = match result {
        Ok(session) => session,
        Err(error) => {
            end_exclusive(&state);
            return Err(error);
        }
    };
    let (core, session) = if let Some(staging_dir) = staging {
        let vault_id = session.vault_id();
        let root = staging_dir
            .parent()
            .expect("staging directory has a parent");
        let final_dir = root.join(vault_id.to_string());
        drop(session);
        if let Err(error) = std::fs::rename(&staging_dir, &final_dir) {
            end_exclusive(&state);
            return Err(CommandError {
                code: if error.kind() == std::io::ErrorKind::AlreadyExists {
                    "vault_already_exists"
                } else {
                    "vault_library_unavailable"
                },
                detail: None,
            });
        }
        let _ = std::fs::write(final_dir.join("vault-name"), name);
        let final_core = UndercloudCore::new(final_dir.join("vault.sqlite3"));
        let locked = final_core.open_vault().await.map_err(command_error)?;
        let final_session = locked.unlock(&password).await.map_err(command_error)?;
        (final_core, final_session)
    } else {
        if let Some(parent) = PathBuf::from(&catalog_path).parent() {
            let _ = std::fs::write(parent.join("vault-name"), name);
        }
        (core, session)
    };
    *state.core.lock().await = core;
    let mut vault = state.vault.lock().await;
    cancel_displaced_session(&mut vault);
    *vault = Some(VaultState::Unlocked(Box::new(session)));
    let status = status_of(vault.as_ref());
    drop(vault);
    *state.active_vault_id.lock().await = status
        .vault_id
        .as_deref()
        .and_then(|id| Uuid::parse_str(id).ok());
    if let Some(VaultState::Unlocked(session)) = state.vault.lock().await.as_ref() {
        session.spawn_deletion_reconciliation();
    }
    end_exclusive(&state);
    Ok(status)
}

#[tauri::command]
pub async fn open_vault(
    state: State<'_, AppState>,
    catalog_path: String,
    operation_id: String,
) -> Result<Status, CommandError> {
    let _span = command_span("open_vault", &operation_id);
    begin_exclusive(&state)?;
    let core = UndercloudCore::new(PathBuf::from(&catalog_path));
    let locked = match core.open_vault().await.map_err(command_error) {
        Ok(locked) => locked,
        Err(error) => {
            end_exclusive(&state);
            return Err(error);
        }
    };
    *state.core.lock().await = core;
    let mut vault = state.vault.lock().await;
    cancel_displaced_session(&mut vault);
    *vault = Some(VaultState::Locked(locked));
    let status = status_of(vault.as_ref());
    drop(vault);
    *state.active_vault_id.lock().await = None;
    end_exclusive(&state);
    Ok(status)
}

#[tauri::command]
pub async fn unlock_vault(
    app: AppHandle,
    state: State<'_, AppState>,
    password: String,
    operation_id: String,
) -> Result<Status, CommandError> {
    let _span = command_span("unlock_vault", &operation_id);
    emit_initialization(
        &app,
        &operation_id,
        "opening_catalog",
        "Opening encrypted catalog",
        None,
    );
    begin_exclusive(&state)?;
    let current = {
        let mut vault = state.vault.lock().await;
        vault.take()
    };
    let Some(current) = current else {
        end_exclusive(&state);
        return Err(CommandError {
            code: "not_locked",
            detail: None,
        });
    };
    let VaultState::Locked(locked) = current else {
        let mut vault = state.vault.lock().await;
        *vault = Some(current);
        end_exclusive(&state);
        return Err(CommandError {
            code: "not_locked",
            detail: None,
        });
    };
    emit_initialization(
        &app,
        &operation_id,
        "reconnecting_accounts",
        "Reconnecting storage accounts",
        None,
    );
    let unlock_result =
        match tokio::time::timeout(std::time::Duration::from_secs(30), locked.unlock(&password))
            .await
        {
            Err(_) => {
                let mut vault = state.vault.lock().await;
                *vault = Some(VaultState::Locked(locked));
                emit_initialization(
                    &app,
                    &operation_id,
                    "failed",
                    "Vault initialization timed out",
                    Some("provider_timeout".to_owned()),
                );
                end_exclusive(&state);
                return Err(CommandError {
                    code: "provider_timeout",
                    detail: None,
                });
            }
            Ok(result) => result,
        };
    let session = match unlock_result {
        Ok(session) => session,
        Err(error) => {
            let mut vault = state.vault.lock().await;
            *vault = Some(VaultState::Locked(locked));
            emit_initialization(
                &app,
                &operation_id,
                "failed",
                "Vault initialization could not finish",
                Some("initialization_failed".to_owned()),
            );
            end_exclusive(&state);
            return Err(command_error(error));
        }
    };
    emit_initialization(
        &app,
        &operation_id,
        "loading_metadata",
        "Loading files and metadata",
        None,
    );
    emit_initialization(
        &app,
        &operation_id,
        "checking_health",
        "Checking storage health",
        None,
    );
    let mut vault = state.vault.lock().await;
    *vault = Some(VaultState::Unlocked(Box::new(session)));
    let status = status_of(vault.as_ref());
    drop(vault);
    *state.active_vault_id.lock().await = status
        .vault_id
        .as_deref()
        .and_then(|id| Uuid::parse_str(id).ok());
    if let Some(VaultState::Unlocked(session)) = state.vault.lock().await.as_ref() {
        session.spawn_deletion_reconciliation();
    }
    end_exclusive(&state);
    emit_initialization(&app, &operation_id, "ready", "Vault ready", None);
    Ok(status)
}

#[tauri::command]
pub async fn lock_vault(
    state: State<'_, AppState>,
    operation_id: String,
) -> Result<Status, CommandError> {
    let _span = command_span("lock_vault", &operation_id);
    state.deletion_challenges.lock().await.clear();
    state.completed_deletions.lock().await.clear();
    begin_exclusive(&state)?;
    let current = {
        let mut vault = state.vault.lock().await;
        vault.take()
    };
    let Some(current) = current else {
        end_exclusive(&state);
        return Ok(current_status(&state).await);
    };
    let VaultState::Unlocked(session) = current else {
        let mut vault = state.vault.lock().await;
        *vault = Some(current);
        end_exclusive(&state);
        return Ok(current_status(&state).await);
    };
    let core = { state.core.lock().await.clone() };
    let locked = match core.open_vault().await.map_err(command_error) {
        Ok(locked) => locked,
        Err(error) => {
            let mut vault = state.vault.lock().await;
            *vault = Some(VaultState::Unlocked(session));
            end_exclusive(&state);
            return Err(error);
        }
    };
    let mut vault = state.vault.lock().await;
    *vault = Some(VaultState::Locked(locked));
    drop(vault);
    *state.active_vault_id.lock().await = None;
    session.cancel_background_work();
    drop(session);
    end_exclusive(&state);
    Ok(current_status(&state).await)
}

#[tauri::command]
pub async fn vault_status(
    state: State<'_, AppState>,
    operation_id: String,
) -> Result<Status, CommandError> {
    let _span = command_span("vault_status", &operation_id);
    Ok(current_status(&state).await)
}

#[tauri::command]
pub async fn authorize_cloud_provider(
    state: State<'_, AppState>,
    input: CloudProviderInput,
    operation_id: String,
) -> Result<String, CommandError> {
    let _span = command_span("authorize_cloud_provider", &operation_id);
    let kind = cloud_kind(&input.kind)?;
    let mut session = begin_session(&state).await?;
    let started_at = activity_now();
    let _ = session
        .record_activity(NewActivityEvent {
            operation_id: operation_id.clone(),
            event_type: "provider_connect".into(),
            status: "started".into(),
            related_file_id: None,
            related_target_id: None,
            display_metadata: kind.as_str().into(),
            started_at: started_at.clone(),
            completed_at: None,
            transferred_bytes: None,
            error_code: None,
            retry_classification: None,
        })
        .await;
    let cancel = OAuthCancellation::new();
    *state.oauth_cancel.lock().await = Some(cancel.clone());
    let result = async {
        let token = session
            .authorize_cloud_provider(kind, &cancel)
            .await
            .map_err(command_error)?;
        let config = session
            .official_cloud_provider_config(kind, undercloud_credentials::new_oauth_reference())
            .map_err(command_error)?;
        session
            .add_cloud_provider(config, token)
            .await
            .map_err(command_error)
    }
    .await;
    let _ = session
        .record_activity(NewActivityEvent {
            operation_id: operation_id.clone(),
            event_type: "provider_connect".into(),
            status: if result.is_ok() {
                "completed"
            } else {
                "failed"
            }
            .into(),
            related_file_id: None,
            related_target_id: None,
            display_metadata: kind.as_str().into(),
            started_at,
            completed_at: Some(activity_now()),
            transferred_bytes: None,
            error_code: result.as_ref().err().map(|e| e.code.into()),
            retry_classification: None,
        })
        .await;
    *state.oauth_cancel.lock().await = None;
    end_session(&state, session).await;
    result.map(|id| id.to_string())
}

#[tauri::command]
pub async fn cancel_authorization(
    state: State<'_, AppState>,
    operation_id: String,
) -> Result<(), CommandError> {
    let _span = command_span("cancel_authorization", &operation_id);
    if let Some(cancel) = state.oauth_cancel.lock().await.as_ref() {
        cancel.cancel();
    }
    Ok(())
}

#[tauri::command]
pub async fn remove_cloud_provider(
    state: State<'_, AppState>,
    target: String,
    revoke: bool,
    operation_id: String,
) -> Result<(), CommandError> {
    let _span = command_span("remove_cloud_provider", &operation_id);
    let id = parse_id(&target)?;
    let mut session = begin_session(&state).await?;
    let started_at = activity_now();
    let _ = session
        .record_activity(NewActivityEvent {
            operation_id: operation_id.clone(),
            event_type: "provider_disconnect".into(),
            status: "started".into(),
            related_file_id: None,
            related_target_id: Some(id),
            display_metadata: "Storage account".into(),
            started_at: started_at.clone(),
            completed_at: None,
            transferred_bytes: None,
            error_code: None,
            retry_classification: None,
        })
        .await;
    let result = session
        .remove_cloud_provider(id, revoke)
        .await
        .map_err(command_error);
    let _ = session
        .record_activity(NewActivityEvent {
            operation_id: operation_id.clone(),
            event_type: "provider_disconnect".into(),
            status: if result.is_ok() {
                "completed"
            } else {
                "failed"
            }
            .into(),
            related_file_id: None,
            related_target_id: Some(id),
            display_metadata: "Storage account".into(),
            started_at,
            completed_at: Some(activity_now()),
            transferred_bytes: None,
            error_code: result.as_ref().err().map(|e| e.code.into()),
            retry_classification: None,
        })
        .await;
    end_session(&state, session).await;
    result
}

#[tauri::command]
pub async fn storage_target_ids(
    state: State<'_, AppState>,
    operation_id: String,
) -> Result<Vec<String>, CommandError> {
    let _span = command_span("storage_target_ids", &operation_id);
    let session = begin_session(&state).await?;
    let result = session.storage_target_ids().await.map_err(command_error);
    end_session(&state, session).await;
    Ok(result?.into_iter().map(|id| id.to_string()).collect())
}

#[tauri::command]
pub async fn provider_summaries(
    state: State<'_, AppState>,
    operation_id: String,
) -> Result<Vec<ProviderDto>, CommandError> {
    let _span = command_span("provider_summaries", &operation_id);
    let session = begin_session(&state).await?;
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(15),
        session.provider_summaries(),
    )
    .await
    .map_err(|_| CommandError {
        code: "provider_timeout",
        detail: None,
    })?
    .map_err(command_error);
    end_session(&state, session).await;
    Ok(result?.into_iter().map(provider_dto).collect())
}

#[tauri::command]
pub async fn rename_provider(
    state: State<'_, AppState>,
    target: String,
    display_name: String,
    operation_id: String,
) -> Result<(), CommandError> {
    let _span = command_span("rename_provider", &operation_id);
    let session = begin_session(&state).await?;
    let result = session
        .rename_provider(parse_id(&target)?, &display_name)
        .await
        .map_err(command_error);
    end_session(&state, session).await;
    result
}

#[tauri::command]
pub async fn activity_events(
    state: State<'_, AppState>,
    cursor: Option<String>,
    page_size: Option<u32>,
    event_type: Option<String>,
    status: Option<String>,
    started_after: Option<String>,
    started_before: Option<String>,
    operation_id: String,
) -> Result<ActivityPageDto, CommandError> {
    let _span = command_span("activity_events", &operation_id);
    let session = begin_session(&state).await?;
    let result = session
        .activity_events(
            cursor.as_deref(),
            page_size.unwrap_or(50),
            event_type.as_deref(),
            status.as_deref(),
            started_after.as_deref(),
            started_before.as_deref(),
        )
        .await
        .map_err(command_error);
    end_session(&state, session).await;
    let (events, next_cursor) = result?;
    Ok(ActivityPageDto {
        events: events.into_iter().map(activity_dto).collect(),
        next_cursor,
    })
}
fn provider_dto(provider: ProviderSummary) -> ProviderDto {
    ProviderDto {
        id: provider.id.to_string(),
        kind: provider.kind,
        connected: provider.connected,
        health: provider.health,
        used_bytes: provider.used_bytes,
        total_bytes: provider.total_bytes,
        quota_known: provider.quota_known,
        display_name: provider.display_name,
    }
}

fn activity_dto(event: undercloud_core::ActivityEventRecord) -> ActivityDto {
    ActivityDto {
        id: event.id.to_string(),
        operation_id: event.operation_id,
        event_type: event.event_type,
        status: event.status,
        related_file_id: event.related_file_id.map(|v| v.to_string()),
        related_target_id: event.related_target_id.map(|v| v.to_string()),
        display_metadata: event.display_metadata,
        started_at: event.started_at,
        completed_at: event.completed_at,
        transferred_bytes: event.transferred_bytes,
        error_code: event.error_code,
        retry_classification: event.retry_classification,
    }
}

#[derive(Debug, Serialize)]
pub struct ActivityPageDto {
    pub events: Vec<ActivityDto>,
    pub next_cursor: Option<String>,
}

#[tauri::command]
pub async fn list_files(
    state: State<'_, AppState>,
    operation_id: String,
) -> Result<Vec<FileDto>, CommandError> {
    let _span = command_span("list_files", &operation_id);
    let session = begin_session(&state).await?;
    let result = session.list_files_cached().await.map_err(command_error);
    end_session(&state, session).await;
    Ok(result?.into_iter().map(file_dto).collect())
}

#[derive(Debug, Serialize)]
pub struct FilePageDto {
    pub files: Vec<FileDto>,
    /// Pass as `after` on the next call to continue; `None` means this was
    /// the last page.
    pub next_cursor: Option<String>,
}

/// Keyset-paginated file listing (task-perf.md 7 pagination requirement).
/// `after` is the `next_cursor` from a previous page, or `None`/absent for
/// the first page. `limit` is clamped to [1, 1000] so a caller cannot
/// request an unbounded page.
#[tauri::command]
pub async fn list_files_page(
    state: State<'_, AppState>,
    operation_id: String,
    after: Option<String>,
    limit: u32,
) -> Result<FilePageDto, CommandError> {
    let _span = command_span("list_files_page", &operation_id);
    let after = after.map(|a| parse_id(&a)).transpose()?;
    let limit = limit.clamp(1, 1000);
    let session = begin_session(&state).await?;
    let result = session.list_files_page(after, limit).await.map_err(command_error);
    end_session(&state, session).await;
    let files = result?;
    let next_cursor = (files.len() as u32 == limit)
        .then(|| files.last().map(|f| f.logical_file_id.to_string()))
        .flatten();
    Ok(FilePageDto {
        files: files.into_iter().map(file_dto).collect(),
        next_cursor,
    })
}
fn file_dto(file: FileSummary) -> FileDto {
    FileDto {
        logical_file_id: file.logical_file_id.to_string(),
        name: file.name,
        mime: file.mime,
        file_version_id: file.file_version_id.map(|x| x.to_string()),
        size_bytes: file.size_bytes,
        health: file.health.map(health_name),
        health_current: file.health_current,
        verified_copies: file.verified_copies,
        required_copies: file.required_copies,
        last_verified_at: file.last_verified_at,
    }
}

#[derive(Debug, Serialize)]
pub struct ProtectionTargetDto {
    pub provider_name: String,
    pub provider_kind: String,
    pub connected: bool,
    pub state: String,
    pub verified_objects: u32,
    pub expected_objects: u32,
    pub repair_possible: bool,
    pub last_verified_at: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ProtectionMapDto {
    pub file_version_id: String,
    pub verified_copies: u32,
    pub required_copies: u32,
    pub last_verified_at: Option<String>,
    pub targets: Vec<ProtectionTargetDto>,
}

#[tauri::command]
pub async fn protection_map(
    state: State<'_, AppState>,
    file_version_id: String,
    operation_id: String,
) -> Result<ProtectionMapDto, CommandError> {
    let _span = command_span("protection_map", &operation_id);
    let version = parse_id(&file_version_id)?;
    let session = begin_session(&state).await?;
    let result = async {
        let map = session
            .protection_map(version)
            .await
            .map_err(command_error)?;
        let providers = session.provider_summaries().await.map_err(command_error)?;
        Ok::<_, CommandError>(ProtectionMapDto {
            file_version_id: map.file_version_id.to_string(),
            verified_copies: map.verified_copies,
            required_copies: map.required_copies,
            last_verified_at: map.last_verified_at,
            targets: map
                .targets
                .into_iter()
                .map(|target| {
                    let provider = providers
                        .iter()
                        .find(|provider| provider.id == target.target_id);
                    ProtectionTargetDto {
                        provider_name: provider
                            .map(|p| p.display_name.clone())
                            .unwrap_or_else(|| "Storage account".into()),
                        provider_kind: provider
                            .map(|p| p.kind.clone())
                            .unwrap_or_else(|| "cloud".into()),
                        connected: provider.is_some_and(|p| p.connected),
                        state: if !provider.is_some_and(|p| p.connected) {
                            "unavailable"
                        } else if target.corrupt {
                            "corrupt"
                        } else if target.pending {
                            "verifying"
                        } else if target.complete {
                            "complete"
                        } else if target.verified_objects > 0 {
                            "partial"
                        } else {
                            "missing"
                        }
                        .into(),
                        verified_objects: target.verified_objects,
                        expected_objects: target.expected_objects,
                        repair_possible: provider.is_some_and(|p| p.connected) && !target.complete,
                        last_verified_at: target.last_verified_at,
                    }
                })
                .collect(),
        })
    }
    .await;
    end_session(&state, session).await;
    result
}

fn trash_file_dto(item: TrashFileSummary) -> TrashFileDto {
    TrashFileDto {
        file: file_dto(item.file),
        deletion_id: item.deletion_id.to_string(),
        state: item.state,
        purge_after: item.purge_after,
        retry_classification: item.retry_classification,
        replica_count: item.replica_count,
    }
}

fn deletion_confirmation_mode(mode: &str) -> Result<&'static str, CommandError> {
    match mode {
        "trash" => Ok("trash"),
        "permanent" => Ok("permanent"),
        _ => Err(CommandError {
            code: "invalid_transition",
            detail: None,
        }),
    }
}

fn permanent_deletion_prepare_allowed(state: &str) -> bool {
    matches!(
        state,
        "trashed" | "purge_scheduled" | "purge_planned" | "deleting" | "delete_incomplete"
    )
}

fn deletion_transition_error(operation_id: &str, stage: &'static str) -> CommandError {
    tracing::warn!(target: "undercloud.command", subsystem = "tauri", operation = "prepare_file_deletion", operation_id = %operation_id, transition_stage = stage);
    CommandError {
        code: "invalid_transition",
        detail: None,
    }
}

#[tauri::command]
pub async fn list_trash(
    state: State<'_, AppState>,
    operation_id: String,
) -> Result<Vec<TrashFileDto>, CommandError> {
    let _span = command_span("list_trash", &operation_id);
    let session = begin_session(&state).await?;
    let result = session.list_trash().await.map_err(command_error);
    end_session(&state, session).await;
    Ok(result?.into_iter().map(trash_file_dto).collect())
}

#[tauri::command]
pub async fn prepare_file_deletion(
    state: State<'_, AppState>,
    file_id: String,
    mode: String,
    retention_days: Option<u32>,
    operation_id: String,
) -> Result<FileDeletionChallengeDto, CommandError> {
    let _span = command_span("prepare_file_deletion", &operation_id);
    let mode = deletion_confirmation_mode(&mode)?.to_owned();
    if mode == "trash" && !matches!(retention_days, Some(30 | 60 | 90) | None) {
        return Err(deletion_transition_error(&operation_id, "retention"));
    }
    let file_id = parse_id(&file_id)?;
    let session = begin_session(&state).await?;
    let active = session.file_summary(file_id).await.map_err(command_error)?;
    let trash = session.list_trash().await.map_err(command_error)?;
    let (file, state_name) =
        if let Some(file) = active {
            (file, "active".to_owned())
        } else if let Some(item) = trash
            .into_iter()
            .find(|item| item.file.logical_file_id == file_id)
        {
            (item.file, item.state)
        } else {
            end_session(&state, session).await;
            return Err(deletion_transition_error(&operation_id, "file_not_found"));
        };
    let valid = (mode == "trash" && state_name == "active")
        || (mode == "permanent" && permanent_deletion_prepare_allowed(&state_name));
    if !valid {
        end_session(&state, session).await;
        return Err(deletion_transition_error(&operation_id, "state"));
    }
    let expected = if mode == "permanent" {
        file.name.clone()
    } else {
        "CONFIRM".to_owned()
    };
    let replica_count = match session.count_file_replicas(file_id).await {
        Ok(count) => count,
        Err(error) => {
            let error = command_error(error);
            end_session(&state, session).await;
            return Err(error);
        }
    };
    let challenge_id = Uuid::new_v4();
    let expires_at = std::time::Instant::now() + std::time::Duration::from_secs(120);
    let expires_at_unix_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        + 120_000;
    state.deletion_challenges.lock().await.insert(
        challenge_id,
        DeletionChallenge {
            vault_id: *state
                .active_vault_id
                .lock()
                .await
                .as_ref()
                .ok_or(CommandError {
                    code: "locked",
                    detail: None,
                })?,
            file_id,
            mode: mode.clone(),
            expected_confirmation: expected.clone(),
            state: state_name.clone(),
            current_version_id: file.file_version_id,
            purge_after: retention_days.map(|days| {
                activity_now()
                    .parse::<u64>()
                    .unwrap_or_default()
                    .saturating_add(days as u64 * 86_400_000)
                    .to_string()
            }),
            expires_at,
        },
    );
    end_session(&state, session).await;
    Ok(FileDeletionChallengeDto {
        challenge_id: challenge_id.to_string(),
        file_id: file_id.to_string(),
        mode,
        display_name: file.name,
        state: state_name,
        current_version_id: file.file_version_id.map(|id| id.to_string()),
        expected_confirmation: expected,
        expires_at_unix_ms,
        operation_id,
        replica_count,
    })
}

#[tauri::command]
pub async fn confirm_file_deletion(
    state: State<'_, AppState>,
    challenge_id: String,
    confirmation_text: String,
    operation_id: String,
) -> Result<bool, CommandError> {
    let _span = command_span("confirm_file_deletion", &operation_id);
    let challenge_id = parse_id(&challenge_id)?;
    if let Some(result) = state
        .completed_deletions
        .lock()
        .await
        .get(&challenge_id)
        .copied()
    {
        return Ok(result);
    }
    let challenge = state
        .deletion_challenges
        .lock()
        .await
        .get(&challenge_id)
        .cloned()
        .ok_or(CommandError {
            code: "invalid_transition",
            detail: None,
        })?;
    if challenge.expires_at <= std::time::Instant::now()
        || confirmation_text != challenge.expected_confirmation
    {
        return Err(CommandError {
            code: "invalid_transition",
            detail: None,
        });
    }
    let active_vault = *state.active_vault_id.lock().await;
    if active_vault != Some(challenge.vault_id) {
        return Err(CommandError {
            code: "locked",
            detail: None,
        });
    }
    let session = begin_session(&state).await?;
    let current = session
        .file_summary(challenge.file_id)
        .await
        .map_err(command_error)?;
    let current_trash = session.list_trash().await.map_err(command_error)?;
    let current_state = current
        .as_ref()
        .map(|file| ("active", file.file_version_id))
        .or_else(|| {
            current_trash
                .iter()
                .find(|item| item.file.logical_file_id == challenge.file_id)
                .map(|item| (item.state.as_str(), item.file.file_version_id))
        });
    let unchanged = current_state.is_some_and(|(state, version)| {
        state == challenge.state && version == challenge.current_version_id
    });
    if !unchanged {
        end_session(&state, session).await;
        return Err(CommandError {
            code: "invalid_transition",
            detail: None,
        });
    }
    let result = if challenge.mode == "trash" {
        session
            .move_file_to_trash(challenge.file_id, &operation_id, challenge.purge_after)
            .await
            .map(|_| true)
    } else {
        session
            .permanently_delete_file(challenge.file_id, &operation_id, CancellationToken::new())
            .await
            .map(|outcome| outcome.completed)
    }
    .map_err(command_error);
    end_session(&state, session).await;
    if let Ok(value) = result {
        state.deletion_challenges.lock().await.remove(&challenge_id);
        state
            .completed_deletions
            .lock()
            .await
            .insert(challenge_id, value);
        Ok(value)
    } else {
        result
    }
}

#[tauri::command]
pub async fn restore_from_trash(
    state: State<'_, AppState>,
    file_id: String,
    operation_id: String,
) -> Result<(), CommandError> {
    let _span = command_span("restore_from_trash", &operation_id);
    let file_id = parse_id(&file_id)?;
    let session = begin_session(&state).await?;
    let result = session
        .restore_file_from_trash(file_id, &operation_id)
        .await
        .map_err(command_error);
    end_session(&state, session).await;
    result
}

#[tauri::command]
pub async fn upload_file(
    app: AppHandle,
    state: State<'_, AppState>,
    source_path: String,
    logical_name: String,
    idempotency_key: String,
    operation_id: String,
) -> Result<(), CommandError> {
    let _span = command_span("upload_file", &operation_id);
    let path = PathBuf::from(source_path);
    let size = tokio::fs::metadata(&path)
        .await
        .map_err(|_| CommandError {
            code: "source_unavailable",
            detail: None,
        })?
        .len();
    let file = tokio::fs::File::open(path)
        .await
        .map_err(|_| CommandError {
            code: "source_unavailable",
            detail: None,
        })?;
    let session = begin_session(&state).await?;
    let started_at = activity_now();
    let _ = session
        .record_activity(NewActivityEvent {
            operation_id: operation_id.clone(),
            event_type: "upload".into(),
            status: "started".into(),
            related_file_id: None,
            related_target_id: None,
            display_metadata: logical_name.clone(),
            started_at: started_at.clone(),
            completed_at: None,
            transferred_bytes: Some(size),
            error_code: None,
            retry_classification: None,
        })
        .await;
    let cancel = CancellationToken::new();
    *state.upload_cancel.lock().await = Some(cancel.clone());
    let (tx, mut rx) = tokio::sync::mpsc::channel::<undercloud_core::UploadProgress>(8);
    let emitter = tokio::spawn(async move {
        while let Some(p) = rx.recv().await {
            let _ = tauri::Emitter::emit(
                &app,
                "upload-progress",
                ProgressDto {
                    bytes_processed: p.bytes_processed,
                    total_bytes: p.total_bytes,
                },
            );
        }
    });
    let result = session
        .upload_file_with_cancel(
            file,
            Some(size),
            &logical_name,
            None,
            &idempotency_key,
            tx,
            cancel,
        )
        .await
        .map_err(command_error);
    let status = if result.is_ok() {
        "completed"
    } else if result
        .as_ref()
        .err()
        .is_some_and(|error| error.code == "cancelled")
    {
        "cancelled"
    } else {
        "failed"
    };
    let _ = session
        .record_activity(NewActivityEvent {
            operation_id: operation_id.clone(),
            event_type: "upload".into(),
            status: status.into(),
            related_file_id: None,
            related_target_id: None,
            display_metadata: logical_name.clone(),
            started_at,
            completed_at: Some(activity_now()),
            transferred_bytes: Some(size),
            error_code: result.as_ref().err().map(|e| e.code.into()),
            retry_classification: None,
        })
        .await;
    *state.upload_cancel.lock().await = None;
    end_session(&state, session).await;
    let _ = emitter.await;
    result.map(|_| ())
}

#[tauri::command]
pub async fn restore_file(
    state: State<'_, AppState>,
    file_version_id: String,
    destination_dir: String,
    file_name: String,
    operation_id: String,
) -> Result<(), CommandError> {
    let _span = command_span("restore_file", &operation_id);
    let id = parse_id(&file_version_id)?;
    validate_restore_file_name(&file_name)?;
    let destination = Path::new(&destination_dir).join(&file_name);
    let token = CancellationToken::new();
    let session = begin_session(&state).await?;
    let started_at = activity_now();
    let _ = session
        .record_activity(NewActivityEvent {
            operation_id: operation_id.clone(),
            event_type: "restore".into(),
            status: "started".into(),
            related_file_id: None,
            related_target_id: None,
            display_metadata: file_name.clone(),
            started_at: started_at.clone(),
            completed_at: None,
            transferred_bytes: None,
            error_code: None,
            retry_classification: None,
        })
        .await;
    *state.restore_cancel.lock().await = Some(token.clone());
    let result = session
        .restore_file(id, &destination, token)
        .await
        .map_err(command_error);
    let status = if result.is_ok() {
        "completed"
    } else if result
        .as_ref()
        .err()
        .is_some_and(|error| error.code == "cancelled")
    {
        "cancelled"
    } else {
        "failed"
    };
    let _ = session
        .record_activity(NewActivityEvent {
            operation_id,
            event_type: "restore".into(),
            status: status.into(),
            related_file_id: None,
            related_target_id: None,
            display_metadata: file_name,
            started_at,
            completed_at: Some(activity_now()),
            transferred_bytes: None,
            error_code: result.as_ref().err().map(|e| e.code.into()),
            retry_classification: None,
        })
        .await;
    *state.restore_cancel.lock().await = None;
    end_session(&state, session).await;
    result
}
#[tauri::command]
pub async fn cancel_restore(
    state: State<'_, AppState>,
    operation_id: String,
) -> Result<(), CommandError> {
    let _span = command_span("cancel_restore", &operation_id);
    if let Some(token) = state.restore_cancel.lock().await.as_ref() {
        token.cancel();
    }
    Ok(())
}
#[tauri::command]
pub async fn cancel_upload(
    state: State<'_, AppState>,
    operation_id: String,
) -> Result<(), CommandError> {
    let _span = command_span("cancel_upload", &operation_id);
    if let Some(token) = state.upload_cancel.lock().await.as_ref() {
        token.cancel();
    }
    Ok(())
}
#[tauri::command]
pub async fn file_health(
    state: State<'_, AppState>,
    file_version_id: String,
    operation_id: String,
) -> Result<&'static str, CommandError> {
    let _span = command_span("file_health", &operation_id);
    let id = parse_id(&file_version_id)?;
    let session = begin_session(&state).await?;
    let started_at = activity_now();
    let _ = session
        .record_activity(NewActivityEvent {
            operation_id: operation_id.clone(),
            event_type: "health_check".into(),
            status: "started".into(),
            related_file_id: Some(id),
            related_target_id: None,
            display_metadata: "File health".into(),
            started_at: started_at.clone(),
            completed_at: None,
            transferred_bytes: None,
            error_code: None,
            retry_classification: None,
        })
        .await;
    let result = session
        .health(id)
        .await
        .map(health_name)
        .map_err(command_error);
    let _ = session
        .record_activity(NewActivityEvent {
            operation_id,
            event_type: "health_check".into(),
            status: if result.is_ok() {
                "completed"
            } else {
                "failed"
            }
            .into(),
            related_file_id: Some(id),
            related_target_id: None,
            display_metadata: "File health".into(),
            started_at,
            completed_at: Some(activity_now()),
            transferred_bytes: None,
            error_code: result.as_ref().err().map(|e| e.code.into()),
            retry_classification: None,
        })
        .await;
    end_session(&state, session).await;
    result
}

#[derive(Debug, Serialize)]
pub struct VerifyAllSummaryDto {
    pub files_protected: u32,
    pub files_degraded: u32,
    pub files_at_risk: u32,
    pub files_unrecoverable: u32,
    pub failed: u32,
}

#[tauri::command]
pub async fn verify_all(
    state: State<'_, AppState>,
    operation_id: String,
) -> Result<VerifyAllSummaryDto, CommandError> {
    let _span = command_span("verify_all", &operation_id);
    let session = begin_session(&state).await?;
    let files = session.list_files_cached().await.map_err(command_error)?;
    let mut summary = VerifyAllSummaryDto {
        files_protected: 0,
        files_degraded: 0,
        files_at_risk: 0,
        files_unrecoverable: 0,
        failed: 0,
    };
    for file in files {
        let Some(version) = file.file_version_id else {
            continue;
        };
        match session.health(version).await {
            Ok(undercloud_core::FileHealth::Healthy) => summary.files_protected += 1,
            Ok(undercloud_core::FileHealth::Degraded) => summary.files_degraded += 1,
            Ok(undercloud_core::FileHealth::AtRisk) => summary.files_at_risk += 1,
            Ok(undercloud_core::FileHealth::Unrecoverable) => summary.files_unrecoverable += 1,
            Ok(_) | Err(_) => summary.failed += 1,
        }
    }
    end_session(&state, session).await;
    Ok(summary)
}
#[tauri::command]
pub async fn repair_file(
    state: State<'_, AppState>,
    file_version_id: String,
    operation_id: String,
) -> Result<&'static str, CommandError> {
    let _span = command_span("repair_file", &operation_id);
    let v = parse_id(&file_version_id)?;
    let session = begin_session(&state).await?;
    let started_at = activity_now();
    let _ = session
        .record_activity(NewActivityEvent {
            operation_id: operation_id.clone(),
            event_type: "repair".into(),
            status: "started".into(),
            related_file_id: Some(v),
            related_target_id: None,
            display_metadata: "Repair file".into(),
            started_at: started_at.clone(),
            completed_at: None,
            transferred_bytes: None,
            error_code: None,
            retry_classification: None,
        })
        .await;
    let result = session
        .repair_automatically(v)
        .await
        .map(health_name)
        .map_err(command_error);
    let status = if result.is_ok() {
        "completed"
    } else if result
        .as_ref()
        .err()
        .is_some_and(|error| error.code == "cancelled")
    {
        "cancelled"
    } else {
        "failed"
    };
    let _ = session
        .record_activity(NewActivityEvent {
            operation_id,
            event_type: "repair".into(),
            status: status.into(),
            related_file_id: Some(v),
            related_target_id: None,
            display_metadata: "Repair file".into(),
            started_at,
            completed_at: Some(activity_now()),
            transferred_bytes: None,
            error_code: result.as_ref().err().map(|e| e.code.into()),
            retry_classification: None,
        })
        .await;
    end_session(&state, session).await;
    result
}
#[tauri::command]
pub async fn change_password(
    state: State<'_, AppState>,
    current_password: String,
    new_password: String,
    operation_id: String,
) -> Result<(), CommandError> {
    let _span = command_span("change_password", &operation_id);
    let mut session = begin_session(&state).await?;
    let result = session
        .change_password(&current_password, &new_password)
        .await
        .map_err(command_error);
    end_session(&state, session).await;
    result
}
#[tauri::command]
pub async fn export_recovery_kit(
    state: State<'_, AppState>,
    destination: String,
    passphrase: String,
    operation_id: String,
) -> Result<(), CommandError> {
    let _span = command_span("export_recovery_kit", &operation_id);
    let core = { state.core.lock().await.clone() };
    let session = begin_session(&state).await?;
    let started_at = activity_now();
    let _ = session
        .record_activity(NewActivityEvent {
            operation_id: operation_id.clone(),
            event_type: "recovery_export".into(),
            status: "started".into(),
            related_file_id: None,
            related_target_id: None,
            display_metadata: "Recovery kit".into(),
            started_at: started_at.clone(),
            completed_at: None,
            transferred_bytes: None,
            error_code: None,
            retry_classification: None,
        })
        .await;
    let result = core
        .export_recovery_kit(&session, Path::new(&destination), &passphrase)
        .await
        .map_err(command_error);
    let _ = session
        .record_activity(NewActivityEvent {
            operation_id,
            event_type: "recovery_export".into(),
            status: if result.is_ok() {
                "completed"
            } else {
                "failed"
            }
            .into(),
            related_file_id: None,
            related_target_id: None,
            display_metadata: "Recovery kit".into(),
            started_at,
            completed_at: Some(activity_now()),
            transferred_bytes: None,
            error_code: result.as_ref().err().map(|e| e.code.into()),
            retry_classification: None,
        })
        .await;
    end_session(&state, session).await;
    result
}
#[tauri::command]
pub async fn import_recovery_kit(
    state: State<'_, AppState>,
    kit_path: String,
    catalog_path: String,
    passphrase: String,
    operation_id: String,
) -> Result<Status, CommandError> {
    let _span = command_span("import_recovery_kit", &operation_id);
    begin_exclusive(&state)?;
    let core = UndercloudCore::new(PathBuf::from(&catalog_path));
    let session = match core
        .import_recovery_kit(Path::new(&kit_path), Path::new(&catalog_path), &passphrase)
        .await
        .map_err(command_error)
    {
        Ok(session) => session,
        Err(error) => {
            end_exclusive(&state);
            return Err(error);
        }
    };
    *state.core.lock().await = core;
    let mut vault = state.vault.lock().await;
    cancel_displaced_session(&mut vault);
    *vault = Some(VaultState::Unlocked(Box::new(session)));
    let status = status_of(vault.as_ref());
    drop(vault);
    *state.active_vault_id.lock().await = status
        .vault_id
        .as_deref()
        .and_then(|id| Uuid::parse_str(id).ok());
    end_exclusive(&state);
    Ok(status)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn errors_are_codes_and_never_carry_paths_or_secrets() {
        let error = command_error(CoreError::Authentication);
        let json: serde_json::Value = serde_json::to_value(&error).unwrap();
        assert_eq!(json["code"], "authentication_failed");
        assert_eq!(json["message"], "The password was not accepted.");
        assert!(json["incident_id"].as_str().is_some());
    }

    #[test]
    fn provider_request_rejected_carries_only_an_http_status_as_detail() {
        let error = command_error(CoreError::Provider(ProviderError::RequestRejected {
            status: 400,
            message: None,
        }));
        let json: serde_json::Value = serde_json::to_value(&error).unwrap();
        assert_eq!(json["code"], "provider_request_rejected");
        assert!(json.get("detail").is_none());
    }

    #[test]
    fn provider_request_rejected_appends_the_provider_message_when_present() {
        let error = command_error(CoreError::Provider(ProviderError::RequestRejected {
            status: 400,
            message: Some("Invalid parent folder".to_owned()),
        }));
        let json: serde_json::Value = serde_json::to_value(&error).unwrap();
        assert_eq!(json["code"], "provider_request_rejected");
        assert!(json.get("detail").is_none());
        assert!(!json.to_string().contains("Invalid parent folder"));
    }

    #[test]
    fn permanent_deletion_allows_retryable_trash_states_only() {
        assert!(permanent_deletion_prepare_allowed("trashed"));
        assert!(permanent_deletion_prepare_allowed("purge_scheduled"));
        assert!(permanent_deletion_prepare_allowed("delete_incomplete"));
        assert!(!permanent_deletion_prepare_allowed("active"));
        assert!(permanent_deletion_prepare_allowed("purge_planned"));
        assert!(permanent_deletion_prepare_allowed("deleting"));
        assert!(!permanent_deletion_prepare_allowed("purged"));
    }

    #[tokio::test]
    async fn status_does_not_wait_for_an_active_operation() {
        let state = AppState::default();
        begin_exclusive(&state).unwrap();
        assert_eq!(current_status(&state).await.state, "locked");
        assert!(begin_exclusive(&state).is_err());
        end_exclusive(&state);
        assert!(begin_exclusive(&state).is_ok());
        end_exclusive(&state);
    }
}
