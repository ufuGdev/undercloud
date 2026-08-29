// SPDX-License-Identifier: Apache-2.0
//! Typed, vault-scoped repositories for the unlocked catalog.
use std::marker::PhantomData;

use rusqlite::{params, Connection, OptionalExtension, Transaction as SqlTransaction};
use uuid::Uuid;

use undercloud_crypto::{CatalogFieldSubkey, PasswordEnvelope};
use undercloud_crypto::{FileKeyType, WrappedFileKey};

use crate::error::CatalogError;
use crate::executor::CatalogExecutorHandle;
use crate::field_envelope::{self, EntityType, FieldTag};

type WrappedKeyRow = (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, i64, i64);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorageTargetRecord {
    pub id: Uuid,
    pub provider_kind: String,
    pub config: Vec<u8>,
    pub display_order: i64,
    pub oauth_application_profile: String,
    pub display_name: Option<String>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActivityEventRecord {
    pub id: Uuid,
    pub vault_id: Uuid,
    pub operation_id: String,
    pub event_type: String,
    pub status: String,
    pub related_file_id: Option<Uuid>,
    pub related_target_id: Option<Uuid>,
    pub display_metadata: String,
    pub started_at: String,
    pub completed_at: Option<String>,
    pub transferred_bytes: Option<u64>,
    pub error_code: Option<String>,
    pub retry_classification: Option<String>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewActivityEvent {
    pub operation_id: String,
    pub event_type: String,
    pub status: String,
    pub related_file_id: Option<Uuid>,
    pub related_target_id: Option<Uuid>,
    pub display_metadata: String,
    pub started_at: String,
    pub completed_at: Option<String>,
    pub transferred_bytes: Option<u64>,
    pub error_code: Option<String>,
    pub retry_classification: Option<String>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogicalFolderRecord {
    pub id: Uuid,
    pub parent_folder_id: Option<Uuid>,
    pub name: String,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogicalFileRecord {
    pub id: Uuid,
    pub folder_id: Option<Uuid>,
    pub name: String,
    pub mime: Option<String>,
    pub current_version_id: Option<Uuid>,
    pub lifecycle_state: String,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileVersionRecord {
    pub id: Uuid,
    pub logical_file_id: Uuid,
    pub file_size: u64,
    pub chunk_count: u32,
    pub content_hash: Vec<u8>,
    pub state: String,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChunkRecord {
    pub id: Uuid,
    pub file_version_id: Uuid,
    pub chunk_index: u32,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplicaRecord {
    pub id: Uuid,
    pub chunk_id: Option<Uuid>,
    pub file_version_id: Uuid,
    pub storage_target_id: Uuid,
    pub object_kind: ObjectKind,
    pub locator: String,
    pub state: ReplicaState,
    pub last_verified_at: Option<String>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncJobRecord {
    pub id: Uuid,
    pub file_version_id: Option<Uuid>,
    pub job_kind: JobKind,
    pub state: String,
    pub idempotency_key: String,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncJobObjectRecord {
    pub id: Uuid,
    pub sync_job_id: Uuid,
    pub storage_target_id: Uuid,
    pub object_kind: ObjectKind,
    pub chunk_index: Option<u32>,
    pub locator: String,
    pub state: String,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HealthObservationRecord {
    pub id: Uuid,
    pub file_version_id: Uuid,
    pub observed_at: String,
    pub verified_replica_count: u32,
    pub required_replica_count: u32,
    pub health_state: HealthState,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileSummaryRow {
    pub id: Uuid,
    pub name: String,
    pub mime: Option<String>,
    pub current_version_id: Option<Uuid>,
    pub file_size: Option<u64>,
    pub chunk_count: Option<u32>,
    pub verified_replica_count: Option<u32>,
    pub required_replica_count: Option<u32>,
    pub last_verified_at: Option<String>,
    pub health_state: Option<HealthState>,
}
type SummaryTuple = (
    String,
    Vec<u8>,
    Option<Vec<u8>>,
    Option<String>,
    Option<i64>,
    Option<i64>,
    Option<i64>,
    Option<i64>,
    Option<String>,
    Option<String>,
);

/// Shared row-shape for `list_file_summary_rows`, `list_file_summary_row`,
/// and `list_file_summary_page` -- all three select the same ten columns.
fn row_to_summary_tuple(r: &rusqlite::Row) -> rusqlite::Result<SummaryTuple> {
    Ok((
        r.get::<_, String>(0)?,
        r.get::<_, Vec<u8>>(1)?,
        r.get::<_, Option<Vec<u8>>>(2)?,
        r.get::<_, Option<String>>(3)?,
        r.get::<_, Option<i64>>(4)?,
        r.get::<_, Option<i64>>(5)?,
        r.get::<_, Option<i64>>(6)?,
        r.get::<_, Option<i64>>(7)?,
        r.get::<_, Option<String>>(8)?,
        r.get::<_, Option<String>>(9)?,
    ))
}

/// Decrypts and converts one [`row_to_summary_tuple`] result into a
/// [`FileSummaryRow`]; shared decrypt/convert logic for every caller of
/// the summary query so they cannot silently diverge.
fn summary_tuple_to_row(
    t: SummaryTuple,
    key: &CatalogFieldSubkey,
    vault: Uuid,
) -> Result<FileSummaryRow, CatalogError> {
    let (
        id_s,
        name,
        mime,
        current,
        size,
        chunk_count,
        verified,
        required,
        observed_at,
        health_state,
    ) = t;
    let i = id(id_s)?;
    Ok(FileSummaryRow {
        id: i,
        name: String::from_utf8(field_envelope::decrypt_field(
            key,
            vault,
            EntityType::LogicalFile,
            i,
            FieldTag::Name,
            &name,
        )?)
        .map_err(|_| CatalogError::InvalidState)?,
        mime: mime
            .map(|m| {
                field_envelope::decrypt_field(
                    key,
                    vault,
                    EntityType::LogicalFile,
                    i,
                    FieldTag::Mime,
                    &m,
                )
            })
            .transpose()?
            .map(String::from_utf8)
            .transpose()
            .map_err(|_| CatalogError::InvalidState)?,
        current_version_id: current.map(id).transpose()?,
        file_size: size
            .map(u64::try_from)
            .transpose()
            .map_err(|_| CatalogError::InvalidState)?,
        chunk_count: chunk_count
            .map(u32::try_from)
            .transpose()
            .map_err(|_| CatalogError::InvalidState)?,
        verified_replica_count: verified
            .map(u32::try_from)
            .transpose()
            .map_err(|_| CatalogError::InvalidState)?,
        required_replica_count: required
            .map(u32::try_from)
            .transpose()
            .map_err(|_| CatalogError::InvalidState)?,
        last_verified_at: observed_at,
        health_state: health_state.map(|s| HealthState::parse(&s)).transpose()?,
    })
}

/// Replica fields needed for bulk protection-map computation, without the
/// per-row locator decryption `ReplicaRecord` pays for — the locator is
/// never used by that computation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplicaLite {
    pub file_version_id: Uuid,
    pub chunk_id: Option<Uuid>,
    pub storage_target_id: Uuid,
    pub object_kind: ObjectKind,
    pub state: ReplicaState,
    pub last_verified_at: Option<String>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryFreshnessRecord {
    pub generation: u64,
    pub exported_generation: Option<u64>,
    pub exported_at: Option<String>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepairJobRecord {
    pub id: Uuid,
    pub file_version_id: Uuid,
    pub missing_storage_target_id: Uuid,
    pub source_storage_target_id: Uuid,
    pub state: String,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeletionJobRecord {
    pub id: Uuid,
    pub logical_file_id: Uuid,
    pub mode: String,
    pub trashed_at: String,
    pub purge_after: Option<String>,
    pub operation_id: String,
    pub state: String,
    pub retry_classification: Option<String>,
    pub incident_code: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeletionItemRecord {
    pub id: Uuid,
    pub deletion_id: Uuid,
    pub file_version_id: Uuid,
    pub replica_id: Uuid,
    pub storage_target_id: Uuid,
    pub object_kind: ObjectKind,
    pub locator: String,
    pub state: String,
    pub provider_result: Option<String>,
    pub retry_count: u32,
    pub next_retry_at: Option<String>,
    pub confirmed_deleted_at: Option<String>,
}

#[derive(Debug, Clone)]
pub struct CatalogSnapshot {
    pub vault_id: Uuid,
    pub targets: Vec<StorageTargetRecord>,
    pub folders: Vec<LogicalFolderRecord>,
    pub files: Vec<LogicalFileRecord>,
    pub versions: Vec<FileVersionRecord>,
    pub wrapped_keys: Vec<(Uuid, WrappedFileKey, WrappedFileKey)>,
    pub chunks: Vec<ChunkRecord>,
    pub replicas: Vec<ReplicaRecord>,
    pub activities: Vec<ActivityEventRecord>,
    pub deletion_jobs: Vec<DeletionJobRecord>,
    pub deletion_items: Vec<DeletionItemRecord>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectKind {
    Chunk,
    Manifest,
}
impl ObjectKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Chunk => "chunk",
            Self::Manifest => "manifest",
        }
    }
    fn parse(v: &str) -> Result<Self, CatalogError> {
        match v {
            "chunk" => Ok(Self::Chunk),
            "manifest" => Ok(Self::Manifest),
            _ => Err(CatalogError::InvalidState),
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplicaState {
    Pending,
    Verified,
    Missing,
    Corrupt,
}
impl ReplicaState {
    fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Verified => "verified",
            Self::Missing => "missing",
            Self::Corrupt => "corrupt",
        }
    }
    fn parse(v: &str) -> Result<Self, CatalogError> {
        match v {
            "pending" => Ok(Self::Pending),
            "verified" => Ok(Self::Verified),
            "missing" => Ok(Self::Missing),
            "corrupt" => Ok(Self::Corrupt),
            _ => Err(CatalogError::InvalidState),
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JobKind {
    Upload,
    Restore,
    Repair,
}
impl JobKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Upload => "upload",
            Self::Restore => "restore",
            Self::Repair => "repair",
        }
    }
    fn parse(v: &str) -> Result<Self, CatalogError> {
        match v {
            "upload" => Ok(Self::Upload),
            "restore" => Ok(Self::Restore),
            "repair" => Ok(Self::Repair),
            _ => Err(CatalogError::InvalidState),
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HealthState {
    Healthy,
    Degraded,
    AtRisk,
    Unrecoverable,
}
impl HealthState {
    fn as_str(self) -> &'static str {
        match self {
            Self::Healthy => "healthy",
            Self::Degraded => "degraded",
            Self::AtRisk => "at_risk",
            Self::Unrecoverable => "unrecoverable",
        }
    }
    fn parse(v: &str) -> Result<Self, CatalogError> {
        match v {
            "healthy" => Ok(Self::Healthy),
            "degraded" => Ok(Self::Degraded),
            "at_risk" => Ok(Self::AtRisk),
            "unrecoverable" => Ok(Self::Unrecoverable),
            _ => Err(CatalogError::InvalidState),
        }
    }
}

fn now() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .to_string()
}
fn id(v: String) -> Result<Uuid, CatalogError> {
    Uuid::parse_str(&v).map_err(|_| CatalogError::NotFound)
}
fn valid_job_state(state: &str) -> bool {
    matches!(
        state,
        "pending" | "running" | "completed" | "failed" | "cancelled"
    )
}
fn ensure_uuid(
    conn: &Connection,
    table: &str,
    value: Uuid,
    vault: Uuid,
) -> Result<(), CatalogError> {
    let sql = match table {
        "folders" => "SELECT 1 FROM logical_folders WHERE id=?1 AND vault_id=?2",
        "files" => "SELECT 1 FROM logical_files WHERE id=?1 AND vault_id=?2",
        "versions" => "SELECT 1 FROM file_versions WHERE id=?1 AND vault_id=?2",
        "targets" => "SELECT 1 FROM storage_targets WHERE id=?1 AND vault_id=?2",
        _ => return Err(CatalogError::InvariantViolation),
    };
    conn.query_row(sql, params![value.to_string(), vault.to_string()], |_| {
        Ok(())
    })
    .map_err(|e| {
        if matches!(e, rusqlite::Error::QueryReturnedNoRows) {
            CatalogError::InvariantViolation
        } else {
            e.into()
        }
    })
}
fn ensure_uuid_tx(
    tx: &SqlTransaction<'_>,
    table: &str,
    value: Uuid,
    vault: Uuid,
) -> Result<(), CatalogError> {
    let sql = match table {
        "folders" => "SELECT 1 FROM logical_folders WHERE id=?1 AND vault_id=?2",
        "files" => "SELECT 1 FROM logical_files WHERE id=?1 AND vault_id=?2",
        "versions" => "SELECT 1 FROM file_versions WHERE id=?1 AND vault_id=?2",
        "targets" => "SELECT 1 FROM storage_targets WHERE id=?1 AND vault_id=?2",
        _ => return Err(CatalogError::InvariantViolation),
    };
    tx.query_row(sql, params![value.to_string(), vault.to_string()], |_| {
        Ok(())
    })
    .map_err(|e| {
        if matches!(e, rusqlite::Error::QueryReturnedNoRows) {
            CatalogError::InvariantViolation
        } else {
            e.into()
        }
    })
}

#[derive(Clone)]
pub struct UnlockedCatalog {
    executor: CatalogExecutorHandle,
    vault_id: Uuid,
    catalog_field_subkey: CatalogFieldSubkey,
}
impl std::fmt::Debug for UnlockedCatalog {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UnlockedCatalog")
            .field("vault_id", &self.vault_id)
            .field("catalog_field_subkey", &"<redacted>")
            .finish()
    }
}
impl UnlockedCatalog {
    /// Returns the `EXPLAIN QUERY PLAN` rows for the `list_file_summary_rows`
    /// query, as `(id, parent, detail)` triples — a diagnostic hook for
    /// performance tests to assert the correlated-subquery plan stays
    /// index-assisted (no `SCAN` on `health_observations` or `chunks`) as
    /// catalog scale grows, instead of trusting wall-clock timing alone.
    pub async fn explain_file_summary_query_plan(&self) -> Result<Vec<String>, CatalogError> {
        let v = self.vault_id.to_string();
        self.executor
            .call(move |x| {
                let mut s = x.prepare(
                    "EXPLAIN QUERY PLAN SELECT lf.id, lf.name_envelope, lf.mime_envelope, lf.current_version_id, \
                     fv.file_size, fv.chunk_count, ho.verified_replica_count, ho.required_replica_count, \
                     ho.observed_at, ho.health_state \
                     FROM logical_files lf \
                     LEFT JOIN file_versions fv ON fv.id = lf.current_version_id \
                     LEFT JOIN health_observations ho ON ho.id = ( \
                         SELECT id FROM health_observations \
                         WHERE file_version_id = lf.current_version_id \
                         ORDER BY observed_at DESC, id DESC LIMIT 1) \
                     WHERE lf.vault_id = ?1 AND lf.lifecycle_state = 'active' ORDER BY lf.id",
                )?;
                let rows = s.query_map([v], |r| r.get::<_, String>(3))?;
                rows.map(|r| r.map_err(Into::into)).collect()
            })
            .await
    }
    /// Number of completed executor round trips (`call()` invocations) so
    /// far on this handle; a diagnostic/test counter, not a production
    /// dependency. See [`Self::reset_round_trip_count`].
    pub fn round_trip_count(&self) -> u64 {
        self.executor.round_trip_count()
    }
    /// Zeroes the round-trip counter, so a test/benchmark can measure just
    /// the calls made by one subsequent operation.
    pub fn reset_round_trip_count(&self) {
        self.executor.reset_round_trip_count()
    }
    pub async fn recovery_freshness(&self) -> Result<RecoveryFreshnessRecord, CatalogError> {
        let vault = self.vault_id.to_string();
        self.executor.call(move |x| {
            x.query_row("SELECT recovery_generation,recovery_export_generation,recovery_exported_at FROM vaults WHERE id=?1", [vault], |row| {
                Ok(RecoveryFreshnessRecord {
                    generation: u64::try_from(row.get::<_, i64>(0)?).map_err(|_| rusqlite::Error::InvalidQuery)?,
                    exported_generation: row.get::<_, Option<i64>>(1)?.map(|value| u64::try_from(value).map_err(|_| rusqlite::Error::InvalidQuery)).transpose()?,
                    exported_at: row.get(2)?,
                })
            }).map_err(Into::into)
        }).await
    }
    pub async fn bump_recovery_generation(&self) -> Result<u64, CatalogError> {
        let vault = self.vault_id.to_string();
        self.executor
            .call(move |x| {
                x.execute(
                    "UPDATE vaults SET recovery_generation=recovery_generation+1 WHERE id=?1",
                    [&vault],
                )?;
                x.query_row(
                    "SELECT recovery_generation FROM vaults WHERE id=?1",
                    [vault],
                    |row| row.get::<_, i64>(0),
                )
                .map(|value| u64::try_from(value).map_err(|_| CatalogError::InvalidState))?
            })
            .await
    }
    pub async fn record_recovery_export(
        &self,
        generation: u64,
        exported_at: &str,
    ) -> Result<(), CatalogError> {
        let vault = self.vault_id.to_string();
        let exported_at = exported_at.to_owned();
        self.executor.call(move |x| {
            let changed = x.execute("UPDATE vaults SET recovery_export_generation=?1,recovery_exported_at=?2 WHERE id=?3 AND recovery_generation=?1", params![i64::try_from(generation).map_err(|_| CatalogError::InvalidState)?, exported_at, vault])?;
            if changed == 0 {
                return Err(CatalogError::InvalidState);
            }
            Ok(())
        }).await
    }
    pub(crate) fn new(
        executor: CatalogExecutorHandle,
        vault_id: Uuid,
        catalog_field_subkey: CatalogFieldSubkey,
    ) -> Self {
        Self {
            executor,
            vault_id,
            catalog_field_subkey,
        }
    }
    fn enc(&self, e: EntityType, i: Uuid, f: FieldTag, v: &[u8]) -> Result<Vec<u8>, CatalogError> {
        field_envelope::encrypt_field(&self.catalog_field_subkey, self.vault_id, e, i, f, v)
            .map_err(Into::into)
    }
    pub async fn create_storage_target(
        &self,
        provider_kind: &str,
        config: &[u8],
        display_order: i64,
    ) -> Result<Uuid, CatalogError> {
        self.create_storage_target_with_profile(provider_kind, config, display_order, "none")
            .await
    }

    pub async fn create_storage_target_with_profile(
        &self,
        provider_kind: &str,
        config: &[u8],
        display_order: i64,
        oauth_application_profile: &str,
    ) -> Result<Uuid, CatalogError> {
        let id = Uuid::new_v4();
        let c = self.enc(
            EntityType::StorageTarget,
            id,
            FieldTag::ProviderConfig,
            config,
        )?;
        let v = self.vault_id.to_string();
        let k = provider_kind.to_owned();
        let p = oauth_application_profile.to_owned();
        let t = now();
        self.executor.call(move|x| { x.execute("INSERT INTO storage_targets (id,vault_id,provider_kind,config_envelope,display_order,created_at,oauth_application_profile,display_name_envelope) VALUES (?1,?2,?3,?4,?5,?6,?7,NULL)",params![id.to_string(),v,k,c,display_order,t,p])?; Ok(id) }).await
    }
    pub async fn load_storage_targets(&self) -> Result<Vec<StorageTargetRecord>, CatalogError> {
        let v = self.vault_id.to_string();
        let key = self.catalog_field_subkey.clone();
        let vault = self.vault_id;
        self.executor.call(move|x| { let mut s=x.prepare("SELECT id,provider_kind,config_envelope,display_order,oauth_application_profile,display_name_envelope FROM storage_targets WHERE vault_id=?1 ORDER BY display_order,id")?; let rows=s.query_map([v],|r| Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?,r.get::<_,Vec<u8>>(2)?,r.get::<_,i64>(3)?,r.get::<_,String>(4)?,r.get::<_,Option<Vec<u8>>>(5)?)))?; let mut out=Vec::new(); for r in rows { let (i,p,c,o,profile,name)=r?; let i=id(i)?; let c=field_envelope::decrypt_field(&key,vault,EntityType::StorageTarget,i,FieldTag::ProviderConfig,&c)?; let display_name=name.map(|v| field_envelope::decrypt_field(&key,vault,EntityType::StorageTarget,i,FieldTag::DisplayName,&v)).transpose()?.map(|v| String::from_utf8(v).map_err(|_|CatalogError::InvalidState)).transpose()?; out.push(StorageTargetRecord{id:i,provider_kind:p,config:c,display_order:o,oauth_application_profile:profile,display_name}); } Ok(out) }).await
    }

    pub async fn set_storage_target_display_name(
        &self,
        target: Uuid,
        name: &str,
    ) -> Result<(), CatalogError> {
        let value = name.trim();
        if value.is_empty() || value.chars().count() > 80 || value.chars().any(|c| c.is_control()) {
            return Err(CatalogError::InvalidState);
        }
        let envelope = self.enc(
            EntityType::StorageTarget,
            target,
            FieldTag::DisplayName,
            value.as_bytes(),
        )?;
        let vault = self.vault_id.to_string();
        self.executor.call(move |x| { let changed = x.execute("UPDATE storage_targets SET display_name_envelope=?1 WHERE id=?2 AND vault_id=?3", params![envelope, target.to_string(), vault])?; if changed == 0 { return Err(CatalogError::NotFound); } Ok(()) }).await
    }

    pub async fn create_activity_event(
        &self,
        event: NewActivityEvent,
    ) -> Result<Uuid, CatalogError> {
        let id = Uuid::new_v4();
        let metadata = self.enc(
            EntityType::ActivityEvent,
            id,
            FieldTag::Description,
            event.display_metadata.as_bytes(),
        )?;
        let vault = self.vault_id.to_string();
        self.executor.call(move |x| { x.execute("INSERT INTO activity_events (id,vault_id,operation_id,event_type,status,related_file_id,related_target_id,display_metadata_envelope,started_at,completed_at,transferred_bytes,error_code,retry_classification) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)", params![id.to_string(), vault, event.operation_id, event.event_type, event.status, event.related_file_id.map(|v|v.to_string()), event.related_target_id.map(|v|v.to_string()), metadata, event.started_at, event.completed_at, event.transferred_bytes.map(|v| i64::try_from(v).map_err(|_| CatalogError::InvariantViolation)).transpose()?, event.error_code, event.retry_classification])?; Ok(id) }).await
    }

    pub async fn list_activity_events(
        &self,
        cursor: Option<&str>,
        page_size: u32,
        event_type: Option<&str>,
        status: Option<&str>,
        started_after: Option<&str>,
        started_before: Option<&str>,
    ) -> Result<(Vec<ActivityEventRecord>, Option<String>), CatalogError> {
        let size = page_size.clamp(1, 100) as usize;
        let cursor = cursor.map(str::to_owned);
        let event_type = event_type.map(str::to_owned);
        let status = status.map(str::to_owned);
        let started_after = started_after.map(str::to_owned);
        let started_before = started_before.map(str::to_owned);
        let key = self.catalog_field_subkey.clone();
        let vault_id = self.vault_id;
        let vault = self.vault_id.to_string();
        self.executor.call(move |x| {
            let mut sql = String::from("SELECT id,operation_id,event_type,status,related_file_id,related_target_id,display_metadata_envelope,started_at,completed_at,transferred_bytes,error_code,retry_classification FROM activity_events WHERE vault_id=?1");
            let mut next = 2;
            if cursor.is_some() { sql.push_str(&format!(" AND (started_at < ?{} OR (started_at = ?{} AND id < ?{}))", next, next, next + 1)); next += 2; }
            if event_type.is_some() { sql.push_str(&format!(" AND event_type=?{}", next)); next += 1; }
            if status.is_some() { sql.push_str(&format!(" AND status=?{}", next)); next += 1; }
            if started_after.is_some() { sql.push_str(&format!(" AND started_at>=?{}", next)); next += 1; }
            if started_before.is_some() { sql.push_str(&format!(" AND started_at<=?{}", next)); next += 1; }
            sql.push_str(&format!(" ORDER BY started_at DESC,id DESC LIMIT ?{}", next));
            let mut statement = x.prepare(&sql)?;
            let mut binds: Vec<Box<dyn rusqlite::ToSql>> = vec![Box::new(vault)];
            if let Some(c) = &cursor { let mut parts=c.splitn(2,'|'); binds.push(Box::new(parts.next().unwrap_or_default().to_owned())); binds.push(Box::new(parts.next().unwrap_or_default().to_owned())); }
            if let Some(t) = event_type { binds.push(Box::new(t)); }
            if let Some(s) = status { binds.push(Box::new(s)); }
            if let Some(v) = started_after { binds.push(Box::new(v)); }
            if let Some(v) = started_before { binds.push(Box::new(v)); }
            binds.push(Box::new(size as i64));
            let params = rusqlite::params_from_iter(binds.iter().map(|v| v.as_ref()));
            let rows = statement.query_map(params, |r| Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?,r.get::<_,String>(2)?,r.get::<_,String>(3)?,r.get::<_,Option<String>>(4)?,r.get::<_,Option<String>>(5)?,r.get::<_,Vec<u8>>(6)?,r.get::<_,String>(7)?,r.get::<_,Option<String>>(8)?,r.get::<_,Option<i64>>(9)?,r.get::<_,Option<String>>(10)?,r.get::<_,Option<String>>(11)?)))?;
            let mut out=Vec::new(); for row in rows { let (i,op,typ,st,rf,rt,md,start,done,bytes,err,retry)=row?; let event_id=super::unlocked::id(i)?; out.push(ActivityEventRecord{id:event_id,vault_id,operation_id:op,event_type:typ,status:st,related_file_id:rf.map(super::unlocked::id).transpose()?,related_target_id:rt.map(super::unlocked::id).transpose()?,display_metadata:String::from_utf8(field_envelope::decrypt_field(&key,vault_id,EntityType::ActivityEvent,event_id,FieldTag::Description,&md)?).map_err(|_|CatalogError::InvalidState)?,started_at:start,completed_at:done,transferred_bytes:bytes.map(|v|u64::try_from(v).map_err(|_|CatalogError::InvalidState)).transpose()?,error_code:err,retry_classification:retry}); }
            let next = out.last().map(|v| format!("{}|{}", v.started_at, v.id)); Ok((out,next))
        }).await
    }

    pub async fn delete_storage_target(&self, target: Uuid) -> Result<(), CatalogError> {
        let vault = self.vault_id.to_string();
        self.executor
            .call(move |x| {
                let tx = x.transaction()?;
                tx.execute(
                    "DELETE FROM sync_job_objects WHERE storage_target_id=?1 AND vault_id=?2",
                    params![target.to_string(), vault.clone()],
                )?;
                tx.execute(
                    "DELETE FROM repair_jobs WHERE missing_storage_target_id=?1 OR source_storage_target_id=?1",
                    params![target.to_string()],
                )?;
                tx.execute(
                    "DELETE FROM replicas WHERE storage_target_id=?1",
                    params![target.to_string()],
                )?;
                let deleted = tx.execute(
                    "DELETE FROM storage_targets WHERE id=?1 AND vault_id=?2",
                    params![target.to_string(), vault],
                )?;
                if deleted == 0 {
                    return Err(CatalogError::InvariantViolation);
                }
                tx.commit()?;
                Ok(())
            })
            .await
    }

    pub async fn create_logical_folder(
        &self,
        parent: Option<Uuid>,
        name: &str,
    ) -> Result<Uuid, CatalogError> {
        let id = Uuid::new_v4();
        let n = self.enc(
            EntityType::LogicalFolder,
            id,
            FieldTag::Name,
            name.as_bytes(),
        )?;
        let v = self.vault_id;
        let p = parent.map(|x| x.to_string());
        let t = now();
        self.executor.call(move|x| { if let Some(p)=parent { ensure_uuid(x,"folders",p,v)?; } x.execute("INSERT INTO logical_folders (id,vault_id,parent_folder_id,name_envelope,created_at) VALUES (?1,?2,?3,?4,?5)",params![id.to_string(),v.to_string(),p,n,t])?; Ok(id) }).await
    }
    pub async fn list_logical_folders(&self) -> Result<Vec<LogicalFolderRecord>, CatalogError> {
        let v = self.vault_id.to_string();
        let key = self.catalog_field_subkey.clone();
        let vault = self.vault_id;
        self.executor.call(move|x| { let mut s=x.prepare("SELECT id,parent_folder_id,name_envelope FROM logical_folders WHERE vault_id=?1 ORDER BY parent_folder_id,id")?; let rows=s.query_map([v],|r|Ok((r.get::<_,String>(0)?,r.get::<_,Option<String>>(1)?,r.get::<_,Vec<u8>>(2)?)))?; let mut out=Vec::new(); for r in rows { let(i,p,n)=r?;let i=id(i)?;out.push(LogicalFolderRecord{id:i,parent_folder_id:p.map(id).transpose()?,name:String::from_utf8(field_envelope::decrypt_field(&key,vault,EntityType::LogicalFolder,i,FieldTag::Name,&n)?) .map_err(|_|CatalogError::InvalidState)?}); } Ok(out) }).await
    }
    pub async fn list_logical_files(&self) -> Result<Vec<LogicalFileRecord>, CatalogError> {
        let v = self.vault_id.to_string();
        let key = self.catalog_field_subkey.clone();
        let vault = self.vault_id;
        self.executor.call(move |x| {
            let mut s = x.prepare("SELECT id,folder_id,name_envelope,mime_envelope,current_version_id,lifecycle_state FROM logical_files WHERE vault_id=?1 AND lifecycle_state='active' ORDER BY id")?;
            let rows = s.query_map([v], |r| Ok((r.get::<_,String>(0)?, r.get::<_,Option<String>>(1)?, r.get::<_,Vec<u8>>(2)?, r.get::<_,Option<Vec<u8>>>(3)?, r.get::<_,Option<String>>(4)?, r.get::<_,String>(5)?)))?;
            rows.map(|r| {
                let (i, folder, name, mime, current, lifecycle_state) = r?;
                let i = id(i)?;
                Ok(LogicalFileRecord {
                    id: i,
                    folder_id: folder.map(id).transpose()?,
                    name: String::from_utf8(field_envelope::decrypt_field(&key, vault, EntityType::LogicalFile, i, FieldTag::Name, &name)?).map_err(|_| CatalogError::InvalidState)?,
                    mime: mime.map(|m| field_envelope::decrypt_field(&key, vault, EntityType::LogicalFile, i, FieldTag::Mime, &m)).transpose()?.map(String::from_utf8).transpose().map_err(|_| CatalogError::InvalidState)?,
                    current_version_id: current.map(id).transpose()?,
                    lifecycle_state,
                })
            }).collect()
        }).await
    }
    /// Single-round-trip listing: logical file metadata, current version
    /// size, and the latest durable health observation, batched in one
    /// query instead of two catalog round trips per file. Rows whose
    /// current version has no health observation yet report `None` for
    /// health fields; the caller falls back to a live protection-map
    /// lookup only for those.
    // (helper functions row_to_summary_tuple / summary_tuple_to_row are
    // defined at module scope below, shared by list_file_summary_rows,
    // list_file_summary_row, and list_file_summary_page.)
    /// Keyset-paginated form of [`Self::list_file_summary_rows`]: `after`
    /// is the last-seen `id` from the previous page (`None` for the first
    /// page), `limit` bounds the row count. Ordered by `lf.id` (already
    /// this table's primary key and the sort the unpaginated query uses),
    /// so pagination is stable under concurrent inserts/deletes elsewhere
    /// in the catalog -- a row's position never shifts relative to ids
    /// already returned, and a newly inserted row with a smaller id than
    /// `after` is correctly never reintroduced on a later page.
    pub async fn list_file_summary_page(
        &self,
        after: Option<Uuid>,
        limit: u32,
    ) -> Result<Vec<FileSummaryRow>, CatalogError> {
        let v = self.vault_id.to_string();
        let vault = self.vault_id;
        let key = self.catalog_field_subkey.clone();
        let after = after.map(|u| u.to_string());
        let limit = i64::from(limit);
        self.executor.call(move |x| {
            let base = "SELECT lf.id, lf.name_envelope, lf.mime_envelope, lf.current_version_id, \
                 fv.file_size, fv.chunk_count, ho.verified_replica_count, ho.required_replica_count, \
                 ho.observed_at, ho.health_state \
                 FROM logical_files lf \
                 LEFT JOIN file_versions fv ON fv.id = lf.current_version_id \
                 LEFT JOIN health_observations ho ON ho.id = ( \
                     SELECT id FROM health_observations \
                     WHERE file_version_id = lf.current_version_id \
                     ORDER BY observed_at DESC, id DESC LIMIT 1) \
                 WHERE lf.vault_id = ?1 AND lf.lifecycle_state = 'active'";
            let rows = if let Some(after) = &after {
                let sql = format!("{base} AND lf.id > ?2 ORDER BY lf.id LIMIT ?3");
                let mut s = x.prepare(&sql)?;
                let mapped = s
                    .query_map(params![v, after, limit], row_to_summary_tuple)?
                    .collect::<Result<Vec<_>, _>>()?;
                mapped
            } else {
                let sql = format!("{base} ORDER BY lf.id LIMIT ?2");
                let mut s = x.prepare(&sql)?;
                let mapped = s
                    .query_map(params![v, limit], row_to_summary_tuple)?
                    .collect::<Result<Vec<_>, _>>()?;
                mapped
            };
            rows.into_iter()
                .map(|row| summary_tuple_to_row(row, &key, vault))
                .collect()
        })
        .await
    }
    pub async fn list_file_summary_rows(&self) -> Result<Vec<FileSummaryRow>, CatalogError> {
        let v = self.vault_id.to_string();
        let vault = self.vault_id;
        let key = self.catalog_field_subkey.clone();
        self.executor.call(move |x| {
            let mut s = x.prepare(
                "SELECT lf.id, lf.name_envelope, lf.mime_envelope, lf.current_version_id, \
                 fv.file_size, fv.chunk_count, ho.verified_replica_count, ho.required_replica_count, \
                 ho.observed_at, ho.health_state \
                 FROM logical_files lf \
                 LEFT JOIN file_versions fv ON fv.id = lf.current_version_id \
                 LEFT JOIN health_observations ho ON ho.id = ( \
                     SELECT id FROM health_observations \
                     WHERE file_version_id = lf.current_version_id \
                     ORDER BY observed_at DESC, id DESC LIMIT 1) \
                 WHERE lf.vault_id = ?1 AND lf.lifecycle_state = 'active' ORDER BY lf.id",
            )?;
            let rows = s.query_map([v], row_to_summary_tuple)?;
            rows.map(|r| summary_tuple_to_row(r?, &key, vault)).collect()
        })
        .await
    }
    /// Single-file variant of [`Self::list_file_summary_rows`]: the same
    /// query narrowed to one logical file id, so a point lookup costs one
    /// indexed round trip instead of fetching (or client-side scanning)
    /// the entire vault listing.
    pub async fn list_file_summary_row(
        &self,
        file: Uuid,
    ) -> Result<Option<FileSummaryRow>, CatalogError> {
        let v = self.vault_id.to_string();
        let f = file.to_string();
        let vault = self.vault_id;
        let key = self.catalog_field_subkey.clone();
        self.executor.call(move |x| {
            let row = x
                .query_row(
                    "SELECT lf.id, lf.name_envelope, lf.mime_envelope, lf.current_version_id, \
                     fv.file_size, fv.chunk_count, ho.verified_replica_count, ho.required_replica_count, \
                     ho.observed_at, ho.health_state \
                     FROM logical_files lf \
                     LEFT JOIN file_versions fv ON fv.id = lf.current_version_id \
                     LEFT JOIN health_observations ho ON ho.id = ( \
                         SELECT id FROM health_observations \
                         WHERE file_version_id = lf.current_version_id \
                         ORDER BY observed_at DESC, id DESC LIMIT 1) \
                     WHERE lf.vault_id = ?1 AND lf.lifecycle_state = 'active' AND lf.id = ?2",
                    params![v, f],
                    row_to_summary_tuple,
                )
                .optional()?;
            let Some(row) = row else {
                return Ok(None);
            };
            summary_tuple_to_row(row, &key, vault).map(Some)
        }).await
    }
    pub async fn create_logical_file(
        &self,
        folder: Option<Uuid>,
        name: &str,
        mime: Option<&str>,
    ) -> Result<Uuid, CatalogError> {
        let id = Uuid::new_v4();
        let n = self.enc(EntityType::LogicalFile, id, FieldTag::Name, name.as_bytes())?;
        let m = match mime {
            Some(x) => Some(self.enc(EntityType::LogicalFile, id, FieldTag::Mime, x.as_bytes())?),
            None => None,
        };
        let v = self.vault_id;
        let f = folder.map(|x| x.to_string());
        let t = now();
        self.executor.call(move|x|{if let Some(f)=folder{ensure_uuid(x,"folders",f,v)?;}x.execute("INSERT INTO logical_files (id,vault_id,folder_id,name_envelope,mime_envelope,current_version_id,created_at) VALUES (?1,?2,?3,?4,?5,NULL,?6)",params![id.to_string(),v.to_string(),f,n,m,t])?;Ok(id)}).await
    }
    pub async fn load_logical_file(&self, file: Uuid) -> Result<LogicalFileRecord, CatalogError> {
        let v = self.vault_id.to_string();
        let key = self.catalog_field_subkey.clone();
        let vault = self.vault_id;
        self.executor.call(move|x|{let (f,n,m,c,state)=x.query_row("SELECT folder_id,name_envelope,mime_envelope,current_version_id,lifecycle_state FROM logical_files WHERE id=?1 AND vault_id=?2",params![file.to_string(),v],|r|Ok((r.get::<_,Option<String>>(0)?,r.get::<_,Vec<u8>>(1)?,r.get::<_,Option<Vec<u8>>>(2)?,r.get::<_,Option<String>>(3)?,r.get::<_,String>(4)?)))?;Ok(LogicalFileRecord{id:file,folder_id:f.map(id).transpose()?,name:String::from_utf8(field_envelope::decrypt_field(&key,vault,EntityType::LogicalFile,file,FieldTag::Name,&n)?).map_err(|_|CatalogError::InvalidState)?,mime:m.map(|b|field_envelope::decrypt_field(&key,vault,EntityType::LogicalFile,file,FieldTag::Mime,&b)).transpose()?.map(String::from_utf8).transpose().map_err(|_|CatalogError::InvalidState)?,current_version_id:c.map(id).transpose()?,lifecycle_state:state})}).await
    }

    pub async fn list_trashed_files(&self) -> Result<Vec<LogicalFileRecord>, CatalogError> {
        let v = self.vault_id.to_string();
        let key = self.catalog_field_subkey.clone();
        let vault = self.vault_id;
        self.executor.call(move |x| {
            let mut s = x.prepare("SELECT id,folder_id,name_envelope,mime_envelope,current_version_id,lifecycle_state FROM logical_files WHERE vault_id=?1 AND lifecycle_state<>'active' ORDER BY id")?;
            let rows = s.query_map([v], |r| Ok((r.get::<_,String>(0)?, r.get::<_,Option<String>>(1)?, r.get::<_,Vec<u8>>(2)?, r.get::<_,Option<Vec<u8>>>(3)?, r.get::<_,Option<String>>(4)?, r.get::<_,String>(5)?)))?;
            rows.map(|r| {
                let (i, folder, name, mime, current, lifecycle_state) = r?;
                let i = id(i)?;
                Ok(LogicalFileRecord {
                    id: i,
                    folder_id: folder.map(id).transpose()?,
                    name: String::from_utf8(field_envelope::decrypt_field(&key, vault, EntityType::LogicalFile, i, FieldTag::Name, &name)?).map_err(|_| CatalogError::InvalidState)?,
                    mime: mime.map(|m| field_envelope::decrypt_field(&key, vault, EntityType::LogicalFile, i, FieldTag::Mime, &m)).transpose()?.map(String::from_utf8).transpose().map_err(|_| CatalogError::InvalidState)?,
                    current_version_id: current.map(id).transpose()?,
                    lifecycle_state,
                })
            }).collect()
        }).await
    }
    pub async fn count_file_replicas(&self, file: Uuid) -> Result<u32, CatalogError> {
        let vault = self.vault_id;
        self.executor.call(move |x| { let count:i64=x.query_row("SELECT COUNT(*) FROM replicas r JOIN file_versions v ON v.id=r.file_version_id WHERE v.logical_file_id=?1 AND v.vault_id=?2",params![file.to_string(),vault.to_string()],|r|r.get(0))?; u32::try_from(count).map_err(|_|CatalogError::InvalidState) }).await
    }

    pub async fn move_file_to_trash(
        &self,
        file: Uuid,
        deletion: Uuid,
        operation_id: &str,
        purge_after: Option<&str>,
    ) -> Result<(), CatalogError> {
        let vault = self.vault_id;
        let op = operation_id.to_owned();
        let purge = purge_after.map(str::to_owned);
        self.executor.call(move |x| {
            let tx = x.transaction()?;
            let state: String = tx.query_row("SELECT lifecycle_state FROM logical_files WHERE id=?1 AND vault_id=?2", params![file.to_string(), vault.to_string()], |r| r.get(0))?;
            if state != "active" {
                return Err(CatalogError::InvalidState);
            }
            let timestamp = now();
            let lifecycle = if purge.is_some() { "purge_scheduled" } else { "trashed" };
            tx.execute("UPDATE logical_files SET lifecycle_state=?3 WHERE id=?1 AND vault_id=?2 AND lifecycle_state='active'", params![file.to_string(), vault.to_string(), lifecycle])?;
            let job_state = if purge.is_some() { "purge_scheduled" } else { "trashed" };
            tx.execute("INSERT INTO deletion_jobs (id,vault_id,logical_file_id,mode,trashed_at,purge_after,operation_id,state,retry_classification,incident_code,created_at,updated_at) VALUES (?1,?2,?3,'trash',?4,?5,?6,?7,NULL,NULL,?4,?4)", params![deletion.to_string(), vault.to_string(), file.to_string(), timestamp, purge, op, job_state])?;
            tx.commit()?;
            Ok(())
        }).await
    }

    pub async fn restore_file_from_trash(&self, file: Uuid) -> Result<(), CatalogError> {
        let vault = self.vault_id;
        self.executor.call(move |x| {
            let tx = x.transaction()?;
            let state: String = tx.query_row("SELECT lifecycle_state FROM logical_files WHERE id=?1 AND vault_id=?2", params![file.to_string(), vault.to_string()], |r| r.get(0))?;
            if state == "active" {
                return Ok(());
            }
            let job: (String, String) = tx.query_row("SELECT id,state FROM deletion_jobs WHERE logical_file_id=?1 AND vault_id=?2 ORDER BY updated_at DESC,id DESC LIMIT 1", params![file.to_string(), vault.to_string()], |r| Ok((r.get(0)?, r.get(1)?)))?;
            if matches!(job.1.as_str(), "purge_planned" | "deleting" | "delete_incomplete" | "purged") {
                return Err(CatalogError::InvalidState);
            }
            tx.execute("UPDATE logical_files SET lifecycle_state='active' WHERE id=?1 AND vault_id=?2", params![file.to_string(), vault.to_string()])?;
            tx.execute("UPDATE deletion_jobs SET state='cancelled',updated_at=?1 WHERE id=?2 AND vault_id=?3", params![now(), job.0, vault.to_string()])?;
            tx.commit()?;
            Ok(())
        }).await
    }

    pub async fn plan_permanent_deletion(
        &self,
        file: Uuid,
        deletion: Uuid,
        operation_id: &str,
    ) -> Result<(), CatalogError> {
        let vault = self.vault_id;
        let op = operation_id.to_owned();
        let key = self.catalog_field_subkey.clone();
        self.executor.call(move |x| {
            let tx = x.transaction()?;
            let state: String = tx.query_row("SELECT lifecycle_state FROM logical_files WHERE id=?1 AND vault_id=?2", params![file.to_string(), vault.to_string()], |r| r.get(0))?;
            if !matches!(state.as_str(), "trashed" | "purge_scheduled" | "purge_planned" | "deleting" | "delete_incomplete") {
                return Err(CatalogError::InvalidState);
            }
            if let Ok(existing) = tx.query_row("SELECT state FROM deletion_jobs WHERE logical_file_id=?1 AND vault_id=?2 AND mode='permanent' AND state NOT IN ('purged','cancelled') ORDER BY updated_at DESC,id DESC LIMIT 1", params![file.to_string(), vault.to_string()], |r| r.get::<_, String>(0)) {
                if matches!(existing.as_str(), "purge_planned" | "deleting" | "delete_incomplete") {
                    return Ok(());
                }
            }
            let timestamp = now();
            tx.execute("INSERT INTO deletion_jobs (id,vault_id,logical_file_id,mode,trashed_at,purge_after,operation_id,state,retry_classification,incident_code,created_at,updated_at) SELECT ?1,?2,?3,'permanent',trashed_at,NULL,?4,'purge_planned',NULL,NULL,?5,?5 FROM deletion_jobs WHERE logical_file_id=?3 AND vault_id=?2 AND state IN ('trashed','purge_scheduled') ORDER BY updated_at DESC,id DESC LIMIT 1", params![deletion.to_string(), vault.to_string(), file.to_string(), op, timestamp])?;
            if tx.changes() == 0 {
                return Err(CatalogError::InvariantViolation);
            }
            let mut query = tx.prepare("SELECT v.id,r.id,r.storage_target_id,r.object_kind,r.locator_envelope FROM file_versions v JOIN replicas r ON r.file_version_id=v.id WHERE v.logical_file_id=?1 AND v.vault_id=?2 ORDER BY v.id,r.id")?;
            let rows = query.query_map(params![file.to_string(), vault.to_string()], |r| Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?,r.get::<_,String>(2)?,r.get::<_,String>(3)?,r.get::<_,Vec<u8>>(4)?)))?;
            for row in rows {
                let (version, replica, target, kind, locator) = row?;
                let item = Uuid::new_v4();
                let plain = field_envelope::decrypt_field(&key, vault, EntityType::Replica, Uuid::parse_str(&replica).map_err(|_| CatalogError::InvalidState)?, FieldTag::ProviderLocator, &locator)?;
                let copied = field_envelope::encrypt_field(&key, vault, EntityType::Replica, item, FieldTag::ProviderLocator, &plain)?;
                tx.execute("INSERT INTO deletion_items (id,deletion_id,file_version_id,replica_id,storage_target_id,object_kind,locator_envelope,state,provider_result,retry_count,next_retry_at,confirmed_deleted_at) VALUES (?1,?2,?3,?4,?5,?6,?7,'pending',NULL,0,NULL,NULL)", params![item.to_string(), deletion.to_string(), version, replica, target, kind, copied])?;
            }
            drop(query);
            tx.execute("UPDATE logical_files SET lifecycle_state='purge_planned' WHERE id=?1 AND vault_id=?2", params![file.to_string(), vault.to_string()])?;
            tx.commit()?;
            Ok(())
        }).await
    }

    pub async fn destroy_file_keys_and_start_deletion(
        &self,
        deletion: Uuid,
    ) -> Result<(), CatalogError> {
        let vault = self.vault_id;
        self.executor.call(move |x| {
            let tx = x.transaction()?;
            let file: String = tx.query_row("SELECT logical_file_id FROM deletion_jobs WHERE id=?1 AND vault_id=?2 AND state='purge_planned'", params![deletion.to_string(), vault.to_string()], |r| r.get(0))?;
            tx.execute("DELETE FROM wrapped_file_keys WHERE file_version_id IN (SELECT id FROM file_versions WHERE logical_file_id=?1 AND vault_id=?2)", params![file, vault.to_string()])?;
            tx.execute("UPDATE deletion_jobs SET state='deleting',updated_at=?1 WHERE id=?2 AND vault_id=?3", params![now(), deletion.to_string(), vault.to_string()])?;
            tx.execute("UPDATE logical_files SET lifecycle_state='deleting' WHERE id=?1 AND vault_id=?2", params![file, vault.to_string()])?;
            tx.commit()?;
            Ok(())
        }).await
    }

    pub async fn list_deletion_items(
        &self,
        deletion: Uuid,
    ) -> Result<Vec<DeletionItemRecord>, CatalogError> {
        let vault = self.vault_id;
        let key = self.catalog_field_subkey.clone();
        self.executor.call(move |x| {
            let mut s = x.prepare("SELECT i.id,i.deletion_id,i.file_version_id,i.replica_id,i.storage_target_id,i.object_kind,i.locator_envelope,i.state,i.provider_result,i.retry_count,i.next_retry_at,i.confirmed_deleted_at FROM deletion_items i JOIN deletion_jobs d ON d.id=i.deletion_id WHERE i.deletion_id=?1 AND d.vault_id=?2 ORDER BY i.id")?;
            let rows = s.query_map(params![deletion.to_string(), vault.to_string()], |r| Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?,r.get::<_,String>(2)?,r.get::<_,String>(3)?,r.get::<_,String>(4)?,r.get::<_,String>(5)?,r.get::<_,Vec<u8>>(6)?,r.get::<_,String>(7)?,r.get::<_,Option<String>>(8)?,r.get::<_,i64>(9)?,r.get::<_,Option<String>>(10)?,r.get::<_,Option<String>>(11)?)))?;
            rows.map(|row| { let (i,d,v,r,t,k,l,s,p,c,n,done)=row?; let id_value=id(i)?; Ok(DeletionItemRecord{id:id_value,deletion_id:id(d)?,file_version_id:id(v)?,replica_id:id(r)?,storage_target_id:id(t)?,object_kind:ObjectKind::parse(&k)?,locator:String::from_utf8(field_envelope::decrypt_field(&key,vault,EntityType::Replica,id_value,FieldTag::ProviderLocator,&l)?).map_err(|_|CatalogError::InvalidState)?,state:s,provider_result:p,retry_count:u32::try_from(c).map_err(|_|CatalogError::InvalidState)?,next_retry_at:n,confirmed_deleted_at:done}) }).collect()
        }).await
    }

    pub async fn is_deletion_item_shared(&self, item: Uuid) -> Result<bool, CatalogError> {
        let vault = self.vault_id;
        let key = self.catalog_field_subkey.clone();
        self.executor.call(move |x| {
            let (replica, target, kind, locator): (String, String, String, Vec<u8>) = x.query_row(
                "SELECT replica_id,storage_target_id,object_kind,locator_envelope FROM deletion_items WHERE id=?1 AND deletion_id IN (SELECT id FROM deletion_jobs WHERE vault_id=?2)",
                params![item.to_string(), vault.to_string()],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )?;
            let replica_id = id(replica)?;
            let wanted = field_envelope::decrypt_field(&key, vault, EntityType::Replica, item, FieldTag::ProviderLocator, &locator)?;
            let mut statement = x.prepare("SELECT id,locator_envelope FROM replicas WHERE storage_target_id=?1 AND object_kind=?2 AND id<>?3")?;
            let mut rows = statement.query(params![target, kind, replica_id.to_string()])?;
            while let Some(row) = rows.next()? {
                let other = id(row.get::<_, String>(0)?)?;
                let envelope: Vec<u8> = row.get(1)?;
                let value = field_envelope::decrypt_field(&key, vault, EntityType::Replica, other, FieldTag::ProviderLocator, &envelope)?;
                if value == wanted { return Ok(true); }
            }
            Ok(false)
        }).await
    }

    pub async fn load_deletion_job(
        &self,
        deletion: Uuid,
    ) -> Result<DeletionJobRecord, CatalogError> {
        let vault = self.vault_id;
        self.executor.call(move |x| { let row=x.query_row("SELECT logical_file_id,mode,trashed_at,purge_after,operation_id,state,retry_classification,incident_code,created_at,updated_at FROM deletion_jobs WHERE id=?1 AND vault_id=?2",params![deletion.to_string(),vault.to_string()],|r|Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?,r.get::<_,String>(2)?,r.get::<_,Option<String>>(3)?,r.get::<_,String>(4)?,r.get::<_,String>(5)?,r.get::<_,Option<String>>(6)?,r.get::<_,Option<String>>(7)?,r.get::<_,String>(8)?,r.get::<_,String>(9)?)))?; Ok(DeletionJobRecord{id:deletion,logical_file_id:id(row.0)?,mode:row.1,trashed_at:row.2,purge_after:row.3,operation_id:row.4,state:row.5,retry_classification:row.6,incident_code:row.7,created_at:row.8,updated_at:row.9}) }).await
    }

    pub async fn list_deletion_jobs(&self) -> Result<Vec<DeletionJobRecord>, CatalogError> {
        let vault = self.vault_id;
        self.executor.call(move |x| { let mut s=x.prepare("SELECT id,logical_file_id,mode,trashed_at,purge_after,operation_id,state,retry_classification,incident_code,created_at,updated_at FROM deletion_jobs WHERE vault_id=?1 AND state NOT IN ('purged','cancelled') ORDER BY updated_at,id")?; let rows=s.query_map([vault.to_string()],|r|Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?,r.get::<_,String>(2)?,r.get::<_,String>(3)?,r.get::<_,Option<String>>(4)?,r.get::<_,String>(5)?,r.get::<_,String>(6)?,r.get::<_,Option<String>>(7)?,r.get::<_,Option<String>>(8)?,r.get::<_,String>(9)?,r.get::<_,String>(10)?)))?; rows.map(|r|{let(i,f,m,t,p,o,s,re,inc,c,u)=r?;Ok(DeletionJobRecord{id:id(i)?,logical_file_id:id(f)?,mode:m,trashed_at:t,purge_after:p,operation_id:o,state:s,retry_classification:re,incident_code:inc,created_at:c,updated_at:u})}).collect() }).await
    }

    pub async fn set_deletion_item_result(
        &self,
        item: Uuid,
        state: &str,
        result: Option<&str>,
        retry_count: u32,
        next_retry_at: Option<&str>,
    ) -> Result<(), CatalogError> {
        let vault = self.vault_id.to_string();
        let state = state.to_owned();
        let result = result.map(str::to_owned);
        let next = next_retry_at.map(str::to_owned);
        self.executor.call(move |x| { let changed=x.execute("UPDATE deletion_items SET state=?1,provider_result=?2,retry_count=?3,next_retry_at=?4,confirmed_deleted_at=CASE WHEN ?1='deleted' THEN ?5 ELSE confirmed_deleted_at END WHERE id=?6 AND deletion_id IN (SELECT id FROM deletion_jobs WHERE vault_id=?7)",params![state,result,i64::from(retry_count),next,now(),item.to_string(),vault])?; if changed==0{return Err(CatalogError::NotFound)} Ok(()) }).await
    }

    pub async fn set_deletion_job_state(
        &self,
        deletion: Uuid,
        state: &str,
        retry: Option<&str>,
        incident: Option<&str>,
    ) -> Result<(), CatalogError> {
        let vault = self.vault_id.to_string();
        let state = state.to_owned();
        let retry = retry.map(str::to_owned);
        let incident = incident.map(str::to_owned);
        self.executor.call(move |x| { let n=x.execute("UPDATE deletion_jobs SET state=?1,retry_classification=?2,incident_code=?3,updated_at=?4 WHERE id=?5 AND vault_id=?6",params![state,retry,incident,now(),deletion.to_string(),vault])?; if n==0{return Err(CatalogError::NotFound)} Ok(()) }).await
    }

    pub async fn complete_deletion_if_ready(&self, deletion: Uuid) -> Result<bool, CatalogError> {
        let vault = self.vault_id;
        self.executor.call(move |x| { let tx=x.transaction()?; let (file,pending):(String,i64)=tx.query_row("SELECT logical_file_id,(SELECT COUNT(*) FROM deletion_items WHERE deletion_id=?1 AND state NOT IN ('deleted','shared')) FROM deletion_jobs WHERE id=?1 AND vault_id=?2",params![deletion.to_string(),vault.to_string()],|r|Ok((r.get(0)?,r.get(1)?)))?; if pending!=0 { tx.execute("UPDATE deletion_jobs SET state='delete_incomplete',retry_classification=COALESCE((SELECT provider_result FROM deletion_items WHERE deletion_id=?2 AND state NOT IN ('deleted','shared') AND provider_result IS NOT NULL ORDER BY retry_count DESC,id LIMIT 1),retry_classification),updated_at=?1 WHERE id=?2 AND vault_id=?3",params![now(),deletion.to_string(),vault.to_string()])?; tx.commit()?; return Ok(false); } tx.execute("DELETE FROM logical_files WHERE id=?1 AND vault_id=?2",params![file,vault.to_string()])?; tx.execute("DELETE FROM deletion_items WHERE deletion_id=?1",params![deletion.to_string()])?; tx.execute("UPDATE deletion_jobs SET state='purged',updated_at=?1 WHERE id=?2 AND vault_id=?3",params![now(),deletion.to_string(),vault.to_string()])?; tx.commit()?; Ok(true) }).await
    }

    pub async fn create_file_version(
        &self,
        file: Uuid,
        size: u64,
        chunks: u32,
        hash: [u8; 32],
    ) -> Result<Uuid, CatalogError> {
        let id = Uuid::new_v4();
        let v = self.vault_id;
        let t = now();
        self.executor.call(move|x|{ensure_uuid(x,"files",file,v)?;x.execute("INSERT INTO file_versions (id,logical_file_id,vault_id,file_size,chunk_count,content_hash,state,created_at) VALUES (?1,?2,?3,?4,?5,?6,'pending',?7)",params![id.to_string(),file.to_string(),v.to_string(),i64::try_from(size).map_err(|_|CatalogError::InvariantViolation)?,i64::from(chunks),hash.to_vec(),t])?;Ok(id)}).await
    }
    pub async fn load_file_version(
        &self,
        version: Uuid,
    ) -> Result<FileVersionRecord, CatalogError> {
        let v = self.vault_id.to_string();
        self.executor.call(move|x|{let(f,s,c,h,st)=x.query_row("SELECT logical_file_id,file_size,chunk_count,content_hash,state FROM file_versions WHERE id=?1 AND vault_id=?2",params![version.to_string(),v],|r|Ok((r.get::<_,String>(0)?,r.get::<_,i64>(1)?,r.get::<_,i64>(2)?,r.get::<_,Vec<u8>>(3)?,r.get::<_,String>(4)?)))?;if !valid_job_state(&st)&&st!="healthy"{return Err(CatalogError::InvalidState)};Ok(FileVersionRecord{id:version,logical_file_id:id(f)?,file_size:u64::try_from(s).map_err(|_|CatalogError::InvalidState)?,chunk_count:u32::try_from(c).map_err(|_|CatalogError::InvalidState)?,content_hash:h,state:st})}).await
    }
    pub async fn ensure_version_active(&self, version: Uuid) -> Result<(), CatalogError> {
        let vault = self.vault_id;
        self.executor.call(move |x| { let state:String=x.query_row("SELECT f.lifecycle_state FROM logical_files f JOIN file_versions v ON v.logical_file_id=f.id WHERE v.id=?1 AND f.vault_id=?2",params![version.to_string(),vault.to_string()],|r|r.get(0))?; if state!="active" { return Err(CatalogError::InvalidState); } Ok(()) }).await
    }
    pub async fn store_wrapped_file_keys(
        &self,
        version: Uuid,
        dek: &WrappedFileKey,
        manifest: &WrappedFileKey,
    ) -> Result<(), CatalogError> {
        if dek.key_type != FileKeyType::Dek || manifest.key_type != FileKeyType::ManifestKey {
            return Err(CatalogError::InvariantViolation);
        }
        let v = self.vault_id.to_string();
        let d = dek.clone();
        let m = manifest.clone();
        self.executor.call(move|x|{ensure_uuid(x,"versions",version,Uuid::parse_str(&v).map_err(|_|CatalogError::InvariantViolation)?)?;x.execute("INSERT INTO wrapped_file_keys (file_version_id,dek_key_type,dek_nonce,dek_ciphertext,manifest_key_key_type,manifest_key_nonce,manifest_key_ciphertext) VALUES (?1,?2,?3,?4,?5,?6,?7)",params![version.to_string(),d.key_type as u8,d.nonce.to_vec(),d.ciphertext,m.key_type as u8,m.nonce.to_vec(),m.ciphertext])?;Ok(())}).await
    }
    pub async fn load_wrapped_file_keys(
        &self,
        version: Uuid,
    ) -> Result<(WrappedFileKey, WrappedFileKey), CatalogError> {
        let v = self.vault_id.to_string();
        self.executor.call(move|x|{let(dn,dc,mn,mc,dt,mt) = x.query_row("SELECT dek_nonce,dek_ciphertext,manifest_key_nonce,manifest_key_ciphertext,dek_key_type,manifest_key_key_type FROM wrapped_file_keys k JOIN file_versions f ON f.id=k.file_version_id WHERE k.file_version_id=?1 AND f.vault_id=?2",params![version.to_string(),v],|r|Ok((r.get::<_,Vec<u8>>(0)?,r.get::<_,Vec<u8>>(1)?,r.get::<_,Vec<u8>>(2)?,r.get::<_,Vec<u8>>(3)?,r.get::<_,i64>(4)?,r.get::<_,i64>(5)?)))?;Ok((WrappedFileKey{key_type:if dt==1{FileKeyType::Dek}else{return Err(CatalogError::InvalidState)},nonce:dn.try_into().map_err(|_|CatalogError::InvalidState)?,ciphertext:dc},WrappedFileKey{key_type:if mt==2{FileKeyType::ManifestKey}else{return Err(CatalogError::InvalidState)},nonce:mn.try_into().map_err(|_|CatalogError::InvalidState)?,ciphertext:mc}))}).await
    }

    pub async fn create_chunk(&self, version: Uuid, index: u32) -> Result<Uuid, CatalogError> {
        let id = Uuid::new_v4();
        let v = self.vault_id;
        self.executor
            .call(move |x| {
                ensure_uuid(x, "versions", version, v)?;
                x.execute(
                    "INSERT INTO chunks (id,file_version_id,chunk_index) VALUES (?1,?2,?3)",
                    params![id.to_string(), version.to_string(), i64::from(index)],
                )?;
                Ok(id)
            })
            .await
    }
    pub async fn update_file_version_metadata(
        &self,
        version: Uuid,
        file_size: u64,
        chunk_count: u32,
        content_hash: [u8; 32],
    ) -> Result<(), CatalogError> {
        let v = self.vault_id;
        self.executor.call(move |x| {
            ensure_uuid(x, "versions", version, v)?;
            x.execute(
                "UPDATE file_versions SET file_size=?1,chunk_count=?2,content_hash=?3 WHERE id=?4 AND vault_id=?5",
                params![i64::try_from(file_size).map_err(|_| CatalogError::InvariantViolation)?, i64::from(chunk_count), content_hash.to_vec(), version.to_string(), v.to_string()],
            )?;
            Ok(())
        }).await
    }
    pub async fn replace_password_envelope(
        &self,
        envelope: &PasswordEnvelope,
    ) -> Result<(), CatalogError> {
        let v = self.vault_id.to_string();
        let envelope = envelope.clone();
        self.executor.call(move |x| {
            let tx = x.transaction()?;
            tx.execute(
                "UPDATE key_envelopes SET envelope_version=?1,salt=?2,m_cost=?3,t_cost=?4,p_cost=?5,nonce=?6,ciphertext=?7 WHERE vault_id=?8",
                params![i64::from(envelope.envelope_version), envelope.salt.to_vec(), i64::from(envelope.m_cost), i64::from(envelope.t_cost), i64::from(envelope.p_cost), envelope.nonce.to_vec(), envelope.ciphertext, v],
            )?;
            tx.commit()?;
            Ok(())
        }).await
    }
    pub async fn create_replica(
        &self,
        version: Uuid,
        chunk: Option<Uuid>,
        target: Uuid,
        kind: ObjectKind,
        locator: &str,
    ) -> Result<Uuid, CatalogError> {
        if (kind == ObjectKind::Chunk) != chunk.is_some() {
            return Err(CatalogError::InvariantViolation);
        }
        let id = Uuid::new_v4();
        let l = self.enc(
            EntityType::Replica,
            id,
            FieldTag::ProviderLocator,
            locator.as_bytes(),
        )?;
        let v = self.vault_id;
        self.executor.call(move |x| {
            ensure_uuid(x, "versions", version, v)?;
            ensure_uuid(x, "targets", target, v)?;
            if let Some(c) = chunk {
                x.query_row(
                    "SELECT 1 FROM chunks c JOIN file_versions f ON f.id=c.file_version_id WHERE c.id=?1 AND f.vault_id=?2",
                    params![c.to_string(), v.to_string()],
                    |_| Ok(()),
                )
                .map_err(|_| CatalogError::InvariantViolation)?;
            }
            if let Ok(existing) = x.query_row(
                "SELECT id FROM replicas WHERE file_version_id=?1 AND storage_target_id=?2 AND object_kind=?3 AND ((chunk_id IS NULL AND ?4 IS NULL) OR chunk_id=?4)",
                params![version.to_string(), target.to_string(), kind.as_str(), chunk.map(|x| x.to_string())],
                |r| r.get::<_, String>(0),
            ) {
                return Uuid::parse_str(&existing).map_err(|_| CatalogError::InvalidState);
            }
            x.execute(
                "INSERT INTO replicas (id,chunk_id,file_version_id,storage_target_id,object_kind,locator_envelope,state,last_verified_at) VALUES (?1,?2,?3,?4,?5,?6,'pending',NULL)",
                params![id.to_string(), chunk.map(|x| x.to_string()), version.to_string(), target.to_string(), kind.as_str(), l],
            )?;
            Ok(id)
        }).await
    }
    pub async fn set_replica_state(
        &self,
        replica: Uuid,
        state: ReplicaState,
    ) -> Result<(), CatalogError> {
        let v = self.vault_id.to_string();
        self.executor.call(move|x|{let n=x.execute("UPDATE replicas SET state=?1,last_verified_at=CASE WHEN ?1='verified' THEN ?3 ELSE last_verified_at END WHERE id=?2 AND file_version_id IN (SELECT id FROM file_versions WHERE vault_id=?4)",params![state.as_str(),replica.to_string(),now(),v])?;if n==0{Err(CatalogError::InvariantViolation)}else{Ok(())}}).await
    }
    pub async fn update_replica_locator(
        &self,
        replica: Uuid,
        locator: &str,
    ) -> Result<(), CatalogError> {
        let envelope = self.enc(
            EntityType::Replica,
            replica,
            FieldTag::ProviderLocator,
            locator.as_bytes(),
        )?;
        let vault = self.vault_id.to_string();
        self.executor.call(move |x| {
            let n = x.execute("UPDATE replicas SET locator_envelope=?1 WHERE id=?2 AND file_version_id IN (SELECT id FROM file_versions WHERE vault_id=?3)", params![envelope, replica.to_string(), vault])?;
            if n == 0 { Err(CatalogError::InvariantViolation) } else { Ok(()) }
        }).await
    }

    pub async fn create_sync_job(
        &self,
        version: Option<Uuid>,
        kind: JobKind,
        key: &str,
    ) -> Result<Uuid, CatalogError> {
        let id = Uuid::new_v4();
        let v = self.vault_id;
        let k = key.to_owned();
        let t = now();
        self.executor.call(move|x|{if let Some(ver)=version{ensure_uuid(x,"versions",ver,v)?;}x.execute("INSERT INTO sync_jobs (id,vault_id,file_version_id,job_kind,state,idempotency_key,created_at,updated_at) VALUES (?1,?2,?3,?4,'pending',?5,?6,?6)",params![id.to_string(),v.to_string(),version.map(|x|x.to_string()),kind.as_str(),k,t])?;Ok(id)}).await
    }
    pub async fn find_sync_job_by_idempotency_key(
        &self,
        key: &str,
    ) -> Result<Option<SyncJobRecord>, CatalogError> {
        let v = self.vault_id.to_string();
        let k = key.to_owned();
        self.executor.call(move|x|{let r=x.query_row("SELECT id,file_version_id,job_kind,state,idempotency_key FROM sync_jobs WHERE idempotency_key=?1 AND vault_id=?2",params![k,v],|r|Ok((r.get::<_,String>(0)?,r.get::<_,Option<String>>(1)?,r.get::<_,String>(2)?,r.get::<_,String>(3)?,r.get::<_,String>(4)?)));match r{Ok((i,f,j,s,k))=>Ok(Some(SyncJobRecord{id:id(i)?,file_version_id:f.map(id).transpose()?,job_kind:JobKind::parse(&j)?,state:s,idempotency_key:k})),Err(rusqlite::Error::QueryReturnedNoRows)=>Ok(None),Err(e)=>Err(e.into())}}).await
    }
    /// Atomically reclaims a job that previously failed outright, flipping it back to "pending" only if still "failed"; if two retries race, only one `UPDATE` matches the guard and returns `true`, the loser sees `false` and must treat the key as a live duplicate.
    pub async fn reclaim_failed_sync_job(&self, job: Uuid) -> Result<bool, CatalogError> {
        let v = self.vault_id.to_string();
        self.executor
            .call(move |x| {
                let n = x.execute(
                    "UPDATE sync_jobs SET state='pending',file_version_id=NULL,updated_at=?1 WHERE id=?2 AND vault_id=?3 AND state='failed'",
                    params![now(), job.to_string(), v],
                )?;
                Ok(n > 0)
            })
            .await
    }
    pub async fn set_sync_job_state(&self, job: Uuid, state: &str) -> Result<(), CatalogError> {
        if !valid_job_state(state) {
            return Err(CatalogError::InvalidState);
        }
        let v = self.vault_id.to_string();
        let s = state.to_owned();
        self.executor
            .call(move |x| {
                let n = x.execute(
                    "UPDATE sync_jobs SET state=?1,updated_at=?2 WHERE id=?3 AND vault_id=?4",
                    params![s, now(), job.to_string(), v],
                )?;
                if n == 0 {
                    Err(CatalogError::InvariantViolation)
                } else {
                    Ok(())
                }
            })
            .await
    }
    pub async fn list_sync_jobs(&self) -> Result<Vec<SyncJobRecord>, CatalogError> {
        let v = self.vault_id.to_string();
        self.executor.call(move |x| {
            let mut s = x.prepare("SELECT id,file_version_id,job_kind,state,idempotency_key FROM sync_jobs WHERE vault_id=?1 ORDER BY created_at,id")?;
            let rows = s.query_map([v], |r| Ok((r.get::<_,String>(0)?, r.get::<_,Option<String>>(1)?, r.get::<_,String>(2)?, r.get::<_,String>(3)?, r.get::<_,String>(4)?)))?;
            rows.map(|r| { let (i,f,j,state,key)=r?; Ok(SyncJobRecord{id:id(i)?,file_version_id:f.map(id).transpose()?,job_kind:JobKind::parse(&j)?,state,idempotency_key:key}) }).collect()
        }).await
    }
    pub async fn record_sync_job_object(
        &self,
        job: Uuid,
        target: Uuid,
        kind: ObjectKind,
        chunk_index: Option<u32>,
        locator: &str,
    ) -> Result<Uuid, CatalogError> {
        let id = Uuid::new_v4();
        let envelope = self.enc(
            EntityType::Replica,
            id,
            FieldTag::ProviderLocator,
            locator.as_bytes(),
        )?;
        let vault = self.vault_id;
        self.executor.call(move |x| {
            ensure_uuid(x, "targets", target, vault)?;
            x.execute("INSERT INTO sync_job_objects (id,sync_job_id,vault_id,storage_target_id,object_kind,chunk_index,locator_envelope,state) SELECT ?1,?2,?3,?4,?5,?6,?7,'pending' WHERE EXISTS (SELECT 1 FROM sync_jobs WHERE id=?2 AND vault_id=?3)", params![id.to_string(),job.to_string(),vault.to_string(),target.to_string(),kind.as_str(),chunk_index.map(i64::from),envelope])?;
            if x.changes() == 0 { return Err(CatalogError::NotFound); }
            Ok(id)
        }).await
    }
    pub async fn list_sync_job_objects(
        &self,
        job: Uuid,
    ) -> Result<Vec<SyncJobObjectRecord>, CatalogError> {
        let vault = self.vault_id;
        let key = self.catalog_field_subkey.clone();
        self.executor.call(move |x| {
            let mut s = x.prepare("SELECT id,sync_job_id,storage_target_id,object_kind,chunk_index,locator_envelope,state FROM sync_job_objects WHERE sync_job_id=?1 AND vault_id=?2 AND state='pending' ORDER BY id")?;
            let rows = s.query_map(params![job.to_string(),vault.to_string()], |r| Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?,r.get::<_,String>(2)?,r.get::<_,String>(3)?,r.get::<_,Option<i64>>(4)?,r.get::<_,Vec<u8>>(5)?,r.get::<_,String>(6)?)))?;
            rows.map(|row| { let (i,j,t,k,index,loc,state)=row?; let id_value=id(i)?; Ok(SyncJobObjectRecord{id:id_value,sync_job_id:id(j)?,storage_target_id:id(t)?,object_kind:ObjectKind::parse(&k)?,chunk_index:index.map(|v|u32::try_from(v).map_err(|_|CatalogError::InvalidState)).transpose()?,locator:String::from_utf8(field_envelope::decrypt_field(&key,vault,EntityType::Replica,id_value,FieldTag::ProviderLocator,&loc)?).map_err(|_|CatalogError::InvalidState)?,state}) }).collect()
        }).await
    }
    pub async fn mark_sync_job_object_deleted(&self, object: Uuid) -> Result<(), CatalogError> {
        let vault = self.vault_id.to_string();
        self.executor
            .call(move |x| {
                let n = x.execute(
                    "UPDATE sync_job_objects SET state='deleted' WHERE id=?1 AND vault_id=?2",
                    params![object.to_string(), vault],
                )?;
                if n == 0 {
                    return Err(CatalogError::NotFound);
                }
                Ok(())
            })
            .await
    }
    pub async fn record_health_observation(
        &self,
        version: Uuid,
        verified: u32,
        required: u32,
        state: HealthState,
    ) -> Result<Uuid, CatalogError> {
        let id = Uuid::new_v4();
        let v = self.vault_id;
        self.executor.call(move|x|{ensure_uuid(x,"versions",version,v)?;x.execute("INSERT INTO health_observations (id,file_version_id,observed_at,verified_replica_count,required_replica_count,health_state) VALUES (?1,?2,?3,?4,?5,?6)",params![id.to_string(),version.to_string(),now(),i64::from(verified),i64::from(required),state.as_str()])?;Ok(id)}).await
    }
    pub async fn create_repair_job(
        &self,
        version: Uuid,
        missing: Uuid,
        source: Uuid,
    ) -> Result<Uuid, CatalogError> {
        let id = Uuid::new_v4();
        let v = self.vault_id;
        self.executor.call(move|x|{ensure_uuid(x,"versions",version,v)?;ensure_uuid(x,"targets",missing,v)?;ensure_uuid(x,"targets",source,v)?;let state:String=x.query_row("SELECT f.lifecycle_state FROM logical_files f JOIN file_versions v ON v.logical_file_id=f.id WHERE v.id=?1 AND f.vault_id=?2",params![version.to_string(),v.to_string()],|r|r.get(0))?;if state!="active"{return Err(CatalogError::InvalidState)};if let Ok(existing)=x.query_row("SELECT id FROM repair_jobs WHERE file_version_id=?1 AND missing_storage_target_id=?2 AND state IN ('pending','running','failed') ORDER BY created_at DESC,id DESC LIMIT 1",params![version.to_string(),missing.to_string()],|r|r.get::<_,String>(0)){return Uuid::parse_str(&existing).map_err(|_|CatalogError::InvalidState);}x.execute("INSERT INTO repair_jobs (id,file_version_id,missing_storage_target_id,source_storage_target_id,state,created_at,completed_at) VALUES (?1,?2,?3,?4,'pending',?5,NULL)",params![id.to_string(),version.to_string(),missing.to_string(),source.to_string(),now()])?;Ok(id)}).await
    }
    pub async fn set_repair_job_state(&self, job: Uuid, state: &str) -> Result<(), CatalogError> {
        if !valid_job_state(state) {
            return Err(CatalogError::InvalidState);
        }
        let v = self.vault_id.to_string();
        let s = state.to_owned();
        self.executor.call(move|x|{let n=x.execute("UPDATE repair_jobs SET state=?1 WHERE id=?2 AND file_version_id IN (SELECT id FROM file_versions WHERE vault_id=?3)",params![s,job.to_string(),v])?;if n==0{Err(CatalogError::InvariantViolation)}else{Ok(())}}).await
    }
    pub async fn list_chunks(&self, version: Uuid) -> Result<Vec<ChunkRecord>, CatalogError> {
        let v = self.vault_id;
        self.executor.call(move |x| {
            ensure_uuid(x, "versions", version, v)?;
            let mut s = x.prepare("SELECT id,chunk_index FROM chunks WHERE file_version_id=?1 ORDER BY chunk_index,id")?;
            let rows = s.query_map([version.to_string()], |r| Ok((r.get::<_,String>(0)?, r.get::<_,i64>(1)?)))?;
            rows.map(|r| { let (i,n)=r?; Ok(ChunkRecord{id:id(i)?,file_version_id:version,chunk_index:u32::try_from(n).map_err(|_|CatalogError::InvalidState)?}) }).collect()
        }).await
    }

    pub async fn list_replicas(&self, version: Uuid) -> Result<Vec<ReplicaRecord>, CatalogError> {
        let v = self.vault_id;
        let key = self.catalog_field_subkey.clone();
        self.executor.call(move |x| {
            ensure_uuid(x,"versions",version,v)?;
            let mut s=x.prepare("SELECT id,chunk_id,storage_target_id,object_kind,locator_envelope,state,last_verified_at FROM replicas WHERE file_version_id=?1 ORDER BY chunk_id,id")?;
            let rows=s.query_map([version.to_string()],|r|Ok((r.get::<_,String>(0)?,r.get::<_,Option<String>>(1)?,r.get::<_,String>(2)?,r.get::<_,String>(3)?,r.get::<_,Vec<u8>>(4)?,r.get::<_,String>(5)?,r.get::<_,Option<String>>(6)?)))?;
            rows.map(|r|{let(i,c,t,k,l,st,verified_at)=r?;let i=id(i)?;Ok(ReplicaRecord{id:i,chunk_id:c.map(id).transpose()?,file_version_id:version,storage_target_id:id(t)?,object_kind:ObjectKind::parse(&k)?,locator:String::from_utf8(field_envelope::decrypt_field(&key,v,EntityType::Replica,i,FieldTag::ProviderLocator,&l)?).map_err(|_|CatalogError::InvalidState)?,state:ReplicaState::parse(&st)?,last_verified_at:verified_at})}).collect()
        }).await
    }

    /// Batched form of [`Self::list_chunks`] for bulk protection-map
    /// fallback: one query for every version in `versions` instead of one
    /// executor round trip each.
    pub async fn list_chunks_for_versions(
        &self,
        versions: &[Uuid],
    ) -> Result<std::collections::HashMap<Uuid, Vec<ChunkRecord>>, CatalogError> {
        if versions.is_empty() {
            return Ok(std::collections::HashMap::new());
        }
        let ids: Vec<String> = versions.iter().map(Uuid::to_string).collect();
        self.executor
            .call(move |x| {
                let placeholders = std::iter::repeat_n("?", ids.len()).collect::<Vec<_>>().join(",");
                let sql = format!(
                    "SELECT id,file_version_id,chunk_index FROM chunks WHERE file_version_id IN ({placeholders}) ORDER BY file_version_id,chunk_index,id"
                );
                let mut s = x.prepare(&sql)?;
                let params: Vec<&dyn rusqlite::ToSql> =
                    ids.iter().map(|v| v as &dyn rusqlite::ToSql).collect();
                let rows = s.query_map(params.as_slice(), |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, i64>(2)?,
                    ))
                })?;
                let mut out: std::collections::HashMap<Uuid, Vec<ChunkRecord>> =
                    std::collections::HashMap::new();
                for row in rows {
                    let (chunk_id, version_id, index) = row?;
                    let chunk_id = id(chunk_id)?;
                    let version_id = id(version_id)?;
                    out.entry(version_id).or_default().push(ChunkRecord {
                        id: chunk_id,
                        file_version_id: version_id,
                        chunk_index: u32::try_from(index).map_err(|_| CatalogError::InvalidState)?,
                    });
                }
                Ok(out)
            })
            .await
    }
    /// Batched replica fetch for bulk protection-map fallback. Skips
    /// locator decryption entirely (unused by that computation), unlike
    /// [`Self::list_replicas`].
    pub async fn list_replica_lite_for_versions(
        &self,
        versions: &[Uuid],
    ) -> Result<std::collections::HashMap<Uuid, Vec<ReplicaLite>>, CatalogError> {
        if versions.is_empty() {
            return Ok(std::collections::HashMap::new());
        }
        let ids: Vec<String> = versions.iter().map(Uuid::to_string).collect();
        self.executor
            .call(move |x| {
                let placeholders = std::iter::repeat_n("?", ids.len()).collect::<Vec<_>>().join(",");
                let sql = format!(
                    "SELECT file_version_id,chunk_id,storage_target_id,object_kind,state,last_verified_at FROM replicas WHERE file_version_id IN ({placeholders}) ORDER BY file_version_id,chunk_id,id"
                );
                let mut s = x.prepare(&sql)?;
                let params: Vec<&dyn rusqlite::ToSql> =
                    ids.iter().map(|v| v as &dyn rusqlite::ToSql).collect();
                let rows = s.query_map(params.as_slice(), |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, Option<String>>(1)?,
                        r.get::<_, String>(2)?,
                        r.get::<_, String>(3)?,
                        r.get::<_, String>(4)?,
                        r.get::<_, Option<String>>(5)?,
                    ))
                })?;
                let mut out: std::collections::HashMap<Uuid, Vec<ReplicaLite>> =
                    std::collections::HashMap::new();
                for row in rows {
                    let (version_id, chunk_id, target_id, kind, state, verified_at) = row?;
                    let version_id = id(version_id)?;
                    out.entry(version_id).or_default().push(ReplicaLite {
                        file_version_id: version_id,
                        chunk_id: chunk_id.map(id).transpose()?,
                        storage_target_id: id(target_id)?,
                        object_kind: ObjectKind::parse(&kind)?,
                        state: ReplicaState::parse(&state)?,
                        last_verified_at: verified_at,
                    });
                }
                Ok(out)
            })
            .await
    }
    pub async fn list_storage_target_locators(
        &self,
        target: Uuid,
    ) -> Result<Vec<String>, CatalogError> {
        let v = self.vault_id;
        let key = self.catalog_field_subkey.clone();
        self.executor.call(move |x| {
            ensure_uuid(x, "targets", target, v)?;
            let mut s = x.prepare(
                "SELECT r.id,r.locator_envelope FROM replicas r JOIN file_versions f ON f.id=r.file_version_id WHERE r.storage_target_id=?1 AND f.vault_id=?2",
            )?;
            let rows = s.query_map(params![target.to_string(), v.to_string()], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, Vec<u8>>(1)?))
            })?;
            rows.map(|row| {
                let (raw_id, envelope) = row?;
                let replica = id(raw_id)?;
                let locator = field_envelope::decrypt_field(
                    &key,
                    v,
                    EntityType::Replica,
                    replica,
                    FieldTag::ProviderLocator,
                    &envelope,
                )?;
                String::from_utf8(locator).map_err(|_| CatalogError::InvalidState)
            })
            .collect()
        }).await
    }

    pub async fn recovery_snapshot(&self) -> Result<CatalogSnapshot, CatalogError> {
        let vault = self.vault_id;
        let key = self.catalog_field_subkey.clone();
        let mut snapshot = self.executor.call(move |x| {
            let tx = x.transaction()?;
            let mut targets = Vec::new();
            let mut s = tx.prepare("SELECT id,provider_kind,config_envelope,display_order,oauth_application_profile,display_name_envelope FROM storage_targets WHERE vault_id=?1 ORDER BY display_order,id")?;
            let rows = s.query_map([vault.to_string()], |r| Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?,r.get::<_,Vec<u8>>(2)?,r.get::<_,i64>(3)?,r.get::<_,String>(4)?,r.get::<_,Option<Vec<u8>>>(5)?)))?;
            for r in rows { let (i,p,c,o,profile,name)=r?; let i=id(i)?; let display_name=name.map(|v|field_envelope::decrypt_field(&key,vault,EntityType::StorageTarget,i,FieldTag::DisplayName,&v)).transpose()?.map(|v|String::from_utf8(v).map_err(|_|CatalogError::InvalidState)).transpose()?; targets.push(StorageTargetRecord{id:i,provider_kind:p,config:field_envelope::decrypt_field(&key,vault,EntityType::StorageTarget,i,FieldTag::ProviderConfig,&c)?,display_order:o,oauth_application_profile:profile,display_name}); }
            drop(s);
            let mut folders = Vec::new();
            let mut s = tx.prepare("SELECT id,parent_folder_id,name_envelope FROM logical_folders WHERE vault_id=?1 ORDER BY parent_folder_id,id")?;
            let rows=s.query_map([vault.to_string()],|r|Ok((r.get::<_,String>(0)?,r.get::<_,Option<String>>(1)?,r.get::<_,Vec<u8>>(2)?)))?;
            for r in rows { let(i,p,n)=r?;let i=id(i)?;folders.push(LogicalFolderRecord{id:i,parent_folder_id:p.map(id).transpose()?,name:String::from_utf8(field_envelope::decrypt_field(&key,vault,EntityType::LogicalFolder,i,FieldTag::Name,&n)?).map_err(|_|CatalogError::InvalidState)?}); }
            drop(s);
            let mut files = Vec::new();
            let mut s=tx.prepare("SELECT id,folder_id,name_envelope,mime_envelope,current_version_id,lifecycle_state FROM logical_files WHERE vault_id=?1 ORDER BY id")?;
            let rows=s.query_map([vault.to_string()],|r|Ok((r.get::<_,String>(0)?,r.get::<_,Option<String>>(1)?,r.get::<_,Vec<u8>>(2)?,r.get::<_,Option<Vec<u8>>>(3)?,r.get::<_,Option<String>>(4)?,r.get::<_,String>(5)?)))?;
            for r in rows { let(i,f,n,m,c,state)=r?;let i=id(i)?;files.push(LogicalFileRecord{id:i,folder_id:f.map(id).transpose()?,name:String::from_utf8(field_envelope::decrypt_field(&key,vault,EntityType::LogicalFile,i,FieldTag::Name,&n)?).map_err(|_|CatalogError::InvalidState)?,mime:m.map(|b|field_envelope::decrypt_field(&key,vault,EntityType::LogicalFile,i,FieldTag::Mime,&b)).transpose()?.map(String::from_utf8).transpose().map_err(|_|CatalogError::InvalidState)?,current_version_id:c.map(id).transpose()?,lifecycle_state:state}); }
            drop(s);
            let mut versions = Vec::new();
            let mut keys = Vec::new();
            let mut chunks = Vec::new();
            let mut replicas = Vec::new();
            let mut activities = Vec::new();
            let mut s=tx.prepare("SELECT id,logical_file_id,file_size,chunk_count,content_hash,state FROM file_versions WHERE vault_id=?1 ORDER BY id")?;
            let rows=s.query_map([vault.to_string()],|r|Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?,r.get::<_,i64>(2)?,r.get::<_,i64>(3)?,r.get::<_,Vec<u8>>(4)?,r.get::<_,String>(5)?)))?;
            for r in rows { let(i,f,sz,cc,h,st)=r?;let i=id(i)?;versions.push(FileVersionRecord{id:i,logical_file_id:id(f)?,file_size:u64::try_from(sz).map_err(|_|CatalogError::InvalidState)?,chunk_count:u32::try_from(cc).map_err(|_|CatalogError::InvalidState)?,content_hash:h,state:st});
                let keys_row: Option<WrappedKeyRow> = tx.query_row("SELECT dek_nonce,dek_ciphertext,manifest_key_nonce,manifest_key_ciphertext,dek_key_type,manifest_key_key_type FROM wrapped_file_keys WHERE file_version_id=?1",[i.to_string()],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?))).optional()?;
                if let Some((dn,dc,mn,mc,dt,mt)) = keys_row {
                    keys.push((i,WrappedFileKey{key_type:if dt==1{FileKeyType::Dek}else{return Err(CatalogError::InvalidState)},nonce:dn.try_into().map_err(|_|CatalogError::InvalidState)?,ciphertext:dc},WrappedFileKey{key_type:if mt==2{FileKeyType::ManifestKey}else{return Err(CatalogError::InvalidState)},nonce:mn.try_into().map_err(|_|CatalogError::InvalidState)?,ciphertext:mc}));
                }
                let mut cs=tx.prepare("SELECT id,chunk_index FROM chunks WHERE file_version_id=?1 ORDER BY chunk_index,id")?; let cr=cs.query_map([i.to_string()],|r|Ok((r.get::<_,String>(0)?,r.get::<_,i64>(1)?)))?; for c in cr {let(ci,ix)=c?;chunks.push(ChunkRecord{id:id(ci)?,file_version_id:i,chunk_index:u32::try_from(ix).map_err(|_|CatalogError::InvalidState)?});} drop(cs);
                let mut rs=tx.prepare("SELECT id,chunk_id,storage_target_id,object_kind,locator_envelope,state,last_verified_at FROM replicas WHERE file_version_id=?1 ORDER BY chunk_id,id")?; let rr=rs.query_map([i.to_string()],|r|Ok((r.get::<_,String>(0)?,r.get::<_,Option<String>>(1)?,r.get::<_,String>(2)?,r.get::<_,String>(3)?,r.get::<_,Vec<u8>>(4)?,r.get::<_,String>(5)?,r.get::<_,Option<String>>(6)?)))?; for q in rr {let(ri,ci,ti,kind,loc,state,verified_at)=q?;let ri=id(ri)?;replicas.push(ReplicaRecord{id:ri,chunk_id:ci.map(id).transpose()?,file_version_id:i,storage_target_id:id(ti)?,object_kind:ObjectKind::parse(&kind)?,locator:String::from_utf8(field_envelope::decrypt_field(&key,vault,EntityType::Replica,ri,FieldTag::ProviderLocator,&loc)?).map_err(|_|CatalogError::InvalidState)?,state:ReplicaState::parse(&state)?,last_verified_at:verified_at});} drop(rs);
            }
            drop(s);
            let mut s=tx.prepare("SELECT id,operation_id,event_type,status,related_file_id,related_target_id,display_metadata_envelope,started_at,completed_at,transferred_bytes,error_code,retry_classification FROM activity_events WHERE vault_id=?1 ORDER BY started_at,id")?;
            let rows=s.query_map([vault.to_string()],|r|Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?,r.get::<_,String>(2)?,r.get::<_,String>(3)?,r.get::<_,Option<String>>(4)?,r.get::<_,Option<String>>(5)?,r.get::<_,Vec<u8>>(6)?,r.get::<_,String>(7)?,r.get::<_,Option<String>>(8)?,r.get::<_,Option<i64>>(9)?,r.get::<_,Option<String>>(10)?,r.get::<_,Option<String>>(11)?)))?;
            for r in rows { let(i,op,typ,st,rf,rt,md,start,done,bytes,err,retry)=r?; let event_id=id(i)?; activities.push(ActivityEventRecord{id:event_id,vault_id:vault,operation_id:op,event_type:typ,status:st,related_file_id:rf.map(super::unlocked::id).transpose()?,related_target_id:rt.map(super::unlocked::id).transpose()?,display_metadata:String::from_utf8(field_envelope::decrypt_field(&key,vault,EntityType::ActivityEvent,event_id,FieldTag::Description,&md)?).map_err(|_|CatalogError::InvalidState)?,started_at:start,completed_at:done,transferred_bytes:bytes.map(|v|u64::try_from(v).map_err(|_|CatalogError::InvalidState)).transpose()?,error_code:err,retry_classification:retry}); }
            drop(s);
            tx.commit()?;
            Ok(CatalogSnapshot{vault_id:vault,targets,folders,files,versions,wrapped_keys:keys,chunks,replicas,activities,deletion_jobs:Vec::new(),deletion_items:Vec::new()})
        }).await?;
        let jobs = self.list_deletion_jobs().await?;
        let mut items = Vec::new();
        for job in &jobs {
            items.extend(self.list_deletion_items(job.id).await?);
        }
        snapshot.deletion_jobs = jobs;
        snapshot.deletion_items = items;
        Ok(snapshot)
    }

    pub async fn import_recovery_snapshot(
        &self,
        snapshot: CatalogSnapshot,
    ) -> Result<(), CatalogError> {
        if snapshot.vault_id != self.vault_id {
            return Err(CatalogError::InvariantViolation);
        }
        let vault = self.vault_id;
        let key = self.catalog_field_subkey.clone();
        self.executor.call(move |x| {
            let tx = x.transaction()?;
            for t in &snapshot.targets {
                let config = field_envelope::encrypt_field(&key, vault, EntityType::StorageTarget, t.id, FieldTag::ProviderConfig, b"recovery-target")?;
                let display_name = t.display_name.as_ref().map(|v| field_envelope::encrypt_field(&key, vault, EntityType::StorageTarget, t.id, FieldTag::DisplayName, v.as_bytes())).transpose()?;
                tx.execute("INSERT INTO storage_targets (id,vault_id,provider_kind,config_envelope,display_order,created_at,oauth_application_profile,display_name_envelope) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)", params![t.id.to_string(),vault.to_string(),t.provider_kind,config,t.display_order,now(),t.oauth_application_profile,display_name])?;
            }
            for f in &snapshot.folders {
                if let Some(parent) = f.parent_folder_id { ensure_uuid_tx(&tx,"folders",parent,vault)?; }
                let name=field_envelope::encrypt_field(&key,vault,EntityType::LogicalFolder,f.id,FieldTag::Name,f.name.as_bytes())?;
                tx.execute("INSERT INTO logical_folders (id,vault_id,parent_folder_id,name_envelope,created_at) VALUES (?1,?2,?3,?4,?5)",params![f.id.to_string(),vault.to_string(),f.parent_folder_id.map(|x|x.to_string()),name,now()])?;
            }
            for f in &snapshot.files {
                if let Some(folder)=f.folder_id { ensure_uuid_tx(&tx,"folders",folder,vault)?; }
                let name=field_envelope::encrypt_field(&key,vault,EntityType::LogicalFile,f.id,FieldTag::Name,f.name.as_bytes())?;
                let mime=f.mime.as_ref().map(|m|field_envelope::encrypt_field(&key,vault,EntityType::LogicalFile,f.id,FieldTag::Mime,m.as_bytes())).transpose()?;
                tx.execute("INSERT INTO logical_files (id,vault_id,folder_id,name_envelope,mime_envelope,current_version_id,created_at,lifecycle_state) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",params![f.id.to_string(),vault.to_string(),f.folder_id.map(|x|x.to_string()),name,mime,f.current_version_id.map(|x|x.to_string()),now(),f.lifecycle_state])?;
            }
            for v in &snapshot.versions {
                ensure_uuid_tx(&tx,"files",v.logical_file_id,vault)?;
                tx.execute("INSERT INTO file_versions (id,logical_file_id,vault_id,file_size,chunk_count,content_hash,state,created_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",params![v.id.to_string(),v.logical_file_id.to_string(),vault.to_string(),i64::try_from(v.file_size).map_err(|_|CatalogError::InvariantViolation)?,i64::from(v.chunk_count),v.content_hash,v.state,now()])?;
            }
            for (version,dek,manifest) in &snapshot.wrapped_keys {
                ensure_uuid_tx(&tx,"versions",*version,vault)?;
                tx.execute("INSERT INTO wrapped_file_keys (file_version_id,dek_key_type,dek_nonce,dek_ciphertext,manifest_key_key_type,manifest_key_nonce,manifest_key_ciphertext) VALUES (?1,?2,?3,?4,?5,?6,?7)",params![version.to_string(),dek.key_type as u8,dek.nonce.to_vec(),dek.ciphertext,manifest.key_type as u8,manifest.nonce.to_vec(),manifest.ciphertext])?;
            }
            for c in &snapshot.chunks {
                ensure_uuid_tx(&tx,"versions",c.file_version_id,vault)?;
                tx.execute("INSERT INTO chunks (id,file_version_id,chunk_index) VALUES (?1,?2,?3)",params![c.id.to_string(),c.file_version_id.to_string(),i64::from(c.chunk_index)])?;
            }
            for r in &snapshot.replicas {
                ensure_uuid_tx(&tx,"versions",r.file_version_id,vault)?; ensure_uuid_tx(&tx,"targets",r.storage_target_id,vault)?;
                if let Some(c)=r.chunk_id { tx.query_row("SELECT 1 FROM chunks c JOIN file_versions v ON v.id=c.file_version_id WHERE c.id=?1 AND v.vault_id=?2",params![c.to_string(),vault.to_string()], |_| Ok(())).map_err(|_|CatalogError::InvariantViolation)?; }
                let loc=field_envelope::encrypt_field(&key,vault,EntityType::Replica,r.id,FieldTag::ProviderLocator,r.locator.as_bytes())?;
                tx.execute("INSERT INTO replicas (id,chunk_id,file_version_id,storage_target_id,object_kind,locator_envelope,state,last_verified_at) VALUES (?1,?2,?3,?4,?5,?6,?7,NULL)",params![r.id.to_string(),r.chunk_id.map(|x|x.to_string()),r.file_version_id.to_string(),r.storage_target_id.to_string(),r.object_kind.as_str(),loc,r.state.as_str()])?;
            }
            for d in &snapshot.deletion_jobs {
                ensure_uuid_tx(&tx, "files", d.logical_file_id, vault)?;
                tx.execute("INSERT INTO deletion_jobs (id,vault_id,logical_file_id,mode,trashed_at,purge_after,operation_id,state,retry_classification,incident_code,created_at,updated_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)", params![d.id.to_string(), vault.to_string(), d.logical_file_id.to_string(), d.mode, d.trashed_at, d.purge_after, d.operation_id, d.state, d.retry_classification, d.incident_code, d.created_at, d.updated_at])?;
            }
            for i in &snapshot.deletion_items {
                ensure_uuid_tx(&tx, "versions", i.file_version_id, vault)?;
                ensure_uuid_tx(&tx, "replicas", i.replica_id, vault)?;
                ensure_uuid_tx(&tx, "targets", i.storage_target_id, vault)?;
                let loc = field_envelope::encrypt_field(&key, vault, EntityType::Replica, i.id, FieldTag::ProviderLocator, i.locator.as_bytes())?;
                tx.execute("INSERT INTO deletion_items (id,deletion_id,file_version_id,replica_id,storage_target_id,object_kind,locator_envelope,state,provider_result,retry_count,next_retry_at,confirmed_deleted_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)", params![i.id.to_string(), i.deletion_id.to_string(), i.file_version_id.to_string(), i.replica_id.to_string(), i.storage_target_id.to_string(), i.object_kind.as_str(), loc, i.state, i.provider_result, i64::from(i.retry_count), i.next_retry_at, i.confirmed_deleted_at])?;
            }
            for a in &snapshot.activities {
                let metadata=field_envelope::encrypt_field(&key,vault,EntityType::ActivityEvent,a.id,FieldTag::Description,a.display_metadata.as_bytes())?;
                tx.execute("INSERT INTO activity_events (id,vault_id,operation_id,event_type,status,related_file_id,related_target_id,display_metadata_envelope,started_at,completed_at,transferred_bytes,error_code,retry_classification) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)",params![a.id.to_string(),vault.to_string(),a.operation_id,a.event_type,a.status,a.related_file_id.map(|v|v.to_string()),a.related_target_id.map(|v|v.to_string()),metadata,a.started_at,a.completed_at,a.transferred_bytes.map(|v|i64::try_from(v).map_err(|_|CatalogError::InvariantViolation)).transpose()?,a.error_code,a.retry_classification])?;
            }
            tx.commit()?;
            Ok(())
        }).await
    }

    pub async fn list_health_observations(
        &self,
        version: Uuid,
    ) -> Result<Vec<HealthObservationRecord>, CatalogError> {
        let v = self.vault_id;
        self.executor.call(move|x|{ensure_uuid(x,"versions",version,v)?;let mut s=x.prepare("SELECT id,observed_at,verified_replica_count,required_replica_count,health_state FROM health_observations WHERE file_version_id=?1 ORDER BY observed_at,id")?;let rows=s.query_map([version.to_string()],|r|Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?,r.get::<_,i64>(2)?,r.get::<_,i64>(3)?,r.get::<_,String>(4)?)))?;rows.map(|r|{let(i,at,a,b,s)=r?;Ok(HealthObservationRecord{id:id(i)?,file_version_id:version,observed_at:at,verified_replica_count:u32::try_from(a).map_err(|_|CatalogError::InvalidState)?,required_replica_count:u32::try_from(b).map_err(|_|CatalogError::InvalidState)?,health_state:HealthState::parse(&s)?})}).collect()}).await
    }

    pub async fn load_repair_job(&self, job: Uuid) -> Result<RepairJobRecord, CatalogError> {
        let v = self.vault_id;
        self.executor.call(move|x|{let(f,m,s,st)=x.query_row("SELECT file_version_id,missing_storage_target_id,source_storage_target_id,state FROM repair_jobs WHERE id=?1 AND file_version_id IN (SELECT id FROM file_versions WHERE vault_id=?2)",[job.to_string(),v.to_string()],|r|Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?,r.get::<_,String>(2)?,r.get::<_,String>(3)?)))?;Ok(RepairJobRecord{id:job,file_version_id:id(f)?,missing_storage_target_id:id(m)?,source_storage_target_id:id(s)?,state:st})}).await
    }

    pub async fn mark_file_version_healthy(&self, version: Uuid) -> Result<(), CatalogError> {
        let v = self.vault_id.to_string();
        self.executor.call(move|x|{let tx=x.transaction()?;let(state,required):(String,Option<i64>)=tx.query_row("SELECT state, (SELECT required_replica_count FROM health_observations WHERE file_version_id=?1 ORDER BY observed_at DESC, id DESC LIMIT 1) FROM file_versions WHERE id=?1 AND vault_id=?2",params![version.to_string(),v],|r|Ok((r.get(0)?,r.get(1)?)))?;let required=required.ok_or(CatalogError::InvariantViolation)?;let verified:i64=tx.query_row("SELECT COUNT(*) FROM replicas r JOIN file_versions f ON f.id=r.file_version_id WHERE r.file_version_id=?1 AND r.state='verified' AND f.vault_id=?2",params![version.to_string(),v],|r|r.get(0))?;if verified<required{return Err(CatalogError::InvariantViolation)};let _=state;tx.execute("UPDATE file_versions SET state='healthy' WHERE id=?1 AND vault_id=?2",params![version.to_string(),v])?;tx.commit()?;Ok(())}).await
    }

    pub async fn transaction<F, T>(&self, f: F) -> Result<T, CatalogError>
    where
        F: for<'a> FnOnce(&mut CatalogTransaction<'a>) -> Result<T, CatalogError> + Send + 'static,
        T: Send + 'static,
    {
        let v = self.vault_id;
        let key = self.catalog_field_subkey.clone();
        self.executor
            .call(move |x| {
                let tx = x.transaction()?;
                let mut c = CatalogTransaction {
                    tx,
                    v,
                    key: &key,
                    _marker: PhantomData,
                };
                let result = f(&mut c);
                match result {
                    Ok(v) => {
                        c.tx.commit()?;
                        Ok(v)
                    }
                    Err(e) => Err(e),
                }
            })
            .await
    }
}

pub struct CatalogTransaction<'a> {
    tx: SqlTransaction<'a>,
    v: Uuid,
    key: &'a CatalogFieldSubkey,
    _marker: PhantomData<&'a ()>,
}
impl<'a> CatalogTransaction<'a> {
    pub fn create_logical_file(
        &mut self,
        folder: Option<Uuid>,
        name: &str,
        mime: Option<&str>,
    ) -> Result<Uuid, CatalogError> {
        let id = Uuid::new_v4();
        if let Some(f) = folder {
            ensure_uuid_tx(&self.tx, "folders", f, self.v)?;
        }
        let n = field_envelope::encrypt_field(
            self.key,
            self.v,
            EntityType::LogicalFile,
            id,
            FieldTag::Name,
            name.as_bytes(),
        )?;
        let m = match mime {
            Some(s) => Some(field_envelope::encrypt_field(
                self.key,
                self.v,
                EntityType::LogicalFile,
                id,
                FieldTag::Mime,
                s.as_bytes(),
            )?),
            None => None,
        };
        self.tx.execute("INSERT INTO logical_files (id,vault_id,folder_id,name_envelope,mime_envelope,current_version_id,created_at) VALUES (?1,?2,?3,?4,?5,NULL,?6)",params![id.to_string(),self.v.to_string(),folder.map(|x|x.to_string()),n,m,now()])?;
        Ok(id)
    }
    pub fn create_file_version(
        &mut self,
        id: Uuid,
        file: Uuid,
        size: u64,
        chunks: u32,
        hash: [u8; 32],
    ) -> Result<(), CatalogError> {
        ensure_uuid_tx(&self.tx, "files", file, self.v)?;
        self.tx.execute("INSERT INTO file_versions (id,logical_file_id,vault_id,file_size,chunk_count,content_hash,state,created_at) VALUES (?1,?2,?3,?4,?5,?6,'pending',?7)",params![id.to_string(),file.to_string(),self.v.to_string(),i64::try_from(size).map_err(|_|CatalogError::InvariantViolation)?,i64::from(chunks),hash.to_vec(),now()])?;
        Ok(())
    }

    pub fn store_wrapped_file_keys(
        &mut self,
        version: Uuid,
        dek: &WrappedFileKey,
        manifest: &WrappedFileKey,
    ) -> Result<(), CatalogError> {
        if dek.key_type != FileKeyType::Dek || manifest.key_type != FileKeyType::ManifestKey {
            return Err(CatalogError::InvariantViolation);
        }
        self.tx.execute("INSERT INTO wrapped_file_keys (file_version_id,dek_key_type,dek_nonce,dek_ciphertext,manifest_key_key_type,manifest_key_nonce,manifest_key_ciphertext) VALUES (?1,?2,?3,?4,?5,?6,?7)",params![version.to_string(),dek.key_type as u8,dek.nonce.to_vec(),dek.ciphertext,manifest.key_type as u8,manifest.nonce.to_vec(),manifest.ciphertext])?;
        Ok(())
    }

    pub fn create_chunk(
        &mut self,
        version: Uuid,
        id: Uuid,
        index: u32,
    ) -> Result<(), CatalogError> {
        self.tx.execute(
            "INSERT INTO chunks (id,file_version_id,chunk_index) VALUES (?1,?2,?3)",
            params![id.to_string(), version.to_string(), i64::from(index)],
        )?;
        Ok(())
    }

    /// Inserts a replica row that is already verified, for callers that only commit to the catalog *after* every object replica has been written and checked at its storage target.
    pub fn create_replica_verified(
        &mut self,
        version: Uuid,
        chunk: Option<Uuid>,
        target: Uuid,
        kind: ObjectKind,
        id: Uuid,
        locator: &str,
    ) -> Result<(), CatalogError> {
        if (kind == ObjectKind::Chunk) != chunk.is_some() {
            return Err(CatalogError::InvariantViolation);
        }
        let l = field_envelope::encrypt_field(
            self.key,
            self.v,
            EntityType::Replica,
            id,
            FieldTag::ProviderLocator,
            locator.as_bytes(),
        )?;
        self.tx.execute("INSERT INTO replicas (id,chunk_id,file_version_id,storage_target_id,object_kind,locator_envelope,state,last_verified_at) VALUES (?1,?2,?3,?4,?5,?6,'verified',NULL)",
            params![id.to_string(), chunk.map(|x|x.to_string()), version.to_string(), target.to_string(), kind.as_str(), l])?;
        Ok(())
    }

    /// Transitions a sync job reserved earlier (before replication started) to "completed" and links it to the file version the commit just created.
    pub fn mark_sync_job_completed(
        &mut self,
        job: Uuid,
        version: Uuid,
    ) -> Result<(), CatalogError> {
        let n = self.tx.execute(
            "UPDATE sync_jobs SET file_version_id=?1,state='completed',updated_at=?2 WHERE id=?3 AND vault_id=?4",
            params![version.to_string(), now(), job.to_string(), self.v.to_string()],
        )?;
        if n == 0 {
            return Err(CatalogError::InvariantViolation);
        }
        Ok(())
    }

    pub fn record_health_observation(
        &mut self,
        version: Uuid,
        verified: u32,
        required: u32,
        state: HealthState,
    ) -> Result<(), CatalogError> {
        let oid = Uuid::new_v4();
        self.tx.execute("INSERT INTO health_observations (id,file_version_id,observed_at,verified_replica_count,required_replica_count,health_state) VALUES (?1,?2,?3,?4,?5,?6)",params![oid.to_string(),version.to_string(),now(),i64::from(verified),i64::from(required),state.as_str()])?;
        Ok(())
    }

    pub fn mark_file_version_healthy(&mut self, version: Uuid) -> Result<(), CatalogError> {
        let n = self.tx.execute(
            "UPDATE file_versions SET state='healthy' WHERE id=?1 AND vault_id=?2",
            params![version.to_string(), self.v.to_string()],
        )?;
        if n == 0 {
            return Err(CatalogError::InvariantViolation);
        }
        Ok(())
    }
    pub fn set_current_version(&mut self, file: Uuid, version: Uuid) -> Result<(), CatalogError> {
        let n = self.tx.execute(
            "UPDATE logical_files SET current_version_id=?1 WHERE id=?2 AND vault_id=?3",
            params![version.to_string(), file.to_string(), self.v.to_string()],
        )?;
        if n == 0 {
            return Err(CatalogError::InvariantViolation);
        }
        Ok(())
    }
}
