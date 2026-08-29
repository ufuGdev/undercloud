use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use bincode::Options;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use tokio::io::AsyncWriteExt;
use uuid::Uuid;

use undercloud_catalog::{
    CatalogSnapshot, DeletionItemRecord, DeletionJobRecord, FileVersionRecord, ObjectKind,
    ReplicaState,
};
use undercloud_crypto::{
    derive_vault_subkeys, unwrap_master_key, wrap_master_key, FileKeyType, PasswordEnvelope,
    WrappedFileKey,
};

use crate::{CancellationToken, CoreError, VaultSession};

const MAGIC: &[u8; 4] = b"UCRK";
const FORMAT_VERSION: u16 = 1;
const ENVELOPE_TYPE: u8 = 1;
const MAX_PAYLOAD: usize = 512 * 1024 * 1024;

fn sqlite_companion(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(suffix);
    PathBuf::from(name)
}

#[derive(Serialize, Deserialize)]
struct WireSnapshot {
    vault_id: Uuid,
    timestamp: u64,
    sequence: u64,
    targets: Vec<WireTarget>,
    folders: Vec<WireFolder>,
    files: Vec<WireFile>,
    versions: Vec<WireVersion>,
    keys: Vec<WireKeys>,
    chunks: Vec<WireChunk>,
    replicas: Vec<WireReplica>,
    #[serde(default)]
    activities: Vec<WireActivity>,
    #[serde(default)]
    deletion_jobs: Vec<WireDeletionJob>,
    #[serde(default)]
    deletion_items: Vec<WireDeletionItem>,
}
#[derive(Serialize, Deserialize)]
struct WireTarget {
    id: Uuid,
    provider_kind: String,
    display_order: i64,
    oauth_application_profile: String,
    #[serde(default)]
    display_name: Option<String>,
}
#[derive(Serialize, Deserialize)]
struct LegacyWireSnapshot {
    vault_id: Uuid,
    timestamp: u64,
    sequence: u64,
    targets: Vec<LegacyWireTarget>,
    folders: Vec<WireFolder>,
    files: Vec<WireFile>,
    versions: Vec<WireVersion>,
    keys: Vec<WireKeys>,
    chunks: Vec<WireChunk>,
    replicas: Vec<WireReplica>,
    activities: Vec<WireActivity>,
    deletion_jobs: Vec<WireDeletionJob>,
    deletion_items: Vec<WireDeletionItem>,
}
#[derive(Serialize, Deserialize)]
struct LegacyWireTarget {
    id: Uuid,
    provider_kind: String,
    display_order: i64,
    oauth_application_profile: String,
}
#[derive(Serialize, Deserialize)]
struct WireFolder {
    id: Uuid,
    parent: Option<Uuid>,
    name: String,
}
#[derive(Serialize, Deserialize)]
struct WireFile {
    id: Uuid,
    folder: Option<Uuid>,
    name: String,
    mime: Option<String>,
    current: Option<Uuid>,
    #[serde(default = "active_lifecycle_state")]
    lifecycle_state: String,
}
fn active_lifecycle_state() -> String {
    "active".to_owned()
}

fn deserialize_wire_snapshot(plain: &[u8]) -> Result<WireSnapshot, CoreError> {
    let options = bincode::DefaultOptions::new().with_fixint_encoding();
    match options.reject_trailing_bytes().deserialize(plain) {
        Ok(wire) => Ok(wire),
        Err(_) => {
            let legacy: LegacyWireSnapshot = options
                .reject_trailing_bytes()
                .deserialize(plain)
                .map_err(|_| CoreError::InvalidRecoveryKit)?;
            Ok(WireSnapshot {
                vault_id: legacy.vault_id,
                timestamp: legacy.timestamp,
                sequence: legacy.sequence,
                targets: legacy
                    .targets
                    .into_iter()
                    .map(|target| WireTarget {
                        id: target.id,
                        provider_kind: target.provider_kind,
                        display_order: target.display_order,
                        oauth_application_profile: target.oauth_application_profile,
                        display_name: None,
                    })
                    .collect(),
                folders: legacy.folders,
                files: legacy.files,
                versions: legacy.versions,
                keys: legacy.keys,
                chunks: legacy.chunks,
                replicas: legacy.replicas,
                activities: legacy.activities,
                deletion_jobs: legacy.deletion_jobs,
                deletion_items: legacy.deletion_items,
            })
        }
    }
}
#[derive(Serialize, Deserialize)]
struct WireVersion {
    id: Uuid,
    file: Uuid,
    size: u64,
    chunks: u32,
    hash: Vec<u8>,
    state: String,
}
#[derive(Serialize, Deserialize)]
struct WireKeys {
    version: Uuid,
    dek_type: u8,
    dek_nonce: [u8; 24],
    dek: Vec<u8>,
    manifest_type: u8,
    manifest_nonce: [u8; 24],
    manifest: Vec<u8>,
}
#[derive(Serialize, Deserialize)]
struct WireChunk {
    id: Uuid,
    version: Uuid,
    index: u32,
}
#[derive(Serialize, Deserialize)]
struct WireReplica {
    id: Uuid,
    chunk: Option<Uuid>,
    version: Uuid,
    target: Uuid,
    kind: u8,
    locator: String,
    state: u8,
}
#[derive(Serialize, Deserialize)]
struct WireActivity {
    id: Uuid,
    operation_id: String,
    event_type: String,
    status: String,
    related_file_id: Option<Uuid>,
    related_target_id: Option<Uuid>,
    display_metadata: String,
    started_at: String,
    completed_at: Option<String>,
    transferred_bytes: Option<u64>,
    error_code: Option<String>,
    retry_classification: Option<String>,
}
#[derive(Serialize, Deserialize)]
struct WireDeletionJob {
    id: Uuid,
    file: Uuid,
    mode: String,
    trashed_at: String,
    purge_after: Option<String>,
    operation_id: String,
    state: String,
    retry: Option<String>,
    incident: Option<String>,
    created_at: String,
    updated_at: String,
}
#[derive(Serialize, Deserialize)]
struct WireDeletionItem {
    id: Uuid,
    deletion: Uuid,
    version: Uuid,
    replica: Uuid,
    target: Uuid,
    kind: u8,
    locator: String,
    state: String,
    provider_result: Option<String>,
    retry_count: u32,
    next_retry_at: Option<String>,
    confirmed_deleted_at: Option<String>,
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
fn aad(vault: Uuid, timestamp: u64, sequence: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + 2 + 16 + 8 + 8 + 1);
    out.extend_from_slice(b"UCRK");
    out.extend_from_slice(&FORMAT_VERSION.to_be_bytes());
    out.extend_from_slice(vault.as_bytes());
    out.extend_from_slice(&timestamp.to_be_bytes());
    out.extend_from_slice(&sequence.to_be_bytes());
    out.push(ENVELOPE_TYPE);
    out
}
fn push_u16(out: &mut Vec<u8>, v: u16) {
    out.extend_from_slice(&v.to_be_bytes());
}
fn push_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_be_bytes());
}
fn push_u64(out: &mut Vec<u8>, v: u64) {
    out.extend_from_slice(&v.to_be_bytes());
}
fn take<'a>(bytes: &'a [u8], at: &mut usize, n: usize) -> Result<&'a [u8], CoreError> {
    let end = at.checked_add(n).ok_or(CoreError::InvalidRecoveryKit)?;
    let b = bytes.get(*at..end).ok_or(CoreError::InvalidRecoveryKit)?;
    *at = end;
    Ok(b)
}
fn read_u16(bytes: &[u8], at: &mut usize) -> Result<u16, CoreError> {
    Ok(u16::from_be_bytes(
        take(bytes, at, 2)?
            .try_into()
            .map_err(|_| CoreError::InvalidRecoveryKit)?,
    ))
}
fn read_u32(bytes: &[u8], at: &mut usize) -> Result<u32, CoreError> {
    Ok(u32::from_be_bytes(
        take(bytes, at, 4)?
            .try_into()
            .map_err(|_| CoreError::InvalidRecoveryKit)?,
    ))
}
fn read_u64(bytes: &[u8], at: &mut usize) -> Result<u64, CoreError> {
    Ok(u64::from_be_bytes(
        take(bytes, at, 8)?
            .try_into()
            .map_err(|_| CoreError::InvalidRecoveryKit)?,
    ))
}
fn uuid(bytes: &[u8]) -> Result<Uuid, CoreError> {
    Uuid::from_slice(bytes).map_err(|_| CoreError::InvalidRecoveryKit)
}

fn key_to_wire(version: Uuid, d: &WrappedFileKey, m: &WrappedFileKey) -> WireKeys {
    WireKeys {
        version,
        dek_type: d.key_type as u8,
        dek_nonce: d.nonce,
        dek: d.ciphertext.clone(),
        manifest_type: m.key_type as u8,
        manifest_nonce: m.nonce,
        manifest: m.ciphertext.clone(),
    }
}
fn snapshot_to_wire(s: CatalogSnapshot, timestamp: u64, sequence: u64) -> WireSnapshot {
    WireSnapshot {
        vault_id: s.vault_id,
        timestamp,
        sequence,
        targets: s
            .targets
            .into_iter()
            .map(|x| WireTarget {
                id: x.id,
                provider_kind: x.provider_kind,
                display_order: x.display_order,
                oauth_application_profile: x.oauth_application_profile,
                display_name: x.display_name,
            })
            .collect(),
        folders: s
            .folders
            .into_iter()
            .map(|x| WireFolder {
                id: x.id,
                parent: x.parent_folder_id,
                name: x.name,
            })
            .collect(),
        files: s
            .files
            .into_iter()
            .map(|x| WireFile {
                id: x.id,
                folder: x.folder_id,
                name: x.name,
                mime: x.mime,
                current: x.current_version_id,
                lifecycle_state: x.lifecycle_state,
            })
            .collect(),
        versions: s
            .versions
            .into_iter()
            .map(|x| WireVersion {
                id: x.id,
                file: x.logical_file_id,
                size: x.file_size,
                chunks: x.chunk_count,
                hash: x.content_hash,
                state: x.state,
            })
            .collect(),
        keys: s
            .wrapped_keys
            .into_iter()
            .map(|(v, d, m)| key_to_wire(v, &d, &m))
            .collect(),
        chunks: s
            .chunks
            .into_iter()
            .map(|x| WireChunk {
                id: x.id,
                version: x.file_version_id,
                index: x.chunk_index,
            })
            .collect(),
        replicas: s
            .replicas
            .into_iter()
            .map(|x| WireReplica {
                id: x.id,
                chunk: x.chunk_id,
                version: x.file_version_id,
                target: x.storage_target_id,
                kind: if x.object_kind == ObjectKind::Chunk {
                    1
                } else {
                    2
                },
                locator: x.locator,
                state: match x.state {
                    ReplicaState::Pending => 1,
                    ReplicaState::Verified => 2,
                    ReplicaState::Missing => 3,
                    ReplicaState::Corrupt => 4,
                },
            })
            .collect(),
        activities: s
            .activities
            .into_iter()
            .map(|x| WireActivity {
                id: x.id,
                operation_id: x.operation_id,
                event_type: x.event_type,
                status: x.status,
                related_file_id: x.related_file_id,
                related_target_id: x.related_target_id,
                display_metadata: x.display_metadata,
                started_at: x.started_at,
                completed_at: x.completed_at,
                transferred_bytes: x.transferred_bytes,
                error_code: x.error_code,
                retry_classification: x.retry_classification,
            })
            .collect(),
        deletion_jobs: s
            .deletion_jobs
            .into_iter()
            .map(|x| WireDeletionJob {
                id: x.id,
                file: x.logical_file_id,
                mode: x.mode,
                trashed_at: x.trashed_at,
                purge_after: x.purge_after,
                operation_id: x.operation_id,
                state: x.state,
                retry: x.retry_classification,
                incident: x.incident_code,
                created_at: x.created_at,
                updated_at: x.updated_at,
            })
            .collect(),
        deletion_items: s
            .deletion_items
            .into_iter()
            .map(|x| WireDeletionItem {
                id: x.id,
                deletion: x.deletion_id,
                version: x.file_version_id,
                replica: x.replica_id,
                target: x.storage_target_id,
                kind: if x.object_kind == ObjectKind::Chunk {
                    1
                } else {
                    2
                },
                locator: x.locator,
                state: x.state,
                provider_result: x.provider_result,
                retry_count: x.retry_count,
                next_retry_at: x.next_retry_at,
                confirmed_deleted_at: x.confirmed_deleted_at,
            })
            .collect(),
    }
}
fn unique<I: IntoIterator<Item = Uuid>>(ids: I) -> Result<(), CoreError> {
    let mut s = HashSet::new();
    for id in ids {
        if !s.insert(id) {
            return Err(CoreError::InvalidRecoveryKit);
        }
    }
    Ok(())
}

fn wire_versions(versions: Vec<WireVersion>) -> Result<Vec<FileVersionRecord>, CoreError> {
    versions
        .into_iter()
        .map(|x| {
            if x.hash.len() != 32 {
                return Err(CoreError::InvalidRecoveryKit);
            }
            Ok(FileVersionRecord {
                id: x.id,
                logical_file_id: x.file,
                file_size: x.size,
                chunk_count: x.chunks,
                content_hash: x.hash,
                state: x.state,
            })
        })
        .collect()
}

fn wire_keys(
    keys: Vec<WireKeys>,
) -> Result<Vec<(Uuid, WrappedFileKey, WrappedFileKey)>, CoreError> {
    keys.into_iter()
        .map(|x| {
            if x.dek_type != 1 || x.manifest_type != 2 {
                return Err(CoreError::InvalidRecoveryKit);
            }
            Ok((
                x.version,
                WrappedFileKey {
                    key_type: FileKeyType::Dek,
                    nonce: x.dek_nonce,
                    ciphertext: x.dek,
                },
                WrappedFileKey {
                    key_type: FileKeyType::ManifestKey,
                    nonce: x.manifest_nonce,
                    ciphertext: x.manifest,
                },
            ))
        })
        .collect()
}

fn wire_replicas(
    replicas: Vec<WireReplica>,
) -> Result<Vec<undercloud_catalog::ReplicaRecord>, CoreError> {
    replicas
        .into_iter()
        .map(|x| {
            let kind = match x.kind {
                1 => ObjectKind::Chunk,
                2 => ObjectKind::Manifest,
                _ => return Err(CoreError::InvalidRecoveryKit),
            };
            let state = match x.state {
                1 => ReplicaState::Pending,
                2 => ReplicaState::Verified,
                3 => ReplicaState::Missing,
                4 => ReplicaState::Corrupt,
                _ => return Err(CoreError::InvalidRecoveryKit),
            };
            if (kind == ObjectKind::Chunk) != x.chunk.is_some() {
                return Err(CoreError::InvalidRecoveryKit);
            }
            Ok(undercloud_catalog::ReplicaRecord {
                id: x.id,
                chunk_id: x.chunk,
                file_version_id: x.version,
                storage_target_id: x.target,
                object_kind: kind,
                locator: x.locator,
                state,
                last_verified_at: None,
            })
        })
        .collect()
}

fn wire_deletion_items(items: Vec<WireDeletionItem>) -> Result<Vec<DeletionItemRecord>, CoreError> {
    items
        .into_iter()
        .map(|x| {
            Ok(DeletionItemRecord {
                id: x.id,
                deletion_id: x.deletion,
                file_version_id: x.version,
                replica_id: x.replica,
                storage_target_id: x.target,
                object_kind: match x.kind {
                    1 => ObjectKind::Chunk,
                    2 => ObjectKind::Manifest,
                    _ => return Err(CoreError::InvalidRecoveryKit),
                },
                locator: x.locator,
                state: x.state,
                provider_result: x.provider_result,
                retry_count: x.retry_count,
                next_retry_at: x.next_retry_at,
                confirmed_deleted_at: x.confirmed_deleted_at,
            })
        })
        .collect()
}

fn wire_to_snapshot(w: WireSnapshot) -> Result<CatalogSnapshot, CoreError> {
    if w.vault_id.is_nil() || w.timestamp == 0 {
        return Err(CoreError::InvalidRecoveryKit);
    }
    unique(w.targets.iter().map(|x| x.id))?;
    unique(w.folders.iter().map(|x| x.id))?;
    unique(w.files.iter().map(|x| x.id))?;
    unique(w.versions.iter().map(|x| x.id))?;
    unique(w.chunks.iter().map(|x| x.id))?;
    unique(w.replicas.iter().map(|x| x.id))?;
    let versions = wire_versions(w.versions)?;
    let keys = wire_keys(w.keys)?;
    let replicas = wire_replicas(w.replicas)?;
    Ok(CatalogSnapshot {
        vault_id: w.vault_id,
        targets: w
            .targets
            .into_iter()
            .map(|x| undercloud_catalog::StorageTargetRecord {
                id: x.id,
                provider_kind: x.provider_kind,
                config: Vec::new(),
                display_order: x.display_order,
                oauth_application_profile: x.oauth_application_profile,
                display_name: x.display_name,
            })
            .collect(),
        folders: w
            .folders
            .into_iter()
            .map(|x| undercloud_catalog::LogicalFolderRecord {
                id: x.id,
                parent_folder_id: x.parent,
                name: x.name,
            })
            .collect(),
        files: w
            .files
            .into_iter()
            .map(|x| undercloud_catalog::LogicalFileRecord {
                id: x.id,
                folder_id: x.folder,
                name: x.name,
                mime: x.mime,
                current_version_id: x.current,
                lifecycle_state: x.lifecycle_state,
            })
            .collect(),
        versions,
        wrapped_keys: keys,
        chunks: w
            .chunks
            .into_iter()
            .map(|x| undercloud_catalog::ChunkRecord {
                id: x.id,
                file_version_id: x.version,
                chunk_index: x.index,
            })
            .collect(),
        replicas,
        activities: w
            .activities
            .into_iter()
            .map(|x| undercloud_catalog::ActivityEventRecord {
                id: x.id,
                vault_id: w.vault_id,
                operation_id: x.operation_id,
                event_type: x.event_type,
                status: x.status,
                related_file_id: x.related_file_id,
                related_target_id: x.related_target_id,
                display_metadata: x.display_metadata,
                started_at: x.started_at,
                completed_at: x.completed_at,
                transferred_bytes: x.transferred_bytes,
                error_code: x.error_code,
                retry_classification: x.retry_classification,
            })
            .collect(),
        deletion_jobs: w
            .deletion_jobs
            .into_iter()
            .map(|x| DeletionJobRecord {
                id: x.id,
                logical_file_id: x.file,
                mode: x.mode,
                trashed_at: x.trashed_at,
                purge_after: x.purge_after,
                operation_id: x.operation_id,
                state: x.state,
                retry_classification: x.retry,
                incident_code: x.incident,
                created_at: x.created_at,
                updated_at: x.updated_at,
            })
            .collect(),
        deletion_items: wire_deletion_items(w.deletion_items)?,
    })
}

pub async fn export(
    session: &VaultSession,
    destination: &Path,
    passphrase: &str,
) -> Result<(), CoreError> {
    if passphrase.is_empty() {
        return Err(CoreError::Authentication);
    }
    if destination.exists() {
        return Err(CoreError::RecoveryDestinationExists);
    }
    let snapshot = session.catalog.recovery_snapshot().await?;
    let timestamp = now();
    let sequence = timestamp;
    let wire = snapshot_to_wire(snapshot, timestamp, sequence);
    let plain = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .serialize(&wire)
        .map_err(|_| CoreError::InvalidRecoveryKit)?;
    let envelope = wrap_master_key(session.vault_id, passphrase, &session.master_key)
        .map_err(|_| CoreError::Authentication)?;
    let subkeys = derive_vault_subkeys(&session.master_key, session.vault_id);
    let cipher = XChaCha20Poly1305::new(subkeys.recovery.expose_bytes().into());
    let mut nonce = [0u8; 24];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: &plain,
                aad: &aad(session.vault_id, timestamp, sequence),
            },
        )
        .map_err(|_| CoreError::Authentication)?;
    let mut out = Vec::new();
    out.extend_from_slice(MAGIC);
    push_u16(&mut out, FORMAT_VERSION);
    out.extend_from_slice(session.vault_id.as_bytes());
    push_u64(&mut out, timestamp);
    push_u64(&mut out, sequence);
    out.push(ENVELOPE_TYPE);
    out.extend_from_slice(&envelope.salt);
    push_u32(&mut out, envelope.m_cost);
    push_u32(&mut out, envelope.t_cost);
    push_u32(&mut out, envelope.p_cost);
    out.extend_from_slice(&envelope.nonce);
    push_u32(
        &mut out,
        u32::try_from(envelope.ciphertext.len()).map_err(|_| CoreError::InvalidRecoveryKit)?,
    );
    out.extend_from_slice(&envelope.ciphertext);
    out.extend_from_slice(&nonce);
    push_u64(
        &mut out,
        u64::try_from(ciphertext.len()).map_err(|_| CoreError::InvalidRecoveryKit)?,
    );
    out.extend_from_slice(&ciphertext);
    let digest = blake3::hash(&out);
    out.extend_from_slice(digest.as_bytes());
    let parent = destination
        .parent()
        .ok_or(CoreError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "invalid destination",
        )))?;
    let name = destination
        .file_name()
        .ok_or(CoreError::InvalidRecoveryKit)?
        .to_string_lossy();
    let tmp = parent.join(format!(".{name}.{}.tmp", Uuid::new_v4()));
    let result = async {
        let mut f = tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)
            .await?;
        f.write_all(&out).await?;
        f.sync_all().await?;
        drop(f);
        tokio::fs::hard_link(&tmp, destination).await?;
        cleanup_published_export_temp(&tmp).await;
        Ok::<(), CoreError>(())
    }
    .await;
    if result.is_err() {
        let _ = tokio::fs::remove_file(&tmp).await;
    }
    result
}

async fn cleanup_published_export_temp(path: &Path) {
    if let Err(error) = tokio::fs::remove_file(path).await {
        tracing::warn!(
            subsystem = "core",
            operation = "recovery_export",
            error = %error,
            "recovery export published but temporary cleanup failed"
        );
    }
}

pub async fn import(
    kit: &Path,
    destination: &Path,
    passphrase: &str,
) -> Result<VaultSession, CoreError> {
    if destination.exists() {
        return Err(CoreError::RecoveryDestinationExists);
    }
    let bytes = tokio::fs::read(kit).await?;
    if bytes.len() < 4 + 2 + 16 + 8 + 8 + 1 + 16 + 12 + 24 + 4 + 24 + 8 + 32 {
        return Err(CoreError::InvalidRecoveryKit);
    };
    let (body, check) = bytes.split_at(bytes.len() - 32);
    if blake3::hash(body).as_bytes() != check {
        return Err(CoreError::Authentication);
    };
    let mut at = 0usize;
    if take(body, &mut at, 4)? != MAGIC {
        return Err(CoreError::InvalidRecoveryKit);
    };
    if read_u16(body, &mut at)? != FORMAT_VERSION {
        return Err(CoreError::UnsupportedRecoveryVersion);
    };
    let vault = uuid(take(body, &mut at, 16)?)?;
    let timestamp = read_u64(body, &mut at)?;
    let sequence = read_u64(body, &mut at)?;
    if timestamp == 0 || timestamp > now().saturating_add(300_000) || sequence != timestamp {
        return Err(CoreError::StaleRecoverySnapshot);
    };
    if take(body, &mut at, 1)?[0] != ENVELOPE_TYPE {
        return Err(CoreError::InvalidRecoveryKit);
    };
    let salt: [u8; 16] = take(body, &mut at, 16)?
        .try_into()
        .map_err(|_| CoreError::InvalidRecoveryKit)?;
    let m = read_u32(body, &mut at)?;
    let t = read_u32(body, &mut at)?;
    let p = read_u32(body, &mut at)?;
    let nonce: [u8; 24] = take(body, &mut at, 24)?
        .try_into()
        .map_err(|_| CoreError::InvalidRecoveryKit)?;
    let clen =
        usize::try_from(read_u32(body, &mut at)?).map_err(|_| CoreError::InvalidRecoveryKit)?;
    if clen > MAX_PAYLOAD {
        return Err(CoreError::InvalidRecoveryKit);
    };
    let ciphertext = take(body, &mut at, clen)?.to_vec();
    let snonce: [u8; 24] = take(body, &mut at, 24)?
        .try_into()
        .map_err(|_| CoreError::InvalidRecoveryKit)?;
    let plen =
        usize::try_from(read_u64(body, &mut at)?).map_err(|_| CoreError::InvalidRecoveryKit)?;
    if plen > MAX_PAYLOAD || plen != body.len().saturating_sub(at) {
        return Err(CoreError::InvalidRecoveryKit);
    };
    let encrypted = take(body, &mut at, plen)?;
    if at != body.len() {
        return Err(CoreError::InvalidRecoveryKit);
    };
    let envelope = PasswordEnvelope {
        vault_id: vault,
        envelope_version: 1,
        salt,
        m_cost: m,
        t_cost: t,
        p_cost: p,
        nonce,
        ciphertext,
    };
    let master =
        unwrap_master_key(vault, passphrase, &envelope).map_err(|_| CoreError::Authentication)?;
    let subkeys = derive_vault_subkeys(&master, vault);
    let cipher = XChaCha20Poly1305::new(subkeys.recovery.expose_bytes().into());
    let plain = cipher
        .decrypt(
            XNonce::from_slice(&snonce),
            Payload {
                msg: encrypted,
                aad: &aad(vault, timestamp, sequence),
            },
        )
        .map_err(|_| CoreError::Authentication)?;
    let wire = deserialize_wire_snapshot(&plain)?;
    if wire.vault_id != vault || wire.timestamp != timestamp || wire.sequence != sequence {
        return Err(CoreError::StaleRecoverySnapshot);
    };
    let snapshot = wire_to_snapshot(wire)?;
    let result = async {
        let bootstrap = undercloud_catalog::CatalogBootstrap::open(destination).await?;
        let new_envelope =
            wrap_master_key(vault, passphrase, &master).map_err(|_| CoreError::Authentication)?;
        bootstrap.create_vault(vault, 1, &new_envelope).await?;
        let catalog = bootstrap.unlock(subkeys.catalog_field.clone()).await?;
        catalog.import_recovery_snapshot(snapshot).await?;
        Ok::<VaultSession, CoreError>(VaultSession {
            vault_id: vault,
            master_key: master,
            subkeys,
            catalog,
            envelope: new_envelope,
            providers: std::collections::HashMap::new(),
            roots: std::collections::HashMap::new(),
            credential_store: std::sync::Arc::new(
                undercloud_credentials::OsKeyringCredentialStore::new("undercloud"),
            ),
            oauth_flow: undercloud_provider_cloud::OAuthFlow::new(),
            oauth_registry: undercloud_provider_cloud::OAuthApplicationRegistry::official(),
            background_cancel: CancellationToken::new(),
            repair_locks: crate::KeyedLock::new(),
        })
    }
    .await;
    if result.is_err() {
        let _ = tokio::fs::remove_file(destination).await;
        let _ = tokio::fs::remove_file(sqlite_companion(destination, "-wal")).await;
        let _ = tokio::fs::remove_file(sqlite_companion(destination, "-shm")).await;
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn legacy_recovery_kit_without_display_name_imports_and_remains_usable() {
        let directory = tempfile::tempdir().unwrap();
        let original_db = directory.path().join("original.sqlite");
        let current_kit = directory.path().join("current.ucrk");
        let legacy_kit = directory.path().join("legacy.ucrk");
        let recovered_db = directory.path().join("recovered.sqlite");
        let reexported_kit = directory.path().join("reexported.ucrk");
        let restored = directory.path().join("restored.bin");
        let provider_root = directory.path().join("provider");
        let source = b"legacy recovery remains operational".to_vec();
        tokio::fs::create_dir_all(&provider_root).await.unwrap();

        let core = crate::UndercloudCore::new(&original_db);
        let mut session = core.create_vault("legacy-passphrase").await.unwrap();
        let target = session.add_local_provider(&provider_root).await.unwrap();
        let (progress, _) = tokio::sync::mpsc::channel(4);
        let uploaded = session
            .upload_file(
                tokio::io::BufReader::new(std::io::Cursor::new(source.clone())),
                Some(source.len() as u64),
                "legacy.bin",
                None,
                "legacy-upload",
                progress,
            )
            .await
            .unwrap();
        core.export_recovery_kit(&session, &current_kit, "legacy-passphrase")
            .await
            .unwrap();
        write_legacy_kit(&session, &current_kit, &legacy_kit)
            .await
            .unwrap();

        let recovered_core = crate::UndercloudCore::new(&recovered_db);
        let mut recovered = recovered_core
            .import_recovery_kit(&legacy_kit, &recovered_db, "legacy-passphrase")
            .await
            .unwrap();
        assert_eq!(recovered.storage_target_ids().await.unwrap(), vec![target]);
        assert_eq!(recovered.recovery_freshness().await.unwrap().generation, 0);
        recovered
            .reconnect_local_provider(target, &provider_root)
            .await
            .unwrap();
        assert_eq!(
            recovered
                .verify_recovered_health(uploaded.file_version_id)
                .await
                .unwrap(),
            crate::FileHealth::Healthy
        );
        recovered
            .restore_file(
                uploaded.file_version_id,
                &restored,
                crate::CancellationToken::new(),
            )
            .await
            .unwrap();
        assert_eq!(tokio::fs::read(&restored).await.unwrap(), source);

        recovered_core
            .export_recovery_kit(&recovered, &reexported_kit, "legacy-passphrase")
            .await
            .unwrap();
        let reimported_db = directory.path().join("reimported.sqlite");
        crate::UndercloudCore::new(&reimported_db)
            .import_recovery_kit(&reexported_kit, &reimported_db, "legacy-passphrase")
            .await
            .unwrap();
    }

    async fn write_legacy_kit(
        session: &VaultSession,
        current_kit: &Path,
        legacy_kit: &Path,
    ) -> Result<(), CoreError> {
        let bytes = tokio::fs::read(current_kit).await?;
        let (body, _) = bytes.split_at(bytes.len() - 32);
        let mut at = 4 + 2 + 16;
        let timestamp = read_u64(body, &mut at)?;
        let sequence = read_u64(body, &mut at)?;
        at += 1 + 16 + 4 + 4 + 4 + 24;
        let clen =
            usize::try_from(read_u32(body, &mut at)?).map_err(|_| CoreError::InvalidRecoveryKit)?;
        at += clen;
        let nonce_start = at;
        let old_nonce = take(body, &mut at, 24)?;
        let plen =
            usize::try_from(read_u64(body, &mut at)?).map_err(|_| CoreError::InvalidRecoveryKit)?;
        let encrypted = take(body, &mut at, plen)?;
        let cipher = XChaCha20Poly1305::new(
            derive_vault_subkeys(&session.master_key, session.vault_id)
                .recovery
                .expose_bytes()
                .into(),
        );
        let plain = cipher
            .decrypt(
                XNonce::from_slice(old_nonce),
                Payload {
                    msg: encrypted,
                    aad: &aad(session.vault_id, timestamp, sequence),
                },
            )
            .map_err(|_| CoreError::Authentication)?;
        let wire = deserialize_wire_snapshot(&plain)?;
        let legacy = LegacyWireSnapshot {
            vault_id: wire.vault_id,
            timestamp: wire.timestamp,
            sequence: wire.sequence,
            targets: wire
                .targets
                .into_iter()
                .map(|target| LegacyWireTarget {
                    id: target.id,
                    provider_kind: target.provider_kind,
                    display_order: target.display_order,
                    oauth_application_profile: target.oauth_application_profile,
                })
                .collect(),
            folders: wire.folders,
            files: wire.files,
            versions: wire.versions,
            keys: wire.keys,
            chunks: wire.chunks,
            replicas: wire.replicas,
            activities: wire.activities,
            deletion_jobs: wire.deletion_jobs,
            deletion_items: wire.deletion_items,
        };
        let legacy_plain = bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .serialize(&legacy)
            .map_err(|_| CoreError::InvalidRecoveryKit)?;
        let mut new_nonce = [0u8; 24];
        rand::rngs::OsRng.fill_bytes(&mut new_nonce);
        let legacy_ciphertext = cipher
            .encrypt(
                XNonce::from_slice(&new_nonce),
                Payload {
                    msg: &legacy_plain,
                    aad: &aad(session.vault_id, timestamp, sequence),
                },
            )
            .map_err(|_| CoreError::Authentication)?;
        let mut output = body[..nonce_start].to_vec();
        output.extend_from_slice(&new_nonce);
        push_u64(&mut output, legacy_ciphertext.len() as u64);
        output.extend_from_slice(&legacy_ciphertext);
        output.extend_from_slice(blake3::hash(&output).as_bytes());
        tokio::fs::write(legacy_kit, output).await?;
        Ok(())
    }

    #[tokio::test]
    async fn published_export_survives_temporary_cleanup_failure() {
        let directory = tempfile::tempdir().unwrap();
        let destination = directory.path().join("published.ucrk");
        let temp = directory.path().join("published.tmp");
        tokio::fs::write(&temp, b"published").await.unwrap();
        tokio::fs::hard_link(&temp, &destination).await.unwrap();
        tokio::fs::remove_file(&temp).await.unwrap();

        cleanup_published_export_temp(&temp).await;

        assert_eq!(tokio::fs::read(&destination).await.unwrap(), b"published");
    }
}
