// SPDX-License-Identifier: Apache-2.0
//! Encrypted local catalog (vault identity, storage targets, the logical file/folder tree, wrapped keys, chunk/replica placement, durable job/health state — see `docs/adr/ADR-003-local-catalog.md`): a persistence layer with no UI- or provider-implementation-specific dependency (never Tauri, frontend code, a concrete cloud-provider crate, or `crates/core`, which consumes it instead), where every SQL query is parameterized and [`UnlockedCatalog`] (via [`CatalogBootstrap::unlock`]) is the only type able to reach any table beyond `vaults`/`key_envelopes`.
mod bootstrap;
mod error;
mod executor;
mod field_envelope;
mod migrations;
mod unlocked;

pub use bootstrap::CatalogBootstrap;
pub use error::CatalogError;
pub use field_envelope::{
    decrypt_field, encrypt_field, EntityType, FieldTag, FIELD_ENVELOPE_VERSION,
};
pub use unlocked::{
    ActivityEventRecord, CatalogSnapshot, CatalogTransaction, ChunkRecord, DeletionItemRecord,
    DeletionJobRecord, FileSummaryRow, FileVersionRecord, HealthObservationRecord, HealthState,
    JobKind, LogicalFileRecord, LogicalFolderRecord, NewActivityEvent, ObjectKind,
    RecoveryFreshnessRecord, RepairJobRecord, ReplicaLite, ReplicaRecord, ReplicaState,
    StorageTargetRecord, SyncJobObjectRecord, SyncJobRecord, UnlockedCatalog,
};

use std::path::Path;

use rusqlite::Connection;

/// Opens (creating if necessary) the SQLite database at `path`, wires every pragma ADR-003 "Storage engine and durability policy" mandates, tightens Unix file permissions, and applies pending migrations; must run *on the executor thread* as the `init` closure to [`crate::executor::CatalogExecutor::spawn`], never called directly from async context.
pub(crate) fn open_and_migrate(path: &Path) -> Result<Connection, CatalogError> {
    let created_by_this_call = !path.exists();

    let conn = Connection::open(path)?;

    // Every connection is configured identically, once, here — see ADR-003 "Storage engine and durability policy".
    conn.pragma_update(None, "foreign_keys", "ON")?;
    conn.pragma_update(None, "journal_mode", "WAL")?;
    conn.pragma_update(None, "busy_timeout", 5000)?;
    conn.pragma_update(None, "synchronous", "FULL")?;
    // Page-cache/memory-map sizing only — no durability or consistency
    // impact, unlike `synchronous`/`journal_mode` above. Bounded constants
    // (not scaling with catalog size): 20 MiB page cache, up to 256 MiB
    // memory-mapped I/O for large scans (SQLite falls back to normal I/O
    // beyond that transparently, and unsupported platforms/filesystems
    // ignore `mmap_size` safely per SQLite's own documented behavior).
    // `cache_size` is negative here deliberately: negative means "size in
    // KiB", positive would mean "number of pages" — this is 20,000 KiB
    // (~19.5 MiB), not 20,000 pages (~80 MiB at the default 4 KiB page
    // size). Applied identically to every connection this executor ever
    // opens (there is exactly one, opened once in `open_and_migrate`).
    // Isolated effect measured separately from the query/index change —
    // see the performance report's cache/mmap isolation table.
    conn.pragma_update(None, "cache_size", -20_000i64)?;
    conn.pragma_update(None, "mmap_size", 268_435_456i64)?;

    #[cfg(unix)]
    if created_by_this_call {
        tighten_permissions(path)?;
    }
    #[cfg(not(unix))]
    let _ = created_by_this_call;

    let mut conn = conn;
    migrations::run(&mut conn)?;

    Ok(conn)
}

/// Best-effort defense-in-depth, not a substitute for field encryption (ADR-003): restricts the catalog file to owner read/write only, though a local attacker with any read access still only sees ciphertext for every encrypted field.
#[cfg(unix)]
fn tighten_permissions(path: &Path) -> Result<(), CatalogError> {
    use std::os::unix::fs::PermissionsExt;

    let metadata = std::fs::metadata(path)?;
    let mut permissions = metadata.permissions();
    permissions.set_mode(0o600);
    std::fs::set_permissions(path, permissions)?;
    Ok(())
}
