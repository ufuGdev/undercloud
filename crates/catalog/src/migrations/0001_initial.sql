-- SPDX-License-Identifier: Apache-2.0
--
-- Initial catalog schema (docs/adr/ADR-003-local-catalog.md, "Schema"
-- section — this file is authoritative; if the ADR's prose summary and
-- this SQL ever disagree, this SQL is correct and the ADR needs fixing).
--
-- Every primary key is an application-generated TEXT UUID (never a
-- SQLite INTEGER PRIMARY KEY / rowid) so that field-encryption AAD can
-- bind to a stable identifier that never changes after insert. `PRIMARY
-- KEY` alone does not imply `NOT NULL` for a non-INTEGER primary key in
-- SQLite, so every primary-key column below is declared `NOT NULL`
-- explicitly.
--
-- `PRAGMA foreign_keys = ON` is set once per connection at open time
-- (crates/catalog/src/lib.rs), not here — the pragma is a no-op inside
-- a transaction, and every migration runs inside one.

CREATE TABLE vaults (
    id TEXT PRIMARY KEY NOT NULL,
    created_at TEXT NOT NULL,
    catalog_format_version INTEGER NOT NULL
);

CREATE TABLE key_envelopes (
    vault_id TEXT PRIMARY KEY NOT NULL,
    envelope_version INTEGER NOT NULL,
    salt BLOB NOT NULL,
    m_cost INTEGER NOT NULL,
    t_cost INTEGER NOT NULL,
    p_cost INTEGER NOT NULL,
    nonce BLOB NOT NULL,
    ciphertext BLOB NOT NULL,
    FOREIGN KEY (vault_id) REFERENCES vaults (id)
);

CREATE TABLE storage_targets (
    id TEXT PRIMARY KEY NOT NULL,
    vault_id TEXT NOT NULL,
    provider_kind TEXT NOT NULL,
    config_envelope BLOB NOT NULL,
    display_order INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY (vault_id) REFERENCES vaults (id)
);

CREATE TABLE logical_folders (
    id TEXT PRIMARY KEY NOT NULL,
    vault_id TEXT NOT NULL,
    parent_folder_id TEXT,
    name_envelope BLOB NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY (vault_id) REFERENCES vaults (id),
    FOREIGN KEY (parent_folder_id) REFERENCES logical_folders (id) ON DELETE RESTRICT
);

CREATE TABLE logical_files (
    id TEXT PRIMARY KEY NOT NULL,
    vault_id TEXT NOT NULL,
    folder_id TEXT,
    name_envelope BLOB NOT NULL,
    mime_envelope BLOB,
    -- No FK declared: this forward-references `file_versions`, created
    -- below `logical_files`. Enforced at the application/repository
    -- layer instead — a deliberate schema limitation, documented in
    -- ADR-003, not an oversight.
    current_version_id TEXT,
    created_at TEXT NOT NULL,
    FOREIGN KEY (vault_id) REFERENCES vaults (id),
    FOREIGN KEY (folder_id) REFERENCES logical_folders (id) ON DELETE RESTRICT
);

CREATE TABLE file_versions (
    id TEXT PRIMARY KEY NOT NULL,
    logical_file_id TEXT NOT NULL,
    vault_id TEXT NOT NULL,
    file_size INTEGER NOT NULL,
    chunk_count INTEGER NOT NULL,
    content_hash BLOB NOT NULL,
    state TEXT NOT NULL,
    created_at TEXT NOT NULL,
    CHECK (file_size >= 0),
    CHECK (chunk_count >= 0),
    FOREIGN KEY (logical_file_id) REFERENCES logical_files (id) ON DELETE CASCADE,
    FOREIGN KEY (vault_id) REFERENCES vaults (id)
);

CREATE TABLE wrapped_file_keys (
    -- PRIMARY KEY on file_version_id structurally enforces exactly one
    -- row (one wrapped DEK + one wrapped ManifestKey) per file version.
    file_version_id TEXT PRIMARY KEY NOT NULL,
    dek_key_type INTEGER NOT NULL,
    dek_nonce BLOB NOT NULL,
    dek_ciphertext BLOB NOT NULL,
    manifest_key_key_type INTEGER NOT NULL,
    manifest_key_nonce BLOB NOT NULL,
    manifest_key_ciphertext BLOB NOT NULL,
    FOREIGN KEY (file_version_id) REFERENCES file_versions (id) ON DELETE CASCADE
);

CREATE TABLE chunks (
    id TEXT PRIMARY KEY NOT NULL,
    file_version_id TEXT NOT NULL,
    chunk_index INTEGER NOT NULL,
    CHECK (chunk_index >= 0),
    UNIQUE (file_version_id, chunk_index),
    FOREIGN KEY (file_version_id) REFERENCES file_versions (id) ON DELETE CASCADE
);

CREATE TABLE replicas (
    id TEXT PRIMARY KEY NOT NULL,
    -- Nullable: null when this replica represents the manifest object
    -- rather than a chunk.
    chunk_id TEXT,
    file_version_id TEXT NOT NULL,
    storage_target_id TEXT NOT NULL,
    object_kind TEXT NOT NULL,
    locator_envelope BLOB NOT NULL,
    state TEXT NOT NULL,
    last_verified_at TEXT,
    CHECK (object_kind IN ('chunk', 'manifest')),
    CHECK (state IN ('pending', 'verified', 'missing', 'corrupt')),
    UNIQUE (chunk_id, storage_target_id),
    UNIQUE (file_version_id, storage_target_id, object_kind),
    FOREIGN KEY (chunk_id) REFERENCES chunks (id) ON DELETE CASCADE,
    FOREIGN KEY (file_version_id) REFERENCES file_versions (id) ON DELETE CASCADE,
    FOREIGN KEY (storage_target_id) REFERENCES storage_targets (id) ON DELETE RESTRICT
);

CREATE TABLE sync_jobs (
    id TEXT PRIMARY KEY NOT NULL,
    vault_id TEXT NOT NULL,
    -- The only non-CASCADE/RESTRICT FK in this schema: a job's own row
    -- is retained for audit/restart-classification purposes even if the
    -- file version it was about gets deleted through some future
    -- cleanup path.
    file_version_id TEXT,
    job_kind TEXT NOT NULL,
    state TEXT NOT NULL,
    idempotency_key TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    CHECK (job_kind IN ('upload', 'restore', 'repair')),
    FOREIGN KEY (vault_id) REFERENCES vaults (id),
    FOREIGN KEY (file_version_id) REFERENCES file_versions (id) ON DELETE SET NULL
);

CREATE TABLE health_observations (
    id TEXT PRIMARY KEY NOT NULL,
    file_version_id TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    verified_replica_count INTEGER NOT NULL,
    required_replica_count INTEGER NOT NULL,
    health_state TEXT NOT NULL,
    CHECK (verified_replica_count >= 0),
    CHECK (required_replica_count >= 0),
    CHECK (health_state IN ('healthy', 'degraded', 'at_risk', 'unrecoverable')),
    FOREIGN KEY (file_version_id) REFERENCES file_versions (id) ON DELETE CASCADE
);

CREATE TABLE repair_jobs (
    id TEXT PRIMARY KEY NOT NULL,
    file_version_id TEXT NOT NULL,
    missing_storage_target_id TEXT NOT NULL,
    source_storage_target_id TEXT NOT NULL,
    state TEXT NOT NULL,
    created_at TEXT NOT NULL,
    completed_at TEXT,
    FOREIGN KEY (file_version_id) REFERENCES file_versions (id) ON DELETE CASCADE,
    FOREIGN KEY (missing_storage_target_id) REFERENCES storage_targets (id) ON DELETE RESTRICT,
    FOREIGN KEY (source_storage_target_id) REFERENCES storage_targets (id) ON DELETE RESTRICT
);
