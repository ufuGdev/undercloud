ALTER TABLE logical_files ADD COLUMN lifecycle_state TEXT NOT NULL DEFAULT 'active';

CREATE TABLE IF NOT EXISTS deletion_jobs (
    id TEXT PRIMARY KEY NOT NULL,
    vault_id TEXT NOT NULL,
    logical_file_id TEXT NOT NULL,
    mode TEXT NOT NULL,
    trashed_at TEXT NOT NULL,
    purge_after TEXT,
    operation_id TEXT NOT NULL,
    state TEXT NOT NULL,
    retry_classification TEXT,
    incident_code TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (vault_id) REFERENCES vaults (id)
);

CREATE TABLE IF NOT EXISTS deletion_items (
    id TEXT PRIMARY KEY NOT NULL,
    deletion_id TEXT NOT NULL,
    file_version_id TEXT NOT NULL,
    replica_id TEXT NOT NULL,
    storage_target_id TEXT NOT NULL,
    object_kind TEXT NOT NULL,
    locator_envelope BLOB NOT NULL,
    state TEXT NOT NULL,
    provider_result TEXT,
    retry_count INTEGER NOT NULL DEFAULT 0,
    next_retry_at TEXT,
    confirmed_deleted_at TEXT,
    FOREIGN KEY (deletion_id) REFERENCES deletion_jobs (id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_logical_files_lifecycle ON logical_files(vault_id, lifecycle_state, id);
CREATE INDEX IF NOT EXISTS idx_deletion_jobs_vault_state ON deletion_jobs(vault_id, state, updated_at);
CREATE INDEX IF NOT EXISTS idx_deletion_items_due ON deletion_items(deletion_id, state, next_retry_at);
