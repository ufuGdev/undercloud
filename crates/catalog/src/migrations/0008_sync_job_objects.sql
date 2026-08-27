CREATE TABLE IF NOT EXISTS sync_job_objects (
    id TEXT PRIMARY KEY NOT NULL,
    sync_job_id TEXT NOT NULL,
    vault_id TEXT NOT NULL,
    storage_target_id TEXT NOT NULL,
    object_kind TEXT NOT NULL,
    chunk_index INTEGER,
    locator_envelope BLOB NOT NULL,
    state TEXT NOT NULL DEFAULT 'pending',
    FOREIGN KEY (sync_job_id) REFERENCES sync_jobs(id) ON DELETE CASCADE,
    FOREIGN KEY (vault_id) REFERENCES vaults(id),
    FOREIGN KEY (storage_target_id) REFERENCES storage_targets(id) ON DELETE RESTRICT,
    CHECK (object_kind IN ('chunk', 'manifest')),
    CHECK (state IN ('pending', 'deleted'))
);
CREATE INDEX IF NOT EXISTS idx_sync_job_objects_job ON sync_job_objects(sync_job_id, state, id);
