ALTER TABLE storage_targets ADD COLUMN display_name_envelope BLOB;

CREATE TABLE IF NOT EXISTS activity_events (
    id TEXT PRIMARY KEY NOT NULL,
    vault_id TEXT NOT NULL,
    operation_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    status TEXT NOT NULL,
    related_file_id TEXT,
    related_target_id TEXT,
    display_metadata_envelope BLOB NOT NULL,
    started_at TEXT NOT NULL,
    completed_at TEXT,
    transferred_bytes INTEGER,
    error_code TEXT,
    retry_classification TEXT,
    FOREIGN KEY (vault_id) REFERENCES vaults (id)
);
CREATE INDEX IF NOT EXISTS idx_activity_events_vault_time ON activity_events(vault_id, started_at DESC, id DESC);
