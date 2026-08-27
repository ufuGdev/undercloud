-- Indexes for foreign-key columns traversed by list/snapshot/health
-- paths. Without these, per-file and per-vault lookups degrade to full
-- table scans as the catalog grows.
CREATE INDEX idx_replicas_file_version ON replicas(file_version_id);
CREATE INDEX idx_health_observations_file_version ON health_observations(file_version_id);
CREATE INDEX idx_repair_jobs_file_version ON repair_jobs(file_version_id);
CREATE INDEX idx_sync_jobs_vault_created ON sync_jobs(vault_id, created_at);
CREATE INDEX idx_logical_files_folder ON logical_files(folder_id);
CREATE INDEX idx_file_versions_logical_file ON file_versions(logical_file_id);
CREATE INDEX idx_storage_targets_vault ON storage_targets(vault_id);
