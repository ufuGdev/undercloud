-- Composite index covering `list_file_summary_rows`'s correlated
-- subquery (WHERE file_version_id = ? ORDER BY observed_at DESC, id DESC
-- LIMIT 1): the existing idx_health_observations_file_version index only
-- covers the equality search, leaving SQLite to build a temporary b-tree
-- to satisfy the ORDER BY on every row of the outer query. This index
-- lets SQLite walk straight to the newest observation per version with no
-- sort step.
CREATE INDEX IF NOT EXISTS idx_health_observations_file_version_latest
    ON health_observations(file_version_id, observed_at DESC, id DESC);
