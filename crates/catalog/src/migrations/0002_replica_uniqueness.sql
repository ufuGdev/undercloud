-- Allow one replica for every chunk on a target while retaining exactly
-- one manifest replica per target. Migration is transactional; the old
-- table remains untouched if any rebuild statement fails.
CREATE TABLE replicas_v2 (
    id TEXT PRIMARY KEY NOT NULL,
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
    FOREIGN KEY (chunk_id) REFERENCES chunks (id) ON DELETE CASCADE,
    FOREIGN KEY (file_version_id) REFERENCES file_versions (id) ON DELETE CASCADE,
    FOREIGN KEY (storage_target_id) REFERENCES storage_targets (id) ON DELETE RESTRICT
);

INSERT INTO replicas_v2
    (id, chunk_id, file_version_id, storage_target_id, object_kind,
     locator_envelope, state, last_verified_at)
SELECT id, chunk_id, file_version_id, storage_target_id, object_kind,
       locator_envelope, state, last_verified_at
FROM replicas;

DROP TABLE replicas;
ALTER TABLE replicas_v2 RENAME TO replicas;

CREATE UNIQUE INDEX replicas_manifest_target_unique
    ON replicas (file_version_id, storage_target_id)
    WHERE object_kind = 'manifest';
