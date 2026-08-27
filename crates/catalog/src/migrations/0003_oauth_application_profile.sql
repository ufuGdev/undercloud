ALTER TABLE storage_targets
    ADD COLUMN oauth_application_profile TEXT NOT NULL DEFAULT 'none';
