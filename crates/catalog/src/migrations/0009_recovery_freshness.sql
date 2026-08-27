ALTER TABLE vaults ADD COLUMN recovery_generation INTEGER NOT NULL DEFAULT 0;
ALTER TABLE vaults ADD COLUMN recovery_export_generation INTEGER;
ALTER TABLE vaults ADD COLUMN recovery_exported_at TEXT;
