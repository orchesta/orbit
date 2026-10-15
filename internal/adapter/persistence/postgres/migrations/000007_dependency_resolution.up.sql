ALTER TABLE dependencies ADD COLUMN is_resolved BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE dependencies ADD COLUMN is_dev BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE vulnerabilities ALTER COLUMN fixed_version TYPE TEXT;
