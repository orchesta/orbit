-- Lossy: truncates fixed_version values longer than 100 characters.
ALTER TABLE vulnerabilities ALTER COLUMN fixed_version TYPE VARCHAR(100) USING left(fixed_version, 100);
ALTER TABLE dependencies DROP COLUMN is_dev;
ALTER TABLE dependencies DROP COLUMN is_resolved;
