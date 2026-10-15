ALTER TABLE dependencies
    ALTER COLUMN current_version TYPE VARCHAR(100) USING left(current_version, 100),
    ALTER COLUMN latest_version TYPE VARCHAR(100) USING left(latest_version, 100);

DROP INDEX IF EXISTS idx_repositories_next_scan;
ALTER TABLE repositories DROP COLUMN IF EXISTS next_scan_at;

DROP INDEX IF EXISTS idx_scan_results_repo_completed;
DROP INDEX IF EXISTS idx_scan_results_pending;
DROP INDEX IF EXISTS idx_scan_results_one_active;
ALTER TABLE scan_results
    DROP COLUMN IF EXISTS heartbeat_at,
    DROP COLUMN IF EXISTS attempts,
    DROP COLUMN IF EXISTS total_vulns;
