-- Scans still pending or running when this migration runs were orphaned by
-- the previous process; close them so the one-active-scan index can apply.
UPDATE scan_results
SET status = 'failed',
    error = COALESCE(error, 'interrupted'),
    completed_at = COALESCE(completed_at, NOW())
WHERE status IN ('pending', 'running');

ALTER TABLE scan_results
    ADD COLUMN total_vulns  INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN attempts     INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN heartbeat_at TIMESTAMP WITH TIME ZONE;

-- total_vulns was never stored; derive it for existing scans.
UPDATE scan_results s
SET total_vulns = (
    SELECT COUNT(*) FROM vulnerabilities v
    JOIN dependencies d ON d.id = v.dependency_id
    WHERE d.scan_result_id = s.id
);

-- At most one queued or running scan per repository.
CREATE UNIQUE INDEX idx_scan_results_one_active ON scan_results (repository_id)
    WHERE status IN ('pending', 'running');
-- Workers pick the oldest pending scan.
CREATE INDEX idx_scan_results_pending ON scan_results (started_at) WHERE status = 'pending';
-- Latest completed scan per repository.
CREATE INDEX idx_scan_results_repo_completed ON scan_results (repository_id, started_at DESC)
    WHERE status = 'completed';

ALTER TABLE repositories ADD COLUMN next_scan_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW();
-- Spread the first automatic scans of existing repositories over an hour.
UPDATE repositories SET next_scan_at = NOW() + random() * INTERVAL '1 hour';
CREATE INDEX idx_repositories_next_scan ON repositories (next_scan_at) WHERE is_active;

ALTER TABLE dependencies
    ALTER COLUMN current_version TYPE TEXT,
    ALTER COLUMN latest_version TYPE TEXT;
