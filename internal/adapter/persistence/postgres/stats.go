package postgres

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
)

// LatestScanTotals sums vulnerable dependencies and vulnerabilities over each
// repository's latest completed scan, so repeated scans don't inflate them.
func LatestScanTotals(ctx context.Context, pool *pgxpool.Pool) (vulnerableDeps, totalVulns int, err error) {
	err = pool.QueryRow(ctx, `
		WITH latest AS (
			SELECT DISTINCT ON (repository_id) vulnerable_deps, total_vulns
			FROM scan_results
			WHERE status = 'completed'
			ORDER BY repository_id, started_at DESC, id DESC
		)
		SELECT COALESCE(SUM(vulnerable_deps), 0), COALESCE(SUM(total_vulns), 0) FROM latest
	`).Scan(&vulnerableDeps, &totalVulns)
	return vulnerableDeps, totalVulns, err
}

// UnverifiedRepoCount counts repositories without a successful vulnerability
// check: never completed a scan, or whose newest scan failed.
func UnverifiedRepoCount(ctx context.Context, pool *pgxpool.Pool) (int, error) {
	var n int
	err := pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM repositories rp
		LEFT JOIN LATERAL (
			SELECT status FROM scan_results WHERE repository_id = rp.id ORDER BY started_at DESC, id DESC LIMIT 1
		) newest ON true
		WHERE newest.status = 'failed'
		   OR NOT EXISTS (SELECT 1 FROM scan_results s WHERE s.repository_id = rp.id AND s.status = 'completed')`).Scan(&n)
	return n, err
}

// NewestScanStatusJoin joins the status of a repository's newest scan_results
// row (any status) as ns.status, NULL when it has none. Append it after
// "FROM repositories r". It is spliced into fmt.Sprintf format strings, so it
// must never contain '%'.
const NewestScanStatusJoin = `
		LEFT JOIN LATERAL (
			SELECT status FROM scan_results WHERE repository_id = r.id ORDER BY started_at DESC, id DESC LIMIT 1
		) ns ON true`

// LatestMaliciousCount counts the findings of known malicious packages in
// each repository's latest completed scan (see maliciousVuln).
func LatestMaliciousCount(ctx context.Context, pool *pgxpool.Pool) (int, error) {
	var n int
	err := pool.QueryRow(ctx, `
		WITH latest AS (`+latestCompletedScans+`)
		SELECT COUNT(*) FROM vulnerabilities v
		JOIN dependencies d ON d.id = v.dependency_id
		JOIN latest l ON l.id = d.scan_result_id
		WHERE `+maliciousVuln).Scan(&n)
	return n, err
}
