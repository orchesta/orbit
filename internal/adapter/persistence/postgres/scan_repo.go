package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/orchesta/orbit/internal/domain/entity"
	"github.com/orchesta/orbit/internal/domain/repository"
)

// scanColumns lists scan_results columns in the order scanRow reads them.
const scanColumns = "id, repository_id, status, total_deps, outdated_deps, vulnerable_deps, total_vulns, attempts, duration, error, started_at, completed_at"

var _ repository.ScanResultRepo = (*ScanResultPostgresRepo)(nil)

// ScanResultPostgresRepo implements ScanResultRepo using PostgreSQL.
type ScanResultPostgresRepo struct {
	pool *pgxpool.Pool
}

func NewScanResultPostgresRepo(pool *pgxpool.Pool) *ScanResultPostgresRepo {
	return &ScanResultPostgresRepo{pool: pool}
}

func (r *ScanResultPostgresRepo) Create(ctx context.Context, scan *entity.ScanResult) error {
	query := `
		INSERT INTO scan_results (id, repository_id, status, total_deps, outdated_deps, vulnerable_deps, total_vulns, duration, error, started_at, completed_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
	`
	_, err := r.pool.Exec(ctx, query,
		scan.ID, scan.RepositoryID, scan.Status, scan.TotalDeps, scan.OutdatedDeps,
		scan.VulnerableDeps, scan.TotalVulns, scan.Duration, scan.Error, scan.StartedAt, scan.CompletedAt,
	)
	return err
}

func (r *ScanResultPostgresRepo) GetByID(ctx context.Context, id uuid.UUID) (*entity.ScanResult, error) {
	query := `
		SELECT ` + scanColumns + `
		FROM scan_results WHERE id = $1
	`
	row := r.pool.QueryRow(ctx, query, id)
	return r.scanRow(row)
}

func (r *ScanResultPostgresRepo) GetByRepositoryID(ctx context.Context, repoID uuid.UUID, limit int) ([]*entity.ScanResult, error) {
	query := `
		SELECT ` + scanColumns + `
		FROM scan_results WHERE repository_id = $1 ORDER BY started_at DESC, id DESC LIMIT $2
	`
	rows, err := r.pool.Query(ctx, query, repoID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return r.scanRows(rows)
}

func (r *ScanResultPostgresRepo) GetLatestByRepositoryID(ctx context.Context, repoID uuid.UUID) (*entity.ScanResult, error) {
	query := `
		SELECT ` + scanColumns + `
		FROM scan_results WHERE repository_id = $1 ORDER BY started_at DESC, id DESC LIMIT 1
	`
	row := r.pool.QueryRow(ctx, query, repoID)
	return r.scanRow(row)
}

func (r *ScanResultPostgresRepo) Update(ctx context.Context, scan *entity.ScanResult) error {
	query := `
		UPDATE scan_results
		SET status = $2, total_deps = $3, outdated_deps = $4, vulnerable_deps = $5,
			total_vulns = $9, duration = $6, error = $7, completed_at = $8
		WHERE id = $1 AND attempts = $10 AND status = 'running'
	`
	tag, err := r.pool.Exec(ctx, query,
		scan.ID, scan.Status, scan.TotalDeps, scan.OutdatedDeps,
		scan.VulnerableDeps, scan.Duration, scan.Error, scan.CompletedAt, scan.TotalVulns, scan.Attempt,
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return repository.ErrScanNotOwned
	}
	return nil
}

func (r *ScanResultPostgresRepo) scanRow(row pgx.Row) (*entity.ScanResult, error) {
	var scan entity.ScanResult
	err := row.Scan(
		&scan.ID, &scan.RepositoryID, &scan.Status, &scan.TotalDeps, &scan.OutdatedDeps,
		&scan.VulnerableDeps, &scan.TotalVulns, &scan.Attempt, &scan.Duration, &scan.Error, &scan.StartedAt, &scan.CompletedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return &scan, nil
}

func (r *ScanResultPostgresRepo) scanRows(rows pgx.Rows) ([]*entity.ScanResult, error) {
	var results []*entity.ScanResult
	for rows.Next() {
		var scan entity.ScanResult
		err := rows.Scan(
			&scan.ID, &scan.RepositoryID, &scan.Status, &scan.TotalDeps, &scan.OutdatedDeps,
			&scan.VulnerableDeps, &scan.TotalVulns, &scan.Attempt, &scan.Duration, &scan.Error, &scan.StartedAt, &scan.CompletedAt,
		)
		if err != nil {
			return nil, err
		}
		results = append(results, &scan)
	}
	return results, rows.Err()
}

// Enqueue adds scan as pending unless the repository already has an active
// scan, which is then returned with created=false.
func (r *ScanResultPostgresRepo) Enqueue(ctx context.Context, scan *entity.ScanResult) (*entity.ScanResult, bool, error) {
	// The active scan can finish between the conflicting insert and the
	// lookup; retrying then inserts successfully.
	for attempt := 0; attempt < 3; attempt++ {
		created, err := r.scanRow(r.pool.QueryRow(ctx, `
			INSERT INTO scan_results (id, repository_id, status, started_at)
			VALUES ($1, $2, 'pending', $3)
			ON CONFLICT (repository_id) WHERE status IN ('pending', 'running') DO NOTHING
			RETURNING `+scanColumns, scan.ID, scan.RepositoryID, scan.StartedAt))
		if err != nil {
			return nil, false, err
		}
		if created != nil {
			return created, true, nil
		}
		existing, err := r.scanRow(r.pool.QueryRow(ctx,
			`SELECT `+scanColumns+` FROM scan_results WHERE repository_id = $1 AND status IN ('pending', 'running')`,
			scan.RepositoryID))
		if err != nil {
			return nil, false, err
		}
		if existing != nil {
			return existing, false, nil
		}
	}
	return nil, false, fmt.Errorf("could not enqueue scan for repository %s", scan.RepositoryID)
}

// ClaimNext marks the oldest pending scan running and returns it, or nil.
func (r *ScanResultPostgresRepo) ClaimNext(ctx context.Context) (*entity.ScanResult, error) {
	return r.scanRow(r.pool.QueryRow(ctx, `
		UPDATE scan_results
		SET status = 'running', started_at = NOW(), heartbeat_at = NOW(), attempts = attempts + 1
		WHERE id = (
			SELECT id FROM scan_results WHERE status = 'pending'
			ORDER BY started_at LIMIT 1
			FOR UPDATE SKIP LOCKED
		)
		RETURNING `+scanColumns))
}

// Heartbeat records that the worker running scan id under attempt is still alive.
func (r *ScanResultPostgresRepo) Heartbeat(ctx context.Context, id uuid.UUID, attempt int) error {
	tag, err := r.pool.Exec(ctx, "UPDATE scan_results SET heartbeat_at = NOW() WHERE id = $1 AND status = 'running' AND attempts = $2", id, attempt)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return repository.ErrScanNotOwned
	}
	return nil
}

// Requeue returns a running scan to the queue without using up an attempt.
func (r *ScanResultPostgresRepo) Requeue(ctx context.Context, id uuid.UUID, attempt int) error {
	tag, err := r.pool.Exec(ctx, `
		UPDATE scan_results SET status = 'pending', heartbeat_at = NULL, attempts = GREATEST(attempts - 1, 0)
		WHERE id = $1 AND status = 'running' AND attempts = $2`, id, attempt)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return repository.ErrScanNotOwned
	}
	return nil
}

// RecoverStale fails stale running scans that used maxAttempts and requeues
// the rest. A missing heartbeat counts as stale since started_at.
func (r *ScanResultPostgresRepo) RecoverStale(ctx context.Context, staleAfter time.Duration, maxAttempts int) (int, int, error) {
	secs := staleAfter.Seconds()
	failed, err := r.pool.Exec(ctx, `
		UPDATE scan_results
		SET status = 'failed', error = 'interrupted: the worker running this scan stopped responding',
		    completed_at = NOW(), heartbeat_at = NULL
		WHERE status = 'running' AND COALESCE(heartbeat_at, started_at) < NOW() - make_interval(secs => $1)
		  AND attempts >= $2`, secs, maxAttempts)
	if err != nil {
		return 0, 0, err
	}
	requeued, err := r.pool.Exec(ctx, `
		UPDATE scan_results SET status = 'pending', heartbeat_at = NULL
		WHERE status = 'running' AND COALESCE(heartbeat_at, started_at) < NOW() - make_interval(secs => $1)`, secs)
	if err != nil {
		return 0, int(failed.RowsAffected()), err
	}
	return int(requeued.RowsAffected()), int(failed.RowsAffected()), nil
}

// PruneHistory deletes finished scans beyond the newest keep, always keeping
// the latest completed one. Dependencies and vulnerabilities cascade.
func (r *ScanResultPostgresRepo) PruneHistory(ctx context.Context, repoID uuid.UUID, keep int) (int, error) {
	tag, err := r.pool.Exec(ctx, `
		DELETE FROM scan_results
		WHERE repository_id = $1
		  AND status IN ('completed', 'failed')
		  AND id NOT IN (
			SELECT id FROM scan_results
			WHERE repository_id = $1 AND status IN ('completed', 'failed')
			ORDER BY started_at DESC, id DESC LIMIT $2)
		  AND id IS DISTINCT FROM (
			SELECT id FROM scan_results
			WHERE repository_id = $1 AND status = 'completed'
			ORDER BY started_at DESC, id DESC LIMIT 1)`, repoID, keep)
	if err != nil {
		return 0, err
	}
	return int(tag.RowsAffected()), nil
}
