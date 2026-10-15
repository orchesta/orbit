package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/orchesta/orbit/internal/domain/entity"
	"github.com/orchesta/orbit/internal/domain/repository"
)

// uniqueViolation is the SQLSTATE of a violated unique constraint.
const uniqueViolation = "23505"

// repositoryURLKey is the name of the UNIQUE(url) constraint on repositories.
const repositoryURLKey = "repositories_url_key"

// Ensure interface compliance at compile time.
var _ repository.RepositoryRepo = (*RepositoryPostgresRepo)(nil)

// RepositoryPostgresRepo implements RepositoryRepo using PostgreSQL.
type RepositoryPostgresRepo struct {
	pool    *pgxpool.Pool
	secrets SecretSealer
}

// NewRepositoryPostgresRepo creates a new RepositoryPostgresRepo.
func NewRepositoryPostgresRepo(pool *pgxpool.Pool, secrets SecretSealer) *RepositoryPostgresRepo {
	return &RepositoryPostgresRepo{pool: pool, secrets: secrets}
}

func (r *RepositoryPostgresRepo) Create(ctx context.Context, repo *entity.Repository, nextScanAt time.Time) error {
	query := `
		INSERT INTO repositories (id, name, url, provider, default_branch, schedule, auth_token, is_active, last_scanned_at, created_at, updated_at, next_scan_at, git_host_id)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
	`
	token, err := r.secrets.Seal(repo.AuthToken)
	if err != nil {
		return err
	}
	_, err = r.pool.Exec(ctx, query,
		repo.ID, repo.Name, repo.URL, repo.Provider, repo.DefaultBranch,
		repo.Schedule, token, repo.IsActive, repo.LastScannedAt,
		repo.CreatedAt, repo.UpdatedAt, nextScanAt, repo.GitHostID,
	)
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == uniqueViolation && pgErr.ConstraintName == repositoryURLKey {
		return repository.ErrDuplicate
	}
	return err
}

func (r *RepositoryPostgresRepo) GetByID(ctx context.Context, id uuid.UUID) (*entity.Repository, error) {
	query := `
		SELECT id, name, url, provider, default_branch, schedule, auth_token, is_active, last_scanned_at, created_at, updated_at, git_host_id
		FROM repositories WHERE id = $1
	`
	row := r.pool.QueryRow(ctx, query, id)
	return r.scanRow(row)
}

func (r *RepositoryPostgresRepo) GetAll(ctx context.Context) ([]*entity.Repository, error) {
	query := `
		SELECT id, name, url, provider, default_branch, schedule, auth_token, is_active, last_scanned_at, created_at, updated_at, git_host_id
		FROM repositories ORDER BY name ASC
	`
	rows, err := r.pool.Query(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return r.scanRows(rows)
}

func (r *RepositoryPostgresRepo) GetActive(ctx context.Context) ([]*entity.Repository, error) {
	query := `
		SELECT id, name, url, provider, default_branch, schedule, auth_token, is_active, last_scanned_at, created_at, updated_at, git_host_id
		FROM repositories WHERE is_active = true ORDER BY name ASC
	`
	rows, err := r.pool.Query(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return r.scanRows(rows)
}

// Update stores repo and, when nextScanAt is non-nil, next_scan_at in the
// same statement; a nil nextScanAt keeps the stored next_scan_at.
func (r *RepositoryPostgresRepo) Update(ctx context.Context, repo *entity.Repository, nextScanAt *time.Time) error {
	query := `
		UPDATE repositories
		SET name = $2, url = $3, provider = $4, default_branch = $5, schedule = $6,
			auth_token = $7, is_active = $8, last_scanned_at = $9, updated_at = $10,
			next_scan_at = COALESCE($11::timestamptz, next_scan_at),
			git_host_id = $12
		WHERE id = $1
	`
	token, err := r.secrets.Seal(repo.AuthToken)
	if err != nil {
		return err
	}
	_, err = r.pool.Exec(ctx, query,
		repo.ID, repo.Name, repo.URL, repo.Provider, repo.DefaultBranch,
		repo.Schedule, token, repo.IsActive, repo.LastScannedAt,
		repo.UpdatedAt, nextScanAt, repo.GitHostID,
	)
	return err
}

func (r *RepositoryPostgresRepo) Delete(ctx context.Context, id uuid.UUID) error {
	_, err := r.pool.Exec(ctx, "DELETE FROM repositories WHERE id = $1", id)
	return err
}

func (r *RepositoryPostgresRepo) scanRow(row pgx.Row) (*entity.Repository, error) {
	var repo entity.Repository
	err := row.Scan(
		&repo.ID, &repo.Name, &repo.URL, &repo.Provider, &repo.DefaultBranch,
		&repo.Schedule, &repo.AuthToken, &repo.IsActive, &repo.LastScannedAt,
		&repo.CreatedAt, &repo.UpdatedAt, &repo.GitHostID,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	if repo.AuthToken, err = r.secrets.Open(repo.AuthToken); err != nil {
		return nil, fmt.Errorf("failed to open auth token for repository %s: %w", repo.ID, err)
	}
	return &repo, nil
}

func (r *RepositoryPostgresRepo) scanRows(rows pgx.Rows) ([]*entity.Repository, error) {
	var repos []*entity.Repository
	for rows.Next() {
		var repo entity.Repository
		err := rows.Scan(
			&repo.ID, &repo.Name, &repo.URL, &repo.Provider, &repo.DefaultBranch,
			&repo.Schedule, &repo.AuthToken, &repo.IsActive, &repo.LastScannedAt,
			&repo.CreatedAt, &repo.UpdatedAt, &repo.GitHostID,
		)
		if err != nil {
			return nil, err
		}
		if repo.AuthToken, err = r.secrets.Open(repo.AuthToken); err != nil {
			return nil, fmt.Errorf("failed to open auth token for repository %s: %w", repo.ID, err)
		}
		repos = append(repos, &repo)
	}
	return repos, rows.Err()
}

// SetNextScanAt sets when the scheduler should next queue the repository.
func (r *RepositoryPostgresRepo) SetNextScanAt(ctx context.Context, id uuid.UUID, at time.Time) error {
	_, err := r.pool.Exec(ctx, "UPDATE repositories SET next_scan_at = $2 WHERE id = $1", id, at)
	return err
}

// MarkScanned records when the repository was last scanned, touching no other column.
func (r *RepositoryPostgresRepo) MarkScanned(ctx context.Context, id uuid.UUID, at time.Time) error {
	_, err := r.pool.Exec(ctx, "UPDATE repositories SET last_scanned_at = $2 WHERE id = $1", id, at)
	return err
}

// ClaimDueRepositories returns due active repositories and advances their
// next_scan_at, skipping rows locked by another scheduler.
func (r *RepositoryPostgresRepo) ClaimDueRepositories(ctx context.Context, now time.Time, limit int, next func(schedule string, after time.Time) time.Time) ([]uuid.UUID, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	rows, err := tx.Query(ctx, `
		SELECT id, schedule FROM repositories
		WHERE is_active AND next_scan_at <= $1
		ORDER BY next_scan_at
		LIMIT $2
		FOR UPDATE SKIP LOCKED`, now, limit)
	if err != nil {
		return nil, err
	}
	type due struct {
		id       uuid.UUID
		schedule string
	}
	var dues []due
	for rows.Next() {
		var d due
		if err := rows.Scan(&d.id, &d.schedule); err != nil {
			rows.Close()
			return nil, err
		}
		dues = append(dues, d)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	ids := make([]uuid.UUID, 0, len(dues))
	for _, d := range dues {
		if _, err := tx.Exec(ctx, "UPDATE repositories SET next_scan_at = $2 WHERE id = $1", d.id, next(d.schedule, now)); err != nil {
			return nil, err
		}
		ids = append(ids, d.id)
	}
	return ids, tx.Commit(ctx)
}

// ExistingURLs reports which of urls (compared normalized) are already stored.
func (r *RepositoryPostgresRepo) ExistingURLs(ctx context.Context, urls []string) (map[string]bool, error) {
	normalized := make([]string, len(urls))
	for i, u := range urls {
		normalized[i] = entity.NormalizeRepositoryURL(u)
	}
	rows, err := r.pool.Query(ctx, `
		SELECT n FROM (
			SELECT regexp_replace(rtrim(lower(regexp_replace(url, '^\s+|\s+$', '', 'g')), '/'), '\.git$', '') AS n FROM repositories
		) s WHERE n = ANY($1)`, normalized)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	found := map[string]bool{}
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, err
		}
		found[n] = true
	}
	return found, rows.Err()
}
