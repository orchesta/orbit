package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/aligoren/orbit/internal/domain/entity"
	"github.com/aligoren/orbit/internal/domain/repository"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// SQLSTATEs of a violated foreign key. ON DELETE RESTRICT reports
// restrict_violation (23001); NO ACTION and other checks report 23503.
const (
	foreignKeyViolation = "23503"
	restrictViolation   = "23001"
)

const (
	// gitHostBaseURLKey is the name of the unique index on lower(base_url).
	gitHostBaseURLKey = "git_hosts_base_url_lower_key"
	// repositoriesGitHostFK is the name of repositories.git_host_id's foreign key.
	repositoriesGitHostFK = "repositories_git_host_id_fkey"
)

// Ensure interface compliance at compile time.
var _ repository.GitHostRepo = (*GitHostPostgresRepo)(nil)

// GitHostPostgresRepo implements GitHostRepo using PostgreSQL.
type GitHostPostgresRepo struct {
	pool *pgxpool.Pool
}

// NewGitHostPostgresRepo creates a new GitHostPostgresRepo.
func NewGitHostPostgresRepo(pool *pgxpool.Pool) *GitHostPostgresRepo {
	return &GitHostPostgresRepo{pool: pool}
}

func (r *GitHostPostgresRepo) Create(ctx context.Context, h *entity.GitHost) error {
	_, err := r.pool.Exec(ctx,
		"INSERT INTO git_hosts (id, kind, name, base_url, created_at) VALUES ($1, $2, $3, $4, $5)",
		h.ID, h.Kind, h.Name, h.BaseURL, h.CreatedAt,
	)
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == uniqueViolation && pgErr.ConstraintName == gitHostBaseURLKey {
		return repository.ErrDuplicate
	}
	return err
}

func (r *GitHostPostgresRepo) GetByID(ctx context.Context, id uuid.UUID) (*entity.GitHost, error) {
	h, err := scanGitHost(r.pool.QueryRow(ctx,
		"SELECT id, kind, name, base_url, created_at FROM git_hosts WHERE id = $1", id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return h, err
}

func (r *GitHostPostgresRepo) List(ctx context.Context) ([]*entity.GitHost, error) {
	rows, err := r.pool.Query(ctx, "SELECT id, kind, name, base_url, created_at FROM git_hosts ORDER BY name ASC, created_at ASC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var hosts []*entity.GitHost
	for rows.Next() {
		h, err := scanGitHost(rows)
		if err != nil {
			return nil, err
		}
		hosts = append(hosts, h)
	}
	return hosts, rows.Err()
}

func (r *GitHostPostgresRepo) Delete(ctx context.Context, id uuid.UUID) error {
	_, err := r.pool.Exec(ctx, "DELETE FROM git_hosts WHERE id = $1", id)
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && (pgErr.Code == restrictViolation || pgErr.Code == foreignKeyViolation) && pgErr.ConstraintName == repositoriesGitHostFK {
		return repository.ErrInUse
	}
	return err
}

func scanGitHost(row pgx.Row) (*entity.GitHost, error) {
	var h entity.GitHost
	var kind string
	var created time.Time
	if err := row.Scan(&h.ID, &kind, &h.Name, &h.BaseURL, &created); err != nil {
		return nil, err
	}
	h.Kind = entity.GitProvider(kind)
	h.CreatedAt = created
	return &h, nil
}
