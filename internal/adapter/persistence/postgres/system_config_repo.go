package postgres

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/orchesta/orbit/internal/domain/repository"
)

var _ repository.SystemConfigRepo = (*SystemConfigPostgresRepo)(nil)

type SystemConfigPostgresRepo struct {
	pool *pgxpool.Pool
}

func NewSystemConfigPostgresRepo(pool *pgxpool.Pool) *SystemConfigPostgresRepo {
	return &SystemConfigPostgresRepo{pool: pool}
}

func (r *SystemConfigPostgresRepo) Get(ctx context.Context, key string) (string, error) {
	var value string
	err := r.pool.QueryRow(ctx, "SELECT value FROM system_config WHERE key = $1", key).Scan(&value)
	if err != nil {
		if err.Error() == "no rows in result set" {
			return "", nil
		}
		return "", err
	}
	return value, nil
}

func (r *SystemConfigPostgresRepo) Set(ctx context.Context, key, value string) error {
	query := `
		INSERT INTO system_config (key, value, updated_at) VALUES ($1, $2, NOW())
		ON CONFLICT (key) DO UPDATE SET value = $2, updated_at = NOW()
	`
	_, err := r.pool.Exec(ctx, query, key, value)
	return err
}
