package postgres

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/orchesta/orbit/internal/domain/entity"
	"github.com/orchesta/orbit/internal/domain/repository"
)

var _ repository.UserRepo = (*UserPostgresRepo)(nil)

type UserPostgresRepo struct {
	pool *pgxpool.Pool
}

func NewUserPostgresRepo(pool *pgxpool.Pool) *UserPostgresRepo {
	return &UserPostgresRepo{pool: pool}
}

func (r *UserPostgresRepo) Create(ctx context.Context, user *entity.User) error {
	query := `
		INSERT INTO users (id, email, password_hash, display_name, role, is_active, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`
	_, err := r.pool.Exec(ctx, query,
		user.ID, user.Email, user.PasswordHash, user.DisplayName,
		user.Role, user.IsActive, user.CreatedAt, user.UpdatedAt,
	)
	return err
}

func (r *UserPostgresRepo) GetByID(ctx context.Context, id uuid.UUID) (*entity.User, error) {
	query := `SELECT id, email, password_hash, display_name, role, is_active, created_at, updated_at FROM users WHERE id = $1`
	return r.scanUser(ctx, query, id)
}

func (r *UserPostgresRepo) GetByEmail(ctx context.Context, email string) (*entity.User, error) {
	query := `SELECT id, email, password_hash, display_name, role, is_active, created_at, updated_at FROM users WHERE lower(email) = lower($1)`
	return r.scanUser(ctx, query, email)
}

func (r *UserPostgresRepo) Count(ctx context.Context) (int, error) {
	var count int
	err := r.pool.QueryRow(ctx, "SELECT COUNT(*) FROM users").Scan(&count)
	return count, err
}

func (r *UserPostgresRepo) scanUser(ctx context.Context, query string, args ...interface{}) (*entity.User, error) {
	var user entity.User
	err := r.pool.QueryRow(ctx, query, args...).Scan(
		&user.ID, &user.Email, &user.PasswordHash, &user.DisplayName,
		&user.Role, &user.IsActive, &user.CreatedAt, &user.UpdatedAt,
	)
	if err != nil {
		if err.Error() == "no rows in result set" {
			return nil, nil
		}
		return nil, err
	}
	return &user, nil
}

// CreateInitialAdmin inserts the first admin and marks setup completed in one
// transaction. The conditional upsert serialises concurrent setups: only one
// caller can flip the flag; every other one gets ErrSetupAlreadyCompleted.
// If a user already exists while the flag is unset (older installs did not
// always persist it), the flag is committed as completed and no user is added.
func (r *UserPostgresRepo) CreateInitialAdmin(ctx context.Context, user *entity.User) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	tag, err := tx.Exec(ctx, `
		INSERT INTO system_config (key, value, updated_at) VALUES ('setup_completed', 'true', NOW())
		ON CONFLICT (key) DO UPDATE SET value = 'true', updated_at = NOW()
		WHERE system_config.value <> 'true'
	`)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return repository.ErrSetupAlreadyCompleted
	}

	var hasUsers bool
	if err := tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM users)").Scan(&hasUsers); err != nil {
		return err
	}
	if hasUsers {
		if err := tx.Commit(ctx); err != nil {
			return err
		}
		return repository.ErrSetupAlreadyCompleted
	}

	if _, err := tx.Exec(ctx, `
		INSERT INTO users (id, email, password_hash, display_name, role, is_active, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`, user.ID, user.Email, user.PasswordHash, user.DisplayName, user.Role, user.IsActive, user.CreatedAt, user.UpdatedAt); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
