package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// AccessToken represents a stored access token.
type AccessToken struct {
	ID        uuid.UUID  `json:"id"`
	Label     string     `json:"label"`
	Provider  string     `json:"provider"`
	GitHostID *uuid.UUID `json:"git_host_id,omitempty"`
	Token     string     `json:"-"` // Never serialized to JSON
	CreatedAt time.Time  `json:"created_at"`
}

// AccessTokenResponse is what we return to the API (masked token).
type AccessTokenResponse struct {
	ID        uuid.UUID  `json:"id"`
	Label     string     `json:"label"`
	Provider  string     `json:"provider"`
	GitHostID *uuid.UUID `json:"git_host_id,omitempty"`
	Masked    string     `json:"masked_token"`
	CreatedAt time.Time  `json:"created_at"`
}

// AccessTokenPostgresRepo handles access_tokens CRUD operations.
type AccessTokenPostgresRepo struct {
	pool    *pgxpool.Pool
	secrets SecretSealer
}

// NewAccessTokenPostgresRepo creates a new AccessTokenPostgresRepo.
func NewAccessTokenPostgresRepo(pool *pgxpool.Pool, secrets SecretSealer) *AccessTokenPostgresRepo {
	return &AccessTokenPostgresRepo{pool: pool, secrets: secrets}
}

// Pool returns the underlying connection pool.
func (r *AccessTokenPostgresRepo) Pool() *pgxpool.Pool {
	return r.pool
}

// Create inserts a new access token.
func (r *AccessTokenPostgresRepo) Create(ctx context.Context, label, provider string, gitHostID *uuid.UUID, token string) (*AccessToken, error) {
	t := &AccessToken{
		ID:        uuid.New(),
		Label:     label,
		Provider:  provider,
		GitHostID: gitHostID,
		Token:     token,
		CreatedAt: time.Now().UTC(),
	}
	stored, err := r.secrets.Seal(token)
	if err != nil {
		return nil, fmt.Errorf("failed to seal access token: %w", err)
	}
	_, err = r.pool.Exec(ctx,
		"INSERT INTO access_tokens (id, label, provider, git_host_id, token, created_at) VALUES ($1, $2, $3, $4, $5, $6)",
		t.ID, t.Label, t.Provider, t.GitHostID, stored, t.CreatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create access token: %w", err)
	}
	return t, nil
}

// GetAll returns all access tokens (with masked values).
func (r *AccessTokenPostgresRepo) GetAll(ctx context.Context) ([]AccessTokenResponse, error) {
	rows, err := r.pool.Query(ctx, "SELECT id, label, provider, git_host_id, token, created_at FROM access_tokens ORDER BY created_at DESC")
	if err != nil {
		return nil, fmt.Errorf("failed to get access tokens: %w", err)
	}
	defer rows.Close()

	var tokens []AccessTokenResponse
	for rows.Next() {
		var id uuid.UUID
		var label, provider, token string
		var gitHostID *uuid.UUID
		var createdAt time.Time
		if err := rows.Scan(&id, &label, &provider, &gitHostID, &token, &createdAt); err != nil {
			return nil, fmt.Errorf("failed to scan access token: %w", err)
		}
		plain, err := r.secrets.Open(token)
		if err != nil {
			return nil, fmt.Errorf("failed to open access token %s: %w", id, err)
		}
		masked := MaskToken(plain)
		tokens = append(tokens, AccessTokenResponse{
			ID:        id,
			Label:     label,
			Provider:  provider,
			GitHostID: gitHostID,
			Masked:    masked,
			CreatedAt: createdAt,
		})
	}
	return tokens, nil
}

// GetByID returns the full token value for a given ID.
func (r *AccessTokenPostgresRepo) GetByID(ctx context.Context, id uuid.UUID) (*AccessToken, error) {
	var t AccessToken
	err := r.pool.QueryRow(ctx,
		"SELECT id, label, provider, git_host_id, token, created_at FROM access_tokens WHERE id = $1", id,
	).Scan(&t.ID, &t.Label, &t.Provider, &t.GitHostID, &t.Token, &t.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("failed to get access token: %w", err)
	}
	if t.Token, err = r.secrets.Open(t.Token); err != nil {
		return nil, fmt.Errorf("failed to open access token %s: %w", id, err)
	}
	return &t, nil
}

// Delete removes an access token by ID.
func (r *AccessTokenPostgresRepo) Delete(ctx context.Context, id uuid.UUID) error {
	_, err := r.pool.Exec(ctx, "DELETE FROM access_tokens WHERE id = $1", id)
	if err != nil {
		return fmt.Errorf("failed to delete access token: %w", err)
	}
	return nil
}
