package repository

import (
	"context"
	"errors"

	"github.com/aligoren/orbit/internal/domain/entity"
	"github.com/google/uuid"
)

// ErrInUse is returned by Delete when other records still reference the row.
var ErrInUse = errors.New("in use")

// GitHostRepo is the port for Git host connection persistence.
type GitHostRepo interface {
	// Create stores h. It returns ErrDuplicate when the base URL is already stored.
	Create(ctx context.Context, h *entity.GitHost) error
	// GetByID returns nil, nil when no connection has the id.
	GetByID(ctx context.Context, id uuid.UUID) (*entity.GitHost, error)
	List(ctx context.Context) ([]*entity.GitHost, error)
	// Delete removes the connection and its access tokens. It returns ErrInUse
	// when repositories still reference it.
	Delete(ctx context.Context, id uuid.UUID) error
}
