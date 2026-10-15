package repository

import (
	"context"

	"github.com/aligoren/orbit/internal/domain/entity"
	"github.com/google/uuid"
)

// DependencyRepo is the port for dependency persistence operations.
type DependencyRepo interface {
	Create(ctx context.Context, dep *entity.Dependency) error
	CreateBatch(ctx context.Context, deps []*entity.Dependency) error
	GetByID(ctx context.Context, id uuid.UUID) (*entity.Dependency, error)
	GetByScanResultID(ctx context.Context, scanResultID uuid.UUID) ([]*entity.Dependency, error)
	GetByRepositoryID(ctx context.Context, repoID uuid.UUID) ([]*entity.Dependency, error)
	GetOutdatedByRepositoryID(ctx context.Context, repoID uuid.UUID) ([]*entity.Dependency, error)
	DeleteByScanResultID(ctx context.Context, scanResultID uuid.UUID) error
}
