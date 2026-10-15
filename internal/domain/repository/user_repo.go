package repository

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/orchesta/orbit/internal/domain/entity"
)

// ErrSetupAlreadyCompleted is returned when the first admin has already been created.
var ErrSetupAlreadyCompleted = errors.New("setup already completed")

// UserRepo defines the interface for user persistence.
type UserRepo interface {
	Create(ctx context.Context, user *entity.User) error
	GetByID(ctx context.Context, id uuid.UUID) (*entity.User, error)
	GetByEmail(ctx context.Context, email string) (*entity.User, error)
	Count(ctx context.Context) (int, error)
	// CreateInitialAdmin creates the first admin and marks setup completed in
	// one atomic step. It returns ErrSetupAlreadyCompleted if setup is done.
	CreateInitialAdmin(ctx context.Context, user *entity.User) error
}

// SystemConfigRepo defines the interface for system configuration.
type SystemConfigRepo interface {
	Get(ctx context.Context, key string) (string, error)
	Set(ctx context.Context, key, value string) error
}
