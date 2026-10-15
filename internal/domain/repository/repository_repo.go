package repository

import (
	"context"
	"errors"
	"time"

	"github.com/aligoren/orbit/internal/domain/entity"
	"github.com/google/uuid"
)

// ErrDuplicate is returned by Create when a repository with the same URL is already stored.
var ErrDuplicate = errors.New("repository already exists")

// RepositoryRepo is the port for repository persistence operations.
type RepositoryRepo interface {
	// Create stores repo with next_scan_at set to nextScanAt. It returns
	// ErrDuplicate when the URL is already stored.
	Create(ctx context.Context, repo *entity.Repository, nextScanAt time.Time) error
	GetByID(ctx context.Context, id uuid.UUID) (*entity.Repository, error)
	GetAll(ctx context.Context) ([]*entity.Repository, error)
	GetActive(ctx context.Context) ([]*entity.Repository, error)
	// Update stores repo's editable columns. A non-nil nextScanAt also sets
	// next_scan_at in the same statement, so a schedule change and its next
	// run are saved together; nil leaves next_scan_at unchanged.
	Update(ctx context.Context, repo *entity.Repository, nextScanAt *time.Time) error
	Delete(ctx context.Context, id uuid.UUID) error
	// SetNextScanAt sets when the scheduler should next queue the repository.
	SetNextScanAt(ctx context.Context, id uuid.UUID, at time.Time) error
	// MarkScanned records when the repository was last scanned without
	// touching any other column.
	MarkScanned(ctx context.Context, id uuid.UUID, at time.Time) error
	// ClaimDueRepositories returns active repositories whose next scan is due
	// at now and moves each one's next_scan_at to next(schedule, now), in one
	// transaction that skips rows another scheduler is processing.
	ClaimDueRepositories(ctx context.Context, now time.Time, limit int, next func(schedule string, after time.Time) time.Time) ([]uuid.UUID, error)
	// ExistingURLs reports which of urls (compared normalized) are already stored,
	// keyed by the normalized URL.
	ExistingURLs(ctx context.Context, urls []string) (map[string]bool, error)
}
