package repository

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/orchesta/orbit/internal/domain/entity"
)

// ErrScanNotOwned is returned when a worker writes to a scan that was
// reclaimed by another worker.
var ErrScanNotOwned = errors.New("scan is no longer owned by this worker")

// ScanResultRepo is the port for scan result persistence operations.
type ScanResultRepo interface {
	Create(ctx context.Context, scan *entity.ScanResult) error
	GetByID(ctx context.Context, id uuid.UUID) (*entity.ScanResult, error)
	GetByRepositoryID(ctx context.Context, repoID uuid.UUID, limit int) ([]*entity.ScanResult, error)
	GetLatestByRepositoryID(ctx context.Context, repoID uuid.UUID) (*entity.ScanResult, error)
	// Update saves scan. It returns ErrScanNotOwned when the stored attempts
	// differ from scan.Attempt.
	Update(ctx context.Context, scan *entity.ScanResult) error
	// Enqueue adds scan as pending unless the repository already has a pending
	// or running scan; then that scan is returned and created is false.
	Enqueue(ctx context.Context, scan *entity.ScanResult) (*entity.ScanResult, bool, error)
	// ClaimNext marks the oldest pending scan running and returns it, or nil
	// when nothing is queued. Concurrent callers never receive the same scan.
	ClaimNext(ctx context.Context) (*entity.ScanResult, error)
	// Heartbeat records that the worker running a scan is still alive. It
	// returns ErrScanNotOwned when the scan is not running under attempt.
	Heartbeat(ctx context.Context, id uuid.UUID, attempt int) error
	// Requeue returns a running scan to the queue without using up an attempt.
	// It returns ErrScanNotOwned when the scan is not running under attempt.
	Requeue(ctx context.Context, id uuid.UUID, attempt int) error
	// RecoverStale handles running scans whose heartbeat is older than
	// staleAfter: ones that used maxAttempts fail, the rest are requeued.
	RecoverStale(ctx context.Context, staleAfter time.Duration, maxAttempts int) (requeued, failed int, err error)
	// PruneHistory deletes a repository's finished scans beyond the newest
	// keep, always keeping its latest completed scan.
	PruneHistory(ctx context.Context, repoID uuid.UUID, keep int) (int, error)
}
