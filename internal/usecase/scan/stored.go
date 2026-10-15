package scan

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"

	"github.com/orchesta/orbit/internal/domain/entity"
	"github.com/orchesta/orbit/internal/engine"
)

var (
	// ErrScanNotFound is returned for an unknown (or pruned) scan.
	ErrScanNotFound = errors.New("scan not found")
	// ErrScanNotCompleted is returned for a scan that is pending, running
	// or failed: its dependencies or vulnerabilities may be missing.
	ErrScanNotCompleted = errors.New("scan not completed")
)

// CompletedScanResult loads a completed scan with its stored dependencies
// and vulnerabilities, as an engine.Result that report.Build accepts. A
// scan that is not completed is refused (ErrScanNotCompleted): failIncomplete
// keeps the dependencies of a failed scan but not its vulnerabilities, so
// anything built from it would look clean.
func (uc *UseCase) CompletedScanResult(ctx context.Context, scanID uuid.UUID) (*entity.ScanResult, *engine.Result, error) {
	s, err := uc.scanRepo.GetByID(ctx, scanID)
	if err != nil {
		return nil, nil, fmt.Errorf("load scan: %w", err)
	}
	if s == nil {
		return nil, nil, ErrScanNotFound
	}
	if s.Status != entity.ScanStatusCompleted {
		return nil, nil, ErrScanNotCompleted
	}
	deps, err := uc.depRepo.GetByScanResultID(ctx, scanID)
	if err != nil {
		return nil, nil, fmt.Errorf("load dependencies: %w", err)
	}
	vulns, err := uc.vulnRepo.GetByScanResultID(ctx, scanID)
	if err != nil {
		return nil, nil, fmt.Errorf("load vulnerabilities: %w", err)
	}
	return s, &engine.Result{Dependencies: deps, Vulnerabilities: vulns}, nil
}
