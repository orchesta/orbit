package scan

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	"github.com/orchesta/orbit/internal/domain/entity"
	"github.com/orchesta/orbit/internal/engine"
)

// SBOMSource is what an SBOM of one stored scan is built from.
type SBOMSource struct {
	Scan       *entity.ScanResult
	Repository *entity.Repository // nil if the repository row is gone
	Result     *engine.Result     // the scan's dependencies and vulnerabilities
}

// SBOMSource loads a completed scan with its repository, dependencies and
// vulnerabilities. It fails like CompletedScanResult: ErrScanNotFound,
// ErrScanNotCompleted or a store error.
func (uc *UseCase) SBOMSource(ctx context.Context, scanID uuid.UUID) (*SBOMSource, error) {
	s, res, err := uc.CompletedScanResult(ctx, scanID)
	if err != nil {
		return nil, err
	}
	repo, err := uc.repoRepo.GetByID(ctx, s.RepositoryID)
	if err != nil {
		return nil, fmt.Errorf("load repository: %w", err)
	}
	return &SBOMSource{Scan: s, Repository: repo, Result: res}, nil
}
