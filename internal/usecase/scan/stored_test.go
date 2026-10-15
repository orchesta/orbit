package scan

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/orchesta/orbit/internal/domain/entity"
	"github.com/orchesta/orbit/internal/domain/repository"
)

type storedScanRepo struct {
	repository.ScanResultRepo
	scan *entity.ScanResult
	err  error
}

func (f storedScanRepo) GetByID(context.Context, uuid.UUID) (*entity.ScanResult, error) {
	return f.scan, f.err
}

type storedDepRepo struct {
	repository.DependencyRepo
	deps []*entity.Dependency
}

func (f storedDepRepo) GetByScanResultID(context.Context, uuid.UUID) ([]*entity.Dependency, error) {
	return f.deps, nil
}

type storedVulnRepo struct {
	repository.VulnerabilityRepo
	vulns []*entity.Vulnerability
	err   error
}

func (f storedVulnRepo) GetByScanResultID(context.Context, uuid.UUID) ([]*entity.Vulnerability, error) {
	return f.vulns, f.err
}

func storedUseCase(scans storedScanRepo, deps []*entity.Dependency, vulns storedVulnRepo) *UseCase {
	return NewUseCase(nil, scans, storedDepRepo{deps: deps}, vulns, nil, nil, nil, Options{}, discardLogger())
}

func TestCompletedScanResultLoadsACompletedScan(t *testing.T) {
	s := entity.NewScanResult(uuid.New())
	s.Complete(1, 0, 1, 1)
	dep := entity.NewDependency(s.RepositoryID, s.ID, "lodash", "4.17.15", "package-lock.json", entity.EcosystemNpm)
	vuln := entity.NewVulnerability(dep.ID, "GHSA-1", "bad", entity.SeverityHigh)
	got, res, err := storedUseCase(storedScanRepo{scan: s}, []*entity.Dependency{dep},
		storedVulnRepo{vulns: []*entity.Vulnerability{vuln}}).CompletedScanResult(context.Background(), s.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got != s || len(res.Dependencies) != 1 || len(res.Vulnerabilities) != 1 {
		t.Fatalf("scan %+v, result %+v", got, res)
	}
}

func TestCompletedScanResultRefusesMissingAndUnfinishedScans(t *testing.T) {
	if _, _, err := storedUseCase(storedScanRepo{}, nil, storedVulnRepo{}).CompletedScanResult(context.Background(), uuid.New()); !errors.Is(err, ErrScanNotFound) {
		t.Errorf("missing scan: err = %v", err)
	}
	for _, st := range []entity.ScanStatus{entity.ScanStatusPending, entity.ScanStatusRunning, entity.ScanStatusFailed} {
		s := entity.NewScanResult(uuid.New())
		s.Status = st
		if _, _, err := storedUseCase(storedScanRepo{scan: s}, nil, storedVulnRepo{}).CompletedScanResult(context.Background(), s.ID); !errors.Is(err, ErrScanNotCompleted) {
			t.Errorf("%s scan: err = %v", st, err)
		}
	}
}

func TestCompletedScanResultPassesStoreErrors(t *testing.T) {
	boom := errors.New("db down")
	if _, _, err := storedUseCase(storedScanRepo{err: boom}, nil, storedVulnRepo{}).CompletedScanResult(context.Background(), uuid.New()); !errors.Is(err, boom) {
		t.Errorf("scan lookup: err = %v, want the store error", err)
	}
	s := entity.NewScanResult(uuid.New())
	s.Complete(0, 0, 0, 0)
	if _, _, err := storedUseCase(storedScanRepo{scan: s}, nil, storedVulnRepo{err: boom}).CompletedScanResult(context.Background(), s.ID); !errors.Is(err, boom) {
		t.Errorf("vulnerabilities: err = %v, want the store error", err)
	}
}
