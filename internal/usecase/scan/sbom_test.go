package scan

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/orchesta/orbit/internal/domain/entity"
	"github.com/orchesta/orbit/internal/domain/repository"
)

// SBOMSource is CompletedScanResult plus the repository row; the refusals
// and store errors of CompletedScanResult are tested in stored_test.go.

type failingRepoRepo struct {
	repository.RepositoryRepo
	err error
}

func (f failingRepoRepo) GetByID(context.Context, uuid.UUID) (*entity.Repository, error) {
	return nil, f.err
}

func completedScan() (*entity.ScanResult, []*entity.Dependency, storedVulnRepo) {
	s := entity.NewScanResult(uuid.New())
	s.Complete(1, 0, 1, 1)
	dep := entity.NewDependency(s.RepositoryID, s.ID, "lodash", "4.17.15", "package-lock.json", entity.EcosystemNpm)
	vuln := entity.NewVulnerability(dep.ID, "GHSA-1", "bad", entity.SeverityHigh)
	return s, []*entity.Dependency{dep}, storedVulnRepo{vulns: []*entity.Vulnerability{vuln}}
}

func sbomUseCase(repos repository.RepositoryRepo, s *entity.ScanResult, deps []*entity.Dependency, vulns storedVulnRepo) *UseCase {
	return NewUseCase(repos, storedScanRepo{scan: s}, storedDepRepo{deps: deps}, vulns, nil, nil, nil, Options{}, discardLogger())
}

func TestSBOMSourceAddsTheRepository(t *testing.T) {
	s, deps, vulns := completedScan()
	src, err := sbomUseCase(&fakeRepoRepo{}, s, deps, vulns).SBOMSource(context.Background(), s.ID)
	if err != nil {
		t.Fatal(err)
	}
	if src.Scan != s {
		t.Errorf("scan = %+v, want %+v", src.Scan, s)
	}
	if src.Repository == nil || src.Repository.Name != "app" || src.Repository.ID != s.RepositoryID {
		t.Errorf("repository = %+v, want %q with ID %s", src.Repository, "app", s.RepositoryID)
	}
	if len(src.Result.Dependencies) != 1 || len(src.Result.Vulnerabilities) != 1 {
		t.Errorf("result = %+v", src.Result)
	}
}

func TestSBOMSourceWithoutTheRepositoryRow(t *testing.T) {
	s, deps, vulns := completedScan()
	src, err := sbomUseCase(&fakeRepoRepo{missing: true}, s, deps, vulns).SBOMSource(context.Background(), s.ID)
	if err != nil {
		t.Fatal(err)
	}
	if src.Repository != nil {
		t.Errorf("repository = %+v, want nil", src.Repository)
	}
	if src.Scan != s || len(src.Result.Dependencies) != 1 {
		t.Errorf("scan %+v, result %+v", src.Scan, src.Result)
	}
}

func TestSBOMSourcePassesRepositoryErrors(t *testing.T) {
	s, deps, vulns := completedScan()
	boom := errors.New("db down")
	if _, err := sbomUseCase(failingRepoRepo{err: boom}, s, deps, vulns).SBOMSource(context.Background(), s.ID); !errors.Is(err, boom) {
		t.Errorf("err = %v, want the store error", err)
	}
}
