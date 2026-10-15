//go:build integration

package postgres

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/orchesta/orbit/internal/domain/entity"
)

func completedScan(t *testing.T, ctx context.Context, scans *ScanResultPostgresRepo, repoID uuid.UUID, startedAt time.Time, vulnerable, total int) *entity.ScanResult {
	t.Helper()
	s := entity.NewScanResult(repoID)
	s.StartedAt = startedAt
	s.Complete(1, 0, vulnerable, total)
	if err := scans.Create(ctx, s); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestCreateBatchHandlesLargeScans(t *testing.T) {
	ctx := context.Background()
	pool := newTestPool(t)
	repoID := newQueueRepo(t, ctx, pool, "mono")
	s := completedScan(t, ctx, NewScanResultPostgresRepo(pool), repoID, time.Now(), 0, 0)

	deps := make([]*entity.Dependency, 6000)
	for i := range deps {
		deps[i] = entity.NewDependency(repoID, s.ID, fmt.Sprintf("pkg-%d", i), "git+https://github.com/o/r.git#"+strings.Repeat("a", 40), "package.json", entity.EcosystemNpm)
	}
	if err := NewDependencyPostgresRepo(pool).CreateBatch(ctx, deps); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := pool.QueryRow(ctx, "SELECT COUNT(*) FROM dependencies WHERE scan_result_id = $1", s.ID).Scan(&n); err != nil || n != 6000 {
		t.Fatalf("stored %d deps (%v), want 6000", n, err)
	}
}

func TestVulnerabilityCreateBatchIsAtomic(t *testing.T) {
	ctx := context.Background()
	pool := newTestPool(t)
	repoID := newQueueRepo(t, ctx, pool, "a")
	s := completedScan(t, ctx, NewScanResultPostgresRepo(pool), repoID, time.Now(), 0, 0)
	dep := entity.NewDependency(repoID, s.ID, "lodash", "4.17.0", "package.json", entity.EcosystemNpm)
	if err := NewDependencyPostgresRepo(pool).CreateBatch(ctx, []*entity.Dependency{dep}); err != nil {
		t.Fatal(err)
	}
	good := entity.NewVulnerability(dep.ID, "CVE-1", "ok", entity.SeverityHigh)
	orphan := entity.NewVulnerability(uuid.New(), "CVE-2", "no such dependency", entity.SeverityLow)
	if err := NewVulnerabilityPostgresRepo(pool).CreateBatch(ctx, []*entity.Vulnerability{good, orphan}); err == nil {
		t.Fatal("a batch with an invalid row must fail")
	}
	var n int
	if err := pool.QueryRow(ctx, "SELECT COUNT(*) FROM vulnerabilities").Scan(&n); err != nil || n != 0 {
		t.Fatalf("partial batch left %d rows (%v); want 0", n, err)
	}
}

func TestRepositoryQueriesUseLatestCompletedScan(t *testing.T) {
	ctx := context.Background()
	pool := newTestPool(t)
	scans := NewScanResultPostgresRepo(pool)
	repoID := newQueueRepo(t, ctx, pool, "a")
	good := completedScan(t, ctx, scans, repoID, time.Now().Add(-time.Hour), 1, 1)
	dep := entity.NewDependency(repoID, good.ID, "lodash", "4.17.0", "package.json", entity.EcosystemNpm)
	if err := NewDependencyPostgresRepo(pool).CreateBatch(ctx, []*entity.Dependency{dep}); err != nil {
		t.Fatal(err)
	}
	if err := NewVulnerabilityPostgresRepo(pool).CreateBatch(ctx, []*entity.Vulnerability{entity.NewVulnerability(dep.ID, "CVE-1", "x", entity.SeverityHigh)}); err != nil {
		t.Fatal(err)
	}
	// A newer scan failed; it must not hide the last good results.
	if _, err := pool.Exec(ctx, "INSERT INTO scan_results (id, repository_id, status, started_at) VALUES ($1, $2, 'failed', NOW())", uuid.New(), repoID); err != nil {
		t.Fatal(err)
	}

	deps, err := NewDependencyPostgresRepo(pool).GetByRepositoryID(ctx, repoID)
	if err != nil || len(deps) != 1 {
		t.Fatalf("deps = %d, %v; want 1 from the last completed scan", len(deps), err)
	}
	vulns, err := NewVulnerabilityPostgresRepo(pool).GetByRepositoryID(ctx, repoID)
	if err != nil || len(vulns) != 1 {
		t.Fatalf("vulns = %d, %v; want 1 from the last completed scan", len(vulns), err)
	}
}

func TestLatestScanTotalsCountOnlyLatestCompleted(t *testing.T) {
	ctx := context.Background()
	pool := newTestPool(t)
	scans := NewScanResultPostgresRepo(pool)
	a, b := newQueueRepo(t, ctx, pool, "a"), newQueueRepo(t, ctx, pool, "b")
	completedScan(t, ctx, scans, a, time.Now().Add(-2*time.Hour), 4, 9) // superseded
	completedScan(t, ctx, scans, a, time.Now().Add(-time.Hour), 2, 3)
	completedScan(t, ctx, scans, b, time.Now().Add(-time.Hour), 1, 5)

	vulnerable, total, err := LatestScanTotals(ctx, pool)
	if err != nil || vulnerable != 3 || total != 8 {
		t.Fatalf("LatestScanTotals = %d, %d, %v; want 3, 8", vulnerable, total, err)
	}
}

func TestDependencyResolutionFlagsRoundTrip(t *testing.T) {
	ctx := context.Background()
	pool := newTestPool(t)
	scans, deps, vulns := NewScanResultPostgresRepo(pool), NewDependencyPostgresRepo(pool), NewVulnerabilityPostgresRepo(pool)
	repoID := newQueueRepo(t, ctx, pool, "flags")
	s := entity.NewScanResult(repoID)
	s.Complete(0, 0, 0, 0)
	if err := scans.Create(ctx, s); err != nil {
		t.Fatal(err)
	}
	d := entity.NewDependency(repoID, s.ID, "lodash", "4.17.21", "package-lock.json", entity.EcosystemNpm)
	d.IsResolved, d.IsDev = true, true
	plain := entity.NewDependency(repoID, s.ID, "zzz", "1.0.0", "package.json", entity.EcosystemNpm)
	if err := deps.CreateBatch(ctx, []*entity.Dependency{d, plain}); err != nil {
		t.Fatal(err)
	}
	got, err := deps.GetByScanResultID(ctx, s.ID)
	if err != nil || len(got) != 2 {
		t.Fatalf("GetByScanResultID = %d, %v", len(got), err)
	}
	if !got[0].IsResolved || !got[0].IsDev || got[1].IsResolved || got[1].IsDev {
		t.Fatalf("flags = %+v / %+v", got[0], got[1])
	}
	byID, err := deps.GetByID(ctx, d.ID)
	if err != nil || !byID.IsResolved || !byID.IsDev {
		t.Fatalf("GetByID = %+v, %v", byID, err)
	}

	long := strings.Repeat("1", 150)
	v := entity.NewVulnerability(d.ID, "OSV-LONG", "s", entity.SeverityHigh)
	v.FixedVersion = &long
	if err := vulns.CreateBatch(ctx, []*entity.Vulnerability{v}); err != nil {
		t.Fatalf("long fixed_version: %v", err)
	}
}

// With lockfiles a package can have several rows; every dependency list is
// ordered by name, version and file so the order is stable between reads.
func TestDependencyListsAreTotallyOrdered(t *testing.T) {
	ctx := context.Background()
	pool := newTestPool(t)
	scans, deps := NewScanResultPostgresRepo(pool), NewDependencyPostgresRepo(pool)
	repoID := newQueueRepo(t, ctx, pool, "order")
	s := completedScan(t, ctx, scans, repoID, time.Now(), 0, 0)
	// Inserted in the reverse of the expected order.
	var rows []*entity.Dependency
	for _, r := range [][2]string{
		{"4.17.21", "package-lock.json"},
		{"4.17.21", "a/package-lock.json"},
		{"4.17.15", "package-lock.json"},
	} {
		d := entity.NewDependency(repoID, s.ID, "lodash", r[0], r[1], entity.EcosystemNpm)
		d.IsOutdated, d.UpdateType = true, entity.UpdateTypePatch
		rows = append(rows, d)
	}
	if err := deps.CreateBatch(ctx, rows); err != nil {
		t.Fatal(err)
	}
	want := "lodash@4.17.15 package-lock.json, lodash@4.17.21 a/package-lock.json, lodash@4.17.21 package-lock.json"
	for name, list := range map[string]func() ([]*entity.Dependency, error){
		"GetByScanResultID":         func() ([]*entity.Dependency, error) { return deps.GetByScanResultID(ctx, s.ID) },
		"GetByRepositoryID":         func() ([]*entity.Dependency, error) { return deps.GetByRepositoryID(ctx, repoID) },
		"GetOutdatedByRepositoryID": func() ([]*entity.Dependency, error) { return deps.GetOutdatedByRepositoryID(ctx, repoID) },
	} {
		got, err := list()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		var parts []string
		for _, d := range got {
			parts = append(parts, fmt.Sprintf("%s@%s %s", d.Name, d.CurrentVersion, d.ManifestFile))
		}
		if strings.Join(parts, ", ") != want {
			t.Errorf("%s = %s; want %s", name, strings.Join(parts, ", "), want)
		}
	}
}
