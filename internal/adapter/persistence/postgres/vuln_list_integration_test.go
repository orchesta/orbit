//go:build integration

package postgres

import (
	"context"
	"testing"
	"time"

	"github.com/aligoren/orbit/internal/domain/entity"
	"github.com/google/uuid"
)

// seedScanWithVulns stores a completed scan for repoID with one dependency per
// severity given and returns the scan.
func seedScanWithVulns(t *testing.T, ctx context.Context, repoID uuid.UUID, startedAt time.Time, scans *ScanResultPostgresRepo, deps *DependencyPostgresRepo, vulns *VulnerabilityPostgresRepo, severities ...entity.Severity) *entity.ScanResult {
	t.Helper()
	s := entity.NewScanResult(repoID)
	s.StartedAt = startedAt
	s.Complete(len(severities), 0, len(severities), len(severities))
	if err := scans.Create(ctx, s); err != nil {
		t.Fatal(err)
	}
	for i, sev := range severities {
		d := entity.NewDependency(repoID, s.ID, "pkg-"+string(sev), "1.0.0", "package.json", entity.EcosystemNpm)
		if err := deps.CreateBatch(ctx, []*entity.Dependency{d}); err != nil {
			t.Fatal(err)
		}
		v := entity.NewVulnerability(d.ID, "OSV-"+string(sev)+"-"+string(rune('a'+i)), "summary", sev)
		if err := vulns.CreateBatch(ctx, []*entity.Vulnerability{v}); err != nil {
			t.Fatal(err)
		}
	}
	return s
}

func TestListLatestVulnerabilitiesUsesLatestCompletedScans(t *testing.T) {
	ctx := context.Background()
	pool := newTestPool(t)
	scans, deps, vulns := NewScanResultPostgresRepo(pool), NewDependencyPostgresRepo(pool), NewVulnerabilityPostgresRepo(pool)
	a, b := newQueueRepo(t, ctx, pool, "alpha"), newQueueRepo(t, ctx, pool, "beta")

	seedScanWithVulns(t, ctx, a, time.Now().Add(-2*time.Hour), scans, deps, vulns, entity.SeverityCritical, entity.SeverityLow) // superseded
	seedScanWithVulns(t, ctx, a, time.Now().Add(-time.Hour), scans, deps, vulns, entity.SeverityHigh, entity.SeverityUnknown)
	seedScanWithVulns(t, ctx, b, time.Now().Add(-time.Hour), scans, deps, vulns, entity.SeverityCritical)

	all, total, err := vulns.ListLatest(ctx, "", 25, 0)
	if err != nil || total != 3 || len(all) != 3 {
		t.Fatalf("ListLatest = %d items, total %d, %v; want 3", len(all), total, err)
	}
	if all[0].Severity != entity.SeverityCritical || all[0].RepositoryName != "beta" || all[2].Severity != entity.SeverityUnknown {
		t.Fatalf("order = %s/%s, %s, %s; want critical first and unknown last", all[0].Severity, all[0].RepositoryName, all[1].Severity, all[2].Severity)
	}
	if all[0].PackageName == "" || all[0].CurrentVersion != "1.0.0" {
		t.Fatalf("finding lacks package details: %+v", all[0])
	}

	high, total, err := vulns.ListLatest(ctx, "high", 25, 0)
	if err != nil || total != 1 || len(high) != 1 || high[0].RepositoryName != "alpha" {
		t.Fatalf("severity filter = %+v, %d, %v", high, total, err)
	}

	page2, total, err := vulns.ListLatest(ctx, "", 2, 2)
	if err != nil || total != 3 || len(page2) != 1 {
		t.Fatalf("second page = %d items, total %d, %v", len(page2), total, err)
	}
}

func TestLatestSummaryCountsSeveritiesAndUnverifiedRepos(t *testing.T) {
	ctx := context.Background()
	pool := newTestPool(t)
	scans, deps, vulns := NewScanResultPostgresRepo(pool), NewDependencyPostgresRepo(pool), NewVulnerabilityPostgresRepo(pool)
	ok := newQueueRepo(t, ctx, pool, "ok")
	newQueueRepo(t, ctx, pool, "never-scanned")
	failedNewest := newQueueRepo(t, ctx, pool, "failed-newest")

	seedScanWithVulns(t, ctx, ok, time.Now().Add(-time.Hour), scans, deps, vulns, entity.SeverityCritical, entity.SeverityUnknown, entity.SeverityUnknown)
	seedScanWithVulns(t, ctx, failedNewest, time.Now().Add(-2*time.Hour), scans, deps, vulns, entity.SeverityLow)
	if _, err := pool.Exec(ctx, "INSERT INTO scan_results (id, repository_id, status, started_at) VALUES ($1, $2, 'failed', NOW())", uuid.New(), failedNewest); err != nil {
		t.Fatal(err)
	}

	counts, unverified, err := vulns.LatestSummary(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if counts.Critical != 1 || counts.Low != 1 || counts.Unknown != 2 || counts.High != 0 {
		t.Fatalf("counts = %+v", counts)
	}
	if unverified != 2 {
		t.Fatalf("unverified = %d, want 2 (never scanned + newest scan failed)", unverified)
	}
}

func TestUnverifiedRepoCountMatchesLatestSummary(t *testing.T) {
	ctx := context.Background()
	pool := newTestPool(t)
	scans, deps, vulns := NewScanResultPostgresRepo(pool), NewDependencyPostgresRepo(pool), NewVulnerabilityPostgresRepo(pool)
	ok := newQueueRepo(t, ctx, pool, "ok")
	newQueueRepo(t, ctx, pool, "never-scanned")
	failedNewest := newQueueRepo(t, ctx, pool, "failed-newest")
	seedScanWithVulns(t, ctx, ok, time.Now().Add(-time.Hour), scans, deps, vulns, entity.SeverityHigh)
	seedScanWithVulns(t, ctx, failedNewest, time.Now().Add(-2*time.Hour), scans, deps, vulns, entity.SeverityLow)
	if _, err := pool.Exec(ctx, "INSERT INTO scan_results (id, repository_id, status, started_at) VALUES ($1, $2, 'failed', NOW())", uuid.New(), failedNewest); err != nil {
		t.Fatal(err)
	}

	got, err := UnverifiedRepoCount(ctx, pool)
	if err != nil || got != 2 {
		t.Fatalf("UnverifiedRepoCount = %d, %v; want 2", got, err)
	}
	_, want, err := vulns.LatestSummary(ctx)
	if err != nil || got != want {
		t.Fatalf("UnverifiedRepoCount = %d, LatestSummary = %d, %v; they must agree", got, want, err)
	}
}

func TestNewestScanStatusLateralReportsNewestScanOrNull(t *testing.T) {
	ctx := context.Background()
	pool := newTestPool(t)
	scans, deps, vulns := NewScanResultPostgresRepo(pool), NewDependencyPostgresRepo(pool), NewVulnerabilityPostgresRepo(pool)
	never := newQueueRepo(t, ctx, pool, "never")
	done := newQueueRepo(t, ctx, pool, "done")
	running := newQueueRepo(t, ctx, pool, "running")
	seedScanWithVulns(t, ctx, done, time.Now().Add(-time.Hour), scans, deps, vulns, entity.SeverityLow)
	seedScanWithVulns(t, ctx, running, time.Now().Add(-2*time.Hour), scans, deps, vulns, entity.SeverityLow)
	if _, err := pool.Exec(ctx, "INSERT INTO scan_results (id, repository_id, status, started_at) VALUES ($1, $2, 'running', NOW())", uuid.New(), running); err != nil {
		t.Fatal(err)
	}

	rows, err := pool.Query(ctx, `SELECT r.id, ns.status FROM repositories r `+NewestScanStatusJoin)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	got := map[uuid.UUID]*string{}
	for rows.Next() {
		var id uuid.UUID
		var status *string
		if err := rows.Scan(&id, &status); err != nil {
			t.Fatal(err)
		}
		got[id] = status
	}
	if got[never] != nil {
		t.Errorf("never-scanned status = %v, want nil", *got[never])
	}
	if s := got[done]; s == nil || *s != "completed" {
		t.Errorf("done status = %v, want completed", s)
	}
	if s := got[running]; s == nil || *s != "running" {
		t.Errorf("running status = %v, want running (newest scan wins over the older completed one)", s)
	}
}
