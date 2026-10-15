//go:build integration

package postgres

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/orchesta/orbit/internal/domain/entity"
	"github.com/orchesta/orbit/internal/domain/repository"
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

	all, total, err := vulns.ListLatest(ctx, repository.VulnerabilityListFilter{}, 25, 0)
	if err != nil || total != 3 || len(all) != 3 {
		t.Fatalf("ListLatest = %d items, total %d, %v; want 3", len(all), total, err)
	}
	if all[0].Severity != entity.SeverityCritical || all[0].RepositoryName != "beta" || all[2].Severity != entity.SeverityUnknown {
		t.Fatalf("order = %s/%s, %s, %s; want critical first and unknown last", all[0].Severity, all[0].RepositoryName, all[1].Severity, all[2].Severity)
	}
	if all[0].PackageName == "" || all[0].CurrentVersion != "1.0.0" {
		t.Fatalf("finding lacks package details: %+v", all[0])
	}

	high, total, err := vulns.ListLatest(ctx, repository.VulnerabilityListFilter{Severity: "high"}, 25, 0)
	if err != nil || total != 1 || len(high) != 1 || high[0].RepositoryName != "alpha" {
		t.Fatalf("severity filter = %+v, %d, %v", high, total, err)
	}

	page2, total, err := vulns.ListLatest(ctx, repository.VulnerabilityListFilter{}, 2, 2)
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

// addVuln stores one vulnerability on a new dependency of scanID.
func addVuln(t *testing.T, ctx context.Context, deps *DependencyPostgresRepo, vulns *VulnerabilityPostgresRepo,
	repoID, scanID uuid.UUID, pkg, osvID string, aliases []string, sev entity.Severity) {
	t.Helper()
	d := entity.NewDependency(repoID, scanID, pkg, "1.0.0", "package-lock.json", entity.EcosystemNpm)
	if err := deps.CreateBatch(ctx, []*entity.Dependency{d}); err != nil {
		t.Fatal(err)
	}
	v := entity.NewVulnerability(d.ID, osvID, "summary", sev)
	v.Aliases = aliases
	if err := vulns.CreateBatch(ctx, []*entity.Vulnerability{v}); err != nil {
		t.Fatal(err)
	}
}

func TestLatestSummaryCountsMaliciousFindings(t *testing.T) {
	ctx := context.Background()
	pool := newTestPool(t)
	scans, deps, vulns := NewScanResultPostgresRepo(pool), NewDependencyPostgresRepo(pool), NewVulnerabilityPostgresRepo(pool)
	repoID := newQueueRepo(t, ctx, pool, "web")

	old := seedScanWithVulns(t, ctx, repoID, time.Now().Add(-2*time.Hour), scans, deps, vulns)
	addVuln(t, ctx, deps, vulns, repoID, old.ID, "superseded", "MAL-2025-00001", nil, entity.SeverityCritical)

	latest := seedScanWithVulns(t, ctx, repoID, time.Now().Add(-time.Hour), scans, deps, vulns, entity.SeverityHigh)
	addVuln(t, ctx, deps, vulns, repoID, latest.ID, "debug", "CVE-2025-59144",
		[]string{"MAL-2025-46974", "GHSA-4x49-vf9v-38px"}, entity.SeverityCritical)
	// Stored before Lookup rated MAL- advisories critical, ID in lower case.
	addVuln(t, ctx, deps, vulns, repoID, latest.ID, "chalk", "mal-2025-46969",
		[]string{"GHSA-2v46-p5h4-248w"}, entity.SeverityUnknown)
	addVuln(t, ctx, deps, vulns, repoID, latest.ID, "lodash", "CVE-2021-23337",
		[]string{"GHSA-35jh-r3h4-6jhm"}, entity.SeverityHigh)

	counts, _, err := vulns.LatestSummary(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if counts.Malicious != 2 || counts.Critical != 1 || counts.High != 2 || counts.Unknown != 1 {
		t.Fatalf("counts = %+v, want 2 malicious (1 critical, 1 unknown) and 2 high", counts)
	}
	n, err := LatestMaliciousCount(ctx, pool)
	if err != nil || n != 2 {
		t.Fatalf("LatestMaliciousCount = %d, %v; want 2 (the superseded scan does not count)", n, err)
	}
}

// TestMaliciousVulnMatchesHasMaliciousID keeps the SQL rule maliciousVuln in
// step with entity.HasMaliciousID, which duplicates it in Go.
func TestMaliciousVulnMatchesHasMaliciousID(t *testing.T) {
	ctx := context.Background()
	pool := newTestPool(t)
	scans, deps, vulns := NewScanResultPostgresRepo(pool), NewDependencyPostgresRepo(pool), NewVulnerabilityPostgresRepo(pool)
	repoID := newQueueRepo(t, ctx, pool, "web")
	scan := seedScanWithVulns(t, ctx, repoID, time.Now(), scans, deps, vulns)

	cases := []struct {
		name    string
		osvID   string
		aliases []string
	}{
		{"upper", "MAL-1", nil},
		{"lower", "mal-1", nil},
		{"mixed case", "Mal-1", nil},
		{"prefix only", "MAL", nil},
		{"prefix and dash only", "MAL-", nil},
		{"embedded prefix", "XMAL-1", nil},
		{"underscore", "MAL_1", nil},
		{"alias only", "CVE-2025-1", []string{"mal-2025-9"}},
		{"nil aliases", "CVE-2025-1", nil},
		{"empty aliases", "CVE-2025-1", []string{}},
		{"later alias", "CVE-2025-1", []string{"GHSA-aaaa-bbbb-cccc", "CVE-2025-2", "MAL-2025-3"}},
		{"no match in list", "CVE-2025-1", []string{"GHSA-aaaa-bbbb-cccc", "XMAL-1"}},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := entity.NewDependency(repoID, scan.ID, "pkg-"+string(rune('a'+i)), "1.0.0", "package-lock.json", entity.EcosystemNpm)
			if err := deps.CreateBatch(ctx, []*entity.Dependency{d}); err != nil {
				t.Fatal(err)
			}
			v := entity.NewVulnerability(d.ID, tc.osvID, "summary", entity.SeverityUnknown)
			v.Aliases = tc.aliases
			if err := vulns.CreateBatch(ctx, []*entity.Vulnerability{v}); err != nil {
				t.Fatal(err)
			}
			var got bool
			if err := pool.QueryRow(ctx, `SELECT `+maliciousVuln+` FROM vulnerabilities v WHERE v.id = $1`, v.ID).Scan(&got); err != nil {
				t.Fatal(err)
			}
			if want := entity.HasMaliciousID(tc.osvID, tc.aliases); got != want {
				t.Fatalf("SQL = %v, HasMaliciousID = %v for %q %q", got, want, tc.osvID, tc.aliases)
			}
		})
	}
}
