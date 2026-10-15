//go:build integration

package scan_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/orchesta/orbit/internal/adapter/persistence/postgres"
	"github.com/orchesta/orbit/internal/domain/entity"
	"github.com/orchesta/orbit/internal/engine"
	"github.com/orchesta/orbit/internal/infrastructure/analyzer"
	"github.com/orchesta/orbit/internal/infrastructure/analyzer/golang"
	"github.com/orchesta/orbit/internal/infrastructure/analyzer/npm"
	"github.com/orchesta/orbit/internal/infrastructure/analyzer/nuget"
	"github.com/orchesta/orbit/internal/infrastructure/analyzer/pip"
	"github.com/orchesta/orbit/internal/infrastructure/config"
	"github.com/orchesta/orbit/internal/infrastructure/crypto"
	"github.com/orchesta/orbit/internal/infrastructure/git"
	"github.com/orchesta/orbit/internal/usecase/scan"
)

// parityLatest answers the registries offline; a missing name is an error,
// so that package keeps no latest version.
var parityLatest = map[string]string{
	"express":  "4.21.2",
	"accepts":  "1.3.8",
	"jest":     "29.7.0",
	"requests": "2.32.3",
	"flask":    "3.0.0",
}

// parityAdvisory is one advisory the fake lookup reports.
type parityAdvisory struct {
	id       string
	severity entity.Severity
	summary  string
}

// parityAdvisories are the advisories the fake lookup reports per package.
var parityAdvisories = map[string][]parityAdvisory{
	"express": {
		{"GHSA-qw6h-vgh9-j6wx", entity.SeverityLow, "express vulnerable to XSS via response.redirect()"},
		{"GHSA-rv95-896h-c2vc", entity.SeverityMedium, "Express.js Open Redirect in malformed URLs"},
	},
	"requests": {
		{"GHSA-9wx4-h78v-vm56", entity.SeverityMedium, "Requests Session object does not verify requests after making first request with verify=False"},
	},
}

// wantParityDeps and wantParityVulns pin what both the engine and a server
// scan must produce for the parity checkout (see describeDeps and
// describeVulns), so a regression shared by both paths is caught too.
var wantParityDeps = []string{
	`Go svc/go.mod github.com/google/uuid@1.6.0 direct=true resolved=false dev=false latest="" outdated=false update=none license=""`,
	`PyPI svc/requirements.txt flask@2.0 direct=true resolved=false dev=false latest="3.0.0" outdated=true update=major license=""`,
	`PyPI svc/requirements.txt requests@2.31.0 direct=true resolved=true dev=false latest="2.32.3" outdated=true update=minor license=""`,
	`npm package-lock.json accepts@1.3.8 direct=false resolved=true dev=false latest="1.3.8" outdated=false update=none license="MIT"`,
	`npm package-lock.json express@4.18.2 direct=true resolved=true dev=false latest="4.21.2" outdated=true update=minor license="MIT"`,
	`npm package-lock.json jest@29.7.0 direct=true resolved=true dev=true latest="29.7.0" outdated=false update=none license=""`,
}

var wantParityVulns = []string{
	`GHSA-9wx4-h78v-vm56 medium "Requests Session object does not verify requests after making first request with verify=False" -> svc/requirements.txt requests@2.31.0`,
	`GHSA-qw6h-vgh9-j6wx low "express vulnerable to XSS via response.redirect()" -> package-lock.json express@4.18.2`,
	`GHSA-rv95-896h-c2vc medium "Express.js Open Redirect in malformed URLs" -> package-lock.json express@4.18.2`,
}

// offlineAnalyzer parses with a real analyzer but answers GetLatestVersion
// from parityLatest.
type offlineAnalyzer struct{ analyzer.Analyzer }

// MatchesFile keeps the wrapped analyzer's FileMatcher (pip's requirements
// files), which embedding the interface would hide.
func (a offlineAnalyzer) MatchesFile(p string) bool {
	fm, ok := a.Analyzer.(analyzer.FileMatcher)
	return ok && fm.MatchesFile(p)
}

func (offlineAnalyzer) GetLatestVersion(_ context.Context, name string) (string, error) {
	if v, ok := parityLatest[name]; ok {
		return v, nil
	}
	return "", errors.New("not found")
}

type parityLookup struct{}

func (parityLookup) Lookup(_ context.Context, deps []*entity.Dependency) ([]*entity.Vulnerability, int, error) {
	var vulns []*entity.Vulnerability
	vulnerable := 0
	for _, d := range deps {
		advs := parityAdvisories[d.Name]
		for _, a := range advs {
			vulns = append(vulns, entity.NewVulnerability(d.ID, a.id, a.summary, a.severity))
		}
		if len(advs) > 0 {
			vulnerable++
		}
	}
	return vulns, vulnerable, nil
}

func parityEngine() *engine.Engine {
	reg := analyzer.NewRegistry()
	for _, a := range []analyzer.Analyzer{npm.NewAnalyzer(), pip.NewAnalyzer(), nuget.NewAnalyzer(), golang.NewAnalyzer()} {
		reg.Register(offlineAnalyzer{a})
	}
	return engine.New(reg, parityLookup{}, engine.Options{CheckLatest: true})
}

// writeParityProject lays the engine's fixed testdata out as one checkout:
// an npm project with a lockfile at the root and a Go + pip service in svc/.
func writeParityProject(dest string) error {
	testdata := filepath.Join("..", "..", "engine", "testdata")
	if err := os.CopyFS(dest, os.DirFS(filepath.Join(testdata, "npm-lock"))); err != nil {
		return err
	}
	return os.CopyFS(filepath.Join(dest, "svc"), os.DirFS(filepath.Join(testdata, "mixed")))
}

type parityCloner struct{}

func (parityCloner) Clone(_ context.Context, opts git.CloneOptions) error {
	return writeParityProject(opts.DestPath)
}

// newParityPool creates a fresh, fully migrated database on
// ORBIT_TEST_DATABASE_URL's server and drops it after the test.
func newParityPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("ORBIT_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("ORBIT_TEST_DATABASE_URL is not set")
	}
	ctx := context.Background()
	admin := connectWithRetry(t, dsn)
	name := "orbit_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		_ = admin.Close(ctx)
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = admin.Exec(context.Background(), "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)")
		_ = admin.Close(context.Background())
	})
	pc, err := pgconn.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.DatabaseConfig{Host: pc.Host, Port: int(pc.Port), User: pc.User, Password: pc.Password, Name: name, SSLMode: "disable"}
	if err := postgres.RunMigrations(cfg, slog.New(slog.NewTextHandler(io.Discard, nil))); err != nil {
		t.Fatal(err)
	}
	pool, err := pgxpool.New(ctx, cfg.DSN())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// connectWithRetry waits for a freshly started Postgres container to accept
// connections.
func connectWithRetry(t *testing.T, dsn string) *pgx.Conn {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for {
		conn, err := pgx.Connect(context.Background(), dsn)
		if err == nil {
			return conn
		}
		if time.Now().After(deadline) {
			t.Fatalf("connect to test database: %v", err)
		}
		time.Sleep(time.Second)
	}
}

// describeDeps renders deps without IDs, sorted, so two runs compare.
func describeDeps(deps []*entity.Dependency) []string {
	var out []string
	for _, d := range deps {
		out = append(out, fmt.Sprintf("%s %s %s@%s direct=%v resolved=%v dev=%v latest=%q outdated=%v update=%s license=%q",
			d.Ecosystem, d.ManifestFile, d.Name, d.CurrentVersion, d.IsDirect, d.IsResolved, d.IsDev,
			d.LatestVersion, d.IsOutdated, d.UpdateType, d.License))
	}
	slices.Sort(out)
	return out
}

// describeVulns renders each finding by its dependency, sorted.
func describeVulns(vulns []*entity.Vulnerability, deps []*entity.Dependency) []string {
	byID := make(map[uuid.UUID]*entity.Dependency, len(deps))
	for _, d := range deps {
		byID[d.ID] = d
	}
	var out []string
	for _, v := range vulns {
		d := byID[v.DependencyID]
		if d == nil {
			out = append(out, v.OSVID+" -> unknown dependency "+v.DependencyID.String())
			continue
		}
		out = append(out, fmt.Sprintf("%s %s %q -> %s %s@%s", v.OSVID, v.Severity, v.Summary, d.ManifestFile, d.Name, d.CurrentVersion))
	}
	slices.Sort(out)
	return out
}

// A server scan stores exactly what the engine finds for the same checkout.
func TestServerScanMatchesEngine(t *testing.T) {
	ctx := context.Background()
	pool := newParityPool(t)

	// What the engine finds on its own.
	root := t.TempDir()
	if err := writeParityProject(root); err != nil {
		t.Fatal(err)
	}
	want, err := parityEngine().Analyze(ctx, root)
	if err != nil {
		t.Fatal(err)
	}
	if got := describeDeps(want.Dependencies); !slices.Equal(got, wantParityDeps) {
		t.Fatalf("engine dependencies:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(wantParityDeps, "\n"))
	}
	if got := describeVulns(want.Vulnerabilities, want.Dependencies); !slices.Equal(got, wantParityVulns) {
		t.Fatalf("engine vulnerabilities:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(wantParityVulns, "\n"))
	}
	if want.OutdatedDeps != 3 || want.VulnerableDeps != 2 {
		t.Fatalf("engine counts: %d outdated, %d vulnerable; want 3 and 2", want.OutdatedDeps, want.VulnerableDeps)
	}

	// The same checkout through a server scan.
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	secrets, err := crypto.NewEncryptor(key)
	if err != nil {
		t.Fatal(err)
	}
	repoRepo := postgres.NewRepositoryPostgresRepo(pool, secrets)
	scanRepo := postgres.NewScanResultPostgresRepo(pool)
	depRepo := postgres.NewDependencyPostgresRepo(pool)
	vulnRepo := postgres.NewVulnerabilityPostgresRepo(pool)

	repo := entity.NewRepository("parity", "https://github.com/o/parity", entity.GitProviderGitHub, "")
	if err := repoRepo.Create(ctx, repo, time.Now().UTC().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	s := entity.NewScanResult(repo.ID)
	s.Start()
	if err := scanRepo.Create(ctx, s); err != nil {
		t.Fatal(err)
	}

	uc := scan.NewUseCase(repoRepo, scanRepo, depRepo, vulnRepo, parityEngine(),
		func(entity.GitProvider) (git.Cloner, error) { return parityCloner{}, nil },
		postgres.NewGitHostPostgresRepo(pool),
		scan.Options{WorkDir: t.TempDir(), CloneTimeout: time.Minute},
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err := uc.Run(ctx, s); err != nil {
		t.Fatal(err)
	}

	stored, err := scanRepo.GetByID(ctx, s.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Status != entity.ScanStatusCompleted {
		t.Fatalf("scan status = %s (%v), want completed", stored.Status, stored.Error)
	}
	gotDeps, err := depRepo.GetByScanResultID(ctx, s.ID)
	if err != nil {
		t.Fatal(err)
	}
	gotVulns, err := vulnRepo.GetByScanResultID(ctx, s.ID)
	if err != nil {
		t.Fatal(err)
	}

	if len(gotDeps) != len(want.Dependencies) || len(gotVulns) != len(want.Vulnerabilities) {
		t.Fatalf("database has %d dependencies and %d vulnerabilities, engine found %d and %d",
			len(gotDeps), len(gotVulns), len(want.Dependencies), len(want.Vulnerabilities))
	}
	if got := describeDeps(gotDeps); !slices.Equal(got, wantParityDeps) {
		t.Fatalf("stored dependencies:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(wantParityDeps, "\n"))
	}
	if got := describeVulns(gotVulns, gotDeps); !slices.Equal(got, wantParityVulns) {
		t.Fatalf("stored vulnerabilities:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(wantParityVulns, "\n"))
	}
	for _, d := range gotDeps {
		if d.RepositoryID != repo.ID {
			t.Fatalf("%s: repository_id = %s, want %s", d.Name, d.RepositoryID, repo.ID)
		}
	}
	if stored.TotalDeps != 6 || stored.OutdatedDeps != 3 || stored.VulnerableDeps != 2 || stored.TotalVulns != 3 {
		t.Fatalf("scan counts = %d deps, %d outdated, %d vulnerable, %d vulns; want 6, 3, 2, 3",
			stored.TotalDeps, stored.OutdatedDeps, stored.VulnerableDeps, stored.TotalVulns)
	}
}
