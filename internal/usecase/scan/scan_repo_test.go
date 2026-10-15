package scan

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/orchesta/orbit/internal/domain/entity"
	"github.com/orchesta/orbit/internal/domain/repository"
	"github.com/orchesta/orbit/internal/engine"
	"github.com/orchesta/orbit/internal/infrastructure/analyzer"
	"github.com/orchesta/orbit/internal/infrastructure/exploit"
	"github.com/orchesta/orbit/internal/infrastructure/git"
)

type fakeRepoRepo struct {
	repository.RepositoryRepo
	missing bool
	repo    *entity.Repository // returned by GetByID when set
	marked  []uuid.UUID
	nextAt  map[uuid.UUID]time.Time // SetNextScanAt calls
}

func (f *fakeRepoRepo) SetNextScanAt(_ context.Context, id uuid.UUID, at time.Time) error {
	if f.nextAt == nil {
		f.nextAt = map[uuid.UUID]time.Time{}
	}
	f.nextAt[id] = at
	return nil
}

func (f *fakeRepoRepo) GetByID(_ context.Context, id uuid.UUID) (*entity.Repository, error) {
	if f.missing {
		return nil, nil
	}
	if f.repo != nil {
		r := *f.repo
		r.ID = id
		return &r, nil
	}
	r := entity.NewRepository("app", "https://github.com/o/app", entity.GitProviderGitHub, "")
	r.ID = id
	return r, nil
}
func (f *fakeRepoRepo) Update(context.Context, *entity.Repository, *time.Time) error { return nil }
func (f *fakeRepoRepo) MarkScanned(_ context.Context, id uuid.UUID, _ time.Time) error {
	f.marked = append(f.marked, id)
	return nil
}

type fakeScanRepo struct {
	repository.ScanResultRepo
	last     entity.ScanResult
	updates  int
	enqueued []uuid.UUID
	existing bool // an active scan already exists, so Enqueue queues nothing
	pruned   map[uuid.UUID]int
}

func (f *fakeScanRepo) Create(_ context.Context, s *entity.ScanResult) error { f.last = *s; return nil }
func (f *fakeScanRepo) Update(_ context.Context, s *entity.ScanResult) error {
	f.last = *s
	f.updates++
	return nil
}
func (f *fakeScanRepo) Enqueue(_ context.Context, s *entity.ScanResult) (*entity.ScanResult, bool, error) {
	f.enqueued = append(f.enqueued, s.RepositoryID)
	return s, !f.existing, nil
}
func (f *fakeScanRepo) PruneHistory(_ context.Context, repoID uuid.UUID, keep int) (int, error) {
	if f.pruned == nil {
		f.pruned = map[uuid.UUID]int{}
	}
	f.pruned[repoID] = keep
	return 0, nil
}

type fakeDepRepo struct {
	repository.DependencyRepo
	deletedFor []uuid.UUID
	saved      []*entity.Dependency
}

func (f *fakeDepRepo) CreateBatch(_ context.Context, deps []*entity.Dependency) error {
	f.saved = append(f.saved, deps...)
	return nil
}
func (f *fakeDepRepo) DeleteByScanResultID(_ context.Context, id uuid.UUID) error {
	f.deletedFor = append(f.deletedFor, id)
	return nil
}

type fakeHostRepo struct {
	repository.GitHostRepo
	host *entity.GitHost
}

func (f fakeHostRepo) GetByID(context.Context, uuid.UUID) (*entity.GitHost, error) {
	return f.host, nil
}

// fakeProvider "clones" by writing a single package.json unless clone is set.
type fakeProvider struct {
	clone func(ctx context.Context, opts git.CloneOptions) error
}

func (f fakeProvider) Clone(ctx context.Context, opts git.CloneOptions) error {
	if f.clone != nil {
		return f.clone(ctx, opts)
	}
	if err := os.MkdirAll(opts.DestPath, 0o755); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(opts.DestPath, "package.json"), []byte("{}"), 0o644)
}

type fakeAnalyzer struct{}

func (fakeAnalyzer) Ecosystem() entity.Ecosystem       { return entity.EcosystemNpm }
func (fakeAnalyzer) DetectManifests() []string         { return []string{"package.json"} }
func (fakeAnalyzer) Kind(string) analyzer.ManifestKind { return analyzer.KindManifest }
func (fakeAnalyzer) ParseDependencies([]byte, string) ([]analyzer.ParsedDependency, error) {
	return []analyzer.ParsedDependency{{Name: "left-pad", CurrentVersion: "1.0.0", IsDirect: true}}, nil
}
func (fakeAnalyzer) GetLatestVersion(context.Context, string) (string, error) { return "1.0.0", nil }

// fakeLookup reports total advisories, all on the first dependency, and
// vulnerable as the vulnerable dependency count.
type fakeLookup struct {
	vulnerable, total int
	err               error
	onCall            func() // runs before Lookup answers, e.g. to cancel the scan
}

func (f fakeLookup) Lookup(_ context.Context, deps []*entity.Dependency) ([]*entity.Vulnerability, int, error) {
	if f.onCall != nil {
		f.onCall()
	}
	if f.err != nil {
		return nil, 0, f.err
	}
	var vulns []*entity.Vulnerability
	for i := range f.total {
		vulns = append(vulns, entity.NewVulnerability(deps[0].ID, fmt.Sprintf("GHSA-%d", i), "test advisory", entity.SeverityHigh))
	}
	return vulns, f.vulnerable, nil
}

type fakeVulnRepo struct {
	repository.VulnerabilityRepo
	calls int
	saved []*entity.Vulnerability
	err   error // returned by CreateBatch
}

func (f *fakeVulnRepo) CreateBatch(_ context.Context, vulns []*entity.Vulnerability) error {
	f.calls++
	if f.err != nil {
		return f.err
	}
	f.saved = append(f.saved, vulns...)
	return nil
}

func discardLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// testEngine builds the engine the server uses (latest versions checked)
// over registry.
func testEngine(registry *analyzer.Registry, lookup engine.VulnLookup, logger *slog.Logger) *engine.Engine {
	return engine.New(registry, lookup, engine.Options{CheckLatest: true, Logger: logger})
}

func newTestUseCase(t *testing.T, repos *fakeRepoRepo, scans *fakeScanRepo, deps *fakeDepRepo, provider fakeProvider, lookup engine.VulnLookup) (*UseCase, Options) {
	uc, opts, _ := newTestUseCaseWithVulns(t, repos, scans, deps, provider, lookup)
	return uc, opts
}

func newTestUseCaseWithVulns(t *testing.T, repos *fakeRepoRepo, scans *fakeScanRepo, deps *fakeDepRepo, provider fakeProvider, lookup engine.VulnLookup) (*UseCase, Options, *fakeVulnRepo) {
	registry := analyzer.NewRegistry()
	registry.Register(fakeAnalyzer{})
	opts := Options{WorkDir: t.TempDir(), CloneTimeout: time.Minute, RetainScans: 10}
	vulns := &fakeVulnRepo{}
	uc := NewUseCase(
		repos, scans, deps, vulns, testEngine(registry, lookup, discardLogger()),
		func(entity.GitProvider) (git.Cloner, error) { return provider, nil },
		nil, opts, discardLogger(),
	)
	return uc, opts, vulns
}

func claimedScan() *entity.ScanResult {
	s := entity.NewScanResult(uuid.New())
	s.Start()
	return s
}

func TestScanMarksFailedWhenVulnerabilityCheckFails(t *testing.T) {
	repos, scans, deps := &fakeRepoRepo{}, &fakeScanRepo{}, &fakeDepRepo{}
	uc, _, vulns := newTestUseCaseWithVulns(t, repos, scans, deps, fakeProvider{}, fakeLookup{err: errors.New("osv.dev error (status 503)")})

	scan := entity.NewScanResult(uuid.New())
	scan.Start()
	err := uc.Run(context.Background(), scan)
	if err != nil {
		t.Fatal(err)
	}
	if scans.last.Status != entity.ScanStatusFailed {
		t.Fatalf("status = %s, want failed", scans.last.Status)
	}
	if want := "vulnerability check failed, results are incomplete: osv.dev error (status 503)"; deref(scans.last.Error) != want {
		t.Fatalf("error = %q, want %q", deref(scans.last.Error), want)
	}
	if scans.last.TotalDeps != 1 {
		t.Fatalf("TotalDeps = %d, want 1 (dependency results are still recorded)", scans.last.TotalDeps)
	}
	if len(deps.saved) != 1 || vulns.calls != 0 {
		t.Fatalf("saved %d dependencies and %d vulnerability batches, want 1 and 0", len(deps.saved), vulns.calls)
	}
}

// The cause is taken from the typed error, not by trimming its text: a
// cause that itself starts with the sentinel's words stays intact.
func TestScanKeepsTheVulnerabilityCheckCauseIntact(t *testing.T) {
	repos, scans, deps := &fakeRepoRepo{}, &fakeScanRepo{}, &fakeDepRepo{}
	uc, _, _ := newTestUseCaseWithVulns(t, repos, scans, deps, fakeProvider{}, fakeLookup{err: errors.New("vulnerability check failed: upstream said so")})
	if err := uc.Run(context.Background(), claimedScan()); err != nil {
		t.Fatal(err)
	}
	if want := "vulnerability check failed, results are incomplete: vulnerability check failed: upstream said so"; deref(scans.last.Error) != want {
		t.Fatalf("error = %q, want %q", deref(scans.last.Error), want)
	}
}

func TestRunFailsWhenVulnerabilitiesCannotBeSaved(t *testing.T) {
	repos, scans, deps := &fakeRepoRepo{}, &fakeScanRepo{}, &fakeDepRepo{}
	uc, _, vulns := newTestUseCaseWithVulns(t, repos, scans, deps, fakeProvider{}, fakeLookup{vulnerable: 1, total: 2})
	vulns.err = errors.New("disk full")
	if err := uc.Run(context.Background(), claimedScan()); err != nil {
		t.Fatal(err)
	}
	if scans.last.Status != entity.ScanStatusFailed {
		t.Fatalf("status = %s, want failed", scans.last.Status)
	}
	if want := "vulnerability check failed, results are incomplete: failed to save vulnerabilities: disk full"; deref(scans.last.Error) != want {
		t.Fatalf("error = %q, want %q", deref(scans.last.Error), want)
	}
	if scans.last.TotalDeps != 1 || scans.last.TotalVulns != 0 || scans.last.VulnerableDeps != 0 {
		t.Fatalf("counts = %d deps, %d vulns, %d vulnerable; want 1, 0, 0", scans.last.TotalDeps, scans.last.TotalVulns, scans.last.VulnerableDeps)
	}
	if len(deps.saved) != 1 || vulns.calls != 1 {
		t.Fatalf("saved %d dependencies, %d vulnerability batches; want 1 and 1", len(deps.saved), vulns.calls)
	}
}

// Engine log lines of a server scan carry the repository name.
func TestRunTagsEngineLogsWithRepository(t *testing.T) {
	repos, scans, deps := &fakeRepoRepo{}, &fakeScanRepo{}, &fakeDepRepo{}
	registry := analyzer.NewRegistry()
	registry.Register(fakeAnalyzer{})
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	uc := NewUseCase(repos, scans, deps, &fakeVulnRepo{}, testEngine(registry, fakeLookup{}, discardLogger()),
		func(entity.GitProvider) (git.Cloner, error) { return fakeProvider{}, nil },
		nil, Options{WorkDir: t.TempDir()}, logger)
	if err := uc.Run(context.Background(), claimedScan()); err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(logs.String(), "\n") {
		if strings.Contains(line, "discovered manifests") {
			if !strings.Contains(line, "repo=app") {
				t.Fatalf("engine log lacks the repository: %s", line)
			}
			return
		}
	}
	t.Fatalf("no engine log on the use case's logger:\n%s", logs.String())
}

func TestScanCompletesWithVulnerabilityCounts(t *testing.T) {
	repos, scans, deps := &fakeRepoRepo{}, &fakeScanRepo{}, &fakeDepRepo{}
	uc, _, vulns := newTestUseCaseWithVulns(t, repos, scans, deps, fakeProvider{}, fakeLookup{vulnerable: 1, total: 3})

	scan := entity.NewScanResult(uuid.New())
	scan.Start()
	err := uc.Run(context.Background(), scan)
	if err != nil {
		t.Fatal(err)
	}
	if scans.last.Status != entity.ScanStatusCompleted || scans.last.VulnerableDeps != 1 || scans.last.TotalVulns != 3 {
		t.Fatalf("got %+v", scans.last)
	}
	// The rows are saved under this scan, and the findings point at them.
	if len(deps.saved) != 1 {
		t.Fatalf("saved %d dependencies, want 1", len(deps.saved))
	}
	dep := deps.saved[0]
	if dep.RepositoryID != scan.RepositoryID || dep.ScanResultID != scan.ID {
		t.Fatalf("dependency owners = %s/%s, want %s/%s", dep.RepositoryID, dep.ScanResultID, scan.RepositoryID, scan.ID)
	}
	if vulns.calls != 1 || len(vulns.saved) != 3 {
		t.Fatalf("vulnerability batches = %d with %d rows, want 1 with 3", vulns.calls, len(vulns.saved))
	}
	for _, v := range vulns.saved {
		if v.DependencyID != dep.ID {
			t.Fatalf("vulnerability %s links to %s, want %s", v.OSVID, v.DependencyID, dep.ID)
		}
	}
}

func TestRunSkipsVulnerabilitySaveWithoutFindings(t *testing.T) {
	repos, scans, deps := &fakeRepoRepo{}, &fakeScanRepo{}, &fakeDepRepo{}
	uc, _, vulns := newTestUseCaseWithVulns(t, repos, scans, deps, fakeProvider{}, fakeLookup{})
	if err := uc.Run(context.Background(), claimedScan()); err != nil {
		t.Fatal(err)
	}
	if scans.last.Status != entity.ScanStatusCompleted || vulns.calls != 0 {
		t.Fatalf("status = %s, vulnerability batches = %d; want completed and 0", scans.last.Status, vulns.calls)
	}
}

// A scan cancelled while its clone is analyzed saves nothing: the caller
// requeues it, and the rerun would only delete partial rows.
func TestRunCancelledDuringAnalysisSavesNothing(t *testing.T) {
	repos, scans, deps := &fakeRepoRepo{}, &fakeScanRepo{}, &fakeDepRepo{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	uc, _, vulns := newTestUseCaseWithVulns(t, repos, scans, deps, fakeProvider{}, fakeLookup{total: 1, vulnerable: 1, onCall: cancel})
	if err := uc.Run(ctx, claimedScan()); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if scans.updates != 0 || len(deps.saved) != 0 || vulns.calls != 0 {
		t.Fatalf("scan updates = %d, dependencies = %d, vulnerability batches = %d; want none", scans.updates, len(deps.saved), vulns.calls)
	}
}

func TestRunRecordsCompletionStampsRepositoryAndPrunes(t *testing.T) {
	repos, scans, deps := &fakeRepoRepo{}, &fakeScanRepo{}, &fakeDepRepo{}
	uc, _ := newTestUseCase(t, repos, scans, deps, fakeProvider{}, fakeLookup{})
	s := claimedScan()
	if err := uc.Run(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	if scans.last.Status != entity.ScanStatusCompleted {
		t.Fatalf("status = %s", scans.last.Status)
	}
	if len(repos.marked) != 1 || repos.marked[0] != s.RepositoryID {
		t.Fatalf("MarkScanned calls = %v", repos.marked)
	}
	if scans.pruned[s.RepositoryID] != 10 {
		t.Fatalf("PruneHistory keep = %d, want 10", scans.pruned[s.RepositoryID])
	}
}

func TestRunPrunesAfterFailure(t *testing.T) {
	repos, scans, deps := &fakeRepoRepo{}, &fakeScanRepo{}, &fakeDepRepo{}
	provider := fakeProvider{clone: func(context.Context, git.CloneOptions) error {
		return errors.New("authentication required")
	}}
	uc, _ := newTestUseCase(t, repos, scans, deps, provider, fakeLookup{})
	s := claimedScan()
	if err := uc.Run(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	if scans.last.Status != entity.ScanStatusFailed {
		t.Fatalf("status = %s, want failed", scans.last.Status)
	}
	if scans.pruned[s.RepositoryID] != 10 {
		t.Fatalf("PruneHistory keep = %d, want 10; failed scans count toward retention too", scans.pruned[s.RepositoryID])
	}
}

func TestRunDeletesPartialResultsOfRequeuedScan(t *testing.T) {
	repos, scans, deps := &fakeRepoRepo{}, &fakeScanRepo{}, &fakeDepRepo{}
	uc, _ := newTestUseCase(t, repos, scans, deps, fakeProvider{}, fakeLookup{})
	s := claimedScan()
	if err := uc.Run(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	if len(deps.deletedFor) != 1 || deps.deletedFor[0] != s.ID {
		t.Fatalf("DeleteByScanResultID calls = %v", deps.deletedFor)
	}
}

func TestRunRemovesCloneDirectory(t *testing.T) {
	repos, scans, deps := &fakeRepoRepo{}, &fakeScanRepo{}, &fakeDepRepo{}
	uc, opts := newTestUseCase(t, repos, scans, deps, fakeProvider{}, fakeLookup{})
	if err := uc.Run(context.Background(), claimedScan()); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(opts.WorkDir)
	if err != nil || len(entries) != 0 {
		t.Fatalf("work dir left %d entries (%v)", len(entries), err)
	}
}

func TestRunCancelledMidScanReturnsWithoutRecording(t *testing.T) {
	repos, scans, deps := &fakeRepoRepo{}, &fakeScanRepo{}, &fakeDepRepo{}
	ctx, cancel := context.WithCancel(context.Background())
	provider := fakeProvider{clone: func(ctx context.Context, _ git.CloneOptions) error {
		cancel()
		<-ctx.Done()
		return ctx.Err()
	}}
	uc, _ := newTestUseCase(t, repos, scans, deps, provider, fakeLookup{})
	if err := uc.Run(ctx, claimedScan()); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if scans.updates != 0 {
		t.Fatal("an interrupted scan must be left for the caller to requeue, not recorded")
	}
}

func TestRunAppliesCloneTimeout(t *testing.T) {
	repos, scans, deps := &fakeRepoRepo{}, &fakeScanRepo{}, &fakeDepRepo{}
	provider := fakeProvider{clone: func(ctx context.Context, _ git.CloneOptions) error {
		<-ctx.Done()
		return ctx.Err()
	}}
	uc, _ := newTestUseCase(t, repos, scans, deps, provider, fakeLookup{})
	uc.opts.CloneTimeout = 20 * time.Millisecond
	if err := uc.Run(context.Background(), claimedScan()); err != nil {
		t.Fatal(err)
	}
	if scans.last.Status != entity.ScanStatusFailed || scans.last.Error == nil || !strings.Contains(*scans.last.Error, "clone failed") {
		t.Fatalf("scan = %+v", scans.last)
	}
}

func TestEnqueueUnknownRepository(t *testing.T) {
	repos, scans, deps := &fakeRepoRepo{missing: true}, &fakeScanRepo{}, &fakeDepRepo{}
	uc, _ := newTestUseCase(t, repos, scans, deps, fakeProvider{}, fakeLookup{})
	if _, _, err := uc.Enqueue(context.Background(), uuid.New()); !errors.Is(err, ErrRepositoryNotFound) {
		t.Fatalf("err = %v", err)
	}
}

func TestRunFailsWhenRepositoryWasDeleted(t *testing.T) {
	repos, scans, deps := &fakeRepoRepo{missing: true}, &fakeScanRepo{}, &fakeDepRepo{}
	uc, _ := newTestUseCase(t, repos, scans, deps, fakeProvider{}, fakeLookup{})
	if err := uc.Run(context.Background(), claimedScan()); err != nil {
		t.Fatal(err)
	}
	if scans.last.Status != entity.ScanStatusFailed {
		t.Fatalf("status = %s", scans.last.Status)
	}
}

// lockAnalyzer reads package.json as a manifest and package-lock.json as a
// lockfile; a file whose content is "broken" fails to parse.
type lockAnalyzer struct{ fakeAnalyzer }

func (lockAnalyzer) DetectManifests() []string {
	return []string{"package.json", "package-lock.json"}
}
func (lockAnalyzer) Kind(p string) analyzer.ManifestKind {
	if filepath.Base(p) == "package-lock.json" {
		return analyzer.KindLockfile
	}
	return analyzer.KindManifest
}
func (lockAnalyzer) ParseDependencies(content []byte, p string) ([]analyzer.ParsedDependency, error) {
	switch {
	case string(content) == "broken":
		return nil, errors.New("unexpected end of JSON input")
	case p == "package.json":
		return []analyzer.ParsedDependency{{Name: "express", CurrentVersion: "^4.18.0", IsDirect: true}}, nil
	case p == "package-lock.json":
		return []analyzer.ParsedDependency{
			{Name: "express", CurrentVersion: "4.18.2", Resolved: true},
			{Name: "accepts", CurrentVersion: "1.3.8", Resolved: true},
		}, nil
	case p == "tools/package.json":
		return []analyzer.ParsedDependency{{Name: "chalk", CurrentVersion: "^5.0.0", IsDirect: true}}, nil
	}
	return nil, errors.New("unexpected file " + p)
}

func TestRunResolvesManifestsAgainstLockfiles(t *testing.T) {
	repos, scans, deps := &fakeRepoRepo{}, &fakeScanRepo{}, &fakeDepRepo{}
	registry := analyzer.NewRegistry()
	registry.Register(lockAnalyzer{})
	provider := fakeProvider{clone: func(_ context.Context, opts git.CloneOptions) error {
		files := map[string]string{
			"package.json":            "{}",
			"package-lock.json":       "{}",
			"tools/package.json":      "{}",
			"tools/package-lock.json": "broken",
		}
		for name, content := range files {
			p := filepath.Join(opts.DestPath, filepath.FromSlash(name))
			if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
				return err
			}
			if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
				return err
			}
		}
		return nil
	}}
	uc := NewUseCase(
		repos, scans, deps, nil, testEngine(registry, fakeLookup{}, discardLogger()),
		func(entity.GitProvider) (git.Cloner, error) { return provider, nil },
		nil, Options{WorkDir: t.TempDir(), CloneTimeout: time.Minute},
		discardLogger(),
	)
	if err := uc.Run(context.Background(), claimedScan()); err != nil {
		t.Fatal(err)
	}

	var got []string
	for _, d := range deps.saved {
		got = append(got, fmt.Sprintf("%s %s %s@%s direct=%v", d.Ecosystem, d.ManifestFile, d.Name, d.CurrentVersion, d.IsDirect))
	}
	want := []string{
		"npm package-lock.json accepts@1.3.8 direct=false",
		"npm package-lock.json express@4.18.2 direct=true",
		// The broken lockfile leaves tools/ to its manifest.
		"npm tools/package.json chalk@^5.0.0 direct=true",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("saved dependencies:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	if scans.last.TotalDeps != 3 {
		t.Fatalf("TotalDeps = %d, want 3", scans.last.TotalDeps)
	}
}

type panickingAnalyzer struct{ fakeAnalyzer }

func (panickingAnalyzer) GetLatestVersion(context.Context, string) (string, error) {
	panic("bad registry response")
}

func TestRunSurvivesPanicInVersionLookup(t *testing.T) {
	repos, scans, deps := &fakeRepoRepo{}, &fakeScanRepo{}, &fakeDepRepo{}
	registry := analyzer.NewRegistry()
	registry.Register(panickingAnalyzer{})
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	uc := NewUseCase(
		repos, scans, deps, nil, testEngine(registry, fakeLookup{}, logger),
		func(entity.GitProvider) (git.Cloner, error) { return fakeProvider{}, nil },
		nil, Options{WorkDir: t.TempDir(), CloneTimeout: time.Minute, RetainScans: 10},
		logger,
	)
	if err := uc.Run(context.Background(), claimedScan()); err != nil {
		t.Fatal(err)
	}
	if scans.last.Status != entity.ScanStatusCompleted {
		t.Fatalf("status = %s, want completed", scans.last.Status)
	}
	if !strings.Contains(logs.String(), "bad registry response") {
		t.Fatalf("panic was not logged: %s", logs.String())
	}
}

func TestRequestScanPostponesNextScheduledRunOnlyWhenQueued(t *testing.T) {
	for _, existing := range []bool{false, true} {
		repos, scans := &fakeRepoRepo{}, &fakeScanRepo{existing: existing}
		uc, _ := newTestUseCase(t, repos, scans, &fakeDepRepo{}, fakeProvider{}, nil)
		id := uuid.New()
		before := time.Now().UTC()
		_, queued, err := uc.RequestScan(context.Background(), id)
		if err != nil {
			t.Fatal(err)
		}
		next, set := repos.nextAt[id]
		if existing {
			if queued || set {
				t.Fatalf("existing scan: queued=%v, next_scan_at set=%v; want neither", queued, set)
			}
			continue
		}
		if !queued || !set || !next.After(before) || next.Minute() != 0 || next.Hour()%6 != 0 {
			t.Fatalf("queued=%v next=%v (set=%v), want the next 6-hourly run after now", queued, next, set)
		}
	}
}

func TestSchedulerEnqueueDoesNotPostponeNextScan(t *testing.T) {
	repos, scans := &fakeRepoRepo{}, &fakeScanRepo{}
	uc, _ := newTestUseCase(t, repos, scans, &fakeDepRepo{}, fakeProvider{}, nil)
	a := uuid.New()
	due := &fakeDue{due: []uuid.UUID{a}, schedules: map[uuid.UUID]string{a: "0 */6 * * *"}}
	s := NewScheduler(due, &fakeStale{}, uc,
		SchedulerConfig{Interval: time.Minute, BatchSize: 100, StaleAfter: time.Minute, MaxAttempts: 3},
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err := s.Tick(context.Background(), time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if len(scans.enqueued) != 1 || len(repos.nextAt) != 0 {
		t.Fatalf("enqueued=%v next_scan_at writes=%v; the claim already advanced it, so there must be none", scans.enqueued, repos.nextAt)
	}
}

// countingAnalyzer reports three rows of one package and counts registry
// lookups.
type countingAnalyzer struct {
	fakeAnalyzer
	lookups *atomic.Int32
}

func (countingAnalyzer) ParseDependencies([]byte, string) ([]analyzer.ParsedDependency, error) {
	return []analyzer.ParsedDependency{
		{Name: "left-pad", CurrentVersion: "1.3.0", IsDirect: true},
		{Name: "left-pad", CurrentVersion: "1.1.0"},
		{Name: "left-pad", CurrentVersion: "0.9.0"},
	}, nil
}

func (a countingAnalyzer) GetLatestVersion(context.Context, string) (string, error) {
	a.lookups.Add(1)
	return "1.3.0", nil
}

// The registry is asked once per package, however many versions of it the
// lockfiles hold; every row gets the answer.
func TestRunLooksUpEachPackageOnce(t *testing.T) {
	repos, scans, deps := &fakeRepoRepo{}, &fakeScanRepo{}, &fakeDepRepo{}
	lookups := &atomic.Int32{}
	registry := analyzer.NewRegistry()
	registry.Register(countingAnalyzer{lookups: lookups})
	uc := NewUseCase(
		repos, scans, deps, nil, testEngine(registry, fakeLookup{}, discardLogger()),
		func(entity.GitProvider) (git.Cloner, error) { return fakeProvider{}, nil },
		nil, Options{WorkDir: t.TempDir(), CloneTimeout: time.Minute},
		discardLogger(),
	)
	if err := uc.Run(context.Background(), claimedScan()); err != nil {
		t.Fatal(err)
	}
	if n := lookups.Load(); n != 1 {
		t.Fatalf("registry lookups = %d, want 1", n)
	}
	if len(deps.saved) != 3 {
		t.Fatalf("saved %d dependencies, want 3", len(deps.saved))
	}
	for _, d := range deps.saved {
		if d.LatestVersion != "1.3.0" || d.IsOutdated != (d.CurrentVersion != "1.3.0") {
			t.Errorf("%s@%s: latest=%q outdated=%v", d.Name, d.CurrentVersion, d.LatestVersion, d.IsOutdated)
		}
	}
	if scans.last.OutdatedDeps != 2 {
		t.Fatalf("OutdatedDeps = %d, want 2", scans.last.OutdatedDeps)
	}
}

func azureFixture(t *testing.T, token string, host *entity.GitHost) (*UseCase, *fakeScanRepo, *git.CloneOptions) {
	t.Helper()
	hostID := uuid.New()
	r := entity.NewRepository("svc", "https://tfs.local:8443/Col/P/_git/svc", entity.GitProviderAzureDevOps, token)
	r.GitHostID = &hostID
	repos, scans := &fakeRepoRepo{repo: r}, &fakeScanRepo{}
	var got git.CloneOptions
	registry := analyzer.NewRegistry()
	registry.Register(fakeAnalyzer{})
	cloner := fakeProvider{clone: func(_ context.Context, o git.CloneOptions) error { got = o; return nil }}
	uc := NewUseCase(repos, scans, &fakeDepRepo{}, nil, testEngine(registry, fakeLookup{}, discardLogger()),
		func(entity.GitProvider) (git.Cloner, error) { return cloner, nil },
		fakeHostRepo{host: host},
		Options{WorkDir: t.TempDir(), CloneTimeout: time.Minute}, discardLogger())
	return uc, scans, &got
}

func TestRunBuildsCredentialFromGitHost(t *testing.T) {
	host, err := entity.NewGitHost(entity.GitProviderAzureDevOps, "tfs", "https://TFS.local:8443/Col")
	if err != nil {
		t.Fatal(err)
	}
	uc, _, got := azureFixture(t, "pat", host)
	if err := uc.Run(context.Background(), claimedScan()); err != nil {
		t.Fatal(err)
	}
	want := git.Credential{HostPort: "tfs.local:8443", Username: "orbit", Token: "pat"}
	if got.Credential == nil || *got.Credential != want {
		t.Fatalf("credential = %+v, want %+v", got.Credential, want)
	}
	if got.AuthToken != "" {
		t.Fatal("AuthToken must not be set alongside a credential")
	}
}

func TestRunClonesAnonymouslyWithoutToken(t *testing.T) {
	host, _ := entity.NewGitHost(entity.GitProviderAzureDevOps, "tfs", "https://tfs.local:8443/Col")
	uc, _, got := azureFixture(t, "", host)
	if err := uc.Run(context.Background(), claimedScan()); err != nil {
		t.Fatal(err)
	}
	if got.Credential != nil || got.AuthToken != "" {
		t.Fatalf("want anonymous clone, got %+v", got)
	}
}

func TestRunFailsWhenGitConnectionIsGone(t *testing.T) {
	uc, scans, _ := azureFixture(t, "pat", nil)
	if err := uc.Run(context.Background(), claimedScan()); err != nil {
		t.Fatal(err)
	}
	if scans.last.Status != entity.ScanStatusFailed || !strings.Contains(deref(scans.last.Error), "git connection no longer exists") {
		t.Fatalf("scan = %s %q", scans.last.Status, deref(scans.last.Error))
	}
}

func TestRunFailsForUnknownProvider(t *testing.T) {
	r := entity.NewRepository("x", "https://bitbucket.org/a/b", entity.GitProvider("bitbucket"), "tok")
	repos, scans := &fakeRepoRepo{repo: r}, &fakeScanRepo{}
	called := false
	uc := NewUseCase(repos, scans, &fakeDepRepo{}, nil, testEngine(analyzer.NewRegistry(), fakeLookup{}, discardLogger()),
		func(p entity.GitProvider) (git.Cloner, error) {
			called = true
			return nil, errors.New("unsupported git provider " + string(p))
		}, nil,
		Options{WorkDir: t.TempDir()}, discardLogger())
	if err := uc.Run(context.Background(), claimedScan()); err != nil {
		t.Fatal(err)
	}
	if !called || scans.last.Status != entity.ScanStatusFailed || !strings.Contains(deref(scans.last.Error), "unsupported git provider") {
		t.Fatalf("called=%v scan = %s %q", called, scans.last.Status, deref(scans.last.Error))
	}
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// fakeExploit marks every vulnerability as known exploited when its KEV
// source answered.
type fakeExploit struct{ result exploit.Result }

func (f fakeExploit) Enrich(_ context.Context, vulns []*entity.Vulnerability) exploit.Result {
	if f.result.KEV.Status == exploit.StatusOK {
		for _, v := range vulns {
			v.KEV = true
		}
	}
	return f.result
}

func newExploitUseCase(t *testing.T, scans *fakeScanRepo, vulns *fakeVulnRepo, enricher engine.ExploitEnricher, logger *slog.Logger) *UseCase {
	t.Helper()
	registry := analyzer.NewRegistry()
	registry.Register(fakeAnalyzer{})
	eng := engine.New(registry, fakeLookup{vulnerable: 1, total: 2}, engine.Options{CheckLatest: true, Logger: discardLogger(), Exploit: enricher})
	return NewUseCase(&fakeRepoRepo{}, scans, &fakeDepRepo{}, vulns, eng,
		func(entity.GitProvider) (git.Cloner, error) { return fakeProvider{}, nil },
		nil, Options{WorkDir: t.TempDir()}, logger)
}

func TestRunSavesExploitSignals(t *testing.T) {
	scans, vulns := &fakeScanRepo{}, &fakeVulnRepo{}
	ok := exploit.SourceResult{Status: exploit.StatusOK}
	uc := newExploitUseCase(t, scans, vulns, fakeExploit{result: exploit.Result{KEV: ok, EPSS: ok}}, discardLogger())
	if err := uc.Run(context.Background(), claimedScan()); err != nil {
		t.Fatal(err)
	}
	if len(vulns.saved) != 2 || !vulns.saved[0].KEV || !vulns.saved[1].KEV {
		t.Fatalf("saved = %+v; want both rows with KEV", vulns.saved)
	}
}

func TestRunCompletesAndWarnsWhenExploitDataFails(t *testing.T) {
	scans, vulns := &fakeScanRepo{}, &fakeVulnRepo{}
	var logs bytes.Buffer
	failed := exploit.SourceResult{Status: exploit.StatusFailed, Err: errors.New("fetch KEV catalog: HTTP 503")}
	uc := newExploitUseCase(t, scans, vulns, fakeExploit{result: exploit.Result{KEV: failed, EPSS: exploit.SourceResult{Status: exploit.StatusOK}}},
		slog.New(slog.NewTextHandler(&logs, nil)))
	if err := uc.Run(context.Background(), claimedScan()); err != nil {
		t.Fatal(err)
	}
	if scans.last.Status != entity.ScanStatusCompleted || len(vulns.saved) != 2 || vulns.saved[0].KEV {
		t.Fatalf("scan %s with %d rows (KEV %v); want completed, 2 rows, no KEV", scans.last.Status, len(vulns.saved), vulns.saved[0].KEV)
	}
	out := logs.String()
	if !strings.Contains(out, "level=WARN") || !strings.Contains(out, "exploit data unavailable") || !strings.Contains(out, "HTTP 503") || !strings.Contains(out, "repo=app") {
		t.Fatalf("logs lack the warning:\n%s", out)
	}
}
