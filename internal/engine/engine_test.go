package engine_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/orchesta/orbit/internal/domain/entity"
	"github.com/orchesta/orbit/internal/engine"
	"github.com/orchesta/orbit/internal/infrastructure/analyzer"
	"github.com/orchesta/orbit/internal/infrastructure/analyzer/golang"
	"github.com/orchesta/orbit/internal/infrastructure/analyzer/npm"
	"github.com/orchesta/orbit/internal/infrastructure/analyzer/nuget"
	"github.com/orchesta/orbit/internal/infrastructure/analyzer/pip"
	"github.com/orchesta/orbit/internal/infrastructure/exploit"
	"github.com/orchesta/orbit/internal/usecase/vulnerability"
)

// The advisory lookup the server and CLI use fits the engine.
var _ engine.VulnLookup = (*vulnerability.UseCase)(nil)

// The exploit data enricher the server and CLI use fits the engine.
var _ engine.ExploitEnricher = (*exploit.Enricher)(nil)

// stubRegistry wraps a real analyzer: parsing is the analyzer's own, while
// GetLatestVersion is answered from latest (a missing name is an error) and
// counted, so no test reaches a real registry.
type stubRegistry struct {
	analyzer.Analyzer
	latest  map[string]string
	panicOn string

	mu          sync.Mutex
	calls       []string
	inFlight    int
	maxInFlight int
}

// MatchesFile keeps the wrapped analyzer's FileMatcher (pip's requirements
// files), which embedding the interface would hide.
func (s *stubRegistry) MatchesFile(p string) bool {
	fm, ok := s.Analyzer.(analyzer.FileMatcher)
	return ok && fm.MatchesFile(p)
}

func (s *stubRegistry) GetLatestVersion(_ context.Context, name string) (string, error) {
	s.mu.Lock()
	s.calls = append(s.calls, name)
	s.inFlight++
	s.maxInFlight = max(s.maxInFlight, s.inFlight)
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.inFlight--
		s.mu.Unlock()
	}()
	if name == s.panicOn {
		panic("bad registry response")
	}
	v, ok := s.latest[name]
	if !ok {
		return "", errors.New("not found")
	}
	return v, nil
}

func (s *stubRegistry) lookups() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := slices.Clone(s.calls)
	slices.Sort(out)
	return out
}

// newRegistry registers the real analyzers, each behind a stubRegistry
// sharing latest.
func newRegistry(latest map[string]string) (*analyzer.Registry, map[entity.Ecosystem]*stubRegistry) {
	reg := analyzer.NewRegistry()
	stubs := make(map[entity.Ecosystem]*stubRegistry)
	for _, a := range []analyzer.Analyzer{npm.NewAnalyzer(), pip.NewAnalyzer(), nuget.NewAnalyzer(), golang.NewAnalyzer()} {
		s := &stubRegistry{Analyzer: a, latest: latest}
		stubs[a.Ecosystem()] = s
		reg.Register(s)
	}
	return reg, stubs
}

// fakeLookup reports one advisory per dependency named in vulnerable.
type fakeLookup struct {
	vulnerable map[string]string // package name -> advisory ID
	err        error
	onCall     func() // runs before Lookup answers, e.g. to cancel the scan
	calls      atomic.Int32
	got        []*entity.Dependency
}

func (f *fakeLookup) Lookup(_ context.Context, deps []*entity.Dependency) ([]*entity.Vulnerability, int, error) {
	f.calls.Add(1)
	f.got = deps
	if f.onCall != nil {
		f.onCall()
	}
	if f.err != nil {
		return nil, 0, f.err
	}
	var vulns []*entity.Vulnerability
	n := 0
	for _, d := range deps {
		if id, ok := f.vulnerable[d.Name]; ok {
			vulns = append(vulns, entity.NewVulnerability(d.ID, id, "test advisory", entity.SeverityHigh))
			n++
		}
	}
	return vulns, n, nil
}

// writeTree creates files (slash paths -> content) under a new temp dir.
func writeTree(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for name, content := range files {
		p := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func describe(deps []*entity.Dependency) string {
	var lines []string
	for _, d := range deps {
		lines = append(lines, fmt.Sprintf("%s %s %s@%s direct=%v resolved=%v dev=%v",
			d.Ecosystem, d.ManifestFile, d.Name, d.CurrentVersion, d.IsDirect, d.IsResolved, d.IsDev))
	}
	return strings.Join(lines, "\n")
}

func analyze(t *testing.T, e *engine.Engine, root string) *engine.Result {
	t.Helper()
	res, err := e.Analyze(context.Background(), root)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	return res
}

func TestAnalyzeResolvesNpmProjectAgainstLockfile(t *testing.T) {
	reg, _ := newRegistry(nil)
	res := analyze(t, engine.New(reg, nil, engine.Options{}), "testdata/npm-lock")

	want := strings.Join([]string{
		"npm package-lock.json accepts@1.3.8 direct=false resolved=true dev=false",
		"npm package-lock.json express@4.18.2 direct=true resolved=true dev=false",
		"npm package-lock.json jest@29.7.0 direct=true resolved=true dev=true",
	}, "\n")
	if got := describe(res.Dependencies); got != want {
		t.Fatalf("dependencies:\n%s\nwant:\n%s", got, want)
	}
	for _, d := range res.Dependencies {
		if d.ID == uuid.Nil || d.RepositoryID != uuid.Nil || d.ScanResultID != uuid.Nil {
			t.Errorf("%s: ID=%s RepositoryID=%s ScanResultID=%s; want a fresh ID and nil owners", d.Name, d.ID, d.RepositoryID, d.ScanResultID)
		}
	}
	if want := []string{"package-lock.json", "package.json"}; !slices.Equal(res.Manifests, want) {
		t.Fatalf("Manifests = %q, want %q", res.Manifests, want)
	}
	if len(res.Warnings) != 0 {
		t.Fatalf("Warnings = %q, want none: every version comes from the lockfile", res.Warnings)
	}
}

func TestAnalyzeMixedPipAndGoProject(t *testing.T) {
	reg, _ := newRegistry(nil)
	res := analyze(t, engine.New(reg, nil, engine.Options{}), "testdata/mixed")

	want := strings.Join([]string{
		"Go go.mod github.com/google/uuid@1.6.0 direct=true resolved=false dev=false",
		"PyPI requirements.txt flask@2.0 direct=true resolved=false dev=false",
		"PyPI requirements.txt requests@2.31.0 direct=true resolved=true dev=false",
	}, "\n")
	if got := describe(res.Dependencies); got != want {
		t.Fatalf("dependencies:\n%s\nwant:\n%s", got, want)
	}
	if want := []string{"go.mod", "requirements.txt"}; !slices.Equal(res.Manifests, want) {
		t.Fatalf("Manifests = %q, want %q", res.Manifests, want)
	}
	// Go has no lockfile (go.mod lists the resolved versions), so only flask counts.
	if want := []string{"1 dependency has no lockfile; its version is approximate"}; !slices.Equal(res.Warnings, want) {
		t.Fatalf("Warnings = %q, want %q", res.Warnings, want)
	}
}

func TestAnalyzeSkipsNodeModules(t *testing.T) {
	root := writeTree(t, map[string]string{
		"package.json":                               `{"dependencies":{"left-pad":"1.3.0"}}`,
		"node_modules/left-pad/package.json":         `{"dependencies":{"evil":"1.0.0"}}`,
		"node_modules/left-pad/package-lock.json":    `{"lockfileVersion":3,"packages":{"node_modules/evil":{"version":"1.0.0"}}}`,
		"web/node_modules/nested/requirements.txt":   "django==1.0\n",
		"web/package.json":                           `{"dependencies":{"react":"18.2.0"}}`,
		"web/node_modules/react/package.json":        `{"dependencies":{"loose-envify":"1.4.0"}}`,
		"web/node_modules/.pnpm/x/node_modules/y.go": "package y\n",
	})
	reg, _ := newRegistry(nil)
	res := analyze(t, engine.New(reg, nil, engine.Options{}), root)

	want := strings.Join([]string{
		"npm package.json left-pad@1.3.0 direct=true resolved=false dev=false",
		"npm web/package.json react@18.2.0 direct=true resolved=false dev=false",
	}, "\n")
	if got := describe(res.Dependencies); got != want {
		t.Fatalf("dependencies:\n%s\nwant:\n%s", got, want)
	}
	if want := []string{"package.json", "web/package.json"}; !slices.Equal(res.Manifests, want) {
		t.Fatalf("Manifests = %q, want %q", res.Manifests, want)
	}
}

func TestAnalyzeReturnsDependenciesWhenVulnerabilityLookupFails(t *testing.T) {
	reg, _ := newRegistry(nil)
	lookup := &fakeLookup{err: errors.New("osv.dev unreachable")}
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	res, err := engine.New(reg, lookup, engine.Options{Logger: logger}).Analyze(context.Background(), "testdata/npm-lock")

	// The caller reports the error; the engine must not log it a second time.
	if strings.Contains(logs.String(), "osv.dev unreachable") || strings.Contains(logs.String(), "level=ERROR") {
		t.Errorf("engine logged the lookup error itself:\n%s", logs.String())
	}

	if !errors.Is(err, engine.ErrVulnerabilityCheck) || !strings.Contains(err.Error(), "osv.dev unreachable") {
		t.Fatalf("err = %v, want ErrVulnerabilityCheck carrying the cause", err)
	}
	if res == nil || len(res.Dependencies) != 3 {
		t.Fatalf("result = %+v, want the 3 dependencies kept", res)
	}
	if res.Vulnerabilities != nil || res.VulnerableDeps != 0 {
		t.Fatalf("vulnerabilities = %v (%d vulnerable), want none", res.Vulnerabilities, res.VulnerableDeps)
	}
}

func TestAnalyzeAttachesVulnerabilities(t *testing.T) {
	reg, _ := newRegistry(nil)
	lookup := &fakeLookup{vulnerable: map[string]string{"express": "GHSA-1", "accepts": "GHSA-2"}}
	res := analyze(t, engine.New(reg, lookup, engine.Options{}), "testdata/npm-lock")

	if lookup.calls.Load() != 1 || len(lookup.got) != len(res.Dependencies) {
		t.Fatalf("lookup calls = %d with %d deps, want 1 call with all %d", lookup.calls.Load(), len(lookup.got), len(res.Dependencies))
	}
	if res.VulnerableDeps != 2 || len(res.Vulnerabilities) != 2 {
		t.Fatalf("VulnerableDeps = %d, Vulnerabilities = %d; want 2 and 2", res.VulnerableDeps, len(res.Vulnerabilities))
	}
	ids := make(map[uuid.UUID]string)
	for _, d := range res.Dependencies {
		ids[d.ID] = d.Name
	}
	for _, v := range res.Vulnerabilities {
		if _, ok := ids[v.DependencyID]; !ok {
			t.Errorf("%s points at %s, which is not in Dependencies", v.OSVID, v.DependencyID)
		}
	}
}

func TestAnalyzeWithoutCheckLatestNeverAsksRegistries(t *testing.T) {
	reg, stubs := newRegistry(map[string]string{"express": "5.0.0"})
	for _, dir := range []string{"testdata/npm-lock", "testdata/mixed"} {
		res := analyze(t, engine.New(reg, nil, engine.Options{CheckLatest: false}), dir)
		if res.OutdatedDeps != 0 {
			t.Errorf("%s: OutdatedDeps = %d, want 0", dir, res.OutdatedDeps)
		}
		for _, d := range res.Dependencies {
			if d.LatestVersion != "" || d.IsOutdated || d.UpdateType != entity.UpdateTypeNone {
				t.Errorf("%s: %s latest=%q outdated=%v update=%s; want untouched", dir, d.Name, d.LatestVersion, d.IsOutdated, d.UpdateType)
			}
		}
	}
	for eco, s := range stubs {
		if calls := s.lookups(); len(calls) != 0 {
			t.Errorf("%s: GetLatestVersion called for %q, want 0 calls", eco, calls)
		}
	}
}

func TestAnalyzeChecksLatestVersionOncePerPackage(t *testing.T) {
	// Two lockfiles hold accepts at two versions: one lookup, two rows.
	root := writeTree(t, map[string]string{
		"a/package.json":      `{"dependencies":{"accepts":"^1.0.0"}}`,
		"a/package-lock.json": `{"lockfileVersion":3,"packages":{"node_modules/accepts":{"version":"1.3.8"}}}`,
		"b/package.json":      `{"dependencies":{"accepts":"^1.0.0","jest":"^29.0.0"}}`,
		"b/package-lock.json": `{"lockfileVersion":3,"packages":{"node_modules/accepts":{"version":"1.3.7"},"node_modules/jest":{"version":"29.7.0"}}}`,
	})
	reg, stubs := newRegistry(map[string]string{"accepts": "1.3.8"}) // jest: lookup error
	res := analyze(t, engine.New(reg, nil, engine.Options{CheckLatest: true}), root)

	if got, want := stubs[entity.EcosystemNpm].lookups(), []string{"accepts", "jest"}; !slices.Equal(got, want) {
		t.Fatalf("lookups = %q, want %q", got, want)
	}
	var got []string
	for _, d := range res.Dependencies {
		got = append(got, fmt.Sprintf("%s %s@%s latest=%q outdated=%v update=%s", d.ManifestFile, d.Name, d.CurrentVersion, d.LatestVersion, d.IsOutdated, d.UpdateType))
	}
	want := []string{
		`a/package-lock.json accepts@1.3.8 latest="1.3.8" outdated=false update=none`,
		`b/package-lock.json accepts@1.3.7 latest="1.3.8" outdated=true update=patch`,
		`b/package-lock.json jest@29.7.0 latest="" outdated=false update=none`,
	}
	if !slices.Equal(got, want) {
		t.Fatalf("dependencies:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	if res.OutdatedDeps != 1 {
		t.Fatalf("OutdatedDeps = %d, want 1", res.OutdatedDeps)
	}
}

func TestAnalyzeLimitsRegistryConcurrency(t *testing.T) {
	deps := make([]string, 0, 12)
	for i := range 12 {
		deps = append(deps, fmt.Sprintf(`"pkg%d":"1.0.0"`, i))
	}
	root := writeTree(t, map[string]string{"package.json": `{"dependencies":{` + strings.Join(deps, ",") + `}}`})
	reg, stubs := newRegistry(nil)
	analyze(t, engine.New(reg, nil, engine.Options{CheckLatest: true, Concurrency: 1}), root)

	s := stubs[entity.EcosystemNpm]
	if n := len(s.lookups()); n != 12 {
		t.Fatalf("lookups = %d, want 12", n)
	}
	if s.maxInFlight != 1 {
		t.Fatalf("max lookups in flight = %d, want 1", s.maxInFlight)
	}
}

func TestAnalyzeSurvivesPanicInRegistryLookup(t *testing.T) {
	reg, stubs := newRegistry(map[string]string{"accepts": "1.3.8", "jest": "29.7.0"})
	stubs[entity.EcosystemNpm].panicOn = "express"
	res := analyze(t, engine.New(reg, nil, engine.Options{CheckLatest: true}), "testdata/npm-lock")

	for _, d := range res.Dependencies {
		wantLatest := map[string]string{"accepts": "1.3.8", "jest": "29.7.0"}[d.Name]
		if d.LatestVersion != wantLatest {
			t.Errorf("%s latest = %q, want %q", d.Name, d.LatestVersion, wantLatest)
		}
	}
}

func TestAnalyzeWarnsAboutBrokenFiles(t *testing.T) {
	root := writeTree(t, map[string]string{
		// A broken manifest is skipped.
		"web/package.json": `{"dependencies": {`,
		// A broken lockfile leaves its directory to the manifest.
		"api/package.json":      `{"dependencies":{"express":"^4.18.0"}}`,
		"api/package-lock.json": `not json`,
		"svc/go.mod":            "module example.com/svc\n\ngo 1.22\n\nrequire github.com/google/uuid v1.6.0\n",
	})
	reg, _ := newRegistry(nil)
	res := analyze(t, engine.New(reg, nil, engine.Options{}), root)

	want := strings.Join([]string{
		"Go svc/go.mod github.com/google/uuid@1.6.0 direct=true resolved=false dev=false",
		"npm api/package.json express@4.18.0 direct=true resolved=false dev=false",
	}, "\n")
	if got := describe(res.Dependencies); got != want {
		t.Fatalf("dependencies:\n%s\nwant:\n%s", got, want)
	}
	if want := []string{"api/package.json", "svc/go.mod"}; !slices.Equal(res.Manifests, want) {
		t.Fatalf("Manifests = %q, want %q (broken files are not parsed)", res.Manifests, want)
	}
	joined := strings.Join(res.Warnings, "\n")
	for _, s := range []string{"api/package-lock.json", "web/package.json", "1 dependency has no lockfile; its version is approximate"} {
		if !strings.Contains(joined, s) {
			t.Errorf("Warnings %q do not mention %q", res.Warnings, s)
		}
	}
	if len(res.Warnings) != 3 {
		t.Fatalf("Warnings = %q, want 3", res.Warnings)
	}
}

func TestAnalyzeTreeWithoutManifests(t *testing.T) {
	root := writeTree(t, map[string]string{"README.md": "# hi\n"})
	reg, _ := newRegistry(nil)
	lookup := &fakeLookup{}
	res := analyze(t, engine.New(reg, lookup, engine.Options{CheckLatest: true}), root)
	if len(res.Dependencies) != 0 || len(res.Manifests) != 0 {
		t.Fatalf("result = %+v, want empty", res)
	}
	if want := []string{"no manifest or lockfile found under " + root}; !slices.Equal(res.Warnings, want) {
		t.Fatalf("Warnings = %q, want %q", res.Warnings, want)
	}
	if lookup.calls.Load() != 0 {
		t.Fatalf("lookup called %d times, want 0", lookup.calls.Load())
	}
}

func TestAnalyzeMissingRootFails(t *testing.T) {
	reg, _ := newRegistry(nil)
	if _, err := engine.New(reg, nil, engine.Options{}).Analyze(context.Background(), filepath.Join(t.TempDir(), "nope")); err == nil {
		t.Fatal("Analyze of a missing directory succeeded")
	}
}

func TestAnalyzeReturnsContextErrorWhenCancelled(t *testing.T) {
	reg, _ := newRegistry(nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	lookup := &fakeLookup{err: context.Canceled}
	_, err := engine.New(reg, lookup, engine.Options{CheckLatest: true}).Analyze(ctx, "testdata/npm-lock")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
}

func TestAnalyzeDoesNotAskGoProjectsForALockfile(t *testing.T) {
	root := writeTree(t, map[string]string{
		"go.mod": "module example.com/svc\n\ngo 1.22\n\nrequire (\n\tgithub.com/google/uuid v1.6.0\n\tgolang.org/x/mod v0.20.0\n)\n",
	})
	reg, _ := newRegistry(nil)
	res := analyze(t, engine.New(reg, nil, engine.Options{}), root)
	if len(res.Dependencies) != 2 {
		t.Fatalf("dependencies:\n%s\nwant 2", describe(res.Dependencies))
	}
	if len(res.Warnings) != 0 {
		t.Fatalf("Warnings = %q, want none for a Go-only project", res.Warnings)
	}
}

func TestAnalyzeCountsUnresolvedDependenciesInPlural(t *testing.T) {
	root := writeTree(t, map[string]string{
		"requirements.txt": "flask>=2.0\ndjango>=4.0\nrequests==2.31.0\n",
		"go.mod":           "module example.com/svc\n\ngo 1.22\n\nrequire github.com/google/uuid v1.6.0\n",
	})
	reg, _ := newRegistry(nil)
	res := analyze(t, engine.New(reg, nil, engine.Options{}), root)
	if want := []string{"2 dependencies have no lockfile; their versions are approximate"}; !slices.Equal(res.Warnings, want) {
		t.Fatalf("Warnings = %q, want %q", res.Warnings, want)
	}
}

// A scan cancelled, or out of time, while advisories are looked up reports
// that, not a failed vulnerability check.
func TestAnalyzeReturnsContextErrorWhenCancelledDuringLookup(t *testing.T) {
	for _, tc := range []struct {
		name string
		ctx  func() (context.Context, context.CancelFunc)
		want error
	}{
		{"cancel", func() (context.Context, context.CancelFunc) {
			return context.WithCancel(context.Background())
		}, context.Canceled},
		{"deadline", func() (context.Context, context.CancelFunc) {
			return context.WithTimeout(context.Background(), 50*time.Millisecond)
		}, context.DeadlineExceeded},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := tc.ctx()
			defer cancel()
			reg, _ := newRegistry(nil)
			lookup := &fakeLookup{err: errors.New("osv.dev: request aborted")}
			lookup.onCall = func() {
				if tc.want == context.Canceled {
					cancel()
				}
				<-ctx.Done()
			}
			res, err := engine.New(reg, lookup, engine.Options{}).Analyze(ctx, "testdata/npm-lock")
			if lookup.calls.Load() != 1 {
				t.Fatalf("lookup calls = %d, want 1", lookup.calls.Load())
			}
			if !errors.Is(err, tc.want) || errors.Is(err, engine.ErrVulnerabilityCheck) {
				t.Fatalf("err = %v, want %v and not ErrVulnerabilityCheck", err, tc.want)
			}
			if res != nil {
				t.Fatalf("result = %+v, want nil", res)
			}
		})
	}
}

func TestAnalyzeLookupErrorIsTypedAndUnwraps(t *testing.T) {
	reg, _ := newRegistry(nil)
	cause := errors.New("vulnerability check failed: odd upstream text")
	_, err := engine.New(reg, &fakeLookup{err: cause}, engine.Options{}).Analyze(context.Background(), "testdata/npm-lock")
	if !errors.Is(err, engine.ErrVulnerabilityCheck) || !errors.Is(err, cause) {
		t.Fatalf("err = %v, want both ErrVulnerabilityCheck and the cause", err)
	}
	var vc *engine.VulnCheckError
	if !errors.As(err, &vc) || vc.Err != cause {
		t.Fatalf("err = %#v, want *engine.VulnCheckError with the cause", err)
	}
	if want := "vulnerability check failed: vulnerability check failed: odd upstream text"; err.Error() != want {
		t.Fatalf("Error() = %q, want %q", err.Error(), want)
	}
}

func TestWithLoggerLogsToTheNewLoggerOnly(t *testing.T) {
	reg, _ := newRegistry(nil)
	var base, scoped bytes.Buffer
	e := engine.New(reg, nil, engine.Options{Logger: slog.New(slog.NewTextHandler(&base, nil))})
	analyze(t, e.WithLogger(slog.New(slog.NewTextHandler(&scoped, nil)).With("repo", "acme/web")), "testdata/npm-lock")
	if !strings.Contains(scoped.String(), "repo=acme/web") || !strings.Contains(scoped.String(), "discovered manifests") {
		t.Fatalf("scoped logger got:\n%s", scoped.String())
	}
	if base.Len() != 0 {
		t.Fatalf("the original engine's logger was used:\n%s", base.String())
	}
	analyze(t, e, "testdata/npm-lock")
	if !strings.Contains(base.String(), "discovered manifests") || strings.Contains(base.String(), "repo=") {
		t.Fatalf("original engine changed:\n%s", base.String())
	}
}

// fakeEnricher marks the advisory named kevID as known exploited and
// returns result; with block it waits for its context and fails.
type fakeEnricher struct {
	kevID  string
	result exploit.Result
	block  bool
	onCall func()
	calls  atomic.Int32
	got    []*entity.Vulnerability
}

func (f *fakeEnricher) Enrich(ctx context.Context, vulns []*entity.Vulnerability) exploit.Result {
	f.calls.Add(1)
	f.got = vulns
	if f.onCall != nil {
		f.onCall()
	}
	if f.block {
		<-ctx.Done()
		failed := exploit.SourceResult{Status: exploit.StatusFailed, Err: ctx.Err()}
		return exploit.Result{KEV: failed, EPSS: failed}
	}
	for _, v := range vulns {
		if v.OSVID == f.kevID {
			v.KEV = true
		}
	}
	return f.result
}

var okExploit = exploit.Result{
	KEV:  exploit.SourceResult{Status: exploit.StatusOK, Version: "2026.10.14"},
	EPSS: exploit.SourceResult{Status: exploit.StatusOK, Version: "2026-10-14"},
}

func TestAnalyzeAddsExploitDataAfterTheLookup(t *testing.T) {
	reg, _ := newRegistry(nil)
	lookup := &fakeLookup{vulnerable: map[string]string{"express": "GHSA-1", "accepts": "GHSA-2"}}
	enricher := &fakeEnricher{kevID: "GHSA-1", result: okExploit}
	res := analyze(t, engine.New(reg, lookup, engine.Options{Exploit: enricher}), "testdata/npm-lock")

	if enricher.calls.Load() != 1 || len(enricher.got) != 2 || enricher.got[0] != res.Vulnerabilities[0] {
		t.Fatalf("enricher got %d vulnerabilities in %d calls; want the lookup's 2 in one call", len(enricher.got), enricher.calls.Load())
	}
	kev := 0
	for _, v := range res.Vulnerabilities {
		if v.KEV {
			kev++
		}
	}
	if kev != 1 || res.Exploit == nil || res.Exploit.KEV.Version != "2026.10.14" || len(res.Warnings) != 0 {
		t.Fatalf("KEV findings %d, exploit %+v, warnings %q", kev, res.Exploit, res.Warnings)
	}
}

func TestAnalyzeTurnsAnExploitFailureIntoAWarning(t *testing.T) {
	reg, _ := newRegistry(nil)
	failed := okExploit
	failed.KEV = exploit.SourceResult{Status: exploit.StatusFailed, Err: errors.New("fetch KEV catalog: HTTP 503")}
	e := engine.New(reg, &fakeLookup{vulnerable: map[string]string{"express": "GHSA-1"}}, engine.Options{Exploit: &fakeEnricher{result: failed}})
	res, err := e.Analyze(context.Background(), "testdata/npm-lock")
	if err != nil {
		t.Fatalf("Analyze = %v; an exploit data failure must not fail the scan", err)
	}
	if len(res.Vulnerabilities) != 1 || !slices.ContainsFunc(res.Warnings, func(w string) bool { return strings.Contains(w, "HTTP 503") }) {
		t.Fatalf("vulnerabilities %d, warnings %q", len(res.Vulnerabilities), res.Warnings)
	}
}

func TestAnalyzeBoundsExploitDataWithItsOwnTimeout(t *testing.T) {
	reg, _ := newRegistry(nil)
	e := engine.New(reg, &fakeLookup{vulnerable: map[string]string{"express": "GHSA-1"}},
		engine.Options{Exploit: &fakeEnricher{block: true}, ExploitTimeout: 20 * time.Millisecond})
	res, err := e.Analyze(context.Background(), "testdata/npm-lock")
	if err != nil || res.Exploit == nil || res.Exploit.KEV.Status != exploit.StatusFailed {
		t.Fatalf("Analyze = %+v, %v; want a result with failed exploit data", res, err)
	}
	if !slices.ContainsFunc(res.Warnings, func(w string) bool { return strings.Contains(w, "deadline exceeded") }) {
		t.Fatalf("warnings = %q, want the timeout", res.Warnings)
	}
}

func TestAnalyzeReturnsContextErrorWhenCancelledDuringExploitData(t *testing.T) {
	reg, _ := newRegistry(nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	e := engine.New(reg, &fakeLookup{vulnerable: map[string]string{"express": "GHSA-1"}},
		engine.Options{Exploit: &fakeEnricher{result: okExploit, onCall: cancel}})
	res, err := e.Analyze(ctx, "testdata/npm-lock")
	if !errors.Is(err, context.Canceled) || res != nil {
		t.Fatalf("Analyze = %+v, %v; want nil, context.Canceled", res, err)
	}
}

func TestAnalyzeSkipsExploitDataWhenTheLookupFails(t *testing.T) {
	reg, _ := newRegistry(nil)
	enricher := &fakeEnricher{result: okExploit}
	res, err := engine.New(reg, &fakeLookup{err: errors.New("osv.dev unreachable")}, engine.Options{Exploit: enricher}).
		Analyze(context.Background(), "testdata/npm-lock")
	if !errors.Is(err, engine.ErrVulnerabilityCheck) || enricher.calls.Load() != 0 || res.Exploit != nil {
		t.Fatalf("err %v, enricher calls %d, exploit %+v", err, enricher.calls.Load(), res.Exploit)
	}
}

func TestAnalyzeTreeWithoutManifestsMarksExploitDataSkipped(t *testing.T) {
	reg, _ := newRegistry(nil)
	res := analyze(t, engine.New(reg, &fakeLookup{}, engine.Options{Exploit: &fakeEnricher{}}), writeTree(t, map[string]string{"README.md": "x"}))
	if res.Exploit == nil || res.Exploit.KEV.Status != exploit.StatusSkipped || res.Exploit.EPSS.Status != exploit.StatusSkipped {
		t.Fatalf("exploit = %+v, want both skipped", res.Exploit)
	}
	if res := analyze(t, engine.New(reg, &fakeLookup{}, engine.Options{}), writeTree(t, map[string]string{"README.md": "x"})); res.Exploit != nil {
		t.Fatalf("exploit data off: Exploit = %+v, want nil", res.Exploit)
	}
}

// The npm fixture with a real dependency graph: Via survives Resolve and
// reaches the scanned dependencies.
func TestAnalyzeCarriesViaFromThePackageLock(t *testing.T) {
	reg, _ := newRegistry(nil)
	res := analyze(t, engine.New(reg, nil, engine.Options{}), "../infrastructure/analyzer/npm/testdata/lock-v3-graph")
	via := map[string][]string{}
	for _, d := range res.Dependencies {
		via[d.Name+"@"+d.CurrentVersion] = d.Via
	}
	if got := via["qs@6.7.0"]; !slices.Equal(got, []string{"express"}) {
		t.Errorf("qs@6.7.0 via %v, want [express]", got)
	}
	if got := via["safe-buffer@5.1.2"]; !slices.Equal(got, []string{"express", "mocha"}) {
		t.Errorf("safe-buffer@5.1.2 via %v, want [express mocha]", got)
	}
	if got := via["express@4.17.1"]; got != nil {
		t.Errorf("express@4.17.1 via %v, want nil", got)
	}
}
