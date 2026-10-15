package engine_test

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/orchesta/orbit/internal/domain/entity"
	"github.com/orchesta/orbit/internal/engine"
	"github.com/orchesta/orbit/internal/infrastructure/depsdev"
)

// The deps.dev client the CLI and server use fits the engine.
var _ engine.LicenseFetcher = (*depsdev.Client)(nil)

// fakeLicenses answers License from licenses ("eco name@version" ->
// expression); a key in fail returns an error, panicOn panics, and a
// missing key is "" (unknown). Calls are recorded.
type fakeLicenses struct {
	licenses map[string]string
	fail     map[string]bool
	panicOn  string

	mu    sync.Mutex
	calls []string
}

func (f *fakeLicenses) License(_ context.Context, eco entity.Ecosystem, name, version string) (string, error) {
	key := fmt.Sprintf("%s %s@%s", eco, name, version)
	f.mu.Lock()
	f.calls = append(f.calls, key)
	f.mu.Unlock()
	if name == f.panicOn {
		panic("bad response")
	}
	if f.fail[key] {
		return "", errors.New("deps.dev unreachable")
	}
	return f.licenses[key], nil
}

func (f *fakeLicenses) lookups() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := slices.Clone(f.calls)
	slices.Sort(out)
	return out
}

func TestAnalyzeFetchesMissingLicensesForExactVersionsOnce(t *testing.T) {
	f := &fakeLicenses{licenses: map[string]string{
		"npm b@2.0.0":                     "ISC",
		"Go github.com/google/uuid@1.6.0": "BSD-3-Clause",
		"PyPI requests@2.31.0":            "Apache-2.0",
		"NuGet Newtonsoft.Json@13.0.3":    "MIT",
	}}
	reg, _ := newRegistry(nil)
	res := analyze(t, engine.New(reg, nil, engine.Options{Licenses: f}), licenseTree(t))

	// a has a lockfile license; flask and Serilog have ranges; b is asked once.
	wantCalls := []string{"Go github.com/google/uuid@1.6.0", "NuGet Newtonsoft.Json@13.0.3", "PyPI requests@2.31.0", "npm b@2.0.0"}
	if got := f.lookups(); !slices.Equal(got, wantCalls) {
		t.Fatalf("lookups = %q, want %q", got, wantCalls)
	}
	want := []string{
		`net/App.csproj Newtonsoft.Json@13.0.3 license="MIT"`,
		`net/App.csproj Serilog@[3.0,4.0) license=""`,
		`package-lock.json a@1.0.0 license="MIT"`,
		`package-lock.json b@2.0.0 license="ISC"`,
		`py/requirements.txt flask@2.0 license=""`,
		`py/requirements.txt requests@2.31.0 license="Apache-2.0"`,
		`svc/go.mod github.com/google/uuid@1.6.0 license="BSD-3-Clause"`,
	}
	got := licensesOf(res.Dependencies)
	slices.Sort(got)
	if !slices.Equal(got, want) {
		t.Fatalf("licenses:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	if res.LicenseLookupFailed != 0 {
		t.Fatalf("LicenseLookupFailed = %d", res.LicenseLookupFailed)
	}
}

func TestAnalyzeNeverOverwritesALockfileLicense(t *testing.T) {
	// The fetcher would answer for a, but the lockfile already says MIT.
	f := &fakeLicenses{licenses: map[string]string{"npm a@1.0.0": "GPL-3.0-only"}}
	reg, _ := newRegistry(nil)
	res := analyze(t, engine.New(reg, nil, engine.Options{Licenses: f}), licenseTree(t))
	if slices.Contains(f.lookups(), "npm a@1.0.0") {
		t.Fatalf("lookups = %q, must not ask for a package with a lockfile license", f.lookups())
	}
	if got := licensesOf(res.Dependencies); !slices.Contains(got, `package-lock.json a@1.0.0 license="MIT"`) {
		t.Fatalf("licenses:\n%s", strings.Join(got, "\n"))
	}
}

func TestAnalyzeCountsFailedLicenseLookupsAndPanics(t *testing.T) {
	f := &fakeLicenses{
		licenses: map[string]string{"npm b@2.0.0": "ISC"},
		fail:     map[string]bool{"PyPI requests@2.31.0": true},
		panicOn:  "github.com/google/uuid",
	}
	reg, _ := newRegistry(nil)
	res := analyze(t, engine.New(reg, nil, engine.Options{Licenses: f}), licenseTree(t))
	if res.LicenseLookupFailed != 2 {
		t.Fatalf("LicenseLookupFailed = %d, want 2", res.LicenseLookupFailed)
	}
	var warning string
	for _, w := range res.Warnings {
		if strings.HasPrefix(w, "license lookup failed for 2 packages: ") {
			warning = w
		}
	}
	if warning == "" {
		t.Fatalf("Warnings = %q, want one about 2 failed lookups", res.Warnings)
	}
	if got := licensesOf(res.Dependencies); !slices.Contains(got, `package-lock.json b@2.0.0 license="ISC"`) {
		t.Fatalf("the lookups that worked must still apply:\n%s", strings.Join(got, "\n"))
	}
}

func TestAnalyzeWarnsAboutOneFailedLicenseLookupInSingular(t *testing.T) {
	f := &fakeLicenses{fail: map[string]bool{"PyPI requests@2.31.0": true}}
	reg, _ := newRegistry(nil)
	res := analyze(t, engine.New(reg, nil, engine.Options{Licenses: f}), licenseTree(t))
	if res.LicenseLookupFailed != 1 {
		t.Fatalf("LicenseLookupFailed = %d, want 1", res.LicenseLookupFailed)
	}
	if !slices.Contains(res.Warnings, "license lookup failed for 1 package: deps.dev unreachable") {
		t.Fatalf("Warnings = %q", res.Warnings)
	}
	if res.LicenseLookupErr == nil || res.LicenseLookupErr.Error() != "deps.dev unreachable" {
		t.Fatalf("LicenseLookupErr = %v, want the first failure", res.LicenseLookupErr)
	}
}

// blockingLicenses holds every lookup until the test sends on release, and
// records how many lookups are in flight at once.
type blockingLicenses struct {
	release chan struct{}

	mu          sync.Mutex
	calls       int
	inFlight    int
	maxInFlight int
}

func (b *blockingLicenses) License(ctx context.Context, _ entity.Ecosystem, _, _ string) (string, error) {
	b.mu.Lock()
	b.calls++
	b.inFlight++
	b.maxInFlight = max(b.maxInFlight, b.inFlight)
	b.mu.Unlock()
	defer func() {
		b.mu.Lock()
		b.inFlight--
		b.mu.Unlock()
	}()
	select {
	case <-b.release:
		return "MIT", nil
	case <-ctx.Done():
		return "", ctx.Err()
	}
}

// stats returns the lookups started, in flight now, and at most in flight.
func (b *blockingLicenses) stats() (calls, inFlight, maxInFlight int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.calls, b.inFlight, b.maxInFlight
}

// waitInFlight waits until at least n lookups are in flight.
func (b *blockingLicenses) waitInFlight(t *testing.T, n int) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, inFlight, _ := b.stats(); inFlight >= n {
			return
		}
		if time.Now().After(deadline) {
			_, inFlight, _ := b.stats()
			t.Fatalf("lookups in flight = %d, want %d", inFlight, n)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestAnalyzeLimitsLicenseConcurrency(t *testing.T) {
	const total, limit = 12, 2
	deps := make([]string, 0, total)
	for i := range total {
		deps = append(deps, fmt.Sprintf(`"node_modules/pkg%d":{"version":"1.0.0"}`, i))
	}
	root := writeTree(t, map[string]string{"package-lock.json": `{"lockfileVersion":3,"packages":{` + strings.Join(deps, ",") + `}}`})
	f := &blockingLicenses{release: make(chan struct{})}
	reg, _ := newRegistry(nil)
	e := engine.New(reg, nil, engine.Options{Licenses: f, LicenseConcurrency: limit})

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	type outcome struct {
		res *engine.Result
		err error
	}
	done := make(chan outcome, 1)
	go func() {
		res, err := e.Analyze(ctx, root)
		done <- outcome{res, err}
	}()

	// Every lookup blocks, so the engine fills all its slots; release them
	// one at a time and check that no more than limit are ever held.
	for released := range total {
		f.waitInFlight(t, min(limit, total-released))
		if released == 0 {
			// Give an unbounded engine time to start more lookups.
			time.Sleep(50 * time.Millisecond)
		}
		if _, inFlight, _ := f.stats(); inFlight > limit {
			t.Fatalf("lookups in flight = %d, want at most %d", inFlight, limit)
		}
		f.release <- struct{}{}
	}
	out := <-done
	if out.err != nil {
		t.Fatalf("Analyze: %v", out.err)
	}

	calls, _, maxInFlight := f.stats()
	if calls != total {
		t.Fatalf("lookups = %d, want %d", calls, total)
	}
	if maxInFlight != limit {
		t.Fatalf("max lookups in flight = %d, want exactly %d", maxInFlight, limit)
	}
	for _, d := range out.res.Dependencies {
		if d.License != "MIT" {
			t.Fatalf("%s license = %q, want MIT", d.Name, d.License)
		}
	}
}

func TestAnalyzeReturnsContextErrorWhenCancelledDuringLicenseLookup(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	f := &cancellingLicenses{cancel: cancel}
	reg, _ := newRegistry(nil)
	res, err := engine.New(reg, nil, engine.Options{Licenses: f}).Analyze(ctx, licenseTree(t))
	if !errors.Is(err, context.Canceled) || res != nil {
		t.Fatalf("Analyze = %v, %v; want nil, context.Canceled", res, err)
	}
}

// cancellingLicenses cancels the scan on its first call and then fails.
type cancellingLicenses struct {
	once   sync.Once
	cancel context.CancelFunc
}

func (c *cancellingLicenses) License(ctx context.Context, _ entity.Ecosystem, _, _ string) (string, error) {
	c.once.Do(c.cancel)
	return "", ctx.Err()
}
