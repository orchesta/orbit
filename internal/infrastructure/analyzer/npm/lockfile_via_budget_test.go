package npm

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"runtime"
	"slices"
	"testing"
	"time"

	"github.com/orchesta/orbit/internal/infrastructure/analyzer"
)

const viaSkippedWarning = "dependency paths (VIA) skipped: the lockfile graph is too large"

// chainPackageLock returns a lockfile v3 whose root depends on roots
// packages pkg-i, each depending on link-0; link-j depends on link-(j+1),
// up to link-(chain-1). Every pkg-i pulls in every link, so Via holds
// roots x chain names in all.
func chainPackageLock(roots, chain int) []byte {
	var b bytes.Buffer
	b.WriteString(`{"lockfileVersion":3,"packages":{"":{"dependencies":{`)
	for i := range roots {
		if i > 0 {
			b.WriteString(",")
		}
		fmt.Fprintf(&b, `"pkg-%d":"^1.0.0"`, i)
	}
	b.WriteString(`}}`)
	for i := range roots {
		fmt.Fprintf(&b, `,"node_modules/pkg-%d":{"version":"1.0.0","dependencies":{"link-0":"^1.0.0"}}`, i)
	}
	for j := range chain {
		next := ""
		if j+1 < chain {
			next = fmt.Sprintf(`"link-%d":"^1.0.0"`, j+1)
		}
		fmt.Fprintf(&b, `,"node_modules/link-%d":{"version":"1.0.0","dependencies":{%s}}`, j, next)
	}
	b.WriteString(`}}`)
	return b.Bytes()
}

// randomGraphLock returns a lockfile v3 with n hoisted packages p-i, each
// depending on k random others, cycles included. The root depends on the
// first roots of them.
func randomGraphLock(roots, n, k int) []byte {
	r := rand.New(rand.NewPCG(7, 9))
	var b bytes.Buffer
	b.WriteString(`{"lockfileVersion":3,"packages":{"":{"dependencies":{`)
	for i := range roots {
		if i > 0 {
			b.WriteString(",")
		}
		fmt.Fprintf(&b, `"p-%d":"1"`, i)
	}
	b.WriteString(`}}`)
	for i := range n {
		fmt.Fprintf(&b, `,"node_modules/p-%d":{"version":"1.0.0","dependencies":{`, i)
		for j := range k {
			if j > 0 {
				b.WriteString(",")
			}
			fmt.Fprintf(&b, `"p-%d":"1"`, r.IntN(n))
		}
		b.WriteString(`}}`)
	}
	b.WriteString(`}}`)
	return b.Bytes()
}

func parseLockWith(t *testing.T, content []byte, opts analyzer.ParseOptions) ([]analyzer.ParsedDependency, []string) {
	t.Helper()
	deps, warnings, err := NewAnalyzer().ParseWithOptions(content, "package-lock.json", opts)
	if err != nil {
		t.Fatal(err)
	}
	return deps, warnings
}

func viaNames(deps []analyzer.ParsedDependency) int {
	n := 0
	for _, d := range deps {
		n += len(d.Via)
	}
	return n
}

// Up to 1,000,000 names Via is complete; past it there is none at all,
// since a partial Via would leave out paths, and a warning says why.
func TestPackageLockViaBudget(t *testing.T) {
	deps, warnings := parseLockWith(t, chainPackageLock(1000, 1000), analyzer.ParseOptions{})
	if len(warnings) != 0 || viaNames(deps) != 1_000_000 {
		t.Fatalf("at the budget: %d Via names, warnings %q; want 1000000 and none", viaNames(deps), warnings)
	}

	deps, warnings = parseLockWith(t, chainPackageLock(1001, 1000), analyzer.ParseOptions{})
	if !slices.Equal(warnings, []string{viaSkippedWarning}) {
		t.Fatalf("over the budget: warnings %q, want %q", warnings, viaSkippedWarning)
	}
	if n := viaNames(deps); n != 0 {
		t.Fatalf("over the budget: %d Via names, want none", n)
	}
	if len(deps) != 2001 {
		t.Fatalf("over the budget: %d dependencies, want all 2001", len(deps))
	}
}

// Lockfiles whose walks would take gigabytes or minutes stop early: one
// with many direct dependencies sharing a large graph (the walk records a
// name per direct dependency and entry it reaches), and one whose entries
// are all direct (the walks record nothing but each crosses the graph).
func TestPackageLockViaBudgetBoundsTheWork(t *testing.T) {
	if testing.Short() {
		t.Skip("large lockfiles")
	}
	for name, content := range map[string][]byte{
		"2000 direct, 20000 entries": randomGraphLock(2000, 20000, 4),
		"all 20000 entries direct":   randomGraphLock(20000, 20000, 4),
	} {
		t.Run(name, func(t *testing.T) {
			runtime.GC()
			var before, after runtime.MemStats
			runtime.ReadMemStats(&before)
			start := time.Now()
			deps, warnings := parseLockWith(t, content, analyzer.ParseOptions{})
			elapsed := time.Since(start)
			runtime.ReadMemStats(&after)
			if !slices.Equal(warnings, []string{viaSkippedWarning}) {
				t.Fatalf("warnings %q, want %q", warnings, viaSkippedWarning)
			}
			if n := viaNames(deps); n != 0 {
				t.Fatalf("%d Via names, want none", n)
			}
			// Unbounded, the first took 2.3 GB; parsing alone takes about
			// 60 MB.
			alloc := (after.TotalAlloc - before.TotalAlloc) >> 20
			t.Logf("%d KB lockfile: %v, %d MB allocated", len(content)>>10, elapsed, alloc)
			if alloc > 400 {
				t.Errorf("allocated %d MB, want at most 400", alloc)
			}
		})
	}
}

// With SkipVia the graph is not walked at all: no Via, and no warning even
// for a lockfile over the budget.
func TestPackageLockSkipVia(t *testing.T) {
	skip := analyzer.ParseOptions{SkipVia: true}
	full, _ := parseLockWith(t, readFixture(t, "lock-v3-graph/package-lock.json"), analyzer.ParseOptions{})
	if viaNames(full) == 0 {
		t.Fatal("the fixture has no Via to skip")
	}
	got, warnings := parseLockWith(t, readFixture(t, "lock-v3-graph/package-lock.json"), skip)
	if len(warnings) != 0 || len(got) != len(full) {
		t.Fatalf("got %d dependencies, warnings %q; want %d and none", len(got), warnings, len(full))
	}
	if !slices.EqualFunc(got, full, func(a, b analyzer.ParsedDependency) bool {
		return a.Name == b.Name && a.CurrentVersion == b.CurrentVersion && a.Dev == b.Dev && a.Via == nil
	}) {
		t.Fatalf("SkipVia changed more than Via:\n got %+v\nwant %+v", got, full)
	}

	got, warnings = parseLockWith(t, chainPackageLock(1001, 1000), skip)
	if len(warnings) != 0 || viaNames(got) != 0 {
		t.Fatalf("over the budget with SkipVia: %d Via names, warnings %q; want neither", viaNames(got), warnings)
	}
}

// mustLockVia is lockVia for a lockfile within its bounds.
func mustLockVia(t *testing.T, pkgs map[string]lockPackage) map[string][]string {
	t.Helper()
	via, ok := lockVia(pkgs)
	if !ok {
		t.Fatal("lockVia gave up")
	}
	return via
}

// Three direct dependencies each reach the four links: 12 names, and 12
// edges followed (one out of each pkg-i and of each link but the last).
func TestLockViaStopsAtEitherBound(t *testing.T) {
	var lock packageLock
	if err := json.Unmarshal(chainPackageLock(3, 4), &lock); err != nil {
		t.Fatal(err)
	}
	if via, ok := lockViaWithin(lock.Packages, 12, 12); !ok || len(via["node_modules/link-3"]) != 3 {
		t.Fatalf("at both bounds: via %v, ok %v; want link-3 via all three", via, ok)
	}
	for _, b := range [][2]int{{11, 100}, {100, 11}} {
		if via, ok := lockViaWithin(lock.Packages, b[0], b[1]); ok || via != nil {
			t.Errorf("names %d, steps %d: via %v, ok %v; want nil and false", b[0], b[1], via, ok)
		}
	}
}
