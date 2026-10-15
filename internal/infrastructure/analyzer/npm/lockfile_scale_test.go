package npm

import (
	"bytes"
	"encoding/json"
	"fmt"
	"maps"
	"math/rand/v2"
	"path"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/orchesta/orbit/internal/infrastructure/analyzer"
)

// syntheticPnpmLock returns a pnpm v9 lockfile with n packages (n even):
// pkg-i, a dependency of the root importer, depends on dep-i. Every fourth
// pkg-i is a devDependency, so it and its dep-i are dev only.
func syntheticPnpmLock(n int) []byte {
	var b bytes.Buffer
	b.WriteString("lockfileVersion: '9.0'\n\nimporters:\n\n  .:\n    dependencies:\n")
	for i := 0; i < n/2; i++ {
		if i%4 != 0 {
			fmt.Fprintf(&b, "      pkg-%d:\n        specifier: ^1.0.0\n        version: 1.0.%d\n", i, i)
		}
	}
	b.WriteString("    devDependencies:\n")
	for i := 0; i < n/2; i += 4 {
		fmt.Fprintf(&b, "      pkg-%d:\n        specifier: ^1.0.0\n        version: 1.0.%d\n", i, i)
	}
	b.WriteString("\npackages:\n\n")
	for i := 0; i < n/2; i++ {
		fmt.Fprintf(&b, "  pkg-%d@1.0.%d:\n    resolution: {integrity: sha512-%060d}\n\n", i, i, i)
		fmt.Fprintf(&b, "  dep-%d@2.0.%d:\n    resolution: {integrity: sha512-%060d}\n\n", i, i, i)
	}
	b.WriteString("snapshots:\n\n")
	for i := 0; i < n/2; i++ {
		fmt.Fprintf(&b, "  pkg-%d@1.0.%d:\n    dependencies:\n      dep-%d: 2.0.%d\n\n", i, i, i, i)
		fmt.Fprintf(&b, "  dep-%d@2.0.%d: {}\n\n", i, i)
	}
	return b.Bytes()
}

// syntheticYarnBerry returns a yarn berry lockfile with n packages.
func syntheticYarnBerry(n int) []byte {
	var b bytes.Buffer
	b.WriteString("__metadata:\n  version: 8\n  cacheKey: 10c0\n\n")
	for i := range n {
		fmt.Fprintf(&b, "\"pkg-%d@npm:^1.0.0\":\n  version: 1.0.%d\n  resolution: \"pkg-%d@npm:1.0.%d\"\n  checksum: 10c0/%060d\n  languageName: node\n  linkType: hard\n\n", i, i, i, i, i)
	}
	return b.Bytes()
}

func TestSyntheticYAMLLockfiles(t *testing.T) {
	const n = 400
	deps, err := NewAnalyzer().ParseDependencies(syntheticPnpmLock(n), "pnpm-lock.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if len(deps) != n {
		t.Fatalf("pnpm: %d dependencies, want %d", len(deps), n)
	}
	for _, d := range deps {
		var i int
		if _, err := fmt.Sscanf(d.Name[strings.Index(d.Name, "-")+1:], "%d", &i); err != nil {
			t.Fatalf("unexpected package %s", d.Name)
		}
		if want := i%4 == 0; d.Dev != want || !d.Resolved {
			t.Errorf("pnpm: %s@%s dev=%v resolved=%v, want dev=%v", d.Name, d.CurrentVersion, d.Dev, d.Resolved, want)
		}
	}

	deps, err = NewAnalyzer().ParseDependencies(syntheticYarnBerry(n), "yarn.lock")
	if err != nil {
		t.Fatal(err)
	}
	if len(deps) != n {
		t.Fatalf("yarn berry: %d dependencies, want %d", len(deps), n)
	}
}

// YAML lockfiles are walked as nodes. Decoding them into Go maps or structs
// with yaml.v3 is quadratic in the number of keys (it checks them for
// duplicates pairwise) and rejects a repeated key. These lockfiles repeat a
// key, so they fail to parse if map decoding comes back.
func TestYAMLLockfilesWithDuplicateKeys(t *testing.T) {
	tests := []struct {
		file, content string
		want          []analyzer.ParsedDependency
	}{
		{"pnpm-lock.yaml", `lockfileVersion: '9.0'

importers:

  .:
    dependencies:
      ms:
        specifier: ^2.0.0
        version: 2.0.0

packages:

  ms@2.0.0:
    resolution: {integrity: sha512-a}

  ms@2.0.0:
    resolution: {integrity: sha512-a}

snapshots:

  ms@2.0.0: {}
`, []analyzer.ParsedDependency{locked("ms", "2.0.0", false)}},
		{"yarn.lock", `__metadata:
  version: 8
  cacheKey: 10c0

"express@npm:^4.18.0":
  version: 4.18.2
  resolution: "express@npm:4.18.2"
  languageName: node
  linkType: hard

"express@npm:^4.18.0":
  version: 4.18.2
  resolution: "express@npm:4.18.2"
  languageName: node
  linkType: hard
`, []analyzer.ParsedDependency{locked("express", "4.18.2", false)}},
	}
	for _, tt := range tests {
		t.Run(tt.file, func(t *testing.T) {
			got, err := NewAnalyzer().ParseDependencies([]byte(tt.content), tt.file)
			if err != nil {
				t.Fatalf("parse failed (map decoding is back?): %v", err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("got  %+v\nwant %+v", got, tt.want)
			}
		})
	}
}

func TestYAMLLockfileSizeCap(t *testing.T) {
	for _, file := range []string{"pnpm-lock.yaml", "yarn.lock"} {
		header := "lockfileVersion: '9.0'\n"
		if file == "yarn.lock" {
			header = "__metadata:\n  version: 8\n"
		}
		content := []byte(header + "#" + strings.Repeat("x", maxYAMLLockfileBytes) + "\n")
		_, err := NewAnalyzer().ParseDependencies(content, file)
		if err == nil || !strings.Contains(err.Error(), "larger than") {
			t.Errorf("%s over the YAML cap: err = %v, want a size error", file, err)
		}
	}
}

// Parse time should grow linearly with size: compare ns/op of the 4k and 32k
// cases (go test -run '^$' -bench 'ParsePnpmLock|ParseYarnBerry').

func BenchmarkParsePnpmLock(b *testing.B) {
	benchmarkParse(b, "pnpm-lock.yaml", syntheticPnpmLock)
}

func BenchmarkParseYarnBerry(b *testing.B) {
	benchmarkParse(b, "yarn.lock", syntheticYarnBerry)
}

func benchmarkParse(b *testing.B, file string, gen func(int) []byte) {
	for _, n := range []int{4000, 32000} {
		content := gen(n)
		b.Run(fmt.Sprintf("%dk", n/1000), func(b *testing.B) {
			b.SetBytes(int64(len(content)))
			for b.Loop() {
				if _, err := NewAnalyzer().ParseDependencies(content, file); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// syntheticPackageLock returns a lockfile v3 whose root depends on n
// packages pkg-i; pkg-i depends on dep-i and shared, and dep-i on shared.
func syntheticPackageLock(n int) []byte {
	var b bytes.Buffer
	b.WriteString(`{"lockfileVersion":3,"packages":{"":{"dependencies":{`)
	for i := range n {
		if i > 0 {
			b.WriteString(",")
		}
		fmt.Fprintf(&b, `"pkg-%d":"^1.0.0"`, i)
	}
	b.WriteString(`}}`)
	for i := range n {
		fmt.Fprintf(&b, `,"node_modules/pkg-%d":{"version":"1.0.0","dependencies":{"dep-%d":"^1.0.0","shared":"^1.0.0"}}`, i, i)
		fmt.Fprintf(&b, `,"node_modules/dep-%d":{"version":"1.0.0","dependencies":{"shared":"^1.0.0"}}`, i)
	}
	b.WriteString(`,"node_modules/shared":{"version":"1.0.0"}}}`)
	return b.Bytes()
}

func TestSyntheticPackageLockVia(t *testing.T) {
	const n = 2000
	deps, err := NewAnalyzer().ParseDependencies(syntheticPackageLock(n), "package-lock.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(deps) != 2*n+1 {
		t.Fatalf("%d dependencies, want %d", len(deps), 2*n+1)
	}
	for _, d := range deps {
		switch {
		case d.Name == "shared" && len(d.Via) != n:
			t.Errorf("shared: %d names in Via, want %d", len(d.Via), n)
		case d.Name == "dep-7" && !reflect.DeepEqual(d.Via, []string{"pkg-7"}):
			t.Errorf("dep-7: Via = %v, want [pkg-7]", d.Via)
		case strings.HasPrefix(d.Name, "pkg-") && d.Via != nil:
			t.Errorf("%s is declared by the project; Via = %v", d.Name, d.Via)
		}
	}
}

// perRootLockVia is the plain form of lockVia: one walk, with its own seen
// set, per (direct dependency name, entry) pair. lockVia must agree with it.
func perRootLockVia(pkgs map[string]lockPackage) map[string][]string {
	type root struct{ name, key string }
	var roots []root
	direct := make(map[string]bool)
	edges := make(map[string][]string)
	for key, pkg := range pkgs {
		if pkg.Link {
			continue
		}
		project := isProjectFolder(key)
		for _, name := range pkg.requiredNames(project) {
			target, ok := resolveLockDep(pkgs, key, name)
			if !ok || pkgs[target].Link {
				continue
			}
			if project {
				roots = append(roots, root{name, target})
				direct[target] = true
			} else {
				edges[key] = append(edges[key], target)
			}
		}
	}
	via := make(map[string]map[string]bool)
	for _, r := range roots {
		seen := map[string]bool{r.key: true}
		stack := []string{r.key}
		for len(stack) > 0 {
			k := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			for _, t := range edges[k] {
				if seen[t] {
					continue
				}
				seen[t] = true
				stack = append(stack, t)
				if direct[t] {
					continue
				}
				if via[t] == nil {
					via[t] = make(map[string]bool)
				}
				via[t][r.name] = true
			}
		}
	}
	out := make(map[string][]string)
	for key, names := range via {
		out[key] = slices.Sorted(maps.Keys(names))
	}
	return out
}

// randomPackageLock returns the packages of a lockfile with hoisted and
// nested copies, workspace folders with their own node_modules, links,
// cycles and requirements nothing satisfies.
func randomPackageLock(r *rand.Rand) map[string]lockPackage {
	const names = 12
	name := func() string { return fmt.Sprintf("p%d", r.IntN(names)) }
	deps := func(n int) json.RawMessage {
		m := map[string]string{}
		for range n {
			m[name()] = "^1.0.0"
		}
		b, _ := json.Marshal(m)
		return b
	}
	pkgs := map[string]lockPackage{
		"":           {Dependencies: deps(3), DevDependencies: deps(2)},
		"packages/a": {Dependencies: deps(3)},
		"packages/b": {Dependencies: deps(2), DevDependencies: deps(1)},
	}
	pkgs["node_modules/ws-a"] = lockPackage{Link: true, Resolved: "packages/a"}
	parents := []string{"", "packages/a"}
	for range 40 {
		parent := parents[r.IntN(len(parents))]
		key := path.Join(parent, "node_modules", name())
		if strings.HasPrefix(key, "packages/") && r.IntN(3) > 0 {
			key = path.Join("node_modules", name()) // mostly hoisted
		}
		pkg := lockPackage{Version: "1.0.0", Dependencies: deps(r.IntN(3))}
		if r.IntN(4) == 0 {
			pkg.PeerDependencies = deps(1)
		}
		pkgs[key] = pkg
		parents = append(parents, key)
	}
	return pkgs
}

func TestLockViaMatchesPerRootWalk(t *testing.T) {
	r := rand.New(rand.NewPCG(1, 2))
	shared := 0 // entries more than one direct dependency pulls in
	for i := range 300 {
		pkgs := randomPackageLock(r)
		got, ok := lockVia(pkgs)
		if want := perRootLockVia(pkgs); !ok || !reflect.DeepEqual(got, want) {
			t.Fatalf("lockfile %d:\n got %v\nwant %v", i, got, want)
		}
		for _, names := range got {
			if len(names) > 1 {
				shared++
			}
		}
	}
	if shared == 0 {
		t.Fatal("the random lockfiles never share an entry between direct dependencies")
	}
	for _, fixture := range []string{"lock-v3", "lock-v3-graph", "lock-workspaces", "lock-workspace-links"} {
		var lock packageLock
		if err := json.Unmarshal(readFixture(t, fixture+"/package-lock.json"), &lock); err != nil {
			t.Fatal(err)
		}
		if got, want := mustLockVia(t, lock.Packages), perRootLockVia(lock.Packages); !reflect.DeepEqual(got, want) {
			t.Fatalf("%s:\n got %v\nwant %v", fixture, got, want)
		}
	}
}
