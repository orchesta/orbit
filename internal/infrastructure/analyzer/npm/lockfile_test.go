package npm

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/orchesta/orbit/internal/infrastructure/analyzer"
)

func locked(name, version string, dev bool) analyzer.ParsedDependency {
	return analyzer.ParsedDependency{Name: name, CurrentVersion: version, Resolved: true, Dev: dev}
}

func internal(name, dir string) analyzer.ParsedDependency {
	return analyzer.ParsedDependency{Name: name, Internal: true, Dir: dir}
}

func readFixture(t *testing.T, rel string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", filepath.FromSlash(rel)))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestParseLockfiles(t *testing.T) {
	tests := []struct {
		fixture string
		want    []analyzer.ParsedDependency
	}{
		{"lock-v3/package-lock.json", []analyzer.ParsedDependency{
			locked("@scope/lib", "2.1.0", false),
			locked("express", "4.18.2", false),
			locked("fsevents", "2.3.3", true),
			locked("jest", "29.7.0", true),
			internal("local-pkg", "packages/local-pkg"),
			locked("ms", "2.0.0", false),
			locked("ms", "2.1.3", false),
			locked("real-name", "1.0.0", false),
			locked("registry-pkg", "3.0.0", false),
		}},
		{"lock-v1/package-lock.json", []analyzer.ParsedDependency{
			locked("@scope/lib", "2.1.0", false),
			locked("bar", "1.0.0", false),
			locked("express", "4.18.2", false),
			locked("jest", "29.7.0", true),
			locked("ms", "2.0.0", false),
			locked("ms", "2.1.3", false),
		}},
		{"yarn-v1/yarn.lock", []analyzer.ParsedDependency{
			locked("@scope/lib", "2.1.0", false),
			locked("bar", "1.5.0", false),
			locked("express", "4.18.2", false),
			locked("ms", "2.0.0", false),
			locked("ms", "2.1.3", false),
		}},
		{"yarn-berry/yarn.lock", []analyzer.ParsedDependency{
			locked("@scope/lib", "2.1.0", false),
			locked("express", "4.18.2", false),
			locked("resolve", "1.22.8", false),
			internal("shared", "packages/shared"),
		}},
		{"pnpm-v6/pnpm-lock.yaml", []analyzer.ParsedDependency{
			locked("@scope/lib", "2.1.0", false),
			locked("@types/node", "20.0.0", true),
			locked("express", "4.18.2", false),
			locked("jest", "29.7.0", true),
			locked("ms", "2.0.0", false),
		}},
		{"pnpm-v9/pnpm-lock.yaml", []analyzer.ParsedDependency{
			locked("@scope/lib", "2.1.0", false),
			locked("@types/node", "20.0.0", true),
			locked("express", "4.18.2", false),
			locked("jest", "29.7.0", true),
			locked("ms", "2.0.0", false),
			locked("ms", "2.1.3", true),
			internal("shared", "../shared"),
		}},
	}
	a := NewAnalyzer()
	for _, tt := range tests {
		t.Run(tt.fixture, func(t *testing.T) {
			if got := a.Kind(tt.fixture); got != analyzer.KindLockfile {
				t.Fatalf("Kind = %v, want KindLockfile", got)
			}
			got, err := a.ParseDependencies(readFixture(t, tt.fixture), tt.fixture)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("got  %+v\nwant %+v", got, tt.want)
			}
		})
	}
}

func TestParseLockfileErrors(t *testing.T) {
	a := NewAnalyzer()
	for _, name := range []string{"package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "yarn.lock"} {
		content := "{ not valid"
		if name == "yarn.lock" {
			content = "__metadata:\n  version: [oops"
		}
		if _, err := a.ParseDependencies([]byte(content), "sub/"+name); err == nil {
			t.Errorf("%s: want an error for malformed content", name)
		}
	}
}

func TestDetectsLockfiles(t *testing.T) {
	a := NewAnalyzer()
	want := map[string]analyzer.ManifestKind{
		"package.json":        analyzer.KindManifest,
		"package-lock.json":   analyzer.KindLockfile,
		"npm-shrinkwrap.json": analyzer.KindLockfile,
		"yarn.lock":           analyzer.KindLockfile,
		"pnpm-lock.yaml":      analyzer.KindLockfile,
	}
	if got := a.DetectManifests(); len(got) != len(want) {
		t.Fatalf("DetectManifests = %v", got)
	}
	for name, kind := range want {
		if got := a.Kind("web/" + name); got != kind {
			t.Errorf("Kind(%s) = %v, want %v", name, got, kind)
		}
	}
}

func TestParsePackageJSON(t *testing.T) {
	content := `{
		"dependencies": {"express": "^4.18.0", "linked": "link:../linked", "wsp": "workspace:*", "gh": "github:user/repo", "shorthand": "user/repo", "gitdep": "git+https://x/y.git", "cat": "catalog:", "jsrdep": "jsr:^1.0.0", "foo": "npm:bar@^1.2.0", "filedep": "file:../f"},
		"devDependencies": {"jest": "~29.0.0"},
		"peerDependencies": {"react": ">=18.0.0"},
		"optionalDependencies": {"fsevents": "2.3.3"}
	}`
	got, err := NewAnalyzer().ParseDependencies([]byte(content), "package.json")
	if err != nil {
		t.Fatal(err)
	}
	want := []analyzer.ParsedDependency{
		{Name: "bar", CurrentVersion: "1.2.0", IsDirect: true},
		{Name: "express", CurrentVersion: "4.18.0", IsDirect: true},
		{Name: "fsevents", CurrentVersion: "2.3.3", IsDirect: true},
		{Name: "jest", CurrentVersion: "29.0.0", IsDirect: true, Dev: true},
		{Name: "react", CurrentVersion: "18.0.0", IsDirect: true},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got  %+v\nwant %+v", got, want)
	}
}

// A workspaces lockfile whose root package.json declares nothing: the
// workspace packages' declarations make their dependencies direct.
func TestWorkspaceLockfileDirectness(t *testing.T) {
	a := NewAnalyzer()
	parse := func(path, fixture string) analyzer.ParsedFile {
		deps, err := a.ParseDependencies(readFixture(t, fixture), path)
		if err != nil {
			t.Fatal(err)
		}
		return analyzer.ParsedFile{Analyzer: a, Path: path, Kind: a.Kind(path), Deps: deps}
	}
	got := analyzer.Resolve([]analyzer.ParsedFile{
		parse("package-lock.json", "lock-workspaces/package-lock.json"),
		parse("package.json", "lock-workspaces/root-package.json"),
		parse("packages/a/package.json", "lock-workspaces/a-package.json"),
		parse("packages/b/package.json", "lock-workspaces/b-package.json"),
	})
	var sb strings.Builder
	for _, d := range got {
		if d.ManifestFile != "package-lock.json" {
			t.Errorf("unexpected entry from %s: %s", d.ManifestFile, d.Name)
		}
		sb.WriteString(d.Name + "=" + map[bool]string{true: "direct", false: "indirect"}[d.IsDirect] + " ")
	}
	if want := "left-pad=direct lodash=direct transitive=indirect "; sb.String() != want {
		t.Errorf("got %q, want %q", sb.String(), want)
	}
}

// Two importers depend on different versions of one package, and a dev
// dependency reaches the second version too: that version is still a
// production dependency of apps/b. Map iteration order must not matter, so
// the lockfile is parsed many times.
func TestPnpmImportersWithDifferentVersions(t *testing.T) {
	content := readFixture(t, "pnpm-v9-importers/pnpm-lock.yaml")
	want := []analyzer.ParsedDependency{
		internal("", "apps/a"), // the importers are workspaces
		internal("", "apps/b"),
		locked("debug", "4.3.4", false),
		locked("jest", "29.7.0", true),
		locked("ms", "2.0.0", false),
		locked("ms", "2.1.2", false),
		locked("ms", "2.1.3", false),
	}
	for i := 0; i < 30; i++ {
		got, err := NewAnalyzer().ParseDependencies(content, "pnpm-lock.yaml")
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("run %d:\ngot  %+v\nwant %+v", i, got, want)
		}
	}
}

// Workspace packages are linked, not installed from the registry: a sibling
// that a workspace depends on with a registry range must not be reported as
// an approximate registry dependency. A dependency really missing from the
// lockfile still is.
func TestWorkspaceLinksAreNotRegistryDependencies(t *testing.T) {
	a := NewAnalyzer()
	parse := func(path, fixture string) analyzer.ParsedFile {
		deps, err := a.ParseDependencies(readFixture(t, fixture), path)
		if err != nil {
			t.Fatal(err)
		}
		return analyzer.ParsedFile{Analyzer: a, Path: path, Kind: a.Kind(path), Deps: deps}
	}
	got := analyzer.Resolve([]analyzer.ParsedFile{
		parse("package-lock.json", "lock-workspace-links/package-lock.json"),
		parse("package.json", "lock-workspace-links/root-package.json"),
		parse("packages/web/package.json", "lock-workspace-links/web-package.json"),
		parse("packages/shared/package.json", "lock-workspace-links/shared-package.json"),
		// Not a workspace: it uses the published package of the same name.
		parse("examples/demo/package.json", "lock-workspace-links/demo-package.json"),
	})
	var lines []string
	for _, d := range got {
		lines = append(lines, fmt.Sprintf("%s %s@%s direct=%v resolved=%v dev=%v", d.ManifestFile, d.Name, d.CurrentVersion, d.IsDirect, d.Resolved, d.Dev))
	}
	want := []string{
		"examples/demo/package.json @mono/shared@1.0.0 direct=true resolved=false dev=false",
		"package-lock.json jest@29.7.0 direct=true resolved=true dev=true",
		"package-lock.json js-tokens@4.0.0 direct=false resolved=true dev=false",
		"package-lock.json lodash@4.17.15 direct=true resolved=true dev=false",
		"package-lock.json lodash@4.17.21 direct=true resolved=true dev=false",
		"package-lock.json loose-envify@1.4.0 direct=false resolved=true dev=false",
		"package-lock.json react@18.2.0 direct=true resolved=true dev=false",
		"package-lock.json typescript@5.4.5 direct=true resolved=true dev=true",
		"packages/web/package.json dayjs@1.11.0 direct=true resolved=false dev=false",
	}
	if strings.Join(lines, "\n") != strings.Join(want, "\n") {
		t.Errorf("got:\n%s\nwant:\n%s", strings.Join(lines, "\n"), strings.Join(want, "\n"))
	}
}

// pnpm and yarn berry record workspace siblings too: as link: versions in
// the importers and as workspace: resolutions.
func TestLinkedPackagesFromYAMLLockfiles(t *testing.T) {
	a := NewAnalyzer()
	for _, tc := range []struct{ file, fixture string }{
		{"pnpm-lock.yaml", "pnpm-v9/pnpm-lock.yaml"},
		{"yarn.lock", "yarn-berry/yarn.lock"},
	} {
		t.Run(tc.file, func(t *testing.T) {
			lockDeps, err := a.ParseDependencies(readFixture(t, tc.fixture), tc.file)
			if err != nil {
				t.Fatal(err)
			}
			got := analyzer.Resolve([]analyzer.ParsedFile{
				{Analyzer: a, Path: tc.file, Kind: analyzer.KindLockfile, Deps: lockDeps},
				// The root manifest: the lockfile's directory is a workspace.
				{Analyzer: a, Path: "package.json", Kind: analyzer.KindManifest, Deps: []analyzer.ParsedDependency{
					{Name: "shared", CurrentVersion: "1.0.0", IsDirect: true},
				}},
			})
			for _, d := range got {
				if d.Name == "shared" {
					t.Errorf("workspace package reported: %+v", d)
				}
			}
		})
	}
}

// A library's own name is not hidden: its root is a workspace, but an
// example outside the workspaces depends on the published package.
func TestBerryRootWorkspaceIsNotInternal(t *testing.T) {
	a := NewAnalyzer()
	lockDeps, err := a.ParseDependencies(readFixture(t, "yarn-berry-library/yarn.lock"), "yarn.lock")
	if err != nil {
		t.Fatal(err)
	}
	got := analyzer.Resolve([]analyzer.ParsedFile{
		{Analyzer: a, Path: "yarn.lock", Kind: analyzer.KindLockfile, Deps: lockDeps},
		{Analyzer: a, Path: "package.json", Kind: analyzer.KindManifest, Deps: []analyzer.ParsedDependency{
			{Name: "express", CurrentVersion: "4.18.0", IsDirect: true},
		}},
		{Analyzer: a, Path: "examples/demo/package.json", Kind: analyzer.KindManifest, Deps: []analyzer.ParsedDependency{
			{Name: "mylib", CurrentVersion: "1.0.0", IsDirect: true},
		}},
	})
	var lines []string
	for _, d := range got {
		lines = append(lines, d.ManifestFile+" "+d.Name+"@"+d.CurrentVersion)
	}
	want := "examples/demo/package.json mylib@1.0.0, yarn.lock express@4.18.2"
	if strings.Join(lines, ", ") != want {
		t.Errorf("got %s, want %s", strings.Join(lines, ", "), want)
	}
}
