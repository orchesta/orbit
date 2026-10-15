package analyzer

import (
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/orchesta/orbit/internal/domain/entity"
)

var (
	fakeNpm   = manifestAnalyzer{eco: entity.EcosystemNpm}
	fakePyPI  = manifestAnalyzer{eco: entity.EcosystemPyPI}
	fakeNuGet = manifestAnalyzer{eco: entity.EcosystemNuGet}
)

// manifest builds a parsed manifest whose entries are direct, as manifest
// parsers report them.
func manifest(a Analyzer, path string, deps ...ParsedDependency) ParsedFile {
	for i := range deps {
		deps[i].IsDirect = true
	}
	return ParsedFile{Analyzer: a, Path: path, Kind: KindManifest, Deps: deps}
}

// lockfile builds a parsed lockfile whose entries are resolved, as lockfile
// parsers report them.
func lockfile(a Analyzer, path string, deps ...ParsedDependency) ParsedFile {
	for i := range deps {
		deps[i].Resolved = true
	}
	return ParsedFile{Analyzer: a, Path: path, Kind: KindLockfile, Deps: deps}
}

func d(name, version string) ParsedDependency {
	return ParsedDependency{Name: name, CurrentVersion: version}
}

func directDep(name, version string) ParsedDependency {
	return ParsedDependency{Name: name, CurrentVersion: version, IsDirect: true}
}

func devDep(name, version string) ParsedDependency {
	return ParsedDependency{Name: name, CurrentVersion: version, Dev: true}
}

// pinnedDep is a manifest entry pinned to an exact version, which the
// manifest parser marks Resolved (requirements.txt name==X).
func pinnedDep(name, version string) ParsedDependency {
	return ParsedDependency{Name: name, CurrentVersion: version, Resolved: true}
}

// internalDep is a lockfile entry for a package of the project itself in
// dir, relative to the lockfile.
func internalDep(name, dir string) ParsedDependency {
	return ParsedDependency{Name: name, Internal: true, Dir: dir}
}

// want describes one expected result; flags is a set of "direct", "resolved"
// and "dev".
func want(eco entity.Ecosystem, file, name, version string, flags ...string) ResolvedDependency {
	r := ResolvedDependency{
		ParsedDependency: ParsedDependency{Name: name, CurrentVersion: version},
		Ecosystem:        eco,
		ManifestFile:     file,
	}
	for _, f := range flags {
		switch f {
		case "direct":
			r.IsDirect = true
		case "resolved":
			r.Resolved = true
		case "dev":
			r.Dev = true
		default:
			panic("unknown flag " + f)
		}
	}
	return r
}

const (
	npm   = entity.EcosystemNpm
	pypi  = entity.EcosystemPyPI
	nuget = entity.EcosystemNuGet
)

func TestResolve(t *testing.T) {
	tests := []struct {
		name  string
		files []ParsedFile
		want  []ResolvedDependency
	}{
		{
			name:  "no files",
			files: nil,
			want:  nil,
		},
		{
			name: "manifest only",
			files: []ParsedFile{
				manifest(fakeNpm, "package.json", d("express", "^4.18.0"), devDep("jest", "^29.0.0")),
			},
			want: []ResolvedDependency{
				want(npm, "package.json", "express", "^4.18.0", "direct"),
				want(npm, "package.json", "jest", "^29.0.0", "direct", "dev"),
			},
		},
		{
			name: "manifest only keeps one entry per name and version",
			files: []ParsedFile{
				manifest(fakeNpm, "package.json", d("left-pad", "1.3.0"), d("left-pad", "1.3.0"), d("left-pad", "^1.0.0")),
			},
			want: []ResolvedDependency{
				want(npm, "package.json", "left-pad", "1.3.0", "direct"),
				want(npm, "package.json", "left-pad", "^1.0.0", "direct"),
			},
		},
		{
			name: "manifest and lockfile in the same directory",
			files: []ParsedFile{
				manifest(fakeNpm, "package.json", d("express", "^4.18.0")),
				lockfile(fakeNpm, "package-lock.json", d("express", "4.18.2"), d("accepts", "1.3.8"), devDep("jest", "29.7.0")),
			},
			want: []ResolvedDependency{
				want(npm, "package-lock.json", "accepts", "1.3.8", "resolved"),
				want(npm, "package-lock.json", "express", "4.18.2", "direct", "resolved"),
				want(npm, "package-lock.json", "jest", "29.7.0", "resolved", "dev"),
			},
		},
		{
			name: "root lockfile covers workspace manifests",
			files: []ParsedFile{
				manifest(fakeNpm, "packages/a/package.json", d("react", "^18.0.0")),
				lockfile(fakeNpm, "package-lock.json", d("react", "18.2.0"), d("lodash", "4.17.21"), d("loose-envify", "1.4.0")),
				manifest(fakeNpm, "package.json"),
				manifest(fakeNpm, "packages/b/package.json", d("lodash", "^4.17.0"), d("react", "^18.2.0")),
			},
			want: []ResolvedDependency{
				want(npm, "package-lock.json", "lodash", "4.17.21", "direct", "resolved"),
				want(npm, "package-lock.json", "loose-envify", "1.4.0", "resolved"),
				want(npm, "package-lock.json", "react", "18.2.0", "direct", "resolved"),
			},
		},
		{
			name: "subdirectory with its own lockfile",
			files: []ParsedFile{
				manifest(fakeNpm, "package.json", d("express", "^4.18.0")),
				lockfile(fakeNpm, "package-lock.json", d("express", "4.18.2"), d("lodash", "4.17.21")),
				manifest(fakeNpm, "tools/package.json", d("lodash", "^4.17.0")),
				lockfile(fakeNpm, "tools/package-lock.json", d("lodash", "4.17.20"), d("chalk", "5.3.0")),
				manifest(fakeNpm, "tools/cli/package.json", d("chalk", "^5.0.0")),
			},
			want: []ResolvedDependency{
				// The tools manifests are covered by tools/package-lock.json
				// only, so lodash is transitive in the root lockfile.
				want(npm, "package-lock.json", "express", "4.18.2", "direct", "resolved"),
				want(npm, "package-lock.json", "lodash", "4.17.21", "resolved"),
				want(npm, "tools/package-lock.json", "chalk", "5.3.0", "direct", "resolved"),
				want(npm, "tools/package-lock.json", "lodash", "4.17.20", "direct", "resolved"),
			},
		},
		{
			name: "a lockfile does not cover a sibling directory sharing its prefix",
			files: []ParsedFile{
				lockfile(fakeNpm, "app/package-lock.json", d("react", "18.2.0")),
				manifest(fakeNpm, "app/package.json", d("react", "^18.0.0")),
				manifest(fakeNpm, "application/package.json", d("vue", "^3.0.0")),
			},
			want: []ResolvedDependency{
				want(npm, "app/package-lock.json", "react", "18.2.0", "direct", "resolved"),
				want(npm, "application/package.json", "vue", "^3.0.0", "direct"),
			},
		},
		{
			name: "manifest dependency missing from the lockfile",
			files: []ParsedFile{
				manifest(fakeNpm, "package.json", d("express", "^4.18.0"), d("newpkg", "^1.0.0")),
				lockfile(fakeNpm, "package-lock.json", d("express", "4.18.2")),
			},
			want: []ResolvedDependency{
				want(npm, "package-lock.json", "express", "4.18.2", "direct", "resolved"),
				want(npm, "package.json", "newpkg", "^1.0.0", "direct"),
			},
		},
		{
			name: "a lockfile that yielded nothing leaves its directory to the manifest",
			files: []ParsedFile{
				manifest(fakeNpm, "package.json", d("express", "^4.18.0")),
				lockfile(fakeNpm, "package-lock.json", d("express", "4.18.2"), d("chalk", "4.1.2")),
				manifest(fakeNpm, "tools/package.json", d("chalk", "^5.0.0")),
				lockfile(fakeNpm, "tools/package-lock.json"), // unreadable or broken
			},
			want: []ResolvedDependency{
				want(npm, "package-lock.json", "chalk", "4.1.2", "resolved"),
				want(npm, "package-lock.json", "express", "4.18.2", "direct", "resolved"),
				want(npm, "tools/package.json", "chalk", "^5.0.0", "direct"),
			},
		},
		{
			name: "an exact pin the lockfile does not have at that version is kept",
			files: []ParsedFile{
				manifest(fakePyPI, "requirements.txt",
					pinnedDep("urllib3", "1.26.5"),  // the lockfile has 2.0.7 only
					pinnedDep("requests", "2.31.0"), // the lockfile agrees
					d("flask", ">=2.0"),             // a range: the lockfile's version stands
				),
				lockfile(fakePyPI, "poetry.lock", d("urllib3", "2.0.7"), d("requests", "2.31.0"), d("flask", "3.0.0")),
			},
			want: []ResolvedDependency{
				want(pypi, "poetry.lock", "flask", "3.0.0", "direct", "resolved"),
				want(pypi, "poetry.lock", "requests", "2.31.0", "direct", "resolved"),
				want(pypi, "poetry.lock", "urllib3", "2.0.7", "direct", "resolved"),
				want(pypi, "requirements.txt", "urllib3", "1.26.5", "direct", "resolved"),
			},
		},
		{
			name: "a lockfile's internal packages are not reported and satisfy its workspaces' manifests",
			files: []ParsedFile{
				manifest(fakeNpm, "package.json", d("@mono/util", "^1.0.0")),
				manifest(fakeNpm, "packages/web/package.json", d("@mono/shared", "^1.0.0"), pinnedDep("@mono/util", "1.0.0")),
				// Not a workspace: it uses the published package.
				manifest(fakeNpm, "examples/demo/package.json", d("@mono/shared", "^1.0.0")),
				lockfile(fakeNpm, "package-lock.json",
					d("react", "18.2.0"),
					internalDep("@mono/shared", "packages/shared"),
					internalDep("@mono/util", "packages/util"),
					internalDep("", "packages/web"),
				),
			},
			want: []ResolvedDependency{
				want(npm, "examples/demo/package.json", "@mono/shared", "^1.0.0", "direct"),
				want(npm, "package-lock.json", "react", "18.2.0", "resolved"),
			},
		},
		{
			name: "two versions of the same package",
			files: []ParsedFile{
				manifest(fakeNpm, "package.json", d("lodash", "^4.17.21"), d("old-lib", "^1.0.0")),
				lockfile(fakeNpm, "package-lock.json",
					d("lodash", "4.17.21"),
					d("old-lib", "1.0.0"),
					d("lodash", "4.17.15"),
					devDep("lodash", "4.17.21"), // the same version again, nested
				),
			},
			want: []ResolvedDependency{
				// Both versions are named in the manifest; the lockfile does
				// not say which one the manifest asked for.
				want(npm, "package-lock.json", "lodash", "4.17.15", "direct", "resolved"),
				want(npm, "package-lock.json", "lodash", "4.17.21", "direct", "resolved"),
				want(npm, "package-lock.json", "old-lib", "1.0.0", "direct", "resolved"),
			},
		},
		{
			name: "duplicate entries are dev only when every entry is",
			files: []ParsedFile{
				lockfile(fakeNpm, "package-lock.json", devDep("a", "1.0.0"), devDep("a", "1.0.0"), devDep("b", "1.0.0"), d("b", "1.0.0")),
			},
			want: []ResolvedDependency{
				want(npm, "package-lock.json", "a", "1.0.0", "resolved", "dev"),
				want(npm, "package-lock.json", "b", "1.0.0", "resolved"),
			},
		},
		{
			name: "lockfile's own direct information wins",
			files: []ParsedFile{
				manifest(fakeNuGet, "src/App/App.csproj", d("Newtonsoft.Json", "13.0.1"), d("Microsoft.CSharp", "4.7.0"), d("Polly", "8.0.0")),
				lockfile(fakeNuGet, "src/App/packages.lock.json",
					directDep("Newtonsoft.Json", "13.0.3"),
					directDep("Serilog", "3.1.1"),
					d("Microsoft.CSharp", "4.7.0"),
				),
			},
			want: []ResolvedDependency{
				// Polly is not in the lockfile, so the manifest entry stays.
				want(nuget, "src/App/App.csproj", "Polly", "8.0.0", "direct"),
				want(nuget, "src/App/packages.lock.json", "Microsoft.CSharp", "4.7.0", "resolved"),
				want(nuget, "src/App/packages.lock.json", "Newtonsoft.Json", "13.0.3", "direct", "resolved"),
				want(nuget, "src/App/packages.lock.json", "Serilog", "3.1.1", "direct", "resolved"),
			},
		},
		{
			name: "two ecosystems in the same directory",
			files: []ParsedFile{
				manifest(fakePyPI, "requirements.txt", d("requests", "==2.31.0")),
				lockfile(fakeNpm, "package-lock.json", d("express", "4.18.2")),
				manifest(fakeNpm, "package.json", d("express", "^4.18.0")),
			},
			want: []ResolvedDependency{
				// An npm lockfile does not cover a PyPI manifest.
				want(pypi, "requirements.txt", "requests", "==2.31.0", "direct"),
				want(npm, "package-lock.json", "express", "4.18.2", "direct", "resolved"),
			},
		},
		{
			name: "names match the way the ecosystem compares them",
			files: []ParsedFile{
				manifest(fakePyPI, "pyproject.toml", d("Django", ">=4.2"), d("typing_extensions", ">=4.0"), d("zope.interface", "*")),
				lockfile(fakePyPI, "poetry.lock", d("django", "4.2.7"), d("typing-extensions", "4.8.0"), d("zope-interface", "6.1")),
				manifest(fakeNuGet, "App.csproj", d("newtonsoft.json", "13.0.1")),
				lockfile(fakeNuGet, "packages.lock.json", d("Newtonsoft.Json", "13.0.3")),
				manifest(fakeNpm, "package.json", d("React", "^18.0.0")),
				lockfile(fakeNpm, "package-lock.json", d("react", "18.2.0")),
			},
			want: []ResolvedDependency{
				want(nuget, "packages.lock.json", "Newtonsoft.Json", "13.0.3", "direct", "resolved"),
				want(pypi, "poetry.lock", "django", "4.2.7", "direct", "resolved"),
				want(pypi, "poetry.lock", "typing-extensions", "4.8.0", "direct", "resolved"),
				want(pypi, "poetry.lock", "zope-interface", "6.1", "direct", "resolved"),
				// npm names are case-sensitive: React is not react.
				want(npm, "package-lock.json", "react", "18.2.0", "resolved"),
				want(npm, "package.json", "React", "^18.0.0", "direct"),
			},
		},
		{
			name: "the most preferred lockfile in a directory wins",
			files: []ParsedFile{
				manifest(fakeNpm, "package.json", d("express", "^4.18.0"), d("newpkg", "^1.0.0")),
				lockfile(fakeNpm, "yarn.lock", d("express", "4.18.1")),
				lockfile(fakeNpm, "npm-shrinkwrap.json", d("express", "4.18.0")),
				lockfile(fakeNpm, "package-lock.json", d("express", "4.18.2")),
				lockfile(fakeNpm, "pnpm-lock.yaml", d("express", "4.17.0")),
			},
			want: []ResolvedDependency{
				want(npm, "package-lock.json", "express", "4.18.2", "direct", "resolved"),
				want(npm, "package.json", "newpkg", "^1.0.0", "direct"),
			},
		},
		{
			name: "a failed lockfile falls back to the next-ranked one",
			files: []ParsedFile{
				manifest(fakeNpm, "package.json", d("express", "^4.18.0")),
				{Analyzer: fakeNpm, Path: "package-lock.json", Kind: KindLockfile, Failed: true},
				lockfile(fakeNpm, "yarn.lock", d("express", "4.18.1")),
			},
			want: []ResolvedDependency{
				want(npm, "yarn.lock", "express", "4.18.1", "direct", "resolved"),
			},
		},
		{
			name: "preference runs down the list and per ecosystem",
			files: []ParsedFile{
				lockfile(fakeNpm, "yarn.lock", d("a", "1.0.0")),
				lockfile(fakeNpm, "pnpm-lock.yaml", d("a", "2.0.0")),
				lockfile(fakePyPI, "Pipfile.lock", d("p", "1.0")),
				lockfile(fakePyPI, "uv.lock", d("p", "2.0")),
			},
			want: []ResolvedDependency{
				want(pypi, "uv.lock", "p", "2.0", "resolved"),
				want(npm, "pnpm-lock.yaml", "a", "2.0.0", "resolved"),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Resolve(tt.files)
			if len(got) == 0 && len(tt.want) == 0 {
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Resolve() mismatch\n got: %s\nwant: %s", format(got), format(tt.want))
			}
		})
	}
}

func format(rs []ResolvedDependency) string {
	var b strings.Builder
	for _, r := range rs {
		fmt.Fprintf(&b, "\n  %s %s %s@%s direct=%v resolved=%v dev=%v",
			r.Ecosystem, r.ManifestFile, r.Name, r.CurrentVersion, r.IsDirect, r.Resolved, r.Dev)
	}
	return b.String()
}

func TestResolveDoesNotModifyInput(t *testing.T) {
	files := []ParsedFile{
		manifest(fakeNpm, "package.json", d("express", "^4.18.0")),
		lockfile(fakeNpm, "package-lock.json", d("express", "4.18.2")),
	}
	Resolve(files)
	if files[1].Deps[0].IsDirect {
		t.Error("Resolve changed the lockfile's parsed dependency")
	}
}

// A manifest entry keeps the parser's Resolved (exact requirements.txt pins);
// a lockfile entry is always Resolved.
func TestResolveKeepsManifestResolved(t *testing.T) {
	pinned := ParsedDependency{Name: "django", CurrentVersion: "4.2.1", Resolved: true}
	ranged := ParsedDependency{Name: "requests", CurrentVersion: "2.0"}
	got := Resolve([]ParsedFile{manifest(fakePyPI, "requirements.txt", pinned, ranged)})
	exp := []ResolvedDependency{
		want(entity.EcosystemPyPI, "requirements.txt", "django", "4.2.1", "direct", "resolved"),
		want(entity.EcosystemPyPI, "requirements.txt", "requests", "2.0", "direct"),
	}
	if !reflect.DeepEqual(got, exp) {
		t.Errorf("got  %+v\nwant %+v", got, exp)
	}

	// A lockfile entry not flagged by its parser is still Resolved.
	unflagged := ParsedFile{Analyzer: fakePyPI, Path: "poetry.lock", Kind: KindLockfile, Deps: []ParsedDependency{d("a", "1.0")}}
	res := Resolve([]ParsedFile{unflagged})
	if len(res) != 1 || !res[0].Resolved {
		t.Errorf("lockfile entry not resolved: %+v", res)
	}
}

func TestResolveCentralVersions(t *testing.T) {
	props := func(path string, deps ...ParsedDependency) ParsedFile {
		return ParsedFile{Analyzer: fakeNuGet, Path: path, Kind: KindVersions, Deps: deps}
	}
	tests := []struct {
		name  string
		files []ParsedFile
		want  []ResolvedDependency
	}{
		{
			name: "versionless reference takes the version, props file is not reported",
			files: []ParsedFile{
				props("Directory.Packages.props", d("Serilog", "3.1.1")),
				manifest(fakeNuGet, "src/App/App.csproj", d("serilog", ""), d("Dapper", "2.1.35")),
			},
			want: []ResolvedDependency{
				want(nuget, "src/App/App.csproj", "Dapper", "2.1.35", "direct"),
				want(nuget, "src/App/App.csproj", "serilog", "3.1.1", "direct"),
			},
		},
		{
			name: "nearest ancestor wins",
			files: []ParsedFile{
				props("Directory.Packages.props", d("Serilog", "3.0.0")),
				props("src/Directory.Packages.props", d("Serilog", "3.1.1")),
				manifest(fakeNuGet, "src/App/App.csproj", d("Serilog", "")),
				manifest(fakeNuGet, "tools/Tool.csproj", d("Serilog", "")),
			},
			want: []ResolvedDependency{
				want(nuget, "src/App/App.csproj", "Serilog", "3.1.1", "direct"),
				want(nuget, "tools/Tool.csproj", "Serilog", "3.0.0", "direct"),
			},
		},
		{
			name: "nearest props without the package leaves the version empty",
			files: []ParsedFile{
				props("Directory.Packages.props", d("Serilog", "3.0.0")),
				props("src/Directory.Packages.props", d("Dapper", "2.1.35")),
				manifest(fakeNuGet, "src/App/App.csproj", d("Serilog", "")),
			},
			want: []ResolvedDependency{
				want(nuget, "src/App/App.csproj", "Serilog", "", "direct"),
			},
		},
		{
			name: "explicit version is kept and no props means no version",
			files: []ParsedFile{
				props("other/Directory.Packages.props", d("Serilog", "3.0.0")),
				manifest(fakeNuGet, "src/App/App.csproj", d("Serilog", ""), d("Dapper", "1.0.0")),
			},
			want: []ResolvedDependency{
				want(nuget, "src/App/App.csproj", "Dapper", "1.0.0", "direct"),
				want(nuget, "src/App/App.csproj", "Serilog", "", "direct"),
			},
		},
		{
			name: "other ecosystems are not touched",
			files: []ParsedFile{
				props("Directory.Packages.props", d("left-pad", "1.3.0")),
				manifest(fakeNpm, "package.json", d("left-pad", "")),
			},
			want: []ResolvedDependency{
				want(npm, "package.json", "left-pad", "", "direct"),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Resolve(tt.files); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("got  %+v\nwant %+v", got, tt.want)
			}
		})
	}
}

func TestResolveIgnoresFailedVersionsFile(t *testing.T) {
	files := []ParsedFile{
		{Analyzer: fakeNuGet, Path: "Directory.Packages.props", Kind: KindVersions, Failed: true},
		manifest(fakeNuGet, "App.csproj", d("Serilog", ""), d("Dapper", "2.1.35")),
	}
	want := []ResolvedDependency{
		want(nuget, "App.csproj", "Dapper", "2.1.35", "direct"),
		want(nuget, "App.csproj", "Serilog", "", "direct"),
	}
	if got := Resolve(files); !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v\nwant %+v", got, want)
	}
}

func TestMergeNames(t *testing.T) {
	if got := MergeNames(nil, nil); got != nil {
		t.Errorf("MergeNames(nil, nil) = %v, want nil", got)
	}
	a := []string{"mocha", "express"}
	got := MergeNames(a, []string{"express", "body-parser"})
	if want := []string{"body-parser", "express", "mocha"}; !slices.Equal(got, want) {
		t.Errorf("MergeNames = %v, want %v", got, want)
	}
	if !slices.Equal(a, []string{"mocha", "express"}) {
		t.Errorf("input modified: %v", a)
	}
}

// One package and version installed twice in one lockfile (two nested
// copies) is reported once, pulled in by every parent of either copy.
func TestResolveMergesVia(t *testing.T) {
	lock := lockfile(fakeNpm, "package-lock.json",
		ParsedDependency{Name: "qs", CurrentVersion: "6.7.0", Via: []string{"express"}},
		ParsedDependency{Name: "qs", CurrentVersion: "6.7.0", Via: []string{"body-parser", "express"}},
		ParsedDependency{Name: "ms", CurrentVersion: "2.0.0"},
	)
	via := map[string][]string{}
	for _, r := range Resolve([]ParsedFile{lock}) {
		via[r.Name+"@"+r.CurrentVersion] = r.Via
	}
	want := map[string][]string{"ms@2.0.0": nil, "qs@6.7.0": {"body-parser", "express"}}
	if !reflect.DeepEqual(via, want) {
		t.Fatalf("via = %v, want %v", via, want)
	}
}

func TestResolveKeepsLockfileLicenses(t *testing.T) {
	licensed := func(name, version, license string) ParsedDependency {
		return ParsedDependency{Name: name, CurrentVersion: version, License: license}
	}
	got := Resolve([]ParsedFile{
		manifest(fakeNpm, "package.json", d("a", "^1.0.0")),
		// The same entry twice, once without a license: the license is kept.
		lockfile(fakeNpm, "package-lock.json", d("a", "1.0.0"), licensed("a", "1.0.0", "MIT"), licensed("b", "2.0.0", "ISC")),
	})
	if len(got) != 2 {
		t.Fatalf("Resolve = %+v, want a and b", got)
	}
	if got[0].Name != "a" || got[0].License != "MIT" || !got[0].IsDirect {
		t.Errorf("a = %+v, want direct with MIT", got[0])
	}
	if got[1].Name != "b" || got[1].License != "ISC" {
		t.Errorf("b = %+v, want ISC", got[1])
	}
}
