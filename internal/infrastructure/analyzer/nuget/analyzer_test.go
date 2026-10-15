package nuget

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/aligoren/orbit/internal/infrastructure/analyzer"
)

func TestGetLatestVersionEscapesName(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.EscapedPath()
		_, _ = w.Write([]byte(`{"versions":["1.0.0","2.0.0"]}`))
	}))
	defer srv.Close()

	a := NewAnalyzer()
	a.registryURL = srv.URL
	v, err := a.GetLatestVersion(context.Background(), "Evil/../X")
	if err != nil || v != "2.0.0" {
		t.Fatalf("GetLatestVersion = %q, %v", v, err)
	}
	if gotPath != "/evil%2F..%2Fx/index.json" {
		t.Fatalf("path = %q", gotPath)
	}
}

func readFixture(t *testing.T, rel string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", filepath.FromSlash(rel)))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestParsePackagesLock(t *testing.T) {
	got, err := NewAnalyzer().ParseDependencies(readFixture(t, "lock/packages.lock.json"), "src/App/packages.lock.json")
	if err != nil {
		t.Fatal(err)
	}
	want := []analyzer.ParsedDependency{
		{Name: "Newtonsoft.Json", CurrentVersion: "13.0.3", IsDirect: true, Resolved: true},
		{Name: "Serilog", CurrentVersion: "3.1.1", Resolved: true},
		{Name: "System.Memory", CurrentVersion: "4.5.5", Resolved: true},
		{Name: "System.Memory", CurrentVersion: "4.5.6", Resolved: true},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v\nwant %+v", got, want)
	}
}

func TestParsePackagesLockInvalid(t *testing.T) {
	if _, err := NewAnalyzer().ParseDependencies([]byte("{nope"), "packages.lock.json"); err == nil {
		t.Fatal("expected an error")
	}
}

func TestKindsAndMatching(t *testing.T) {
	a := NewAnalyzer()
	for path, want := range map[string]analyzer.ManifestKind{
		"packages.lock.json":           analyzer.KindLockfile,
		"src/App/packages.lock.json":   analyzer.KindLockfile,
		"Directory.Packages.props":     analyzer.KindVersions,
		"src/Directory.Packages.props": analyzer.KindVersions,
		"App.csproj":                   analyzer.KindManifest,
		"packages.config":              analyzer.KindManifest,
	} {
		if got := a.Kind(path); got != want {
			t.Errorf("Kind(%q) = %v, want %v", path, got, want)
		}
	}
	r := analyzer.NewRegistry()
	r.Register(a)
	if len(r.DetectManifestFiles("src/App/packages.lock.json")) != 1 {
		t.Error("packages.lock.json is not detected")
	}
}

func TestParseCentralVersions(t *testing.T) {
	got, err := NewAnalyzer().ParseDependencies(readFixture(t, "central/Directory.Packages.props"), "Directory.Packages.props")
	if err != nil {
		t.Fatal(err)
	}
	want := []analyzer.ParsedDependency{
		{Name: "Newtonsoft.Json", CurrentVersion: "13.0.3"},
		{Name: "Polly", CurrentVersion: "8.*"},
		{Name: "Serilog", CurrentVersion: "3.1.1"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v\nwant %+v", got, want)
	}
}

func TestParseCsprojVersionForms(t *testing.T) {
	got, err := NewAnalyzer().ParseDependencies(readFixture(t, "csproj/Mixed.csproj"), "Mixed.csproj")
	if err != nil {
		t.Fatal(err)
	}
	want := []analyzer.ParsedDependency{
		{Name: "Dapper", CurrentVersion: "2.1.35", IsDirect: true},
		{Name: "Polly", CurrentVersion: "[7.0,8.0)", IsDirect: true},
		{Name: "Serilog", CurrentVersion: "3.*", IsDirect: true},
		{Name: "xunit", CurrentVersion: "2.6.6", IsDirect: true},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v\nwant %+v", got, want)
	}
}

func TestParseCsprojVersionOverrideAndMissing(t *testing.T) {
	got, err := NewAnalyzer().ParseDependencies(readFixture(t, "central/App.csproj"), "App.csproj")
	if err != nil {
		t.Fatal(err)
	}
	want := []analyzer.ParsedDependency{
		{Name: "Humanizer", CurrentVersion: "2.14.1", IsDirect: true},
		{Name: "Newtonsoft.Json", IsDirect: true},
		{Name: "Polly", IsDirect: true},
		{Name: "Serilog", CurrentVersion: "3.0.0", IsDirect: true},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v\nwant %+v", got, want)
	}
}

// TestCentralVersionsEndToEnd parses the fixtures and resolves them as a scan does.
func TestCentralVersionsEndToEnd(t *testing.T) {
	a := NewAnalyzer()
	parse := func(fixture, path string) analyzer.ParsedFile {
		deps, err := a.ParseDependencies(readFixture(t, fixture), path)
		if err != nil {
			t.Fatal(err)
		}
		return analyzer.ParsedFile{Analyzer: a, Path: path, Kind: a.Kind(path), Deps: deps}
	}
	got := analyzer.Resolve([]analyzer.ParsedFile{
		parse("central/Directory.Packages.props", "Directory.Packages.props"),
		parse("central/App.csproj", "src/App/App.csproj"),
	})
	type row struct {
		file, name, version string
		resolved            bool
	}
	var rows []row
	for _, d := range got {
		rows = append(rows, row{d.ManifestFile, d.Name, d.CurrentVersion, d.Resolved})
	}
	want := []row{
		{"src/App/App.csproj", "Humanizer", "2.14.1", false},
		{"src/App/App.csproj", "Newtonsoft.Json", "13.0.3", false},
		{"src/App/App.csproj", "Polly", "8.*", false},
		{"src/App/App.csproj", "Serilog", "3.0.0", false},
	}
	if !reflect.DeepEqual(rows, want) {
		t.Fatalf("got %+v\nwant %+v", rows, want)
	}
}

func TestParsePackagesLockSpellingIsDeterministic(t *testing.T) {
	content := readFixture(t, "lock/packages.lock.json")
	for i := 0; i < 50; i++ {
		got, err := NewAnalyzer().ParseDependencies(content, "packages.lock.json")
		if err != nil {
			t.Fatal(err)
		}
		if got[0].Name != "Newtonsoft.Json" {
			t.Fatalf("run %d: spelling %q", i, got[0].Name)
		}
	}
}

// TestLockfileWithCentralVersionsEndToEnd resolves a lockfile, props file and
// csproj of one directory.
func TestLockfileWithCentralVersionsEndToEnd(t *testing.T) {
	a := NewAnalyzer()
	parse := func(fixture, path string) analyzer.ParsedFile {
		deps, err := a.ParseDependencies(readFixture(t, fixture), path)
		if err != nil {
			t.Fatal(err)
		}
		return analyzer.ParsedFile{Analyzer: a, Path: path, Kind: a.Kind(path), Deps: deps}
	}
	got := analyzer.Resolve([]analyzer.ParsedFile{
		parse("central/Directory.Packages.props", "Directory.Packages.props"),
		parse("lock/packages.lock.json", "packages.lock.json"),
		parse("central/App.csproj", "App.csproj"),
	})
	type row struct {
		file, name, version string
		direct, resolved    bool
	}
	var rows []row
	for _, d := range got {
		rows = append(rows, row{d.ManifestFile, d.Name, d.CurrentVersion, d.IsDirect, d.Resolved})
	}
	want := []row{
		{"App.csproj", "Humanizer", "2.14.1", true, false},
		{"App.csproj", "Polly", "8.*", true, false},
		{"packages.lock.json", "Newtonsoft.Json", "13.0.3", true, true},
		{"packages.lock.json", "Serilog", "3.1.1", false, true},
		{"packages.lock.json", "System.Memory", "4.5.5", false, true},
		{"packages.lock.json", "System.Memory", "4.5.6", false, true},
	}
	if !reflect.DeepEqual(rows, want) {
		t.Fatalf("got %+v\nwant %+v", rows, want)
	}
}
