package golang

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/orchesta/orbit/internal/infrastructure/analyzer"
)

const sampleGoMod = `module modulekit.io/app

go 1.22

toolchain go1.22.3

require golang.org/x/text v0.14.0

require (
	github.com/stretchr/testify v1.9.0 // indirect
	go.uber.org/zap v1.27.0
	golang.org/x/net v0.20.0
	google.golang.org/grpc v1.62.0
	gopkg.in/yaml.v3 v3.0.1
	modernc.org/sqlite v1.29.0
	modulekit.io/lib v0.1.0
	example.com/local v1.0.0
	example.com/forked v1.2.0
)

replace example.com/local => ../local

replace example.com/forked v1.2.0 => github.com/me/forked v1.2.1
`

func TestParseDependencies(t *testing.T) {
	got, err := NewAnalyzer().ParseDependencies([]byte(sampleGoMod), "go.mod")
	if err != nil {
		t.Fatal(err)
	}
	want := []analyzer.ParsedDependency{
		{Name: "github.com/me/forked", CurrentVersion: "1.2.1", IsDirect: true},
		{Name: "github.com/stretchr/testify", CurrentVersion: "1.9.0", IsDirect: false},
		{Name: "go.uber.org/zap", CurrentVersion: "1.27.0", IsDirect: true},
		{Name: "golang.org/x/net", CurrentVersion: "0.20.0", IsDirect: true},
		{Name: "golang.org/x/text", CurrentVersion: "0.14.0", IsDirect: true},
		{Name: "google.golang.org/grpc", CurrentVersion: "1.62.0", IsDirect: true},
		{Name: "gopkg.in/yaml.v3", CurrentVersion: "3.0.1", IsDirect: true},
		{Name: "modernc.org/sqlite", CurrentVersion: "1.29.0", IsDirect: true},
		{Name: "modulekit.io/lib", CurrentVersion: "0.1.0", IsDirect: true},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ParseDependencies =\n%+v\nwant\n%+v", got, want)
	}
}

func TestParseDependenciesRejectsMalformedGoMod(t *testing.T) {
	if _, err := NewAnalyzer().ParseDependencies([]byte("module x\nrequire (\n\tfoo\n"), "go.mod"); err == nil {
		t.Fatal("expected a parse error")
	}
}

func TestGetLatestVersionEscapesModulePath(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.EscapedPath()
		_, _ = w.Write([]byte("v1.3.0\nv1.4.0\n"))
	}))
	defer srv.Close()

	a := NewAnalyzer()
	a.proxyURL = srv.URL
	if _, err := a.GetLatestVersion(context.Background(), "github.com/BurntSushi/toml"); err != nil {
		t.Fatal(err)
	}
	if gotPath != "/github.com/!burnt!sushi/toml/@v/list" {
		t.Fatalf("path = %q", gotPath)
	}
}

func TestGetLatestVersionRejectsInvalidModulePath(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))
	defer srv.Close()

	a := NewAnalyzer()
	a.proxyURL = srv.URL
	if _, err := a.GetLatestVersion(context.Background(), "../../etc"); err == nil || called {
		t.Fatalf("err=%v called=%v; invalid paths must fail before any request", err, called)
	}
}

func latestFor(t *testing.T, list string) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(list))
	}))
	defer srv.Close()

	a := NewAnalyzer()
	a.proxyURL = srv.URL
	got, err := a.GetLatestVersion(context.Background(), "example.com/m")
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func TestGetLatestVersionSortsBySemver(t *testing.T) {
	if got := latestFor(t, "v1.9.0\nv1.10.0\n"); got != "1.10.0" {
		t.Fatalf("got %q, want 1.10.0", got)
	}
}

func TestGetLatestVersionSkipsPrereleases(t *testing.T) {
	if got := latestFor(t, "v1.0.0\nv2.0.0-rc1\n"); got != "1.0.0" {
		t.Fatalf("got %q, want 1.0.0", got)
	}
}

func TestGetLatestVersionFallsBackToLatestPrerelease(t *testing.T) {
	if got := latestFor(t, "v2.0.0-rc1\nv2.0.0-rc2\nv2.0.0-beta\n"); got != "2.0.0-rc2" {
		t.Fatalf("got %q, want 2.0.0-rc2", got)
	}
}
