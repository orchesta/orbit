package pip

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/aligoren/orbit/internal/infrastructure/analyzer"
)

func readFixture(t *testing.T, rel string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", filepath.FromSlash(rel)))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func locked(name, version string, dev bool) analyzer.ParsedDependency {
	return analyzer.ParsedDependency{Name: name, CurrentVersion: version, Resolved: true, Dev: dev}
}

func TestParseLockfiles(t *testing.T) {
	tests := []struct {
		fixture string
		path    string
		want    []analyzer.ParsedDependency
	}{
		{"poetry-old/poetry.lock", "poetry.lock", []analyzer.ParsedDependency{
			locked("pytest", "7.4.0", true),
			locked("requests", "2.31.0", false),
			locked("typing-extensions", "4.8.0", false),
		}},
		{"poetry-new/poetry.lock", "svc/poetry.lock", []analyzer.ParsedDependency{
			locked("certifi", "2023.7.22", false), // in main and dev
			locked("private", "1.0.0", false),     // custom registry stays
			locked("pytest", "7.4.0", true),
			locked("requests", "2.31.0", false),
		}},
		{"uv/uv.lock", "uv.lock", []analyzer.ParsedDependency{
			locked("requests", "2.31.0", false),
			locked("typing-extensions", "4.8.0", false),
		}},
		{"pipfile-lock/Pipfile.lock", "Pipfile.lock", []analyzer.ParsedDependency{
			locked("flask-cors", "4.0.0", false),
			locked("pytest", "7.4.0", true),
			locked("requests", "2.31.0", false),
		}},
	}
	a := NewAnalyzer()
	for _, tt := range tests {
		t.Run(tt.fixture, func(t *testing.T) {
			if got := a.Kind(tt.path); got != analyzer.KindLockfile {
				t.Fatalf("Kind = %v, want KindLockfile", got)
			}
			got, err := a.ParseDependencies(readFixture(t, tt.fixture), tt.path)
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
	for _, name := range []string{"poetry.lock", "uv.lock", "Pipfile.lock", "pyproject.toml"} {
		content := "[[package"
		if name == "Pipfile.lock" {
			content = "{ not valid"
		}
		if _, err := a.ParseDependencies([]byte(content), "sub/"+name); err == nil {
			t.Errorf("%s: want an error for malformed content", name)
		}
	}
}

func TestDetectsLockfilesAndRequirementsFiles(t *testing.T) {
	a := NewAnalyzer()
	want := map[string]analyzer.ManifestKind{
		"requirements.txt":     analyzer.KindManifest,
		"requirements-dev.txt": analyzer.KindManifest,
		"pyproject.toml":       analyzer.KindManifest,
		"Pipfile":              analyzer.KindManifest,
		"poetry.lock":          analyzer.KindLockfile,
		"uv.lock":              analyzer.KindLockfile,
		"Pipfile.lock":         analyzer.KindLockfile,
	}
	for name, kind := range want {
		if got := a.Kind("svc/" + name); got != kind {
			t.Errorf("Kind(%s) = %v, want %v", name, got, kind)
		}
	}

	r := analyzer.NewRegistry()
	r.Register(a)
	for path, matches := range map[string]bool{
		"requirements.txt":              true,
		"svc/requirements-dev.txt":      true,
		"svc/requirements_test.txt":     true,
		"svc/dev-requirements.txt":      true,
		"svc/Requirements-Dev.TXT":      true,
		"svc/devops-requirements.txt":   true,
		"svc/my_requirements_notes.txt": false,
		"svc/requirements.in":           false,
		"svc/notes.txt":                 false,
		"poetry.lock":                   true,
		"a/b/uv.lock":                   true,
		"Pipfile.lock":                  true,
		"Pipfile":                       true,
		"pyproject.toml":                true,
		"svc/requirements-dev.txt.orig": false,
	} {
		got := len(r.DetectManifestFiles(path))
		if want := map[bool]int{true: 1, false: 0}[matches]; got != want {
			t.Errorf("DetectManifestFiles(%q) = %d matches, want %d", path, got, want)
		}
	}
}

func TestNormalizeName(t *testing.T) {
	for in, want := range map[string]string{
		"Requests":          "requests",
		"typing_extensions": "typing-extensions",
		"zope.interface":    "zope-interface",
		"A__b..c--D":        "a-b-c-d",
		" Spaced ":          "spaced",
	} {
		if got := normalizeName(in); got != want {
			t.Errorf("normalizeName(%q) = %q, want %q", in, got, want)
		}
	}
}
