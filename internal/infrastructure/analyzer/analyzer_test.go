package analyzer

import (
	"context"
	"path"
	"strings"
	"testing"

	"github.com/orchesta/orbit/internal/domain/entity"
)

func TestMatchesManifest(t *testing.T) {
	tests := []struct {
		path, manifest string
		want           bool
	}{
		// Exact file names match the whole path or the last path element.
		{"package.json", "package.json", true},
		{"web/package.json", "package.json", true},
		{"a/b/c/package.json", "package.json", true},
		{"mypackage.json", "package.json", false},
		{"web/mypackage.json", "package.json", false},
		{"package.json.bak", "package.json", false},
		{"package.json/readme.md", "package.json", false},
		{"Package.json", "package.json", false}, // exact names are case-sensitive
		{"src/Pipfile", "Pipfile", true},
		{"src/pipfile", "Pipfile", false},
		{"", "package.json", false},

		// A leading '.' means a case-insensitive suffix.
		{"App.csproj", ".csproj", true},
		{"src/App/App.csproj", ".csproj", true},
		{"src/App/App.CSPROJ", ".csproj", true},
		{".csproj", ".csproj", true},
		{"src/App/App.csproj.user", ".csproj", false},
		{"src/App/App.fsproj", ".csproj", false},
	}
	for _, tt := range tests {
		if got := matchesManifest(tt.path, tt.manifest); got != tt.want {
			t.Errorf("matchesManifest(%q, %q) = %v, want %v", tt.path, tt.manifest, got, tt.want)
		}
	}
}

// manifestAnalyzer is a minimal Analyzer for registry tests.
type manifestAnalyzer struct {
	eco       entity.Ecosystem
	manifests []string
}

func (a manifestAnalyzer) Ecosystem() entity.Ecosystem { return a.eco }
func (a manifestAnalyzer) DetectManifests() []string   { return a.manifests }
func (a manifestAnalyzer) Kind(string) ManifestKind    { return KindManifest }
func (a manifestAnalyzer) ParseDependencies([]byte, string) ([]ParsedDependency, error) {
	return nil, nil
}
func (a manifestAnalyzer) GetLatestVersion(context.Context, string) (string, error) { return "", nil }

func TestDetectManifestFiles(t *testing.T) {
	r := NewRegistry()
	r.Register(manifestAnalyzer{eco: entity.EcosystemNpm, manifests: []string{"package.json"}})
	r.Register(manifestAnalyzer{eco: entity.EcosystemNuGet, manifests: []string{".csproj", "packages.config"}})

	tests := []struct {
		path string
		want []entity.Ecosystem
	}{
		{"package.json", []entity.Ecosystem{entity.EcosystemNpm}},
		{"web/app/package.json", []entity.Ecosystem{entity.EcosystemNpm}},
		{"src/App/App.csproj", []entity.Ecosystem{entity.EcosystemNuGet}},
		{"src/App/packages.config", []entity.Ecosystem{entity.EcosystemNuGet}},
		{"README.md", nil},
		{"src/App/App.cs", nil},
	}
	for _, tt := range tests {
		matches := r.DetectManifestFiles(tt.path)
		if len(matches) != len(tt.want) {
			t.Errorf("DetectManifestFiles(%q) returned %d matches, want %d", tt.path, len(matches), len(tt.want))
			continue
		}
		for i, m := range matches {
			if m.ManifestPath != tt.path {
				t.Errorf("DetectManifestFiles(%q)[%d].ManifestPath = %q", tt.path, i, m.ManifestPath)
			}
			if m.Analyzer.Ecosystem() != tt.want[i] {
				t.Errorf("DetectManifestFiles(%q)[%d] ecosystem = %s, want %s", tt.path, i, m.Analyzer.Ecosystem(), tt.want[i])
			}
		}
	}
}

func TestDetectManifestFilesMatchesEveryAnalyzer(t *testing.T) {
	r := NewRegistry()
	r.Register(manifestAnalyzer{eco: entity.EcosystemNpm, manifests: []string{"shared.json"}})
	r.Register(manifestAnalyzer{eco: entity.EcosystemPyPI, manifests: []string{"shared.json"}})

	matches := r.DetectManifestFiles("x/shared.json")
	got := map[entity.Ecosystem]bool{}
	for _, m := range matches {
		got[m.Analyzer.Ecosystem()] = true
	}
	if len(matches) != 2 || !got[entity.EcosystemNpm] || !got[entity.EcosystemPyPI] {
		t.Errorf("DetectManifestFiles matched %v, want npm and PyPI once each", got)
	}
}

// patternAnalyzer matches by name list and by MatchesFile.
type patternAnalyzer struct{ manifestAnalyzer }

func (patternAnalyzer) MatchesFile(p string) bool { return strings.HasPrefix(path.Base(p), "req") }

func TestDetectManifestFilesMatchesOncePerAnalyzer(t *testing.T) {
	r := NewRegistry()
	r.Register(patternAnalyzer{manifestAnalyzer{eco: entity.EcosystemPyPI, manifests: []string{"requirements.txt", "requirements.txt", ".txt"}}})
	if got := len(r.DetectManifestFiles("x/requirements.txt")); got != 1 {
		t.Errorf("matches = %d, want 1", got)
	}
	if got := len(r.DetectManifestFiles("x/other.txt")); got != 1 {
		t.Errorf("suffix matches = %d, want 1", got)
	}
	if got := len(r.DetectManifestFiles("x/other.md")); got != 0 {
		t.Errorf("matches = %d, want 0", got)
	}
}
