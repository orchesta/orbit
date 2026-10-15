package analyzer

import (
	"context"
	"strings"

	"github.com/orchesta/orbit/internal/domain/entity"
)

// Analyzer defines the interface for ecosystem-specific package analyzers.
// Each supported ecosystem (npm, pip, NuGet, etc.) implements this interface.
type Analyzer interface {
	// Ecosystem returns the ecosystem this analyzer supports.
	Ecosystem() entity.Ecosystem

	// DetectManifests returns a list of known manifest filenames this analyzer handles.
	// These are used to filter discovered files in a repository.
	DetectManifests() []string

	// Kind tells whether a matched file declares dependencies (a manifest)
	// or pins their exact versions (a lockfile).
	Kind(manifestPath string) ManifestKind

	// ParseDependencies parses a manifest file and extracts dependencies.
	ParseDependencies(content []byte, manifestPath string) ([]ParsedDependency, error)

	// GetLatestVersion queries the package registry for the latest version.
	GetLatestVersion(ctx context.Context, packageName string) (string, error)
}

// ParsedDependency represents a dependency extracted from a manifest file.
type ParsedDependency struct {
	Name           string
	CurrentVersion string
	// IsDirect marks a dependency the project declares itself. Manifest
	// parsers set it. Lockfile parsers set it only if the format records
	// directness for every entry; otherwise they leave it false and Resolve
	// derives it from the covered manifests.
	IsDirect bool
	Resolved bool // version comes from a lockfile (exact), not a manifest range
	Dev      bool // development-only dependency, when the source says so
	// Internal marks a lockfile entry for a package of the project itself,
	// such as an npm workspace linked into node_modules; Resolve never
	// reports it. Dir is the package's directory relative to the lockfile's,
	// and Name is empty when only the directory is known. The lockfile's
	// directory and these directories are the project's workspaces: in their
	// manifests an Internal name is satisfied, so a sibling is not reported
	// as a registry dependency.
	Internal bool
	Dir      string
}

// ManifestKind tells Resolve how a matched file is used.
type ManifestKind int

const (
	KindManifest ManifestKind = iota // declares direct dependencies (package.json, *.csproj, ...)
	KindLockfile                     // pins exact versions (package-lock.json, poetry.lock, ...)
	// KindVersions supplies versions to the manifests below it without
	// declaring dependencies itself (NuGet's Directory.Packages.props). It is
	// never reported.
	KindVersions
)

// Registry holds all registered analyzers and provides lookup functionality.
type Registry struct {
	analyzers map[entity.Ecosystem]Analyzer
}

// NewRegistry creates a new analyzer registry.
func NewRegistry() *Registry {
	return &Registry{
		analyzers: make(map[entity.Ecosystem]Analyzer),
	}
}

// Register adds an analyzer to the registry.
func (r *Registry) Register(a Analyzer) {
	r.analyzers[a.Ecosystem()] = a
}

// Get returns the analyzer for the given ecosystem.
func (r *Registry) Get(ecosystem entity.Ecosystem) (Analyzer, bool) {
	a, ok := r.analyzers[ecosystem]
	return a, ok
}

// GetAll returns all registered analyzers.
func (r *Registry) GetAll() []Analyzer {
	result := make([]Analyzer, 0, len(r.analyzers))
	for _, a := range r.analyzers {
		result = append(result, a)
	}
	return result
}

// DetectManifestFiles checks if a file path matches any registered analyzer's manifest files.
// Returns the matching analyzer(s) and the manifest filename.
func (r *Registry) DetectManifestFiles(filePath string) []ManifestMatch {
	var matches []ManifestMatch
	for _, a := range r.analyzers {
		matched := false
		if fm, ok := a.(FileMatcher); ok {
			matched = fm.MatchesFile(filePath)
		}
		for _, manifest := range a.DetectManifests() {
			if matched {
				break
			}
			matched = matchesManifest(filePath, manifest)
		}
		if matched {
			// One match per analyzer, however many patterns hit.
			matches = append(matches, ManifestMatch{
				Analyzer:     a,
				ManifestPath: filePath,
			})
		}
	}
	return matches
}

// FileMatcher is implemented by analyzers that recognize manifests by more
// than the fixed names and suffixes of DetectManifests.
type FileMatcher interface {
	// MatchesFile reports whether the file at filePath is one of the
	// analyzer's manifests or lockfiles.
	MatchesFile(filePath string) bool
}

// ManifestMatch represents a match between a file and an analyzer.
type ManifestMatch struct {
	Analyzer     Analyzer
	ManifestPath string
}

// matchesManifest checks if a file path matches the manifest pattern.
func matchesManifest(filePath, manifest string) bool {
	// If manifest starts with '.', treat it as an extension suffix
	if strings.HasPrefix(manifest, ".") {
		return strings.HasSuffix(strings.ToLower(filePath), strings.ToLower(manifest))
	}

	// Otherwise, check exact match or path ending with /manifest
	if filePath == manifest {
		return true
	}
	if len(filePath) > len(manifest) && filePath[len(filePath)-len(manifest)-1] == '/' {
		return filePath[len(filePath)-len(manifest):] == manifest
	}
	return false
}
