package npm

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"sort"
	"time"

	"github.com/orchesta/orbit/internal/domain/entity"
	"github.com/orchesta/orbit/internal/infrastructure/analyzer"
	"github.com/orchesta/orbit/internal/infrastructure/httpclient"
)

// Ensure interface compliance.
var (
	_ analyzer.Analyzer      = (*Analyzer)(nil)
	_ analyzer.OptionsParser = (*Analyzer)(nil)
)

// Analyzer implements the analyzer.Analyzer interface for npm packages.
type Analyzer struct {
	httpClient  *http.Client
	registryURL string
}

// NewAnalyzer creates a new npm analyzer.
func NewAnalyzer() *Analyzer {
	return &Analyzer{
		httpClient:  httpclient.New(15 * time.Second),
		registryURL: "https://registry.npmjs.org",
	}
}

func (a *Analyzer) Ecosystem() entity.Ecosystem {
	return entity.EcosystemNpm
}

func (a *Analyzer) DetectManifests() []string {
	return []string{"package.json", "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml"}
}

// Kind reports the lockfiles as such and package.json as a manifest.
func (a *Analyzer) Kind(manifestPath string) analyzer.ManifestKind {
	if isLockfile(manifestPath) {
		return analyzer.KindLockfile
	}
	return analyzer.KindManifest
}

// packageJSON represents the structure of a package.json file.
type packageJSON struct {
	Dependencies         map[string]string `json:"dependencies"`
	DevDependencies      map[string]string `json:"devDependencies"`
	PeerDependencies     map[string]string `json:"peerDependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
}

// ParseDependencies parses package.json or, by file name, one of the
// lockfiles. Manifest entries are direct; lockfile entries are not marked,
// since Resolve derives directness from the package.json files they cover.
func (a *Analyzer) ParseDependencies(content []byte, manifestPath string) ([]analyzer.ParsedDependency, error) {
	deps, _, err := a.ParseWithOptions(content, manifestPath, analyzer.ParseOptions{})
	return deps, err
}

// ParseWithOptions is ParseDependencies with options. Only package-lock.json
// and npm-shrinkwrap.json use them, and only they warn: when their graph is
// too large to record Via (see lockVia).
func (a *Analyzer) ParseWithOptions(content []byte, manifestPath string, opts analyzer.ParseOptions) ([]analyzer.ParsedDependency, []string, error) {
	var deps []analyzer.ParsedDependency
	var err error
	switch path.Base(manifestPath) {
	case "package-lock.json", "npm-shrinkwrap.json":
		return parsePackageLock(content, opts)
	case "yarn.lock":
		deps, err = parseYarnLock(content)
	case "pnpm-lock.yaml":
		deps, err = parsePnpmLock(content)
	default:
		deps, err = parsePackageJSON(content)
	}
	return deps, nil, err
}

// parsePackageJSON reads the dependencies a package.json declares.
func parsePackageJSON(content []byte) ([]analyzer.ParsedDependency, error) {
	var pkg packageJSON
	if err := json.Unmarshal(content, &pkg); err != nil {
		return nil, fmt.Errorf("failed to parse package.json: %w", err)
	}

	var deps []analyzer.ParsedDependency
	for _, section := range []struct {
		entries map[string]string
		dev     bool
	}{
		{pkg.Dependencies, false},
		{pkg.DevDependencies, true},
		{pkg.PeerDependencies, false},
		{pkg.OptionalDependencies, false},
	} {
		for name, version := range section.entries {
			if real, v, ok := aliasTarget(version); ok {
				name, version = real, v // an alias: the real package is what gets installed
			}
			if !isRegistryVersion(version) {
				continue
			}
			deps = append(deps, analyzer.ParsedDependency{
				Name:           name,
				CurrentVersion: analyzer.CleanVersion(version),
				IsDirect:       true,
				Dev:            section.dev,
			})
		}
	}

	// Sort for consistent output
	sort.Slice(deps, func(i, j int) bool {
		if deps[i].Name != deps[j].Name {
			return deps[i].Name < deps[j].Name
		}
		return deps[i].CurrentVersion < deps[j].CurrentVersion
	})

	return deps, nil
}

// registryResponse represents the npm registry response.
type registryResponse struct {
	DistTags struct {
		Latest string `json:"latest"`
	} `json:"dist-tags"`
}

func (a *Analyzer) GetLatestVersion(ctx context.Context, packageName string) (string, error) {
	reqURL := a.registryURL + "/" + url.PathEscape(packageName)

	req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to query npm registry: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return "", fmt.Errorf("package %s not found on npm", packageName)
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("npm registry error (status %d): %s", resp.StatusCode, string(body))
	}

	var result registryResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("failed to decode registry response: %w", err)
	}

	return result.DistTags.Latest, nil
}
