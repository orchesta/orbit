package nuget

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/orchesta/orbit/internal/domain/entity"
	"github.com/orchesta/orbit/internal/infrastructure/analyzer"
	"github.com/orchesta/orbit/internal/infrastructure/httpclient"
)

// Ensure interface compliance.
var _ analyzer.Analyzer = (*Analyzer)(nil)

// Analyzer implements the analyzer.Analyzer interface for NuGet packages.
//
// Known limitations: MSBuild element and attribute names are matched with the
// case used in the SDK documentation (PackageReference, Include, Version, ...);
// Update= items and Condition attributes are ignored, so a conditional
// reference is reported as if unconditional; properties such as $(Version)
// are not expanded and stay in the version as written. Duplicate names keep
// document order (stable sort); among duplicate PackageVersion entries the
// first in document order supplies the central version.
type Analyzer struct {
	httpClient  *http.Client
	registryURL string
}

// NewAnalyzer creates a new NuGet analyzer.
func NewAnalyzer() *Analyzer {
	return &Analyzer{
		httpClient:  httpclient.New(15 * time.Second),
		registryURL: "https://api.nuget.org/v3-flatcontainer",
	}
}

func (a *Analyzer) Ecosystem() entity.Ecosystem {
	return entity.EcosystemNuGet
}

func (a *Analyzer) DetectManifests() []string {
	return []string{".csproj", ".fsproj", ".vbproj", "packages.config", "Directory.Packages.props", "packages.lock.json"}
}

// Kind reports packages.lock.json as a lockfile, Directory.Packages.props as
// a source of versions, and everything else as a manifest.
func (a *Analyzer) Kind(manifestPath string) analyzer.ManifestKind {
	switch path.Base(manifestPath) {
	case "packages.lock.json":
		return analyzer.KindLockfile
	case "Directory.Packages.props":
		return analyzer.KindVersions
	}
	return analyzer.KindManifest
}

// csprojFile represents a simplified .csproj XML structure.
type csprojFile struct {
	XMLName    xml.Name          `xml:"Project"`
	ItemGroups []csprojItemGroup `xml:"ItemGroup"`
}

type csprojItemGroup struct {
	PackageReferences []packageReference `xml:"PackageReference"`
}

type packageReference struct {
	Include         string `xml:"Include,attr"`
	Version         string `xml:"Version,attr"`
	VersionOverride string `xml:"VersionOverride,attr"`
	VersionElement  string `xml:"Version"`
}

// version returns the version a reference sets itself: VersionOverride (central
// management), the Version attribute, or a <Version> child element.
func (r packageReference) version() string {
	for _, v := range []string{r.VersionOverride, r.Version, r.VersionElement} {
		if v = strings.TrimSpace(v); v != "" {
			return v
		}
	}
	return ""
}

// propsFile represents a Directory.Packages.props file.
type propsFile struct {
	XMLName    xml.Name `xml:"Project"`
	ItemGroups []struct {
		PackageVersions []struct {
			Include string `xml:"Include,attr"`
			Version string `xml:"Version,attr"`
		} `xml:"PackageVersion"`
	} `xml:"ItemGroup"`
}

// packagesConfig represents a packages.config XML structure.
type packagesConfig struct {
	XMLName  xml.Name       `xml:"packages"`
	Packages []packageEntry `xml:"package"`
}

type packageEntry struct {
	ID      string `xml:"id,attr"`
	Version string `xml:"version,attr"`
}

func (a *Analyzer) ParseDependencies(content []byte, manifestPath string) ([]analyzer.ParsedDependency, error) {
	lowerPath := strings.ToLower(manifestPath)

	if strings.HasSuffix(lowerPath, ".csproj") ||
		strings.HasSuffix(lowerPath, ".fsproj") ||
		strings.HasSuffix(lowerPath, ".vbproj") {
		return a.parseCsproj(content)
	}
	if path.Base(lowerPath) == "directory.packages.props" {
		return a.parseCentralVersions(content)
	}
	if path.Base(lowerPath) == "packages.lock.json" {
		return a.parsePackagesLock(content)
	}
	if strings.HasSuffix(lowerPath, "packages.config") {
		return a.parsePackagesConfig(content)
	}
	return nil, fmt.Errorf("unsupported manifest: %s", manifestPath)
}

func (a *Analyzer) parseCsproj(content []byte) ([]analyzer.ParsedDependency, error) {
	var proj csprojFile
	if err := xml.Unmarshal(content, &proj); err != nil {
		return nil, fmt.Errorf("failed to parse csproj: %w", err)
	}

	var deps []analyzer.ParsedDependency
	for _, ig := range proj.ItemGroups {
		for _, ref := range ig.PackageReferences {
			if ref.Include == "" {
				continue
			}
			deps = append(deps, analyzer.ParsedDependency{
				Name:           ref.Include,
				CurrentVersion: ref.version(),
				IsDirect:       true,
			})
		}
	}

	sort.SliceStable(deps, func(i, j int) bool {
		return deps[i].Name < deps[j].Name
	})

	return deps, nil
}

// parseCentralVersions reads the PackageVersion entries of a
// Directory.Packages.props. They are version declarations, not dependencies.
func (a *Analyzer) parseCentralVersions(content []byte) ([]analyzer.ParsedDependency, error) {
	var props propsFile
	if err := xml.Unmarshal(content, &props); err != nil {
		return nil, fmt.Errorf("failed to parse Directory.Packages.props: %w", err)
	}
	var deps []analyzer.ParsedDependency
	for _, ig := range props.ItemGroups {
		for _, pv := range ig.PackageVersions {
			if pv.Include == "" {
				continue
			}
			deps = append(deps, analyzer.ParsedDependency{Name: pv.Include, CurrentVersion: strings.TrimSpace(pv.Version)})
		}
	}
	sort.SliceStable(deps, func(i, j int) bool { return deps[i].Name < deps[j].Name })
	return deps, nil
}

// packagesLock represents packages.lock.json: target framework -> package -> entry.
type packagesLock struct {
	Dependencies map[string]map[string]struct {
		Type     string `json:"type"`
		Resolved string `json:"resolved"`
	} `json:"dependencies"`
}

// parsePackagesLock merges the target frameworks of a packages.lock.json. An
// entry is direct if any framework records it as Direct; Project entries
// (references to other projects) are skipped.
func (a *Analyzer) parsePackagesLock(content []byte) ([]analyzer.ParsedDependency, error) {
	var lock packagesLock
	if err := json.Unmarshal(content, &lock); err != nil {
		return nil, fmt.Errorf("failed to parse packages.lock.json: %w", err)
	}
	type key struct{ name, version string }
	index := make(map[key]int)
	var deps []analyzer.ParsedDependency
	frameworks := make([]string, 0, len(lock.Dependencies))
	for fw := range lock.Dependencies {
		frameworks = append(frameworks, fw)
	}
	sort.Strings(frameworks)
	for _, fw := range frameworks {
		for name, entry := range lock.Dependencies[fw] {
			if entry.Type == "Project" || entry.Resolved == "" {
				continue
			}
			direct := entry.Type == "Direct"
			k := key{strings.ToLower(name), entry.Resolved}
			if i, ok := index[k]; ok {
				deps[i].IsDirect = deps[i].IsDirect || direct
				if betterSpelling(name, deps[i].Name) {
					deps[i].Name = name
				}
				continue
			}
			index[k] = len(deps)
			deps = append(deps, analyzer.ParsedDependency{Name: name, CurrentVersion: entry.Resolved, IsDirect: direct, Resolved: true})
		}
	}
	// Entries are unique per lowercase name and version, so this order is total.
	sort.Slice(deps, func(i, j int) bool {
		if li, lj := strings.ToLower(deps[i].Name), strings.ToLower(deps[j].Name); li != lj {
			return li < lj
		}
		return deps[i].CurrentVersion < deps[j].CurrentVersion
	})
	return deps, nil
}

// betterSpelling reports whether a is the preferred spelling of a package ID
// over b: the one with more uppercase letters (the canonical "Newtonsoft.Json"
// over "newtonsoft.json"), then the lexicographically smaller one. The rule
// does not depend on the order the frameworks or entries are visited in.
func betterSpelling(a, b string) bool {
	upper := func(s string) int {
		n := 0
		for _, r := range s {
			if unicode.IsUpper(r) {
				n++
			}
		}
		return n
	}
	if ua, ub := upper(a), upper(b); ua != ub {
		return ua > ub
	}
	return a < b
}

func (a *Analyzer) parsePackagesConfig(content []byte) ([]analyzer.ParsedDependency, error) {
	var pkgs packagesConfig
	if err := xml.Unmarshal(content, &pkgs); err != nil {
		return nil, fmt.Errorf("failed to parse packages.config: %w", err)
	}

	var deps []analyzer.ParsedDependency
	for _, pkg := range pkgs.Packages {
		deps = append(deps, analyzer.ParsedDependency{
			Name:           pkg.ID,
			CurrentVersion: pkg.Version,
			IsDirect:       true,
		})
	}

	sort.SliceStable(deps, func(i, j int) bool {
		return deps[i].Name < deps[j].Name
	})

	return deps, nil
}

// nugetIndexResponse represents the NuGet API response for package versions.
type nugetIndexResponse struct {
	Versions []string `json:"versions"`
}

func (a *Analyzer) GetLatestVersion(ctx context.Context, packageName string) (string, error) {
	// NuGet API uses lowercase package names
	lowerName := strings.ToLower(packageName)
	reqURL := a.registryURL + "/" + url.PathEscape(lowerName) + "/index.json"

	req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to query NuGet: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return "", fmt.Errorf("package %s not found on NuGet", packageName)
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("NuGet error (status %d): %s", resp.StatusCode, string(body))
	}

	var result nugetIndexResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("failed to decode NuGet response: %w", err)
	}

	if len(result.Versions) == 0 {
		return "", fmt.Errorf("no versions found for %s", packageName)
	}

	// Filter out pre-release versions (those containing '-')
	var stableVersions []string
	for _, v := range result.Versions {
		if !strings.Contains(v, "-") {
			stableVersions = append(stableVersions, v)
		}
	}

	if len(stableVersions) > 0 {
		return stableVersions[len(stableVersions)-1], nil
	}

	// If no stable versions, return the latest pre-release
	return result.Versions[len(result.Versions)-1], nil
}
