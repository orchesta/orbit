package golang

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"golang.org/x/mod/modfile"
	"golang.org/x/mod/module"
	"golang.org/x/mod/semver"

	"github.com/orchesta/orbit/internal/domain/entity"
	"github.com/orchesta/orbit/internal/infrastructure/analyzer"
	"github.com/orchesta/orbit/internal/infrastructure/httpclient"
)

// Ensure interface compliance.
var _ analyzer.Analyzer = (*Analyzer)(nil)

// Analyzer implements the analyzer.Analyzer interface for Go modules.
type Analyzer struct {
	httpClient *http.Client
	proxyURL   string
}

// NewAnalyzer creates a new Go analyzer.
func NewAnalyzer() *Analyzer {
	return &Analyzer{
		httpClient: httpclient.New(15 * time.Second),
		proxyURL:   "https://proxy.golang.org",
	}
}

func (a *Analyzer) Ecosystem() entity.Ecosystem {
	return entity.EcosystemGo
}

func (a *Analyzer) DetectManifests() []string {
	return []string{"go.mod"}
}

// Kind reports every file this analyzer matches as a manifest.
func (a *Analyzer) Kind(string) analyzer.ManifestKind {
	return analyzer.KindManifest
}

func (a *Analyzer) ParseDependencies(content []byte, manifestPath string) ([]analyzer.ParsedDependency, error) {
	f, err := modfile.Parse(manifestPath, content, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to parse go.mod: %w", err)
	}

	// A replace without an old version applies to every version of the module.
	replacements := make(map[module.Version]module.Version, len(f.Replace))
	for _, r := range f.Replace {
		replacements[r.Old] = r.New
	}

	var deps []analyzer.ParsedDependency
	for _, req := range f.Require {
		mod := req.Mod
		if repl, ok := replacements[mod]; ok {
			mod = repl
		} else if repl, ok := replacements[module.Version{Path: mod.Path}]; ok {
			mod = repl
		}
		// Replaced by a local directory: there is no published version to check.
		if mod.Version == "" {
			continue
		}
		deps = append(deps, analyzer.ParsedDependency{
			Name:           mod.Path,
			CurrentVersion: strings.TrimPrefix(mod.Version, "v"),
			IsDirect:       !req.Indirect,
		})
	}

	sort.Slice(deps, func(i, j int) bool {
		return deps[i].Name < deps[j].Name
	})

	return deps, nil
}

func (a *Analyzer) GetLatestVersion(ctx context.Context, moduleName string) (string, error) {
	// The proxy protocol escapes upper-case letters as "!" + lower-case.
	escaped, err := module.EscapePath(moduleName)
	if err != nil {
		return "", fmt.Errorf("invalid module path %q: %w", moduleName, err)
	}
	reqURL := a.proxyURL + "/" + escaped + "/@v/list"

	req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
	if err != nil {
		return "", err
	}

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("proxy error: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	var stable, pre []string
	for _, v := range strings.Fields(string(body)) {
		if !semver.IsValid(v) {
			continue
		}
		if semver.Prerelease(v) != "" {
			pre = append(pre, v)
		} else {
			stable = append(stable, v)
		}
	}
	candidates := stable
	if len(candidates) == 0 {
		candidates = pre
	}
	if len(candidates) == 0 {
		return "", fmt.Errorf("no versions found")
	}

	// The proxy list is unordered; sort by semver precedence, not lexically.
	semver.Sort(candidates)
	latest := candidates[len(candidates)-1]

	return strings.TrimPrefix(latest, "v"), nil
}
