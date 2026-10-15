package pip

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/orchesta/orbit/internal/domain/entity"
	"github.com/orchesta/orbit/internal/infrastructure/analyzer"
	"github.com/orchesta/orbit/internal/infrastructure/httpclient"
)

// Ensure interface compliance.
var _ analyzer.Analyzer = (*Analyzer)(nil)

// Analyzer implements the analyzer.Analyzer interface for Python/pip packages.
type Analyzer struct {
	httpClient  *http.Client
	registryURL string
}

// NewAnalyzer creates a new pip analyzer.
func NewAnalyzer() *Analyzer {
	return &Analyzer{
		httpClient:  httpclient.New(15 * time.Second),
		registryURL: "https://pypi.org",
	}
}

func (a *Analyzer) Ecosystem() entity.Ecosystem {
	return entity.EcosystemPyPI
}

func (a *Analyzer) DetectManifests() []string {
	return []string{
		"pyproject.toml", "Pipfile", "poetry.lock", "uv.lock", "Pipfile.lock",
	}
}

// MatchesFile reports whether a path is a requirements file; the other files
// are matched by DetectManifests.
func (a *Analyzer) MatchesFile(filePath string) bool {
	return isRequirementsFile(path.Base(filePath))
}

// Kind reports the lockfiles as such and everything else as a manifest.
func (a *Analyzer) Kind(manifestPath string) analyzer.ManifestKind {
	switch path.Base(manifestPath) {
	case "poetry.lock", "uv.lock", "Pipfile.lock":
		return analyzer.KindLockfile
	}
	return analyzer.KindManifest
}

// nameTokens splits a file name, without its extension, into lowercase
// tokens separated by '-', '_' and '.'.
func nameTokens(base string) []string {
	base = strings.ToLower(base)
	base = strings.TrimSuffix(base, ".txt")
	return strings.FieldsFunc(base, func(r rune) bool { return r == '-' || r == '_' || r == '.' })
}

// isRequirementsFile reports whether a file name is a requirements file: a
// .txt file whose first or last name token is "requirements"
// (requirements.txt, requirements-dev.txt, dev-requirements.txt).
func isRequirementsFile(base string) bool {
	if !strings.HasSuffix(strings.ToLower(base), ".txt") {
		return false
	}
	tokens := nameTokens(base)
	return len(tokens) > 0 && (tokens[0] == "requirements" || tokens[len(tokens)-1] == "requirements")
}

// devTokens are the name tokens that mark development-only dependencies.
var devTokens = []string{"dev", "develop", "development", "test", "tests", "testing", "lint", "doc", "docs"}

// isDevRequirementsFile reports whether a requirements file lists
// development-only dependencies, by whole name tokens: requirements-dev.txt
// and requirements_test.txt do, requirements-docker.txt does not.
func isDevRequirementsFile(base string) bool {
	return slices.ContainsFunc(nameTokens(base), func(t string) bool { return slices.Contains(devTokens, t) })
}

// ParseDependencies parses a manifest or lockfile, chosen by file name.
func (a *Analyzer) ParseDependencies(content []byte, manifestPath string) ([]analyzer.ParsedDependency, error) {
	base := path.Base(manifestPath)
	switch {
	case base == "poetry.lock":
		return parsePoetryLock(content)
	case base == "uv.lock":
		return parseUVLock(content)
	case base == "Pipfile.lock":
		return parsePipfileLock(content)
	case base == "pyproject.toml":
		return parsePyproject(content)
	case base == "Pipfile":
		return a.parsePipfile(content)
	case isRequirementsFile(base):
		return parseRequirementsTxt(content, isDevRequirementsFile(base))
	}
	return nil, fmt.Errorf("unsupported manifest: %s", manifestPath)
}

// parseRequirementsTxt parses a requirements file. A line that is exactly
// "name==X" (pip-compile / pip freeze output) is an exact pin and Resolved.
func parseRequirementsTxt(content []byte, dev bool) ([]analyzer.ParsedDependency, error) {
	var deps []analyzer.ParsedDependency
	scanner := bufio.NewScanner(bytes.NewReader(content))

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip comments, empty lines and options (-r, -e, --hash continuation lines).
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
			continue
		}
		// An inline comment starts at a '#' after a space or tab; a trailing
		// "\" continues the line onto option lines that are skipped above.
		line = stripInlineComment(line)
		line = strings.TrimSpace(strings.TrimSuffix(line, "\\"))

		name, version, exact := parseRequirementSpec(line)
		if name == "" || strings.ContainsAny(name, "/:") {
			continue // URL or path requirement without a package name
		}

		deps = append(deps, analyzer.ParsedDependency{
			Name:           normalizeName(name),
			CurrentVersion: version,
			IsDirect:       true,
			Resolved:       exact,
			Dev:            dev,
		})
	}

	sortDeps(deps)
	return deps, scanner.Err()
}

// stripInlineComment removes a comment that follows whitespace.
func stripInlineComment(line string) string {
	for i := 1; i < len(line); i++ {
		if line[i] == '#' && (line[i-1] == ' ' || line[i-1] == '\t') {
			return strings.TrimSpace(line[:i])
		}
	}
	return line
}

// specOperators lists the PEP 440 comparison operators, longest first so
// that "===" is not read as "==".
var specOperators = []string{"===", "==", "~=", "<=", ">=", "!=", "<", ">"}

// parseRequirementSpec splits a requirement into its name and the version of
// its first specifier. A direct reference ("name @ url") has no registry
// version and returns an empty name. The legacy "name (>=1.0)" form is read
// like "name>=1.0". exact is true when the whole requirement is a single
// "==" pin of a concrete version (no other specifier, no wildcard).
//
// The operator is found by its position in the line: the first character
// that can start one ('<', '>', '=', '!', '~') ends the name.
func parseRequirementSpec(line string) (name, version string, exact bool) {
	// Remove environment markers: ; python_version >= "3.6"
	if idx := strings.IndexByte(line, ';'); idx != -1 {
		line = line[:idx]
	}
	// Remove extras: package[extra]==1.0
	if idx := strings.IndexByte(line, '['); idx != -1 {
		if closeIdx := strings.IndexByte(line[idx:], ']'); closeIdx != -1 {
			line = line[:idx] + line[idx+closeIdx+1:]
		}
	}
	line = strings.TrimSpace(line)

	// Direct reference: name @ url
	if strings.IndexByte(line, '@') != -1 {
		return "", "", false
	}
	// Legacy parenthesized specifiers: name (>=1.0)
	line = strings.NewReplacer("(", "", ")", "").Replace(line)

	pos := strings.IndexAny(line, "<>=!~")
	if pos == -1 {
		return line, "", false
	}
	name = strings.TrimSpace(line[:pos])
	spec := line[pos:]

	clauses := strings.Split(spec, ",")
	first := strings.TrimSpace(clauses[0])
	for _, op := range specOperators {
		rest, ok := strings.CutPrefix(first, op)
		if !ok {
			continue
		}
		version = strings.TrimSpace(rest)
		// Anything after whitespace is not part of the version (e.g. --hash).
		if i := strings.IndexAny(version, " \t"); i != -1 {
			version = version[:i]
		}
		exact = op == "==" && len(clauses) == 1 && version != "" && !strings.Contains(version, "*")
		return name, version, exact
	}
	return name, "", false
}

// normalizeName normalizes a package name per PEP 503: lowercase, with every
// run of '-', '_' and '.' replaced by a single '-'.
func normalizeName(name string) string {
	var sb strings.Builder
	sep := false
	for _, r := range strings.ToLower(strings.TrimSpace(name)) {
		if r == '-' || r == '_' || r == '.' {
			sep = true
			continue
		}
		if sep {
			sb.WriteByte('-')
			sep = false
		}
		sb.WriteRune(r)
	}
	return sb.String()
}

// sortDeps orders dependencies by name and version.
func sortDeps(deps []analyzer.ParsedDependency) {
	sort.Slice(deps, func(i, j int) bool {
		if deps[i].Name != deps[j].Name {
			return deps[i].Name < deps[j].Name
		}
		return deps[i].CurrentVersion < deps[j].CurrentVersion
	})
}

// parsePipfile does a basic parse of Pipfile dependencies.
func (a *Analyzer) parsePipfile(content []byte) ([]analyzer.ParsedDependency, error) {
	var deps []analyzer.ParsedDependency
	scanner := bufio.NewScanner(bytes.NewReader(content))
	inPackages := false

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if line == "[packages]" || line == "[dev-packages]" {
			inPackages = true
			continue
		}

		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			inPackages = false
			continue
		}

		if inPackages && strings.Contains(line, "=") {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				name := strings.TrimSpace(parts[0])
				version, ok := pipfileVersion(strings.TrimSpace(parts[1]))
				if !ok {
					continue
				}
				if version == "*" {
					version = ""
				}
				version = analyzer.CleanVersion(version)
				deps = append(deps, analyzer.ParsedDependency{
					Name:           normalizeName(name),
					CurrentVersion: version,
					IsDirect:       true,
				})
			}
		}
	}

	sortDeps(deps)
	return deps, scanner.Err()
}

var (
	pipfileVersionRe = regexp.MustCompile(`version\s*=\s*["']([^"']*)["']`)
	quotedRe         = regexp.MustCompile(`"[^"]*"|'[^']*'`)
	pipfileSourceRe  = regexp.MustCompile(`\b(git|path|file|url|hg|svn|bzr)\s*=`)
)

// pipfileVersion extracts the version of a Pipfile package value, which is a
// string or an inline table. ok is false for git, path and URL packages.
func pipfileVersion(value string) (version string, ok bool) {
	if strings.HasPrefix(value, "{") {
		if pipfileSourceRe.MatchString(quotedRe.ReplaceAllString(value, `""`)) {
			return "", false
		}
		if m := pipfileVersionRe.FindStringSubmatch(value); m != nil {
			return strings.TrimSpace(m[1]), true
		}
		return "", true
	}
	value = strings.Trim(value, `"'`)
	if strings.Contains(value, "://") {
		return "", false
	}
	return value, true
}

// pypiResponse represents the PyPI JSON API response.
type pypiResponse struct {
	Info struct {
		Version string `json:"version"`
	} `json:"info"`
}

func (a *Analyzer) GetLatestVersion(ctx context.Context, packageName string) (string, error) {
	reqURL := a.registryURL + "/pypi/" + url.PathEscape(packageName) + "/json"

	req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to query PyPI: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return "", fmt.Errorf("package %s not found on PyPI", packageName)
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("PyPI error (status %d): %s", resp.StatusCode, string(body))
	}

	var result pypiResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("failed to decode PyPI response: %w", err)
	}

	return result.Info.Version, nil
}
