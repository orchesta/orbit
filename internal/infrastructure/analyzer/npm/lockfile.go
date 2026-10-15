package npm

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"net/url"
	"path"
	"slices"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/orchesta/orbit/internal/infrastructure/analyzer"
)

// Lockfile parsers report every entry with IsDirect false: none of these
// formats records directness for every entry, so Resolve derives it from the
// package.json files the lockfile covers (which also handles workspaces).
// Workspace packages and other linked folders are reported as Internal
// entries, with their directories.

func isLockfile(p string) bool {
	switch path.Base(p) {
	case "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml":
		return true
	}
	return false
}

// nonRegistryPrefixes mark versions that do not name a registry release.
var nonRegistryPrefixes = []string{
	"link:", "file:", "workspace:", "portal:", "patch:", "exec:", "npm:", "catalog:", "jsr:",
	"git+", "git:", "git@", "github:", "gitlab:", "bitbucket:", "gist:",
	"http:", "https:", "ssh:",
}

// isRegistryVersion reports whether a version or range refers to a registry
// release rather than a local path, workspace, alias or git/url source.
func isRegistryVersion(v string) bool {
	v = strings.TrimSpace(v)
	if v == "" {
		return false
	}
	for _, p := range nonRegistryPrefixes {
		if strings.HasPrefix(v, p) {
			return false
		}
	}
	// "user/repo" GitHub shorthand and relative paths.
	return !strings.Contains(v, "/")
}

// aliasTarget splits an npm alias version ("npm:bar@^1.2.0") into the real
// package and its version. ok is false for anything else.
func aliasTarget(version string) (name, ver string, ok bool) {
	rest, found := strings.CutPrefix(strings.TrimSpace(version), "npm:")
	if !found {
		return "", "", false
	}
	name, ver = nameBeforeSpec(rest)
	if name == rest || name == "" || ver == "" {
		return "", "", false // "npm:^1.0.0" carries no package name
	}
	return name, ver, true
}

// isRegistryResolved reports whether a lockfile's resolved location is a
// registry tarball. Registry tarballs, public or private, have a "/-/" in
// their path; git, file, link and archive downloads do not. An empty value
// (not recorded) is accepted.
func isRegistryResolved(resolved string) bool {
	if resolved == "" {
		return true
	}
	u, err := url.Parse(resolved)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return false
	}
	return strings.Contains(u.Path, "/-/")
}

// depSet collects lockfile entries, merging repeated name/version pairs:
// an entry is dev only if every occurrence is.
type depSet struct {
	index map[[2]string]int
	deps  []analyzer.ParsedDependency
}

func (s *depSet) add(name, version string, dev bool) {
	if name == "" || !isRegistryVersion(version) {
		return
	}
	if s.index == nil {
		s.index = make(map[[2]string]int)
	}
	key := [2]string{name, version}
	if i, ok := s.index[key]; ok {
		s.deps[i].Dev = s.deps[i].Dev && dev
		return
	}
	s.index[key] = len(s.deps)
	s.deps = append(s.deps, analyzer.ParsedDependency{Name: name, CurrentVersion: version, Resolved: true, Dev: dev})
}

// addInternal records a package of the project itself (a workspace or a
// linked folder) by name, by directory relative to the lockfile, or both, so
// Resolve does not take a workspace manifest naming it for a registry
// dependency.
func (s *depSet) addInternal(name, dir string) {
	if name == "" && dir == "" {
		return
	}
	if s.index == nil {
		s.index = make(map[[2]string]int)
	}
	key := [2]string{name, "\x00" + dir} // registry versions never start with NUL
	if _, ok := s.index[key]; ok {
		return
	}
	s.index[key] = len(s.deps)
	s.deps = append(s.deps, analyzer.ParsedDependency{Name: name, Internal: true, Dir: dir})
}

func (s *depSet) sorted() []analyzer.ParsedDependency {
	sort.Slice(s.deps, func(i, j int) bool {
		if s.deps[i].Name != s.deps[j].Name {
			return s.deps[i].Name < s.deps[j].Name
		}
		if s.deps[i].CurrentVersion != s.deps[j].CurrentVersion {
			return s.deps[i].CurrentVersion < s.deps[j].CurrentVersion
		}
		return s.deps[i].Dir < s.deps[j].Dir
	})
	return s.deps
}

// nameBeforeSpec returns the package name of a descriptor such as
// "@scope/a@^1.0.0" or "a@npm:^1.0.0": everything before the first '@' that
// is not the scope marker.
func nameBeforeSpec(desc string) (name, spec string) {
	if len(desc) == 0 {
		return "", ""
	}
	i := strings.Index(desc[1:], "@")
	if i < 0 {
		return desc, ""
	}
	return desc[:i+1], desc[i+2:]
}

// ---- package-lock.json / npm-shrinkwrap.json ----

type packageLock struct {
	Packages     map[string]lockPackage `json:"packages"`
	Dependencies map[string]lockV1Dep   `json:"dependencies"`
}

type lockPackage struct {
	Name        string `json:"name"`
	Version     string `json:"version"`
	Resolved    string `json:"resolved"`
	Link        bool   `json:"link"`
	Dev         bool   `json:"dev"`
	DevOptional bool   `json:"devOptional"`
}

type lockV1Dep struct {
	Version      string               `json:"version"`
	Dev          bool                 `json:"dev"`
	Dependencies map[string]lockV1Dep `json:"dependencies"`
}

func parsePackageLock(content []byte) ([]analyzer.ParsedDependency, error) {
	var lock packageLock
	if err := json.Unmarshal(content, &lock); err != nil {
		return nil, fmt.Errorf("failed to parse package-lock.json: %w", err)
	}

	var set depSet
	if len(lock.Packages) > 0 {
		// lockfileVersion 2 and 3.
		const marker = "node_modules/"
		for key, pkg := range lock.Packages {
			i := strings.LastIndex(key, marker)
			if key == "" || i < 0 {
				continue // the root or a workspace folder
			}
			name := key[i+len(marker):]
			if pkg.Link {
				// A workspace or another linked folder; resolved is its
				// directory relative to the lockfile.
				set.addInternal(name, pkg.Resolved)
				continue
			}
			if !isRegistryResolved(pkg.Resolved) {
				continue // a git, file or archive install
			}
			if pkg.Name != "" {
				name = pkg.Name // an aliased install: the real package
			}
			set.add(name, pkg.Version, pkg.Dev || pkg.DevOptional)
		}
		return set.sorted(), nil
	}

	// lockfileVersion 1.
	var walk func(map[string]lockV1Dep)
	walk = func(m map[string]lockV1Dep) {
		for name, dep := range m {
			version := dep.Version
			if real, v, ok := aliasTarget(version); ok {
				name, version = real, v
			}
			set.add(name, version, dep.Dev)
			walk(dep.Dependencies)
		}
	}
	walk(lock.Dependencies)
	return set.sorted(), nil
}

// ---- yarn.lock ----

func parseYarnLock(content []byte) ([]analyzer.ParsedDependency, error) {
	if bytes.Contains(content, []byte("__metadata:")) {
		return parseYarnBerry(content)
	}
	return parseYarnClassic(content)
}

func parseYarnClassic(content []byte) ([]analyzer.ParsedDependency, error) {
	var set depSet
	sc := bufio.NewScanner(bytes.NewReader(content))
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)

	var name, version, resolved string // the block being read; name "" when skipped
	flush := func() {
		if name != "" && version != "" && isRegistryResolved(resolved) {
			set.add(name, version, false)
		}
		name, version, resolved = "", "", ""
	}
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), " \t\r")
		switch {
		case line == "" || strings.HasPrefix(line, "#"):
		case line[0] != ' ':
			flush()
			header := strings.TrimSuffix(line, ":")
			first, _, _ := strings.Cut(header, ",")
			n, spec := nameBeforeSpec(strings.Trim(strings.TrimSpace(first), `"`))
			if real, _, ok := aliasTarget(spec); ok {
				name = real
			} else if isRegistryVersion(spec) {
				name = n
			}
		case name != "" && strings.HasPrefix(line, "  version "):
			version = strings.Trim(strings.TrimSpace(strings.TrimPrefix(line, "  version ")), `"`)
		case name != "" && strings.HasPrefix(line, "  resolved "):
			resolved = strings.Trim(strings.TrimSpace(strings.TrimPrefix(line, "  resolved ")), `"`)
		}
	}
	flush()
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("failed to read yarn.lock: %w", err)
	}
	return set.sorted(), nil
}

func parseYarnBerry(content []byte) ([]analyzer.ParsedDependency, error) {
	root, err := yamlRoot(content, "yarn.lock")
	if err != nil {
		return nil, err
	}
	var set depSet
	eachPair(root, func(key string, entry *yaml.Node) {
		if key == "__metadata" {
			return
		}
		// The resolution names the package actually installed; it carries
		// the protocol (npm:, workspace:, patch:, link:, ...).
		desc := scalar(field(entry, "resolution"))
		if desc == "" {
			first, _, _ := strings.Cut(key, ",")
			desc = strings.Trim(strings.TrimSpace(first), `"`)
		}
		name, spec := nameBeforeSpec(desc)
		switch {
		case strings.HasPrefix(spec, "workspace:"):
			// The root workspace ("workspace:.") is the lockfile's own
			// directory, which Resolve treats as a workspace anyway. Its
			// name is not recorded: a library's examples outside the
			// workspaces may use the published package of that name.
			if dir := strings.TrimPrefix(spec, "workspace:"); dir != "." {
				set.addInternal(name, dir)
			}
		case strings.HasPrefix(spec, "npm:"):
			set.add(name, scalar(field(entry, "version")), false)
		}
	})
	return set.sorted(), nil
}

// ---- YAML lockfiles ----

// maxYAMLLockfileBytes caps the YAML lockfiles (pnpm-lock.yaml and yarn
// berry's yarn.lock), below the read limit of other lockfiles: their parse
// tree takes many times the file's size in memory. A larger one fails to
// parse, so Resolve falls back to another lockfile of its directory or to
// its manifests.
const maxYAMLLockfileBytes = 16 << 20

// yamlRoot parses a YAML lockfile into a node tree and returns its top-level
// mapping, nil for an empty file.
//
// Lockfiles are walked as nodes instead of being decoded into Go maps:
// yaml.v3 checks a mapping's keys for duplicates pairwise while decoding it
// into a map, which is quadratic in the number of packages (minutes for a
// large monorepo lockfile). Anchors and aliases, which pnpm and yarn never
// write, are not followed.
func yamlRoot(content []byte, file string) (*yaml.Node, error) {
	if len(content) > maxYAMLLockfileBytes {
		return nil, fmt.Errorf("%s is larger than %d bytes", file, maxYAMLLockfileBytes)
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(content, &doc); err != nil {
		return nil, fmt.Errorf("failed to parse %s: %w", file, err)
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) == 0 {
		return nil, nil // empty
	}
	root := doc.Content[0]
	if root.Kind == yaml.ScalarNode && root.Tag == "!!null" {
		return nil, nil
	}
	if root.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("failed to parse %s: the top level is not a mapping", file)
	}
	return root, nil
}

// eachPair calls fn with each key and value of a mapping node, in order.
// Other nodes, nil included, have no pairs.
func eachPair(n *yaml.Node, fn func(key string, value *yaml.Node)) {
	if n == nil || n.Kind != yaml.MappingNode {
		return
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		fn(n.Content[i].Value, n.Content[i+1])
	}
}

// field returns the value of key in a mapping node, or nil. It scans the
// mapping, so it is meant for the small per-package mappings.
func field(n *yaml.Node, key string) *yaml.Node {
	if n == nil || n.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			return n.Content[i+1]
		}
	}
	return nil
}

// scalar returns the value of a scalar node, or "" for anything else.
func scalar(n *yaml.Node) string {
	if n == nil || n.Kind != yaml.ScalarNode {
		return ""
	}
	return n.Value
}

// ---- pnpm-lock.yaml ----

// pnpmRefVersion returns the version of a dependency reference: either the
// bare version or a {specifier, version} mapping.
func pnpmRefVersion(n *yaml.Node) string {
	if n != nil && n.Kind == yaml.ScalarNode {
		return n.Value
	}
	return scalar(field(n, "version"))
}

// pnpmRefKey returns the peer-stripped "name@version" key a dependency
// reference points to.
func pnpmRefKey(name, version string) string {
	version = stripPeers(version)
	if strings.Contains(version, "@") {
		return version // an alias: the version names the real package
	}
	return name + "@" + version
}

// stripPeers drops the parenthesised peer suffix of a pnpm package key.
func stripPeers(key string) string {
	if i := strings.Index(key, "("); i >= 0 {
		return key[:i]
	}
	return key
}

// splitPnpmKey splits a packages key ("/a@1.2.3(x@1)", "/@s/a@1.2.3",
// "a@1.2.3") into name and version.
func splitPnpmKey(key string) (name, version string, ok bool) {
	key = strings.TrimPrefix(stripPeers(key), "/")
	i := strings.LastIndex(key, "@")
	if i <= 0 {
		return "", "", false
	}
	return key[:i], key[i+1:], true
}

func parsePnpmLock(content []byte) ([]analyzer.ParsedDependency, error) {
	root, err := yamlRoot(content, "pnpm-lock.yaml")
	if err != nil {
		return nil, err
	}

	// The project's own dependencies: each importer's, and the top level of
	// a single-project lockfile. Roots are kept per importer: importers may
	// depend on different versions of one package, and each is a root. A
	// link: version is a workspace sibling or a local folder, relative to
	// the importer's directory; every importer is a workspace.
	var set depSet
	var prodRoots, devRoots []string
	addRoots := func(importerDir string, project *yaml.Node) {
		for _, section := range []struct {
			key   string
			roots *[]string
		}{
			{"dependencies", &prodRoots},
			{"optionalDependencies", &prodRoots},
			{"devDependencies", &devRoots},
		} {
			eachPair(field(project, section.key), func(name string, ref *yaml.Node) {
				version := pnpmRefVersion(ref)
				if target, ok := strings.CutPrefix(version, "link:"); ok {
					set.addInternal(name, path.Join(importerDir, target))
					return
				}
				*section.roots = append(*section.roots, pnpmRefKey(name, version))
			})
		}
	}
	addRoots(".", root)
	eachPair(field(root, "importers"), func(dir string, importer *yaml.Node) {
		if dir != "." {
			set.addInternal("", dir)
		}
		addRoots(dir, importer)
	})
	prodReach, devReach := pnpmReachability(field(root, "snapshots"), prodRoots, devRoots)

	eachPair(field(root, "packages"), func(key string, pkg *yaml.Node) {
		res := field(pkg, "resolution")
		if scalar(field(res, "type")) == "git" || scalar(field(res, "repo")) != "" || scalar(field(res, "tarball")) != "" {
			return
		}
		name, version, ok := splitPnpmKey(key)
		if !ok {
			return
		}
		var dev bool
		switch strings.ToLower(scalar(field(pkg, "dev"))) {
		case "true": // lockfile v6 records it per package
			dev = true
		case "false":
		default:
			// Newer lockfiles do not: a package is dev when only the
			// devDependencies lead to it. Unknown stays false.
			ref := name + "@" + version
			dev = devReach[ref] && !prodReach[ref]
		}
		set.add(name, version, dev)
	})
	return set.sorted(), nil
}

// pnpmReachability walks the snapshots from the importers' production and
// development dependencies. Roots and the returned sets hold peer-stripped
// "name@version" keys.
func pnpmReachability(snapshots *yaml.Node, prodRoots, devRoots []string) (prod, dev map[string]bool) {
	byBase := make(map[string][]*yaml.Node)
	eachPair(snapshots, func(key string, snap *yaml.Node) {
		base := strings.TrimPrefix(stripPeers(key), "/")
		byBase[base] = append(byBase[base], snap)
	})

	walk := func(roots []string) map[string]bool {
		seen := make(map[string]bool)
		queue := slices.Clone(roots)
		for len(queue) > 0 {
			k := queue[len(queue)-1]
			queue = queue[:len(queue)-1]
			if seen[k] {
				continue
			}
			seen[k] = true
			for _, snap := range byBase[k] {
				for _, section := range []string{"dependencies", "optionalDependencies"} {
					eachPair(field(snap, section), func(name string, version *yaml.Node) {
						queue = append(queue, pnpmRefKey(name, scalar(version)))
					})
				}
			}
		}
		return seen
	}
	return walk(prodRoots), walk(devRoots)
}
