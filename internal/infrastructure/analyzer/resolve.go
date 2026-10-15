package analyzer

import (
	"cmp"
	"path"
	"slices"
	"strings"

	"github.com/aligoren/orbit/internal/domain/entity"
)

// ParsedFile is one manifest or lockfile after parsing.
type ParsedFile struct {
	Analyzer Analyzer
	Path     string // relative to the scan root, '/'-separated
	Kind     ManifestKind
	Deps     []ParsedDependency
	// Failed marks a file that could not be read or parsed. Resolve ignores
	// a failed lockfile when another lockfile of its ecosystem and directory
	// is usable.
	Failed bool
}

// ResolvedDependency is a dependency attributed to the file it was found in.
type ResolvedDependency struct {
	ParsedDependency
	Ecosystem    entity.Ecosystem
	ManifestFile string // lockfile path when Resolved, else the manifest path
}

// Resolve merges parsed files into the dependency list a scan reports.
//
// Files are grouped by ecosystem. A lockfile covers the manifests of its
// ecosystem in its own directory and below, unless a deeper directory has a
// lockfile of its own; the manifests then belong to the deepest one. When a
// directory holds several lockfiles of one ecosystem, only the most preferred
// (see lockfilePreference) is used.
//
//   - Every lockfile entry except Internal ones is reported, attributed to
//     the lockfile, with Resolved set. If the lockfile marks any entry
//     direct, it is taken to know which dependencies are direct and its
//     values are kept; otherwise an entry is direct when a manifest the
//     lockfile covers names it.
//   - A covered manifest in one of a covering lockfile's workspaces (its
//     own directory or an Internal entry's Dir) never reports a name the
//     lockfile marks Internal: that is a sibling package of the project. A
//     manifest outside the workspaces, such as an example using the
//     published package, keeps it. Otherwise a covered manifest's entry is
//     reported when no covering lockfile has the name at all (the
//     lockfile is out of date), and also when the entry pins an exact
//     version (its parser set Resolved) that no covering lockfile has: a pin
//     such as requirements.txt's urllib3==1.26.5 may be installed on its
//     own, so dropping it could hide a vulnerable version.
//   - An uncovered manifest is reported as parsed.
//
// Manifest entries are attributed to the manifest and keep the parser's
// Resolved: only exact pins set it. Names are compared the way the ecosystem
// compares them (PyPI and NuGet names are case-insensitive). Entries with the same ecosystem, file, name
// and version are reported once: direct if any of them is, dev only if all
// of them are. The result is sorted by ecosystem, file, name and version.
//
// A lockfile that could not be read or parsed can be passed with no Deps:
// its directory then keeps its manifests' results instead of falling to a
// lockfile further up.
func Resolve(files []ParsedFile) []ResolvedDependency {
	byEcosystem := make(map[entity.Ecosystem][]ParsedFile)
	for _, f := range files {
		if f.Analyzer == nil {
			continue
		}
		eco := f.Analyzer.Ecosystem()
		byEcosystem[eco] = append(byEcosystem[eco], f)
	}

	out := &collector{index: make(map[resolvedKey]int)}
	for eco, group := range byEcosystem {
		resolveEcosystem(eco, group, out)
	}

	slices.SortFunc(out.deps, func(a, b ResolvedDependency) int {
		return cmp.Or(
			cmp.Compare(a.Ecosystem, b.Ecosystem),
			cmp.Compare(a.ManifestFile, b.ManifestFile),
			cmp.Compare(a.Name, b.Name),
			cmp.Compare(a.CurrentVersion, b.CurrentVersion),
		)
	})
	return out.deps
}

// resolveEcosystem resolves the files of one ecosystem into out.
func resolveEcosystem(eco entity.Ecosystem, files []ParsedFile, out *collector) {
	files = applyVersions(eco, files)
	// Lockfiles by directory, keeping only the preferred one of each.
	lockfiles := make(map[string][]ParsedFile)
	for _, f := range files {
		if f.Kind == KindLockfile {
			dir := path.Dir(f.Path)
			lockfiles[dir] = append(lockfiles[dir], f)
		}
	}
	for dir, locks := range lockfiles {
		lockfiles[dir] = preferredLockfiles(locks)
	}

	// Names declared by the manifests each lockfile directory covers, and
	// the covered manifests themselves.
	declared := make(map[string]map[string]bool)
	covered := make(map[string][]ParsedFile)
	for _, f := range files {
		if f.Kind == KindLockfile {
			continue
		}
		dir, ok := coveringDir(path.Dir(f.Path), lockfiles)
		if !ok {
			for _, dep := range f.Deps {
				out.addManifestDep(eco, f.Path, dep)
			}
			continue
		}
		covered[dir] = append(covered[dir], f)
		if declared[dir] == nil {
			declared[dir] = make(map[string]bool)
		}
		for _, dep := range f.Deps {
			declared[dir][nameKey(eco, dep.Name)] = true
		}
	}

	for dir, locks := range lockfiles {
		locked := make(map[string]map[string]bool) // name key -> versions
		internal := make(map[string]bool)          // name keys of the project's own packages
		workspaces := map[string]bool{dir: true}   // directories of the project's own packages
		for _, lock := range locks {
			knowsDirect := slices.ContainsFunc(lock.Deps, func(dep ParsedDependency) bool { return dep.IsDirect })
			for _, dep := range lock.Deps {
				key := nameKey(eco, dep.Name)
				if dep.Internal {
					if dep.Name != "" {
						internal[key] = true
					}
					if dep.Dir != "" {
						workspaces[path.Join(dir, dep.Dir)] = true
					}
					continue
				}
				if locked[key] == nil {
					locked[key] = make(map[string]bool)
				}
				locked[key][dep.CurrentVersion] = true
				if !knowsDirect {
					dep.IsDirect = declared[dir][key]
				}
				dep.Resolved = true
				out.add(eco, lock.Path, dep)
			}
		}
		// Manifest entries that no lockfile here has at all, and exact pins
		// that no lockfile here has at that version.
		for _, m := range covered[dir] {
			inWorkspace := workspaces[path.Dir(m.Path)]
			for _, dep := range m.Deps {
				key := nameKey(eco, dep.Name)
				if inWorkspace && internal[key] {
					continue
				}
				versions, ok := locked[key]
				if !ok || (dep.Resolved && !versions[dep.CurrentVersion]) {
					out.addManifestDep(eco, m.Path, dep)
				}
			}
		}
	}
}

// applyVersions consumes the KindVersions files of one ecosystem: a manifest
// entry without a version takes it from the nearest ancestor directory that
// has such a file, as MSBuild finds Directory.Packages.props (the first one
// up the tree is used alone; it is not merged with the ones above it). The
// version files themselves are dropped. The input is not modified.
func applyVersions(eco entity.Ecosystem, files []ParsedFile) []ParsedFile {
	versions := make(map[string]map[string]string) // directory -> name key -> version
	for _, f := range files {
		if f.Kind != KindVersions {
			continue
		}
		dir := path.Dir(f.Path)
		if versions[dir] == nil {
			versions[dir] = make(map[string]string)
		}
		for _, dep := range f.Deps {
			if _, dup := versions[dir][nameKey(eco, dep.Name)]; !dup {
				versions[dir][nameKey(eco, dep.Name)] = dep.CurrentVersion
			}
		}
	}

	out := make([]ParsedFile, 0, len(files))
	for _, f := range files {
		if f.Kind == KindVersions {
			continue
		}
		if f.Kind == KindManifest && len(versions) > 0 && slices.ContainsFunc(f.Deps, func(d ParsedDependency) bool { return d.CurrentVersion == "" }) {
			if byName, ok := nearestVersions(path.Dir(f.Path), versions); ok {
				f.Deps = slices.Clone(f.Deps)
				for i, dep := range f.Deps {
					if dep.CurrentVersion == "" {
						f.Deps[i].CurrentVersion = byName[nameKey(eco, dep.Name)]
					}
				}
			}
		}
		out = append(out, f)
	}
	return out
}

// nearestVersions returns the versions of the closest directory at or above
// dir that has a version file.
func nearestVersions(dir string, versions map[string]map[string]string) (map[string]string, bool) {
	for ; ; dir = path.Dir(dir) {
		if v, ok := versions[dir]; ok {
			return v, true
		}
		if dir == "." || dir == "/" {
			return nil, false
		}
	}
}

// lockfilePreference lists, per ecosystem, the lockfile names of one
// directory in order of preference. Only the most preferred lockfile present
// in a directory is used; the others are ignored. Lockfiles not listed rank
// last and, if no listed one is present, are all used.
var lockfilePreference = map[entity.Ecosystem][]string{
	entity.EcosystemNpm:  {"package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "yarn.lock"},
	entity.EcosystemPyPI: {"poetry.lock", "uv.lock", "Pipfile.lock"},
}

// preferredLockfiles returns the lockfiles of one directory and ecosystem
// that rank best in lockfilePreference.
func preferredLockfiles(locks []ParsedFile) []ParsedFile {
	if len(locks) < 2 {
		return locks
	}
	rank := func(f ParsedFile) int {
		order := lockfilePreference[f.Analyzer.Ecosystem()]
		if i := slices.Index(order, path.Base(f.Path)); i >= 0 {
			return i
		}
		return len(order)
	}
	usable := slices.DeleteFunc(slices.Clone(locks), func(f ParsedFile) bool { return f.Failed })
	if len(usable) == 0 {
		return locks // all failed: the directory stays covered, with no entries
	}
	best := slices.MinFunc(usable, func(a, b ParsedFile) int { return cmp.Compare(rank(a), rank(b)) })
	var kept []ParsedFile
	for _, f := range usable {
		if rank(f) == rank(best) {
			kept = append(kept, f)
		}
	}
	return kept
}

// coveringDir returns the deepest directory holding a lockfile that covers
// manifestDir: manifestDir itself or one of its ancestors.
func coveringDir(manifestDir string, lockfiles map[string][]ParsedFile) (string, bool) {
	for dir := manifestDir; ; dir = path.Dir(dir) {
		if _, ok := lockfiles[dir]; ok {
			return dir, true
		}
		if dir == "." || dir == "/" {
			return "", false
		}
	}
}

// nameKey returns the form of a package name that the ecosystem treats as
// identical: PyPI names are normalized as in PEP 503, NuGet IDs are
// case-insensitive, and other names are compared as written.
func nameKey(eco entity.Ecosystem, name string) string {
	switch eco {
	case entity.EcosystemPyPI:
		return strings.Join(strings.FieldsFunc(strings.ToLower(name), func(r rune) bool {
			return r == '-' || r == '_' || r == '.'
		}), "-")
	case entity.EcosystemNuGet:
		return strings.ToLower(name)
	default:
		return name
	}
}

type resolvedKey struct {
	eco                 entity.Ecosystem
	file, name, version string
}

// collector accumulates resolved dependencies, merging repeated entries.
type collector struct {
	deps  []ResolvedDependency
	index map[resolvedKey]int
}

// addManifestDep records an entry taken from a manifest. Resolved is kept as
// the parser set it: only manifests that pin exact versions (requirements.txt
// with name==X) set it.
func (c *collector) addManifestDep(eco entity.Ecosystem, file string, dep ParsedDependency) {
	c.add(eco, file, dep)
}

func (c *collector) add(eco entity.Ecosystem, file string, dep ParsedDependency) {
	key := resolvedKey{eco: eco, file: file, name: dep.Name, version: dep.CurrentVersion}
	if i, ok := c.index[key]; ok {
		c.deps[i].IsDirect = c.deps[i].IsDirect || dep.IsDirect
		c.deps[i].Dev = c.deps[i].Dev && dep.Dev
		c.deps[i].Resolved = c.deps[i].Resolved || dep.Resolved
		return
	}
	c.index[key] = len(c.deps)
	c.deps = append(c.deps, ResolvedDependency{ParsedDependency: dep, Ecosystem: eco, ManifestFile: file})
}
