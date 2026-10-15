package pip

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/BurntSushi/toml"

	"github.com/orchesta/orbit/internal/infrastructure/analyzer"
)

// Lockfile parsers report every entry with IsDirect false: poetry.lock,
// uv.lock and Pipfile.lock do not record directness for every entry, so
// Resolve derives it from the manifests the lockfile covers.

// depSet collects dependencies, folding repeated name+version entries into
// one that is dev only if every occurrence is.
type depSet struct {
	deps  []analyzer.ParsedDependency
	index map[string]int
}

func (s *depSet) add(dep analyzer.ParsedDependency) {
	key := dep.Name + "\x00" + dep.CurrentVersion
	if i, ok := s.index[key]; ok {
		s.deps[i].Dev = s.deps[i].Dev && dep.Dev
		s.deps[i].IsDirect = s.deps[i].IsDirect || dep.IsDirect
		return
	}
	if s.index == nil {
		s.index = make(map[string]int)
	}
	s.index[key] = len(s.deps)
	s.deps = append(s.deps, dep)
}

func (s *depSet) sorted() []analyzer.ParsedDependency {
	sortDeps(s.deps)
	return s.deps
}

func lockedDep(name, version string, dev bool) analyzer.ParsedDependency {
	return analyzer.ParsedDependency{Name: normalizeName(name), CurrentVersion: version, Resolved: true, Dev: dev}
}

// poetryLock is the part of poetry.lock that is read. Poetry before 1.5 marks
// development packages with category = "dev"; later versions list the
// dependency groups of a package in groups.
type poetryLock struct {
	Packages []struct {
		Name     string   `toml:"name"`
		Version  string   `toml:"version"`
		Category string   `toml:"category"`
		Groups   []string `toml:"groups"`
		Source   struct {
			Type string `toml:"type"`
		} `toml:"source"`
	} `toml:"package"`
}

func parsePoetryLock(content []byte) ([]analyzer.ParsedDependency, error) {
	var lock poetryLock
	if err := toml.Unmarshal(content, &lock); err != nil {
		return nil, fmt.Errorf("parse poetry.lock: %w", err)
	}
	var set depSet
	for _, p := range lock.Packages {
		if p.Name == "" || p.Version == "" {
			continue
		}
		switch p.Source.Type {
		case "git", "url", "directory", "file":
			continue // not a registry release
		}
		dev := p.Category == "dev"
		if len(p.Groups) > 0 {
			dev = !slices.Contains(p.Groups, "main")
		}
		set.add(lockedDep(p.Name, p.Version, dev))
	}
	return set.sorted(), nil
}

// uvLock is the part of uv.lock that is read. The project itself and path
// dependencies have an editable, virtual or directory source and are not
// registry packages.
type uvLock struct {
	Packages []struct {
		Name    string `toml:"name"`
		Version string `toml:"version"`
		Source  struct {
			Editable  string `toml:"editable"`
			Virtual   string `toml:"virtual"`
			Directory string `toml:"directory"`
		} `toml:"source"`
	} `toml:"package"`
}

func parseUVLock(content []byte) ([]analyzer.ParsedDependency, error) {
	var lock uvLock
	if err := toml.Unmarshal(content, &lock); err != nil {
		return nil, fmt.Errorf("parse uv.lock: %w", err)
	}
	var set depSet
	for _, p := range lock.Packages {
		if p.Name == "" || p.Version == "" {
			continue
		}
		if p.Source.Editable != "" || p.Source.Virtual != "" || p.Source.Directory != "" {
			continue
		}
		set.add(lockedDep(p.Name, p.Version, false))
	}
	return set.sorted(), nil
}

// pipfileLock is the part of Pipfile.lock that is read.
type pipfileLock struct {
	Default map[string]pipfileLockEntry `json:"default"`
	Develop map[string]pipfileLockEntry `json:"develop"`
}

type pipfileLockEntry struct {
	Version string `json:"version"` // "==1.2.3"; absent for git and path packages
}

func parsePipfileLock(content []byte) ([]analyzer.ParsedDependency, error) {
	var lock pipfileLock
	if err := json.Unmarshal(content, &lock); err != nil {
		return nil, fmt.Errorf("parse Pipfile.lock: %w", err)
	}
	var set depSet
	for _, section := range []struct {
		entries map[string]pipfileLockEntry
		dev     bool
	}{{lock.Default, false}, {lock.Develop, true}} {
		for name, e := range section.entries {
			version, ok := strings.CutPrefix(e.Version, "==")
			if !ok || version == "" {
				continue
			}
			set.add(lockedDep(name, version, section.dev))
		}
	}
	return set.sorted(), nil
}

// pyproject is the part of pyproject.toml that is read.
type pyproject struct {
	Project struct {
		Dependencies         []string            `toml:"dependencies"`
		OptionalDependencies map[string][]string `toml:"optional-dependencies"`
	} `toml:"project"`
	Tool struct {
		Poetry struct {
			Dependencies    map[string]any `toml:"dependencies"`
			DevDependencies map[string]any `toml:"dev-dependencies"` // legacy
			Group           map[string]struct {
				Optional     bool           `toml:"optional"`
				Dependencies map[string]any `toml:"dependencies"`
			} `toml:"group"`
		} `toml:"poetry"`
	} `toml:"tool"`
	// DependencyGroups is PEP 735; its entries are requirement strings or
	// {include-group = "..."} tables.
	DependencyGroups map[string][]any `toml:"dependency-groups"`
}

// devGroupNames are the dependency group names that mean development-only.
var devGroupNames = []string{"dev", "test", "tests", "lint", "docs", "doc"}

func isDevGroup(name string) bool {
	return slices.Contains(devGroupNames, strings.ToLower(name))
}

func parsePyproject(content []byte) ([]analyzer.ParsedDependency, error) {
	var pp pyproject
	if err := toml.Unmarshal(content, &pp); err != nil {
		return nil, fmt.Errorf("parse pyproject.toml: %w", err)
	}

	var set depSet
	addRequirement := func(req string, dev bool) {
		name, version, _ := parseRequirementSpec(req)
		if name == "" {
			return
		}
		set.add(analyzer.ParsedDependency{Name: normalizeName(name), CurrentVersion: version, IsDirect: true, Dev: dev})
	}
	for _, req := range pp.Project.Dependencies {
		addRequirement(req, false)
	}
	for _, reqs := range pp.Project.OptionalDependencies {
		for _, req := range reqs {
			addRequirement(req, false)
		}
	}

	poetry := pp.Tool.Poetry
	addPoetry := func(deps map[string]any, dev bool) {
		for name, spec := range deps {
			if normalizeName(name) == "python" {
				continue
			}
			version, ok := poetryVersion(spec)
			if !ok {
				continue
			}
			set.add(analyzer.ParsedDependency{Name: normalizeName(name), CurrentVersion: version, IsDirect: true, Dev: dev})
		}
	}
	addPoetry(poetry.Dependencies, false)
	addPoetry(poetry.DevDependencies, true)
	for name, group := range poetry.Group {
		addPoetry(group.Dependencies, name != "main" && (group.Optional || isDevGroup(name)))
	}
	for name, entries := range pp.DependencyGroups {
		for _, e := range entries {
			if req, ok := e.(string); ok {
				addRequirement(req, isDevGroup(name))
			}
		}
	}
	return set.sorted(), nil
}

// poetryVersion extracts the version constraint of a Poetry dependency, which
// is a string, a table with a version key, or an array of such tables. ok is
// false for path, git and url dependencies, which name no registry release.
func poetryVersion(spec any) (version string, ok bool) {
	switch v := spec.(type) {
	case string:
		return cleanConstraint(v), true
	case map[string]any:
		s, hasVersion := v["version"].(string)
		if !hasVersion {
			return "", !(v["path"] != nil || v["git"] != nil || v["url"] != nil)
		}
		return cleanConstraint(s), true
	case []map[string]any:
		if len(v) > 0 {
			return poetryVersion(v[0])
		}
	case []any:
		if len(v) > 0 {
			return poetryVersion(v[0])
		}
	}
	return "", false
}

// cleanConstraint reduces a constraint such as "^1.2", ">=4.2,<5.0" or "*"
// to its first version.
func cleanConstraint(c string) string {
	c, _, _ = strings.Cut(c, ",")
	c = strings.TrimSpace(c)
	if c == "*" {
		return ""
	}
	return analyzer.CleanVersion(c)
}
