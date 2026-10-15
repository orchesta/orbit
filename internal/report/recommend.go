package report

import (
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/orchesta/orbit/internal/domain/entity"
	"github.com/orchesta/orbit/internal/engine"
)

// Recommendation is the smallest upgrade of one installed package that
// clears the most of its known advisories in a report.
type Recommendation struct {
	Ecosystem string `json:"ecosystem"`
	Package   string `json:"package"`
	Current   string `json:"current"`
	// Upgrade is the highest fixed version among Fixes, which is the lowest
	// version at or above every one of them; "" when no advisory has a
	// known fix above Current.
	Upgrade string   `json:"upgrade"`
	Fixes   []string `json:"fixes"` // advisory IDs that Upgrade fixes, sorted and unique
	// NoFix lists the advisories without a known fix above Current, sorted
	// and unique.
	NoFix    []string `json:"no_fix"`
	Manifest string   `json:"manifest"`
	// Via names the direct dependencies that pull the package in, sorted
	// and joined by ", ", when the lockfile records them; "" otherwise.
	Via string `json:"via"`
	// Malicious is set when an advisory reports the package as malicious:
	// it should be removed, not upgraded. Upgrade may still be set, from
	// an advisory in the group that is not a MAL- record (see highestFix);
	// the outputs name it but do not recommend it as an upgrade.
	Malicious bool `json:"malicious"`
}

// Recommend returns one Recommendation per installed package with a
// finding that is not ignored. A package is installed once per ecosystem,
// manifest, name and version: two versions of one package, such as a copy
// nested under another dependency, are recommended separately.
//
// An advisory counts as fixed when its fixed version is above the installed
// one, or when the two cannot be compared; Upgrade is the highest such
// fixed version. The other advisories are listed in NoFix, so a stale fixed
// version at or below the installed one never becomes a downgrade. Go
// upgrades get the "v" that go get expects. Ignored findings are left out:
// the project has accepted them.
//
// The result lists the packages to remove (Malicious) first, then sorts by
// the most severe advisory, package, installed version, manifest and
// ecosystem. Only fixed versions are compared: Orbit does not check that
// Upgrade exists in the registry, that no other advisory affects it, or
// that the package's dependents accept it.
func Recommend(findings []Finding) []Recommendation {
	type key struct {
		eco                     entity.Ecosystem
		manifest, name, version string
	}
	type group struct {
		rec  Recommendation
		rank int
	}
	byKey := make(map[key]*group)
	var groups []*group
	for _, f := range findings {
		if f.Ignored {
			continue
		}
		d, v := f.Dependency, f.Vulnerability
		k := key{d.Ecosystem, d.ManifestFile, d.Name, d.CurrentVersion}
		g, ok := byKey[k]
		if !ok {
			g = &group{rec: Recommendation{
				Ecosystem: string(d.Ecosystem), Package: d.Name, Current: d.CurrentVersion,
				Fixes: []string{}, NoFix: []string{}, Manifest: d.ManifestFile,
				Via: joinVia(d.Via),
			}}
			byKey[k] = g
			groups = append(groups, g)
		}
		g.rank = max(g.rank, severityRank(v.Severity))
		g.rec.Malicious = g.rec.Malicious || f.Malicious
		fix := fixedIn(v)
		if fix == "" || !aboveInstalled(fix, d.CurrentVersion) {
			g.rec.NoFix = append(g.rec.NoFix, v.OSVID)
			continue
		}
		g.rec.Fixes = append(g.rec.Fixes, v.OSVID)
		if g.rec.Upgrade == "" || newer(fix, g.rec.Upgrade) {
			g.rec.Upgrade = fix
		}
	}
	sort.SliceStable(groups, func(i, j int) bool {
		a, b := groups[i], groups[j]
		if a.rec.Malicious != b.rec.Malicious {
			return a.rec.Malicious
		}
		if a.rank != b.rank {
			return a.rank > b.rank
		}
		ra, rb := a.rec, b.rec
		if ra.Package != rb.Package {
			return ra.Package < rb.Package
		}
		if ra.Current != rb.Current {
			return ra.Current < rb.Current
		}
		if ra.Manifest != rb.Manifest {
			return ra.Manifest < rb.Manifest
		}
		return ra.Ecosystem < rb.Ecosystem
	})
	out := make([]Recommendation, 0, len(groups))
	for _, g := range groups {
		r := g.rec
		sort.Strings(r.Fixes)
		r.Fixes = slices.Compact(r.Fixes)
		sort.Strings(r.NoFix)
		r.NoFix = slices.Compact(r.NoFix)
		if r.Upgrade != "" && r.Ecosystem == string(entity.EcosystemGo) && !strings.HasPrefix(r.Upgrade, "v") {
			r.Upgrade = "v" + r.Upgrade
		}
		out = append(out, r)
	}
	return out
}

// joinVia sorts and de-duplicates via, without modifying it, and joins it
// with ", ".
func joinVia(via []string) string {
	s := slices.Clone(via)
	slices.Sort(s)
	return strings.Join(slices.Compact(s), ", ")
}

// aboveInstalled reports whether fix is above the installed version. A pair
// that cannot be compared (a manifest range such as ">=1 <2") counts as
// above, so such a fix is still recommended.
func aboveInstalled(fix, installed string) bool {
	order, comparable := versionOrder(fix, installed)
	return !comparable || order > 0
}

// RecommendFor builds the recommendations for scan data as the server
// stores it: dependencies and their vulnerabilities, with no ignore file.
// Advisories that are aliases of each other are merged first, as in Build.
// The result is never nil.
func RecommendFor(deps []*entity.Dependency, vulns []*entity.Vulnerability) []Recommendation {
	_, s := Build(&engine.Result{Dependencies: deps, Vulnerabilities: vulns}, nil, "", time.Time{})
	return s.Recommendations
}
