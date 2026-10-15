package report

import (
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/orchesta/orbit/internal/domain/entity"
)

// SBOMOptions describes the subject of an SBOM and makes it reproducible.
type SBOMOptions struct {
	Name   string    // the scanned project: the root component / package
	Now    time.Time // creation time, written in UTC to the second
	Serial uuid.UUID // CycloneDX serialNumber; the unique part of the SPDX namespace
}

// sbomPackage is one package of an SBOM: the dependencies of a scan that
// share ecosystem, name (compared by ecosystem rules) and version, from
// however many manifests.
type sbomPackage struct {
	Ecosystem entity.Ecosystem
	Name      string // spelling of the first dependency in Summary.Deps order
	Version   string // as orbit reports it (Go without the "v")
	PURL      string // "" when the ecosystem has no purl type
	Ref       string // CycloneDX bom-ref, unique in the document
	License   string // first non-empty license of the group
	Direct    bool   // any member is direct
	Dev       bool   // every member is dev-only
	Resolved  bool   // any member's version came from a lockfile
	Manifests []string
}

// sbomKey compares names with the shared ecosystem rules (packageKey, the
// equivalence samePackage and the baseline use) and versions in their native
// form, so one package never yields two equal bom-refs.
func sbomKey(d *entity.Dependency) string {
	return string(d.Ecosystem) + "\x00" + packageKey(d.Ecosystem, d.Name) + "\x00" + nativeVersion(d.Ecosystem, d.CurrentVersion)
}

// sbomPackages groups deps (sorted by Build) into packages sorted by bom-ref
// and maps every dependency ID to its package. A package's name is that of
// its first dependency in deps.
func sbomPackages(deps []*entity.Dependency) ([]*sbomPackage, map[uuid.UUID]*sbomPackage) {
	var pkgs []*sbomPackage
	byKey := map[string]*sbomPackage{}
	byDep := make(map[uuid.UUID]*sbomPackage, len(deps))
	for _, d := range deps {
		k := sbomKey(d)
		p, ok := byKey[k]
		if !ok {
			p = &sbomPackage{
				Ecosystem: d.Ecosystem, Name: d.Name, Version: d.CurrentVersion,
				PURL: PackageURL(d.Ecosystem, d.Name, d.CurrentVersion),
				Dev:  true,
			}
			// The bom-ref keeps a non-exact version, so two declared ranges
			// of one package stay two components.
			p.Ref = buildPURL(d.Ecosystem, d.Name, d.CurrentVersion, true)
			if p.Ref == "" {
				p.Ref = "orbit:" + purlEscape(string(d.Ecosystem)) + "/" + purlEscape(d.Name) + "@" + purlEscape(d.CurrentVersion)
			}
			byKey[k] = p
			pkgs = append(pkgs, p)
		}
		p.Direct = p.Direct || d.IsDirect
		p.Dev = p.Dev && d.IsDev
		p.Resolved = p.Resolved || d.IsResolved
		if p.License == "" {
			p.License = d.License
		}
		if d.ManifestFile != "" && !slices.Contains(p.Manifests, d.ManifestFile) {
			p.Manifests = append(p.Manifests, d.ManifestFile)
		}
		byDep[d.ID] = p
	}
	for _, p := range pkgs {
		slices.Sort(p.Manifests)
	}
	slices.SortFunc(pkgs, func(a, b *sbomPackage) int { return strings.Compare(a.Ref, b.Ref) })
	return pkgs, byDep
}

// webURL reports whether s is an absolute http(s) URL without spaces, the
// only references written as CycloneDX advisories.
func webURL(s string) bool {
	if strings.ContainsAny(s, " \t\r\n") {
		return false
	}
	u, err := url.Parse(s)
	return err == nil && (u.Scheme == "https" || u.Scheme == "http") && u.Host != ""
}

// sbomTime formats t as the second-precision UTC timestamp both formats use.
func sbomTime(t time.Time) string {
	return t.UTC().Format("2006-01-02T15:04:05Z")
}

// rootName is the project name, or "unnamed" when none was given: both
// formats require a name.
func rootName(opts SBOMOptions) string {
	if opts.Name == "" {
		return "unnamed"
	}
	return opts.Name
}
