// Package report renders engine scan results as a table, JSON, SARIF and
// JUnit, and computes the summary and the failure threshold.
package report

import (
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/orchesta/orbit/internal/domain/entity"
	"github.com/orchesta/orbit/internal/engine"
)

// Finding is one vulnerability on one dependency.
type Finding struct {
	Dependency    *entity.Dependency
	Vulnerability *entity.Vulnerability
	Ignored       bool // matched an active .orbitignore entry
	IgnoreReason  string
}

// Summary aggregates a scan.
type Summary struct {
	Dependencies, Vulnerable int
	BySeverity               map[entity.Severity]int // not counting ignored findings
	Threshold                entity.Severity         // "" for none
	Failed                   bool                    // a non-ignored finding at or above Threshold
	Warnings                 []string

	// Deps lists every dependency (sorted), including those without findings.
	// The JSON report needs it because WriteJSON only receives findings.
	Deps []*entity.Dependency
}

// ToolInfo identifies the producing tool in JSON and SARIF output.
type ToolInfo struct{ Name, Version, InformationURI string }

// IgnoreEntry suppresses one advisory, optionally limited to a package.
type IgnoreEntry struct {
	ID      string    // advisory ID or alias (CVE)
	Package string    // optional; empty matches any package
	Reason  string    // shown in reports
	Expires time.Time // zero means never
}

// IgnoreList is the set of suppressions, normally from ParseIgnoreFile.
// A nil list ignores nothing.
type IgnoreList struct {
	Entries []IgnoreEntry
}

// Match reports whether the advisory (by ID or alias) on package pkg of
// ecosystem eco is ignored at now. IDs compare case-insensitively; package
// names follow eco's rules (PEP 503 for PyPI, case-insensitive for NuGet,
// exact otherwise).
func (l *IgnoreList) Match(id string, aliases []string, pkg string, eco entity.Ecosystem, now time.Time) (reason string, ok bool) {
	i := l.matchIndex(id, aliases, pkg, eco, now)
	if i < 0 {
		return "", false
	}
	return l.Entries[i].Reason, true
}

// matchIndex returns the index of the first active matching entry, or -1.
// Package names follow eco's rules (see samePackage).
func (l *IgnoreList) matchIndex(id string, aliases []string, pkg string, eco entity.Ecosystem, now time.Time) int {
	if m := l.matchAll(id, aliases, pkg, eco, now); len(m) > 0 {
		return m[0]
	}
	return -1
}

// matchAll returns the indexes of all active matching entries, in order.
func (l *IgnoreList) matchAll(id string, aliases []string, pkg string, eco entity.Ecosystem, now time.Time) []int {
	if l == nil {
		return nil
	}
	var out []int
	for i, e := range l.Entries {
		if !e.Expires.IsZero() && !now.Before(e.Expires) {
			continue
		}
		if e.Package != "" && !samePackage(eco, e.Package, pkg) {
			continue
		}
		if strings.EqualFold(e.ID, id) || slices.ContainsFunc(aliases, func(a string) bool { return strings.EqualFold(e.ID, a) }) {
			out = append(out, i)
		}
	}
	return out
}

func severityRank(s entity.Severity) int {
	switch s {
	case entity.SeverityCritical:
		return 4
	case entity.SeverityHigh:
		return 3
	case entity.SeverityMedium:
		return 2
	case entity.SeverityLow:
		return 1
	}
	return 0
}

// atOrAbove reports whether sev reaches threshold (threshold "" never does).
func atOrAbove(sev, threshold entity.Severity) bool {
	return threshold != "" && severityRank(sev) >= severityRank(threshold)
}

// Build pairs vulnerabilities with their dependencies, merges the advisories
// of one dependency that are aliases of each other into one finding (see
// mergeAliases), applies ignores, sorts deterministically (severity, id,
// package, version, manifest, ecosystem) and summarizes. A merged finding is
// ignored when any of its IDs matches an entry; every matching entry counts
// as used.
func Build(res *engine.Result, ignores *IgnoreList, threshold entity.Severity, now time.Time) ([]Finding, Summary) {
	byID := make(map[uuid.UUID]*entity.Dependency, len(res.Dependencies))
	for _, d := range res.Dependencies {
		byID[d.ID] = d
	}
	findings := []Finding{}
	unmatched := 0
	used := make([]bool, 0)
	if ignores != nil {
		used = make([]bool, len(ignores.Entries))
	}
	var matched []*entity.Vulnerability
	for _, v := range res.Vulnerabilities {
		if _, ok := byID[v.DependencyID]; !ok {
			unmatched++
			continue
		}
		matched = append(matched, v)
	}
	for _, v := range mergeAliases(matched) {
		d := byID[v.DependencyID]
		f := Finding{Dependency: d, Vulnerability: v}
		if m := ignores.matchAll(v.OSVID, v.Aliases, d.Name, d.Ecosystem, now); len(m) > 0 {
			f.IgnoreReason, f.Ignored = ignores.Entries[m[0]].Reason, true
			for _, i := range m {
				used[i] = true
			}
		}
		findings = append(findings, f)
	}
	sort.SliceStable(findings, func(i, j int) bool {
		a, b := findings[i], findings[j]
		if ra, rb := severityRank(a.Vulnerability.Severity), severityRank(b.Vulnerability.Severity); ra != rb {
			return ra > rb
		}
		if a.Vulnerability.OSVID != b.Vulnerability.OSVID {
			return a.Vulnerability.OSVID < b.Vulnerability.OSVID
		}
		if a.Dependency.Name != b.Dependency.Name {
			return a.Dependency.Name < b.Dependency.Name
		}
		if a.Dependency.CurrentVersion != b.Dependency.CurrentVersion {
			return a.Dependency.CurrentVersion < b.Dependency.CurrentVersion
		}
		if a.Dependency.ManifestFile != b.Dependency.ManifestFile {
			return a.Dependency.ManifestFile < b.Dependency.ManifestFile
		}
		return a.Dependency.Ecosystem < b.Dependency.Ecosystem
	})

	deps := append([]*entity.Dependency(nil), res.Dependencies...)
	sort.SliceStable(deps, func(i, j int) bool {
		a, b := deps[i], deps[j]
		if a.ManifestFile != b.ManifestFile {
			return a.ManifestFile < b.ManifestFile
		}
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		if a.CurrentVersion != b.CurrentVersion {
			return a.CurrentVersion < b.CurrentVersion
		}
		return a.Ecosystem < b.Ecosystem
	})

	warnings := append([]string(nil), res.Warnings...)
	if unmatched > 0 {
		warnings = append(warnings, fmt.Sprintf("%d findings could not be matched to a dependency", unmatched))
	}
	warnings = append(warnings, ignores.ignoreWarnings(used, now)...)
	sort.Strings(warnings)

	s := Summary{
		Dependencies: len(res.Dependencies),
		BySeverity:   map[entity.Severity]int{},
		Threshold:    threshold,
		Warnings:     warnings,
		Deps:         deps,
	}
	vulnerable := map[uuid.UUID]bool{}
	for _, f := range findings {
		if f.Ignored {
			continue
		}
		vulnerable[f.Dependency.ID] = true
		s.BySeverity[f.Vulnerability.Severity]++
		if atOrAbove(f.Vulnerability.Severity, threshold) {
			s.Failed = true
		}
	}
	s.Vulnerable = len(vulnerable)
	return findings, s
}

func fixedIn(v *entity.Vulnerability) string {
	if v.FixedVersion == nil || *v.FixedVersion == "" {
		return ""
	}
	return *v.FixedVersion
}
