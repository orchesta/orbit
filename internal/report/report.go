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
	// Malicious marks a known malicious package: a MAL- advisory is among the
	// finding's IDs. It fails every threshold and is never ignored.
	Malicious bool
}

// Summary aggregates a scan.
type Summary struct {
	Dependencies, Vulnerable int
	BySeverity               map[entity.Severity]int // not counting ignored findings
	Malicious                int                     // malicious findings (never ignored)
	Threshold                entity.Severity         // "" for none
	// Failed is true when a finding trips the gate (see failsGate): it is
	// not ignored and, with a Threshold set, at or above it or malicious,
	// or with FailOnKEV listed in CISA KEV.
	Failed bool
	// ThresholdFailed is the severity and malicious part of Failed, without
	// the --fail-on-kev gate (see thresholdGateFailed). The table names it
	// on its "threshold" line; KEVFailed has a line of its own.
	ThresholdFailed bool
	Warnings        []string
	FailOnKEV       bool          // a non-ignored KEV finding fails, whatever its severity
	KEVFindings     int           // non-ignored findings listed in CISA KEV
	KEVFailed       bool          // the --fail-on-kev gate failed (see kevGateFailed)
	Exploit         ExploitStatus // where the exploit data came from

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

// failsGate reports whether f trips the exit-1 gate of s. It is the only
// place that decides this, so the summary and JUnit agree. An ignored
// finding never does. With a threshold (not --fail-on none), a malicious
// package always does and any other finding does at or above s.Threshold.
// With s.FailOnKEV, a finding listed in CISA KEV does too, whatever its
// severity and also with --fail-on none (see kevGate).
func failsGate(f Finding, s Summary) bool {
	if f.Ignored {
		return false
	}
	if s.Threshold != "" && (f.Malicious || atOrAbove(f.Vulnerability.Severity, s.Threshold)) {
		return true
	}
	return kevGate(f, s)
}

// thresholdGateFailed reports whether a finding trips the severity and
// malicious part of the gate: failsGate with FailOnKEV off, so the gate
// keeps one definition.
func thresholdGateFailed(f []Finding, s Summary) bool {
	s.FailOnKEV = false
	for _, x := range f {
		if failsGate(x, s) {
			return true
		}
	}
	return false
}

// maliciousID is the first MAL- ID among v's IDs, or v.OSVID if none is.
func maliciousID(v *entity.Vulnerability) string {
	for _, id := range idSet(v) {
		if entity.IsMaliciousID(id) {
			return id
		}
	}
	return v.OSVID
}

// Build is BuildWithOptions with a severity threshold only.
func Build(res *engine.Result, ignores *IgnoreList, threshold entity.Severity, now time.Time) ([]Finding, Summary) {
	return BuildWithOptions(res, ignores, BuildOptions{Threshold: threshold}, now)
}

// BuildWithOptions pairs vulnerabilities with their dependencies, merges
// the advisories of one dependency that are aliases of each other into one
// finding (see mergeAliases), marks known malicious packages, applies
// ignores, sorts deterministically (malicious first, then severity; then
// KEV listing and higher EPSS first; then id, package, version, manifest,
// ecosystem) and summarizes. A merged finding is ignored when any of its
// IDs matches an entry; every matching entry counts as used. A malicious
// finding is never ignored: each entry that matches it is reported in a
// warning instead. The report fails when a finding trips failsGate.
func BuildWithOptions(res *engine.Result, ignores *IgnoreList, opts BuildOptions, now time.Time) ([]Finding, Summary) {
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
	var notApplied []string
	for _, v := range mergeAliases(matched) {
		d := byID[v.DependencyID]
		f := Finding{Dependency: d, Vulnerability: v, Malicious: v.IsMalicious()}
		if m := ignores.matchAll(v.OSVID, v.Aliases, d.Name, d.Ecosystem, now); len(m) > 0 {
			for _, i := range m {
				used[i] = true
				if f.Malicious {
					notApplied = append(notApplied, fmt.Sprintf(
						"ignore entry %s not applied: %s@%s is a known malicious package (%s)",
						ignores.Entries[i].ID, d.Name, d.CurrentVersion, maliciousID(v)))
				}
			}
			if !f.Malicious {
				f.IgnoreReason, f.Ignored = ignores.Entries[m[0]].Reason, true
			}
		}
		findings = append(findings, f)
	}
	sort.SliceStable(findings, func(i, j int) bool {
		a, b := findings[i], findings[j]
		if a.Malicious != b.Malicious {
			return a.Malicious
		}
		if ra, rb := severityRank(a.Vulnerability.Severity), severityRank(b.Vulnerability.Severity); ra != rb {
			return ra > rb
		}
		if a.Vulnerability.KEV != b.Vulnerability.KEV {
			return a.Vulnerability.KEV
		}
		if ea, eb := epssOf(a.Vulnerability), epssOf(b.Vulnerability); ea != eb {
			return ea > eb
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
	warnings = append(warnings, notApplied...)
	sort.Strings(warnings)

	s := Summary{
		Dependencies: len(res.Dependencies),
		BySeverity:   map[entity.Severity]int{},
		Threshold:    opts.Threshold,
		FailOnKEV:    opts.FailOnKEV,
		Exploit:      exploitStatus(res.Exploit),
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
		if f.Malicious {
			s.Malicious++
		}
		if f.Vulnerability.KEV {
			s.KEVFindings++
		}
		if failsGate(f, s) {
			s.Failed = true
		}
	}
	s.KEVFailed = kevGateFailed(findings, s)
	s.ThresholdFailed = thresholdGateFailed(findings, s)
	s.Vulnerable = len(vulnerable)
	return findings, s
}

func fixedIn(v *entity.Vulnerability) string {
	if v.FixedVersion == nil || *v.FixedVersion == "" {
		return ""
	}
	return *v.FixedVersion
}
