package report

import (
	"cmp"
	"fmt"
	"slices"
	"time"

	"github.com/orchesta/orbit/internal/domain/entity"
	"github.com/orchesta/orbit/internal/spdx"
)

// LicenseViolation is a dependency whose license the policy denies: its
// expression cannot be satisfied without one of the denied licenses.
type LicenseViolation struct {
	Dependency *entity.Dependency
	// Denied lists, sorted, the denied identifiers the expression cannot
	// avoid. For a violation that is not Ignored, it leaves out those that
	// license: entries accept.
	Denied       []string
	Ignored      bool // accepted by license: entries of the ignore file
	IgnoreReason string
}

// ApplyLicensePolicy checks every dependency in s.Deps against deny, a list
// of canonical SPDX identifiers from spdx.ParseIDs, and records the result
// in s: DeniedLicenses, LicenseViolations and LicenseFailed (a violation
// that is not ignored). It never changes Failed, so the exit code is 1 when
// Failed or LicenseFailed is set. A dependency whose license is "" cannot be
// judged and is counted in a warning instead, never as a violation. An
// active "license:<ID> package=<name>" entry of ignores allows that license
// for that package; a violation that only such entries clear is kept,
// marked Ignored with the first entry's reason. Expired and unused license
// entries are warned about. With an empty deny list nothing is denied, so
// every license entry is unused. Set s.ShowLicenses first (the warning's
// --licenses hint depends on it). Call it once, after BuildWithOptions and
// ApplyBaseline: the baseline does not filter license violations.
func ApplyLicensePolicy(s *Summary, deny []string, ignores *IgnoreList, now time.Time) {
	s.DeniedLicenses = slices.Clone(deny)
	denied := make(map[string]bool, len(deny))
	for _, id := range deny {
		denied[id] = true
	}
	var used []bool
	if ignores != nil {
		used = make([]bool, len(ignores.Entries))
	}
	unknown := 0
	for _, d := range s.Deps {
		if len(deny) == 0 {
			break
		}
		if d.License == "" {
			unknown++
			continue
		}
		hits, ok := spdx.Evaluate(d.License, func(id string) bool { return denied[id] })
		if !ok {
			continue
		}
		accepted := ignores.acceptedLicenses(d, now)
		v := LicenseViolation{Dependency: d, Denied: hits}
		first := -1
		for _, id := range hits {
			if i, ok := accepted[id]; ok {
				used[i] = true
				if first < 0 || i < first {
					first = i
				}
			}
		}
		// Evaluate again without the accepted licenses: a violation that
		// remains names only the licenses still denied, so no report
		// shows an accepted license as an active violation.
		remaining, still := spdx.Evaluate(d.License, func(id string) bool {
			_, ok := accepted[id]
			return denied[id] && !ok
		})
		if still {
			s.LicenseFailed = true
			v.Denied = remaining
		} else {
			// Only accepted licenses stood in the way, and every denied
			// license that matters is in hits, so first is set.
			v.Ignored, v.IgnoreReason = true, ignores.Entries[first].Reason
		}
		s.LicenseViolations = append(s.LicenseViolations, v)
	}
	slices.SortStableFunc(s.LicenseViolations, func(a, b LicenseViolation) int {
		return cmp.Or(
			cmp.Compare(a.Dependency.Name, b.Dependency.Name),
			cmp.Compare(a.Dependency.CurrentVersion, b.Dependency.CurrentVersion),
			cmp.Compare(a.Dependency.ManifestFile, b.Dependency.ManifestFile),
			cmp.Compare(a.Dependency.Ecosystem, b.Dependency.Ecosystem),
		)
	})
	if unknown > 0 {
		noun, verb := "dependencies have", "were"
		if unknown == 1 {
			noun, verb = "dependency has", "was"
		}
		hint := ""
		if !s.ShowLicenses {
			hint = "; --licenses looks them up on deps.dev"
		}
		s.Warnings = append(s.Warnings, fmt.Sprintf("license policy: %d %s no known license and %s not checked%s", unknown, noun, verb, hint))
	}
	s.Warnings = append(s.Warnings, ignores.ignoreWarnings(used, now, true)...)
	slices.Sort(s.Warnings)
}

// acceptedLicenses maps each license that an active license entry accepts
// for d's package to the index of the first such entry.
func (l *IgnoreList) acceptedLicenses(d *entity.Dependency, now time.Time) map[string]int {
	out := make(map[string]int)
	if l == nil {
		return out
	}
	for i, e := range l.Entries {
		if e.License == "" || (!e.Expires.IsZero() && !now.Before(e.Expires)) {
			continue
		}
		if !samePackage(d.Ecosystem, e.Package, d.Name) {
			continue
		}
		if _, seen := out[e.License]; !seen {
			out[e.License] = i
		}
	}
	return out
}
