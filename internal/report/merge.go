package report

import (
	"sort"
	"strings"

	"github.com/google/uuid"

	"github.com/orchesta/orbit/internal/domain/entity"
	"github.com/orchesta/orbit/internal/infrastructure/analyzer"
	"github.com/orchesta/orbit/internal/infrastructure/exploit"
)

// mergeAliases merges the vulnerabilities of one dependency that are the same
// issue under different advisory IDs: two vulnerabilities belong together when
// their ID sets ({OSVID} ∪ Aliases, compared case-insensitively) intersect,
// transitively. osv.dev reports such pairs, for example two GitHub advisories
// for one CVE. A group of one is returned unchanged; a larger group becomes a
// new vulnerability (see mergeGroup). The input is not modified, and the
// output keeps the order of each group's first member.
func mergeAliases(vulns []*entity.Vulnerability) []*entity.Vulnerability {
	parent := make([]int, len(vulns))
	for i := range parent {
		parent[i] = i
	}
	var find func(int) int
	find = func(i int) int {
		if parent[i] != i {
			parent[i] = find(parent[i])
		}
		return parent[i]
	}
	type key struct {
		dep uuid.UUID
		id  string
	}
	owner := make(map[key]int)
	for i, v := range vulns {
		for _, id := range idSet(v) {
			k := key{v.DependencyID, strings.ToUpper(id)}
			if j, ok := owner[k]; ok {
				parent[find(i)] = find(j)
			} else {
				owner[k] = i
			}
		}
	}

	groups := make(map[int][]*entity.Vulnerability)
	var roots []int
	for i, v := range vulns {
		r := find(i)
		if _, ok := groups[r]; !ok {
			roots = append(roots, r)
		}
		groups[r] = append(groups[r], v)
	}
	out := make([]*entity.Vulnerability, 0, len(roots))
	for _, r := range roots {
		out = append(out, mergeGroup(groups[r]))
	}
	return out
}

// idSet is the advisory's own ID followed by its aliases.
func idSet(v *entity.Vulnerability) []string {
	return append([]string{v.OSVID}, v.Aliases...)
}

// mergeGroup combines vulnerabilities of one dependency that are the same
// issue. Members are ranked by severity (highest first), then ID, aliases and
// summary, so the result does not depend on input order. The merged finding:
//   - is reported under a CVE ID of a member if there is one, otherwise the
//     smallest member ID, and lists every other ID (sorted) as an alias;
//   - has the highest severity and the first non-empty summary and details;
//   - has the references of all members, first-ranked member first;
//   - is fixed in the highest fixed version, or not at all if any member has
//     no fix (upgrading must clear every advisory in the group). Malicious
//     package advisories (see maliciousAdvisory) take no part when the group
//     has other members: a MAL- record names no fix, and the other
//     advisories say which release is clean;
//   - is in KEV if any member is (earliest date) and has the highest EPSS of
//     its members.
func mergeGroup(group []*entity.Vulnerability) *entity.Vulnerability {
	if len(group) == 1 {
		return group[0]
	}
	members := append([]*entity.Vulnerability(nil), group...)
	sort.SliceStable(members, func(i, j int) bool {
		a, b := members[i], members[j]
		if ra, rb := severityRank(a.Severity), severityRank(b.Severity); ra != rb {
			return ra > rb
		}
		if a.OSVID != b.OSVID {
			return a.OSVID < b.OSVID
		}
		if aa, ba := strings.Join(a.Aliases, ","), strings.Join(b.Aliases, ","); aa != ba {
			return aa < ba
		}
		return a.Summary < b.Summary
	})

	m := *members[0]
	m.OSVID = groupID(members)
	m.Aliases, m.References, m.Summary, m.Details = nil, nil, "", ""
	seenID := map[string]bool{strings.ToUpper(m.OSVID): true}
	seenRef := map[string]bool{}
	for _, v := range members {
		for _, id := range idSet(v) {
			if u := strings.ToUpper(id); !seenID[u] {
				seenID[u] = true
				m.Aliases = append(m.Aliases, id)
			}
		}
		for _, r := range v.References {
			if !seenRef[r] {
				seenRef[r] = true
				m.References = append(m.References, r)
			}
		}
		if m.Summary == "" {
			m.Summary = v.Summary
		}
		if m.Details == "" {
			m.Details = v.Details
		}
	}
	sort.Strings(m.Aliases)
	m.FixedVersion = highestFix(members)
	mergeExploit(&m, members)
	return &m
}

// mergeExploit gives the merged finding the strongest exploit signal of
// its members: listed in KEV if any member is, since the earliest date,
// and the highest EPSS with that member's percentile. The combining rule
// is exploit.MergeKEV and exploit.MergeEPSS, the same one the enricher
// uses for the CVE IDs of one advisory.
func mergeExploit(m *entity.Vulnerability, members []*entity.Vulnerability) {
	m.KEV, m.KEVDateAdded, m.EPSS, m.EPSSPercentile = false, nil, nil, nil
	for _, v := range members {
		exploit.MergeKEV(m, v.KEV, v.KEVDateAdded)
		exploit.MergeEPSS(m, v.EPSS, v.EPSSPercentile)
	}
}

// groupID picks the ID a merged group is reported under.
func groupID(members []*entity.Vulnerability) string {
	best := ""
	for _, v := range members {
		id := v.OSVID
		idCVE, bestCVE := isCVE(id), isCVE(best)
		switch {
		case best == "":
			best = id
		case idCVE && !bestCVE:
			best = id
		case idCVE == bestCVE && id < best:
			best = id
		}
	}
	return best
}

// isCVE reports whether id is a CVE ID (case-insensitive).
func isCVE(id string) bool {
	return strings.HasPrefix(strings.ToUpper(id), "CVE-")
}

// highestFix returns the highest fixed version of members, or nil if any
// member has no fix. Members that are malicious package advisories are
// left out unless every member is one.
func highestFix(members []*entity.Vulnerability) *string {
	candidates := make([]*entity.Vulnerability, 0, len(members))
	for _, v := range members {
		if !maliciousAdvisory(v) {
			candidates = append(candidates, v)
		}
	}
	if len(candidates) == 0 {
		candidates = members
	}
	best := ""
	for _, v := range candidates {
		f := fixedIn(v)
		if f == "" {
			return nil
		}
		if best == "" || newer(f, best) {
			best = f
		}
	}
	return &best
}

// newer reports whether version a is higher than b. Versions the analyzer
// cannot compare fall back to string order, so the choice stays stable.
func newer(a, b string) bool {
	if analyzer.CompareVersions(b, a) != "none" {
		return true
	}
	if analyzer.CompareVersions(a, b) != "none" {
		return false
	}
	return a > b
}

// maliciousAdvisory reports whether v is itself an OpenSSF malicious package
// advisory, not an advisory that only lists one among its aliases. Lookup
// reports an advisory that has a CVE alias under the CVE and puts the
// advisory's own ID first among the aliases (see aliasesFor in
// internal/usecase/vulnerability), so that ID is checked as well.
func maliciousAdvisory(v *entity.Vulnerability) bool {
	if entity.IsMaliciousID(v.OSVID) {
		return true
	}
	return isCVE(v.OSVID) && len(v.Aliases) > 0 && entity.IsMaliciousID(v.Aliases[0])
}
