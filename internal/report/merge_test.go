package report

import (
	"bytes"
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/orchesta/orbit/internal/domain/entity"
	"github.com/orchesta/orbit/internal/engine"
)

// lodashResult is lodash@4.17.15 with the two GitHub advisories for
// CVE-2021-23337 as Lookup reports them: both get the CVE as primary ID, list
// each other as aliases and differ in their fixed version.
func lodashResult() *engine.Result {
	dep := &entity.Dependency{ID: uuid.New(), Name: "lodash", CurrentVersion: "4.17.15", Ecosystem: entity.EcosystemNpm,
		ManifestFile: "package-lock.json", IsResolved: true}
	return &engine.Result{
		Dependencies: []*entity.Dependency{dep},
		Vulnerabilities: []*entity.Vulnerability{
			{ID: uuid.New(), DependencyID: dep.ID, OSVID: "CVE-2021-23337", Severity: entity.SeverityHigh,
				Aliases:      []string{"GHSA-35jh-r3h4-6jhm", "CVE-2021-23337", "GHSA-r5fr-rjxr-66jc"},
				FixedVersion: strp("4.17.21")},
			{ID: uuid.New(), DependencyID: dep.ID, OSVID: "CVE-2021-23337", Severity: entity.SeverityHigh,
				Aliases:      []string{"GHSA-r5fr-rjxr-66jc", "CVE-2021-23337", "GHSA-35jh-r3h4-6jhm"},
				FixedVersion: strp("4.18.0")},
		},
		VulnerableDeps: 1,
	}
}

func TestBuildMergesAliasedAdvisories(t *testing.T) {
	f, s := Build(lodashResult(), nil, entity.SeverityHigh, fixedNow)
	if len(f) != 1 {
		t.Fatalf("findings = %d, want 1 merged finding", len(f))
	}
	v := f[0].Vulnerability
	if v.OSVID != "CVE-2021-23337" || v.Severity != entity.SeverityHigh || fixedIn(v) != "4.18.0" {
		t.Fatalf("merged = %s %s fixed %q, want CVE-2021-23337 high fixed 4.18.0", v.OSVID, v.Severity, fixedIn(v))
	}
	if want := []string{"GHSA-35jh-r3h4-6jhm", "GHSA-r5fr-rjxr-66jc"}; !slices.Equal(v.Aliases, want) {
		t.Fatalf("aliases = %q, want %q", v.Aliases, want)
	}
	if s.BySeverity[entity.SeverityHigh] != 1 || s.Vulnerable != 1 || !s.Failed {
		t.Fatalf("summary = %+v, want one high finding", s)
	}
}

func TestBuildIgnoreOfEitherAdvisorySuppressesTheGroup(t *testing.T) {
	for _, id := range []string{"GHSA-35jh-r3h4-6jhm", "ghsa-r5fr-rjxr-66jc", "CVE-2021-23337"} {
		t.Run(id, func(t *testing.T) {
			l := &IgnoreList{Entries: []IgnoreEntry{{ID: id, Reason: "accepted"}}}
			f, s := Build(lodashResult(), l, entity.SeverityHigh, fixedNow)
			if len(f) != 1 || !f[0].Ignored || f[0].IgnoreReason != "accepted" {
				t.Fatalf("findings = %+v, want one ignored finding", f)
			}
			if s.Failed || s.BySeverity[entity.SeverityHigh] != 0 || len(s.Warnings) != 0 {
				t.Fatalf("summary = %+v, want passed with no warnings", s)
			}
		})
	}
}

// Every entry that matches a merged finding counts as used.
func TestBuildEntriesForBothAdvisoriesAreUsed(t *testing.T) {
	l := &IgnoreList{Entries: []IgnoreEntry{{ID: "GHSA-35jh-r3h4-6jhm", Reason: "a"}, {ID: "GHSA-r5fr-rjxr-66jc", Reason: "b"}}}
	_, s := Build(lodashResult(), l, entity.SeverityHigh, fixedNow)
	if len(s.Warnings) != 0 {
		t.Fatalf("warnings = %q, want none", s.Warnings)
	}
}

func TestBuildMergesTransitivelyAndOnlyPerDependency(t *testing.T) {
	a := &entity.Dependency{ID: uuid.New(), Name: "a", CurrentVersion: "1.0.0", Ecosystem: entity.EcosystemNpm, ManifestFile: "m"}
	b := &entity.Dependency{ID: uuid.New(), Name: "b", CurrentVersion: "1.0.0", Ecosystem: entity.EcosystemNpm, ManifestFile: "m"}
	v := func(d *entity.Dependency, id string, sev entity.Severity, sum string, fix *string, refs []string, aliases ...string) *entity.Vulnerability {
		return &entity.Vulnerability{ID: uuid.New(), DependencyID: d.ID, OSVID: id, Severity: sev, Summary: sum,
			FixedVersion: fix, References: refs, Aliases: aliases}
	}
	res := &engine.Result{
		Dependencies: []*entity.Dependency{a, b},
		Vulnerabilities: []*entity.Vulnerability{
			v(a, "GHSA-x", entity.SeverityLow, "", strp("1.2.0"), nil, "OSV-y"),
			v(a, "PYSEC-z", entity.SeverityCritical, "", strp("1.10.0"), []string{"https://example.com/z"}, "OSV-y"),
			v(a, "GHSA-w", entity.SeverityMedium, "z summary", strp("1.3.0"), []string{"https://example.com/w"}, "pysec-z"),
			v(a, "GHSA-other", entity.SeverityLow, "unrelated", nil, nil),
			v(b, "GHSA-x", entity.SeverityLow, "same advisory, other package", nil, nil),
		},
	}
	f, s := Build(res, nil, "", fixedNow)
	if len(f) != 3 {
		t.Fatalf("findings = %d, want 3 (one merged group on a, one unrelated on a, one on b)", len(f))
	}
	m := f[0]
	if m.Dependency != a || m.Vulnerability.Severity != entity.SeverityCritical {
		t.Fatalf("first finding = %s on %s, want the critical group on a", m.Vulnerability.OSVID, m.Dependency.Name)
	}
	mv := m.Vulnerability
	if mv.OSVID != "GHSA-w" {
		t.Errorf("group ID = %s, want GHSA-w (no CVE: smallest member ID)", mv.OSVID)
	}
	if want := []string{"GHSA-x", "OSV-y", "PYSEC-z"}; !slices.Equal(mv.Aliases, want) {
		t.Errorf("aliases = %q, want %q", mv.Aliases, want)
	}
	if mv.Summary != "z summary" || fixedIn(mv) != "1.10.0" {
		t.Errorf("summary %q fixed %q, want the non-empty summary and the highest fix 1.10.0", mv.Summary, fixedIn(mv))
	}
	if len(mv.References) != 2 || mv.References[0] != "https://example.com/z" {
		t.Errorf("references = %q, want the most severe member's first", mv.References)
	}
	if s.BySeverity[entity.SeverityCritical] != 1 || s.BySeverity[entity.SeverityLow] != 2 || s.Vulnerable != 2 {
		t.Errorf("summary = %+v", s)
	}
	for _, v := range res.Vulnerabilities {
		if v.OSVID == "GHSA-x" && v.DependencyID == a.ID && (v.Severity != entity.SeverityLow || len(v.Aliases) != 1) {
			t.Error("Build modified its input")
		}
	}
}

func TestBuildMergedGroupWithoutFixHasNoFix(t *testing.T) {
	res := lodashResult()
	res.Vulnerabilities[1].FixedVersion = nil
	f, _ := Build(res, nil, "", fixedNow)
	if len(f) != 1 || f[0].Vulnerability.FixedVersion != nil {
		t.Fatalf("fixed = %v, want none: one advisory has no fix", f[0].Vulnerability.FixedVersion)
	}
	var b bytes.Buffer
	if err := WriteTable(&b, f, Summary{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), "lodash@4.17.15  -") {
		t.Errorf("table should show no fix:\n%s", b.String())
	}
}

// The SARIF rule takes the first non-empty summary and help URI among the
// findings that share an advisory ID, not just the first finding's.
func TestSARIFRulePrefersNonEmptyText(t *testing.T) {
	d1 := &entity.Dependency{ID: uuid.New(), Name: "p", CurrentVersion: "1", ManifestFile: "m", Ecosystem: "npm"}
	d2 := &entity.Dependency{ID: uuid.New(), Name: "q", CurrentVersion: "1", ManifestFile: "m", Ecosystem: "npm"}
	res := &engine.Result{Dependencies: []*entity.Dependency{d1, d2}, Vulnerabilities: []*entity.Vulnerability{
		{DependencyID: d1.ID, OSVID: "A-1", Severity: entity.SeverityHigh},
		{DependencyID: d2.ID, OSVID: "A-1", Severity: entity.SeverityHigh, Summary: "real summary", References: []string{"https://example.com/a1"}},
	}}
	f, s := Build(res, nil, "", fixedNow)
	var b bytes.Buffer
	if err := WriteSARIF(&b, f, s, ToolInfo{Name: "orbit"}, SARIFOptions{}); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Runs []struct {
			Tool struct {
				Driver struct {
					Rules []struct {
						Short   struct{ Text string } `json:"shortDescription"`
						HelpURI string                `json:"helpUri"`
					}
				}
			}
		}
	}
	if err := json.Unmarshal(b.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	r := doc.Runs[0].Tool.Driver.Rules
	if len(r) != 1 || r[0].Short.Text != "real summary" || r[0].HelpURI != "https://example.com/a1" {
		t.Fatalf("rules = %+v", r)
	}
}

func TestDependencySortBreaksTiesByEcosystem(t *testing.T) {
	mk := func(eco entity.Ecosystem) *entity.Dependency {
		return &entity.Dependency{ID: uuid.New(), Name: "p", CurrentVersion: "1", ManifestFile: "m", Ecosystem: eco}
	}
	res := &engine.Result{Dependencies: []*entity.Dependency{mk("npm"), mk("PyPI")}}
	_, s := Build(res, nil, "", fixedNow)
	if s.Deps[0].Ecosystem != "PyPI" || s.Deps[1].Ecosystem != "npm" {
		t.Fatalf("deps order = %s, %s; want PyPI, npm", s.Deps[0].Ecosystem, s.Deps[1].Ecosystem)
	}
}

func TestMatchUsesEcosystemPackageRules(t *testing.T) {
	l := &IgnoreList{Entries: []IgnoreEntry{{ID: "X-1", Package: "Zope_Interface", Reason: "r"}}}
	if _, ok := l.Match("X-1", nil, "zope.interface", entity.EcosystemPyPI, fixedNow); !ok {
		t.Error("PyPI names must match by PEP 503 normalisation")
	}
	if _, ok := l.Match("X-1", nil, "zope.interface", entity.EcosystemNpm, fixedNow); ok {
		t.Error("npm names must match exactly")
	}
}

// Two advisories for one CVE where only the lower-ranked one carries the
// KEV listing: the merged finding keeps the strongest signal. Lookup reports
// both under the CVE with their own GHSA ID as an alias.
func TestBuildMergedGroupKeepsTheStrongestExploitSignal(t *testing.T) {
	dep := &entity.Dependency{ID: uuid.New(), Name: "jquery", CurrentVersion: "3.4.1", Ecosystem: entity.EcosystemNpm, ManifestFile: "package-lock.json"}
	added := time.Date(2025, 1, 23, 0, 0, 0, 0, time.UTC)
	high, pctHigh, low, pctLow := 0.84887, 0.9971, 0.2, 0.9
	res := &engine.Result{
		Dependencies: []*entity.Dependency{dep},
		Vulnerabilities: []*entity.Vulnerability{
			{ID: uuid.New(), DependencyID: dep.ID, OSVID: "CVE-2020-11023", Aliases: []string{"GHSA-aaaa-aaaa-aaaa"},
				Severity: entity.SeverityHigh, EPSS: &low, EPSSPercentile: &pctLow},
			{ID: uuid.New(), DependencyID: dep.ID, OSVID: "CVE-2020-11023", Aliases: []string{"GHSA-jpcq-cgw6-v4j6"},
				Severity: entity.SeverityMedium, KEV: true, KEVDateAdded: &added, EPSS: &high, EPSSPercentile: &pctHigh},
		},
	}
	f, s := Build(res, nil, entity.SeverityCritical, fixedNow)
	if len(f) != 1 {
		t.Fatalf("findings = %d, want 1", len(f))
	}
	v := f[0].Vulnerability
	if v.OSVID != "CVE-2020-11023" || v.Severity != entity.SeverityHigh || !v.KEV || !v.KEVDateAdded.Equal(added) ||
		*v.EPSS != high || *v.EPSSPercentile != pctHigh {
		t.Fatalf("merged = %+v", v)
	}
	if s.KEVFindings != 1 {
		t.Fatalf("KEV findings = %d, want 1", s.KEVFindings)
	}
}
