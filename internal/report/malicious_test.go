package report

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"slices"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/orchesta/orbit/internal/domain/entity"
	"github.com/orchesta/orbit/internal/engine"
)

func npmDep(name, version string) *entity.Dependency {
	return &entity.Dependency{ID: uuid.New(), Name: name, CurrentVersion: version, Ecosystem: entity.EcosystemNpm,
		ManifestFile: "package-lock.json", IsResolved: true}
}

// debugGitHubAdvisory is the GitHub advisory for debug@4.4.2 as Lookup
// reports it (osv.dev, October 2026): rated high, fixed in 4.4.3, under
// CVE-2025-59144 with the MAL- advisory among its aliases.
func debugGitHubAdvisory(dep uuid.UUID) *entity.Vulnerability {
	return &entity.Vulnerability{ID: uuid.New(), DependencyID: dep, OSVID: "CVE-2025-59144", Severity: entity.SeverityHigh,
		Summary:      "debug@4.4.2 contains malware after npm account takeover",
		Aliases:      []string{"GHSA-4x49-vf9v-38px", "GHSA-8mgj-vmr8-frr6", "MAL-2025-46974"},
		FixedVersion: strp("4.4.3"),
		References:   []string{"https://github.com/debug-js/debug/security/advisories/GHSA-4x49-vf9v-38px"}}
}

// debugMalAdvisory is the unscored MAL- advisory for debug@4.4.2 as Lookup
// reports it: rated critical, under CVE-2025-59144 with its own ID first
// among the aliases, and no fix.
func debugMalAdvisory(dep uuid.UUID) *entity.Vulnerability {
	return &entity.Vulnerability{ID: uuid.New(), DependencyID: dep, OSVID: "CVE-2025-59144", Severity: entity.SeverityCritical,
		Summary: "Malicious code in debug (npm)",
		Aliases: []string{"MAL-2025-46974", "GHSA-4x49-vf9v-38px", "GHSA-8mgj-vmr8-frr6"}}
}

// maliciousResult is what Lookup reports for three npm packages (osv.dev,
// October 2026): debug@4.4.2 has the GitHub advisory (high, fixed in 4.4.3)
// and the unscored MAL- advisory, both under CVE-2025-59144; chalk@5.6.1 has
// only a MAL- advisory; lodash has an ordinary critical advisory.
func maliciousResult() *engine.Result {
	debug, chalk, lodash := npmDep("debug", "4.4.2"), npmDep("chalk", "5.6.1"), npmDep("lodash", "4.17.15")
	return &engine.Result{
		Dependencies: []*entity.Dependency{debug, chalk, lodash},
		Vulnerabilities: []*entity.Vulnerability{
			debugGitHubAdvisory(debug.ID),
			debugMalAdvisory(debug.ID),
			{ID: uuid.New(), DependencyID: chalk.ID, OSVID: "MAL-2025-46969", Severity: entity.SeverityCritical,
				Summary: "Malicious code in chalk (npm)", Aliases: []string{"GHSA-2v46-p5h4-248w"},
				References: []string{"https://github.com/advisories/GHSA-2v46-p5h4-248w"}},
			{ID: uuid.New(), DependencyID: lodash.ID, OSVID: "GHSA-crit-0003", Severity: entity.SeverityCritical,
				Summary: "Remote code execution"},
		},
		VulnerableDeps: 3,
	}
}

// debugGitHubOnly is debug@4.4.2 when osv.dev returns only the GitHub
// advisory: rated high, with the MAL- advisory among its aliases.
func debugGitHubOnly() *engine.Result {
	debug := npmDep("debug", "4.4.2")
	return &engine.Result{
		Dependencies:    []*entity.Dependency{debug},
		Vulnerabilities: []*entity.Vulnerability{debugGitHubAdvisory(debug.ID)},
		VulnerableDeps:  1,
	}
}

func TestBuildMergesMaliciousWithGitHubAdvisory(t *testing.T) {
	f, s := Build(maliciousResult(), nil, entity.SeverityHigh, fixedNow)
	var ids []string
	for _, x := range f {
		ids = append(ids, x.Vulnerability.OSVID)
	}
	// Malicious findings first, then by severity and ID.
	if want := []string{"CVE-2025-59144", "MAL-2025-46969", "GHSA-crit-0003"}; !slices.Equal(ids, want) {
		t.Fatalf("order = %q, want %q", ids, want)
	}
	debug := f[0]
	if !debug.Malicious || debug.Vulnerability.Severity != entity.SeverityCritical || debug.Dependency.Name != "debug" {
		t.Fatalf("debug = %+v malicious=%v, want the merged critical malicious finding", debug.Vulnerability, debug.Malicious)
	}
	if want := []string{"GHSA-4x49-vf9v-38px", "GHSA-8mgj-vmr8-frr6", "MAL-2025-46974"}; !slices.Equal(debug.Vulnerability.Aliases, want) {
		t.Fatalf("debug aliases = %q, want %q", debug.Vulnerability.Aliases, want)
	}
	// The MAL- advisory names no fix; the GitHub advisory's fix is kept.
	if got := fixedIn(debug.Vulnerability); got != "4.4.3" {
		t.Fatalf("debug fixed in %q, want 4.4.3 from the GitHub advisory", got)
	}
	if !f[1].Malicious || f[2].Malicious {
		t.Fatalf("malicious = %v %v, want chalk true and lodash false", f[1].Malicious, f[2].Malicious)
	}
	if s.Malicious != 2 || s.BySeverity[entity.SeverityCritical] != 3 || s.Vulnerable != 3 || !s.Failed {
		t.Fatalf("summary = %+v, want 2 malicious, 3 critical, failed", s)
	}
}

func TestBuildMaliciousFailsAtEveryThreshold(t *testing.T) {
	for _, th := range []entity.Severity{entity.SeverityCritical, entity.SeverityHigh, entity.SeverityMedium,
		entity.SeverityLow, entity.SeverityUnknown} {
		_, s := Build(debugGitHubOnly(), nil, th, fixedNow)
		if !s.Failed || s.Malicious != 1 {
			t.Errorf("threshold %s: failed=%v malicious=%d, want a failure for a high malicious finding", th, s.Failed, s.Malicious)
		}
	}
	if _, s := Build(debugGitHubOnly(), nil, "", fixedNow); s.Failed {
		t.Error("--fail-on none must not fail, even on a malicious package")
	}
}

// A MAL- advisory names no fix. Merged with an ordinary advisory, the group
// keeps that advisory's fix; a group of MAL- advisories alone has none; an
// ordinary member without a fix still leaves the group without one.
func TestMergeTakesTheFixFromNonMaliciousMembers(t *testing.T) {
	dep := uuid.New()
	gh, mal := debugGitHubAdvisory(dep), debugMalAdvisory(dep)
	other := &entity.Vulnerability{DependencyID: dep, OSVID: "MAL-2025-99999", Severity: entity.SeverityCritical,
		Aliases: []string{"MAL-2025-46974"}}
	nofix := &entity.Vulnerability{DependencyID: dep, OSVID: "GHSA-zzzz-zzzz-zzzz", Severity: entity.SeverityHigh,
		Aliases: []string{"CVE-2025-59144"}}
	if !maliciousAdvisory(mal) || !maliciousAdvisory(other) || maliciousAdvisory(gh) || maliciousAdvisory(nofix) {
		t.Fatal("maliciousAdvisory must recognise the MAL- records only, not advisories that list one as an alias")
	}
	cases := []struct {
		name    string
		members []*entity.Vulnerability
		want    string
	}{
		{"GitHub and MAL-", []*entity.Vulnerability{mal, gh}, "4.4.3"},
		{"MAL- only", []*entity.Vulnerability{mal, other}, ""},
		{"ordinary member without a fix", []*entity.Vulnerability{gh, mal, nofix}, ""},
	}
	for _, c := range cases {
		got := mergeAliases(c.members)
		if len(got) != 1 {
			t.Fatalf("%s: %d findings, want one merged finding", c.name, len(got))
		}
		if fix := fixedIn(got[0]); fix != c.want {
			t.Errorf("%s: fixed in %q, want %q", c.name, fix, c.want)
		}
	}
}

func TestBuildDoesNotIgnoreMaliciousFindings(t *testing.T) {
	l := &IgnoreList{Entries: []IgnoreEntry{
		{ID: "CVE-2025-59144", Reason: "not reachable"},
		{ID: "mal-2025-46969", Package: "chalk", Reason: "reviewed"},
		{ID: "GHSA-crit-0003", Reason: "accepted"},
	}}
	f, s := Build(maliciousResult(), l, entity.SeverityCritical, fixedNow)
	if f[0].Ignored || f[1].Ignored || !f[2].Ignored {
		t.Fatalf("ignored = %v %v %v, want only lodash ignored", f[0].Ignored, f[1].Ignored, f[2].Ignored)
	}
	if !s.Failed || s.Malicious != 2 || s.BySeverity[entity.SeverityCritical] != 2 {
		t.Fatalf("summary = %+v, want failed with 2 malicious critical findings", s)
	}
	// The exact match also shows that no matching entry is reported unused.
	want := []string{
		"ignore entry CVE-2025-59144 not applied: debug@4.4.2 is a known malicious package (MAL-2025-46974)",
		"ignore entry mal-2025-46969 not applied: chalk@5.6.1 is a known malicious package (MAL-2025-46969)",
	}
	if !slices.Equal(s.Warnings, want) {
		t.Fatalf("warnings = %q, want %q", s.Warnings, want)
	}
}

func TestTableMarksMaliciousFindings(t *testing.T) {
	f, s := Build(maliciousResult(), nil, entity.SeverityHigh, fixedNow)
	var b bytes.Buffer
	if err := WriteTable(&b, f, s); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(b.String(), "\n")
	for i, prefix := range map[int]string{
		1: "CRITICAL (malicious)  CVE-2025-59144  debug@4.4.2 ",
		2: "CRITICAL (malicious)  MAL-2025-46969  chalk@5.6.1 ",
		3: "CRITICAL              GHSA-crit-0003  lodash@4.17.15",
	} {
		if !strings.HasPrefix(lines[i], prefix) {
			t.Errorf("line %d = %q, want prefix %q", i, lines[i], prefix)
		}
	}
	if want := "3 dependencies, 3 vulnerable (3 critical), 2 malicious\n"; !strings.Contains(b.String(), want) {
		t.Errorf("summary line missing %q:\n%s", want, b.String())
	}
}

func TestTableSummaryOmitsZeroMalicious(t *testing.T) {
	f, s := build(t, entity.SeverityHigh)
	var b bytes.Buffer
	if err := WriteTable(&b, f, s); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(b.String(), "malicious") {
		t.Errorf("no malicious findings, but the table mentions them:\n%s", b.String())
	}
}

func TestJSONReportsMalicious(t *testing.T) {
	f, s := Build(maliciousResult(), nil, entity.SeverityHigh, fixedNow)
	var b bytes.Buffer
	if err := WriteJSON(&b, f, s, testTool); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Summary struct {
			Malicious int `json:"malicious"`
		} `json:"summary"`
		Findings []struct {
			ID        string `json:"id"`
			Malicious bool   `json:"malicious"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(b.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	type row struct {
		id  string
		mal bool
	}
	var got []row
	for _, x := range doc.Findings {
		got = append(got, row{x.ID, x.Malicious})
	}
	want := []row{{"CVE-2025-59144", true}, {"MAL-2025-46969", true}, {"GHSA-crit-0003", false}}
	if !slices.Equal(got, want) || doc.Summary.Malicious != 2 {
		t.Fatalf("findings = %v summary.malicious = %d, want %v and 2", got, doc.Summary.Malicious, want)
	}
	if !strings.Contains(b.String(), `"malicious": false`) {
		t.Error(`"malicious" must be present on every finding, also when false`)
	}
}

func TestSARIFMarksMaliciousRules(t *testing.T) {
	f, s := Build(maliciousResult(), nil, entity.SeverityHigh, fixedNow)
	var b bytes.Buffer
	if err := WriteSARIF(&b, f, s, testTool, SARIFOptions{}); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Runs []struct {
			Tool struct {
				Driver struct {
					Rules []struct {
						ID         string `json:"id"`
						Properties struct {
							SecuritySeverity string   `json:"security-severity"`
							Tags             []string `json:"tags"`
						} `json:"properties"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID  string                `json:"ruleId"`
				Level   string                `json:"level"`
				Message struct{ Text string } `json:"message"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(b.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	type rule struct{ id, sev, tags string }
	var got []rule
	for _, r := range doc.Runs[0].Tool.Driver.Rules {
		got = append(got, rule{r.ID, r.Properties.SecuritySeverity, strings.Join(r.Properties.Tags, ",")})
	}
	want := []rule{
		{"CVE-2025-59144", "10.0", "security,malicious"},
		{"MAL-2025-46969", "10.0", "security,malicious"},
		{"GHSA-crit-0003", "9.5", ""},
	}
	if !slices.Equal(got, want) {
		t.Fatalf("rules = %v, want %v", got, want)
	}
	res := doc.Runs[0].Results
	// The merged debug finding keeps the GitHub advisory's fix (see highestFix).
	if res[0].Level != "error" || res[0].Message.Text != "debug@4.4.2 is a known malicious package (MAL-2025-46974); remove or replace it (fixed in 4.4.3)" {
		t.Errorf("result 0 = %+v", res[0])
	}
	if res[1].Message.Text != "chalk@5.6.1 is a known malicious package (MAL-2025-46969); remove or replace it" {
		t.Errorf("result 1 = %+v", res[1])
	}
	if res[2].Message.Text != "lodash@4.17.15 is affected by GHSA-crit-0003 (no fix available)" {
		t.Errorf("ordinary result message changed: %q", res[2].Message.Text)
	}
}

// The GitHub advisory alone is rated high; with --fail-on critical it must
// still be a JUnit failure, typed malicious.
func TestJUnitMaliciousFailureType(t *testing.T) {
	f, s := Build(debugGitHubOnly(), nil, entity.SeverityCritical, fixedNow)
	var b bytes.Buffer
	if err := WriteJUnit(&b, f, s); err != nil {
		t.Fatal(err)
	}
	var suite struct {
		Failures int `xml:"failures,attr"`
		Cases    []struct {
			Failure *struct {
				Message string `xml:"message,attr"`
				Type    string `xml:"type,attr"`
				Body    string `xml:",chardata"`
			} `xml:"failure"`
		} `xml:"testcase"`
	}
	if err := xml.Unmarshal(b.Bytes(), &suite); err != nil {
		t.Fatal(err)
	}
	if suite.Failures != 1 || len(suite.Cases) != 1 || suite.Cases[0].Failure == nil {
		t.Fatalf("want one failure:\n%s", b.String())
	}
	fl := suite.Cases[0].Failure
	if fl.Type != "malicious" ||
		fl.Message != "high: debug@4.4.2 contains malware after npm account takeover" ||
		fl.Body != "debug@4.4.2 is a known malicious package (MAL-2025-46974) (fixed in 4.4.3)" {
		t.Fatalf("failure = %+v", fl)
	}
}
