package report

import (
	"bytes"
	"maps"
	"strings"
	"testing"

	"github.com/orchesta/orbit/internal/domain/entity"
	"github.com/orchesta/orbit/internal/engine"
)

// fixtureBaselineJSON is a report from an older orbit on older versions:
//   - lodash GHSA-crit-0003 (another version) is still present;
//   - Django lists cve-2020-0002 as an alias, so django's GHSA-high-0002
//     (alias CVE-2020-0002) is the same issue (PEP 503 name, any ID case);
//   - GHSA-esc-0005 is on PyPI express, not npm express, so it does not match.
const fixtureBaselineJSON = `{
  "schema_version": 1,
  "tool": {"name": "orbit", "version": "1.0.0", "information_uri": ""},
  "summary": {"dependencies": 2},
  "recommendations": [],
  "findings": [
    {"id": "GHSA-crit-0003", "aliases": [], "package": "lodash", "version": "4.17.10", "ecosystem": "npm", "kev": false},
    {"id": "GHSA-other-9999", "aliases": ["cve-2020-0002"], "package": "Django", "version": "2.2.0", "ecosystem": "PyPI"},
    {"id": "GHSA-esc-0005", "aliases": [], "package": "express", "version": "4.18.2", "ecosystem": "PyPI"}
  ]
}`

func fixtureBaseline(t *testing.T) *Baseline {
	t.Helper()
	b, err := ParseBaseline([]byte(fixtureBaselineJSON))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestParseBaselineReadsToolAndFindings(t *testing.T) {
	b := fixtureBaseline(t)
	if b.ToolVersion != "1.0.0" || b.Len() != 3 {
		t.Errorf("tool version %q, %d findings; want 1.0.0, 3", b.ToolVersion, b.Len())
	}
}

func TestParseBaselineAcceptsUTF8BOM(t *testing.T) {
	b, err := ParseBaseline(append([]byte("\ufeff"), fixtureBaselineJSON...))
	if err != nil || b.Len() != 3 {
		t.Fatalf("BOM: %v, %+v", err, b)
	}
}

func TestParseBaselineErrors(t *testing.T) {
	utf16 := []byte{0xFF, 0xFE, '{', 0, '}', 0}
	cases := map[string]struct {
		data string
		want string
	}{
		"empty":          {"", "is empty"},
		"blank":          {" \n\t", "is empty"},
		"bom only":       {"\ufeff", "is empty"},
		"utf-16":         {string(utf16), "UTF-16"},
		"truncated":      {`{"schema_version": 1, "findings": [`, "not an orbit JSON report"},
		"array":          {`[]`, "not an orbit JSON report"},
		"trailing data":  {`{"schema_version": 1, "findings": []} {}`, "not an orbit JSON report"},
		"sarif":          {`{"version": "2.1.0", "runs": []}`, "no schema_version"},
		"newer schema":   {`{"schema_version": 2, "findings": []}`, "schema_version 2 is not supported"},
		"no findings":    {`{"schema_version": 1}`, "no findings array"},
		"null findings":  {`{"schema_version": 1, "findings": null}`, "no findings array"},
		"no package":     {`{"schema_version": 1, "findings": [{"id": "X-1", "ecosystem": "npm"}]}`, "finding 1"},
		"no id":          {`{"schema_version": 1, "findings": [{"package": "p", "ecosystem": "npm"}]}`, "finding 1"},
		"no ecosystem":   {`{"schema_version": 1, "findings": [{"id": "X-1", "package": "p"}]}`, "finding 1"},
		"string version": {`{"schema_version": "1", "findings": []}`, "not an orbit JSON report"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := ParseBaseline([]byte(c.data))
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want it to contain %q", err, c.want)
			}
		})
	}
}

func TestBaselineContains(t *testing.T) {
	b, err := ParseBaseline([]byte(`{"schema_version": 1, "findings": [
	  {"id": "GHSA-aaaa", "aliases": ["CVE-2024-0001"], "package": "Django_Rest.Framework", "ecosystem": "PyPI"},
	  {"id": "GHSA-bbbb", "aliases": [], "package": "Newtonsoft.Json", "ecosystem": "NuGet"},
	  {"id": "GHSA-cccc", "aliases": [], "package": "lodash", "ecosystem": "npm"},
	  {"id": "GO-2024-0001", "aliases": [], "package": "github.com/Sirupsen/logrus", "ecosystem": "Go"}
	]}`))
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name    string
		eco     entity.Ecosystem
		pkg, id string
		aliases []string
		want    bool
	}{
		{"same id", entity.EcosystemNpm, "lodash", "GHSA-cccc", nil, true},
		{"id case", entity.EcosystemNpm, "lodash", "ghsa-cccc", nil, true},
		{"current id is a baseline alias", entity.EcosystemPyPI, "django-rest-framework", "CVE-2024-0001", nil, true},
		{"current alias is the baseline id", entity.EcosystemPyPI, "django-rest-framework", "CVE-2024-0001", []string{"ghsa-aaaa"}, true},
		{"pep 503 name", entity.EcosystemPyPI, "DJANGO-REST-FRAMEWORK", "GHSA-aaaa", nil, true},
		{"nuget name case", entity.EcosystemNuGet, "newtonsoft.json", "GHSA-bbbb", nil, true},
		{"npm name is exact", entity.EcosystemNpm, "Lodash", "GHSA-cccc", nil, false},
		{"go path is exact", entity.EcosystemGo, "github.com/sirupsen/logrus", "GO-2024-0001", nil, false},
		{"go path match", entity.EcosystemGo, "github.com/Sirupsen/logrus", "GO-2024-0001", nil, true},
		{"other ecosystem", entity.EcosystemPyPI, "lodash", "GHSA-cccc", nil, false},
		{"other package", entity.EcosystemNpm, "underscore", "GHSA-cccc", nil, false},
		{"other advisory", entity.EcosystemNpm, "lodash", "GHSA-dddd", []string{"CVE-2024-9999"}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := b.Contains(c.eco, c.pkg, c.id, c.aliases); got != c.want {
				t.Errorf("Contains = %v, want %v", got, c.want)
			}
		})
	}
}

// An orbit before the alias merge wrote one finding per GitHub advisory; the
// merged finding is now reported under the CVE. osv.dev may also add an alias
// later. Either way the finding is not new.
func TestBaselineContainsAcrossAliasDrift(t *testing.T) {
	b, err := ParseBaseline([]byte(`{"schema_version": 1, "findings": [
	  {"id": "GHSA-35jh-r3h4-6jhm", "aliases": ["CVE-2021-23337"], "package": "lodash", "ecosystem": "npm"},
	  {"id": "GHSA-r5fr-rjxr-66jc", "aliases": [], "package": "lodash", "ecosystem": "npm"}
	]}`))
	if err != nil {
		t.Fatal(err)
	}
	if !b.Contains(entity.EcosystemNpm, "lodash", "CVE-2021-23337", []string{"GHSA-35jh-r3h4-6jhm", "GHSA-r5fr-rjxr-66jc"}) {
		t.Error("merged finding under the CVE must match the two old GHSA findings")
	}
	if !b.Contains(entity.EcosystemNpm, "lodash", "CVE-2099-0001", []string{"GHSA-r5fr-rjxr-66jc"}) {
		t.Error("a finding whose primary ID changed must match through a shared alias")
	}
}

// Whatever WriteJSON writes, ParseBaseline reads back, and every finding of
// the report is in the resulting baseline.
func TestBaselineRoundTripsWriteJSON(t *testing.T) {
	f, s := build(t, entity.SeverityHigh)
	var buf bytes.Buffer
	if err := WriteJSON(&buf, f, s, testTool); err != nil {
		t.Fatal(err)
	}
	b, err := ParseBaseline(buf.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if b.Len() != len(f) || b.ToolVersion != testTool.Version {
		t.Fatalf("Len = %d, ToolVersion = %q", b.Len(), b.ToolVersion)
	}
	for _, x := range f {
		if !b.Contains(x.Dependency.Ecosystem, x.Dependency.Name, x.Vulnerability.OSVID, x.Vulnerability.Aliases) {
			t.Errorf("%s on %s missing from its own baseline", x.Vulnerability.OSVID, x.Dependency.Name)
		}
	}
}

func TestBuildWithoutBaselineMarksEveryFindingNew(t *testing.T) {
	f, s := build(t, entity.SeverityHigh)
	for _, x := range f {
		if !x.New {
			t.Errorf("%s: New = false without a baseline", x.Vulnerability.OSVID)
		}
	}
	if s.Baseline || s.New != 4 { // five findings, one ignored
		t.Errorf("Baseline = %v, New = %d; want false, 4", s.Baseline, s.New)
	}
}

func TestApplyBaselineMarksExistingFindings(t *testing.T) {
	f, s := build(t, entity.SeverityHigh)
	ApplyBaseline(f, &s, fixtureBaseline(t))
	got := map[string]bool{}
	for _, x := range f {
		got[x.Vulnerability.OSVID] = x.New
	}
	want := map[string]bool{
		"GHSA-crit-0003": false, "GHSA-esc-0005": true, "GHSA-high-0002": false,
		"GHSA-medium-0001": true, "GHSA-low-0004": true,
	}
	if !maps.Equal(got, want) {
		t.Errorf("New = %v, want %v", got, want)
	}
	if !s.Baseline || s.New != 2 || !s.Failed {
		t.Errorf("Baseline %v, New %d, Failed %v; want true, 2 (esc, medium), true (esc is high and new)", s.Baseline, s.New, s.Failed)
	}
	// Existing findings are still counted and reported.
	if s.Vulnerable != 3 || s.BySeverity[entity.SeverityCritical] != 1 || s.BySeverity[entity.SeverityHigh] != 2 {
		t.Errorf("counts changed: %+v", s)
	}
}

func TestApplyBaselineExistingFindingsDoNotFail(t *testing.T) {
	f, s := build(t, entity.SeverityCritical)
	if !s.Failed || !s.ThresholdFailed {
		t.Fatal("without a baseline the critical finding fails")
	}
	ApplyBaseline(f, &s, fixtureBaseline(t))
	if s.Failed || s.ThresholdFailed {
		t.Errorf("Failed %v, ThresholdFailed %v: the only critical finding is in the baseline; must not fail", s.Failed, s.ThresholdFailed)
	}
}

func TestApplyBaselineIgnoredNewFindingDoesNotFail(t *testing.T) {
	res := fixtureResult()
	res.Vulnerabilities = res.Vulnerabilities[3:4] // GHSA-low-0004, ignored
	f, s := Build(res, fixtureIgnores(), entity.SeverityLow, fixedNow)
	ApplyBaseline(f, &s, fixtureBaseline(t))
	if !f[0].New || s.Failed || s.New != 0 {
		t.Errorf("New %v, Failed %v, s.New %d; want true, false, 0", f[0].New, s.Failed, s.New)
	}
}

func TestApplyBaselineNilChangesNothing(t *testing.T) {
	f, s := build(t, entity.SeverityHigh)
	before := s
	ApplyBaseline(f, &s, nil)
	if s.Baseline || s.New != before.New || s.Failed != before.Failed ||
		s.ThresholdFailed != before.ThresholdFailed || s.KEVFailed != before.KEVFailed {
		t.Errorf("summary changed: %+v", s)
	}
	for _, x := range f {
		if !x.New {
			t.Errorf("%s: New = false after a nil baseline", x.Vulnerability.OSVID)
		}
	}
}

// --fail-on-kev also counts only new findings.
func TestApplyBaselineExistingKEVFindingDoesNotFail(t *testing.T) {
	res := fixtureResult()
	res.Vulnerabilities = res.Vulnerabilities[2:3] // GHSA-crit-0003 on lodash
	res.Vulnerabilities[0].Severity = entity.SeverityLow
	res.Vulnerabilities[0].KEV = true
	f, s := BuildWithOptions(res, nil, BuildOptions{FailOnKEV: true}, fixedNow)
	if !s.Failed || !s.KEVFailed {
		t.Fatalf("Failed %v, KEVFailed %v: a new KEV finding must fail with --fail-on-kev", s.Failed, s.KEVFailed)
	}
	ApplyBaseline(f, &s, fixtureBaseline(t))
	if s.Failed || s.KEVFailed {
		t.Errorf("Failed %v, KEVFailed %v: a KEV finding in the baseline must not fail", s.Failed, s.KEVFailed)
	}
}

// A new KEV finding below the threshold fails --fail-on-kev only: the
// threshold part stays false after ApplyBaseline, the KEV part true.
func TestApplyBaselineNewKEVFindingKeepsGateParts(t *testing.T) {
	res := fixtureResult()
	res.Vulnerabilities = res.Vulnerabilities[0:1] // GHSA-medium-0001 on lodash, not in the baseline
	res.Vulnerabilities[0].KEV = true
	f, s := BuildWithOptions(res, nil, BuildOptions{Threshold: entity.SeverityHigh, FailOnKEV: true}, fixedNow)
	ApplyBaseline(f, &s, fixtureBaseline(t))
	if !f[0].New || !s.Failed || !s.KEVFailed || s.ThresholdFailed {
		t.Errorf("New %v, Failed %v, KEVFailed %v, ThresholdFailed %v; want true, true, true, false",
			f[0].New, s.Failed, s.KEVFailed, s.ThresholdFailed)
	}
}

// A malicious package fails even when the baseline lists it: "it was there
// before" is no reason to keep one. --fail-on none still turns it off.
func TestApplyBaselineMaliciousFindingAlwaysFails(t *testing.T) {
	malicious := func() *engine.Result {
		res := fixtureResult()
		res.Vulnerabilities = res.Vulnerabilities[2:3] // GHSA-crit-0003 on lodash, in the baseline
		res.Vulnerabilities[0].Aliases = []string{"MAL-2025-0003"}
		return res
	}
	f, s := Build(malicious(), nil, entity.SeverityHigh, fixedNow)
	ApplyBaseline(f, &s, fixtureBaseline(t))
	if f[0].New || !f[0].Malicious || s.New != 0 || !s.Failed || !s.ThresholdFailed {
		t.Errorf("New %v, Malicious %v, s.New %d, Failed %v, ThresholdFailed %v; want false, true, 0, true, true",
			f[0].New, f[0].Malicious, s.New, s.Failed, s.ThresholdFailed)
	}
	f, s = Build(malicious(), nil, "", fixedNow)
	ApplyBaseline(f, &s, fixtureBaseline(t))
	if s.Failed {
		t.Error("--fail-on none must not fail, even on a malicious package")
	}
}

// A malicious package listed in CISA KEV fails --fail-on-kev even when the
// baseline lists it, like it fails the threshold.
func TestApplyBaselineMaliciousKEVFindingFailsKEVGate(t *testing.T) {
	res := fixtureResult()
	res.Vulnerabilities = res.Vulnerabilities[2:3] // GHSA-crit-0003 on lodash, in the baseline
	res.Vulnerabilities[0].Aliases = []string{"MAL-2025-0003"}
	res.Vulnerabilities[0].KEV = true
	f, s := BuildWithOptions(res, nil, BuildOptions{FailOnKEV: true}, fixedNow)
	ApplyBaseline(f, &s, fixtureBaseline(t))
	if f[0].New || !s.Failed || !s.KEVFailed {
		t.Errorf("New %v, Failed %v, KEVFailed %v; want false, true, true", f[0].New, s.Failed, s.KEVFailed)
	}
}
