package report

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"flag"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/orchesta/orbit/internal/domain/entity"
	"github.com/orchesta/orbit/internal/engine"
)

var update = flag.Bool("update", false, "rewrite golden files")

var fixedNow = time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)

var testTool = ToolInfo{Name: "orbit", Version: "1.2.3", InformationURI: "https://example.com/orbit"}

const escSummary = "a & b < c > d \" e\nline2"

func strp(s string) *string { return &s }

func fixtureResult() *engine.Result {
	dep := func(n, v, eco, mf string, direct, dev bool) *entity.Dependency {
		return &entity.Dependency{
			ID: uuid.New(), Name: n, CurrentVersion: v, Ecosystem: entity.Ecosystem(eco),
			ManifestFile: mf, IsDirect: direct, IsDev: dev, IsResolved: true,
		}
	}
	lodash := dep("lodash", "4.17.15", "npm", "package-lock.json", true, false)
	django := dep("django", "3.0.0", "PyPI", "requirements.txt", true, false)
	express := dep("express", "4.18.2", "npm", "package-lock.json", false, true)
	vuln := func(d *entity.Dependency, id string, sev entity.Severity, sum string, fix *string, aliases, refs []string) *entity.Vulnerability {
		return &entity.Vulnerability{ID: uuid.New(), DependencyID: d.ID, OSVID: id, Aliases: aliases,
			Summary: sum, Severity: sev, FixedVersion: fix, References: refs}
	}
	return &engine.Result{
		Dependencies: []*entity.Dependency{lodash, django, express},
		Vulnerabilities: []*entity.Vulnerability{
			vuln(lodash, "GHSA-medium-0001", entity.SeverityMedium, "Prototype pollution", strp("4.17.21"),
				[]string{"CVE-2020-0001"}, []string{"https://example.com/m1"}),
			vuln(django, "GHSA-high-0002", entity.SeverityHigh, "SQL injection", strp("3.0.7"),
				[]string{"CVE-2020-0002"}, []string{"https://example.com/h2"}),
			vuln(lodash, "GHSA-crit-0003", entity.SeverityCritical, "Remote code execution", nil,
				nil, nil),
			vuln(django, "GHSA-low-0004", entity.SeverityLow, "Info leak", strp("3.0.8"),
				nil, []string{"https://example.com/l4"}),
			vuln(express, "GHSA-esc-0005", entity.SeverityHigh, escSummary, nil, nil, nil),
		},
		VulnerableDeps: 2,
		Manifests:      []string{"package-lock.json", "requirements.txt"},
		Warnings:       []string{"go.mod: unresolved version"},
	}
}

func fixtureIgnores() *IgnoreList {
	return &IgnoreList{Entries: []IgnoreEntry{
		{ID: "GHSA-low-0004", Reason: "accepted risk", Expires: fixedNow.Add(24 * time.Hour)},
		{ID: "GHSA-high-0002", Reason: "expired", Expires: fixedNow.Add(-time.Hour)},
	}}
}

func build(t *testing.T, th entity.Severity) ([]Finding, Summary) {
	t.Helper()
	return Build(fixtureResult(), fixtureIgnores(), th, fixedNow)
}

func golden(t *testing.T, name string, got []byte) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if *update {
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden (run with -update): %v", err)
	}
	if !bytes.Equal(want, got) {
		t.Errorf("%s differs from golden.\n--- got ---\n%s\n--- want ---\n%s", name, got, want)
	}
}

func TestBuildOrderingAndSummary(t *testing.T) {
	f, s := build(t, entity.SeverityHigh)
	var ids []string
	for _, x := range f {
		ids = append(ids, x.Vulnerability.OSVID)
	}
	want := "GHSA-crit-0003,GHSA-esc-0005,GHSA-high-0002,GHSA-medium-0001,GHSA-low-0004"
	if strings.Join(ids, ",") != want {
		t.Fatalf("order = %v", ids)
	}
	if !f[4].Ignored || f[4].IgnoreReason != "accepted risk" {
		t.Errorf("low should be ignored: %+v", f[4])
	}
	if f[2].Ignored {
		t.Error("expired ignore must not apply")
	}
	if s.BySeverity[entity.SeverityLow] != 0 || s.BySeverity[entity.SeverityCritical] != 1 || s.BySeverity[entity.SeverityHigh] != 2 {
		t.Errorf("BySeverity = %v", s.BySeverity)
	}
	if s.Dependencies != 3 || s.Vulnerable != 3 || !s.Failed || s.Threshold != entity.SeverityHigh {
		t.Errorf("summary = %+v", s)
	}
}

func TestBuildThreshold(t *testing.T) {
	if _, s := build(t, ""); s.Failed {
		t.Error("no threshold must never fail")
	}
	// only the low finding is ignored; critical is not -> fails at critical
	if _, s := build(t, entity.SeverityCritical); !s.Failed {
		t.Error("critical threshold should fail")
	}
	res := fixtureResult()
	res.Vulnerabilities = res.Vulnerabilities[3:4] // only low, ignored
	if _, s := Build(res, fixtureIgnores(), entity.SeverityLow, fixedNow); s.Failed {
		t.Error("ignored finding must not fail")
	}
	if _, s := Build(&engine.Result{}, nil, entity.SeverityLow, fixedNow); s.Failed {
		t.Error("empty result must not fail")
	}
}

func TestTableGolden(t *testing.T) {
	f, s := build(t, entity.SeverityHigh)
	var b bytes.Buffer
	if err := WriteTable(&b, f, s); err != nil {
		t.Fatal(err)
	}
	golden(t, "table.golden", b.Bytes())
	if strings.Contains(b.String(), "\x1b[") {
		t.Error("no color expected for a buffer")
	}
}

func TestJSONGolden(t *testing.T) {
	f, s := build(t, entity.SeverityHigh)
	var b bytes.Buffer
	if err := WriteJSON(&b, f, s, testTool); err != nil {
		t.Fatal(err)
	}
	golden(t, "report.json.golden", b.Bytes())
	var doc map[string]any
	if err := json.Unmarshal(b.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if doc["schema_version"] != float64(1) {
		t.Errorf("schema_version = %v", doc["schema_version"])
	}
	if len(doc["dependencies"].([]any)) != 3 || len(doc["findings"].([]any)) != 5 {
		t.Errorf("unexpected counts: %v", doc)
	}
}

func TestJSONEmptyArraysNotNull(t *testing.T) {
	f, s := Build(&engine.Result{}, nil, "", fixedNow)
	var b bytes.Buffer
	if err := WriteJSON(&b, f, s, testTool); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), `"findings": []`) || !strings.Contains(b.String(), `"dependencies": []`) ||
		!strings.Contains(b.String(), `"recommendations": []`) {
		t.Errorf("want empty arrays:\n%s", b.String())
	}
}

func TestSARIFGolden(t *testing.T) {
	f, s := build(t, entity.SeverityHigh)
	var b bytes.Buffer
	if err := WriteSARIF(&b, f, s, testTool, SARIFOptions{}); err != nil {
		t.Fatal(err)
	}
	golden(t, "report.sarif.golden", b.Bytes())

	var doc struct {
		Version string `json:"version"`
		Runs    []struct {
			Tool struct {
				Driver struct {
					Name  string `json:"name"`
					Rules []struct {
						ID         string                `json:"id"`
						Short      struct{ Text string } `json:"shortDescription"`
						HelpURI    string                `json:"helpUri"`
						Properties map[string]any        `json:"properties"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID    string                `json:"ruleId"`
				Level     string                `json:"level"`
				Message   struct{ Text string } `json:"message"`
				Locations []struct {
					PhysicalLocation struct {
						ArtifactLocation struct{ URI string } `json:"artifactLocation"`
					} `json:"physicalLocation"`
				} `json:"locations"`
				PartialFingerprints map[string]string                      `json:"partialFingerprints"`
				Suppressions        []struct{ Kind, Justification string } `json:"suppressions"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(b.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Version != "2.1.0" || len(doc.Runs) != 1 {
		t.Fatalf("bad doc: %+v", doc.Version)
	}
	run := doc.Runs[0]
	if len(run.Tool.Driver.Rules) != 5 || len(run.Results) != 5 {
		t.Fatalf("rules=%d results=%d", len(run.Tool.Driver.Rules), len(run.Results))
	}
	r0 := run.Results[0]
	if r0.Level != "error" || r0.RuleID != "GHSA-crit-0003" ||
		r0.Message.Text != "lodash@4.17.15 is affected by GHSA-crit-0003 (no fix available)" {
		t.Errorf("r0 = %+v", r0)
	}
	if run.Tool.Driver.Rules[0].Properties["security-severity"] != "9.5" {
		t.Errorf("security-severity = %v", run.Tool.Driver.Rules[0].Properties["security-severity"])
	}
	if run.Results[1].RuleID != "GHSA-esc-0005" || run.Tool.Driver.Rules[1].Short.Text != escSummary {
		t.Errorf("escaped summary did not round-trip: %+v", run.Tool.Driver.Rules[1].Short)
	}
	if len(r0.PartialFingerprints["orbit/v1"]) != 64 {
		t.Errorf("fingerprint = %q", r0.PartialFingerprints["orbit/v1"])
	}
	if run.Results[3].Level != "warning" || run.Results[4].Level != "note" {
		t.Errorf("levels = %s %s", run.Results[3].Level, run.Results[4].Level)
	}
	if len(run.Results[4].Suppressions) != 1 || run.Results[4].Suppressions[0].Kind != "external" ||
		run.Results[4].Suppressions[0].Justification != "accepted risk" {
		t.Errorf("suppression = %+v", run.Results[4].Suppressions)
	}
	if len(r0.Suppressions) != 0 {
		t.Error("non-ignored result must have no suppressions")
	}
	if r0.Locations[0].PhysicalLocation.ArtifactLocation.URI != "package-lock.json" {
		t.Errorf("uri = %q", r0.Locations[0].PhysicalLocation.ArtifactLocation.URI)
	}
}

func TestJUnitGolden(t *testing.T) {
	f, s := build(t, entity.SeverityHigh)
	var b bytes.Buffer
	if err := WriteJUnit(&b, f, s); err != nil {
		t.Fatal(err)
	}
	golden(t, "report.junit.golden", b.Bytes())
	out := b.String()
	if strings.Count(out, "<failure") != 3 || strings.Count(out, "<skipped") != 1 {
		t.Errorf("failures/skipped wrong:\n%s", out)
	}
}

func TestJUnitNoFindingsHasPassingCase(t *testing.T) {
	f, s := Build(&engine.Result{}, nil, entity.SeverityLow, fixedNow)
	var b bytes.Buffer
	if err := WriteJUnit(&b, f, s); err != nil {
		t.Fatal(err)
	}
	if strings.Count(b.String(), "<testcase") != 1 || strings.Contains(b.String(), "<failure") {
		t.Errorf("want one passing case:\n%s", b.String())
	}
	golden(t, "report.junit.empty.golden", b.Bytes())
}

var ansiRE = regexp.MustCompile("\x1b\\[[0-9;]*m")

func TestTableColorAligned(t *testing.T) {
	f, s := build(t, entity.SeverityHigh)
	var plain, colored bytes.Buffer
	if err := writeTable(&plain, f, s, false); err != nil {
		t.Fatal(err)
	}
	if err := writeTable(&colored, f, s, true); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(colored.String(), "\x1b[") {
		t.Fatal("expected ANSI codes")
	}
	if got := ansiRE.ReplaceAllString(colored.String(), ""); got != plain.String() {
		t.Errorf("colored output misaligned after stripping.\n--- got ---\n%s\n--- want ---\n%s", got, plain.String())
	}
}

func TestBuildUnmatchedVulnerabilityWarns(t *testing.T) {
	res := fixtureResult()
	res.Vulnerabilities = append(res.Vulnerabilities,
		&entity.Vulnerability{ID: uuid.New(), DependencyID: uuid.New(), OSVID: "X-1", Severity: entity.SeverityLow})
	res.Warnings = []string{"zzz", "aaa"}
	_, s := Build(res, nil, "", fixedNow)
	want := []string{"1 findings could not be matched to a dependency", "aaa", "zzz"}
	got := append([]string(nil), s.Warnings...)
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("warnings = %v, want %v", got, want)
	}
	if res.Warnings[0] != "zzz" {
		t.Error("input warnings must not be mutated")
	}
}

func TestSortEcosystemLastKey(t *testing.T) {
	mk := func(eco entity.Ecosystem) *entity.Dependency {
		return &entity.Dependency{ID: uuid.New(), Name: "p", CurrentVersion: "1", ManifestFile: "m", Ecosystem: eco}
	}
	a, b := mk("npm"), mk("PyPI")
	res := &engine.Result{Dependencies: []*entity.Dependency{a, b}}
	for _, d := range []*entity.Dependency{a, b} {
		res.Vulnerabilities = append(res.Vulnerabilities, &entity.Vulnerability{DependencyID: d.ID, OSVID: "X", Severity: entity.SeverityLow})
	}
	f, _ := Build(res, nil, "", fixedNow)
	if f[0].Dependency.Ecosystem != "PyPI" || f[1].Dependency.Ecosystem != "npm" {
		t.Errorf("ecosystem order = %s, %s", f[0].Dependency.Ecosystem, f[1].Dependency.Ecosystem)
	}
}

func TestSARIFOptionalAndRuleHardening(t *testing.T) {
	d := &entity.Dependency{ID: uuid.New(), Name: "p", CurrentVersion: "1", ManifestFile: "m", Ecosystem: "npm"}
	d2 := &entity.Dependency{ID: uuid.New(), Name: "q", CurrentVersion: "1", ManifestFile: "m", Ecosystem: "npm"}
	res := &engine.Result{Dependencies: []*entity.Dependency{d, d2}, Vulnerabilities: []*entity.Vulnerability{
		{DependencyID: d.ID, OSVID: "A-1", Severity: entity.SeverityLow},
		{DependencyID: d2.ID, OSVID: "A-1", Severity: entity.SeverityCritical},
	}}
	f, s := Build(res, nil, "", fixedNow)
	var b bytes.Buffer
	if err := WriteSARIF(&b, f, s, ToolInfo{Name: "orbit"}, SARIFOptions{}); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	if strings.Contains(out, "informationUri") || strings.Contains(out, `"version": ""`) {
		t.Errorf("empty tool fields must be omitted:\n%s", out)
	}
	var doc struct {
		Runs []struct {
			Tool struct {
				Driver struct {
					Rules []struct {
						Short      struct{ Text string } `json:"shortDescription"`
						Properties map[string]any        `json:"properties"`
					}
				}
			}
		}
	}
	if err := json.Unmarshal(b.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	rules := doc.Runs[0].Tool.Driver.Rules
	if len(rules) != 1 || rules[0].Short.Text != "A-1" || rules[0].Properties["security-severity"] != "9.5" {
		t.Errorf("rules = %+v", rules)
	}
}

func TestJSONStability(t *testing.T) {
	f, s := Build(&engine.Result{}, nil, "", fixedNow)
	var b bytes.Buffer
	if err := WriteJSON(&b, f, s, ToolInfo{Name: "orbit", Version: "1"}); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Tool    map[string]any
		Summary struct {
			BySeverity map[string]int `json:"by_severity"`
		}
	}
	if err := json.Unmarshal(b.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if v, ok := doc.Tool["information_uri"]; !ok || v != "" {
		t.Errorf("information_uri = %v, %v", v, ok)
	}
	for _, k := range []string{"critical", "high", "medium", "low", "unknown"} {
		if v, ok := doc.Summary.BySeverity[k]; !ok || v != 0 {
			t.Errorf("by_severity[%s] = %v, %v", k, v, ok)
		}
	}
}

func TestJUnitEscapingRoundTrip(t *testing.T) {
	f, s := build(t, entity.SeverityHigh)
	var b bytes.Buffer
	if err := WriteJUnit(&b, f, s); err != nil {
		t.Fatal(err)
	}
	var suite struct {
		Cases []struct {
			Name    string `xml:"name,attr"`
			Failure *struct {
				Message string `xml:"message,attr"`
			} `xml:"failure"`
		} `xml:"testcase"`
	}
	if err := xml.Unmarshal(b.Bytes(), &suite); err != nil {
		t.Fatalf("not well-formed: %v", err)
	}
	for _, c := range suite.Cases {
		if strings.Contains(c.Name, "GHSA-esc-0005") {
			if c.Failure == nil || c.Failure.Message != "high: "+escSummary {
				t.Errorf("failure = %+v", c.Failure)
			}
			return
		}
	}
	t.Error("escaping case missing")
}
