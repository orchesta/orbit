package report

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"slices"
	"strings"
	"testing"

	"github.com/orchesta/orbit/internal/domain/entity"
)

func TestLicenseReports(t *testing.T) {
	ignores, _ := ParseIgnoreFile(strings.NewReader("license:GPL-3.0-only package=gpl  approved\n"))
	s := applyPolicy(t, "GPL-3.0-only,AGPL-3.0-only", ignores)
	var f []Finding

	t.Run("table", func(t *testing.T) {
		var b bytes.Buffer
		if err := WriteTable(&b, []Finding{}, s); err != nil {
			t.Fatal(err)
		}
		out := b.String()
		for _, want := range []string{
			"DENIED                       PACKAGE     LICENSE                         MANIFEST\n",
			"AGPL-3.0-only, GPL-3.0-only  both@1.0.0  GPL-3.0-only AND AGPL-3.0-only  package-lock.json\n",
			"GPL-3.0-only (ignored)       gpl@1.0.0   GPL-3.0-only                    package-lock.json\n",
			"license policy (deny AGPL-3.0-only, GPL-3.0-only): 1 violation, FAILED\n",
			"threshold high: passed\n",
		} {
			if !strings.Contains(out, want) {
				t.Errorf("table lacks %q:\n%s", want, out)
			}
		}
		b.Reset()
		_ = WriteTable(&b, nil, s)
		if strings.Contains(b.String(), "DENIED") || !strings.Contains(b.String(), "license policy") {
			t.Errorf("summary-only table:\n%s", b.String())
		}
	})

	t.Run("json", func(t *testing.T) {
		var b bytes.Buffer
		if err := WriteJSON(&b, f, s, testTool); err != nil {
			t.Fatal(err)
		}
		var doc struct {
			Summary struct {
				Failed         bool     `json:"failed"`
				LicenseFailed  bool     `json:"license_failed"`
				DeniedLicenses []string `json:"denied_licenses"`
			} `json:"summary"`
			Dependencies      []map[string]any `json:"dependencies"`
			LicenseViolations []struct {
				Package string   `json:"package"`
				License string   `json:"license"`
				Denied  []string `json:"denied"`
				Ignored bool     `json:"ignored"`
			} `json:"license_violations"`
		}
		if err := json.Unmarshal(b.Bytes(), &doc); err != nil {
			t.Fatal(err)
		}
		// No findings, so Summary.Failed is false: "failed" is true only
		// because of the license policy.
		if s.Failed || !doc.Summary.Failed || !doc.Summary.LicenseFailed || !slices.Equal(doc.Summary.DeniedLicenses, []string{"AGPL-3.0-only", "GPL-3.0-only"}) {
			t.Errorf("summary = %+v", doc.Summary)
		}
		if len(doc.LicenseViolations) != 2 || doc.LicenseViolations[0].Package != "both" || doc.LicenseViolations[1].Package != "gpl" || !doc.LicenseViolations[1].Ignored {
			t.Errorf("license_violations = %+v", doc.LicenseViolations)
		}
		// Every dependency has "license", "" included when unknown.
		licenses := map[string]any{}
		for _, d := range doc.Dependencies {
			l, ok := d["license"]
			if !ok {
				t.Errorf("dependency without license: %v", d)
			}
			licenses[d["name"].(string)] = l
		}
		if licenses["unknown"] != "" || licenses["both"] != "GPL-3.0-only AND AGPL-3.0-only" || len(licenses) != 6 {
			t.Errorf("dependency licenses = %v", licenses)
		}
	})

	t.Run("sarif", func(t *testing.T) {
		var b bytes.Buffer
		if err := WriteSARIF(&b, f, s, testTool, SARIFOptions{}); err != nil {
			t.Fatal(err)
		}
		var doc struct {
			Runs []struct {
				Tool struct {
					Driver struct {
						Rules []struct {
							ID               string    `json:"id"`
							ShortDescription sarifText `json:"shortDescription"`
							HelpURI          string    `json:"helpUri"`
							Properties       struct {
								Tags []string `json:"tags"`
							} `json:"properties"`
						} `json:"rules"`
					} `json:"driver"`
				} `json:"tool"`
				Results []struct {
					RuleID              string            `json:"ruleId"`
					Level               string            `json:"level"`
					PartialFingerprints map[string]string `json:"partialFingerprints"`
					Suppressions        []json.RawMessage `json:"suppressions"`
				} `json:"results"`
			} `json:"runs"`
		}
		if err := json.Unmarshal(b.Bytes(), &doc); err != nil {
			t.Fatal(err)
		}
		run := doc.Runs[0]
		var rules []string
		for _, r := range run.Tool.Driver.Rules {
			rules = append(rules, r.ID)
		}
		if !slices.Equal(rules, []string{"license/AGPL-3.0-only", "license/GPL-3.0-only"}) {
			t.Fatalf("rules = %q", rules)
		}
		r0 := run.Tool.Driver.Rules[0]
		if r0.HelpURI != "https://spdx.org/licenses/AGPL-3.0-only.html" || r0.ShortDescription.Text != "Denied license AGPL-3.0-only" {
			t.Errorf("rule = %+v", r0)
		}
		if !slices.Equal(r0.Properties.Tags, []string{"license"}) {
			t.Errorf("tags = %q", r0.Properties.Tags)
		}
		// both: two results (one per denied license); gpl: one, suppressed.
		if len(run.Results) != 3 || run.Results[2].RuleID != "license/GPL-3.0-only" || len(run.Results[2].Suppressions) != 1 || run.Results[0].Level != "error" {
			t.Fatalf("results = %+v", run.Results)
		}
		if fp := run.Results[0].PartialFingerprints["orbit/v1"]; fp == "" || fp == run.Results[1].PartialFingerprints["orbit/v1"] {
			t.Errorf("fingerprints = %q, %q", fp, run.Results[1].PartialFingerprints["orbit/v1"])
		}
	})

	t.Run("junit", func(t *testing.T) {
		var b bytes.Buffer
		if err := WriteJUnit(&b, f, s); err != nil {
			t.Fatal(err)
		}
		var suite junitSuite
		if err := xml.Unmarshal(b.Bytes(), &suite); err != nil {
			t.Fatal(err)
		}
		if suite.Tests != 2 || suite.Failures != 1 || suite.Skipped != 1 {
			t.Fatalf("suite = %d tests, %d failures, %d skipped", suite.Tests, suite.Failures, suite.Skipped)
		}
		c := suite.Cases[0]
		if c.Name != "both@1.0.0: license GPL-3.0-only AND AGPL-3.0-only" || c.ClassName != "package-lock.json" || c.Failure == nil || c.Failure.Type != "license" || c.Failure.Message != "denied license: AGPL-3.0-only, GPL-3.0-only" {
			t.Fatalf("case = %+v", c)
		}
		if c := suite.Cases[1]; c.Skipped == nil || c.Skipped.Message != "approved" {
			t.Fatalf("ignored case = %+v", c)
		}
	})
}

func TestTableLicenseColumnOnlyWithShowLicenses(t *testing.T) {
	f, s := build(t, entity.SeverityHigh)
	f[0].Dependency.License = "MIT"
	var b bytes.Buffer
	_ = WriteTable(&b, f, s)
	if strings.Contains(b.String(), "LICENSE") {
		t.Fatalf("LICENSE column without ShowLicenses:\n%s", b.String())
	}
	s.ShowLicenses = true
	b.Reset()
	_ = WriteTable(&b, f, s)
	lines := strings.Split(b.String(), "\n")
	if got := strings.Fields(lines[0]); !slices.Equal(got, []string{"SEVERITY", "ID", "PACKAGE", "LICENSE", "FIXED", "MANIFEST"}) {
		t.Fatalf("header = %q", lines[0])
	}
	// f[0] is lodash (MIT); f[1] is express, whose license is unknown.
	if got := strings.Fields(lines[1]); got[3] != "MIT" {
		t.Fatalf("row 1 = %q", lines[1])
	}
	if got := strings.Fields(lines[2]); got[3] != "-" {
		t.Fatalf("row 2 = %q", lines[2])
	}
}

func TestTableLicenseCellsAreSingleLine(t *testing.T) {
	f, s := build(t, entity.SeverityHigh)
	f[0].Dependency.License = "MIT\nwarning: forged"
	s.ShowLicenses = true
	s.DeniedLicenses = []string{"MIT\nwarning: policy"}
	s.LicenseViolations = []LicenseViolation{{
		Dependency: &entity.Dependency{Name: "evil\r\n##vso[task.complete]", CurrentVersion: "1.0.0",
			ManifestFile: "a\nb/package-lock.json", License: "MIT\x1b[31m"},
		Denied: []string{"MIT"},
	}}
	var b bytes.Buffer
	if err := WriteTable(&b, f, s); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, bad := range []string{"\nwarning: forged", "\nwarning: policy", "\n##vso", "\x1b", "\nb/package-lock.json"} {
		if strings.Contains(out, bad) {
			t.Errorf("table contains %q:\n%s", bad, out)
		}
	}
	if !strings.Contains(out, "evil\ufffd\ufffd##vso[task.complete]@1.0.0") {
		t.Errorf("violation row not neutralised:\n%s", out)
	}
}

func TestLicenseHelpURI(t *testing.T) {
	if got := licenseHelpURI("MIT"); got != "https://spdx.org/licenses/MIT.html" {
		t.Errorf("MIT: %q", got)
	}
	if got := licenseHelpURI("LicenseRef-Proprietary"); got != "" {
		t.Errorf("LicenseRef: %q", got)
	}
}

func TestTableExploitAndLicenseColumnsTogether(t *testing.T) {
	res := exploitFixture()
	res.Dependencies[0].License = "MIT"
	f, s := BuildWithOptions(res, nil, BuildOptions{Threshold: entity.SeverityHigh}, fixedNow)
	s.ShowLicenses = true
	var plain, colored bytes.Buffer
	if err := writeTable(&plain, f, s, false); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(plain.String(), "\n")
	if got := strings.Fields(lines[0]); !slices.Equal(got, []string{"SEVERITY", "KEV", "EPSS", "ID", "PACKAGE", "LICENSE", "FIXED", "MANIFEST"}) {
		t.Fatalf("header = %q", lines[0])
	}
	if want := "LOW       yes  5.0%   CVE-2019-10744  lodash@4.17.15  MIT      4.17.12  package-lock.json"; lines[3] != want {
		t.Fatalf("KEV row = %q, want %q", lines[3], want)
	}
	if err := writeTable(&colored, f, s, true); err != nil {
		t.Fatal(err)
	}
	row := strings.Split(colored.String(), "\n")[3]
	if !strings.Contains(row, colorize("yes", entity.SeverityCritical)) || strings.Contains(row, "\x1b[1;31mMIT") {
		t.Fatalf("colored KEV row = %q", row)
	}
	if got := ansiRE.ReplaceAllString(colored.String(), ""); got != plain.String() {
		t.Errorf("colored table misaligned:\n%s\nwant:\n%s", got, plain.String())
	}
}

// sarifLicenseRun decodes the parts of a SARIF log the license tests read.
type sarifLicenseRun struct {
	Runs []struct {
		Results []struct {
			RuleID        string `json:"ruleId"`
			BaselineState string `json:"baselineState"`
			Locations     []struct {
				PhysicalLocation struct {
					ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
				} `json:"physicalLocation"`
			} `json:"locations"`
		} `json:"results"`
	} `json:"runs"`
}

func TestSARIFLicenseResultsAreNewUnderABaseline(t *testing.T) {
	res := fixtureResult()
	res.Dependencies[0].License = "GPL-3.0-only" // lodash, whose critical finding is in the baseline
	f, s := Build(res, fixtureIgnores(), entity.SeverityCritical, fixedNow)
	ApplyBaseline(f, &s, fixtureBaseline(t))
	ApplyLicensePolicy(&s, []string{"GPL-3.0-only"}, nil, fixedNow)
	var b bytes.Buffer
	if err := WriteSARIF(&b, f, s, testTool, SARIFOptions{}); err != nil {
		t.Fatal(err)
	}
	var doc sarifLicenseRun
	if err := json.Unmarshal(b.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	results := doc.Runs[0].Results
	licenses := 0
	for _, r := range results {
		if r.BaselineState == "" {
			t.Errorf("result %s has no baselineState", r.RuleID)
		}
		if strings.HasPrefix(r.RuleID, "license/") {
			licenses++
			if r.BaselineState != "new" {
				t.Errorf("license result baselineState = %q, want new", r.BaselineState)
			}
		}
	}
	if licenses != 1 || len(results) != len(f)+1 {
		t.Fatalf("%d license results of %d, want 1 of %d", licenses, len(results), len(f)+1)
	}
	// Without a baseline no result has a baselineState.
	s.Baseline = false
	b.Reset()
	if err := WriteSARIF(&b, f, s, testTool, SARIFOptions{}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(b.String(), "baselineState") {
		t.Fatal("baselineState without a baseline")
	}
}

func TestSARIFLicenseResultLocationFollowsOptions(t *testing.T) {
	s := applyPolicy(t, "GPL-3.0-only", nil)
	for _, tc := range []struct {
		opts SARIFOptions
		want sarifArtifactLocation
	}{
		{SARIFOptions{PathPrefix: "web app"}, sarifArtifactLocation{URI: "web%20app/package-lock.json"}},
		{SARIFOptions{RootURI: "file:///repo/"}, sarifArtifactLocation{URI: "package-lock.json", URIBaseID: sarifRootID}},
	} {
		var b bytes.Buffer
		if err := WriteSARIF(&b, nil, s, testTool, tc.opts); err != nil {
			t.Fatal(err)
		}
		var doc sarifLicenseRun
		if err := json.Unmarshal(b.Bytes(), &doc); err != nil {
			t.Fatal(err)
		}
		results := doc.Runs[0].Results
		if len(results) == 0 {
			t.Fatalf("%+v: no results", tc.opts)
		}
		for _, r := range results {
			if got := r.Locations[0].PhysicalLocation.ArtifactLocation; got != tc.want {
				t.Errorf("%+v: %s location = %+v, want %+v", tc.opts, r.RuleID, got, tc.want)
			}
		}
	}
}

// An entry that accepts one of several denied licenses leaves the violation
// active, and every report names only the licenses still denied: no
// unsuppressed SARIF result for the accepted one.
func TestPartlyAcceptedViolationNamesOnlyTheStillDeniedLicenses(t *testing.T) {
	ignores, err := ParseIgnoreFile(strings.NewReader("license:GPL-3.0-only package=x  approved\n"))
	if err != nil {
		t.Fatal(err)
	}
	res := licenseResult()
	res.Dependencies = append(res.Dependencies[:0], &entity.Dependency{Name: "x", CurrentVersion: "1.0.0", Ecosystem: entity.EcosystemNpm,
		ManifestFile: "package-lock.json", IsResolved: true, License: "MIT AND GPL-3.0-only AND AGPL-3.0-only"})
	_, s := Build(res, ignores, entity.SeverityHigh, fixedNow)
	ApplyLicensePolicy(&s, []string{"AGPL-3.0-only", "GPL-3.0-only"}, ignores, fixedNow)
	if got := violationNames(s); !slices.Equal(got, []string{"x=AGPL-3.0-only"}) || !s.LicenseFailed {
		t.Errorf("violations = %q, LicenseFailed = %v; want [x=AGPL-3.0-only], true", got, s.LicenseFailed)
	}

	var b bytes.Buffer
	if err := WriteSARIF(&b, nil, s, testTool, SARIFOptions{}); err != nil {
		t.Fatal(err)
	}
	var doc sarifLicenseRun
	if err := json.Unmarshal(b.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	var rules []string
	for _, r := range doc.Runs[0].Results {
		rules = append(rules, r.RuleID)
	}
	if !slices.Equal(rules, []string{"license/AGPL-3.0-only"}) {
		t.Errorf("SARIF results = %q, want [license/AGPL-3.0-only]", rules)
	}

	b.Reset()
	if err := WriteJUnit(&b, nil, s); err != nil {
		t.Fatal(err)
	}
	var suite junitSuite
	if err := xml.Unmarshal(b.Bytes(), &suite); err != nil {
		t.Fatal(err)
	}
	c := suite.Cases[0]
	if suite.Failures != 1 || c.Failure == nil || c.Failure.Message != "denied license: AGPL-3.0-only" ||
		c.Failure.Body != "x@1.0.0 is licensed under MIT AND GPL-3.0-only AND AGPL-3.0-only; the license policy denies AGPL-3.0-only" {
		t.Fatalf("JUnit case = %+v, failure = %+v", c, c.Failure)
	}
}
