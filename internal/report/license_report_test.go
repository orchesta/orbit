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
		if !slices.Contains(r0.Properties.Tags, "license") {
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
	s.DeniedLicenses = []string{"MIT"}
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
	for _, bad := range []string{"\nwarning: forged", "\n##vso", "\x1b", "\nb/package-lock.json"} {
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
