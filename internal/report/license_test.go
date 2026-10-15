package report

import (
	"slices"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/orchesta/orbit/internal/domain/entity"
	"github.com/orchesta/orbit/internal/engine"
	"github.com/orchesta/orbit/internal/spdx"
)

// licenseResult has one dependency per license case and no findings.
func licenseResult() *engine.Result {
	dep := func(name, eco, license string) *entity.Dependency {
		return &entity.Dependency{ID: uuid.New(), Name: name, CurrentVersion: "1.0.0", Ecosystem: entity.Ecosystem(eco),
			ManifestFile: "package-lock.json", IsResolved: true, License: license}
	}
	return &engine.Result{Dependencies: []*entity.Dependency{
		dep("mit", "npm", "MIT"),
		dep("gpl", "npm", "GPL-3.0-only"),
		dep("dual", "npm", "GPL-3.0-only OR MIT"),
		dep("both", "npm", "GPL-3.0-only AND AGPL-3.0-only"),
		dep("unknown", "npm", ""),
		dep("Py_Pkg", "PyPI", "AGPL-3.0-or-later OR AGPL-3.0-only"),
	}}
}

func applyPolicy(t *testing.T, deny string, ignores *IgnoreList) Summary {
	t.Helper()
	_, s := Build(licenseResult(), ignores, entity.SeverityHigh, fixedNow)
	ids, err := spdx.ParseIDs(deny)
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) == 0 {
		ids = nil
	}
	ApplyLicensePolicy(&s, ids, ignores, fixedNow)
	return s
}

func violationNames(s Summary) []string {
	var out []string
	for _, v := range s.LicenseViolations {
		name := v.Dependency.Name + "=" + strings.Join(v.Denied, "+")
		if v.Ignored {
			name += " (ignored: " + v.IgnoreReason + ")"
		}
		out = append(out, name)
	}
	return out
}

func TestApplyLicensePolicyUsesAndOrSemantics(t *testing.T) {
	s := applyPolicy(t, "AGPL-3.0-only,AGPL-3.0-or-later,GPL-3.0-only", nil)
	want := []string{"Py_Pkg=AGPL-3.0-only+AGPL-3.0-or-later", "both=AGPL-3.0-only+GPL-3.0-only", "gpl=GPL-3.0-only"}
	if got := violationNames(s); !slices.Equal(got, want) {
		t.Fatalf("violations = %q, want %q", got, want)
	}
	if !s.LicenseFailed || s.Failed {
		t.Fatalf("LicenseFailed = %v, Failed = %v; want true, false (no findings)", s.LicenseFailed, s.Failed)
	}
	if !slices.Contains(s.Warnings, "license policy: 1 dependency has no known license and was not checked; --licenses looks them up on deps.dev") {
		t.Fatalf("Warnings = %q", s.Warnings)
	}
}

func TestApplyLicensePolicyWithoutDenyListDoesNothing(t *testing.T) {
	s := applyPolicy(t, "", nil)
	if len(s.LicenseViolations) != 0 || s.LicenseFailed || s.DeniedLicenses != nil || len(s.Warnings) != 0 {
		t.Fatalf("summary = %+v", s)
	}
}

func TestApplyLicensePolicyHintOnlyWithoutLicenses(t *testing.T) {
	_, s := Build(licenseResult(), nil, "", fixedNow)
	s.ShowLicenses = true
	ApplyLicensePolicy(&s, []string{"GPL-3.0-only"}, nil, fixedNow)
	if !slices.Contains(s.Warnings, "license policy: 1 dependency has no known license and was not checked") {
		t.Fatalf("Warnings = %q", s.Warnings)
	}
}

func TestLicenseIgnoreEntries(t *testing.T) {
	ignores, err := ParseIgnoreFile(strings.NewReader(strings.Join([]string{
		"license:gpl-3.0 package=gpl  Legal approved, LEGAL-7",
		"license:GPL-3.0-only package=both  only half of it",
		"license:AGPL-3.0-only package=py-pkg  normalised name matches",
		"license:AGPL-3.0-or-later package=py.pkg expires=2026-10-01  expired",
		"license:MIT package=nothing  never used",
	}, "\n")))
	if err != nil {
		t.Fatal(err)
	}
	s := applyPolicy(t, "AGPL-3.0-only,AGPL-3.0-or-later,GPL-3.0-only", ignores)
	want := []string{
		// Accepting one OR branch is enough; py-pkg matches Py_Pkg (PEP 503).
		"Py_Pkg=AGPL-3.0-only+AGPL-3.0-or-later (ignored: normalised name matches)",
		"both=AGPL-3.0-only", // GPL-3.0-only is accepted for both, AGPL-3.0-only is not
		"gpl=GPL-3.0-only (ignored: Legal approved, LEGAL-7)",
	}
	if got := violationNames(s); !slices.Equal(got, want) {
		t.Fatalf("violations = %q, want %q", got, want)
	}
	if !s.LicenseFailed {
		t.Fatal("unaccepted violations must fail")
	}
	for _, w := range []string{
		"ignore entry license:AGPL-3.0-or-later package=py.pkg expired on 2026-10-01",
		"unused ignore entry license:MIT package=nothing",
	} {
		if !slices.Contains(s.Warnings, w) {
			t.Errorf("missing warning %q in %q", w, s.Warnings)
		}
	}
	for _, w := range s.Warnings {
		if strings.Contains(w, "package=gpl") || strings.Contains(w, "package=both") || strings.Contains(w, "package=py-pkg") {
			t.Errorf("used entry warned about: %q", w)
		}
	}
}

func TestLicenseIgnoreEntriesNeverSuppressAdvisories(t *testing.T) {
	ignores, err := ParseIgnoreFile(strings.NewReader("license:MIT package=lodash  fine\n"))
	if err != nil {
		t.Fatal(err)
	}
	f, s := Build(fixtureResult(), ignores, entity.SeverityHigh, fixedNow)
	for _, x := range f {
		if x.Ignored {
			t.Errorf("%s ignored by a license entry", x.Vulnerability.OSVID)
		}
	}
	for _, w := range s.Warnings {
		if strings.Contains(w, "license:") {
			t.Errorf("Build must leave license entries to ApplyLicensePolicy: %q", w)
		}
	}
}

func TestParseLicenseIgnoreErrors(t *testing.T) {
	for _, line := range []string{
		"license:GPLv3 package=a  not SPDX",
		"license:MIT  no package",
		"license: package=a  empty",
		"license:Apache-2.0+ package=a  plus",
		"license:GPL-2.0-with-classpath-exception package=a  a license WITH an exception",
	} {
		if _, err := ParseIgnoreFile(strings.NewReader(line + "\n")); err == nil || !strings.Contains(err.Error(), "line 1") {
			t.Errorf("%q: err = %v, want a line 1 error", line, err)
		}
	}
	// A deprecated GPL-with-exception identifier is on the SPDX list: the
	// error says what it means and what to name instead, not that it is
	// unknown.
	for line, want := range map[string]string{
		"license:GPL-2.0-with-classpath-exception package=a  x": "name GPL-2.0-only",
		"license:gpl-3.0-with-gcc-exception+ package=a  x":      "name GPL-3.0-or-later",
		"license:GPL-2.0-with-autoconf-exception package=a  x":  "GPL-2.0-only WITH Autoconf-exception-2.0",
	} {
		_, err := ParseIgnoreFile(strings.NewReader(line + "\n"))
		if err == nil || !strings.Contains(err.Error(), want) || strings.Contains(err.Error(), "unknown") {
			t.Errorf("%q: err = %v, want one naming %q", line, err, want)
		}
	}
	l, err := ParseIgnoreFile(strings.NewReader("LICENSE:gpl-2.0+ package=a expires=2027-01-01 ok\n"))
	if err != nil {
		t.Fatal(err)
	}
	if e := l.Entries[0]; e.License != "GPL-2.0-or-later" || e.Package != "a" || e.ID != "license:GPL-2.0-or-later package=a" || e.Expires.IsZero() {
		t.Fatalf("entry = %+v", e)
	}
}

func TestLicenseIgnoreEntriesLeaveTheMaliciousRuleAlone(t *testing.T) {
	ignores, err := ParseIgnoreFile(strings.NewReader(strings.Join([]string{
		"license:GPL-3.0-only package=chalk  reviewed license",
		"MAL-2025-46969 package=chalk  reviewed advisory",
	}, "\n")))
	if err != nil {
		t.Fatal(err)
	}
	res := maliciousResult()
	for _, d := range res.Dependencies {
		d.License = "MIT"
	}
	res.Dependencies[1].License = "GPL-3.0-only" // chalk
	f, s := Build(res, ignores, entity.SeverityCritical, fixedNow)
	want := []string{"ignore entry MAL-2025-46969 not applied: chalk@5.6.1 is a known malicious package (MAL-2025-46969)"}
	if !slices.Equal(s.Warnings, want) {
		t.Fatalf("Build warnings = %q, want %q", s.Warnings, want)
	}
	for _, x := range f {
		if x.Malicious && x.Ignored {
			t.Errorf("%s: malicious finding ignored", x.Vulnerability.OSVID)
		}
	}
	ApplyLicensePolicy(&s, []string{"GPL-3.0-only"}, ignores, fixedNow)
	if got := violationNames(s); !slices.Equal(got, []string{"chalk=GPL-3.0-only (ignored: reviewed license)"}) {
		t.Fatalf("violations = %q", got)
	}
	if s.LicenseFailed || !s.Failed || s.Malicious != 2 {
		t.Fatalf("LicenseFailed = %v, Failed = %v, Malicious = %d; want false, true, 2", s.LicenseFailed, s.Failed, s.Malicious)
	}
	if !slices.Equal(s.Warnings, want) {
		t.Fatalf("warnings = %q, want %q (the license entry was used)", s.Warnings, want)
	}
}

func TestApplyBaselineLeavesTheLicensePolicyAlone(t *testing.T) {
	res := fixtureResult()
	res.Dependencies[0].License = "GPL-3.0-only" // lodash, whose critical finding is in the baseline
	f, s := Build(res, fixtureIgnores(), entity.SeverityCritical, fixedNow)
	ApplyBaseline(f, &s, fixtureBaseline(t))
	ApplyLicensePolicy(&s, []string{"GPL-3.0-only"}, nil, fixedNow)
	if s.Failed || !s.LicenseFailed {
		t.Fatalf("Failed = %v, LicenseFailed = %v; want false, true", s.Failed, s.LicenseFailed)
	}
	if got := violationNames(s); !slices.Equal(got, []string{"lodash=GPL-3.0-only"}) {
		t.Fatalf("violations = %q", got)
	}
	// Recomputing the finding gates must not clear the license result.
	ApplyBaseline(f, &s, fixtureBaseline(t))
	if s.Failed || !s.LicenseFailed || len(s.LicenseViolations) != 1 || !slices.Equal(s.DeniedLicenses, []string{"GPL-3.0-only"}) {
		t.Fatalf("after ApplyBaseline: Failed = %v, LicenseFailed = %v, violations = %d, denied = %q",
			s.Failed, s.LicenseFailed, len(s.LicenseViolations), s.DeniedLicenses)
	}
}
