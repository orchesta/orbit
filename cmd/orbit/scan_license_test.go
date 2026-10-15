package main

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/orchesta/orbit/internal/domain/entity"
	"github.com/orchesta/orbit/internal/engine"
)

// licensedResult has one npm dependency per license, and no findings.
func licensedResult(licenses ...string) *engine.Result {
	res := &engine.Result{Manifests: []string{"package-lock.json"}}
	for i, l := range licenses {
		d := entity.NewDependency(uuid.Nil, uuid.Nil, "pkg"+string(rune('a'+i)), "1.0.0", "package-lock.json", entity.EcosystemNpm)
		d.IsResolved, d.License = true, l
		res.Dependencies = append(res.Dependencies, d)
	}
	return res
}

func TestScanLicensesFlagEnablesTheLookup(t *testing.T) {
	f := &fakeEngine{res: resultWith()}
	runFake(t, f, "--path", t.TempDir())
	if f.licenses {
		t.Error("deps.dev used without --licenses")
	}
	f = &fakeEngine{res: resultWith()}
	runFake(t, f, "--path", t.TempDir(), "--licenses")
	if !f.licenses {
		t.Error("--licenses did not enable the lookup")
	}
}

// --deny-license alone never reaches deps.dev: it judges the licenses the
// lockfiles record.
func TestScanDenyLicenseAloneStaysOffline(t *testing.T) {
	f := &fakeEngine{res: licensedResult("GPL-3.0-only")}
	code, _, _ := runFake(t, f, "--path", t.TempDir(), "--deny-license", "GPL-3.0-only")
	if code != exitFailed {
		t.Fatalf("exit = %d, want %d", code, exitFailed)
	}
	if f.licenses {
		t.Error("--deny-license turned on the deps.dev lookup")
	}
}

func TestScanDenyLicenseExitCodes(t *testing.T) {
	cases := []struct {
		name     string
		licenses []string
		args     []string
		want     int
	}{
		{"denied", []string{"MIT", "GPL-3.0-only"}, []string{"--deny-license", "GPL-3.0-only"}, exitFailed},
		{"deprecated spelling", []string{"GPL-3.0"}, []string{"--deny-license", "gpl-3.0-only"}, exitFailed},
		{"one allowed branch", []string{"GPL-3.0-only OR MIT"}, []string{"--deny-license", "GPL-3.0-only"}, exitOK},
		{"unknown license", []string{""}, []string{"--deny-license", "GPL-3.0-only"}, exitOK},
		{"no policy", []string{"GPL-3.0-only"}, nil, exitOK},
		// --fail-on none turns off the vulnerability threshold only.
		{"fail-on none", []string{"GPL-3.0-only"}, []string{"--fail-on", "none", "--deny-license", "GPL-3.0-only"}, exitFailed},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := &fakeEngine{res: licensedResult(c.licenses...)}
			code, _, stderr := runFake(t, f, append([]string{"--path", t.TempDir()}, c.args...)...)
			if code != c.want {
				t.Fatalf("exit = %d, want %d\n%s", code, c.want, stderr)
			}
		})
	}
}

func TestScanDenyLicenseRejectsUnknownIDs(t *testing.T) {
	f := &fakeEngine{res: licensedResult("MIT")}
	code, _, stderr := runFake(t, f, "--path", t.TempDir(), "--deny-license", "GPLv3")
	if code != exitError || !strings.Contains(stderr, `invalid --deny-license: unknown SPDX license identifier "GPLv3"`) {
		t.Fatalf("exit = %d, stderr:\n%s", code, stderr)
	}
	if f.calls != 0 {
		t.Fatal("the scan ran despite a bad flag")
	}
}

func TestScanFailedLicenseLookupIsAnErrorUnderAPolicy(t *testing.T) {
	res := licensedResult("MIT")
	res.LicenseLookupFailed = 3
	res.Warnings = []string{"license lookup failed for 3 packages: deps.dev unreachable"}
	code, stdout, stderr := runFake(t, &fakeEngine{res: res}, "--path", t.TempDir(), "--licenses", "--deny-license", "GPL-3.0-only")
	if code != exitError || stdout != "" || !strings.Contains(stderr, "license check incomplete: the license lookup failed for 3 packages") {
		t.Fatalf("exit = %d, stdout %q, stderr:\n%s", code, stdout, stderr)
	}
	// Without a policy it is only a warning (in the table on stdout).
	code, stdout, _ = runFake(t, &fakeEngine{res: res}, "--path", t.TempDir(), "--licenses")
	if code != exitOK || !strings.Contains(stdout, "warning: license lookup failed for 3 packages") {
		t.Fatalf("exit = %d, stdout:\n%s", code, stdout)
	}
}

// Like the other checks that fail closed, an incomplete license check
// writes no report and removes the one an earlier run left at --out.
func TestScanFailedLicenseLookupRemovesTheStaleReport(t *testing.T) {
	res := licensedResult("MIT")
	res.LicenseLookupFailed = 1
	out := writeFile(t, t.TempDir(), "orbit.json", `{"stale":"clean report from an earlier run"}`)
	code, _, stderr := runFake(t, &fakeEngine{res: res}, "--path", t.TempDir(), "--licenses",
		"--deny-license", "GPL-3.0-only", "--format", "json", "--out", out)
	if code != exitError || !strings.Contains(stderr, "license check incomplete: the license lookup failed for 1 package\n") {
		t.Fatalf("exit = %d, stderr:\n%s", code, stderr)
	}
	if _, err := os.Stat(out); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("stale report kept: %v", err)
	}
}

func TestScanLicenseReportOutput(t *testing.T) {
	f := &fakeEngine{res: licensedResult("GPL-3.0-only", "MIT")}
	code, stdout, _ := runFake(t, f, "--path", t.TempDir(), "--format", "json", "--deny-license", "GPL-3.0-only")
	if code != exitFailed {
		t.Fatalf("exit = %d", code)
	}
	var doc struct {
		Summary struct {
			Failed        bool `json:"failed"`
			LicenseFailed bool `json:"license_failed"`
		} `json:"summary"`
		Dependencies []struct {
			License string `json:"license"`
		} `json:"dependencies"`
		LicenseViolations []struct {
			Package string   `json:"package"`
			Denied  []string `json:"denied"`
		} `json:"license_violations"`
	}
	if err := json.Unmarshal([]byte(stdout), &doc); err != nil {
		t.Fatal(err)
	}
	if !doc.Summary.Failed || !doc.Summary.LicenseFailed || len(doc.LicenseViolations) != 1 || doc.LicenseViolations[0].Package != "pkga" {
		t.Fatalf("report = %+v", doc)
	}
	if doc.Dependencies[0].License != "GPL-3.0-only" || doc.Dependencies[1].License != "MIT" {
		t.Fatalf("dependencies = %+v", doc.Dependencies)
	}

	_, table, _ := runFake(t, &fakeEngine{res: licensedResult("GPL-3.0-only")}, "--path", t.TempDir(), "--deny-license", "GPL-3.0-only")
	for _, want := range []string{"DENIED        PACKAGE     LICENSE       MANIFEST", "license policy (deny GPL-3.0-only): 1 violation, FAILED"} {
		if !strings.Contains(table, want) {
			t.Errorf("table lacks %q:\n%s", want, table)
		}
	}
}

func TestScanLicenseIgnoreEntryAcceptsAViolation(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, ".orbitignore", "license:GPL-3.0-only package=pkga  approved by legal\n")
	f := &fakeEngine{res: licensedResult("GPL-3.0-only")}
	code, stdout, _ := runFake(t, f, "--path", dir, "--deny-license", "GPL-3.0-only")
	if code != exitOK || !strings.Contains(stdout, "GPL-3.0-only (ignored)") {
		t.Fatalf("exit = %d\n%s", code, stdout)
	}
}

// The policy runs on every scan, so a license: entry that no --deny-license
// needs is reported as unused rather than silently kept.
func TestScanWarnsAboutLicenseEntriesWithoutAPolicy(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, ".orbitignore", "license:GPL-3.0-only package=pkga  approved by legal\n")
	code, stdout, _ := runFake(t, &fakeEngine{res: licensedResult("GPL-3.0-only")}, "--path", dir)
	if code != exitOK || !strings.Contains(stdout, "warning: unused ignore entry license:GPL-3.0-only package=pkga") {
		t.Fatalf("exit = %d\n%s", code, stdout)
	}
}

// Without --licenses an unknown license is not looked up; the warning says
// how to look it up.
func TestScanDenyLicenseHintsAtLicensesForUnknownLicenses(t *testing.T) {
	code, stdout, _ := runFake(t, &fakeEngine{res: licensedResult("", "MIT")}, "--path", t.TempDir(), "--deny-license", "GPL-3.0-only")
	if code != exitOK || !strings.Contains(stdout, "warning: license policy: 1 dependency has no known license and was not checked; --licenses looks them up on deps.dev") {
		t.Fatalf("exit = %d\n%s", code, stdout)
	}
	_, stdout, _ = runFake(t, &fakeEngine{res: licensedResult("", "MIT")}, "--path", t.TempDir(), "--licenses", "--deny-license", "GPL-3.0-only")
	if !strings.Contains(stdout, "was not checked\n") {
		t.Fatalf("hint shown with --licenses:\n%s", stdout)
	}
}

// With --fail-on none a license policy is still a failure threshold, so the
// stderr summary does not claim there is none.
func TestScanSummaryWithALicensePolicyAndNoThreshold(t *testing.T) {
	out := filepath.Join(t.TempDir(), "orbit.json")
	code, _, stderr := runFake(t, &fakeEngine{res: licensedResult("GPL-3.0-only")}, "--path", t.TempDir(),
		"--fail-on", "none", "--deny-license", "GPL-3.0-only", "--format", "json", "--out", out)
	if code != exitFailed {
		t.Fatalf("exit = %d\n%s", code, stderr)
	}
	if strings.Contains(stderr, "no failure threshold") || !strings.Contains(stderr, "orbit: license policy (deny GPL-3.0-only): 1 violation, FAILED") {
		t.Fatalf("stderr:\n%s", stderr)
	}
	_, _, stderr = runFake(t, &fakeEngine{res: licensedResult("GPL-3.0-only")}, "--path", t.TempDir(),
		"--fail-on", "none", "--format", "json", "--out", out)
	if !strings.Contains(stderr, "orbit: no failure threshold (--fail-on none)") {
		t.Fatalf("stderr:\n%s", stderr)
	}
}

// The real engine reads the lockfile's license, so a policy works without
// any network lookup.
func TestScanRealEngineDeniesALockfileLicense(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "package.json", `{"dependencies":{"gpl-pkg":"1.0.0"}}`)
	writeFile(t, dir, "package-lock.json", `{"lockfileVersion":3,"packages":{"node_modules/gpl-pkg":{"version":"1.0.0","license":"GPL-3.0-or-later"}}}`)
	code, stdout, stderr := runReal(t, nil, "--path", dir, "--format", "junit", "--deny-license", "GPL-3.0-or-later")
	if code != exitFailed || !strings.Contains(stdout, `name="gpl-pkg@1.0.0: license GPL-3.0-or-later"`) {
		t.Fatalf("exit = %d\n%s\n%s", code, stdout, stderr)
	}
}
