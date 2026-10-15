package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/orchesta/orbit/internal/domain/entity"
)

// debugAdvisories answers like vulnerability.Lookup for debug@4.4.2 when
// osv.dev returns only the GitHub advisory: rated high, with the OpenSSF
// MAL- advisory among its aliases.
type debugAdvisories struct{}

func (debugAdvisories) Lookup(_ context.Context, deps []*entity.Dependency) ([]*entity.Vulnerability, int, error) {
	var vulns []*entity.Vulnerability
	n := 0
	for _, d := range deps {
		if d.Name != "debug" {
			continue
		}
		n++
		v := entity.NewVulnerability(d.ID, "CVE-2025-59144", "debug@4.4.2 contains malware after npm account takeover", entity.SeverityHigh)
		v.Aliases = []string{"GHSA-4x49-vf9v-38px", "GHSA-8mgj-vmr8-frr6", "MAL-2025-46974"}
		v.FixedVersion = ptr("4.4.3")
		vulns = append(vulns, v)
	}
	return vulns, n, nil
}

// writeDebugProject writes an npm project pinning debug@4.4.2 with a
// lockfile v3.
func writeDebugProject(t *testing.T, dir string) {
	t.Helper()
	writeFile(t, dir, "package.json", `{"name":"e2e","version":"1.0.0","dependencies":{"debug":"4.4.2"}}`)
	writeFile(t, dir, "package-lock.json", `{
  "name": "e2e", "version": "1.0.0", "lockfileVersion": 3, "requires": true,
  "packages": {
    "": {"name": "e2e", "version": "1.0.0", "dependencies": {"debug": "4.4.2"}},
    "node_modules/debug": {"version": "4.4.2", "resolved": "https://registry.npmjs.org/debug/-/debug-4.4.2.tgz"}
  }
}`)
}

func TestScanMaliciousPackageFailsAtEveryThreshold(t *testing.T) {
	dir := t.TempDir()
	writeDebugProject(t, dir)
	for failOn, want := range map[string]int{"critical": 1, "high": 1, "low": 1, "unknown": 1, "none": 0} {
		t.Run(failOn, func(t *testing.T) {
			code, _, stderr := runReal(t, debugAdvisories{}, "--path", dir, "--fail-on", failOn, "--quiet")
			if code != want {
				t.Fatalf("--fail-on %s: exit = %d, want %d; stderr:\n%s", failOn, code, want, stderr)
			}
		})
	}
}

func TestScanMaliciousPackageIgnoreEntryIsNotApplied(t *testing.T) {
	dir := t.TempDir()
	writeDebugProject(t, dir)
	writeFile(t, dir, ".orbitignore", "CVE-2025-59144 not reachable\n")
	code, stdout, stderr := runReal(t, debugAdvisories{}, "--path", dir)
	if code != 1 {
		t.Fatalf("exit = %d, want 1: a malicious package cannot be ignored; stderr:\n%s", code, stderr)
	}
	want := "warning: ignore entry CVE-2025-59144 not applied: debug@4.4.2 is a known malicious package (MAL-2025-46974)"
	if !strings.Contains(stdout, want) {
		t.Fatalf("table lacks %q:\n%s", want, stdout)
	}
	if strings.Contains(stdout, "(ignored)") || strings.Contains(stdout, "unused ignore entry") {
		t.Fatalf("finding shown as ignored or entry as unused:\n%s", stdout)
	}
}

func TestScanMaliciousPackageInJSONAndSummary(t *testing.T) {
	dir := t.TempDir()
	writeDebugProject(t, dir)
	code, stdout, stderr := runReal(t, debugAdvisories{}, "--path", dir, "--format", "json")
	if code != 1 {
		t.Fatalf("exit = %d, want 1; stderr:\n%s", code, stderr)
	}
	var rep struct {
		Summary struct {
			Malicious int `json:"malicious"`
		} `json:"summary"`
		Findings []struct {
			ID        string `json:"id"`
			Malicious bool   `json:"malicious"`
		} `json:"findings"`
	}
	if err := json.Unmarshal([]byte(stdout), &rep); err != nil {
		t.Fatalf("%v\n%s", err, stdout)
	}
	if rep.Summary.Malicious != 1 || len(rep.Findings) != 1 || !rep.Findings[0].Malicious || rep.Findings[0].ID != "CVE-2025-59144" {
		t.Fatalf("report = %+v, want one malicious finding CVE-2025-59144", rep)
	}
	if want := "orbit: 1 dependencies, 1 vulnerable (1 high), 1 malicious"; !strings.Contains(stderr, want) {
		t.Fatalf("stderr lacks %q:\n%s", want, stderr)
	}
}
