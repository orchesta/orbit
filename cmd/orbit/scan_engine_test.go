package main

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aligoren/orbit/internal/domain/entity"
	"github.com/aligoren/orbit/internal/engine"
)

// lodashAdvisories answers like vulnerability.Lookup does for
// lodash@4.17.15: the two GitHub advisories for CVE-2021-23337 both get the
// CVE as primary ID and list each other as aliases.
type lodashAdvisories struct{}

func (lodashAdvisories) Lookup(_ context.Context, deps []*entity.Dependency) ([]*entity.Vulnerability, int, error) {
	var vulns []*entity.Vulnerability
	n := 0
	for _, d := range deps {
		if d.Name != "lodash" {
			continue
		}
		n++
		a := entity.NewVulnerability(d.ID, "CVE-2021-23337", "", entity.SeverityHigh)
		a.Aliases = []string{"GHSA-35jh-r3h4-6jhm", "CVE-2021-23337", "GHSA-r5fr-rjxr-66jc"}
		a.FixedVersion = ptr("4.17.21")
		b := entity.NewVulnerability(d.ID, "CVE-2021-23337", "", entity.SeverityHigh)
		b.Aliases = []string{"GHSA-r5fr-rjxr-66jc", "CVE-2021-23337", "GHSA-35jh-r3h4-6jhm"}
		b.FixedVersion = ptr("4.18.0")
		vulns = append(vulns, a, b)
	}
	return vulns, n, nil
}

func ptr(s string) *string { return &s }

// realDeps runs the production engine (all analyzers, no registry lookups)
// with lookup in place of osv.dev.
func realDeps(lookup engine.VulnLookup) scanDeps {
	return scanDeps{
		newEngine: func(checkLatest bool, logger *slog.Logger) analyzerEngine {
			return engine.New(newAnalyzerRegistry(), lookup, engine.Options{CheckLatest: checkLatest, Logger: logger})
		},
		now: func() time.Time { return testNow },
	}
}

// writeLodashProject writes an npm project pinning lodash@4.17.15 with a
// lockfile v3.
func writeLodashProject(t *testing.T, dir string) {
	t.Helper()
	writeFile(t, dir, "package.json", `{"name":"e2e","version":"1.0.0","dependencies":{"lodash":"4.17.15"}}`)
	writeFile(t, dir, "package-lock.json", `{
  "name": "e2e", "version": "1.0.0", "lockfileVersion": 3, "requires": true,
  "packages": {
    "": {"name": "e2e", "version": "1.0.0", "dependencies": {"lodash": "4.17.15"}},
    "node_modules/lodash": {"version": "4.17.15", "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.15.tgz"}
  }
}`)
}

func runReal(t *testing.T, lookup engine.VulnLookup, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code = runScan(context.Background(), args, &out, &errOut, realDeps(lookup))
	return code, out.String(), errOut.String()
}

type jsonReport struct {
	Summary struct {
		Dependencies int            `json:"dependencies"`
		BySeverity   map[string]int `json:"by_severity"`
		Warnings     []string       `json:"warnings"`
	} `json:"summary"`
	Findings []struct {
		ID           string   `json:"id"`
		Aliases      []string `json:"aliases"`
		Package      string   `json:"package"`
		FixedVersion *string  `json:"fixed_version"`
		Ignored      bool     `json:"ignored"`
	} `json:"findings"`
}

// The real engine and report path: aliased advisories become one finding,
// and an ignore entry for either GitHub advisory suppresses it.
func TestScanRealEngineMergesAliasedAdvisories(t *testing.T) {
	dir := t.TempDir()
	writeLodashProject(t, dir)

	code, stdout, stderr := runReal(t, lodashAdvisories{}, "--path", dir, "--format", "json")
	if code != 1 {
		t.Fatalf("exit = %d, want 1; stderr:\n%s", code, stderr)
	}
	var rep jsonReport
	if err := json.Unmarshal([]byte(stdout), &rep); err != nil {
		t.Fatalf("%v\n%s", err, stdout)
	}
	if rep.Summary.Dependencies != 1 || len(rep.Findings) != 1 || rep.Summary.BySeverity["high"] != 1 {
		t.Fatalf("report = %+v, want one high finding on one dependency", rep)
	}
	f := rep.Findings[0]
	if f.ID != "CVE-2021-23337" || f.Package != "lodash" || f.FixedVersion == nil || *f.FixedVersion != "4.18.0" {
		t.Fatalf("finding = %+v, want CVE-2021-23337 on lodash fixed in 4.18.0", f)
	}

	writeFile(t, dir, ".orbitignore", "GHSA-r5fr-rjxr-66jc accepted until the upgrade\n")
	code, stdout, stderr = runReal(t, lodashAdvisories{}, "--path", dir, "--format", "json")
	if code != 0 {
		t.Fatalf("with ignore: exit = %d, want 0; stderr:\n%s", code, stderr)
	}
	rep = jsonReport{}
	if err := json.Unmarshal([]byte(stdout), &rep); err != nil {
		t.Fatal(err)
	}
	if len(rep.Findings) != 1 || !rep.Findings[0].Ignored || len(rep.Summary.Warnings) != 0 {
		t.Fatalf("with ignore: report = %+v, want the one finding ignored and no warnings", rep)
	}
}

func TestScanSymlinkedPathScansTheTarget(t *testing.T) {
	target := t.TempDir()
	writeLodashProject(t, target)
	link := filepath.Join(t.TempDir(), "checkout")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}

	f := &fakeEngine{res: resultWith()}
	if code, _, stderr := runFake(t, f, "--path", link); code != 0 {
		t.Fatalf("exit = %d; stderr:\n%s", code, stderr)
	}
	want, err := filepath.EvalSymlinks(target)
	if err != nil {
		t.Fatal(err)
	}
	if f.root != want {
		t.Errorf("analyzed %q, want the resolved target %q", f.root, want)
	}

	code, stdout, stderr := runReal(t, lodashAdvisories{}, "--path", link, "--format", "json", "--fail-on", "none")
	if code != 0 {
		t.Fatalf("real engine: exit = %d; stderr:\n%s", code, stderr)
	}
	var rep jsonReport
	if err := json.Unmarshal([]byte(stdout), &rep); err != nil {
		t.Fatal(err)
	}
	if rep.Summary.Dependencies != 1 {
		t.Fatalf("real engine through a symlink found %d dependencies, want 1; stderr:\n%s", rep.Summary.Dependencies, stderr)
	}
}

func TestScanEmptyDirectoryWarnsAndPasses(t *testing.T) {
	dir := t.TempDir()
	code, stdout, stderr := runReal(t, lodashAdvisories{}, "--path", dir)
	if code != 0 {
		t.Fatalf("exit = %d, want 0; stderr:\n%s", code, stderr)
	}
	// The default table on stdout carries the warnings.
	if !strings.Contains(stdout, "warning: no manifest or lockfile found under ") {
		t.Fatalf("output lacks the empty-tree warning:\n%s", stdout)
	}
}
