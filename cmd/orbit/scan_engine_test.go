package main

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/orchesta/orbit/internal/domain/entity"
	"github.com/orchesta/orbit/internal/engine"
	"github.com/orchesta/orbit/internal/infrastructure/exploit"
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

// realDepsWith runs the production engine (all analyzers, no registry
// lookups) with lookup in place of osv.dev and enricher, when exploit data
// is on, in place of cisa.gov and api.first.org.
func realDepsWith(lookup engine.VulnLookup, enricher engine.ExploitEnricher) scanDeps {
	return scanDeps{
		newEngine: func(ec engineConfig, logger *slog.Logger) analyzerEngine {
			opts := engine.Options{CheckLatest: ec.checkLatest, Logger: logger}
			if ec.exploitData && enricher != nil {
				opts.Exploit = enricher
			}
			return engine.New(newAnalyzerRegistry(), lookup, opts)
		},
		now: func() time.Time { return testNow },
	}
}

func realDeps(lookup engine.VulnLookup) scanDeps { return realDepsWith(lookup, nil) }

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

// jqueryAdvisory answers like vulnerability.Lookup for jquery@3.4.1's
// CVE-2020-11023, which CISA added to KEV on 2025-01-23.
type jqueryAdvisory struct{}

func (jqueryAdvisory) Lookup(_ context.Context, deps []*entity.Dependency) ([]*entity.Vulnerability, int, error) {
	var vulns []*entity.Vulnerability
	for _, d := range deps {
		if d.Name == "jquery" {
			v := entity.NewVulnerability(d.ID, "CVE-2020-11023", "Potential XSS vulnerability in jQuery", entity.SeverityMedium)
			v.Aliases = []string{"BIT-drupal-2020-11023", "GHSA-jpcq-cgw6-v4j6"}
			v.FixedVersion = ptr("3.5.0")
			vulns = append(vulns, v)
		}
	}
	return vulns, len(vulns), nil
}

func writeJQueryProject(t *testing.T, dir string) {
	t.Helper()
	writeFile(t, dir, "package.json", `{"name":"e2e","version":"1.0.0","dependencies":{"jquery":"3.4.1"}}`)
	writeFile(t, dir, "package-lock.json", `{
  "name": "e2e", "version": "1.0.0", "lockfileVersion": 3, "requires": true,
  "packages": {
    "": {"name": "e2e", "version": "1.0.0", "dependencies": {"jquery": "3.4.1"}},
    "node_modules/jquery": {"version": "3.4.1", "resolved": "https://registry.npmjs.org/jquery/-/jquery-3.4.1.tgz"}
  }
}`)
}

// exploitServer answers like cisa.gov and api.first.org and counts requests.
func exploitServer(t *testing.T) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var hits atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/kev.json", func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte(`{"title":"CISA Catalog of Known Exploited Vulnerabilities","catalogVersion":"2026.10.14","count":1,
"vulnerabilities":[{"cveID":"CVE-2020-11023","vendorProject":"JQuery","product":"JQuery","dateAdded":"2025-01-23","dueDate":"2025-02-13","knownRansomwareCampaignUse":"Unknown","cwes":["CWE-79"]}]}`))
	})
	mux.HandleFunc("/epss", func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte(`{"status":"OK","status-code":200,"version":"1.0","total":1,"offset":0,"limit":1,
"data":[{"cve":"CVE-2020-11023","epss":"0.848870000","percentile":"0.997100000","date":"2026-10-14"}]}`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, &hits
}

func TestScanRealEngineAddsExploitData(t *testing.T) {
	srv, hits := exploitServer(t)
	enricher := exploit.NewEnricher(exploit.Config{KEVURL: srv.URL + "/kev.json", EPSSURL: srv.URL + "/epss"})
	dir := t.TempDir()
	writeJQueryProject(t, dir)

	var out, errOut bytes.Buffer
	code := runScan(context.Background(), []string{"--path", dir, "--format", "json", "--fail-on-kev"}, &out, &errOut, realDepsWith(jqueryAdvisory{}, enricher))
	if code != 1 {
		t.Fatalf("exit = %d, want 1 (medium, but in KEV); stderr:\n%s", code, errOut.String())
	}
	var doc struct {
		Findings []struct {
			ID           string   `json:"id"`
			KEV          bool     `json:"kev"`
			KEVDateAdded *string  `json:"kev_date_added"`
			EPSS         *float64 `json:"epss"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Findings) != 1 || !doc.Findings[0].KEV || *doc.Findings[0].KEVDateAdded != "2025-01-23" || *doc.Findings[0].EPSS != 0.84887 {
		t.Fatalf("findings = %+v", doc.Findings)
	}

	before := hits.Load()
	out.Reset()
	code = runScan(context.Background(), []string{"--path", dir, "--format", "json", "--no-exploit-data"}, &out, &errOut, realDepsWith(jqueryAdvisory{}, enricher))
	if code != 0 || hits.Load() != before || !strings.Contains(out.String(), `"kev": "disabled"`) {
		t.Fatalf("--no-exploit-data: exit %d, %d requests; want 0 and none", code, hits.Load()-before)
	}
}
