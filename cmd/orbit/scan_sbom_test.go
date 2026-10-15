package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/orchesta/orbit/internal/buildinfo"
	"github.com/orchesta/orbit/internal/domain/entity"
	"github.com/orchesta/orbit/internal/engine"
)

var testSerial = uuid.MustParse("3e671687-395b-41f5-a30f-a58921a69b79")

func (f *fakeEngine) sbomDeps() scanDeps {
	d := f.deps()
	d.newUUID = func() uuid.UUID { return testSerial }
	return d
}

func TestScanCycloneDXToFile(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "shop")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "orbit.cdx.json")
	f := &fakeEngine{res: resultWith(entity.SeverityHigh)}
	var stdout, stderr strings.Builder
	code := runScan(t.Context(), []string{"--path", dir, "--format", "cyclonedx", "--out", out}, &stdout, &stderr, f.sbomDeps())
	if code != exitFailed {
		t.Fatalf("exit = %d, want 1: an SBOM run still applies --fail-on; stderr:\n%s", code, stderr.String())
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	var bom struct {
		BOMFormat    string `json:"bomFormat"`
		SpecVersion  string `json:"specVersion"`
		SerialNumber string `json:"serialNumber"`
		Metadata     struct {
			Timestamp string `json:"timestamp"`
			Tools     struct {
				Components []struct{ Name, Version string } `json:"components"`
			} `json:"tools"`
			Component struct{ Name string } `json:"component"`
		} `json:"metadata"`
		Components      []struct{ PURL string } `json:"components"`
		Vulnerabilities []struct{ ID string }   `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(data, &bom); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, data)
	}
	if bom.BOMFormat != "CycloneDX" || bom.SpecVersion != "1.6" || bom.SerialNumber != "urn:uuid:"+testSerial.String() {
		t.Errorf("header = %+v", bom)
	}
	if bom.Metadata.Timestamp != "2026-10-15T12:00:00Z" || bom.Metadata.Component.Name != "shop" {
		t.Errorf("metadata = %+v", bom.Metadata)
	}
	if tc := bom.Metadata.Tools.Components; len(tc) != 1 || tc[0].Name != "orbit" || tc[0].Version != buildinfo.Version {
		t.Errorf("tools = %+v", tc)
	}
	if len(bom.Components) != 1 || bom.Components[0].PURL != "pkg:npm/lodash@4.17.20" {
		t.Errorf("components = %+v", bom.Components)
	}
	if len(bom.Vulnerabilities) != 1 || bom.Vulnerabilities[0].ID != "GHSA-0" {
		t.Errorf("vulnerabilities = %+v", bom.Vulnerabilities)
	}
	if !strings.Contains(stderr.String(), "orbit: wrote cyclonedx report to") || !strings.Contains(stderr.String(), "threshold high: FAILED") {
		t.Errorf("stderr:\n%s", stderr.String())
	}
}

func TestScanSPDXToStdoutWithName(t *testing.T) {
	f := &fakeEngine{res: resultWith(entity.SeverityHigh)}
	var stdout, stderr strings.Builder
	code := runScan(t.Context(), []string{"--path", t.TempDir(), "--format", "spdx", "--fail-on", "none", "--sbom-name", "acme/shop"},
		&stdout, &stderr, f.sbomDeps())
	if code != exitOK {
		t.Fatalf("exit = %d, want 0 with --fail-on none; stderr:\n%s", code, stderr.String())
	}
	var doc struct {
		SPDXVersion       string `json:"spdxVersion"`
		Name              string `json:"name"`
		DocumentNamespace string `json:"documentNamespace"`
		CreationInfo      struct {
			Creators []string `json:"creators"`
		} `json:"creationInfo"`
	}
	if err := json.Unmarshal([]byte(stdout.String()), &doc); err != nil {
		t.Fatalf("stdout is not the SPDX document: %v\n%s", err, stdout.String())
	}
	if doc.SPDXVersion != "SPDX-2.3" || doc.Name != "acme/shop" {
		t.Errorf("doc = %+v", doc)
	}
	if want := "https://github.com/orchesta/orbit/spdx/acme%2Fshop-" + testSerial.String(); doc.DocumentNamespace != want {
		t.Errorf("documentNamespace = %s, want %s", doc.DocumentNamespace, want)
	}
	if c := doc.CreationInfo.Creators; len(c) != 1 || c[0] != "Tool: orbit-"+buildinfo.Version {
		t.Errorf("creators = %v", c)
	}
	if strings.Contains(stdout.String(), "orbit: ") {
		t.Error("the summary must go to stderr, not into the document")
	}
}

func TestScanSBOMSuggestsLicenses(t *testing.T) {
	f := &fakeEngine{res: resultWith()}
	var stdout, stderr strings.Builder
	runScan(t.Context(), []string{"--path", t.TempDir(), "--format", "cyclonedx"}, &stdout, &stderr, f.sbomDeps())
	if !strings.Contains(stderr.String(), "1 of 1 dependencies have no license in the SBOM; --licenses") {
		t.Errorf("want the --licenses hint:\n%s", stderr.String())
	}
	for _, args := range [][]string{
		{"--format", "json"},
		{"--format", "cyclonedx", "--quiet"},
		{"--format", "cyclonedx", "--licenses"},
	} {
		stderr.Reset()
		runScan(t.Context(), append([]string{"--path", t.TempDir()}, args...), &stdout, &stderr, f.sbomDeps())
		if strings.Contains(stderr.String(), "--licenses looks") {
			t.Errorf("%v: unexpected hint:\n%s", args, stderr.String())
		}
	}
}

func TestSBOMOptionsName(t *testing.T) {
	root := filepath.Join(t.TempDir(), "api")
	if got := sbomOptions(scanConfig{}, root, testNow, nil).Name; got != "api" {
		t.Errorf("default name = %q, want api", got)
	}
	if got := sbomOptions(scanConfig{sbomName: "acme/api"}, root, testNow, nil).Name; got != "acme/api" {
		t.Errorf("--sbom-name = %q", got)
	}
	if got := sbomOptions(scanConfig{}, string(filepath.Separator), testNow, nil).Name; got != "" {
		t.Errorf("filesystem root = %q, want empty (writers say unnamed)", got)
	}
	a, b := sbomOptions(scanConfig{}, root, testNow, nil), sbomOptions(scanConfig{}, root, testNow, nil)
	if a.Serial == b.Serial {
		t.Error("each run needs a new serial number")
	}
}

// cdxDoc is the part of a CycloneDX BOM the CLI tests below read.
type cdxDoc struct {
	SerialNumber string `json:"serialNumber"`
	Metadata     struct {
		Timestamp string `json:"timestamp"`
	} `json:"metadata"`
	Components []struct {
		Name     string `json:"name"`
		Licenses []struct {
			Expression string `json:"expression"`
		} `json:"licenses"`
	} `json:"components"`
	Vulnerabilities []struct {
		ID string `json:"id"`
	} `json:"vulnerabilities"`
}

func parseCDX(t *testing.T, data string) cdxDoc {
	t.Helper()
	var bom cdxDoc
	if err := json.Unmarshal([]byte(data), &bom); err != nil {
		t.Fatalf("not a CycloneDX document: %v\n%s", err, data)
	}
	return bom
}

// An SBOM run keeps the gate of every other format: --fail-on, --fail-on-kev,
// --baseline (which only gates, the SBOM still lists every vulnerability)
// and --deny-license. The document is written whatever the verdict.
func TestScanSBOMKeepsTheGate(t *testing.T) {
	cases := []struct {
		name  string
		res   *engine.Result
		args  []string
		want  int
		vulns int
	}{
		{"fail-on none", resultWith(entity.SeverityCritical), []string{"--fail-on", "none"}, exitOK, 1},
		{"fail-on", resultWith(entity.SeverityCritical), []string{"--fail-on", "critical"}, exitFailed, 1},
		{"below fail-on", resultWith(entity.SeverityMedium), nil, exitOK, 1},
		{"fail-on-kev", kevResult(), []string{"--fail-on-kev"}, exitFailed, 1},
		{"baseline lists it", resultWith(entity.SeverityHigh), []string{"--baseline", writeBaseline(t, "GHSA-0")}, exitOK, 1},
		{"baseline lacks it", resultWith(entity.SeverityHigh), []string{"--baseline", writeBaseline(t, "GHSA-9")}, exitFailed, 1},
		{"deny-license", licensedResult("GPL-3.0-only"), []string{"--fail-on", "none", "--deny-license", "GPL-3.0-only"}, exitFailed, 0},
	}
	for _, format := range sbomFormats {
		for _, c := range cases {
			t.Run(format+"/"+c.name, func(t *testing.T) {
				f := &fakeEngine{res: c.res}
				args := append([]string{"--path", t.TempDir(), "--format", format}, c.args...)
				var stdout, stderr strings.Builder
				code := runScan(t.Context(), args, &stdout, &stderr, f.sbomDeps())
				if code != c.want {
					t.Fatalf("exit = %d, want %d; stderr:\n%s", code, c.want, stderr.String())
				}
				if !json.Valid([]byte(stdout.String())) {
					t.Fatalf("stdout is not the document:\n%s", stdout.String())
				}
				if format == "cyclonedx" {
					if got := len(parseCDX(t, stdout.String()).Vulnerabilities); got != c.vulns {
						t.Errorf("vulnerabilities = %d, want %d", got, c.vulns)
					}
				}
			})
		}
	}
}

// A run that cannot complete exits 2, writes nothing to stdout and removes a
// stale SBOM, as for the other formats.
func TestScanSBOMFailureRemovesStaleReport(t *testing.T) {
	for _, format := range sbomFormats {
		t.Run(format, func(t *testing.T) {
			out := writeFile(t, t.TempDir(), "orbit."+format+".json", `{"stale":"SBOM from an earlier run"}`)
			f := &fakeEngine{err: fmt.Errorf("%w: osv.dev returned 503", engine.ErrVulnerabilityCheck)}
			var stdout, stderr strings.Builder
			code := runScan(t.Context(), []string{"--path", t.TempDir(), "--format", format, "--out", out}, &stdout, &stderr, f.sbomDeps())
			if code != exitError {
				t.Fatalf("exit = %d, want 2; stderr:\n%s", code, stderr.String())
			}
			if stdout.Len() != 0 {
				t.Errorf("stdout must be empty, got:\n%s", stdout.String())
			}
			if _, err := os.Stat(out); !os.IsNotExist(err) {
				t.Errorf("a failed run left %s behind (stat err %v)", out, err)
			}
		})
	}
}

// --quiet drops the progress lines and the --licenses hint but keeps the
// summary; the file is written as usual.
func TestScanSBOMQuietToFile(t *testing.T) {
	out := filepath.Join(t.TempDir(), "orbit.spdx.json")
	f := &fakeEngine{res: resultWith(entity.SeverityHigh)}
	var stdout, stderr strings.Builder
	code := runScan(t.Context(), []string{"--path", t.TempDir(), "--format", "spdx", "--out", out, "--quiet"}, &stdout, &stderr, f.sbomDeps())
	if code != exitFailed {
		t.Fatalf("exit = %d, want 1; stderr:\n%s", code, stderr.String())
	}
	if stdout.Len() != 0 {
		t.Errorf("stdout must be empty with --out, got:\n%s", stdout.String())
	}
	data, err := os.ReadFile(out)
	if err != nil || !strings.Contains(string(data), `"spdxVersion": "SPDX-2.3"`) {
		t.Fatalf("SPDX file not written (err %v):\n%s", err, data)
	}
	for _, unwanted := range []string{"orbit: scanning", "orbit: wrote", "--licenses looks"} {
		if strings.Contains(stderr.String(), unwanted) {
			t.Errorf("--quiet printed %q:\n%s", unwanted, stderr.String())
		}
	}
	if !strings.Contains(stderr.String(), "orbit: threshold high: FAILED") {
		t.Errorf("--quiet dropped the summary:\n%s", stderr.String())
	}
}

// Without an injected generator every run gets a new random serial number,
// never the zero UUID, and the scan time as its timestamp.
func TestScanSBOMFreshSerialAndScanTime(t *testing.T) {
	var serials []string
	for range 2 {
		_, stdout, stderr := runFake(t, &fakeEngine{res: resultWith()}, "--path", t.TempDir(), "--format", "cyclonedx")
		bom := parseCDX(t, stdout)
		if bom.Metadata.Timestamp != "2026-10-15T12:00:00Z" {
			t.Errorf("timestamp = %q, want the scan time; stderr:\n%s", bom.Metadata.Timestamp, stderr)
		}
		if bom.SerialNumber == "urn:uuid:"+uuid.Nil.String() {
			t.Error("zero serial number")
		}
		serials = append(serials, bom.SerialNumber)
	}
	if serials[0] == serials[1] {
		t.Errorf("two runs share the serial number %s", serials[0])
	}
}

// Known licenses go into the SBOM, and the hint counts only the missing ones.
func TestScanSBOMCarriesLicenses(t *testing.T) {
	f := &fakeEngine{res: licensedResult("MIT", "")}
	var stdout, stderr strings.Builder
	runScan(t.Context(), []string{"--path", t.TempDir(), "--format", "cyclonedx"}, &stdout, &stderr, f.sbomDeps())
	bom := parseCDX(t, stdout.String())
	if len(bom.Components) != 2 || len(bom.Components[0].Licenses) != 1 || bom.Components[0].Licenses[0].Expression != "MIT" ||
		len(bom.Components[1].Licenses) != 0 {
		t.Errorf("components = %+v", bom.Components)
	}
	if !strings.Contains(stderr.String(), "orbit: 1 of 2 dependencies have no license in the SBOM; --licenses looks them up on deps.dev\n") {
		t.Errorf("stderr:\n%s", stderr.String())
	}
}

func TestScanSBOMFormatIsCaseInsensitive(t *testing.T) {
	code, stdout, stderr := runFake(t, &fakeEngine{res: resultWith()}, "--path", t.TempDir(), "--format", "CycloneDX")
	if code != exitOK || !strings.Contains(stdout, `"bomFormat": "CycloneDX"`) {
		t.Errorf("exit = %d; stdout:\n%s\nstderr:\n%s", code, stdout, stderr)
	}
}
