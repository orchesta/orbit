package report

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/google/uuid"

	"github.com/aligoren/orbit/internal/domain/entity"
	"github.com/aligoren/orbit/internal/engine"
)

type sarifLocations struct {
	Runs []struct {
		OriginalURIBaseIDs map[string]struct {
			URI string `json:"uri"`
		} `json:"originalUriBaseIds"`
		Results []struct {
			Locations []struct {
				PhysicalLocation struct {
					ArtifactLocation struct {
						URI       string `json:"uri"`
						URIBaseID string `json:"uriBaseId"`
					} `json:"artifactLocation"`
				} `json:"physicalLocation"`
			} `json:"locations"`
			PartialFingerprints map[string]string `json:"partialFingerprints"`
		} `json:"results"`
	} `json:"runs"`
}

func oddPathResult() *engine.Result {
	dep := &entity.Dependency{ID: uuid.New(), Name: "lodash", CurrentVersion: "4.17.15", Ecosystem: entity.EcosystemNpm,
		ManifestFile: "my app/a:b/100%/package-lock.json"}
	return &engine.Result{
		Dependencies: []*entity.Dependency{dep},
		Vulnerabilities: []*entity.Vulnerability{{ID: uuid.New(), DependencyID: dep.ID, OSVID: "GHSA-1",
			Severity: entity.SeverityHigh, Summary: "s"}},
	}
}

func writeSARIFLocations(t *testing.T, res *engine.Result, opts SARIFOptions) (sarifLocations, []byte) {
	t.Helper()
	f, s := Build(res, nil, entity.SeverityHigh, fixedNow)
	var b bytes.Buffer
	if err := WriteSARIF(&b, f, s, testTool, opts); err != nil {
		t.Fatal(err)
	}
	var doc sarifLocations
	if err := json.Unmarshal(b.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	return doc, b.Bytes()
}

// Paths are prefixed with the scanned directory relative to the working
// directory and percent-encoded per segment, ":" included, so the URI is a
// valid relative reference.
func TestSARIFURIsArePrefixedAndEscaped(t *testing.T) {
	doc, _ := writeSARIFLocations(t, oddPathResult(), SARIFOptions{PathPrefix: "svc/api v2"})
	loc := doc.Runs[0].Results[0].Locations[0].PhysicalLocation.ArtifactLocation
	if want := "svc/api%20v2/my%20app/a%3Ab/100%25/package-lock.json"; loc.URI != want || loc.URIBaseID != "" {
		t.Fatalf("location = %+v, want uri %q without a base", loc, want)
	}
	if doc.Runs[0].OriginalURIBaseIDs != nil {
		t.Errorf("originalUriBaseIds = %v, want none", doc.Runs[0].OriginalURIBaseIDs)
	}
}

func TestSARIFFingerprintIgnoresThePrefix(t *testing.T) {
	a, _ := writeSARIFLocations(t, oddPathResult(), SARIFOptions{})
	b, _ := writeSARIFLocations(t, oddPathResult(), SARIFOptions{PathPrefix: "svc"})
	if a.Runs[0].Results[0].PartialFingerprints["orbit/v1"] != b.Runs[0].Results[0].PartialFingerprints["orbit/v1"] {
		t.Error("the fingerprint must not depend on where the scan ran from")
	}
}

// Outside the working directory the URIs stay relative to the scanned
// directory, whose absolute URI is given as the ORBITROOT base.
func TestSARIFURIsUseABaseOutsideTheWorkingDirectory(t *testing.T) {
	doc, out := writeSARIFLocations(t, oddPathResult(), SARIFOptions{RootURI: "file:///work/my%20repo/"})
	loc := doc.Runs[0].Results[0].Locations[0].PhysicalLocation.ArtifactLocation
	if loc.URI != "my%20app/a%3Ab/100%25/package-lock.json" || loc.URIBaseID != "ORBITROOT" {
		t.Fatalf("location = %+v", loc)
	}
	if got := doc.Runs[0].OriginalURIBaseIDs["ORBITROOT"].URI; got != "file:///work/my%20repo/" {
		t.Fatalf("ORBITROOT = %q", got)
	}
	golden(t, "report.sarif.base.golden", out)
}
