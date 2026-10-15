package handler

import (
	"encoding/json"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/orchesta/orbit/internal/domain/entity"
	"github.com/orchesta/orbit/internal/usecase/scan"
)

var sbomTestNow = time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)

const sbomTestSerial = "3e671687-395b-41f5-a30f-a58921a69b79"

// sbomTestScan is one scan with lodash and one advisory on it.
func sbomTestScan(status entity.ScanStatus) (*entity.ScanResult, recDeps, recVulns) {
	s := entity.NewScanResult(uuid.New())
	s.Status = status
	dep := entity.NewDependency(s.RepositoryID, s.ID, "lodash", "4.17.15", "package-lock.json", entity.EcosystemNpm)
	dep.IsResolved = true
	vuln := entity.NewVulnerability(dep.ID, "GHSA-1", "Prototype pollution", entity.SeverityHigh)
	return s, recDeps{deps: []*entity.Dependency{dep}}, recVulns{vulns: []*entity.Vulnerability{vuln}}
}

// newSBOMHandler serves scan s (nil: unknown) of repository repos.
func newSBOMHandler(repos scanTestRepos, s *entity.ScanResult, deps recDeps, vulns recVulns) *ScanHandler {
	uc := scan.NewUseCase(repos, recScans{scan: s}, deps, vulns, nil, nil, nil,
		scan.Options{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	return NewScanHandler(uc)
}

func sbomRouter(h *ScanHandler) http.Handler {
	r := chi.NewRouter()
	h.RegisterRoutes(r)
	return r
}

// newSBOMRouter serves a scan of repository "acme/web" with a fixed clock
// and serial number.
func newSBOMRouter(status entity.ScanStatus) (http.Handler, *entity.ScanResult) {
	s, deps, vulns := sbomTestScan(status)
	h := newSBOMHandler(scanTestRepos{exists: true, name: "acme/web"}, s, deps, vulns)
	h.now = func() time.Time { return sbomTestNow }
	h.newUUID = func() uuid.UUID { return uuid.MustParse(sbomTestSerial) }
	return sbomRouter(h), s
}

func getSBOM(h http.Handler, id, query string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/scans/"+id+"/sbom"+query, nil))
	return rec
}

func TestGetScanSBOMCycloneDX(t *testing.T) {
	h, s := newSBOMRouter(entity.ScanStatusCompleted)
	for _, q := range []string{"", "?format=cyclonedx", "?format=CycloneDX"} {
		rec := getSBOM(h, s.ID.String(), q)
		if rec.Code != http.StatusOK {
			t.Fatalf("%q: status = %d, body %s", q, rec.Code, rec.Body)
		}
		if ct := rec.Header().Get("Content-Type"); ct != "application/vnd.cyclonedx+json; version=1.6" {
			t.Errorf("Content-Type = %q", ct)
		}
		want := `attachment; filename=acme-web-` + s.ID.String()[:8] + `.cdx.json`
		if cd := rec.Header().Get("Content-Disposition"); cd != want {
			t.Errorf("Content-Disposition = %q, want %q", cd, want)
		}
		var bom struct {
			SpecVersion  string `json:"specVersion"`
			SerialNumber string `json:"serialNumber"`
			Metadata     struct {
				Timestamp string                `json:"timestamp"`
				Component struct{ Name string } `json:"component"`
			} `json:"metadata"`
			Components      []struct{ PURL string } `json:"components"`
			Vulnerabilities []struct {
				ID       string
				Analysis *struct{}
			} `json:"vulnerabilities"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &bom); err != nil {
			t.Fatalf("body is not the BOM: %v", err)
		}
		if bom.SpecVersion != "1.6" || bom.SerialNumber != "urn:uuid:"+sbomTestSerial ||
			bom.Metadata.Component.Name != "acme/web" || bom.Metadata.Timestamp != "2026-10-15T12:00:00Z" {
			t.Errorf("bom = %+v", bom)
		}
		if len(bom.Components) != 1 || bom.Components[0].PURL != "pkg:npm/lodash@4.17.15" {
			t.Errorf("components = %+v", bom.Components)
		}
		if len(bom.Vulnerabilities) != 1 || bom.Vulnerabilities[0].ID != "GHSA-1" || bom.Vulnerabilities[0].Analysis != nil {
			t.Errorf("vulnerabilities = %+v", bom.Vulnerabilities)
		}
	}
}

func TestGetScanSBOMSPDX(t *testing.T) {
	h, s := newSBOMRouter(entity.ScanStatusCompleted)
	rec := getSBOM(h, s.ID.String(), "?format=spdx")
	if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != "application/spdx+json" {
		t.Fatalf("status %d, Content-Type %q", rec.Code, rec.Header().Get("Content-Type"))
	}
	want := `attachment; filename=acme-web-` + s.ID.String()[:8] + `.spdx.json`
	if cd := rec.Header().Get("Content-Disposition"); cd != want {
		t.Errorf("Content-Disposition = %q, want %q", cd, want)
	}
	body := rec.Body.String()
	if !strings.Contains(body, `"spdxVersion": "SPDX-2.3"`) || !strings.Contains(body, sbomTestSerial) ||
		!strings.Contains(body, `"created": "2026-10-15T12:00:00Z"`) || strings.Contains(body, "GHSA-1") {
		t.Errorf("body:\n%s", body)
	}
}

// Every download is a new document, so each gets its own serial number.
func TestGetScanSBOMNewSerialPerRequest(t *testing.T) {
	s, deps, vulns := sbomTestScan(entity.ScanStatusCompleted)
	h := sbomRouter(newSBOMHandler(scanTestRepos{exists: true}, s, deps, vulns))
	seen := map[string]bool{}
	for range 2 {
		rec := getSBOM(h, s.ID.String(), "")
		var bom struct {
			SerialNumber string `json:"serialNumber"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &bom); err != nil {
			t.Fatalf("status %d: %v", rec.Code, err)
		}
		if bom.SerialNumber == "urn:uuid:"+uuid.Nil.String() || seen[bom.SerialNumber] {
			t.Fatalf("serial %q repeats or is zero", bom.SerialNumber)
		}
		seen[bom.SerialNumber] = true
	}
}

// The repository name is user data: the file name keeps only
// [A-Za-z0-9._-], without leading dots or dashes, while the document
// carries the name as it is.
func TestGetScanSBOMFileName(t *testing.T) {
	token := regexp.MustCompile(`^[A-Za-z0-9._-]+$`)
	for _, tc := range []struct {
		repos      scanTestRepos
		file, root string
	}{
		{scanTestRepos{exists: true, name: "evil\"; filename=x.sh\r\nX-Y: z/ü"}, "evil-filename-x.sh-X-Y-z-", "evil\"; filename=x.sh\r\nX-Y: z/ü"},
		{scanTestRepos{exists: true, name: "../.env"}, "env", "../.env"},
		{scanTestRepos{exists: true, name: "///"}, "unnamed", "///"},
		{scanTestRepos{exists: false}, "unnamed", "unnamed"},
	} {
		s, deps, vulns := sbomTestScan(entity.ScanStatusCompleted)
		rec := getSBOM(sbomRouter(newSBOMHandler(tc.repos, s, deps, vulns)), s.ID.String(), "")
		if rec.Code != http.StatusOK {
			t.Fatalf("%q: status = %d, body %s", tc.repos.name, rec.Code, rec.Body)
		}
		cd := rec.Header().Get("Content-Disposition")
		disp, params, err := mime.ParseMediaType(cd)
		want := tc.file + "-" + s.ID.String()[:8] + ".cdx.json"
		if err != nil || disp != "attachment" || params["filename"] != want || !token.MatchString(params["filename"]) {
			t.Errorf("%q: Content-Disposition = %q (%v), want file name %q", tc.repos.name, cd, err, want)
		}
		var bom struct {
			Metadata struct {
				Component struct{ Name string } `json:"component"`
			} `json:"metadata"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &bom); err != nil || bom.Metadata.Component.Name != tc.root {
			t.Errorf("%q: root component = %q (%v), want %q", tc.repos.name, bom.Metadata.Component.Name, err, tc.root)
		}
	}
}

// The same answers as GET /scans/{id}/recommendations.
func TestGetScanSBOMErrors(t *testing.T) {
	h, s := newSBOMRouter(entity.ScanStatusCompleted)
	if rec := getSBOM(h, "nope", ""); rec.Code != http.StatusBadRequest {
		t.Errorf("bad id: status = %d, want 400", rec.Code)
	}
	for _, q := range []string{"?format=xml", "?format=sarif", "?format=cyclonedx+json"} {
		if rec := getSBOM(h, s.ID.String(), q); rec.Code != http.StatusBadRequest ||
			!strings.Contains(rec.Body.String(), "invalid format") {
			t.Errorf("%s: status = %d body = %s, want 400", q, rec.Code, rec.Body)
		}
	}
	failed, fs := newSBOMRouter(entity.ScanStatusFailed)
	if rec := getSBOM(failed, fs.ID.String(), ""); rec.Code != http.StatusConflict ||
		!strings.Contains(rec.Body.String(), "scan is not completed") {
		t.Errorf("failed scan: status = %d body = %s, want 409", rec.Code, rec.Body)
	}
	unknown := sbomRouter(newSBOMHandler(scanTestRepos{exists: true}, nil, recDeps{}, recVulns{}))
	if rec := getSBOM(unknown, uuid.NewString(), ""); rec.Code != http.StatusNotFound ||
		!strings.Contains(rec.Body.String(), "scan result not found") {
		t.Errorf("unknown scan: status = %d body = %s, want 404", rec.Code, rec.Body)
	}
}
