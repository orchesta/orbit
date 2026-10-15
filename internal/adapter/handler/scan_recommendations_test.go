package handler

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/orchesta/orbit/internal/domain/entity"
	"github.com/orchesta/orbit/internal/domain/repository"
	"github.com/orchesta/orbit/internal/report"
	"github.com/orchesta/orbit/internal/usecase/scan"
)

type recScans struct {
	repository.ScanResultRepo
	scan *entity.ScanResult
}

func (f recScans) GetByID(context.Context, uuid.UUID) (*entity.ScanResult, error) {
	return f.scan, nil
}

type recDeps struct {
	repository.DependencyRepo
	deps []*entity.Dependency
}

func (f recDeps) GetByScanResultID(context.Context, uuid.UUID) ([]*entity.Dependency, error) {
	return f.deps, nil
}

type recVulns struct {
	repository.VulnerabilityRepo
	vulns []*entity.Vulnerability
}

func (f recVulns) GetByScanResultID(context.Context, uuid.UUID) ([]*entity.Vulnerability, error) {
	return f.vulns, nil
}

// newRecRouter serves scan s (nil: unknown) with deps and vulns.
func newRecRouter(s *entity.ScanResult, deps []*entity.Dependency, vulns []*entity.Vulnerability) http.Handler {
	uc := scan.NewUseCase(nil, recScans{scan: s}, recDeps{deps: deps}, recVulns{vulns: vulns}, nil, nil, nil,
		scan.Options{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	r := chi.NewRouter()
	NewScanHandler(uc).RegisterRoutes(r)
	return r
}

func getRecs(h http.Handler, id string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/scans/"+id+"/recommendations", nil))
	return rec
}

func TestGetRecommendations(t *testing.T) {
	s := entity.NewScanResult(uuid.New())
	s.Complete(1, 0, 1, 3)
	lodash := &entity.Dependency{ID: uuid.New(), ScanResultID: s.ID, Name: "lodash", CurrentVersion: "4.17.15",
		Ecosystem: entity.EcosystemNpm, ManifestFile: "package-lock.json", IsDirect: true, IsResolved: true}
	fix := func(v string) *string { return &v }
	vulns := []*entity.Vulnerability{
		// The server stores two rows for one CVE (two GitHub advisories).
		{ID: uuid.New(), DependencyID: lodash.ID, OSVID: "CVE-2021-23337", Aliases: []string{"GHSA-35jh-r3h4-6jhm"}, Severity: entity.SeverityHigh, FixedVersion: fix("4.17.21")},
		{ID: uuid.New(), DependencyID: lodash.ID, OSVID: "CVE-2021-23337", Aliases: []string{"GHSA-r5fr-rjxr-66jc"}, Severity: entity.SeverityHigh, FixedVersion: fix("4.18.0")},
		{ID: uuid.New(), DependencyID: lodash.ID, OSVID: "CVE-2020-8203", Severity: entity.SeverityHigh, FixedVersion: fix("4.17.19")},
	}

	rec := getRecs(newRecRouter(s, []*entity.Dependency{lodash}, vulns), s.ID.String())
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body)
	}
	var body struct {
		Data []report.Recommendation `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Data) != 1 {
		t.Fatalf("data = %+v, want one recommendation", body.Data)
	}
	got := body.Data[0]
	if got.Package != "lodash" || got.Upgrade != "4.18.0" || got.Via != "" ||
		!slices.Equal(got.Fixes, []string{"CVE-2020-8203", "CVE-2021-23337"}) {
		t.Fatalf("recommendation = %+v", got)
	}

	rec = getRecs(newRecRouter(s, []*entity.Dependency{lodash}, nil), s.ID.String())
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"data":[]`) {
		t.Fatalf("no findings: status = %d body = %s, want an empty list", rec.Code, rec.Body)
	}
}

// The same answers as GET /scans/{id}/sbom (plan 06): 400, 404, and 409 for
// a scan whose stored data may be incomplete.
func TestGetRecommendationsErrors(t *testing.T) {
	done := entity.NewScanResult(uuid.New())
	done.Complete(0, 0, 0, 0)
	if rec := getRecs(newRecRouter(done, nil, nil), "not-a-uuid"); rec.Code != http.StatusBadRequest {
		t.Errorf("invalid id: status = %d, want 400", rec.Code)
	}
	for _, st := range []entity.ScanStatus{entity.ScanStatusPending, entity.ScanStatusRunning, entity.ScanStatusFailed} {
		s := entity.NewScanResult(uuid.New())
		s.Status = st
		rec := getRecs(newRecRouter(s, nil, nil), s.ID.String())
		if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "scan is not completed") {
			t.Errorf("%s scan: status = %d body = %s, want 409", st, rec.Code, rec.Body)
		}
	}
	rec := getRecs(newRecRouter(nil, nil, nil), uuid.NewString())
	if rec.Code != http.StatusNotFound || !strings.Contains(rec.Body.String(), "scan result not found") {
		t.Errorf("unknown scan: status = %d body = %s, want 404", rec.Code, rec.Body)
	}
}
