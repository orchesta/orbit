package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/orchesta/orbit/internal/domain/entity"
	"github.com/orchesta/orbit/internal/domain/repository"
)

type listVulnRepo struct {
	repository.VulnerabilityRepo
	gotSeverity         string
	gotLimit, gotOffset int
}

func (f *listVulnRepo) ListLatest(_ context.Context, severity string, limit, offset int) ([]*entity.VulnerabilityFinding, int, error) {
	f.gotSeverity, f.gotLimit, f.gotOffset = severity, limit, offset
	return nil, 51, nil
}

func (f *listVulnRepo) LatestSummary(context.Context) (entity.SeverityCounts, int, error) {
	return entity.SeverityCounts{Unknown: 4}, 2, nil
}

func TestListVulnerabilities(t *testing.T) {
	repo := &listVulnRepo{}
	r := chi.NewRouter()
	NewVulnHandler(repo, nil).RegisterRoutes(r)

	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/vulnerabilities?severity=unknown&page=3&per_page=25", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body)
	}
	var body struct {
		Data vulnerabilityPage `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if repo.gotSeverity != "unknown" || repo.gotLimit != 25 || repo.gotOffset != 50 {
		t.Fatalf("repo called with %q %d %d", repo.gotSeverity, repo.gotLimit, repo.gotOffset)
	}
	if body.Data.TotalPages != 3 || body.Data.Counts.Unknown != 4 || body.Data.UnverifiedRepositories != 2 || body.Data.Data == nil {
		t.Fatalf("page = %+v", body.Data)
	}

	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/vulnerabilities?severity=urgent", nil))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid severity status = %d, want 400", rec.Code)
	}

	// A huge page would overflow (page-1)*perPage into a negative offset.
	repo.gotLimit, repo.gotOffset = 0, 0
	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/vulnerabilities?page=9223372036854775807&per_page=100", nil))
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "page out of range") {
		t.Fatalf("huge page status = %d: %s, want 400 page out of range", rec.Code, rec.Body)
	}
	if repo.gotLimit != 0 {
		t.Fatalf("repo called for an out-of-range page with offset %d", repo.gotOffset)
	}
}
