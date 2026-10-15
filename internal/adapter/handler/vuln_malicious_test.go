package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/orchesta/orbit/internal/domain/entity"
	"github.com/orchesta/orbit/internal/domain/repository"
)

// maliciousVulnRepo serves the same stored vulnerabilities from every read.
type maliciousVulnRepo struct {
	repository.VulnerabilityRepo
	vulns []*entity.Vulnerability
}

func (f *maliciousVulnRepo) GetByScanResultID(context.Context, uuid.UUID) ([]*entity.Vulnerability, error) {
	return f.vulns, nil
}

func (f *maliciousVulnRepo) GetByRepositoryID(context.Context, uuid.UUID) ([]*entity.Vulnerability, error) {
	return f.vulns, nil
}

func (f *maliciousVulnRepo) GetByID(_ context.Context, id uuid.UUID) (*entity.Vulnerability, error) {
	for _, v := range f.vulns {
		if v.ID == id {
			return v, nil
		}
	}
	return nil, nil
}

func (f *maliciousVulnRepo) ListLatest(context.Context, string, int, int) ([]*entity.VulnerabilityFinding, int, error) {
	var out []*entity.VulnerabilityFinding
	for _, v := range f.vulns {
		out = append(out, &entity.VulnerabilityFinding{ID: v.ID, OSVID: v.OSVID, Aliases: v.Aliases,
			Severity: v.Severity, PackageName: "debug", CurrentVersion: "4.4.2", Ecosystem: entity.EcosystemNpm})
	}
	return out, len(out), nil
}

func (f *maliciousVulnRepo) LatestSummary(context.Context) (entity.SeverityCounts, int, error) {
	return entity.SeverityCounts{}, 0, nil
}

// A row stored before Lookup rated MAL- advisories critical: still unknown,
// with the MAL- ID only among the aliases.
func maliciousFixture() []*entity.Vulnerability {
	mal := entity.NewVulnerability(uuid.New(), "CVE-2025-59144", "Malicious code in debug (npm)", entity.SeverityUnknown)
	mal.Aliases = []string{"MAL-2025-46974", "GHSA-4x49-vf9v-38px"}
	plain := entity.NewVulnerability(uuid.New(), "GHSA-35jh-r3h4-6jhm", "Command injection in lodash", entity.SeverityHigh)
	return []*entity.Vulnerability{mal, plain}
}

func getVulnJSON(t *testing.T, h http.Handler, path string, v any) {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET %s = %d: %s", path, rec.Code, rec.Body)
	}
	if err := json.Unmarshal(rec.Body.Bytes(), v); err != nil {
		t.Fatal(err)
	}
}

func TestVulnerabilityResponsesCarryMalicious(t *testing.T) {
	vulns := maliciousFixture()
	r := chi.NewRouter()
	NewVulnHandler(&maliciousVulnRepo{vulns: vulns}, nil).RegisterRoutes(r)
	id := uuid.New().String()

	for _, path := range []string{"/scans/" + id + "/vulnerabilities", "/repositories/" + id + "/vulnerabilities"} {
		var body struct {
			Data []map[string]any `json:"data"`
		}
		getVulnJSON(t, r, path, &body)
		if len(body.Data) != 2 || body.Data[0]["malicious"] != true || body.Data[1]["malicious"] != false {
			t.Fatalf("GET %s = %v, want malicious true then false", path, body.Data)
		}
		if body.Data[0]["osv_id"] != "CVE-2025-59144" || body.Data[0]["dependency_id"] == nil {
			t.Fatalf("GET %s: stored fields are not flat: %v", path, body.Data[0])
		}
	}

	var one struct {
		Data map[string]any `json:"data"`
	}
	getVulnJSON(t, r, "/vulnerabilities/"+vulns[0].ID.String(), &one)
	if one.Data["malicious"] != true || one.Data["summary"] != "Malicious code in debug (npm)" {
		t.Fatalf("GET /vulnerabilities/{id} = %v", one.Data)
	}

	var page struct {
		Data struct {
			Data []map[string]any `json:"data"`
		} `json:"data"`
	}
	getVulnJSON(t, r, "/vulnerabilities", &page)
	if len(page.Data.Data) != 2 || page.Data.Data[0]["malicious"] != true || page.Data.Data[1]["malicious"] != false ||
		page.Data.Data[0]["package_name"] != "debug" {
		t.Fatalf("GET /vulnerabilities = %v", page.Data.Data)
	}
}
