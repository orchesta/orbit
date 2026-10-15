//go:build integration

package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/orchesta/orbit/internal/adapter/persistence/postgres"
	"github.com/orchesta/orbit/internal/domain/entity"
)

func TestDashboardStatsCountsMaliciousFindings(t *testing.T) {
	ctx := context.Background()
	pool := newListTestPool(t)
	repoID := uuid.New()
	if _, err := pool.Exec(ctx, "INSERT INTO repositories (id, name, url, provider) VALUES ($1, 'web', 'https://example.com/o/web', 'github')", repoID); err != nil {
		t.Fatal(err)
	}
	scan := entity.NewScanResult(repoID)
	scan.Complete(2, 0, 2, 2)
	if err := postgres.NewScanResultPostgresRepo(pool).Create(ctx, scan); err != nil {
		t.Fatal(err)
	}
	chalk := entity.NewDependency(repoID, scan.ID, "chalk", "5.6.1", "package-lock.json", entity.EcosystemNpm)
	lodash := entity.NewDependency(repoID, scan.ID, "lodash", "4.17.15", "package-lock.json", entity.EcosystemNpm)
	if err := postgres.NewDependencyPostgresRepo(pool).CreateBatch(ctx, []*entity.Dependency{chalk, lodash}); err != nil {
		t.Fatal(err)
	}
	if err := postgres.NewVulnerabilityPostgresRepo(pool).CreateBatch(ctx, []*entity.Vulnerability{
		entity.NewVulnerability(chalk.ID, "MAL-2025-46969", "Malicious code in chalk (npm)", entity.SeverityCritical),
		entity.NewVulnerability(lodash.ID, "CVE-2021-23337", "Command injection", entity.SeverityHigh),
	}); err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	NewDashboardHandler(pool).GetStats(rec, httptest.NewRequest(http.MethodGet, "/dashboard/stats", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body)
	}
	var body struct {
		Data map[string]any `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Data["malicious_vulns"] != float64(1) || body.Data["total_vulns"] != float64(2) {
		t.Fatalf("stats = %v, want malicious_vulns 1 and total_vulns 2", body.Data)
	}
}
