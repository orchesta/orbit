package handler

import (
	"net/http"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/orchesta/orbit/internal/adapter/persistence/postgres"
)

// DashboardHandler handles HTTP requests for the dashboard.
type DashboardHandler struct {
	pool *pgxpool.Pool
}

// NewDashboardHandler creates a new DashboardHandler.
func NewDashboardHandler(pool *pgxpool.Pool) *DashboardHandler {
	return &DashboardHandler{pool: pool}
}

// HealthCheck handles GET /api/v1/health
func (h *DashboardHandler) HealthCheck(w http.ResponseWriter, r *http.Request) {
	RespondJSON(w, http.StatusOK, map[string]string{
		"status":  "ok",
		"service": "orbit",
	})
}

// DashboardStats holds aggregate stats for the dashboard.
type DashboardStats struct {
	TotalRepos     int `json:"total_repos"`
	ActiveRepos    int `json:"active_repos"`
	VulnerableDeps int `json:"vulnerable_deps"`
	TotalVulns     int `json:"total_vulns"`
	// UnverifiedRepos counts repositories with no successful vulnerability
	// check (same definition as the Vulnerabilities page).
	UnverifiedRepos int `json:"unverified_repos"`
}

// GetStats handles GET /api/v1/dashboard/stats
func (h *DashboardHandler) GetStats(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	stats := DashboardStats{}

	if err := h.pool.QueryRow(ctx, `SELECT COUNT(*), COUNT(*) FILTER (WHERE is_active) FROM repositories`).
		Scan(&stats.TotalRepos, &stats.ActiveRepos); err != nil {
		RespondServerError(w, r, err)
		return
	}
	vulnerable, total, err := postgres.LatestScanTotals(ctx, h.pool)
	if err != nil {
		RespondServerError(w, r, err)
		return
	}
	stats.VulnerableDeps, stats.TotalVulns = vulnerable, total
	if stats.UnverifiedRepos, err = postgres.UnverifiedRepoCount(ctx, h.pool); err != nil {
		RespondServerError(w, r, err)
		return
	}

	RespondJSON(w, http.StatusOK, stats)
}
