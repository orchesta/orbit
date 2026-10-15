package handler

import (
	"net/http"
	"strconv"

	"github.com/aligoren/orbit/internal/domain/entity"
	"github.com/aligoren/orbit/internal/domain/repository"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

// VulnHandler handles HTTP requests for vulnerability operations.
type VulnHandler struct {
	vulnRepo repository.VulnerabilityRepo
	depRepo  repository.DependencyRepo
}

// NewVulnHandler creates a new VulnHandler.
func NewVulnHandler(vulnRepo repository.VulnerabilityRepo, depRepo repository.DependencyRepo) *VulnHandler {
	return &VulnHandler{
		vulnRepo: vulnRepo,
		depRepo:  depRepo,
	}
}

// RegisterRoutes registers vulnerability routes on the given router.
func (h *VulnHandler) RegisterRoutes(r chi.Router) {
	r.Get("/scans/{id}/vulnerabilities", h.GetByScenResult)
	r.Get("/repositories/{id}/vulnerabilities", h.GetByRepository)
	r.Get("/vulnerabilities", h.List)
	r.Get("/vulnerabilities/{id}", h.GetByID)
}

// GetByScenResult handles GET /api/v1/scans/{id}/vulnerabilities
func (h *VulnHandler) GetByScenResult(w http.ResponseWriter, r *http.Request) {
	scanID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		RespondError(w, http.StatusBadRequest, "invalid scan id")
		return
	}

	vulns, err := h.vulnRepo.GetByScanResultID(r.Context(), scanID)
	if err != nil {
		RespondServerError(w, r, err)
		return
	}

	RespondJSON(w, http.StatusOK, vulns)
}

// GetByRepository handles GET /api/v1/repositories/{id}/vulnerabilities
func (h *VulnHandler) GetByRepository(w http.ResponseWriter, r *http.Request) {
	repoID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		RespondError(w, http.StatusBadRequest, "invalid repository id")
		return
	}

	vulns, err := h.vulnRepo.GetByRepositoryID(r.Context(), repoID)
	if err != nil {
		RespondServerError(w, r, err)
		return
	}

	RespondJSON(w, http.StatusOK, vulns)
}

// GetByID handles GET /api/v1/vulnerabilities/{id}
func (h *VulnHandler) GetByID(w http.ResponseWriter, r *http.Request) {
	vulnID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		RespondError(w, http.StatusBadRequest, "invalid vulnerability id")
		return
	}

	vuln, err := h.vulnRepo.GetByID(r.Context(), vulnID)
	if err != nil {
		RespondServerError(w, r, err)
		return
	}
	if vuln == nil {
		RespondError(w, http.StatusNotFound, "vulnerability not found")
		return
	}

	RespondJSON(w, http.StatusOK, vuln)
}

// vulnerabilityPage is the paginated response of GET /vulnerabilities.
type vulnerabilityPage struct {
	Data                   []*entity.VulnerabilityFinding `json:"data"`
	Total                  int                            `json:"total"`
	Page                   int                            `json:"page"`
	PerPage                int                            `json:"per_page"`
	TotalPages             int                            `json:"total_pages"`
	Counts                 entity.SeverityCounts          `json:"counts"`
	UnverifiedRepositories int                            `json:"unverified_repositories"`
}

// maxVulnerabilityPage is the highest page GET /vulnerabilities accepts.
const maxVulnerabilityPage = 1_000_000

var validSeverities = map[string]bool{"": true, "critical": true, "high": true, "medium": true, "low": true, "unknown": true}

// List handles GET /api/v1/vulnerabilities across every repository's latest completed scan.
func (h *VulnHandler) List(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	severity := q.Get("severity")
	if !validSeverities[severity] {
		RespondError(w, http.StatusBadRequest, "severity must be one of critical, high, medium, low, unknown")
		return
	}
	page, _ := strconv.Atoi(q.Get("page"))
	if page < 1 {
		page = 1
	}
	// Bounds (page-1)*perPage so the offset cannot overflow.
	if page > maxVulnerabilityPage {
		RespondError(w, http.StatusBadRequest, "page out of range")
		return
	}
	perPage, _ := strconv.Atoi(q.Get("per_page"))
	if perPage < 1 || perPage > 100 {
		perPage = 25
	}

	findings, total, err := h.vulnRepo.ListLatest(r.Context(), severity, perPage, (page-1)*perPage)
	if err != nil {
		RespondServerError(w, r, err)
		return
	}
	counts, unverified, err := h.vulnRepo.LatestSummary(r.Context())
	if err != nil {
		RespondServerError(w, r, err)
		return
	}
	if findings == nil {
		findings = []*entity.VulnerabilityFinding{}
	}
	totalPages := (total + perPage - 1) / perPage
	if totalPages < 1 {
		totalPages = 1
	}
	RespondJSON(w, http.StatusOK, vulnerabilityPage{
		Data: findings, Total: total, Page: page, PerPage: perPage, TotalPages: totalPages,
		Counts: counts, UnverifiedRepositories: unverified,
	})
}
