package handler

import (
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/orchesta/orbit/internal/usecase/scan"
)

// ScanHandler handles HTTP requests for scanning operations.
type ScanHandler struct {
	useCase *scan.UseCase
}

// NewScanHandler creates a new ScanHandler.
func NewScanHandler(useCase *scan.UseCase) *ScanHandler {
	return &ScanHandler{useCase: useCase}
}

// RegisterRoutes registers scan routes on the given router.
func (h *ScanHandler) RegisterRoutes(r chi.Router) {
	r.Post("/repositories/{id}/scan", h.TriggerScan)
	r.Get("/repositories/{id}/scans", h.GetScanHistory)
	r.Get("/scans/{id}", h.GetScanResult)
	r.Get("/scans/{id}/dependencies", h.GetScanDependencies)
}

// TriggerScan handles POST /api/v1/repositories/{id}/scan
func (h *ScanHandler) TriggerScan(w http.ResponseWriter, r *http.Request) {
	repoID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		RespondError(w, http.StatusBadRequest, "invalid repository id")
		return
	}

	queued, created, err := h.useCase.RequestScan(r.Context(), repoID)
	if errors.Is(err, scan.ErrRepositoryNotFound) {
		RespondError(w, http.StatusNotFound, "repository not found")
		return
	}
	if err != nil {
		RespondServerError(w, r, err)
		return
	}

	RespondJSON(w, http.StatusAccepted, map[string]any{
		"scan_id": queued.ID,
		"status":  queued.Status,
		"queued":  created,
	})
}

// GetScanHistory handles GET /api/v1/repositories/{id}/scans
func (h *ScanHandler) GetScanHistory(w http.ResponseWriter, r *http.Request) {
	repoID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		RespondError(w, http.StatusBadRequest, "invalid repository id")
		return
	}

	scans, err := h.useCase.GetScanHistory(r.Context(), repoID, 20)
	if err != nil {
		RespondServerError(w, r, err)
		return
	}

	RespondJSON(w, http.StatusOK, scans)
}

// GetScanResult handles GET /api/v1/scans/{id}
func (h *ScanHandler) GetScanResult(w http.ResponseWriter, r *http.Request) {
	scanID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		RespondError(w, http.StatusBadRequest, "invalid scan id")
		return
	}

	result, err := h.useCase.GetScanResult(r.Context(), scanID)
	if err != nil {
		RespondServerError(w, r, err)
		return
	}
	if result == nil {
		RespondError(w, http.StatusNotFound, "scan result not found")
		return
	}

	RespondJSON(w, http.StatusOK, result)
}

// GetScanDependencies handles GET /api/v1/scans/{id}/dependencies
func (h *ScanHandler) GetScanDependencies(w http.ResponseWriter, r *http.Request) {
	scanID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		RespondError(w, http.StatusBadRequest, "invalid scan id")
		return
	}

	deps, err := h.useCase.GetScanDependencies(r.Context(), scanID)
	if err != nil {
		RespondServerError(w, r, err)
		return
	}

	RespondJSON(w, http.StatusOK, deps)
}
