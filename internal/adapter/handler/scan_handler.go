package handler

import (
	"bytes"
	"errors"
	"io"
	"mime"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/orchesta/orbit/internal/report"
	"github.com/orchesta/orbit/internal/usecase/scan"
)

// ScanHandler handles HTTP requests for scanning operations.
type ScanHandler struct {
	useCase *scan.UseCase
	now     func() time.Time // SBOM timestamps
	newUUID func() uuid.UUID // SBOM serial numbers
}

// NewScanHandler creates a new ScanHandler.
func NewScanHandler(useCase *scan.UseCase) *ScanHandler {
	return &ScanHandler{useCase: useCase, now: time.Now, newUUID: uuid.New}
}

// RegisterRoutes registers scan routes on the given router.
func (h *ScanHandler) RegisterRoutes(r chi.Router) {
	r.Post("/repositories/{id}/scan", h.TriggerScan)
	r.Get("/repositories/{id}/scans", h.GetScanHistory)
	r.Get("/scans/{id}", h.GetScanResult)
	r.Get("/scans/{id}/dependencies", h.GetScanDependencies)
	r.Get("/scans/{id}/recommendations", h.GetRecommendations)
	r.Get("/scans/{id}/sbom", h.GetScanSBOM)
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

// GetRecommendations handles GET /api/v1/scans/{id}/recommendations: the
// smallest upgrade per vulnerable package of a completed scan (see
// report.Recommend). Via is always "": the server does not store the
// dependency graph.
func (h *ScanHandler) GetRecommendations(w http.ResponseWriter, r *http.Request) {
	scanID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		RespondError(w, http.StatusBadRequest, "invalid scan id")
		return
	}
	_, res, err := h.useCase.CompletedScanResult(r.Context(), scanID)
	if err != nil {
		respondScanLoadError(w, r, err)
		return
	}
	RespondJSON(w, http.StatusOK, report.RecommendFor(res.Dependencies, res.Vulnerabilities))
}

// respondScanLoadError answers a failed CompletedScanResult: 404 for an
// unknown scan, 409 for a scan that is pending, running or failed, and a
// server error otherwise. Every endpoint built from a stored scan's
// findings answers this way.
func respondScanLoadError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, scan.ErrScanNotFound):
		RespondError(w, http.StatusNotFound, "scan result not found")
	case errors.Is(err, scan.ErrScanNotCompleted):
		RespondError(w, http.StatusConflict, "scan is not completed")
	default:
		RespondServerError(w, r, err)
	}
}

// sbomFormat is one downloadable SBOM format.
type sbomFormat struct {
	contentType, extension string
	write                  func(io.Writer, []report.Finding, report.Summary, report.ToolInfo, report.SBOMOptions) error
}

var sbomFormats = map[string]sbomFormat{
	"cyclonedx": {"application/vnd.cyclonedx+json; version=1.6", ".cdx.json", report.WriteCycloneDX},
	"spdx":      {"application/spdx+json", ".spdx.json", report.WriteSPDX},
}

// unsafeFileChars matches what a download file name should not contain.
var unsafeFileChars = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

// GetScanSBOM handles GET /api/v1/scans/{id}/sbom?format=cyclonedx|spdx
// (default cyclonedx). It renders the stored dependencies and
// vulnerabilities of a completed scan; the server has no .orbitignore, so
// no finding is marked ignored. Each download is a new document: it is
// stamped with the request time and a new serial number.
func (h *ScanHandler) GetScanSBOM(w http.ResponseWriter, r *http.Request) {
	scanID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		RespondError(w, http.StatusBadRequest, "invalid scan id")
		return
	}
	name := strings.ToLower(r.URL.Query().Get("format")) // as the CLI's --format
	if name == "" {
		name = "cyclonedx"
	}
	format, ok := sbomFormats[name]
	if !ok {
		RespondError(w, http.StatusBadRequest, "invalid format: want cyclonedx or spdx")
		return
	}

	src, err := h.useCase.SBOMSource(r.Context(), scanID)
	if err != nil {
		respondScanLoadError(w, r, err)
		return
	}

	project := "unnamed"
	if src.Repository != nil && src.Repository.Name != "" {
		project = src.Repository.Name
	}
	now := h.now()
	findings, summary := report.Build(src.Result, nil, "", now)
	var buf bytes.Buffer
	opts := report.SBOMOptions{Name: project, Now: now, Serial: h.newUUID()}
	if err := format.write(&buf, findings, summary, report.OrbitTool(), opts); err != nil {
		RespondServerError(w, r, err)
		return
	}

	file := sbomFileStem(project) + "-" + scanID.String()[:8] + format.extension
	w.Header().Set("Content-Type", format.contentType)
	w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": file}))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(buf.Bytes())
}

// sbomFileStem turns a repository name, which is user data, into a file
// name stem of [A-Za-z0-9._-] that does not start with a dot or a dash.
func sbomFileStem(project string) string {
	stem := strings.TrimLeft(unsafeFileChars.ReplaceAllString(project, "-"), ".-")
	if stem == "" {
		return "unnamed"
	}
	return stem
}
