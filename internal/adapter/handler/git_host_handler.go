package handler

import (
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/aligoren/orbit/internal/domain/entity"
	domainrepo "github.com/aligoren/orbit/internal/domain/repository"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

// GitHostHandler handles HTTP requests for Git host connections.
type GitHostHandler struct {
	hosts domainrepo.GitHostRepo
}

// NewGitHostHandler creates a new GitHostHandler.
func NewGitHostHandler(hosts domainrepo.GitHostRepo) *GitHostHandler {
	return &GitHostHandler{hosts: hosts}
}

// RegisterRoutes registers connection routes on the given router.
func (h *GitHostHandler) RegisterRoutes(r chi.Router) {
	r.Route("/git-hosts", func(r chi.Router) {
		r.Get("/", h.List)
		r.Post("/", h.Create)
		r.Delete("/{id}", h.Delete)
	})
}

type createGitHostRequest struct {
	Kind    string `json:"kind"`
	Name    string `json:"name"`
	BaseURL string `json:"base_url"`
}

// List handles GET /api/v1/git-hosts
func (h *GitHostHandler) List(w http.ResponseWriter, r *http.Request) {
	hosts, err := h.hosts.List(r.Context())
	if err != nil {
		RespondServerError(w, r, err)
		return
	}
	if hosts == nil {
		hosts = []*entity.GitHost{}
	}
	RespondJSON(w, http.StatusOK, hosts)
}

// Create handles POST /api/v1/git-hosts
func (h *GitHostHandler) Create(w http.ResponseWriter, r *http.Request) {
	var req createGitHostRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	// url.Parse errors quote the whole input, credentials included, so they
	// are replaced with a fixed message.
	if _, err := url.Parse(strings.TrimSpace(req.BaseURL)); err != nil {
		RespondError(w, http.StatusBadRequest, "base_url is not a valid URL")
		return
	}
	host, err := entity.NewGitHost(entity.GitProvider(req.Kind), req.Name, req.BaseURL)
	if err != nil {
		RespondError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := h.hosts.Create(r.Context(), host); err != nil {
		if errors.Is(err, domainrepo.ErrDuplicate) {
			RespondError(w, http.StatusConflict, "a connection with this base URL already exists")
			return
		}
		RespondServerError(w, r, err)
		return
	}
	RespondJSON(w, http.StatusCreated, host)
}

// Delete handles DELETE /api/v1/git-hosts/{id}. The connection's access
// tokens go with it; a connection that repositories still use is kept.
func (h *GitHostHandler) Delete(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		RespondError(w, http.StatusBadRequest, "invalid connection id")
		return
	}
	host, err := h.hosts.GetByID(r.Context(), id)
	if err != nil {
		RespondServerError(w, r, err)
		return
	}
	if host == nil {
		RespondError(w, http.StatusNotFound, "connection not found")
		return
	}
	if err := h.hosts.Delete(r.Context(), id); err != nil {
		if errors.Is(err, domainrepo.ErrInUse) {
			RespondError(w, http.StatusConflict, "connection has repositories")
			return
		}
		RespondServerError(w, r, err)
		return
	}
	RespondJSON(w, http.StatusNoContent, nil)
}
