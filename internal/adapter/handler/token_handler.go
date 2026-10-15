package handler

import (
	"context"
	"fmt"
	"net/http"
	"unicode/utf8"

	"github.com/aligoren/orbit/internal/adapter/persistence/postgres"
	"github.com/aligoren/orbit/internal/domain/entity"
	domainrepo "github.com/aligoren/orbit/internal/domain/repository"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

// tokenStore is the access token persistence TokenHandler uses;
// *postgres.AccessTokenPostgresRepo implements it.
type tokenStore interface {
	GetAll(ctx context.Context) ([]postgres.AccessTokenResponse, error)
	Create(ctx context.Context, label, provider string, gitHostID *uuid.UUID, token string) (*postgres.AccessToken, error)
	Delete(ctx context.Context, id uuid.UUID) error
}

// TokenHandler handles HTTP requests for access token management.
type TokenHandler struct {
	tokenRepo tokenStore
	gitHosts  domainrepo.GitHostRepo
}

// NewTokenHandler creates a new TokenHandler.
func NewTokenHandler(tokenRepo tokenStore, gitHosts domainrepo.GitHostRepo) *TokenHandler {
	return &TokenHandler{tokenRepo: tokenRepo, gitHosts: gitHosts}
}

// RegisterRoutes registers token routes on the given router.
func (h *TokenHandler) RegisterRoutes(r chi.Router) {
	r.Route("/tokens", func(r chi.Router) {
		r.Get("/", h.GetAll)
		r.Post("/", h.Create)
		r.Delete("/{id}", h.Delete)
	})
}

// maxTokenLabel is the access_tokens.label column width, in characters.
const maxTokenLabel = 100

type createTokenRequest struct {
	Label    string `json:"label"`
	Provider string `json:"provider"`
	Token    string `json:"token"`
	// GitHostID names the connection an Azure DevOps token belongs to.
	GitHostID string `json:"git_host_id,omitempty"`
}

// GetAll handles GET /api/v1/tokens
func (h *TokenHandler) GetAll(w http.ResponseWriter, r *http.Request) {
	tokens, err := h.tokenRepo.GetAll(r.Context())
	if err != nil {
		RespondServerError(w, r, err)
		return
	}
	if tokens == nil {
		tokens = []postgres.AccessTokenResponse{}
	}
	RespondJSON(w, http.StatusOK, tokens)
}

// Create handles POST /api/v1/tokens
func (h *TokenHandler) Create(w http.ResponseWriter, r *http.Request) {
	var req createTokenRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.Label == "" || req.Token == "" {
		RespondError(w, http.StatusBadRequest, "label and token are required")
		return
	}
	if len(req.Token) < 8 || len(req.Token) > 512 {
		RespondError(w, http.StatusBadRequest, "token must be between 8 and 512 characters")
		return
	}
	if utf8.RuneCountInString(req.Label) > maxTokenLabel {
		RespondError(w, http.StatusBadRequest, fmt.Sprintf("label must be at most %d characters", maxTokenLabel))
		return
	}
	if req.Provider == "" {
		req.Provider = string(entity.GitProviderGitHub)
	}
	provider := entity.GitProvider(req.Provider)
	if !entity.KnownProvider(provider) {
		RespondError(w, http.StatusBadRequest, "provider must be github, gitlab or azuredevops")
		return
	}
	gitHostID, ok := h.tokenGitHost(w, r, provider, req.GitHostID)
	if !ok {
		return
	}

	token, err := h.tokenRepo.Create(r.Context(), req.Label, req.Provider, gitHostID, req.Token)
	if err != nil {
		RespondServerError(w, r, err)
		return
	}
	// Return the created token with masked value
	RespondJSON(w, http.StatusCreated, postgres.AccessTokenResponse{
		ID:        token.ID,
		Label:     token.Label,
		Provider:  token.Provider,
		GitHostID: token.GitHostID,
		Masked:    postgres.MaskToken(req.Token),
		CreatedAt: token.CreatedAt,
	})
}

// tokenGitHost checks the connection a new token names: Azure DevOps tokens
// need an existing connection of that kind, other providers' tokens must not
// name one. It writes the error response and returns false when the request
// is not acceptable.
func (h *TokenHandler) tokenGitHost(w http.ResponseWriter, r *http.Request, provider entity.GitProvider, rawID string) (*uuid.UUID, bool) {
	if provider != entity.GitProviderAzureDevOps {
		if rawID != "" {
			RespondError(w, http.StatusBadRequest, "git_host_id is only allowed for azuredevops tokens")
			return nil, false
		}
		return nil, true
	}
	if rawID == "" {
		RespondError(w, http.StatusBadRequest, "git_host_id is required for azuredevops tokens")
		return nil, false
	}
	id, err := uuid.Parse(rawID)
	if err != nil {
		RespondError(w, http.StatusBadRequest, "invalid git_host_id")
		return nil, false
	}
	host, err := h.gitHosts.GetByID(r.Context(), id)
	if err != nil {
		RespondServerError(w, r, err)
		return nil, false
	}
	if host == nil || host.Kind != provider {
		RespondError(w, http.StatusBadRequest, "connection not found")
		return nil, false
	}
	return &id, true
}

// Delete handles DELETE /api/v1/tokens/{id}
func (h *TokenHandler) Delete(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		RespondError(w, http.StatusBadRequest, "invalid token id")
		return
	}
	if err := h.tokenRepo.Delete(r.Context(), id); err != nil {
		RespondServerError(w, r, err)
		return
	}
	RespondJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}
