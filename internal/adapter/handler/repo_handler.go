package handler

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/orchesta/orbit/internal/adapter/persistence/postgres"
	"github.com/orchesta/orbit/internal/domain/entity"
	domainrepo "github.com/orchesta/orbit/internal/domain/repository"
	gitprovider "github.com/orchesta/orbit/internal/infrastructure/git"
	"github.com/orchesta/orbit/internal/infrastructure/git/azuredevops"
	"github.com/orchesta/orbit/internal/usecase/repo"
	"github.com/orchesta/orbit/internal/usecase/schedule"
)

// maxBulkImport caps how many repositories one import request may create.
const maxBulkImport = 500

// skippedRepositoriesHeader carries how many repositories an Azure DevOps
// fetch left out because their URL is not under the connection's base URL.
const skippedRepositoriesHeader = "X-Orbit-Skipped-Repositories"

// azureLister lists the repositories a token can see on an Azure DevOps
// connection; *azuredevops.Client implements it.
type azureLister interface {
	// ListRepositories also returns how many repositories were left out
	// because their URL does not belong to the connection.
	ListRepositories(ctx context.Context, host *entity.GitHost, token string) ([]gitprovider.RepoInfo, int, error)
}

// repoTokenStore is the token access RepoHandler needs;
// *postgres.AccessTokenPostgresRepo implements it.
type repoTokenStore interface {
	GetByID(ctx context.Context, id uuid.UUID) (*postgres.AccessToken, error)
	Pool() *pgxpool.Pool
}

// RepoHandler handles HTTP requests for repository management.
type RepoHandler struct {
	useCase      *repo.UseCase
	githubClient gitprovider.Provider
	gitlabClient gitprovider.Provider
	azureClient  azureLister
	tokenRepo    repoTokenStore
	gitHosts     domainrepo.GitHostRepo
}

// NewRepoHandler creates a new RepoHandler.
func NewRepoHandler(useCase *repo.UseCase, githubClient, gitlabClient gitprovider.Provider, azureClient azureLister, tokenRepo repoTokenStore, gitHosts domainrepo.GitHostRepo) *RepoHandler {
	return &RepoHandler{
		useCase:      useCase,
		githubClient: githubClient,
		gitlabClient: gitlabClient,
		azureClient:  azureClient,
		tokenRepo:    tokenRepo,
		gitHosts:     gitHosts,
	}
}

// RegisterRoutes registers repository routes on the given router.
func (h *RepoHandler) RegisterRoutes(r chi.Router) {
	r.Route("/repositories", func(r chi.Router) {
		r.Get("/", h.GetAll)
		r.Post("/", h.Create)
		r.Post("/github/fetch", h.FetchGitHub)
		r.Post("/gitlab/fetch", h.FetchGitLab)
		r.Post("/azuredevops/fetch", h.FetchAzureDevOps)
		r.Post("/import", h.BulkImport)
		r.Route("/{id}", func(r chi.Router) {
			r.Get("/", h.GetByID)
			r.Put("/", h.Update)
			r.Delete("/", h.Delete)
		})
	})
}

// createRequest represents the JSON body for creating a repository.
type createRequest struct {
	Name          string `json:"name"`
	URL           string `json:"url"`
	Provider      string `json:"provider"`
	DefaultBranch string `json:"default_branch,omitempty"`
	Schedule      string `json:"schedule,omitempty"`
	AuthToken     string `json:"auth_token"`
	// GitHostID names the connection of an Azure DevOps repository.
	GitHostID string `json:"git_host_id,omitempty"`
}

// updateRequest represents the JSON body for updating a repository.
type updateRequest struct {
	Name          *string `json:"name,omitempty"`
	URL           *string `json:"url,omitempty"`
	Provider      *string `json:"provider,omitempty"`
	DefaultBranch *string `json:"default_branch,omitempty"`
	Schedule      *string `json:"schedule,omitempty"`
	AuthToken     *string `json:"auth_token,omitempty"`
	IsActive      *bool   `json:"is_active,omitempty"`
	GitHostID     *string `json:"git_host_id,omitempty"`
}

// repoWithScanStats is the enriched response for the repo list.
type repoWithScanStats struct {
	ID             string     `json:"id"`
	Name           string     `json:"name"`
	URL            string     `json:"url"`
	Provider       string     `json:"provider"`
	DefaultBranch  string     `json:"default_branch"`
	IsActive       bool       `json:"is_active"`
	LastScannedAt  *time.Time `json:"last_scanned_at,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
	GitHostID      *uuid.UUID `json:"git_host_id,omitempty"`
	VulnerableDeps int        `json:"vulnerable_deps"`
	OutdatedDeps   int        `json:"outdated_deps"`
	TotalDeps      int        `json:"total_deps"`
	// ScanStatus is the status of the newest scan, omitted when never scanned.
	ScanStatus *string `json:"scan_status,omitempty"`
}

// paginatedRepoResponse wraps the paginated result.
type paginatedRepoResponse struct {
	Data       []repoWithScanStats `json:"data"`
	Total      int                 `json:"total"`
	Page       int                 `json:"page"`
	PerPage    int                 `json:"per_page"`
	TotalPages int                 `json:"total_pages"`
}

// GetAll handles GET /api/v1/repositories with server-side pagination & filtering.
// Query params: page, per_page, provider, q (search), status (vulnerable|outdated|issues), sort (name|recent)
func (h *RepoHandler) GetAll(w http.ResponseWriter, r *http.Request) {
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}
	perPage, _ := strconv.Atoi(r.URL.Query().Get("per_page"))
	if perPage < 1 || perPage > 100 {
		perPage = 25
	}

	provider := r.URL.Query().Get("provider")
	search := r.URL.Query().Get("q")
	status := r.URL.Query().Get("status") // vulnerable, outdated, issues
	order, err := repoListOrder(r.URL.Query().Get("sort"))
	if err != nil {
		RespondError(w, http.StatusBadRequest, err.Error())
		return
	}

	offset := (page - 1) * perPage

	// Build dynamic WHERE clauses
	conditions := []string{"1=1"}
	args := []interface{}{}
	argIdx := 1

	if provider != "" && provider != "all" {
		conditions = append(conditions, fmt.Sprintf("r.provider = $%d", argIdx))
		args = append(args, provider)
		argIdx++
	}
	if search != "" {
		conditions = append(conditions, fmt.Sprintf("(r.name ILIKE $%d OR r.url ILIKE $%d)", argIdx, argIdx))
		args = append(args, "%"+search+"%")
		argIdx++
	}

	// Status filter operates on the latest scan stats
	switch status {
	case "vulnerable":
		conditions = append(conditions, "COALESCE(ls.vulnerable_deps, 0) > 0")
	case "outdated":
		conditions = append(conditions, "COALESCE(ls.outdated_deps, 0) > 0")
	case "issues":
		conditions = append(conditions, "(COALESCE(ls.vulnerable_deps, 0) > 0 OR COALESCE(ls.outdated_deps, 0) > 0)")
	}

	whereClause := strings.Join(conditions, " AND ")

	// Count total
	countQuery := fmt.Sprintf(`
		SELECT COUNT(*)
		FROM repositories r
		LEFT JOIN LATERAL (
			SELECT vulnerable_deps, outdated_deps, total_deps
			FROM scan_results
			WHERE repository_id = r.id AND status = 'completed'
			ORDER BY started_at DESC, id DESC LIMIT 1
		) ls ON true
		WHERE %s
	`, whereClause)

	var total int
	if err := h.tokenRepo.Pool().QueryRow(r.Context(), countQuery, args...).Scan(&total); err != nil {
		RespondServerError(w, r, err)
		return
	}

	// Fetch paginated data
	dataQuery := fmt.Sprintf(`
		SELECT r.id, r.name, r.url, r.provider, r.default_branch, r.is_active, r.last_scanned_at, r.created_at, r.updated_at, r.git_host_id,
		       COALESCE(ls.vulnerable_deps, 0), COALESCE(ls.outdated_deps, 0), COALESCE(ls.total_deps, 0),
		       ns.status
		FROM repositories r`+postgres.NewestScanStatusJoin+`
		LEFT JOIN LATERAL (
			SELECT vulnerable_deps, outdated_deps, total_deps
			FROM scan_results
			WHERE repository_id = r.id AND status = 'completed'
			ORDER BY started_at DESC, id DESC LIMIT 1
		) ls ON true
		WHERE %s
		ORDER BY %s
		LIMIT $%d OFFSET $%d
	`, whereClause, order, argIdx, argIdx+1)

	args = append(args, perPage, offset)

	rows, err := h.tokenRepo.Pool().Query(r.Context(), dataQuery, args...)
	if err != nil {
		RespondServerError(w, r, err)
		return
	}
	defer rows.Close()

	data := []repoWithScanStats{}
	for rows.Next() {
		var repo repoWithScanStats
		if err := rows.Scan(
			&repo.ID, &repo.Name, &repo.URL, &repo.Provider, &repo.DefaultBranch,
			&repo.IsActive, &repo.LastScannedAt, &repo.CreatedAt, &repo.UpdatedAt, &repo.GitHostID,
			&repo.VulnerableDeps, &repo.OutdatedDeps, &repo.TotalDeps, &repo.ScanStatus,
		); err != nil {
			RespondServerError(w, r, err)
			return
		}
		data = append(data, repo)
	}

	totalPages := total / perPage
	if total%perPage != 0 {
		totalPages++
	}
	if totalPages < 1 {
		totalPages = 1
	}

	RespondJSON(w, http.StatusOK, paginatedRepoResponse{
		Data:       data,
		Total:      total,
		Page:       page,
		PerPage:    perPage,
		TotalPages: totalPages,
	})
}

// GetByID handles GET /api/v1/repositories/{id}
func (h *RepoHandler) GetByID(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		RespondError(w, http.StatusBadRequest, "invalid repository id")
		return
	}

	repository, err := h.useCase.GetByID(r.Context(), id)
	if err != nil {
		RespondServerError(w, r, err)
		return
	}
	if repository == nil {
		RespondError(w, http.StatusNotFound, "repository not found")
		return
	}
	RespondJSON(w, http.StatusOK, repository)
}

// Create handles POST /api/v1/repositories
func (h *RepoHandler) Create(w http.ResponseWriter, r *http.Request) {
	var req createRequest
	if !decodeJSON(w, r, &req) {
		return
	}

	if req.Name == "" || req.URL == "" || req.Provider == "" {
		RespondError(w, http.StatusBadRequest, "name, url, and provider are required")
		return
	}

	input := repo.CreateInput{
		Name:          req.Name,
		URL:           req.URL,
		Provider:      entity.GitProvider(req.Provider),
		DefaultBranch: req.DefaultBranch,
		Schedule:      req.Schedule,
		AuthToken:     req.AuthToken,
	}
	if req.GitHostID != "" {
		id, err := uuid.Parse(req.GitHostID)
		if err != nil {
			RespondError(w, http.StatusBadRequest, "invalid git_host_id")
			return
		}
		input.GitHostID = &id
	}

	repository, err := h.useCase.Create(r.Context(), input)
	if err != nil {
		if errors.Is(err, domainrepo.ErrDuplicate) {
			RespondError(w, http.StatusConflict, "repository already exists")
			return
		}
		if isRepoInputError(err) {
			RespondError(w, http.StatusBadRequest, err.Error())
			return
		}
		RespondServerError(w, r, err)
		return
	}
	RespondJSON(w, http.StatusCreated, repository)
}

// isRepoInputError reports whether a repo use case error is the client's
// fault and should be a 400.
func isRepoInputError(err error) bool {
	return errors.Is(err, entity.ErrInvalidRepositoryURL) ||
		errors.Is(err, schedule.ErrInvalidSchedule) ||
		errors.Is(err, repo.ErrGitHostNotFound)
}

// Update handles PUT /api/v1/repositories/{id}
func (h *RepoHandler) Update(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		RespondError(w, http.StatusBadRequest, "invalid repository id")
		return
	}

	var req updateRequest
	if !decodeJSON(w, r, &req) {
		return
	}

	input := repo.UpdateInput{
		Name:          req.Name,
		URL:           req.URL,
		DefaultBranch: req.DefaultBranch,
		Schedule:      req.Schedule,
		AuthToken:     req.AuthToken,
		IsActive:      req.IsActive,
	}

	if req.Provider != nil {
		provider := entity.GitProvider(*req.Provider)
		input.Provider = &provider
	}
	if req.GitHostID != nil {
		hostID, err := uuid.Parse(*req.GitHostID)
		if err != nil {
			RespondError(w, http.StatusBadRequest, "invalid git_host_id")
			return
		}
		input.GitHostID = &hostID
	}

	repository, err := h.useCase.Update(r.Context(), id, input)
	if err != nil {
		if isRepoInputError(err) {
			RespondError(w, http.StatusBadRequest, err.Error())
			return
		}
		RespondServerError(w, r, err)
		return
	}
	RespondJSON(w, http.StatusOK, repository)
}

// Delete handles DELETE /api/v1/repositories/{id}
func (h *RepoHandler) Delete(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		RespondError(w, http.StatusBadRequest, "invalid repository id")
		return
	}

	if err := h.useCase.Delete(r.Context(), id); err != nil {
		RespondServerError(w, r, err)
		return
	}
	RespondJSON(w, http.StatusNoContent, nil)
}

// fetchRequest is the JSON body of the repository fetch endpoints.
type fetchRequest struct {
	TokenID string `json:"token_id"`
}

// loadToken parses a token_id and loads the token. It writes the error
// response and returns false when that fails.
func (h *RepoHandler) loadToken(w http.ResponseWriter, r *http.Request, rawID string) (*postgres.AccessToken, bool) {
	if rawID == "" {
		RespondError(w, http.StatusBadRequest, "token_id is required")
		return nil, false
	}

	tokenUUID, err := uuid.Parse(rawID)
	if err != nil {
		RespondError(w, http.StatusBadRequest, "invalid token_id")
		return nil, false
	}

	accessToken, err := h.tokenRepo.GetByID(r.Context(), tokenUUID)
	if err != nil {
		RespondError(w, http.StatusNotFound, "token not found")
		return nil, false
	}
	return accessToken, true
}

// fetchToken decodes a fetch request and loads its token, which must belong
// to provider so it is never sent to another service. It writes the error
// response and returns false when that fails.
func (h *RepoHandler) fetchToken(w http.ResponseWriter, r *http.Request, provider entity.GitProvider) (*postgres.AccessToken, bool) {
	var req fetchRequest
	if !decodeJSON(w, r, &req) {
		return nil, false
	}
	accessToken, ok := h.loadToken(w, r, req.TokenID)
	if !ok {
		return nil, false
	}
	if entity.GitProvider(accessToken.Provider) != provider {
		RespondError(w, http.StatusBadRequest, "token is for "+accessToken.Provider)
		return nil, false
	}
	return accessToken, true
}

// FetchGitHub handles POST /api/v1/repositories/github/fetch
func (h *RepoHandler) FetchGitHub(w http.ResponseWriter, r *http.Request) {
	accessToken, ok := h.fetchToken(w, r, entity.GitProviderGitHub)
	if !ok {
		return
	}

	repos, err := h.githubClient.ListRepositories(r.Context(), accessToken.Token)
	if err != nil {
		RespondUpstreamError(w, r, "failed to fetch GitHub repositories", err)
		return
	}

	RespondJSON(w, http.StatusOK, repos)
}

// FetchGitLab handles POST /api/v1/repositories/gitlab/fetch
func (h *RepoHandler) FetchGitLab(w http.ResponseWriter, r *http.Request) {
	accessToken, ok := h.fetchToken(w, r, entity.GitProviderGitLab)
	if !ok {
		return
	}

	repos, err := h.gitlabClient.ListRepositories(r.Context(), accessToken.Token)
	if err != nil {
		RespondUpstreamError(w, r, "failed to fetch GitLab projects", err)
		return
	}

	RespondJSON(w, http.StatusOK, repos)
}

// FetchAzureDevOps handles POST /api/v1/repositories/azuredevops/fetch. It
// lists the repositories the token can see on its connection.
func (h *RepoHandler) FetchAzureDevOps(w http.ResponseWriter, r *http.Request) {
	accessToken, ok := h.fetchToken(w, r, entity.GitProviderAzureDevOps)
	if !ok {
		return
	}
	host, ok := h.tokenHost(w, r, accessToken)
	if !ok {
		return
	}

	repos, skipped, err := h.azureClient.ListRepositories(r.Context(), host, accessToken.Token)
	if errors.Is(err, azuredevops.ErrUnauthorized) {
		RespondError(w, http.StatusBadRequest, "Azure DevOps rejected the token (check its scopes and expiry)")
		return
	}
	if err != nil {
		RespondUpstreamError(w, r, "failed to fetch Azure DevOps repositories", err)
		return
	}
	// Repositories whose URL is not under the connection's base URL cannot be
	// imported. The response stays a plain array; the count travels in a
	// header, and a list where every repository was skipped is an error that
	// points at the connection URL.
	if skipped > 0 {
		slog.Warn("azure devops repositories skipped: url not under the connection",
			"connection", host.ID, "base_url", host.BaseURL, "skipped", skipped, "listed", len(repos))
		w.Header().Set(skippedRepositoriesHeader, strconv.Itoa(skipped))
		if len(repos) == 0 {
			RespondError(w, http.StatusBadRequest, "none of the repositories match this connection's URL (check that the connection URL matches the organization's URL)")
			return
		}
	}

	RespondJSON(w, http.StatusOK, repos)
}

// tokenHost loads the connection of an Azure DevOps token. It writes the
// error response and returns false when the token is not an Azure DevOps
// token or its connection is gone.
func (h *RepoHandler) tokenHost(w http.ResponseWriter, r *http.Request, t *postgres.AccessToken) (*entity.GitHost, bool) {
	if entity.GitProvider(t.Provider) != entity.GitProviderAzureDevOps {
		RespondError(w, http.StatusBadRequest, "token is not an azuredevops token")
		return nil, false
	}
	if t.GitHostID == nil {
		RespondError(w, http.StatusBadRequest, "token has no connection")
		return nil, false
	}
	host, err := h.gitHosts.GetByID(r.Context(), *t.GitHostID)
	if err != nil {
		RespondServerError(w, r, err)
		return nil, false
	}
	if host == nil {
		RespondError(w, http.StatusBadRequest, "connection not found")
		return nil, false
	}
	return host, true
}

// bulkImportRequest represents the JSON body for bulk importing repos.
type bulkImportRequest struct {
	TokenID      string       `json:"token_id"`
	Provider     string       `json:"provider"`
	Repositories []importItem `json:"repositories"`
}

// importItem is one repository in a bulk import request.
type importItem struct {
	Name          string `json:"name"`
	URL           string `json:"url"`
	DefaultBranch string `json:"default_branch"`
}

// planImport splits a bulk import into repositories to create and the names
// of those already stored or repeated within the request.
func planImport(items []importItem, existing map[string]bool) ([]importItem, []string) {
	seen := make(map[string]bool, len(existing)+len(items))
	for u := range existing {
		seen[u] = true
	}
	create, skipped := []importItem{}, []string{}
	for _, it := range items {
		key := entity.NormalizeRepositoryURL(it.URL)
		if seen[key] {
			skipped = append(skipped, it.Name)
			continue
		}
		seen[key] = true
		create = append(create, it)
	}
	return create, skipped
}

// repoCreator creates repositories; repo.UseCase implements it.
type repoCreator interface {
	Create(ctx context.Context, input repo.CreateInput) (*entity.Repository, error)
}

// createImported creates each item. An item that another import stored first
// (repository.ErrDuplicate, from the UNIQUE(url) constraint) is skipped
// instead of failing the whole import; the names of those are returned.
func createImported(ctx context.Context, creator repoCreator, provider entity.GitProvider, gitHostID *uuid.UUID, token string, items []importItem) ([]*entity.Repository, []string, error) {
	created, raced := []*entity.Repository{}, []string{}
	for _, it := range items {
		repository, err := creator.Create(ctx, repo.CreateInput{
			Name:          it.Name,
			URL:           it.URL,
			Provider:      provider,
			DefaultBranch: it.DefaultBranch,
			AuthToken:     token,
			GitHostID:     gitHostID,
		})
		if errors.Is(err, domainrepo.ErrDuplicate) {
			raced = append(raced, it.Name)
			continue
		}
		if err != nil {
			return nil, nil, fmt.Errorf("import %s: %w", it.Name, err)
		}
		created = append(created, repository)
	}
	return created, raced, nil
}

// BulkImport handles POST /api/v1/repositories/import
func (h *RepoHandler) BulkImport(w http.ResponseWriter, r *http.Request) {
	var req bulkImportRequest
	if !decodeJSON(w, r, &req) {
		return
	}

	if len(req.Repositories) == 0 {
		RespondError(w, http.StatusBadRequest, "no repositories selected")
		return
	}
	if len(req.Repositories) > maxBulkImport {
		RespondError(w, http.StatusBadRequest, fmt.Sprintf("at most %d repositories per import", maxBulkImport))
		return
	}

	accessToken, ok := h.loadToken(w, r, req.TokenID)
	if !ok {
		return
	}

	// The token decides the provider; the request may only repeat it.
	provider := entity.GitProvider(accessToken.Provider)
	if req.Provider != "" && entity.GitProvider(req.Provider) != provider {
		RespondError(w, http.StatusBadRequest, fmt.Sprintf("provider %q does not match the token's provider %q", req.Provider, provider))
		return
	}
	if !entity.KnownProvider(provider) {
		RespondError(w, http.StatusBadRequest, fmt.Sprintf("unsupported provider %q", provider))
		return
	}

	// validate returns the URL to store. Azure DevOps URLs are canonicalized
	// (no explicit ":443") before the duplicate checks below, so both
	// spellings of a repository are one repository.
	validate := func(raw string) (string, error) { return raw, entity.ValidateRepositoryURL(provider, raw) }
	var gitHostID *uuid.UUID
	if provider == entity.GitProviderAzureDevOps {
		host, ok := h.tokenHost(w, r, accessToken)
		if !ok {
			return
		}
		gitHostID = &host.ID
		validate = func(raw string) (string, error) { return entity.CanonicalHostedRepositoryURL(host, raw) }
	}

	for i, repoReq := range req.Repositories {
		canonical, err := validate(repoReq.URL)
		if err != nil {
			RespondError(w, http.StatusBadRequest, "invalid repository "+repoReq.Name+": "+err.Error())
			return
		}
		req.Repositories[i].URL = canonical
	}

	urls := make([]string, len(req.Repositories))
	for i, it := range req.Repositories {
		urls[i] = it.URL
	}
	existing, err := h.useCase.ExistingURLs(r.Context(), urls)
	if err != nil {
		RespondServerError(w, r, fmt.Errorf("check existing repositories: %w", err))
		return
	}
	toCreate, skipped := planImport(req.Repositories, existing)

	created, raced, err := createImported(r.Context(), h.useCase, provider, gitHostID, accessToken.Token, toCreate)
	if err != nil {
		RespondServerError(w, r, err)
		return
	}
	skipped = append(skipped, raced...)

	RespondJSON(w, http.StatusCreated, map[string]any{"created": created, "skipped": skipped})
}

// repoListOrder maps the ?sort= value to a fixed ORDER BY clause; the value
// never reaches the SQL text itself.
func repoListOrder(sort string) (string, error) {
	switch sort {
	case "", "name":
		return "r.name ASC", nil
	case "recent":
		return "r.created_at DESC, r.name ASC", nil
	default:
		return "", fmt.Errorf("unknown sort %q (use name or recent)", sort)
	}
}
