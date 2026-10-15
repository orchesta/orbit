package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/orchesta/orbit/internal/domain/entity"
	"github.com/orchesta/orbit/internal/domain/repository"
	gitprovider "github.com/orchesta/orbit/internal/infrastructure/git"
	"github.com/orchesta/orbit/internal/infrastructure/git/azuredevops"
	"github.com/orchesta/orbit/internal/usecase/repo"
)

// fakeAzure records the ListRepositories call and answers with repos or err.
type fakeAzure struct {
	repos    []gitprovider.RepoInfo
	skipped  int
	err      error
	calls    int
	gotHost  *entity.GitHost
	gotToken string
}

func (f *fakeAzure) ListRepositories(_ context.Context, host *entity.GitHost, token string) ([]gitprovider.RepoInfo, int, error) {
	f.calls++
	f.gotHost, f.gotToken = host, token
	return f.repos, f.skipped, f.err
}

// fakeListProvider is a GitHub/GitLab client that only lists repositories.
type fakeListProvider struct {
	gitprovider.Provider
	calls int
}

func (f *fakeListProvider) ListRepositories(context.Context, string) ([]gitprovider.RepoInfo, error) {
	f.calls++
	return []gitprovider.RepoInfo{}, nil
}

// memRepos stores repositories in memory for the repo use case.
type memRepos struct {
	repository.RepositoryRepo
	repos   map[uuid.UUID]*entity.Repository
	created []*entity.Repository
	updated int
}

func newMemRepos(repos ...*entity.Repository) *memRepos {
	m := &memRepos{repos: map[uuid.UUID]*entity.Repository{}}
	for _, r := range repos {
		m.repos[r.ID] = r
	}
	return m
}

func (m *memRepos) Create(_ context.Context, r *entity.Repository, _ time.Time) error {
	m.repos[r.ID] = r
	m.created = append(m.created, r)
	return nil
}

// ExistingURLs compares normalized URLs, as the Postgres implementation does.
func (m *memRepos) ExistingURLs(_ context.Context, urls []string) (map[string]bool, error) {
	stored := map[string]bool{}
	for _, r := range m.repos {
		stored[entity.NormalizeRepositoryURL(r.URL)] = true
	}
	found := map[string]bool{}
	for _, u := range urls {
		if n := entity.NormalizeRepositoryURL(u); stored[n] {
			found[n] = true
		}
	}
	return found, nil
}

// GetByID returns a copy, as a database would, so a rejected update cannot
// leave its changes in the store.
func (m *memRepos) GetByID(_ context.Context, id uuid.UUID) (*entity.Repository, error) {
	r, ok := m.repos[id]
	if !ok {
		return nil, nil
	}
	c := *r
	return &c, nil
}

func (m *memRepos) Update(_ context.Context, r *entity.Repository, _ *time.Time) error {
	m.updated++
	m.repos[r.ID] = r
	return nil
}

type repoTestDeps struct {
	tokens *fakeTokens
	hosts  *fakeGitHosts
	azure  *fakeAzure
	github *fakeListProvider
	gitlab *fakeListProvider
	repos  *memRepos
}

func newRepoTestDeps(t *testing.T) (*repoTestDeps, *entity.GitHost) {
	t.Helper()
	host := mustGitHost(t, "acme", "https://dev.azure.com/acme")
	return &repoTestDeps{
		tokens: newFakeTokens(),
		hosts:  newFakeGitHosts(host),
		azure:  &fakeAzure{},
		github: &fakeListProvider{},
		gitlab: &fakeListProvider{},
		repos:  newMemRepos(),
	}, host
}

func (d *repoTestDeps) serve(method, path, body string) *httptest.ResponseRecorder {
	r := chi.NewRouter()
	NewRepoHandler(repo.NewUseCase(d.repos, d.hosts), d.github, d.gitlab, d.azure, d.tokens, d.hosts).RegisterRoutes(r)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(method, path, strings.NewReader(body)))
	return rec
}

// addToken stores a token and returns its id.
func (d *repoTestDeps) addToken(provider string, gitHostID *uuid.UUID) string {
	tok := newToken(provider, gitHostID)
	d.tokens.tokens[tok.ID] = tok
	return tok.ID.String()
}

func TestFetchAzureDevOpsListsTheConnectionsRepositories(t *testing.T) {
	d, host := newRepoTestDeps(t)
	tok := d.addToken("azuredevops", &host.ID)
	d.azure.repos = []gitprovider.RepoInfo{{Name: "Repo", FullName: "Proj/Repo", URL: "https://dev.azure.com/acme/Proj/_git/Repo"}}

	rec := d.serve(http.MethodPost, "/repositories/azuredevops/fetch", `{"token_id":"`+tok+`"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
	if d.azure.calls != 1 || d.azure.gotHost == nil || d.azure.gotHost.ID != host.ID || d.azure.gotToken != "secret-pat-value" {
		t.Fatalf("azure called %d times with host %v token %q", d.azure.calls, d.azure.gotHost, d.azure.gotToken)
	}
	if !strings.Contains(rec.Body.String(), "https://dev.azure.com/acme/Proj/_git/Repo") {
		t.Fatalf("body should list the repository: %s", rec.Body)
	}
}

func TestFetchAzureDevOpsReportsSkippedRepositoriesInAHeader(t *testing.T) {
	d, host := newRepoTestDeps(t)
	tok := d.addToken("azuredevops", &host.ID)
	d.azure.repos = []gitprovider.RepoInfo{{Name: "Repo", FullName: "Proj/Repo", URL: "https://dev.azure.com/acme/Proj/_git/Repo"}}
	d.azure.skipped = 2

	rec := d.serve(http.MethodPost, "/repositories/azuredevops/fetch", `{"token_id":"`+tok+`"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
	if got := rec.Header().Get("X-Orbit-Skipped-Repositories"); got != "2" {
		t.Fatalf("X-Orbit-Skipped-Repositories = %q, want 2", got)
	}
	var body struct {
		Data []gitprovider.RepoInfo `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || len(body.Data) != 1 {
		t.Fatalf("data must stay an array of repositories: %s (%v)", rec.Body, err)
	}
}

func TestFetchAzureDevOpsWithoutSkipsHasNoSkippedHeader(t *testing.T) {
	d, host := newRepoTestDeps(t)
	tok := d.addToken("azuredevops", &host.ID)
	d.azure.repos = []gitprovider.RepoInfo{}

	rec := d.serve(http.MethodPost, "/repositories/azuredevops/fetch", `{"token_id":"`+tok+`"}`)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"data":[]`) {
		t.Fatalf("status=%d body=%s, want 200 with an empty list", rec.Code, rec.Body)
	}
	if got, ok := rec.Header()["X-Orbit-Skipped-Repositories"]; ok {
		t.Fatalf("X-Orbit-Skipped-Repositories = %q, want no header", got)
	}
}

func TestFetchAzureDevOpsAllSkippedIs400(t *testing.T) {
	d, host := newRepoTestDeps(t)
	tok := d.addToken("azuredevops", &host.ID)
	d.azure.repos = []gitprovider.RepoInfo{}
	d.azure.skipped = 3

	rec := d.serve(http.MethodPost, "/repositories/azuredevops/fetch", `{"token_id":"`+tok+`"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s, want 400", rec.Code, rec.Body)
	}
	const msg = "none of the repositories match this connection's URL (check that the connection URL matches the organization's URL)"
	if !strings.Contains(rec.Body.String(), msg) {
		t.Fatalf("body = %s, want %q", rec.Body, msg)
	}
	if got := rec.Header().Get("X-Orbit-Skipped-Repositories"); got != "3" {
		t.Fatalf("X-Orbit-Skipped-Repositories = %q, want 3", got)
	}
}

func TestFetchAzureDevOpsRejectsOtherProvidersTokens(t *testing.T) {
	d, _ := newRepoTestDeps(t)
	tok := d.addToken("github", nil)
	rec := d.serve(http.MethodPost, "/repositories/azuredevops/fetch", `{"token_id":"`+tok+`"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s, want 400", rec.Code, rec.Body)
	}
	if d.azure.calls != 0 {
		t.Fatal("a GitHub token must never be sent to Azure DevOps")
	}
}

func TestFetchAzureDevOpsUnknownTokenIs404(t *testing.T) {
	d, _ := newRepoTestDeps(t)
	rec := d.serve(http.MethodPost, "/repositories/azuredevops/fetch", `{"token_id":"`+uuid.NewString()+`"}`)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status=%d body=%s, want 404", rec.Code, rec.Body)
	}
}

func TestFetchAzureDevOpsRejectedTokenIs400(t *testing.T) {
	d, host := newRepoTestDeps(t)
	tok := d.addToken("azuredevops", &host.ID)
	d.azure.err = azuredevops.ErrUnauthorized
	rec := d.serve(http.MethodPost, "/repositories/azuredevops/fetch", `{"token_id":"`+tok+`"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s, want 400", rec.Code, rec.Body)
	}
	if !strings.Contains(rec.Body.String(), "Azure DevOps rejected the token (check its scopes and expiry)") {
		t.Fatalf("body should explain the rejection: %s", rec.Body)
	}
}

func TestFetchAzureDevOpsHidesUpstreamErrorBodies(t *testing.T) {
	d, host := newRepoTestDeps(t)
	tok := d.addToken("azuredevops", &host.ID)
	d.azure.err = errors.New("Azure DevOps API error (status 500): internal-host-detail")
	rec := d.serve(http.MethodPost, "/repositories/azuredevops/fetch", `{"token_id":"`+tok+`"}`)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status=%d body=%s, want 502", rec.Code, rec.Body)
	}
	if strings.Contains(rec.Body.String(), "internal-host-detail") {
		t.Fatalf("upstream body leaked to the client: %s", rec.Body)
	}
}

func TestFetchGitHubAndGitLabOnlyTakeTheirOwnTokens(t *testing.T) {
	for _, c := range []struct {
		path, provider string
	}{
		{"/repositories/github/fetch", "gitlab"},
		{"/repositories/github/fetch", "azuredevops"},
		{"/repositories/gitlab/fetch", "github"},
		{"/repositories/gitlab/fetch", "azuredevops"},
	} {
		d, host := newRepoTestDeps(t)
		var hostID *uuid.UUID
		if c.provider == "azuredevops" {
			hostID = &host.ID
		}
		tok := d.addToken(c.provider, hostID)
		rec := d.serve(http.MethodPost, c.path, `{"token_id":"`+tok+`"}`)
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "token is for "+c.provider) {
			t.Errorf("%s with a %s token: status=%d body=%s, want 400 token is for %s", c.path, c.provider, rec.Code, rec.Body, c.provider)
		}
		if d.github.calls != 0 || d.gitlab.calls != 0 {
			t.Errorf("%s with a %s token: github called %d, gitlab called %d; want neither", c.path, c.provider, d.github.calls, d.gitlab.calls)
		}
	}
}

func TestFetchGitHubAndGitLabWithTheirOwnTokens(t *testing.T) {
	d, _ := newRepoTestDeps(t)
	for _, c := range []struct {
		path, provider string
		calls          *int
	}{
		{"/repositories/github/fetch", "github", &d.github.calls},
		{"/repositories/gitlab/fetch", "gitlab", &d.gitlab.calls},
	} {
		tok := d.addToken(c.provider, nil)
		rec := d.serve(http.MethodPost, c.path, `{"token_id":"`+tok+`"}`)
		if rec.Code != http.StatusOK || *c.calls != 1 {
			t.Errorf("%s: status=%d calls=%d body=%s, want 200 and one upstream call", c.path, rec.Code, *c.calls, rec.Body)
		}
	}
}

func importBody(tokenID, provider string, urls ...string) string {
	items := make([]map[string]string, len(urls))
	for i, u := range urls {
		items[i] = map[string]string{"name": u[strings.LastIndex(u, "/")+1:], "url": u}
	}
	b, _ := json.Marshal(map[string]any{"token_id": tokenID, "provider": provider, "repositories": items})
	return string(b)
}

func TestBulkImportTakesTheProviderFromTheToken(t *testing.T) {
	d, _ := newRepoTestDeps(t)
	tok := d.addToken("gitlab", nil)
	rec := d.serve(http.MethodPost, "/repositories/import", importBody(tok, "", "https://gitlab.com/o/r"))
	if rec.Code != http.StatusCreated {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
	if len(d.repos.created) != 1 || d.repos.created[0].Provider != entity.GitProviderGitLab || d.repos.created[0].GitHostID != nil {
		t.Fatalf("created = %+v, want one gitlab repository without a connection", d.repos.created)
	}
}

func TestBulkImportGitHubStillWorks(t *testing.T) {
	d, _ := newRepoTestDeps(t)
	tok := d.addToken("github", nil)
	rec := d.serve(http.MethodPost, "/repositories/import", importBody(tok, "github", "https://github.com/o/a", "https://github.com/o/b"))
	if rec.Code != http.StatusCreated || len(d.repos.created) != 2 {
		t.Fatalf("status=%d created=%d body=%s", rec.Code, len(d.repos.created), rec.Body)
	}
	if d.repos.created[0].Provider != entity.GitProviderGitHub || d.repos.created[0].AuthToken != "secret-pat-value" {
		t.Fatalf("created = %+v, want github repositories using the token", d.repos.created[0])
	}
}

func TestBulkImportProviderMismatchIs400(t *testing.T) {
	d, _ := newRepoTestDeps(t)
	tok := d.addToken("github", nil)
	rec := d.serve(http.MethodPost, "/repositories/import", importBody(tok, "gitlab", "https://gitlab.com/o/r"))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s, want 400", rec.Code, rec.Body)
	}
	if len(d.repos.created) != 0 {
		t.Fatal("nothing should be created")
	}
}

func TestBulkImportUnknownProviderIs400(t *testing.T) {
	d, _ := newRepoTestDeps(t)
	tok := d.addToken("bitbucket", nil)
	rec := d.serve(http.MethodPost, "/repositories/import", importBody(tok, "", "https://github.com/o/r"))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s, want 400", rec.Code, rec.Body)
	}
	if len(d.repos.created) != 0 {
		t.Fatal("an unknown provider must not fall back to GitHub")
	}
}

func TestBulkImportAzureValidatesURLsAgainstTheConnection(t *testing.T) {
	d, host := newRepoTestDeps(t)
	tok := d.addToken("azuredevops", &host.ID)
	rec := d.serve(http.MethodPost, "/repositories/import", importBody(tok, "azuredevops",
		"https://dev.azure.com/acme/Proj/_git/Good",
		"https://evil.example/acme/Proj/_git/Bad"))
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "Bad") {
		t.Fatalf("status=%d body=%s, want 400 naming the bad repository", rec.Code, rec.Body)
	}
	if len(d.repos.created) != 0 {
		t.Fatal("nothing should be created when one URL is invalid")
	}
}

func TestBulkImportAzureLinksRepositoriesToTheConnection(t *testing.T) {
	d, host := newRepoTestDeps(t)
	tok := d.addToken("azuredevops", &host.ID)
	rec := d.serve(http.MethodPost, "/repositories/import", importBody(tok, "",
		"https://dev.azure.com/acme/Proj/_git/A",
		"https://dev.azure.com/acme/My%20Project/_git/My%20Repo"))
	if rec.Code != http.StatusCreated || len(d.repos.created) != 2 {
		t.Fatalf("status=%d created=%d body=%s", rec.Code, len(d.repos.created), rec.Body)
	}
	for _, r := range d.repos.created {
		if r.Provider != entity.GitProviderAzureDevOps || r.GitHostID == nil || *r.GitHostID != host.ID {
			t.Fatalf("created %s as %s on %v, want azuredevops on %s", r.URL, r.Provider, r.GitHostID, host.ID)
		}
	}
}

// The same repository spelled with and without ":443" is one repository.
func TestBulkImportAzureDedupesTheDefaultPort(t *testing.T) {
	d, host := newRepoTestDeps(t)
	tok := d.addToken("azuredevops", &host.ID)
	rec := d.serve(http.MethodPost, "/repositories/import", importBody(tok, "",
		"https://dev.azure.com:443/acme/Proj/_git/A",
		"https://dev.azure.com/acme/Proj/_git/A"))
	if rec.Code != http.StatusCreated || len(d.repos.created) != 1 {
		t.Fatalf("status=%d created=%d body=%s, want one repository", rec.Code, len(d.repos.created), rec.Body)
	}
	if got := d.repos.created[0].URL; got != "https://dev.azure.com/acme/Proj/_git/A" {
		t.Fatalf("stored url = %q, want it without :443", got)
	}

	// A later import with ":443" finds the stored repository.
	rec = d.serve(http.MethodPost, "/repositories/import", importBody(tok, "", "https://dev.azure.com:443/acme/Proj/_git/A"))
	if rec.Code != http.StatusCreated || len(d.repos.created) != 1 {
		t.Fatalf("status=%d created=%d body=%s, want the second import skipped", rec.Code, len(d.repos.created), rec.Body)
	}
	if !strings.Contains(rec.Body.String(), `"skipped":["A"]`) {
		t.Fatalf("body = %s, want A skipped", rec.Body)
	}
}

func TestCreateAzureRepositoryNeedsAConnection(t *testing.T) {
	d, _ := newRepoTestDeps(t)
	rec := d.serve(http.MethodPost, "/repositories/", `{"name":"r","url":"https://dev.azure.com/acme/Proj/_git/Repo","provider":"azuredevops"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s, want 400", rec.Code, rec.Body)
	}
}

func TestCreateGitHubRepositoryWithAConnectionIs400(t *testing.T) {
	d, host := newRepoTestDeps(t)
	rec := d.serve(http.MethodPost, "/repositories/", `{"name":"r","url":"https://github.com/o/r","provider":"github","git_host_id":"`+host.ID.String()+`"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s, want 400", rec.Code, rec.Body)
	}
	if len(d.repos.created) != 0 {
		t.Fatal("nothing should be created")
	}
}

func TestCreateAzureRepositoryWithUnknownOrInvalidConnectionIs400(t *testing.T) {
	d, _ := newRepoTestDeps(t)
	for _, id := range []string{uuid.NewString(), "nope"} {
		rec := d.serve(http.MethodPost, "/repositories/", `{"name":"r","url":"https://dev.azure.com/acme/Proj/_git/Repo","provider":"azuredevops","git_host_id":"`+id+`"}`)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status=%d body=%s, want 400", id, rec.Code, rec.Body)
		}
	}
}

func TestCreateAzureRepository(t *testing.T) {
	d, host := newRepoTestDeps(t)
	rec := d.serve(http.MethodPost, "/repositories/", `{"name":"r","url":"https://dev.azure.com/acme/Proj/_git/Repo","provider":"azuredevops","git_host_id":"`+host.ID.String()+`","auth_token":"pat"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status=%d body=%s, want 201", rec.Code, rec.Body)
	}
	if len(d.repos.created) != 1 || d.repos.created[0].GitHostID == nil || *d.repos.created[0].GitHostID != host.ID {
		t.Fatalf("created = %+v, want one repository linked to %s", d.repos.created, host.ID)
	}
}

func TestUpdateAzureRepositoryURLToAnotherHostIs400(t *testing.T) {
	d, host := newRepoTestDeps(t)
	existing := entity.NewRepository("r", "https://dev.azure.com/acme/Proj/_git/Repo", entity.GitProviderAzureDevOps, "pat")
	existing.GitHostID = &host.ID
	d.repos.repos[existing.ID] = existing

	rec := d.serve(http.MethodPut, "/repositories/"+existing.ID.String(), `{"url":"https://tfs.example.com/tfs/Col/Proj/_git/Repo"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s, want 400", rec.Code, rec.Body)
	}
	if d.repos.updated != 0 {
		t.Fatal("repository must not be updated")
	}
}

func TestUpdateRepositoryWithUnknownConnectionIs400(t *testing.T) {
	d, host := newRepoTestDeps(t)
	existing := entity.NewRepository("r", "https://dev.azure.com/acme/Proj/_git/Repo", entity.GitProviderAzureDevOps, "pat")
	existing.GitHostID = &host.ID
	d.repos.repos[existing.ID] = existing

	for _, id := range []string{uuid.NewString(), "nope"} {
		rec := d.serve(http.MethodPut, "/repositories/"+existing.ID.String(), `{"git_host_id":"`+id+`"}`)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status=%d body=%s, want 400", id, rec.Code, rec.Body)
		}
	}
	if d.repos.updated != 0 {
		t.Fatal("repository must not be updated")
	}
}
