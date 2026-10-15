package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/orchesta/orbit/internal/domain/entity"
	"github.com/orchesta/orbit/internal/domain/repository"
)

// fakeGitHosts keeps connections in memory; GitHostRepo calls it does not
// implement panic through the embedded interface.
type fakeGitHosts struct {
	repository.GitHostRepo
	hosts     map[uuid.UUID]*entity.GitHost
	order     []uuid.UUID
	createErr error
	deleteErr error
	listErr   error
	deleted   []uuid.UUID
}

func newFakeGitHosts(hosts ...*entity.GitHost) *fakeGitHosts {
	f := &fakeGitHosts{hosts: map[uuid.UUID]*entity.GitHost{}}
	for _, h := range hosts {
		f.hosts[h.ID] = h
		f.order = append(f.order, h.ID)
	}
	return f
}

func (f *fakeGitHosts) Create(_ context.Context, h *entity.GitHost) error {
	if f.createErr != nil {
		return f.createErr
	}
	f.hosts[h.ID] = h
	f.order = append(f.order, h.ID)
	return nil
}

func (f *fakeGitHosts) GetByID(_ context.Context, id uuid.UUID) (*entity.GitHost, error) {
	return f.hosts[id], nil
}

// List returns nil when empty, as the Postgres implementation does.
func (f *fakeGitHosts) List(context.Context) ([]*entity.GitHost, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	var out []*entity.GitHost
	for _, id := range f.order {
		out = append(out, f.hosts[id])
	}
	return out, nil
}

func (f *fakeGitHosts) Delete(_ context.Context, id uuid.UUID) error {
	if f.deleteErr != nil {
		return f.deleteErr
	}
	f.deleted = append(f.deleted, id)
	delete(f.hosts, id)
	return nil
}

func mustGitHost(t *testing.T, name, baseURL string) *entity.GitHost {
	t.Helper()
	h, err := entity.NewGitHost(entity.GitProviderAzureDevOps, name, baseURL)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func serveGitHosts(hosts *fakeGitHosts, method, path, body string) *httptest.ResponseRecorder {
	r := chi.NewRouter()
	NewGitHostHandler(hosts).RegisterRoutes(r)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(method, path, strings.NewReader(body)))
	return rec
}

func TestListGitHostsReturnsAnEmptyArray(t *testing.T) {
	rec := serveGitHosts(newFakeGitHosts(), http.MethodGet, "/git-hosts/", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
	if !strings.Contains(rec.Body.String(), `"data":[]`) {
		t.Fatalf("an empty list must be a JSON array, got %s", rec.Body)
	}
}

func TestListGitHosts(t *testing.T) {
	host := mustGitHost(t, "acme", "https://dev.azure.com/acme")
	rec := serveGitHosts(newFakeGitHosts(host), http.MethodGet, "/git-hosts/", "")
	var resp struct {
		Data []entity.GitHost `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if rec.Code != http.StatusOK || len(resp.Data) != 1 || resp.Data[0].ID != host.ID || resp.Data[0].BaseURL != host.BaseURL {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
}

func TestListGitHostsHidesStoreErrors(t *testing.T) {
	hosts := newFakeGitHosts()
	hosts.listErr = errors.New("pq: connection refused at 10.0.0.5")
	rec := serveGitHosts(hosts, http.MethodGet, "/git-hosts/", "")
	if rec.Code != http.StatusInternalServerError || strings.Contains(rec.Body.String(), "10.0.0.5") {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
}

func TestCreateGitHostStoresTheNormalizedConnection(t *testing.T) {
	hosts := newFakeGitHosts()
	rec := serveGitHosts(hosts, http.MethodPost, "/git-hosts/", `{"kind":"azuredevops","name":" Acme ","base_url":"https://Dev.Azure.com/acme/"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
	if len(hosts.order) != 1 {
		t.Fatalf("stored %d connections, want 1", len(hosts.order))
	}
	stored := hosts.hosts[hosts.order[0]]
	if stored.Name != "Acme" || stored.BaseURL != "https://dev.azure.com/acme" {
		t.Fatalf("stored %+v, want the normalized name and base URL", stored)
	}
	if !strings.Contains(rec.Body.String(), stored.ID.String()) {
		t.Fatalf("response should carry the new connection: %s", rec.Body)
	}
}

func TestCreateGitHostValidationErrorsAre400(t *testing.T) {
	for _, body := range []string{
		`{"kind":"azuredevops","name":"x","base_url":"http://dev.azure.com/acme"}`,
		`{"kind":"github","name":"x","base_url":"https://github.com"}`,
		`{"kind":"azuredevops","name":"","base_url":"https://dev.azure.com/acme"}`,
		`{"kind":"azuredevops","name":"x","base_url":"https://user:pw@tfs.example.com/tfs"}`,
		`not json`,
	} {
		hosts := newFakeGitHosts()
		rec := serveGitHosts(hosts, http.MethodPost, "/git-hosts/", body)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status=%d body=%s, want 400", body, rec.Code, rec.Body)
		}
		if len(hosts.order) != 0 {
			t.Errorf("%s: an invalid connection must not be stored", body)
		}
	}
}

func TestCreateGitHostDuplicateBaseURLIs409(t *testing.T) {
	hosts := newFakeGitHosts()
	hosts.createErr = repository.ErrDuplicate
	rec := serveGitHosts(hosts, http.MethodPost, "/git-hosts/", `{"kind":"azuredevops","name":"x","base_url":"https://dev.azure.com/acme"}`)
	if rec.Code != http.StatusConflict {
		t.Fatalf("status=%d body=%s, want 409", rec.Code, rec.Body)
	}
	if !strings.Contains(rec.Body.String(), "a connection with this base URL already exists") {
		t.Fatalf("409 must name the connection conflict, got %s", rec.Body)
	}
}

func TestDeleteGitHost(t *testing.T) {
	host := mustGitHost(t, "acme", "https://dev.azure.com/acme")
	hosts := newFakeGitHosts(host)
	rec := serveGitHosts(hosts, http.MethodDelete, "/git-hosts/"+host.ID.String(), "")
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status=%d body=%s, want 204", rec.Code, rec.Body)
	}
	if len(hosts.deleted) != 1 || hosts.deleted[0] != host.ID {
		t.Fatalf("deleted = %v, want %s", hosts.deleted, host.ID)
	}
}

func TestDeleteUnknownGitHostIs404(t *testing.T) {
	hosts := newFakeGitHosts()
	rec := serveGitHosts(hosts, http.MethodDelete, "/git-hosts/"+uuid.NewString(), "")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status=%d body=%s, want 404", rec.Code, rec.Body)
	}
	if len(hosts.deleted) != 0 {
		t.Fatal("nothing should be deleted")
	}
}

func TestDeleteGitHostWithRepositoriesIs409(t *testing.T) {
	host := mustGitHost(t, "acme", "https://dev.azure.com/acme")
	hosts := newFakeGitHosts(host)
	hosts.deleteErr = repository.ErrInUse
	rec := serveGitHosts(hosts, http.MethodDelete, "/git-hosts/"+host.ID.String(), "")
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "connection has repositories") {
		t.Fatalf("status=%d body=%s, want 409 connection has repositories", rec.Code, rec.Body)
	}
}

func TestDeleteGitHostInvalidIDIs400(t *testing.T) {
	rec := serveGitHosts(newFakeGitHosts(), http.MethodDelete, "/git-hosts/not-a-uuid", "")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s, want 400", rec.Code, rec.Body)
	}
}

func TestCreateGitHostErrorsDoNotEchoCredentials(t *testing.T) {
	for _, baseURL := range []string{
		"https://user:secret@tfs.example.com/%zz",
		"https://user:secret@[::1/tfs",
		"https://user:secret@tfs example.com/tfs",
		"https://user:secret@tfs.example.com/tfs",
	} {
		body, _ := json.Marshal(map[string]string{"kind": "azuredevops", "name": "x", "base_url": baseURL})
		rec := serveGitHosts(newFakeGitHosts(), http.MethodPost, "/git-hosts/", string(body))
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status=%d, want 400", baseURL, rec.Code)
		}
		if strings.Contains(rec.Body.String(), "secret") {
			t.Errorf("%s: response echoes the credentials: %s", baseURL, rec.Body)
		}
	}
}
