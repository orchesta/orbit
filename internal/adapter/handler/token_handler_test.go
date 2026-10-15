package handler

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/orchesta/orbit/internal/adapter/persistence/postgres"
)

// fakeTokens is an in-memory access token store for TokenHandler and RepoHandler.
type fakeTokens struct {
	tokens  map[uuid.UUID]*postgres.AccessToken
	created []*postgres.AccessToken
}

func newFakeTokens(tokens ...*postgres.AccessToken) *fakeTokens {
	f := &fakeTokens{tokens: map[uuid.UUID]*postgres.AccessToken{}}
	for _, t := range tokens {
		f.tokens[t.ID] = t
	}
	return f
}

func (f *fakeTokens) GetAll(context.Context) ([]postgres.AccessTokenResponse, error) {
	return nil, nil
}

func (f *fakeTokens) Create(_ context.Context, label, provider string, gitHostID *uuid.UUID, token string) (*postgres.AccessToken, error) {
	t := &postgres.AccessToken{ID: uuid.New(), Label: label, Provider: provider, GitHostID: gitHostID, Token: token, CreatedAt: time.Now().UTC()}
	f.tokens[t.ID] = t
	f.created = append(f.created, t)
	return t, nil
}

func (f *fakeTokens) GetByID(_ context.Context, id uuid.UUID) (*postgres.AccessToken, error) {
	t, ok := f.tokens[id]
	if !ok {
		return nil, errors.New("failed to get access token: no rows in result set")
	}
	return t, nil
}

func (f *fakeTokens) Delete(_ context.Context, id uuid.UUID) error {
	delete(f.tokens, id)
	return nil
}

func (f *fakeTokens) Pool() *pgxpool.Pool { return nil }

func newToken(provider string, gitHostID *uuid.UUID) *postgres.AccessToken {
	return &postgres.AccessToken{ID: uuid.New(), Label: "t", Provider: provider, GitHostID: gitHostID, Token: "secret-pat-value"}
}

func serveTokens(tokens *fakeTokens, hosts *fakeGitHosts, body string) *httptest.ResponseRecorder {
	r := chi.NewRouter()
	NewTokenHandler(tokens, hosts).RegisterRoutes(r)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/tokens/", strings.NewReader(body)))
	return rec
}

func TestCreateTokenRejectsBadLength(t *testing.T) {
	r := chi.NewRouter()
	NewTokenHandler(nil, nil).RegisterRoutes(r)
	for _, tok := range []string{"abc", strings.Repeat("x", 513)} {
		body := `{"label":"x","provider":"github","token":"` + tok + `"}`
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/tokens/", strings.NewReader(body)))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("token len %d: status = %d, want 400", len(tok), rec.Code)
		}
	}
}

func TestCreateTokenDefaultsToGitHub(t *testing.T) {
	tokens := newFakeTokens()
	rec := serveTokens(tokens, newFakeGitHosts(), `{"label":"x","token":"ghp_12345678"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
	if len(tokens.created) != 1 || tokens.created[0].Provider != "github" || tokens.created[0].GitHostID != nil {
		t.Fatalf("created = %+v, want one github token without a connection", tokens.created)
	}
}

func TestCreateTokenRejectsUnknownProvider(t *testing.T) {
	tokens := newFakeTokens()
	rec := serveTokens(tokens, newFakeGitHosts(), `{"label":"x","provider":"bitbucket","token":"12345678"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s, want 400", rec.Code, rec.Body)
	}
	if len(tokens.created) != 0 {
		t.Fatal("token must not be stored")
	}
}

func TestCreateTokenLabelLength(t *testing.T) {
	tokens := newFakeTokens()
	rec := serveTokens(tokens, newFakeGitHosts(), `{"label":"`+strings.Repeat("x", 101)+`","provider":"github","token":"12345678"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("101 characters: status=%d body=%s, want 400", rec.Code, rec.Body)
	}
	// The column counts characters, so 100 multi-byte characters still fit.
	rec = serveTokens(tokens, newFakeGitHosts(), `{"label":"`+strings.Repeat("ş", 100)+`","provider":"github","token":"12345678"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("100 characters: status=%d body=%s, want 201", rec.Code, rec.Body)
	}
	if len(tokens.created) != 1 {
		t.Fatalf("created %d tokens, want 1", len(tokens.created))
	}
}

func TestCreateAzureTokenNeedsAnExistingConnection(t *testing.T) {
	for name, hostID := range map[string]string{
		"missing": ``,
		"unknown": `,"git_host_id":"` + uuid.NewString() + `"`,
		"invalid": `,"git_host_id":"nope"`,
	} {
		tokens := newFakeTokens()
		rec := serveTokens(tokens, newFakeGitHosts(), `{"label":"x","provider":"azuredevops","token":"12345678"`+hostID+`}`)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status=%d body=%s, want 400", name, rec.Code, rec.Body)
		}
		if len(tokens.created) != 0 {
			t.Errorf("%s: token must not be stored", name)
		}
	}
}

func TestCreateGitHubTokenRejectsAConnection(t *testing.T) {
	host := mustGitHost(t, "acme", "https://dev.azure.com/acme")
	tokens := newFakeTokens()
	rec := serveTokens(tokens, newFakeGitHosts(host), `{"label":"x","provider":"github","token":"12345678","git_host_id":"`+host.ID.String()+`"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s, want 400", rec.Code, rec.Body)
	}
	if len(tokens.created) != 0 {
		t.Fatal("token must not be stored")
	}
}

func TestCreateAzureToken(t *testing.T) {
	host := mustGitHost(t, "acme", "https://dev.azure.com/acme")
	tokens := newFakeTokens()
	rec := serveTokens(tokens, newFakeGitHosts(host), `{"label":"x","provider":"azuredevops","token":"12345678","git_host_id":"`+host.ID.String()+`"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status=%d body=%s, want 201", rec.Code, rec.Body)
	}
	if len(tokens.created) != 1 || tokens.created[0].GitHostID == nil || *tokens.created[0].GitHostID != host.ID {
		t.Fatalf("created = %+v, want one token linked to %s", tokens.created, host.ID)
	}
	if !strings.Contains(rec.Body.String(), `"git_host_id":"`+host.ID.String()+`"`) {
		t.Fatalf("response should carry git_host_id: %s", rec.Body)
	}
	if strings.Contains(rec.Body.String(), "12345678") {
		t.Fatalf("response must not carry the raw token: %s", rec.Body)
	}
}
