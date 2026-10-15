package server

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/orchesta/orbit/internal/adapter/handler"
	"github.com/orchesta/orbit/internal/adapter/persistence/postgres"
	"github.com/orchesta/orbit/internal/domain/entity"
	"github.com/orchesta/orbit/internal/domain/repository"
	"github.com/orchesta/orbit/internal/infrastructure/auth"
	"github.com/orchesta/orbit/internal/usecase/repo"
)

func newTestRouter(t *testing.T, opts RouterOptions) (http.Handler, *bytes.Buffer) {
	t.Helper()
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	return NewRouter(Handlers{}, auth.NewJWTService(strings.Repeat("s", 32), 1), nil, logger, opts), &logs
}

func TestRealIPOnlyWhenTrusted(t *testing.T) {
	for _, trusted := range []bool{false, true} {
		h, logs := newTestRouter(t, RouterOptions{TrustProxyHeaders: trusted})
		req := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
		req.Header.Set("X-Forwarded-For", "203.0.113.9")
		h.ServeHTTP(httptest.NewRecorder(), req)
		spoofed := strings.Contains(logs.String(), "remote=203.0.113.9")
		if spoofed != trusted {
			t.Fatalf("trusted=%v: X-Forwarded-For used=%v; logs=%s", trusted, spoofed, logs.String())
		}
	}
}

func TestSecurityHeadersOnEveryResponse(t *testing.T) {
	h, _ := newTestRouter(t, RouterOptions{})
	for _, path := range []string{"/api/v1/health", "/"} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		for _, name := range []string{"X-Content-Type-Options", "X-Frame-Options", "Referrer-Policy", "Content-Security-Policy"} {
			if rec.Header().Get(name) == "" {
				t.Errorf("%s: missing %s", path, name)
			}
		}
	}
}

func TestCORSOnlyForAllowedOrigins(t *testing.T) {
	cases := []struct {
		allowed []string
		origin  string
		want    string
	}{
		{nil, "https://evil.example", ""},
		{[]string{"https://orbit.example.com"}, "https://evil.example", ""},
		{[]string{"https://orbit.example.com"}, "https://orbit.example.com", "https://orbit.example.com"},
	}
	for _, c := range cases {
		h, _ := newTestRouter(t, RouterOptions{CORSAllowedOrigins: c.allowed})
		req := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
		req.Header.Set("Origin", c.origin)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if got := rec.Header().Get("Access-Control-Allow-Origin"); got != c.want {
			t.Errorf("allowed=%v origin=%s: ACAO=%q, want %q", c.allowed, c.origin, got, c.want)
		}
	}
}

func TestRequestBodyIsLimited(t *testing.T) {
	var readErr error
	h := limitRequestBody(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, readErr = io.ReadAll(r.Body)
	}))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/", strings.NewReader(strings.Repeat("x", maxRequestBodyBytes+1))))
	if readErr == nil {
		t.Fatal("reading a body over the limit must fail")
	}
}

func TestNewRoutesRequireAuthentication(t *testing.T) {
	h, _ := newTestRouter(t, RouterOptions{})
	for _, c := range []struct{ method, path string }{
		{http.MethodGet, "/api/v1/git-hosts"},
		{http.MethodPost, "/api/v1/git-hosts"},
		{http.MethodDelete, "/api/v1/git-hosts/00000000-0000-0000-0000-000000000000"},
		{http.MethodPost, "/api/v1/repositories/azuredevops/fetch"},
	} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(c.method, c.path, nil))
		// 401 (not 404) shows the route exists behind the JWT middleware.
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s %s: status %d, want 401", c.method, c.path, rec.Code)
		}
	}
}

// roleUsers resolves every token to one user with the given role.
type roleUsers struct {
	repository.UserRepo
	user *entity.User
}

func (u roleUsers) GetByID(context.Context, uuid.UUID) (*entity.User, error) { return u.user, nil }

// noGitHosts knows no connections.
type noGitHosts struct{ repository.GitHostRepo }

func (noGitHosts) GetByID(context.Context, uuid.UUID) (*entity.GitHost, error) { return nil, nil }

// noTokens stores nothing; Delete always succeeds.
type noTokens struct{}

func (noTokens) GetAll(context.Context) ([]postgres.AccessTokenResponse, error) { return nil, nil }
func (noTokens) Create(context.Context, string, string, *uuid.UUID, string) (*postgres.AccessToken, error) {
	return nil, nil
}
func (noTokens) Delete(context.Context, uuid.UUID) error { return nil }

func TestWritesOnConnectionTokenAndRepositoryRoutesNeedAdmin(t *testing.T) {
	const id = "00000000-0000-0000-0000-000000000000"
	// adminStatus is what an admin gets from the real handler, which proves
	// the request got past the role check to the route.
	routes := []struct {
		method, path, body string
		adminStatus        int
	}{
		{http.MethodPost, "/api/v1/git-hosts", `{}`, http.StatusBadRequest},
		{http.MethodDelete, "/api/v1/git-hosts/" + id, ``, http.StatusNotFound},
		{http.MethodPost, "/api/v1/tokens", `{}`, http.StatusBadRequest},
		{http.MethodDelete, "/api/v1/tokens/" + id, ``, http.StatusOK},
		{http.MethodPost, "/api/v1/repositories/azuredevops/fetch", `{}`, http.StatusBadRequest},
		{http.MethodPost, "/api/v1/repositories/import", `{}`, http.StatusBadRequest},
		{http.MethodPost, "/api/v1/repositories", `{}`, http.StatusBadRequest},
		{http.MethodPut, "/api/v1/repositories/" + id, `{"git_host_id":"nope"}`, http.StatusBadRequest},
	}
	handlers := Handlers{
		GitHost: handler.NewGitHostHandler(noGitHosts{}),
		Token:   handler.NewTokenHandler(noTokens{}, noGitHosts{}),
		Repo:    handler.NewRepoHandler(repo.NewUseCase(nil, noGitHosts{}), nil, nil, nil, nil, noGitHosts{}),
	}
	for _, role := range []entity.Role{entity.RoleViewer, entity.RoleAdmin} {
		user := &entity.User{ID: uuid.New(), Email: "u@example.com", Role: role, IsActive: true}
		jwt := auth.NewJWTService(strings.Repeat("s", 32), 1)
		token, err := jwt.GenerateToken(user)
		if err != nil {
			t.Fatal(err)
		}
		h := NewRouter(handlers, jwt, roleUsers{user: user}, slog.New(slog.NewTextHandler(io.Discard, nil)), RouterOptions{})
		for _, c := range routes {
			req := httptest.NewRequest(c.method, c.path, strings.NewReader(c.body))
			req.Header.Set("Authorization", "Bearer "+token)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			want := c.adminStatus
			if role == entity.RoleViewer {
				want = http.StatusForbidden
			}
			if rec.Code != want {
				t.Errorf("%s %s %s: status %d, want %d; body=%s", role, c.method, c.path, rec.Code, want, rec.Body)
			}
		}
	}
}
