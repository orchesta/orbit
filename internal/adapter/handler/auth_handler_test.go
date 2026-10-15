package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/aligoren/orbit/internal/domain/entity"
	"github.com/aligoren/orbit/internal/domain/repository"
	"github.com/aligoren/orbit/internal/infrastructure/auth"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

type fakeUsers struct {
	repository.UserRepo
	byEmail   map[string]*entity.User
	created   *entity.User
	createErr error
}

func (f *fakeUsers) GetByEmail(_ context.Context, email string) (*entity.User, error) {
	return f.byEmail[email], nil
}

func (f *fakeUsers) GetByID(_ context.Context, _ uuid.UUID) (*entity.User, error) { return nil, nil }

func (f *fakeUsers) CreateInitialAdmin(_ context.Context, u *entity.User) error {
	if f.createErr != nil {
		return f.createErr
	}
	f.created = u
	return nil
}

type fakeConfig struct {
	repository.SystemConfigRepo
	value string
	err   error
}

func (f fakeConfig) Get(context.Context, string) (string, error) { return f.value, f.err }

func newAuthRouter(users *fakeUsers, cfg fakeConfig, opts AuthOptions) http.Handler {
	r := chi.NewRouter()
	h := NewAuthHandler(users, cfg, auth.NewJWTService(strings.Repeat("s", 32), 1), opts)
	h.RegisterPublicRoutes(r)
	return r
}

func post(h http.Handler, path, body string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, path, strings.NewReader(body)))
	return rec
}

const setupBody = `{"email":"admin@example.com","password":"password123"%s}`

func TestSetupRequiresSetupTokenWhenConfigured(t *testing.T) {
	users := &fakeUsers{}
	h := newAuthRouter(users, fakeConfig{value: "false"}, AuthOptions{SetupToken: "s3tup-token"})

	for _, extra := range []string{"", `,"setup_token":"wrong"`} {
		if rec := post(h, "/auth/setup", strings.Replace(setupBody, "%s", extra, 1)); rec.Code != http.StatusForbidden {
			t.Fatalf("token %q: status = %d, want 403", extra, rec.Code)
		}
	}
	if users.created != nil {
		t.Fatal("no user may be created without the setup token")
	}
	rec := post(h, "/auth/setup", strings.Replace(setupBody, "%s", `,"setup_token":"s3tup-token"`, 1))
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%s", rec.Code, rec.Body)
	}
}

func TestSetupFailsClosedWhenStateUnreadable(t *testing.T) {
	users := &fakeUsers{}
	h := newAuthRouter(users, fakeConfig{err: errors.New("db down")}, AuthOptions{})
	if rec := post(h, "/auth/setup", strings.Replace(setupBody, "%s", "", 1)); rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	if users.created != nil {
		t.Fatal("setup must not proceed when its state cannot be read")
	}
}

func TestSetupReturnsConflictWhenAnotherSetupWon(t *testing.T) {
	users := &fakeUsers{createErr: repository.ErrSetupAlreadyCompleted}
	h := newAuthRouter(users, fakeConfig{value: "false"}, AuthOptions{})
	if rec := post(h, "/auth/setup", strings.Replace(setupBody, "%s", "", 1)); rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409", rec.Code)
	}
}

func TestSetupStoresNormalizedEmail(t *testing.T) {
	users := &fakeUsers{}
	h := newAuthRouter(users, fakeConfig{value: "false"}, AuthOptions{})
	rec := post(h, "/auth/setup", `{"email":"  Admin@Example.COM ","password":"password123"}`)
	if rec.Code != http.StatusCreated || users.created == nil || users.created.Email != "admin@example.com" {
		t.Fatalf("status=%d created=%+v", rec.Code, users.created)
	}
}

func TestLoginNormalizesEmail(t *testing.T) {
	u, err := entity.NewUser("admin@example.com", "password123", "Admin", entity.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	users := &fakeUsers{byEmail: map[string]*entity.User{"admin@example.com": u}}
	h := newAuthRouter(users, fakeConfig{value: "true"}, AuthOptions{})
	if rec := post(h, "/auth/login", `{"email":"ADMIN@example.com","password":"password123"}`); rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body)
	}
}

func TestStatusReportsSetupTokenRequirement(t *testing.T) {
	for _, tok := range []string{"", "s3tup-token"} {
		h := newAuthRouter(&fakeUsers{}, fakeConfig{value: "false"}, AuthOptions{SetupToken: tok})
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/auth/status", nil))
		var body struct {
			Data struct {
				SetupTokenRequired bool `json:"setup_token_required"`
			} `json:"data"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		if body.Data.SetupTokenRequired != (tok != "") {
			t.Fatalf("token %q: setup_token_required = %v", tok, body.Data.SetupTokenRequired)
		}
	}
}

func TestLoginRateLimitedAfterRepeatedFailures(t *testing.T) {
	u, err := entity.NewUser("admin@example.com", "password123", "Admin", entity.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	users := &fakeUsers{byEmail: map[string]*entity.User{"admin@example.com": u}}
	h := newAuthRouter(users, fakeConfig{value: "true"}, AuthOptions{Limiter: auth.NewLoginLimiter()})

	for i := 0; i < 5; i++ {
		if rec := post(h, "/auth/login", `{"email":"admin@example.com","password":"wrong-pass"}`); rec.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: status = %d, want 401", i+1, rec.Code)
		}
	}
	rec := post(h, "/auth/login", `{"email":"admin@example.com","password":"password123"}`)
	if rec.Code != http.StatusTooManyRequests || rec.Header().Get("Retry-After") == "" {
		t.Fatalf("status = %d Retry-After=%q, want 429 with Retry-After", rec.Code, rec.Header().Get("Retry-After"))
	}
}

func TestLoginUnknownUserCountsAsFailure(t *testing.T) {
	h := newAuthRouter(&fakeUsers{byEmail: map[string]*entity.User{}}, fakeConfig{value: "true"}, AuthOptions{Limiter: auth.NewLoginLimiter()})
	for i := 0; i < 5; i++ {
		post(h, "/auth/login", `{"email":"ghost@example.com","password":"whatever1"}`)
	}
	if rec := post(h, "/auth/login", `{"email":"ghost@example.com","password":"whatever1"}`); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", rec.Code)
	}
}

func TestLoginSuccessesDoNotExhaustIPLimit(t *testing.T) {
	u, err := entity.NewUser("admin@example.com", "password123", "Admin", entity.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	users := &fakeUsers{byEmail: map[string]*entity.User{"admin@example.com": u}}
	h := newAuthRouter(users, fakeConfig{value: "true"}, AuthOptions{Limiter: auth.NewLoginLimiter()})
	for i := 0; i < 25; i++ {
		if rec := post(h, "/auth/login", `{"email":"admin@example.com","password":"password123"}`); rec.Code != http.StatusOK {
			t.Fatalf("login %d: status = %d, want 200", i+1, rec.Code)
		}
	}
}

func TestLoginConcurrentFailuresCannotBypassLimiter(t *testing.T) {
	u, err := entity.NewUser("admin@example.com", "password123", "Admin", entity.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	users := &fakeUsers{byEmail: map[string]*entity.User{"admin@example.com": u}}
	h := newAuthRouter(users, fakeConfig{value: "true"}, AuthOptions{Limiter: auth.NewLoginLimiter()})

	codes := make([]int, 20)
	var wg sync.WaitGroup
	for i := range codes {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			codes[i] = post(h, "/auth/login", `{"email":"admin@example.com","password":"wrong-pass"}`).Code
		}(i)
	}
	wg.Wait()

	checked := 0
	for _, code := range codes {
		if code == http.StatusUnauthorized {
			checked++
		} else if code != http.StatusTooManyRequests {
			t.Fatalf("unexpected status %d", code)
		}
	}
	if checked != 5 {
		t.Fatalf("%d of 20 concurrent guesses reached the password check, want 5", checked)
	}
}

func TestOversizedBodyReturns413(t *testing.T) {
	h := newAuthRouter(&fakeUsers{}, fakeConfig{value: "false"}, AuthOptions{})
	big := `{"email":"a@example.com","password":"` + strings.Repeat("x", 4096) + `"}`
	for _, path := range []string{"/auth/login", "/auth/setup"} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(big))
		req.Body = http.MaxBytesReader(rec, req.Body, 1024)
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusRequestEntityTooLarge {
			t.Fatalf("%s: status = %d, want 413; body=%s", path, rec.Code, rec.Body)
		}
		if !strings.Contains(rec.Body.String(), "request body too large") {
			t.Fatalf("%s: body = %s", path, rec.Body)
		}
	}
}
