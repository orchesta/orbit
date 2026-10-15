package auth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/orchesta/orbit/internal/domain/entity"
	"github.com/orchesta/orbit/internal/domain/repository"
)

var testSecret = []byte(strings.Repeat("s", 32))

func sign(t *testing.T, method jwt.SigningMethod, claims Claims) string {
	t.Helper()
	s, err := jwt.NewWithClaims(method, claims).SignedString(testSecret)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func validClaims() Claims {
	return Claims{
		UserID: uuid.NewString(),
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "orbit",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	}
}

func TestValidateTokenAcceptsOwnTokens(t *testing.T) {
	s := NewJWTService(string(testSecret), 1)
	tok, err := s.GenerateToken(&entity.User{ID: uuid.New(), Role: entity.RoleAdmin})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.ValidateToken(tok); err != nil {
		t.Fatal(err)
	}
}

func TestValidateTokenRejectsForeignOrWeakTokens(t *testing.T) {
	s := NewJWTService(string(testSecret), 1)

	wrongIssuer := validClaims()
	wrongIssuer.Issuer = "someone-else"
	noExpiry := validClaims()
	noExpiry.ExpiresAt = nil
	expired := validClaims()
	expired.ExpiresAt = jwt.NewNumericDate(time.Now().Add(-time.Minute))

	cases := map[string]string{
		"wrong issuer": sign(t, jwt.SigningMethodHS256, wrongIssuer),
		"no expiry":    sign(t, jwt.SigningMethodHS256, noExpiry),
		"expired":      sign(t, jwt.SigningMethodHS256, expired),
		"HS512":        sign(t, jwt.SigningMethodHS512, validClaims()),
	}
	for name, tok := range cases {
		if _, err := s.ValidateToken(tok); err == nil {
			t.Errorf("%s: token must be rejected", name)
		}
	}
}

func TestRequireAdminForWrites(t *testing.T) {
	ok := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) })
	h := RequireAdminForWrites(ok)

	tests := []struct {
		method string
		role   entity.Role
		want   int
	}{
		{http.MethodGet, entity.RoleViewer, http.StatusNoContent},
		{http.MethodPost, entity.RoleViewer, http.StatusForbidden},
		{http.MethodDelete, entity.RoleViewer, http.StatusForbidden},
		{http.MethodPost, entity.RoleAdmin, http.StatusNoContent},
		{http.MethodPut, "", http.StatusForbidden},
	}
	for _, tt := range tests {
		req := httptest.NewRequest(tt.method, "/x", nil)
		if tt.role != "" {
			req = req.WithContext(context.WithValue(req.Context(), UserContextKey, &entity.User{Role: tt.role}))
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != tt.want {
			t.Errorf("%s as %q: status = %d, want %d", tt.method, tt.role, rec.Code, tt.want)
		}
	}
}

// fakeUserRepo implements repository.UserRepo for the middleware; only GetByID is used.
type fakeUserRepo struct {
	repository.UserRepo
	user *entity.User
	err  error
}

func (f fakeUserRepo) GetByID(context.Context, uuid.UUID) (*entity.User, error) {
	return f.user, f.err
}

func TestMiddlewareUserLookup(t *testing.T) {
	s := NewJWTService(string(testSecret), 1)
	token := sign(t, jwt.SigningMethodHS256, validClaims())
	tests := []struct {
		name string
		repo fakeUserRepo
		want int
	}{
		{"lookup error is an outage", fakeUserRepo{err: errors.New("connection refused")}, http.StatusServiceUnavailable},
		{"unknown user", fakeUserRepo{}, http.StatusUnauthorized},
		{"inactive user", fakeUserRepo{user: &entity.User{IsActive: false}}, http.StatusUnauthorized},
		{"active user", fakeUserRepo{user: &entity.User{IsActive: true}}, http.StatusNoContent},
	}
	for _, tt := range tests {
		h := s.Middleware(tt.repo)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) }))
		req := httptest.NewRequest(http.MethodGet, "/x", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != tt.want {
			t.Errorf("%s: status = %d, want %d", tt.name, rec.Code, tt.want)
		}
		if tt.want == http.StatusServiceUnavailable && strings.Contains(rec.Body.String(), "connection refused") {
			t.Errorf("%s: error text leaked: %s", tt.name, rec.Body.String())
		}
	}
}
