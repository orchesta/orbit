package handler

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"math"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/orchesta/orbit/internal/domain/entity"
	"github.com/orchesta/orbit/internal/domain/repository"
	"github.com/orchesta/orbit/internal/infrastructure/auth"
)

// AuthOptions configures optional authentication behaviour.
type AuthOptions struct {
	// SetupToken, when set, must be presented to create the first admin, so a
	// freshly deployed instance cannot be claimed by whoever reaches it first.
	SetupToken string
	// Limiter, when set, throttles repeated failed logins. Every attempt is
	// counted before the password check; a successful login takes it back.
	Limiter *auth.LoginLimiter
}

// normalizeEmail makes email lookups case- and whitespace-insensitive.
func normalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

// clientIP returns the request's client address without the port. Behind a
// proxy it is only the real client when RealIP middleware is enabled.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// AuthHandler handles authentication and setup endpoints.
type AuthHandler struct {
	userRepo   repository.UserRepo
	configRepo repository.SystemConfigRepo
	jwtService *auth.JWTService
	opts       AuthOptions
}

// NewAuthHandler creates a new AuthHandler.
func NewAuthHandler(userRepo repository.UserRepo, configRepo repository.SystemConfigRepo, jwtService *auth.JWTService, opts AuthOptions) *AuthHandler {
	return &AuthHandler{
		userRepo:   userRepo,
		configRepo: configRepo,
		jwtService: jwtService,
		opts:       opts,
	}
}

// RegisterPublicRoutes registers routes that don't require authentication.
func (h *AuthHandler) RegisterPublicRoutes(r chi.Router) {
	r.Post("/auth/login", h.Login)
	r.Post("/auth/setup", h.Setup)
	r.Get("/auth/status", h.Status)
}

// RegisterProtectedRoutes registers routes that require authentication.
func (h *AuthHandler) RegisterProtectedRoutes(r chi.Router) {
	r.Get("/auth/me", h.Me)
}

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type loginResponse struct {
	Token string       `json:"token"`
	User  *entity.User `json:"user"`
}

type setupRequest struct {
	Email       string `json:"email"`
	Password    string `json:"password"`
	DisplayName string `json:"display_name"`
	SetupToken  string `json:"setup_token"`
}

type statusResponse struct {
	SetupCompleted     bool `json:"setup_completed"`
	SetupTokenRequired bool `json:"setup_token_required"`
}

// Login handles POST /api/v1/auth/login
func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if !decodeJSON(w, r, &req) {
		return
	}

	email := normalizeEmail(req.Email)
	if email == "" || req.Password == "" {
		RespondError(w, http.StatusBadRequest, "email and password required")
		return
	}

	ip := clientIP(r)
	var attemptAt time.Time
	if h.opts.Limiter != nil {
		at, ok, wait := h.opts.Limiter.Attempt(email, ip)
		attemptAt = at
		if !ok {
			w.Header().Set("Retry-After", strconv.Itoa(int(math.Ceil(wait.Seconds()))))
			RespondError(w, http.StatusTooManyRequests, "too many failed login attempts, try again later")
			return
		}
	}

	user, err := h.userRepo.GetByEmail(r.Context(), email)
	if err != nil {
		RespondServerError(w, r, err)
		return
	}
	if user == nil {
		entity.SimulatePasswordCheck(req.Password)
		RespondError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}

	if !user.CheckPassword(req.Password) {
		RespondError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}

	if !user.IsActive {
		RespondError(w, http.StatusForbidden, "account is disabled")
		return
	}

	if h.opts.Limiter != nil {
		h.opts.Limiter.Success(email, ip, attemptAt)
	}

	token, err := h.jwtService.GenerateToken(user)
	if err != nil {
		RespondServerError(w, r, fmt.Errorf("generate token: %w", err))
		return
	}

	RespondJSON(w, http.StatusOK, loginResponse{Token: token, User: user})
}

// Setup handles POST /api/v1/auth/setup — creates the first admin user.
func (h *AuthHandler) Setup(w http.ResponseWriter, r *http.Request) {
	completed, err := h.configRepo.Get(r.Context(), "setup_completed")
	if err != nil {
		RespondServerError(w, r, err)
		return
	}
	if completed == "true" {
		RespondError(w, http.StatusConflict, "setup already completed")
		return
	}

	var req setupRequest
	if !decodeJSON(w, r, &req) {
		return
	}

	if h.opts.SetupToken != "" && subtle.ConstantTimeCompare([]byte(req.SetupToken), []byte(h.opts.SetupToken)) != 1 {
		RespondError(w, http.StatusForbidden, "invalid setup token")
		return
	}

	email := normalizeEmail(req.Email)
	if email == "" || req.Password == "" {
		RespondError(w, http.StatusBadRequest, "email and password required")
		return
	}

	if len(req.Password) < 8 {
		RespondError(w, http.StatusBadRequest, "password must be at least 8 characters")
		return
	}

	displayName := req.DisplayName
	if displayName == "" {
		displayName = "Admin"
	}

	user, err := entity.NewUser(email, req.Password, displayName, entity.RoleAdmin)
	if err != nil {
		RespondServerError(w, r, fmt.Errorf("create user: %w", err))
		return
	}

	if err := h.userRepo.CreateInitialAdmin(r.Context(), user); err != nil {
		if errors.Is(err, repository.ErrSetupAlreadyCompleted) {
			RespondError(w, http.StatusConflict, "setup already completed")
			return
		}
		RespondServerError(w, r, err)
		return
	}

	token, err := h.jwtService.GenerateToken(user)
	if err != nil {
		RespondServerError(w, r, fmt.Errorf("generate token: %w", err))
		return
	}

	RespondJSON(w, http.StatusCreated, loginResponse{Token: token, User: user})
}

// Status handles GET /api/v1/auth/status
func (h *AuthHandler) Status(w http.ResponseWriter, r *http.Request) {
	completed, err := h.configRepo.Get(r.Context(), "setup_completed")
	if err != nil {
		RespondServerError(w, r, err)
		return
	}
	RespondJSON(w, http.StatusOK, statusResponse{
		SetupCompleted:     completed == "true",
		SetupTokenRequired: h.opts.SetupToken != "",
	})
}

// Me handles GET /api/v1/auth/me
func (h *AuthHandler) Me(w http.ResponseWriter, r *http.Request) {
	user := auth.GetUserFromContext(r.Context())
	if user == nil {
		RespondError(w, http.StatusUnauthorized, "not authenticated")
		return
	}
	RespondJSON(w, http.StatusOK, user)
}
