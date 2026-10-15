package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/aligoren/orbit/internal/domain/entity"
	"github.com/aligoren/orbit/internal/domain/repository"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type contextKey string

const UserContextKey contextKey = "user"

// tokenIssuer is the expected "iss" claim for tokens issued by this service.
const tokenIssuer = "orbit"

// Claims represents JWT claims.
type Claims struct {
	UserID      string      `json:"user_id"`
	Email       string      `json:"email"`
	Role        entity.Role `json:"role"`
	DisplayName string      `json:"display_name"`
	jwt.RegisteredClaims
}

// JWTService handles JWT token operations.
type JWTService struct {
	secret     []byte
	expiration time.Duration
}

// NewJWTService creates a new JWT service.
func NewJWTService(secret string, expirationHours int) *JWTService {
	return &JWTService{
		secret:     []byte(secret),
		expiration: time.Duration(expirationHours) * time.Hour,
	}
}

// GenerateToken creates a new JWT token for a user.
func (s *JWTService) GenerateToken(user *entity.User) (string, error) {
	claims := Claims{
		UserID:      user.ID.String(),
		Email:       user.Email,
		Role:        user.Role,
		DisplayName: user.DisplayName,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(s.expiration)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    tokenIssuer,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(s.secret)
}

// ValidateToken validates and parses a JWT token.
func (s *JWTService) ValidateToken(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		return s.secret, nil
	},
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
		jwt.WithIssuer(tokenIssuer),
		jwt.WithExpirationRequired(),
	)
	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		return claims, nil
	}
	return nil, fmt.Errorf("invalid token")
}

// errorResponse mirrors the handler apiResponse for auth errors.
type errorResponse struct {
	Success bool   `json:"success"`
	Error   string `json:"error,omitempty"`
}

func writeError(w http.ResponseWriter, statusCode int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(errorResponse{Success: false, Error: message})
}

// Middleware returns an HTTP middleware that validates JWT tokens.
func (s *JWTService) Middleware(userRepo repository.UserRepo) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				writeError(w, http.StatusUnauthorized, "authorization header required")
				return
			}

			parts := strings.SplitN(authHeader, " ", 2)
			if len(parts) != 2 || parts[0] != "Bearer" {
				writeError(w, http.StatusUnauthorized, "invalid authorization format")
				return
			}

			claims, err := s.ValidateToken(parts[1])
			if err != nil {
				writeError(w, http.StatusUnauthorized, "invalid or expired token")
				return
			}

			userID, err := uuid.Parse(claims.UserID)
			if err != nil {
				writeError(w, http.StatusUnauthorized, "invalid user id in token")
				return
			}

			user, err := userRepo.GetByID(r.Context(), userID)
			if err != nil {
				// A failed lookup is an outage, not a rejected session: answering
				// 401 would make the UI log the user out.
				slog.ErrorContext(r.Context(), "auth user lookup failed", slog.String("error", err.Error()))
				writeError(w, http.StatusServiceUnavailable, "service unavailable")
				return
			}
			if user == nil || !user.IsActive {
				writeError(w, http.StatusUnauthorized, "user not found or inactive")
				return
			}

			ctx := context.WithValue(r.Context(), UserContextKey, user)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// GetUserFromContext retrieves the authenticated user from the request context.
func GetUserFromContext(ctx context.Context) *entity.User {
	user, _ := ctx.Value(UserContextKey).(*entity.User)
	return user
}

// RequireAdminForWrites lets any authenticated user read but only admins
// change state: requests other than GET, HEAD and OPTIONS need RoleAdmin.
func RequireAdminForWrites(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
			next.ServeHTTP(w, r)
			return
		}
		if user := GetUserFromContext(r.Context()); user == nil || user.Role != entity.RoleAdmin {
			writeError(w, http.StatusForbidden, "admin role required")
			return
		}
		next.ServeHTTP(w, r)
	})
}
