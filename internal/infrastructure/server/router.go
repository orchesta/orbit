package server

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/aligoren/orbit/internal/adapter/handler"
	"github.com/aligoren/orbit/internal/domain/repository"
	"github.com/aligoren/orbit/internal/infrastructure/auth"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
)

// Handlers holds all HTTP handlers injected into the server.
type Handlers struct {
	Repo      *handler.RepoHandler
	Scan      *handler.ScanHandler
	Vuln      *handler.VulnHandler
	Auth      *handler.AuthHandler
	Dashboard *handler.DashboardHandler
	Token     *handler.TokenHandler
	GitHost   *handler.GitHostHandler
}

// RouterOptions configures cross-cutting HTTP behaviour.
type RouterOptions struct {
	// TrustProxyHeaders takes the client IP from X-Forwarded-For / X-Real-IP.
	// Enable it only behind a reverse proxy that sets those headers; otherwise
	// clients can spoof their address and dodge per-IP login limits.
	TrustProxyHeaders bool
	// CORSAllowedOrigins lists origins allowed to call the API from a browser.
	// Empty means same-origin only, which is all the bundled UI needs.
	CORSAllowedOrigins []string
}

// NewRouter creates a new Chi router with middleware and routes.
func NewRouter(handlers Handlers, jwtService *auth.JWTService, userRepo repository.UserRepo, logger *slog.Logger, opts RouterOptions) http.Handler {
	r := chi.NewRouter()

	// Middleware
	r.Use(middleware.RequestID)
	if opts.TrustProxyHeaders {
		r.Use(middleware.RealIP)
	}
	r.Use(slogMiddleware(logger))
	r.Use(middleware.Recoverer)
	r.Use(securityHeaders)
	r.Use(middleware.Timeout(60 * time.Second))

	// CORS
	if len(opts.CORSAllowedOrigins) > 0 {
		r.Use(cors.Handler(cors.Options{
			AllowedOrigins:   opts.CORSAllowedOrigins,
			AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
			AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type"},
			AllowCredentials: false,
			MaxAge:           300,
		}))
	}

	// API routes
	r.Route("/api/v1", func(r chi.Router) {
		r.Use(limitRequestBody)
		// Public routes (no auth required)
		r.Get("/health", handlers.Dashboard.HealthCheck)
		handlers.Auth.RegisterPublicRoutes(r)

		// Protected routes (JWT required)
		r.Group(func(r chi.Router) {
			r.Use(jwtService.Middleware(userRepo))
			r.Use(auth.RequireAdminForWrites)
			handlers.Auth.RegisterProtectedRoutes(r)
			handlers.Repo.RegisterRoutes(r)
			handlers.Scan.RegisterRoutes(r)
			handlers.Vuln.RegisterRoutes(r)
			handlers.Token.RegisterRoutes(r)
			handlers.GitHost.RegisterRoutes(r)
			r.Get("/dashboard/stats", handlers.Dashboard.GetStats)
		})
	})

	// Static files (UI)
	fs := http.FileServer(http.Dir("./ui/dist"))
	r.Handle("/*", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// If the request is for a file that doesn't exist, serve index.html (React Router)
		path := r.URL.Path
		if path == "/" || path == "/index.html" {
			fs.ServeHTTP(w, r)
			return
		}

		// Check if file exists
		f, err := http.Dir("./ui/dist").Open(path)
		if err != nil {
			// Serve index.html for SPA routing
			http.ServeFile(w, r, "./ui/dist/index.html")
			return
		}
		f.Close()

		fs.ServeHTTP(w, r)
	}))

	return r
}

// slogMiddleware creates a Chi middleware that logs using slog.
func slogMiddleware(logger *slog.Logger) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
			next.ServeHTTP(ww, r)
			logger.Info("request",
				slog.String("method", r.Method),
				slog.String("path", r.URL.Path),
				slog.Int("status", ww.Status()),
				slog.Duration("duration", time.Since(start)),
				slog.String("remote", r.RemoteAddr),
			)
		})
	}
}
