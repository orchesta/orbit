package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/orchesta/orbit/internal/adapter/handler"
	"github.com/orchesta/orbit/internal/adapter/persistence/postgres"
	"github.com/orchesta/orbit/internal/buildinfo"
	"github.com/orchesta/orbit/internal/engine"
	"github.com/orchesta/orbit/internal/infrastructure/analyzer"
	"github.com/orchesta/orbit/internal/infrastructure/analyzer/golang"
	"github.com/orchesta/orbit/internal/infrastructure/analyzer/npm"
	"github.com/orchesta/orbit/internal/infrastructure/analyzer/nuget"
	"github.com/orchesta/orbit/internal/infrastructure/analyzer/pip"
	"github.com/orchesta/orbit/internal/infrastructure/auth"
	"github.com/orchesta/orbit/internal/infrastructure/config"
	"github.com/orchesta/orbit/internal/infrastructure/crypto"
	"github.com/orchesta/orbit/internal/infrastructure/exploit"
	"github.com/orchesta/orbit/internal/infrastructure/git/azuredevops"
	"github.com/orchesta/orbit/internal/infrastructure/git/github"
	"github.com/orchesta/orbit/internal/infrastructure/git/gitlab"
	"github.com/orchesta/orbit/internal/infrastructure/server"
	"github.com/orchesta/orbit/internal/infrastructure/vulnerability/osv"
	"github.com/orchesta/orbit/internal/usecase/repo"
	"github.com/orchesta/orbit/internal/usecase/scan"
	vulnuc "github.com/orchesta/orbit/internal/usecase/vulnerability"
)

func main() {
	os.Exit(dispatch(os.Args[1:], os.Stdout, os.Stderr, commands{
		serve: func() int {
			runServer() // exits the process itself on a fatal error
			return 0
		},
		scan: func(args []string, stdout, stderr io.Writer) int {
			// Ctrl-C or SIGTERM cancels the scan, which then exits 2. After
			// the first signal the default handling is restored, so a second
			// Ctrl-C ends the process at once.
			ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
			defer stop()
			go func() {
				<-ctx.Done()
				stop()
			}()
			return runScan(ctx, args, stdout, stderr, defaultScanDeps())
		},
	}))
}

// commands are the subcommands dispatch can run; tests replace them.
type commands struct {
	serve func() int
	scan  func(args []string, stdout, stderr io.Writer) int
}

const usage = `Usage:
  orbit [serve]        run the Orbit server (the default)
  orbit scan [flags]   scan a checked-out directory, for CI builds
                       (orbit scan -h lists the flags)
  orbit version        print the version
`

// dispatch picks the subcommand from args (os.Args without the program
// name) and returns the process exit code.
func dispatch(args []string, stdout, stderr io.Writer, cmds commands) int {
	if len(args) == 0 {
		return cmds.serve()
	}
	switch args[0] {
	case "serve":
		return cmds.serve()
	case "scan":
		return cmds.scan(args[1:], stdout, stderr)
	case "version":
		fmt.Fprintf(stdout, "orbit %s\n", buildinfo.Version)
		return 0
	case "help", "-h", "-help", "--help":
		fmt.Fprint(stdout, usage)
		return 0
	default:
		fmt.Fprintf(stderr, "orbit: unknown command %q\n\n%s", args[0], usage)
		return 2
	}
}

// newAnalyzerRegistry registers every supported ecosystem's analyzer.
func newAnalyzerRegistry() *analyzer.Registry {
	registry := analyzer.NewRegistry()
	registry.Register(npm.NewAnalyzer())
	registry.Register(pip.NewAnalyzer())
	registry.Register(nuget.NewAnalyzer())
	registry.Register(golang.NewAnalyzer())
	return registry
}

// runServer runs the Orbit server until SIGINT or SIGTERM.
func runServer() {
	// Initialize logger
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	slog.SetDefault(logger)

	logger.Info("starting orbit server")

	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		logger.Error("failed to load configuration", slog.String("error", err.Error()))
		os.Exit(1)
	}

	// Connect to database
	pool, err := postgres.NewConnection(cfg.Database)
	if err != nil {
		logger.Error("failed to connect to database", slog.String("error", err.Error()))
		os.Exit(1)
	}
	defer pool.Close()
	logger.Info("connected to PostgreSQL")

	// Run database migrations
	if err := postgres.RunMigrations(cfg.Database, logger); err != nil {
		logger.Error("failed to run migrations", slog.String("error", err.Error()))
		os.Exit(1)
	}

	// Encrypt access tokens at rest
	secrets, err := crypto.NewEncryptor(cfg.Crypto.EncryptionKey)
	if err != nil {
		logger.Error("invalid encryption key", slog.String("error", err.Error()))
		os.Exit(1)
	}
	sealed, err := postgres.SealPlaintextSecrets(context.Background(), pool, secrets)
	if err != nil {
		logger.Error("failed to check or encrypt stored access tokens", slog.String("error", err.Error()))
		os.Exit(1)
	}
	if sealed > 0 {
		logger.Info("encrypted stored access tokens", slog.Int("count", sealed))
	}

	// Initialize repositories (adapter layer)
	repoRepo := postgres.NewRepositoryPostgresRepo(pool, secrets)
	scanRepo := postgres.NewScanResultPostgresRepo(pool)
	depRepo := postgres.NewDependencyPostgresRepo(pool)
	vulnRepo := postgres.NewVulnerabilityPostgresRepo(pool)
	userRepo := postgres.NewUserPostgresRepo(pool)
	configRepo := postgres.NewSystemConfigPostgresRepo(pool)
	gitHostRepo := postgres.NewGitHostPostgresRepo(pool)

	// Initialize JWT service
	jwtService := auth.NewJWTService(cfg.Auth.JWTSecret, 24) // 24 hour tokens

	// Initialize Git providers
	githubClient := github.NewClient()
	gitlabClient := gitlab.NewClient()
	azureClient := azuredevops.NewClient()

	gitProviderFactory := newClonerFactory(githubClient, gitlabClient)

	// Initialize analyzer registry
	registry := newAnalyzerRegistry()
	logger.Info("analyzer registry initialized", slog.Int("analyzers", len(registry.GetAll())))

	// Initialize osv.dev client
	osvClient := osv.NewClient()
	osvClient.Logger = logger

	// Initialize use cases
	repoUseCase := repo.NewUseCase(repoRepo, gitHostRepo)
	engineOpts := engine.Options{CheckLatest: true, Logger: logger}
	if cfg.Exploit.Enabled {
		// One enricher for every scan: the KEV catalog is downloaded once and
		// refreshed every 12 hours, EPSS scores are cached for 12 hours.
		engineOpts.Exploit = exploit.NewEnricher(exploit.Config{KEVURL: cfg.Exploit.KEVURL, EPSSURL: cfg.Exploit.EPSSURL, Logger: logger})
	} else {
		logger.Info("exploit data (CISA KEV, FIRST EPSS) is disabled")
	}
	scanEngine := engine.New(registry, vulnuc.NewLookup(osvClient, logger), engineOpts)
	scanUseCase := scan.NewUseCase(
		repoRepo, scanRepo, depRepo, vulnRepo, scanEngine,
		gitProviderFactory, gitHostRepo,
		scan.Options{
			WorkDir:      cfg.Scanner.WorkDir,
			CloneTimeout: time.Duration(cfg.Scanner.CloneTimeout) * time.Second,
			RetainScans:  cfg.Scanner.RetainScans,
		},
		logger,
	)

	// Initialize handlers
	tokenRepo := postgres.NewAccessTokenPostgresRepo(pool, secrets)
	repoHandler := handler.NewRepoHandler(repoUseCase, githubClient, gitlabClient, azureClient, tokenRepo, gitHostRepo)
	scanHandler := handler.NewScanHandler(scanUseCase)
	vulnHandler := handler.NewVulnHandler(vulnRepo, depRepo)
	authHandler := handler.NewAuthHandler(userRepo, configRepo, jwtService, handler.AuthOptions{
		SetupToken: cfg.Auth.SetupToken,
		Limiter:    auth.NewLoginLimiter(),
	})
	dashboardHandler := handler.NewDashboardHandler(pool)
	tokenHandler := handler.NewTokenHandler(tokenRepo, gitHostRepo)
	gitHostHandler := handler.NewGitHostHandler(gitHostRepo)

	// Setup router
	handlers := server.Handlers{
		Repo:      repoHandler,
		Scan:      scanHandler,
		Vuln:      vulnHandler,
		Auth:      authHandler,
		Dashboard: dashboardHandler,
		Token:     tokenHandler,
		GitHost:   gitHostHandler,
	}
	router := server.NewRouter(handlers, jwtService, userRepo, logger, server.RouterOptions{
		TrustProxyHeaders:  cfg.Server.TrustProxyHeaders,
		CORSAllowedOrigins: cfg.Server.CORSAllowedOrigins,
	})

	// Background scanning: a bounded worker pool runs queued scans and the
	// scheduler queues repositories whose schedule is due.
	workerPool := scan.NewWorkerPool(scanRepo, scanUseCase, scan.WorkerPoolConfig{
		Workers:           cfg.Scanner.MaxConcurrentScans,
		PollInterval:      2 * time.Second,
		HeartbeatInterval: 30 * time.Second,
		ScanTimeout:       time.Duration(cfg.Scanner.ScanTimeout) * time.Second,
	}, logger)
	scanScheduler := scan.NewScheduler(repoRepo, scanRepo, scanUseCase, scan.SchedulerConfig{
		Interval:    30 * time.Second,
		BatchSize:   100,
		StaleAfter:  2 * time.Minute,
		MaxAttempts: 3,
	}, logger)

	workersCtx, stopWorkers := context.WithCancel(context.Background())
	workersDone := make(chan struct{})
	go func() {
		workerPool.Run(workersCtx)
		close(workersDone)
	}()
	schedulerCtx, stopScheduler := context.WithCancel(context.Background())
	schedulerDone := make(chan struct{})
	go func() {
		scanScheduler.Run(schedulerCtx)
		close(schedulerDone)
	}()

	// Create HTTP server
	srv := &http.Server{
		Addr:         cfg.Server.Address(),
		Handler:      router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	signalCtx, stopSignals := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stopSignals()

	serverErr := make(chan error, 1)
	go func() {
		logger.Info("HTTP server listening", slog.String("address", cfg.Server.Address()))
		serverErr <- srv.ListenAndServe()
	}()

	exitCode := 0
	select {
	case <-signalCtx.Done():
		logger.Info("shutting down...")
	case err := <-serverErr:
		if !errors.Is(err, http.ErrServerClosed) {
			logger.Error("server error", slog.String("error", err.Error()))
			exitCode = 1
		}
	}
	// Restore default signal handling so a second Ctrl-C ends the process
	// at once instead of waiting for the graceful shutdown below.
	stopSignals()

	// Stop taking requests, then stop queueing, then hand running scans back
	// to the queue, all within the shutdown timeout.
	shutdownCtx, cancelShutdown := context.WithTimeout(context.Background(), time.Duration(cfg.Server.ShutdownTimeout)*time.Second)
	defer cancelShutdown()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		logger.Error("server forced to shutdown", slog.String("error", err.Error()))
	}
	stopScheduler()
	select {
	case <-schedulerDone:
	case <-shutdownCtx.Done():
		logger.Error("scan scheduler did not stop in time")
	}
	stopWorkers()
	select {
	case <-workersDone:
	case <-shutdownCtx.Done():
		logger.Error("scan workers did not stop in time; their scans will be recovered on the next start")
	}

	if exitCode != 0 {
		logger.Error("server stopped after an error")
		// os.Exit skips deferred calls, so release resources first.
		cancelShutdown()
		pool.Close()
		os.Exit(exitCode)
	}
	logger.Info("server stopped gracefully")
}
