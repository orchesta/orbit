package scan

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/orchesta/orbit/internal/domain/entity"
	"github.com/orchesta/orbit/internal/domain/repository"
	"github.com/orchesta/orbit/internal/engine"
	"github.com/orchesta/orbit/internal/infrastructure/git"
	"github.com/orchesta/orbit/internal/usecase/schedule"
)

// ErrRepositoryNotFound is returned when a scan is requested for an unknown repository.
var ErrRepositoryNotFound = errors.New("repository not found")

// Options tunes how scans run.
type Options struct {
	WorkDir      string        // parent of the per-scan clone directories
	CloneTimeout time.Duration // limit for the clone step; 0 means none
	RetainScans  int           // finished scans kept per repository; 0 keeps all
}

// persistTimeout bounds the final writes made after a scan's context ended.
const persistTimeout = 10 * time.Second

// UseCase handles the core scanning workflow.
type UseCase struct {
	repoRepo    repository.RepositoryRepo
	scanRepo    repository.ScanResultRepo
	depRepo     repository.DependencyRepo
	vulnRepo    repository.VulnerabilityRepo
	engine      *engine.Engine
	gitProvider func(entity.GitProvider) (git.Cloner, error)
	gitHostRepo repository.GitHostRepo
	opts        Options
	logger      *slog.Logger
}

// NewUseCase creates a new scan use case. eng analyzes each clone; the
// server builds it with CheckLatest set and a vulnerability lookup.
func NewUseCase(
	repoRepo repository.RepositoryRepo,
	scanRepo repository.ScanResultRepo,
	depRepo repository.DependencyRepo,
	vulnRepo repository.VulnerabilityRepo,
	eng *engine.Engine,
	gitProvider func(entity.GitProvider) (git.Cloner, error),
	gitHostRepo repository.GitHostRepo,
	opts Options,
	logger *slog.Logger,
) *UseCase {
	return &UseCase{
		repoRepo:    repoRepo,
		scanRepo:    scanRepo,
		depRepo:     depRepo,
		vulnRepo:    vulnRepo,
		engine:      eng,
		gitProvider: gitProvider,
		gitHostRepo: gitHostRepo,
		opts:        opts,
		logger:      logger,
	}
}

// Enqueue queues a scan of the repository. If one is already pending or
// running, that scan is returned and created is false.
func (uc *UseCase) Enqueue(ctx context.Context, repoID uuid.UUID) (*entity.ScanResult, bool, error) {
	repo, err := uc.repoRepo.GetByID(ctx, repoID)
	if err != nil {
		return nil, false, fmt.Errorf("failed to get repository: %w", err)
	}
	if repo == nil {
		return nil, false, ErrRepositoryNotFound
	}
	return uc.scanRepo.Enqueue(ctx, entity.NewScanResult(repoID))
}

// RequestScan queues a scan on behalf of a user or API client. When it queued
// a new scan, the repository's next scheduled run moves to the first run after
// now, so the scheduler does not scan it again right away. The scheduler
// itself uses Enqueue: its claim already advanced next_scan_at.
func (uc *UseCase) RequestScan(ctx context.Context, repoID uuid.UUID) (*entity.ScanResult, bool, error) {
	scan, queued, err := uc.Enqueue(ctx, repoID)
	if err != nil || !queued {
		return scan, queued, err
	}
	repo, err := uc.repoRepo.GetByID(ctx, repoID)
	if err != nil || repo == nil {
		uc.logger.Warn("failed to postpone scheduled scan after a requested scan", slog.String("repository_id", repoID.String()), slog.Any("error", err))
		return scan, queued, nil
	}
	now := time.Now().UTC()
	next, err := schedule.Next(repo.Schedule, now)
	if err != nil || next.IsZero() {
		uc.logger.Warn("repository has an unusable schedule; keeping its next scan", slog.String("repository_id", repoID.String()), slog.Any("error", err))
		return scan, queued, nil
	}
	if err := uc.repoRepo.SetNextScanAt(ctx, repoID, next); err != nil {
		uc.logger.Warn("failed to postpone scheduled scan after a requested scan", slog.String("repository_id", repoID.String()), slog.String("error", err.Error()))
	}
	return scan, queued, nil
}

// Run executes a scan that a worker has claimed (status running). The outcome
// is recorded on scan and persisted, even when ctx ends during the final
// write. If ctx is cancelled mid-scan, Run returns ctx.Err() without
// recording anything, so the caller can requeue or fail the scan.
func (uc *UseCase) Run(ctx context.Context, scan *entity.ScanResult) error {
	repo, err := uc.repoRepo.GetByID(ctx, scan.RepositoryID)
	if err != nil {
		return fmt.Errorf("failed to get repository: %w", err)
	}
	if repo == nil {
		return uc.fail(ctx, scan, "repository no longer exists")
	}

	uc.logger.Info("starting scan", slog.String("repo", repo.Name), slog.String("url", repo.URL))

	// A requeued scan may have saved results before it was interrupted.
	if err := uc.depRepo.DeleteByScanResultID(ctx, scan.ID); err != nil {
		return fmt.Errorf("failed to clear previous results: %w", err)
	}

	if err := os.MkdirAll(uc.opts.WorkDir, 0o755); err != nil {
		return uc.fail(ctx, scan, fmt.Sprintf("failed to prepare work directory: %v", err))
	}
	clonePath, err := os.MkdirTemp(uc.opts.WorkDir, "scan-")
	if err != nil {
		return uc.fail(ctx, scan, fmt.Sprintf("failed to prepare work directory: %v", err))
	}
	defer os.RemoveAll(clonePath)

	cloner, err := uc.gitProvider(repo.Provider)
	if err != nil {
		return uc.fail(ctx, scan, fmt.Sprintf("clone failed: %v", err))
	}
	cloneOpts := git.CloneOptions{
		URL:       repo.URL,
		Branch:    repo.DefaultBranch,
		AuthToken: repo.AuthToken,
		DestPath:  clonePath,
		Depth:     1, // Shallow clone for speed
	}
	if repo.GitHostID != nil {
		host, err := uc.gitHostRepo.GetByID(ctx, *repo.GitHostID)
		if err != nil {
			return fmt.Errorf("failed to get git connection: %w", err)
		}
		if host == nil {
			return uc.fail(ctx, scan, "git connection no longer exists")
		}
		// The token goes to the connection's host only, never AuthToken's
		// provider-keyed path.
		cloneOpts.AuthToken = ""
		if repo.AuthToken != "" {
			cloneOpts.Credential = &git.Credential{HostPort: host.HostPort(), Username: "orbit", Token: repo.AuthToken}
		}
	}

	cloneCtx, cancelClone := ctx, context.CancelFunc(func() {})
	if uc.opts.CloneTimeout > 0 {
		cloneCtx, cancelClone = context.WithTimeout(ctx, uc.opts.CloneTimeout)
	}
	err = cloner.Clone(cloneCtx, cloneOpts)
	cancelClone()
	if err != nil {
		return uc.fail(ctx, scan, fmt.Sprintf("clone failed: %v", err))
	}

	res, err := uc.engine.WithLogger(uc.logger.With("repo", repo.Name)).Analyze(ctx, clonePath)
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	var vulnErr *engine.VulnCheckError
	if err != nil && !errors.As(err, &vulnErr) {
		return uc.fail(ctx, scan, err.Error())
	}

	// Exploit data is advisory: the scan is saved without it, and only the
	// log says that its KEV or EPSS fields are missing.
	if res.Exploit != nil {
		for _, w := range res.Exploit.Warnings() {
			uc.logger.Warn("exploit data unavailable; the scan is saved without it",
				slog.String("repo", repo.Name), slog.String("detail", w))
		}
	}

	// Licenses are advisory too: a failed deps.dev lookup leaves those
	// licenses unknown, and only the log says so.
	if res.LicenseLookupFailed > 0 {
		uc.logger.Warn("license lookup on deps.dev failed; the scan is saved with those licenses unknown",
			slog.String("repo", repo.Name), slog.Int("failed", res.LicenseLookupFailed),
			slog.Any("error", res.LicenseLookupErr))
	}

	for _, dep := range res.Dependencies {
		dep.RepositoryID = scan.RepositoryID
		dep.ScanResultID = scan.ID
	}
	if len(res.Dependencies) > 0 {
		if err := uc.depRepo.CreateBatch(ctx, res.Dependencies); err != nil {
			uc.logger.Error("failed to save dependencies", slog.String("error", err.Error()))
			return uc.fail(ctx, scan, fmt.Sprintf("failed to save dependencies: %v", err))
		}
	}

	// A failed vulnerability check must not be recorded as "0
	// vulnerabilities", so the scan is marked failed while keeping the
	// dependency results. fail logs the cause; the engine does not.
	if vulnErr != nil {
		return uc.failIncomplete(ctx, scan, res, vulnErr.Err.Error())
	}
	if len(res.Vulnerabilities) > 0 {
		if err := uc.vulnRepo.CreateBatch(ctx, res.Vulnerabilities); err != nil {
			uc.logger.Error("failed to save vulnerabilities", slog.String("repo", repo.Name), slog.String("error", err.Error()))
			return uc.failIncomplete(ctx, scan, res, fmt.Sprintf("failed to save vulnerabilities: %v", err))
		}
	}

	scan.Complete(len(res.Dependencies), res.OutdatedDeps, res.VulnerableDeps, len(res.Vulnerabilities))
	if err := uc.complete(ctx, scan); err != nil {
		return err
	}

	uc.logger.Info("scan completed",
		slog.String("repo", repo.Name),
		slog.Int("total_deps", scan.TotalDeps),
		slog.Int("outdated", scan.OutdatedDeps),
		slog.Int("vulnerable", scan.VulnerableDeps),
		slog.Duration("duration", scan.Duration),
	)

	return nil
}

// failIncomplete fails a scan whose dependencies were saved but whose
// vulnerability results are missing, keeping the dependency counts.
func (uc *UseCase) failIncomplete(ctx context.Context, scan *entity.ScanResult, res *engine.Result, cause string) error {
	scan.TotalDeps = len(res.Dependencies)
	scan.OutdatedDeps = res.OutdatedDeps
	return uc.fail(ctx, scan, "vulnerability check failed, results are incomplete: "+cause)
}

// fail records scan as failed with msg, unless ctx has ended: then the scan
// was interrupted, not broken, and the caller decides what happens to it.
func (uc *UseCase) fail(ctx context.Context, scan *entity.ScanResult, msg string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	scan.Fail(msg)
	uc.logger.Warn("scan failed", slog.String("scan_id", scan.ID.String()), slog.String("error", msg))
	if err := uc.persist(ctx, scan); err != nil {
		return err
	}
	wctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), persistTimeout)
	defer cancel()
	uc.pruneHistory(wctx, scan.RepositoryID)
	return nil
}

// complete persists a finished scan, stamps the repository and prunes history.
func (uc *UseCase) complete(ctx context.Context, scan *entity.ScanResult) error {
	if err := uc.persist(ctx, scan); err != nil {
		return err
	}
	wctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), persistTimeout)
	defer cancel()
	if err := uc.repoRepo.MarkScanned(wctx, scan.RepositoryID, time.Now().UTC()); err != nil {
		uc.logger.Error("failed to record last scan time", slog.String("scan_id", scan.ID.String()), slog.String("error", err.Error()))
	}
	uc.pruneHistory(wctx, scan.RepositoryID)
	return nil
}

// pruneHistory drops the repository's oldest finished scans beyond
// RetainScans. A failure is logged, never returned: the scan itself is saved.
func (uc *UseCase) pruneHistory(ctx context.Context, repoID uuid.UUID) {
	if uc.opts.RetainScans <= 0 {
		return
	}
	if _, err := uc.scanRepo.PruneHistory(ctx, repoID, uc.opts.RetainScans); err != nil {
		uc.logger.Error("failed to prune scan history", slog.String("repository_id", repoID.String()), slog.String("error", err.Error()))
	}
}

// persist writes scan's state with a context that outlives ctx, so a scan
// finishing during shutdown is not left "running".
func (uc *UseCase) persist(ctx context.Context, scan *entity.ScanResult) error {
	wctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), persistTimeout)
	defer cancel()
	if err := uc.scanRepo.Update(wctx, scan); err != nil {
		return fmt.Errorf("failed to update scan result: %w", err)
	}
	return nil
}

// GetScanHistory retrieves the scan history for a repository.
func (uc *UseCase) GetScanHistory(ctx context.Context, repoID uuid.UUID, limit int) ([]*entity.ScanResult, error) {
	if limit <= 0 {
		limit = 20
	}
	return uc.scanRepo.GetByRepositoryID(ctx, repoID, limit)
}

// GetScanResult retrieves a single scan result with its dependencies.
func (uc *UseCase) GetScanResult(ctx context.Context, scanID uuid.UUID) (*entity.ScanResult, error) {
	return uc.scanRepo.GetByID(ctx, scanID)
}

// GetScanDependencies retrieves all dependencies for a scan.
func (uc *UseCase) GetScanDependencies(ctx context.Context, scanID uuid.UUID) ([]*entity.Dependency, error) {
	return uc.depRepo.GetByScanResultID(ctx, scanID)
}
