package scan

import (
	"context"
	"log/slog"
	"time"

	"github.com/aligoren/orbit/internal/domain/entity"
	"github.com/aligoren/orbit/internal/usecase/schedule"
	"github.com/google/uuid"
)

// DueRepositories hands out repositories whose next scheduled scan is due.
type DueRepositories interface {
	ClaimDueRepositories(ctx context.Context, now time.Time, limit int, next func(expr string, after time.Time) time.Time) ([]uuid.UUID, error)
	SetNextScanAt(ctx context.Context, id uuid.UUID, at time.Time) error
}

// StaleScans recovers scans whose worker stopped.
type StaleScans interface {
	RecoverStale(ctx context.Context, staleAfter time.Duration, maxAttempts int) (int, int, error)
}

// Enqueuer queues a scan for a repository.
type Enqueuer interface {
	Enqueue(ctx context.Context, repoID uuid.UUID) (*entity.ScanResult, bool, error)
}

// SchedulerConfig tunes the scheduler.
type SchedulerConfig struct {
	Interval    time.Duration // time between ticks
	BatchSize   int           // repositories queued per tick at most
	StaleAfter  time.Duration // heartbeat age after which a running scan is stale
	MaxAttempts int           // attempts before a stale scan is failed
}

const (
	// invalidScheduleRetry is how long a repository with an unusable schedule waits.
	invalidScheduleRetry = 24 * time.Hour
	// enqueueRetry is how soon a claimed repository is retried when queueing
	// its scan failed, instead of waiting for its next scheduled run.
	enqueueRetry = time.Minute
	// resetTimeout bounds the reschedule after a failed enqueue.
	resetTimeout = 5 * time.Second
)

// Scheduler queues scans for repositories whose schedule is due. Its state
// lives in the database, so repository changes take effect without
// notification and several replicas can run it at once.
type Scheduler struct {
	repos    DueRepositories
	scans    StaleScans
	enqueuer Enqueuer
	cfg      SchedulerConfig
	logger   *slog.Logger
}

// NewScheduler creates a scheduler.
func NewScheduler(repos DueRepositories, scans StaleScans, enqueuer Enqueuer, cfg SchedulerConfig, logger *slog.Logger) *Scheduler {
	return &Scheduler{repos: repos, scans: scans, enqueuer: enqueuer, cfg: cfg, logger: logger}
}

// Run ticks immediately and then every Interval until ctx is cancelled.
func (s *Scheduler) Run(ctx context.Context) {
	ticker := time.NewTicker(s.cfg.Interval)
	defer ticker.Stop()
	for {
		if err := s.Tick(ctx, time.Now().UTC()); err != nil && ctx.Err() == nil {
			s.logger.Error("scheduler tick failed", slog.String("error", err.Error()))
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// Tick recovers stale scans and queues every repository that is due.
func (s *Scheduler) Tick(ctx context.Context, now time.Time) error {
	requeued, failed, err := s.scans.RecoverStale(ctx, s.cfg.StaleAfter, s.cfg.MaxAttempts)
	if err != nil {
		s.logger.Error("failed to recover stale scans", slog.String("error", err.Error()))
	} else if requeued+failed > 0 {
		s.logger.Warn("recovered stale scans", slog.Int("requeued", requeued), slog.Int("failed", failed))
	}

	ids, err := s.repos.ClaimDueRepositories(ctx, now, s.cfg.BatchSize, s.nextRun)
	if err != nil {
		return err
	}
	// One deadline covers every reschedule of this tick, so a hung database
	// cannot stretch the resets (and a shutdown) to resetTimeout per failure.
	var resetCtx context.Context
	for _, id := range ids {
		if _, _, err := s.enqueuer.Enqueue(ctx, id); err != nil {
			s.logger.Error("failed to queue scheduled scan", slog.String("repository_id", id.String()), slog.String("error", err.Error()))
			if resetCtx == nil {
				var cancel context.CancelFunc
				resetCtx, cancel = context.WithTimeout(context.WithoutCancel(ctx), resetTimeout)
				defer cancel()
			}
			s.retrySoon(resetCtx, id, now)
		}
	}
	return nil
}

// retrySoon brings a claimed repository's next_scan_at forward after its
// enqueue failed: the claim already moved it to the next scheduled run, so
// without this the run would be lost. The enqueue may have failed because ctx
// was cancelled at shutdown, so ctx must be detached from the tick context;
// Tick passes one context with a timeout shared by all resets of the tick.
func (s *Scheduler) retrySoon(ctx context.Context, id uuid.UUID, now time.Time) {
	if err := s.repos.SetNextScanAt(ctx, id, now.Add(enqueueRetry)); err != nil {
		s.logger.Error("failed to reschedule scan after queueing failed", slog.String("repository_id", id.String()), slog.String("error", err.Error()))
	}
}

// nextRun returns the next scheduled run of expr after after. Schedules
// stored before validation enforced MinInterval may fire more often; those
// are clamped to the first run at least MinInterval after after, which keeps
// the cron alignment instead of turning them into a fixed backoff. A valid
// schedule is never clamped, even when after is close to its next run (a new
// repository claimed at 05:50 still runs "0 */6 * * *" at 06:00).
func (s *Scheduler) nextRun(expr string, after time.Time) time.Time {
	next, err := schedule.Next(expr, after)
	if err != nil || next.IsZero() {
		s.logger.Warn("repository has an unusable schedule; retrying later", slog.String("schedule", expr))
		return after.Add(invalidScheduleRetry)
	}
	if next.Sub(after) >= schedule.MinInterval || schedule.Validate(expr) == nil {
		return next
	}
	// Next returns runs strictly after its argument, so subtracting a
	// nanosecond includes a run exactly MinInterval after after.
	clamped, err := schedule.Next(expr, after.Add(schedule.MinInterval-time.Nanosecond))
	if err != nil || clamped.IsZero() {
		s.logger.Warn("repository has an unusable schedule; retrying later", slog.String("schedule", expr))
		return after.Add(invalidScheduleRetry)
	}
	s.logger.Warn("repository schedule runs more often than allowed; delaying its next run",
		slog.String("schedule", expr), slog.Duration("min_interval", schedule.MinInterval), slog.Time("next_scan_at", clamped))
	return clamped
}
