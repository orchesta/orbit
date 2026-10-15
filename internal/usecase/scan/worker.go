package scan

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/orchesta/orbit/internal/domain/entity"
	"github.com/orchesta/orbit/internal/domain/repository"
)

// ScanQueue is the part of scan persistence the worker pool needs.
type ScanQueue interface {
	ClaimNext(ctx context.Context) (*entity.ScanResult, error)
	Heartbeat(ctx context.Context, id uuid.UUID, attempt int) error
	Requeue(ctx context.Context, id uuid.UUID, attempt int) error
	Update(ctx context.Context, scan *entity.ScanResult) error
}

// ScanRunner executes one claimed scan.
type ScanRunner interface {
	Run(ctx context.Context, scan *entity.ScanResult) error
}

// WorkerPoolConfig tunes the worker pool.
type WorkerPoolConfig struct {
	Workers           int           // scans that may run at once
	PollInterval      time.Duration // wait between queue checks while idle
	HeartbeatInterval time.Duration // how often a running scan proves it is alive
	ScanTimeout       time.Duration // limit for one whole scan
}

// WorkerPool runs queued scans with bounded concurrency.
type WorkerPool struct {
	queue  ScanQueue
	runner ScanRunner
	cfg    WorkerPoolConfig
	logger *slog.Logger
}

// NewWorkerPool creates a worker pool.
func NewWorkerPool(queue ScanQueue, runner ScanRunner, cfg WorkerPoolConfig, logger *slog.Logger) *WorkerPool {
	return &WorkerPool{queue: queue, runner: runner, cfg: cfg, logger: logger}
}

// Run starts the workers and blocks until ctx is cancelled and every worker
// has stopped. Scans interrupted by the cancellation go back to the queue.
func (p *WorkerPool) Run(ctx context.Context) {
	var wg sync.WaitGroup
	for i := 0; i < p.cfg.Workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			p.work(ctx)
		}()
	}
	wg.Wait()
}

func (p *WorkerPool) work(ctx context.Context) {
	for ctx.Err() == nil {
		scan, err := p.queue.ClaimNext(ctx)
		if err != nil && ctx.Err() == nil {
			p.logger.Error("failed to claim scan", slog.String("error", err.Error()))
		}
		if scan == nil {
			select {
			case <-ctx.Done():
				return
			case <-time.After(p.cfg.PollInterval):
			}
			continue
		}
		p.process(ctx, scan)
	}
}

func (p *WorkerPool) process(ctx context.Context, scan *entity.ScanResult) {
	jobCtx, cancel := context.WithTimeout(ctx, p.cfg.ScanTimeout)
	defer cancel()
	var lost atomic.Bool
	stopHeartbeat := p.heartbeat(jobCtx, scan, func() { lost.Store(true); cancel() })
	err := p.runSafely(jobCtx, scan)
	stopHeartbeat()

	// A lost heartbeat only matters if it stopped the scan: a scan that
	// still finished and was recorded is left as it is.
	if errors.Is(err, repository.ErrScanNotOwned) || (lost.Load() && err != nil) {
		// Another worker reclaimed this scan; it now owns every write.
		p.logger.Warn("scan was reclaimed by another worker; abandoning it", slog.String("scan_id", scan.ID.String()))
		return
	}
	if scan.Status != entity.ScanStatusRunning {
		if err != nil {
			p.logger.Error("scan finished with an error", slog.String("scan_id", scan.ID.String()), slog.String("error", err.Error()))
		}
		return
	}
	switch {
	case ctx.Err() != nil:
		// Shutting down: hand the scan back so the next start picks it up.
		p.withTimeout(func(wctx context.Context) error { return p.queue.Requeue(wctx, scan.ID, scan.Attempt) }, scan, "requeue")
	case errors.Is(jobCtx.Err(), context.DeadlineExceeded):
		scan.Fail(fmt.Sprintf("scan timed out after %s", p.cfg.ScanTimeout))
		p.withTimeout(func(wctx context.Context) error { return p.queue.Update(wctx, scan) }, scan, "record timeout")
	case err != nil:
		scan.Fail("internal error: " + err.Error())
		p.withTimeout(func(wctx context.Context) error { return p.queue.Update(wctx, scan) }, scan, "record failure")
	}
}

// runSafely turns a panic into an error so one bad repository cannot take
// the process down.
func (p *WorkerPool) runSafely(ctx context.Context, scan *entity.ScanResult) (err error) {
	defer func() {
		if r := recover(); r != nil {
			p.logger.Error("scan panicked", slog.String("scan_id", scan.ID.String()), slog.Any("panic", r), slog.String("stack", string(debug.Stack())))
			err = fmt.Errorf("scan panicked: %v", r)
		}
	}()
	return p.runner.Run(ctx, scan)
}

// heartbeat proves liveness every HeartbeatInterval until stop is called.
// If the queue reports that the scan now belongs to another worker, onLost
// is called once and heartbeating stops.
func (p *WorkerPool) heartbeat(ctx context.Context, scan *entity.ScanResult, onLost func()) (stop func()) {
	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(p.cfg.HeartbeatInterval)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ctx.Done():
				return
			case <-ticker.C:
				err := p.queue.Heartbeat(ctx, scan.ID, scan.Attempt)
				if errors.Is(err, repository.ErrScanNotOwned) {
					onLost()
					return
				}
				if err != nil && ctx.Err() == nil {
					p.logger.Warn("scan heartbeat failed", slog.String("scan_id", scan.ID.String()), slog.String("error", err.Error()))
				}
			}
		}
	}()
	return func() { close(done); wg.Wait() }
}

// withTimeout runs a final bookkeeping write that must happen even during shutdown.
func (p *WorkerPool) withTimeout(write func(context.Context) error, scan *entity.ScanResult, what string) {
	wctx, cancel := context.WithTimeout(context.Background(), persistTimeout)
	defer cancel()
	if err := write(wctx); err != nil {
		p.logger.Error("failed to "+what+" scan", slog.String("scan_id", scan.ID.String()), slog.String("error", err.Error()))
	}
}
