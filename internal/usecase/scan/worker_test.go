package scan

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/orchesta/orbit/internal/domain/entity"
	"github.com/orchesta/orbit/internal/domain/repository"
)

type fakeQueue struct {
	mu           sync.Mutex
	pending      []*entity.ScanResult
	heartbeats   int
	heartbeatErr error
	requeued     []uuid.UUID
	updated      map[uuid.UUID]entity.ScanResult
}

func newFakeQueue(n int) *fakeQueue {
	q := &fakeQueue{updated: map[uuid.UUID]entity.ScanResult{}}
	for i := 0; i < n; i++ {
		q.pending = append(q.pending, entity.NewScanResult(uuid.New()))
	}
	return q
}

func (q *fakeQueue) ClaimNext(context.Context) (*entity.ScanResult, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.pending) == 0 {
		return nil, nil
	}
	s := q.pending[0]
	q.pending = q.pending[1:]
	s.Start()
	return s, nil
}

func (q *fakeQueue) Heartbeat(context.Context, uuid.UUID, int) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.heartbeats++
	return q.heartbeatErr
}

func (q *fakeQueue) Requeue(_ context.Context, id uuid.UUID, _ int) error {
	q.mu.Lock()
	q.requeued = append(q.requeued, id)
	q.mu.Unlock()
	return nil
}

func (q *fakeQueue) Update(_ context.Context, s *entity.ScanResult) error {
	q.mu.Lock()
	q.updated[s.ID] = *s
	q.mu.Unlock()
	return nil
}

func (q *fakeQueue) snapshot() (pending, updated, requeued, heartbeats int) {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.pending), len(q.updated), len(q.requeued), q.heartbeats
}

type runnerFunc func(ctx context.Context, s *entity.ScanResult) error

func (f runnerFunc) Run(ctx context.Context, s *entity.ScanResult) error { return f(ctx, s) }

func testPoolConfig() WorkerPoolConfig {
	return WorkerPoolConfig{Workers: 3, PollInterval: 5 * time.Millisecond, HeartbeatInterval: 10 * time.Millisecond, ScanTimeout: time.Minute}
}

// startPool runs the pool in the background; stop cancels it and waits.
func startPool(q ScanQueue, r ScanRunner, cfg WorkerPoolConfig) (stop func()) {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		NewWorkerPool(q, r, cfg, slog.New(slog.NewTextHandler(io.Discard, nil))).Run(ctx)
		close(done)
	}()
	return func() { cancel(); <-done }
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not met in time")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestWorkerPoolRunsAtMostNScansAtOnce(t *testing.T) {
	q := newFakeQueue(10)
	var running, peak, done int32
	runner := runnerFunc(func(ctx context.Context, s *entity.ScanResult) error {
		n := atomic.AddInt32(&running, 1)
		for {
			p := atomic.LoadInt32(&peak)
			if n <= p || atomic.CompareAndSwapInt32(&peak, p, n) {
				break
			}
		}
		time.Sleep(20 * time.Millisecond)
		atomic.AddInt32(&running, -1)
		s.Complete(0, 0, 0, 0)
		atomic.AddInt32(&done, 1)
		return nil
	})
	stop := startPool(q, runner, testPoolConfig())
	waitFor(t, func() bool { return atomic.LoadInt32(&done) == 10 })
	stop()
	if peak > 3 {
		t.Fatalf("peak concurrency = %d, want <= 3", peak)
	}
	if peak < 2 {
		t.Fatalf("peak concurrency = %d, want >= 2; workers must run scans in parallel", peak)
	}
}

func TestWorkerPoolRequeuesInterruptedScanOnShutdown(t *testing.T) {
	q := newFakeQueue(1)
	started := make(chan struct{})
	runner := runnerFunc(func(ctx context.Context, s *entity.ScanResult) error {
		close(started)
		<-ctx.Done()
		return ctx.Err()
	})
	stop := startPool(q, runner, testPoolConfig())
	<-started
	stop()
	if _, updated, requeued, _ := q.snapshot(); requeued != 1 || updated != 0 {
		t.Fatalf("requeued=%d updated=%d; an interrupted scan goes back to the queue", requeued, updated)
	}
}

func TestWorkerPoolFailsTimedOutScan(t *testing.T) {
	q := newFakeQueue(1)
	cfg := testPoolConfig()
	cfg.ScanTimeout = 30 * time.Millisecond
	runner := runnerFunc(func(ctx context.Context, s *entity.ScanResult) error {
		<-ctx.Done()
		return ctx.Err()
	})
	stop := startPool(q, runner, cfg)
	waitFor(t, func() bool { _, updated, _, _ := q.snapshot(); return updated == 1 })
	stop()
	for _, s := range q.updated {
		if s.Status != entity.ScanStatusFailed || s.Error == nil || !strings.Contains(*s.Error, "timed out") {
			t.Fatalf("timed out scan = %+v", s)
		}
	}
}

func TestWorkerPoolRecoversFromPanic(t *testing.T) {
	q := newFakeQueue(2)
	var calls int32
	runner := runnerFunc(func(ctx context.Context, s *entity.ScanResult) error {
		if atomic.AddInt32(&calls, 1) == 1 {
			panic("boom")
		}
		s.Complete(0, 0, 0, 0)
		return nil
	})
	cfg := testPoolConfig()
	cfg.Workers = 1
	stop := startPool(q, runner, cfg)
	waitFor(t, func() bool { return atomic.LoadInt32(&calls) == 2 })
	waitFor(t, func() bool { _, updated, _, _ := q.snapshot(); return updated >= 1 })
	stop()
	var panicked bool
	for _, s := range q.updated {
		if s.Status == entity.ScanStatusFailed && s.Error != nil && strings.Contains(*s.Error, "panicked") {
			panicked = true
		}
	}
	if !panicked {
		t.Fatalf("panicking scan must be recorded as failed; updated = %+v", q.updated)
	}
}

func TestWorkerPoolStopsScanWhenOwnershipIsLost(t *testing.T) {
	q := newFakeQueue(1)
	q.heartbeatErr = repository.ErrScanNotOwned
	stopped := make(chan struct{})
	runner := runnerFunc(func(ctx context.Context, s *entity.ScanResult) error {
		<-ctx.Done()
		close(stopped)
		return ctx.Err()
	})
	stop := startPool(q, runner, testPoolConfig())
	select {
	case <-stopped:
	case <-time.After(3 * time.Second):
		t.Fatal("a scan whose ownership was lost must be cancelled")
	}
	stop()
	if _, updated, requeued, _ := q.snapshot(); updated != 0 || requeued != 0 {
		t.Fatalf("updated=%d requeued=%d; a worker that lost the scan must not write it", updated, requeued)
	}
}

func TestWorkerPoolIgnoresLostHeartbeatAfterSuccess(t *testing.T) {
	q := newFakeQueue(1)
	q.heartbeatErr = repository.ErrScanNotOwned
	cfg := testPoolConfig()
	cfg.HeartbeatInterval = 5 * time.Millisecond
	logs := &lockedBuffer{}
	var finished atomic.Pointer[entity.ScanResult]
	runner := runnerFunc(func(ctx context.Context, s *entity.ScanResult) error {
		time.Sleep(30 * time.Millisecond)
		s.Complete(0, 0, 0, 0)
		finished.Store(s)
		return nil
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		NewWorkerPool(q, runner, cfg, slog.New(slog.NewTextHandler(logs, nil))).Run(ctx)
		close(done)
	}()
	waitFor(t, func() bool { return finished.Load() != nil })
	waitFor(t, func() bool { _, _, _, hb := q.snapshot(); return hb >= 1 })
	// Give process() time to act on the finished scan before stopping.
	time.Sleep(20 * time.Millisecond)
	cancel()
	<-done
	if _, updated, requeued, _ := q.snapshot(); updated != 0 || requeued != 0 {
		t.Fatalf("updated=%d requeued=%d; the pool must not write a scan the runner finished", updated, requeued)
	}
	if s := finished.Load(); s.Status != entity.ScanStatusCompleted {
		t.Fatalf("status = %s, want completed", s.Status)
	}
	if strings.Contains(logs.String(), "reclaimed") {
		t.Fatalf("a scan that finished successfully must not be reported as reclaimed; logs:\n%s", logs.String())
	}
}

// lockedBuffer is a log sink safe for concurrent writers.
type lockedBuffer struct {
	mu sync.Mutex
	b  strings.Builder
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

func TestWorkerPoolSendsHeartbeats(t *testing.T) {
	q := newFakeQueue(1)
	runner := runnerFunc(func(ctx context.Context, s *entity.ScanResult) error {
		time.Sleep(60 * time.Millisecond)
		s.Complete(0, 0, 0, 0)
		return nil
	})
	stop := startPool(q, runner, testPoolConfig())
	waitFor(t, func() bool { _, _, _, hb := q.snapshot(); return hb >= 2 })
	stop()
}
