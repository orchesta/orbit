//go:build integration

package postgres

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/orchesta/orbit/internal/domain/entity"
	"github.com/orchesta/orbit/internal/domain/repository"
)

func newQueueRepo(t *testing.T, ctx context.Context, pool *pgxpool.Pool, name string) uuid.UUID {
	t.Helper()
	r := entity.NewRepository(name, "https://github.com/o/"+name, entity.GitProviderGitHub, "")
	if err := NewRepositoryPostgresRepo(pool, testSealer(t, testKey)).Create(ctx, r, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	return r.ID
}

func TestEnqueueIsIdempotentPerRepository(t *testing.T) {
	ctx := context.Background()
	pool := newTestPool(t)
	scans := NewScanResultPostgresRepo(pool)
	repoID := newQueueRepo(t, ctx, pool, "a")

	first, created, err := scans.Enqueue(ctx, entity.NewScanResult(repoID))
	if err != nil || !created || first.Status != entity.ScanStatusPending {
		t.Fatalf("first enqueue = %+v, %v, %v", first, created, err)
	}
	second, created, err := scans.Enqueue(ctx, entity.NewScanResult(repoID))
	if err != nil || created || second.ID != first.ID {
		t.Fatalf("second enqueue = %+v, %v, %v; want the existing scan", second, created, err)
	}
}

func TestClaimNextHandsEachScanToOneWorker(t *testing.T) {
	ctx := context.Background()
	pool := newTestPool(t)
	scans := NewScanResultPostgresRepo(pool)
	for _, name := range []string{"a", "b"} {
		if _, _, err := scans.Enqueue(ctx, entity.NewScanResult(newQueueRepo(t, ctx, pool, name))); err != nil {
			t.Fatal(err)
		}
	}

	var mu sync.Mutex
	claimed := map[uuid.UUID]int{}
	var wg sync.WaitGroup
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s, err := scans.ClaimNext(ctx)
			if err != nil {
				t.Error(err)
				return
			}
			if s != nil {
				mu.Lock()
				claimed[s.ID]++
				mu.Unlock()
				if s.Status != entity.ScanStatusRunning {
					t.Errorf("claimed scan status = %s", s.Status)
				}
			}
		}()
	}
	wg.Wait()
	if len(claimed) != 2 {
		t.Fatalf("claimed %d distinct scans, want 2", len(claimed))
	}
	for id, n := range claimed {
		if n != 1 {
			t.Fatalf("scan %s claimed %d times", id, n)
		}
	}
	if s, err := scans.ClaimNext(ctx); err != nil || s != nil {
		t.Fatalf("empty queue: %v, %v", s, err)
	}
}

func TestRequeueAndRecoverStale(t *testing.T) {
	ctx := context.Background()
	pool := newTestPool(t)
	scans := NewScanResultPostgresRepo(pool)
	if _, _, err := scans.Enqueue(ctx, entity.NewScanResult(newQueueRepo(t, ctx, pool, "a"))); err != nil {
		t.Fatal(err)
	}
	attempts := func(id uuid.UUID) (n int, status string) {
		if err := pool.QueryRow(ctx, "SELECT attempts, status FROM scan_results WHERE id = $1", id).Scan(&n, &status); err != nil {
			t.Fatal(err)
		}
		return
	}

	s, err := scans.ClaimNext(ctx)
	if err != nil || s == nil {
		t.Fatalf("ClaimNext = %v, %v", s, err)
	}
	if err := scans.Heartbeat(ctx, s.ID, s.Attempt); err != nil {
		t.Fatal(err)
	}
	if err := scans.Requeue(ctx, s.ID, s.Attempt); err != nil {
		t.Fatal(err)
	}
	if n, status := attempts(s.ID); n != 0 || status != "pending" {
		t.Fatalf("after requeue: attempts=%d status=%s; graceful requeue must not use up an attempt", n, status)
	}

	s, err = scans.ClaimNext(ctx)
	if err != nil || s == nil {
		t.Fatalf("ClaimNext = %v, %v", s, err)
	}
	if _, err := pool.Exec(ctx, "UPDATE scan_results SET heartbeat_at = NOW() - INTERVAL '10 minutes' WHERE id = $1", s.ID); err != nil {
		t.Fatal(err)
	}
	requeued, failed, err := scans.RecoverStale(ctx, 2*time.Minute, 3)
	if err != nil || requeued != 1 || failed != 0 {
		t.Fatalf("RecoverStale = %d, %d, %v; want 1 requeued", requeued, failed, err)
	}

	s, err = scans.ClaimNext(ctx)
	if err != nil || s == nil {
		t.Fatalf("ClaimNext = %v, %v", s, err)
	}
	if _, err := pool.Exec(ctx, "UPDATE scan_results SET heartbeat_at = NOW() - INTERVAL '10 minutes', attempts = 3 WHERE id = $1", s.ID); err != nil {
		t.Fatal(err)
	}
	requeued, failed, err = scans.RecoverStale(ctx, 2*time.Minute, 3)
	if err != nil || requeued != 0 || failed != 1 {
		t.Fatalf("RecoverStale = %d, %d, %v; want 1 failed", requeued, failed, err)
	}
	got, err := scans.GetByID(ctx, s.ID)
	if err != nil || got == nil {
		t.Fatalf("GetByID = %v, %v", got, err)
	}
	if got.Status != entity.ScanStatusFailed || got.Error == nil || !strings.Contains(*got.Error, "interrupted") {
		t.Fatalf("stale scan after max attempts = %+v", got)
	}
}

func TestPruneHistoryKeepsNewestAndLatestCompleted(t *testing.T) {
	ctx := context.Background()
	pool := newTestPool(t)
	scans := NewScanResultPostgresRepo(pool)
	repoID := newQueueRepo(t, ctx, pool, "a")
	base := time.Now().Add(-time.Hour)
	insert := func(status string, offset time.Duration) uuid.UUID {
		id := uuid.New()
		if _, err := pool.Exec(ctx, "INSERT INTO scan_results (id, repository_id, status, started_at) VALUES ($1, $2, $3, $4)", id, repoID, status, base.Add(offset)); err != nil {
			t.Fatal(err)
		}
		return id
	}
	completed := insert("completed", 0)
	for i := 1; i <= 4; i++ {
		insert("failed", time.Duration(i)*time.Minute)
	}

	deleted, err := scans.PruneHistory(ctx, repoID, 2)
	if err != nil || deleted != 2 {
		t.Fatalf("PruneHistory = %d, %v; want 2 deleted", deleted, err)
	}
	if got, err := scans.GetByID(ctx, completed); err != nil || got == nil {
		t.Fatal("the latest completed scan must survive pruning")
	}
}

func TestTotalVulnsIsPersisted(t *testing.T) {
	ctx := context.Background()
	pool := newTestPool(t)
	scans := NewScanResultPostgresRepo(pool)
	s := entity.NewScanResult(newQueueRepo(t, ctx, pool, "a"))
	s.Start()
	if err := scans.Create(ctx, s); err != nil {
		t.Fatal(err)
	}
	s.Complete(10, 2, 1, 7)
	if err := scans.Update(ctx, s); err != nil {
		t.Fatal(err)
	}
	got, err := scans.GetByID(ctx, s.ID)
	if err != nil || got.TotalVulns != 7 {
		t.Fatalf("TotalVulns = %+v, %v", got, err)
	}
}

func TestClaimDueRepositoriesAdvancesSchedule(t *testing.T) {
	ctx := context.Background()
	pool := newTestPool(t)
	repos := NewRepositoryPostgresRepo(pool, testSealer(t, testKey))
	due := newQueueRepo(t, ctx, pool, "due")
	inactive := newQueueRepo(t, ctx, pool, "inactive")
	later := newQueueRepo(t, ctx, pool, "later")
	now := time.Now().UTC()
	if _, err := pool.Exec(ctx, "UPDATE repositories SET next_scan_at = $1", now.Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, "UPDATE repositories SET is_active = false WHERE id = $1", inactive); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, "UPDATE repositories SET next_scan_at = $2 WHERE id = $1", later, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}

	next := func(_ string, after time.Time) time.Time { return after.Add(6 * time.Hour) }
	ids, err := repos.ClaimDueRepositories(ctx, now, 100, next)
	if err != nil || len(ids) != 1 || ids[0] != due {
		t.Fatalf("ClaimDueRepositories = %v, %v; want only %s", ids, err, due)
	}
	var nextAt time.Time
	if err := pool.QueryRow(ctx, "SELECT next_scan_at FROM repositories WHERE id = $1", due).Scan(&nextAt); err != nil {
		t.Fatal(err)
	}
	if nextAt.Sub(now.Add(6*time.Hour)).Abs() > time.Second {
		t.Fatalf("next_scan_at = %v, want %v", nextAt, now.Add(6*time.Hour))
	}
	if ids, err := repos.ClaimDueRepositories(ctx, now, 100, next); err != nil || len(ids) != 0 {
		t.Fatalf("second claim = %v, %v; want none", ids, err)
	}
}

func TestRepositoryUpdateSetsNextScanAtInSameStatement(t *testing.T) {
	ctx := context.Background()
	pool := newTestPool(t)
	repos := NewRepositoryPostgresRepo(pool, testSealer(t, testKey))
	id := newQueueRepo(t, ctx, pool, "a")
	original := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	if _, err := pool.Exec(ctx, "UPDATE repositories SET next_scan_at = $2 WHERE id = $1", id, original); err != nil {
		t.Fatal(err)
	}
	nextScanAt := func() time.Time {
		t.Helper()
		var at time.Time
		if err := pool.QueryRow(ctx, "SELECT next_scan_at FROM repositories WHERE id = $1", id).Scan(&at); err != nil {
			t.Fatal(err)
		}
		return at
	}

	r, err := repos.GetByID(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	r.Name = "renamed"
	if err := repos.Update(ctx, r, nil); err != nil {
		t.Fatal(err)
	}
	if got := nextScanAt(); !got.Equal(original) {
		t.Fatalf("next_scan_at = %v after an update without one, want it kept at %v", got, original)
	}

	r.Schedule = "0 3 * * *"
	next := time.Now().UTC().Add(3 * time.Hour).Truncate(time.Second)
	if err := repos.Update(ctx, r, &next); err != nil {
		t.Fatal(err)
	}
	var schedule string
	if err := pool.QueryRow(ctx, "SELECT schedule FROM repositories WHERE id = $1", id).Scan(&schedule); err != nil {
		t.Fatal(err)
	}
	if got := nextScanAt(); schedule != "0 3 * * *" || !got.Equal(next) {
		t.Fatalf("schedule, next_scan_at = %q, %v; want %q, %v", schedule, got, "0 3 * * *", next)
	}
}

func TestMarkScannedTouchesOnlyLastScanned(t *testing.T) {
	ctx := context.Background()
	pool := newTestPool(t)
	repos := NewRepositoryPostgresRepo(pool, testSealer(t, testKey))
	id := newQueueRepo(t, ctx, pool, "a")
	// A user renames and deactivates the repository while a scan runs.
	if _, err := pool.Exec(ctx, "UPDATE repositories SET name = 'renamed', is_active = false WHERE id = $1", id); err != nil {
		t.Fatal(err)
	}
	at := time.Now().UTC().Truncate(time.Second)
	if err := repos.MarkScanned(ctx, id, at); err != nil {
		t.Fatal(err)
	}
	got, err := repos.GetByID(ctx, id)
	if err != nil || got.Name != "renamed" || got.IsActive || got.LastScannedAt == nil || !got.LastScannedAt.Equal(at) {
		t.Fatalf("after MarkScanned: %+v, %v", got, err)
	}
}

func TestStaleWorkerCannotTouchReclaimedScan(t *testing.T) {
	ctx := context.Background()
	pool := newTestPool(t)
	scans := NewScanResultPostgresRepo(pool)
	if _, _, err := scans.Enqueue(ctx, entity.NewScanResult(newQueueRepo(t, ctx, pool, "a"))); err != nil {
		t.Fatal(err)
	}
	a, err := scans.ClaimNext(ctx)
	if err != nil || a == nil {
		t.Fatalf("ClaimNext A = %v, %v", a, err)
	}
	if _, err := pool.Exec(ctx, "UPDATE scan_results SET heartbeat_at = NOW() - INTERVAL '10 minutes' WHERE id = $1", a.ID); err != nil {
		t.Fatal(err)
	}
	if requeued, _, err := scans.RecoverStale(ctx, 2*time.Minute, 3); err != nil || requeued != 1 {
		t.Fatalf("RecoverStale requeued=%d err=%v", requeued, err)
	}
	b, err := scans.ClaimNext(ctx)
	if err != nil || b == nil || b.ID != a.ID || b.Attempt != a.Attempt+1 {
		t.Fatalf("ClaimNext B = %+v, %v; want attempt %d", b, err, a.Attempt+1)
	}

	if err := scans.Heartbeat(ctx, a.ID, a.Attempt); !errors.Is(err, repository.ErrScanNotOwned) {
		t.Fatalf("stale Heartbeat = %v", err)
	}
	if err := scans.Requeue(ctx, a.ID, a.Attempt); !errors.Is(err, repository.ErrScanNotOwned) {
		t.Fatalf("stale Requeue = %v", err)
	}
	stale := *a
	stale.Complete(1, 0, 0, 0)
	if err := scans.Update(ctx, &stale); !errors.Is(err, repository.ErrScanNotOwned) {
		t.Fatalf("stale Update = %v", err)
	}
	var status string
	var attempts int
	if err := pool.QueryRow(ctx, "SELECT status, attempts FROM scan_results WHERE id = $1", a.ID).Scan(&status, &attempts); err != nil {
		t.Fatal(err)
	}
	if status != "running" || attempts != b.Attempt {
		t.Fatalf("row = %s/%d, want running/%d", status, attempts, b.Attempt)
	}
	if err := scans.Heartbeat(ctx, b.ID, b.Attempt); err != nil {
		t.Fatalf("owner Heartbeat = %v", err)
	}
}

func TestRecoverStaleTreatsMissingHeartbeatAsStale(t *testing.T) {
	ctx := context.Background()
	pool := newTestPool(t)
	scans := NewScanResultPostgresRepo(pool)
	repoID := newQueueRepo(t, ctx, pool, "a")
	if _, err := pool.Exec(ctx, "INSERT INTO scan_results (id, repository_id, status, started_at) VALUES ($1, $2, 'running', NOW() - INTERVAL '10 minutes')", uuid.New(), repoID); err != nil {
		t.Fatal(err)
	}
	requeued, failed, err := scans.RecoverStale(ctx, 2*time.Minute, 3)
	if err != nil || requeued != 1 || failed != 0 {
		t.Fatalf("RecoverStale = %d, %d, %v; want 1 requeued", requeued, failed, err)
	}
}

func TestLateUpdateCannotFinalizeRequeuedScan(t *testing.T) {
	ctx := context.Background()
	pool := newTestPool(t)
	scans := NewScanResultPostgresRepo(pool)
	if _, _, err := scans.Enqueue(ctx, entity.NewScanResult(newQueueRepo(t, ctx, pool, "a"))); err != nil {
		t.Fatal(err)
	}
	a, err := scans.ClaimNext(ctx)
	if err != nil || a == nil {
		t.Fatalf("ClaimNext A = %v, %v", a, err)
	}
	// A stops heartbeating; recovery puts the scan back in the queue without
	// changing attempts, so the pending row still carries A's attempt.
	if _, err := pool.Exec(ctx, "UPDATE scan_results SET heartbeat_at = NOW() - INTERVAL '10 minutes' WHERE id = $1", a.ID); err != nil {
		t.Fatal(err)
	}
	if requeued, _, err := scans.RecoverStale(ctx, 2*time.Minute, 3); err != nil || requeued != 1 {
		t.Fatalf("RecoverStale requeued=%d err=%v", requeued, err)
	}

	late := *a
	late.Complete(1, 0, 0, 0)
	if err := scans.Update(ctx, &late); !errors.Is(err, repository.ErrScanNotOwned) {
		t.Fatalf("late Update = %v, want ErrScanNotOwned", err)
	}
	var status string
	var attempts int
	if err := pool.QueryRow(ctx, "SELECT status, attempts FROM scan_results WHERE id = $1", a.ID).Scan(&status, &attempts); err != nil {
		t.Fatal(err)
	}
	if status != "pending" || attempts != a.Attempt {
		t.Fatalf("row = %s/%d, want pending/%d", status, attempts, a.Attempt)
	}
}
