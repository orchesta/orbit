package scan

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/aligoren/orbit/internal/domain/entity"
	"github.com/google/uuid"
)

type fakeDue struct {
	due       []uuid.UUID
	schedules map[uuid.UUID]string
	next      map[uuid.UUID]time.Time
	limit     int
	reset     map[uuid.UUID]time.Time // SetNextScanAt calls
	resetErr  error
	// State of the last SetNextScanAt call's context, taken during the call.
	resetCtxErr      error
	resetHasDeadline bool
	resetDeadlines   []time.Time   // deadline of every SetNextScanAt call's context
	resetDelay       time.Duration // simulated latency of each SetNextScanAt call
}

func (f *fakeDue) SetNextScanAt(ctx context.Context, id uuid.UUID, at time.Time) error {
	if f.reset == nil {
		f.reset = map[uuid.UUID]time.Time{}
	}
	f.reset[id] = at
	f.resetCtxErr = ctx.Err()
	dl, ok := ctx.Deadline()
	f.resetHasDeadline = ok
	f.resetDeadlines = append(f.resetDeadlines, dl)
	time.Sleep(f.resetDelay)
	return f.resetErr
}

func (f *fakeDue) ClaimDueRepositories(_ context.Context, now time.Time, limit int, next func(string, time.Time) time.Time) ([]uuid.UUID, error) {
	f.limit = limit
	f.next = map[uuid.UUID]time.Time{}
	for _, id := range f.due {
		f.next[id] = next(f.schedules[id], now)
	}
	return f.due, nil
}

type fakeStale struct{ calls int }

func (f *fakeStale) RecoverStale(context.Context, time.Duration, int) (int, int, error) {
	f.calls++
	return 0, 0, nil
}

type fakeEnqueuer struct {
	ids  []uuid.UUID
	fail map[uuid.UUID]bool // repositories whose Enqueue fails
}

func (f *fakeEnqueuer) Enqueue(_ context.Context, id uuid.UUID) (*entity.ScanResult, bool, error) {
	f.ids = append(f.ids, id)
	if f.fail[id] {
		return nil, false, errors.New("queue unavailable")
	}
	return entity.NewScanResult(id), true, nil
}

func newTestScheduler(due *fakeDue, stale *fakeStale, enq *fakeEnqueuer) *Scheduler {
	return NewScheduler(due, stale, enq,
		SchedulerConfig{Interval: time.Minute, BatchSize: 100, StaleAfter: 2 * time.Minute, MaxAttempts: 3},
		slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func TestTickEnqueuesDueRepositoriesAndRecoversStaleScans(t *testing.T) {
	a, b := uuid.New(), uuid.New()
	due := &fakeDue{due: []uuid.UUID{a, b}, schedules: map[uuid.UUID]string{a: "0 */6 * * *", b: "30 2 * * *"}}
	stale, enq := &fakeStale{}, &fakeEnqueuer{}
	now := time.Date(2026, 10, 14, 5, 30, 0, 0, time.UTC)

	if err := newTestScheduler(due, stale, enq).Tick(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	if len(enq.ids) != 2 || stale.calls != 1 || due.limit != 100 {
		t.Fatalf("enqueued=%v stale calls=%d limit=%d", enq.ids, stale.calls, due.limit)
	}
	if want := time.Date(2026, 10, 14, 6, 0, 0, 0, time.UTC); !due.next[a].Equal(want) {
		t.Fatalf("next for a = %v, want %v", due.next[a], want)
	}
	if want := time.Date(2026, 10, 15, 2, 30, 0, 0, time.UTC); !due.next[b].Equal(want) {
		t.Fatalf("next for b = %v, want %v", due.next[b], want)
	}
}

func TestTickBacksOffInvalidSchedules(t *testing.T) {
	a := uuid.New()
	due := &fakeDue{due: []uuid.UUID{a}, schedules: map[uuid.UUID]string{a: "every 6h"}}
	now := time.Date(2026, 10, 14, 5, 30, 0, 0, time.UTC)
	if err := newTestScheduler(due, &fakeStale{}, &fakeEnqueuer{}).Tick(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	if want := now.Add(24 * time.Hour); !due.next[a].Equal(want) {
		t.Fatalf("next = %v, want %v", due.next[a], want)
	}
}

func TestTickRetriesSoonWhenEnqueueFails(t *testing.T) {
	failing, ok := uuid.New(), uuid.New()
	due := &fakeDue{due: []uuid.UUID{failing, ok}, schedules: map[uuid.UUID]string{failing: "0 */6 * * *", ok: "0 */6 * * *"}}
	enq := &fakeEnqueuer{fail: map[uuid.UUID]bool{failing: true}}
	now := time.Date(2026, 10, 14, 5, 30, 0, 0, time.UTC)
	if err := newTestScheduler(due, &fakeStale{}, enq).Tick(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	if want := now.Add(time.Minute); len(due.reset) != 1 || !due.reset[failing].Equal(want) {
		t.Fatalf("SetNextScanAt calls = %v, want only %s at %v", due.reset, failing, want)
	}
}

func TestTickResetsScheduleWithLiveContextOnShutdown(t *testing.T) {
	a := uuid.New()
	due := &fakeDue{due: []uuid.UUID{a}, schedules: map[uuid.UUID]string{a: "0 */6 * * *"}}
	enq := &fakeEnqueuer{fail: map[uuid.UUID]bool{a: true}}
	now := time.Date(2026, 10, 14, 5, 30, 0, 0, time.UTC)
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // shutdown: the enqueue fails because the tick context is gone
	if err := newTestScheduler(due, &fakeStale{}, enq).Tick(ctx, now); err != nil {
		t.Fatal(err)
	}
	if want := now.Add(time.Minute); !due.reset[a].Equal(want) {
		t.Fatalf("SetNextScanAt calls = %v, want %s at %v", due.reset, a, want)
	}
	if due.resetCtxErr != nil {
		t.Fatalf("reset ran with a dead context: %v", due.resetCtxErr)
	}
	if !due.resetHasDeadline {
		t.Fatal("reset context must have a timeout")
	}
}

func TestTickDoesNotResetScheduleWhenEnqueueSucceeds(t *testing.T) {
	a := uuid.New()
	due := &fakeDue{due: []uuid.UUID{a}, schedules: map[uuid.UUID]string{a: "0 */6 * * *"}}
	now := time.Date(2026, 10, 14, 5, 30, 0, 0, time.UTC)
	if err := newTestScheduler(due, &fakeStale{}, &fakeEnqueuer{}).Tick(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	if len(due.reset) != 0 {
		t.Fatalf("SetNextScanAt calls = %v, want none", due.reset)
	}
}

func TestTickKeepsGoingWhenRetryResetFails(t *testing.T) {
	a, b := uuid.New(), uuid.New()
	due := &fakeDue{due: []uuid.UUID{a, b}, schedules: map[uuid.UUID]string{a: "0 */6 * * *", b: "0 */6 * * *"}, resetErr: errors.New("db down")}
	enq := &fakeEnqueuer{fail: map[uuid.UUID]bool{a: true}}
	now := time.Date(2026, 10, 14, 5, 30, 0, 0, time.UTC)
	if err := newTestScheduler(due, &fakeStale{}, enq).Tick(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	if len(enq.ids) != 2 {
		t.Fatalf("enqueued = %v, want both repositories tried", enq.ids)
	}
}

func TestNextRunClampsTooFrequentLegacySchedules(t *testing.T) {
	s := newTestScheduler(&fakeDue{}, &fakeStale{}, &fakeEnqueuer{})
	noon := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		expr  string
		after time.Time
		want  time.Time
	}{
		// Stored before the 15-minute validation; must not fire every minute.
		{"* * * * *", noon, time.Date(2026, 10, 14, 12, 15, 0, 0, time.UTC)},
		{"*/5 * * * *", noon, time.Date(2026, 10, 14, 12, 15, 0, 0, time.UTC)},
		// The clamp keeps the cron alignment: the next listed run at or after 12:15.
		{"0,10 * * * *", noon, time.Date(2026, 10, 14, 13, 0, 0, 0, time.UTC)},
		// A sub-second claim time still waits the full minimum interval.
		{"* * * * *", noon.Add(500 * time.Millisecond), time.Date(2026, 10, 14, 12, 16, 0, 0, time.UTC)},
		// Valid schedules are unchanged.
		{"0 */6 * * *", noon, time.Date(2026, 10, 14, 18, 0, 0, 0, time.UTC)},
		{"0 */6 * * *", time.Date(2026, 10, 14, 5, 50, 0, 0, time.UTC), time.Date(2026, 10, 14, 6, 0, 0, 0, time.UTC)},
	} {
		if got := s.nextRun(tc.expr, tc.after); !got.Equal(tc.want) {
			t.Errorf("nextRun(%q, %v) = %v, want %v", tc.expr, tc.after, got, tc.want)
		}
	}
}

func TestTickSharesOneResetDeadlineAcrossFailedEnqueues(t *testing.T) {
	ids := []uuid.UUID{uuid.New(), uuid.New(), uuid.New()}
	due := &fakeDue{due: ids, schedules: map[uuid.UUID]string{}, resetDelay: 2 * time.Millisecond}
	enq := &fakeEnqueuer{fail: map[uuid.UUID]bool{}}
	for _, id := range ids {
		due.schedules[id] = "0 */6 * * *"
		enq.fail[id] = true
	}
	now := time.Date(2026, 10, 14, 5, 30, 0, 0, time.UTC)
	if err := newTestScheduler(due, &fakeStale{}, enq).Tick(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	if len(due.resetDeadlines) != len(ids) {
		t.Fatalf("SetNextScanAt calls = %d, want %d", len(due.resetDeadlines), len(ids))
	}
	for i, dl := range due.resetDeadlines {
		if !dl.Equal(due.resetDeadlines[0]) {
			t.Fatalf("reset %d deadline %v differs from the first %v; all resets must share one budget", i, dl, due.resetDeadlines[0])
		}
	}
}
