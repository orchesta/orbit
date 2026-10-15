package auth

import (
	"fmt"
	"strconv"
	"sync"
	"testing"
	"time"
)

func newTestLimiter() (*LoginLimiter, *time.Time) {
	now := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
	l := NewLoginLimiter()
	l.now = func() time.Time { return now }
	return l, &now
}

func TestLimiterBlocksEmailAfterFiveAttempts(t *testing.T) {
	l, now := newTestLimiter()
	for i := 0; i < 5; i++ {
		if _, ok, _ := l.Attempt("a@example.com", "10.0.0.1"); !ok {
			t.Fatalf("attempt %d blocked too early", i+1)
		}
	}
	_, ok, wait := l.Attempt("a@example.com", "10.0.0.1")
	if ok || wait != 15*time.Minute {
		t.Fatalf("Attempt = %v, %v; want blocked for 15m", ok, wait)
	}
	*now = now.Add(15*time.Minute + time.Second)
	if _, ok, _ := l.Attempt("a@example.com", "10.0.0.1"); !ok {
		t.Fatal("attempts older than the window must expire")
	}
}

func TestLimiterRefusedAttemptIsNotRecorded(t *testing.T) {
	l, now := newTestLimiter()
	for i := 0; i < 5; i++ {
		l.Attempt("a@example.com", "10.0.0.1")
	}
	*now = now.Add(time.Minute)
	for i := 0; i < 3; i++ {
		if _, ok, _ := l.Attempt("a@example.com", "10.0.0.1"); ok {
			t.Fatal("attempt over the limit must be refused")
		}
	}
	*now = now.Add(14*time.Minute + time.Second)
	if _, ok, _ := l.Attempt("a@example.com", "10.0.0.1"); !ok {
		t.Fatal("refused attempts must not extend the block")
	}
}

func TestLimiterSuccessResetsEmail(t *testing.T) {
	l, _ := newTestLimiter()
	for i := 0; i < 5; i++ {
		l.Attempt("a@example.com", "10.0.0.1")
	}
	at, _, _ := l.Attempt("a@example.com", "10.0.0.1")
	l.Success("a@example.com", "10.0.0.1", at)
	if _, ok, _ := l.Attempt("a@example.com", "10.0.0.1"); !ok {
		t.Fatal("a successful login must reset the email's attempts")
	}
}

func TestLimiterSuccessDoesNotCountTowardIP(t *testing.T) {
	l, _ := newTestLimiter()
	for i := 0; i < 50; i++ {
		email := strconv.Itoa(i) + "@example.com"
		at, ok, _ := l.Attempt(email, "10.0.0.1")
		if !ok {
			t.Fatalf("successful login %d blocked by the IP limit", i+1)
		}
		l.Success(email, "10.0.0.1", at)
	}
}

func TestLimiterCountsIPAcrossEmails(t *testing.T) {
	l, _ := newTestLimiter()
	for i := 0; i < 20; i++ {
		if _, ok, _ := l.Attempt(strconv.Itoa(i)+"@example.com", "10.0.0.1"); !ok {
			t.Fatalf("attempt %d blocked too early", i+1)
		}
	}
	if _, ok, _ := l.Attempt("fresh@example.com", "10.0.0.1"); ok {
		t.Fatal("20 attempts from one IP must block that IP for any email")
	}
	if _, ok, _ := l.Attempt("fresh@example.com", "10.0.0.2"); !ok {
		t.Fatal("another IP must not be affected")
	}
}

func TestLimiterIsolatesEmails(t *testing.T) {
	l, _ := newTestLimiter()
	for i := 0; i < 5; i++ {
		l.Attempt("a@example.com", "10.0.0.1")
	}
	if _, ok, _ := l.Attempt("b@example.com", "10.0.0.2"); !ok {
		t.Fatal("a different email from a different IP must not be blocked")
	}
}

func TestLimiterAttemptIsAtomic(t *testing.T) {
	l, _ := newTestLimiter()
	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		allowed int
	)
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, ok, _ := l.Attempt("a@example.com", "10.0.0.1"); ok {
				mu.Lock()
				allowed++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if allowed != 5 {
		t.Fatalf("%d concurrent attempts allowed, want exactly 5", allowed)
	}
}

func TestLimiterSuccessOnlyRemovesItsOwnAttempt(t *testing.T) {
	l, now := newTestLimiter()
	const ip = "10.0.0.1"
	at, ok, _ := l.Attempt("attacker@example.com", ip) // attacker's own valid login starts
	if !ok {
		t.Fatal("own login blocked")
	}
	*now = now.Add(10 * time.Minute)
	for i := 0; i < 19; i++ { // interleaved password guesses from the same IP
		if _, ok, _ := l.Attempt(fmt.Sprintf("victim%d@example.com", i), ip); !ok {
			t.Fatalf("guess %d blocked too early", i)
		}
		*now = now.Add(time.Second)
	}
	l.Success("attacker@example.com", ip, at) // must remove the login's own entry, not a guess

	// The login's own (oldest) entry is gone; the 19 guesses must still count
	// until they age out, so the 20th failure is allowed and the 21st blocked.
	*now = now.Add(6 * time.Minute) // past the login's original window, inside the guesses'
	if _, ok, _ := l.Attempt("victim-final@example.com", ip); !ok {
		t.Fatal("20th failure blocked too early")
	}
	if _, ok, _ := l.Attempt("another@example.com", ip); ok {
		t.Fatal("20 failed guesses from one IP must block it even when interleaved with a successful login")
	}
}

func TestLimiterBoundsTrackedKeys(t *testing.T) {
	l, _ := newTestLimiter()
	const extra = 100
	// Every key stays active inside the window, so pruning alone frees nothing.
	for i := 0; i < maxTrackedKeys+extra; i++ {
		if _, ok, _ := l.Attempt(strconv.Itoa(i)+"@example.com", "10.0."+strconv.Itoa(i%1000)); !ok {
			t.Fatalf("attempt %d refused", i+1)
		}
	}
	if n := len(l.attempts); n > maxTrackedKeys {
		t.Fatalf("tracking %d keys, want at most %d", n, maxTrackedKeys)
	}
}

func TestLimiterEvictsLeastRecentlyUsedKey(t *testing.T) {
	l, _ := newTestLimiter()
	l.maxKeys = 3
	const ip = "10.0.0.1"
	l.Attempt("a@example.com", ip) // tracks email:a and ip
	l.Attempt("b@example.com", ip) // tracks email:b; the cap is reached
	l.Attempt("a@example.com", ip) // touches email:a, so email:b is now the oldest
	l.Attempt("c@example.com", ip) // a new key must evict exactly email:b

	if n := len(l.attempts); n > 3 {
		t.Fatalf("tracking %d keys, want at most 3", n)
	}
	if _, ok := l.attempts["email:b@example.com"]; ok {
		t.Fatal("the least recently used key must be evicted")
	}
	for _, key := range []string{"email:a@example.com", "email:c@example.com", "ip:" + ip} {
		if _, ok := l.attempts[key]; !ok {
			t.Fatalf("%s was evicted, want it kept", key)
		}
	}
	// The surviving key keeps its history: email:a has two attempts, so three
	// more reach the limit of five.
	for i := 0; i < 3; i++ {
		if _, ok, _ := l.Attempt("a@example.com", ip); !ok {
			t.Fatalf("attempt %d on email:a refused too early", i+3)
		}
	}
	if _, ok, _ := l.Attempt("a@example.com", ip); ok {
		t.Fatal("email:a must keep its counted attempts across evictions of other keys")
	}
}
