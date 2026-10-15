package depsdev

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/orchesta/orbit/internal/domain/entity"
)

// requestLog records the escaped path of each request a test server saw.
type requestLog struct {
	mu    sync.Mutex
	paths []string
}

func (l *requestLog) add(p string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.paths = append(l.paths, p)
}

func (l *requestLog) all() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.paths...)
}

// newTestClient points a client at handler, with no retry delay.
func newTestClient(t *testing.T, handler http.HandlerFunc) (*Client, *requestLog) {
	t.Helper()
	log := &requestLog{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.add(r.URL.EscapedPath())
		handler(w, r)
	}))
	t.Cleanup(srv.Close)
	c := NewClient()
	c.baseURL = srv.URL + "/v3"
	c.retryDelay = 0
	return c, log
}

func respond(body string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}
}

func TestLicenseBuildsTheRequestAndNormalises(t *testing.T) {
	c, paths := newTestClient(t, respond(`{"versionKey":{"system":"NPM","name":"@babel/core","version":"7.24.0"},"licenses":["mit"]}`))
	got, err := c.License(context.Background(), entity.EcosystemNpm, "@babel/core", "7.24.0")
	if err != nil || got != "MIT" {
		t.Fatalf("License = %q, %v; want MIT", got, err)
	}
	if want := "/v3/systems/npm/packages/@babel%2Fcore/versions/7.24.0"; paths.all()[0] != want {
		t.Errorf("path = %s, want %s", paths.all()[0], want)
	}
}

func TestLicenseAddsTheGoVersionPrefix(t *testing.T) {
	c, paths := newTestClient(t, respond(`{"licenses":["BSD-3-Clause"]}`))
	if got, err := c.License(context.Background(), entity.EcosystemGo, "golang.org/x/crypto", "0.21.0"); err != nil || got != "BSD-3-Clause" {
		t.Fatalf("License = %q, %v", got, err)
	}
	if want := "/v3/systems/go/packages/golang.org%2Fx%2Fcrypto/versions/v0.21.0"; paths.all()[0] != want {
		t.Errorf("path = %s, want %s", paths.all()[0], want)
	}
}

func TestLicenseJoinsSeveralLicensesAndDropsNonStandard(t *testing.T) {
	c, _ := newTestClient(t, respond(`{"licenses":["MIT","Apache-2.0","non-standard"]}`))
	if got, _ := c.License(context.Background(), entity.EcosystemGo, "gopkg.in/yaml.v3", "3.0.1"); got != "MIT AND Apache-2.0" {
		t.Fatalf("License = %q", got)
	}
	c, _ = newTestClient(t, respond(`{"licenses":["non-standard"]}`))
	if got, err := c.License(context.Background(), entity.EcosystemPyPI, "numpy", "1.26.4"); err != nil || got != "" {
		t.Fatalf("non-standard = %q, %v; want \"\"", got, err)
	}
}

func TestLicenseNotFoundIsUnknownNotAnError(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "version not found", http.StatusNotFound)
	})
	if got, err := c.License(context.Background(), entity.EcosystemNpm, "private-pkg", "1.0.0"); err != nil || got != "" {
		t.Fatalf("License = %q, %v; want \"\", nil", got, err)
	}
}

func TestLicenseRetriesOnceOnServerErrors(t *testing.T) {
	var calls atomic.Int32
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			http.Error(w, "slow down", http.StatusTooManyRequests)
			return
		}
		respond(`{"licenses":["ISC"]}`)(w, r)
	})
	if got, err := c.License(context.Background(), entity.EcosystemNpm, "a", "1.0.0"); err != nil || got != "ISC" {
		t.Fatalf("License = %q, %v", got, err)
	}
	if calls.Load() != 2 {
		t.Fatalf("calls = %d, want 2", calls.Load())
	}

	calls.Store(0)
	c, _ = newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		http.Error(w, "down", http.StatusServiceUnavailable)
	})
	_, err := c.License(context.Background(), entity.EcosystemNpm, "a", "1.0.0")
	if err == nil || !strings.Contains(err.Error(), "503") || !strings.Contains(err.Error(), "a@1.0.0") {
		t.Fatalf("err = %v, want a 503 naming the package", err)
	}
	if calls.Load() != 2 {
		t.Fatalf("calls = %d, want 2 (one retry)", calls.Load())
	}
}

func TestLicenseDoesNotRetryClientErrors(t *testing.T) {
	var calls atomic.Int32
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		http.Error(w, "bad", http.StatusBadRequest)
	})
	if _, err := c.License(context.Background(), entity.EcosystemNpm, "a", "1.0.0"); err == nil {
		t.Fatal("want an error for 400")
	}
	if calls.Load() != 1 {
		t.Fatalf("calls = %d, want 1", calls.Load())
	}
}

func TestLicenseRejectsAMalformedBody(t *testing.T) {
	c, _ := newTestClient(t, respond(`{"licenses":`))
	if _, err := c.License(context.Background(), entity.EcosystemNpm, "a", "1.0.0"); err == nil {
		t.Fatal("want a decode error")
	}
	c, _ = newTestClient(t, respond(`{"licenses":"MIT"}`))
	if _, err := c.License(context.Background(), entity.EcosystemNpm, "a", "1.0.0"); err == nil {
		t.Fatal("want a decode error for a string instead of a list")
	}
}

func TestLicenseCachesAnswersUntilTheyExpire(t *testing.T) {
	var calls atomic.Int32
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if strings.Contains(r.URL.Path, "missing") {
			http.NotFound(w, r)
			return
		}
		respond(`{"licenses":["MIT"]}`)(w, r)
	})
	now := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	c.now = func() time.Time { return now }
	ctx := context.Background()
	for range 3 {
		_, _ = c.License(ctx, entity.EcosystemNpm, "a", "1.0.0")
		_, _ = c.License(ctx, entity.EcosystemNpm, "missing", "1.0.0")
	}
	if calls.Load() != 2 {
		t.Fatalf("calls = %d, want 2 (answers and not-found are cached)", calls.Load())
	}
	now = now.Add(cacheTTL)
	_, _ = c.License(ctx, entity.EcosystemNpm, "a", "1.0.0")
	if calls.Load() != 3 {
		t.Fatalf("calls = %d, want 3 after the entry expired", calls.Load())
	}
}

func TestLicenseDoesNotCacheErrors(t *testing.T) {
	var calls atomic.Int32
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) <= 2 {
			http.Error(w, "down", http.StatusBadGateway)
			return
		}
		respond(`{"licenses":["MIT"]}`)(w, r)
	})
	if _, err := c.License(context.Background(), entity.EcosystemNpm, "a", "1.0.0"); err == nil {
		t.Fatal("want an error")
	}
	if got, err := c.License(context.Background(), entity.EcosystemNpm, "a", "1.0.0"); err != nil || got != "MIT" {
		t.Fatalf("second lookup = %q, %v; want MIT", got, err)
	}
}

func TestLicenseSkipsUnsupportedInput(t *testing.T) {
	c, paths := newTestClient(t, respond(`{"licenses":["MIT"]}`))
	for _, tc := range []struct {
		eco           entity.Ecosystem
		name, version string
	}{{"Maven", "a", "1"}, {entity.EcosystemNpm, "", "1"}, {entity.EcosystemNpm, "a", ""}} {
		if got, err := c.License(context.Background(), tc.eco, tc.name, tc.version); got != "" || err != nil {
			t.Errorf("License(%+v) = %q, %v", tc, got, err)
		}
	}
	if got := paths.all(); len(got) != 0 {
		t.Fatalf("requests = %q, want none", got)
	}
}

func TestLicenseStopsWhenTheContextEnds(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "busy", http.StatusTooManyRequests)
	})
	c.retryDelay = time.Hour
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(10 * time.Millisecond); cancel() }()
	if _, err := c.License(ctx, entity.EcosystemNpm, "a", "1.0.0"); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
}
