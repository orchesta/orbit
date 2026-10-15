//go:build integration

package handler

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/aligoren/orbit/internal/adapter/persistence/postgres"
	"github.com/aligoren/orbit/internal/infrastructure/config"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// newListTestPool creates a fresh, fully migrated database on
// ORBIT_TEST_DATABASE_URL's server and drops it after the test.
func newListTestPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("ORBIT_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("ORBIT_TEST_DATABASE_URL is not set")
	}
	ctx := context.Background()
	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	name := "orbit_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = admin.Exec(context.Background(), "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)")
		_ = admin.Close(context.Background())
	})
	pc, err := pgconn.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.DatabaseConfig{Host: pc.Host, Port: int(pc.Port), User: pc.User, Password: pc.Password, Name: name, SSLMode: "disable"}
	if err := postgres.RunMigrations(cfg, slog.New(slog.NewTextHandler(io.Discard, nil))); err != nil {
		t.Fatal(err)
	}
	pool, err := pgxpool.New(ctx, cfg.DSN())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func TestGetAllRunsTheListSQLWithFiltersAndScanStatus(t *testing.T) {
	ctx := context.Background()
	pool := newListTestPool(t)
	mustExec := func(sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	repoIDs := map[string]uuid.UUID{}
	addRepo := func(name, provider string) {
		id := uuid.New()
		repoIDs[name] = id
		mustExec("INSERT INTO repositories (id, name, url, provider) VALUES ($1, $2, $3, $4)", id, name, "https://example.com/o/"+name, provider)
	}
	addScan := func(repo, status, id string, startedAgo string, vulnerable int) {
		mustExec("INSERT INTO scan_results (id, repository_id, status, vulnerable_deps, total_deps, started_at) VALUES ($1, $2, $3, $4, $4, NOW() - $5::interval)",
			uuid.MustParse(id), repoIDs[repo], status, vulnerable, startedAgo)
	}

	addRepo("alpha-running", "github") // older completed scan, newest is running
	addRepo("alpha-never", "github")   // never scanned
	addRepo("alpha-done", "github")    // completed only
	addRepo("alpha-gitlab", "gitlab")  // filtered out by provider
	addRepo("beta-github", "github")   // filtered out by q
	addScan("alpha-running", "completed", "00000000-0000-0000-0000-0000000000a1", "2 hours", 3)
	addScan("alpha-running", "running", "00000000-0000-0000-0000-0000000000a2", "1 minute", 0)
	addScan("alpha-done", "completed", "00000000-0000-0000-0000-0000000000b1", "1 hour", 1)
	addScan("alpha-gitlab", "failed", "00000000-0000-0000-0000-0000000000c1", "1 hour", 0)
	addScan("beta-github", "pending", "00000000-0000-0000-0000-0000000000d1", "1 hour", 0)

	h := &RepoHandler{tokenRepo: postgres.NewAccessTokenPostgresRepo(pool, nil)}
	list := func(query string) (int, map[string]*string) {
		t.Helper()
		rec := httptest.NewRecorder()
		h.GetAll(rec, httptest.NewRequest(http.MethodGet, "/repositories?"+query, nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("GET ?%s = %d: %s", query, rec.Code, rec.Body)
		}
		var resp struct {
			Data struct {
				Data []struct {
					Name       string  `json:"name"`
					ScanStatus *string `json:"scan_status"`
				} `json:"data"`
				Total int `json:"total"`
			} `json:"data"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatal(err)
		}
		got := map[string]*string{}
		for _, r := range resp.Data.Data {
			got[r.Name] = r.ScanStatus
		}
		return resp.Data.Total, got
	}
	want := func(got map[string]*string, name, status string) {
		t.Helper()
		s, ok := got[name]
		switch {
		case !ok:
			t.Errorf("%s missing from the list", name)
		case status == "" && s != nil:
			t.Errorf("%s scan_status = %q, want none", name, *s)
		case status != "" && (s == nil || *s != status):
			t.Errorf("%s scan_status = %v, want %q", name, s, status)
		}
	}

	total, got := list("q=alpha&provider=github")
	if total != 3 || len(got) != 3 {
		t.Fatalf("q=alpha&provider=github: total %d, rows %v; want 3", total, got)
	}
	want(got, "alpha-running", "running") // the newest scan wins over the older completed one
	want(got, "alpha-never", "")
	want(got, "alpha-done", "completed")

	// Status filters still follow the latest completed scan, not the newest one.
	total, got = list("q=alpha&status=vulnerable")
	if total != 2 || len(got) != 2 {
		t.Fatalf("status=vulnerable: total %d, rows %v; want 2", total, got)
	}
	want(got, "alpha-running", "running")
	want(got, "alpha-done", "completed")

	// Scans sharing started_at resolve by id DESC, in lockstep everywhere.
	mustExec("UPDATE scan_results SET started_at = NOW() WHERE repository_id = $1", repoIDs["alpha-done"])
	addScan("alpha-done", "failed", "00000000-0000-0000-0000-0000000000b2", "0 seconds", 0)
	mustExec("UPDATE scan_results SET started_at = (SELECT started_at FROM scan_results WHERE id = '00000000-0000-0000-0000-0000000000b1') WHERE id = '00000000-0000-0000-0000-0000000000b2'")
	_, got = list("q=alpha-done")
	want(got, "alpha-done", "failed")
}
