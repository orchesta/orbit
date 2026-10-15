//go:build integration

package postgres

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/aligoren/orbit/internal/infrastructure/config"
	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// newTestPool creates a fresh database with every migration applied and
// drops it after the test.
func newTestPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	pool := newTestPoolAtVersion(t, 0)
	migrateTestPoolToLatest(t, pool)
	return pool
}

// newTestPoolAtVersion creates a fresh database migrated up to version
// (0 = no migrations) and drops it after the test.
func newTestPoolAtVersion(t *testing.T, version uint) *pgxpool.Pool {
	t.Helper()
	dsn := createTestDatabase(t)
	if version > 0 {
		if err := newTestMigrator(t, dsn).Migrate(version); err != nil {
			t.Fatalf("migrate to %d: %v", version, err)
		}
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// migrateTestPoolToLatest applies the remaining migrations to pool's database.
func migrateTestPoolToLatest(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	if err := newTestMigrator(t, pool.Config().ConnString()).Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		t.Fatalf("migrate up: %v", err)
	}
}

// createTestDatabase creates an empty database on ORBIT_TEST_DATABASE_URL's
// server, registers its removal and returns its DSN.
func createTestDatabase(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("ORBIT_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("ORBIT_TEST_DATABASE_URL is not set")
	}
	ctx := context.Background()
	admin := connectWithRetry(t, ctx, dsn)
	name := "orbit_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		_ = admin.Close(ctx)
		t.Fatalf("create database: %v", err)
	}
	t.Cleanup(func() {
		_, _ = admin.Exec(context.Background(), "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)")
		_ = admin.Close(context.Background())
	})

	pc, err := pgconn.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	return config.DatabaseConfig{
		Host: pc.Host, Port: int(pc.Port), User: pc.User, Password: pc.Password,
		Name: name, SSLMode: "disable",
	}.DSN()
}

func newTestMigrator(t *testing.T, dsn string) *migrate.Migrate {
	t.Helper()
	source, err := iofs.New(migrationsFS, "migrations")
	if err != nil {
		t.Fatal(err)
	}
	m, err := migrate.NewWithSourceInstance("iofs", source, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = m.Close() })
	return m
}

// connectWithRetry waits for a freshly started Postgres container to accept connections.
func connectWithRetry(t *testing.T, ctx context.Context, dsn string) *pgx.Conn {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for {
		conn, err := pgx.Connect(ctx, dsn)
		if err == nil {
			return conn
		}
		if time.Now().After(deadline) {
			t.Fatalf("connect to test database: %v", err)
		}
		time.Sleep(time.Second)
	}
}
