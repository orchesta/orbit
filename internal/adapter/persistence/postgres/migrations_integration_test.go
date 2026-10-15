//go:build integration

package postgres

import (
	"context"
	"testing"
)

func TestMigrationsApply(t *testing.T) {
	pool := newTestPool(t)
	var v string
	if err := pool.QueryRow(context.Background(), "SELECT value FROM system_config WHERE key = 'setup_completed'").Scan(&v); err != nil {
		t.Fatal(err)
	}
	if v != "false" {
		t.Fatalf("setup_completed = %q, want false", v)
	}
}

func TestUsersEmailLowerIndexExists(t *testing.T) {
	pool := newTestPool(t)
	var n int
	if err := pool.QueryRow(context.Background(), "SELECT count(*) FROM pg_indexes WHERE indexname = 'idx_users_email_lower'").Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("idx_users_email_lower count = %d, want 1", n)
	}
}
