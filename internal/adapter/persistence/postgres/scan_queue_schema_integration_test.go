//go:build integration

package postgres

import (
	"context"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestOneActiveScanPerRepository(t *testing.T) {
	ctx := context.Background()
	pool := newTestPool(t)
	repoID := uuid.New()
	if _, err := pool.Exec(ctx, "INSERT INTO repositories (id, name, url, provider) VALUES ($1, 'r', 'https://github.com/o/r', 'github')", repoID); err != nil {
		t.Fatal(err)
	}
	insert := func(status string) error {
		_, err := pool.Exec(ctx, "INSERT INTO scan_results (id, repository_id, status) VALUES ($1, $2, $3)", uuid.New(), repoID, status)
		return err
	}
	if err := insert("pending"); err != nil {
		t.Fatal(err)
	}
	for _, status := range []string{"pending", "running"} {
		if err := insert(status); err == nil || !strings.Contains(err.Error(), "idx_scan_results_one_active") {
			t.Fatalf("second active scan (%s) must violate idx_scan_results_one_active, got %v", status, err)
		}
	}
	for _, status := range []string{"completed", "failed", "completed"} {
		if err := insert(status); err != nil {
			t.Fatalf("finished scans are unrestricted: %v", err)
		}
	}
}

func TestNewColumnsHaveDefaults(t *testing.T) {
	ctx := context.Background()
	pool := newTestPool(t)
	repoID, scanID := uuid.New(), uuid.New()
	if _, err := pool.Exec(ctx, "INSERT INTO repositories (id, name, url, provider) VALUES ($1, 'r', 'https://github.com/o/r', 'github')", repoID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, "INSERT INTO scan_results (id, repository_id, status) VALUES ($1, $2, 'completed')", scanID, repoID); err != nil {
		t.Fatal(err)
	}
	var totalVulns, attempts int
	var dueSoon bool
	if err := pool.QueryRow(ctx, "SELECT total_vulns, attempts FROM scan_results WHERE id = $1", scanID).Scan(&totalVulns, &attempts); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, "SELECT next_scan_at <= NOW() FROM repositories WHERE id = $1", repoID).Scan(&dueSoon); err != nil {
		t.Fatal(err)
	}
	if totalVulns != 0 || attempts != 0 || !dueSoon {
		t.Fatalf("total_vulns=%d attempts=%d new repo due=%v", totalVulns, attempts, dueSoon)
	}
	long := strings.Repeat("x", 300)
	if _, err := pool.Exec(ctx, `INSERT INTO dependencies (id, repository_id, scan_result_id, name, current_version, latest_version, ecosystem, manifest_file)
		VALUES ($1, $2, $3, 'pkg', $4, $4, 'npm', 'package.json')`, uuid.New(), repoID, scanID, long); err != nil {
		t.Fatalf("long versions must fit: %v", err)
	}
}

func TestMigrationClosesOrphanedScans(t *testing.T) {
	ctx := context.Background()
	pool := newTestPoolAtVersion(t, 3)
	repoID := uuid.New()
	if _, err := pool.Exec(ctx, "INSERT INTO repositories (id, name, url, provider) VALUES ($1, 'r', 'https://github.com/o/r', 'github')", repoID); err != nil {
		t.Fatal(err)
	}
	for _, status := range []string{"running", "running", "pending"} {
		if _, err := pool.Exec(ctx, "INSERT INTO scan_results (id, repository_id, status) VALUES ($1, $2, $3)", uuid.New(), repoID, status); err != nil {
			t.Fatal(err)
		}
	}
	migrateTestPoolToLatest(t, pool)

	var active int
	if err := pool.QueryRow(ctx, "SELECT COUNT(*) FROM scan_results WHERE status IN ('pending','running')").Scan(&active); err != nil {
		t.Fatal(err)
	}
	if active != 0 {
		t.Fatalf("orphaned active scans = %d, want 0", active)
	}
}
