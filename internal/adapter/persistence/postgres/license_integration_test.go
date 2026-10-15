//go:build integration

package postgres

import (
	"context"
	"testing"

	"github.com/orchesta/orbit/internal/domain/entity"
)

// dependencyLicensesMigration is the version of 000009_dependency_licenses.
const dependencyLicensesMigration uint = 9

func TestDependencyLicenseRoundTrip(t *testing.T) {
	ctx := context.Background()
	pool := newTestPool(t)
	scans, deps := NewScanResultPostgresRepo(pool), NewDependencyPostgresRepo(pool)
	repoID := newQueueRepo(t, ctx, pool, "licenses")
	s := entity.NewScanResult(repoID)
	s.Complete(0, 0, 0, 0)
	if err := scans.Create(ctx, s); err != nil {
		t.Fatal(err)
	}
	batch := entity.NewDependency(repoID, s.ID, "a", "1.0.0", "package-lock.json", entity.EcosystemNpm)
	batch.License = "MIT OR Apache-2.0"
	none := entity.NewDependency(repoID, s.ID, "b", "1.0.0", "package-lock.json", entity.EcosystemNpm)
	if err := deps.CreateBatch(ctx, []*entity.Dependency{batch, none}); err != nil {
		t.Fatal(err)
	}
	single := entity.NewDependency(repoID, s.ID, "c", "1.0.0", "package-lock.json", entity.EcosystemNpm)
	single.License = "ISC"
	if err := deps.Create(ctx, single); err != nil {
		t.Fatal(err)
	}

	got, err := deps.GetByScanResultID(ctx, s.ID)
	if err != nil || len(got) != 3 {
		t.Fatalf("GetByScanResultID = %d, %v", len(got), err)
	}
	if got[0].License != "MIT OR Apache-2.0" || got[1].License != "" || got[2].License != "ISC" {
		t.Fatalf("licenses = %q, %q, %q", got[0].License, got[1].License, got[2].License)
	}
	byRepo, err := deps.GetByRepositoryID(ctx, repoID)
	if err != nil || len(byRepo) != 3 || byRepo[0].License != "MIT OR Apache-2.0" {
		t.Fatalf("GetByRepositoryID = %+v, %v", byRepo, err)
	}
	byID, err := deps.GetByID(ctx, single.ID)
	if err != nil || byID.License != "ISC" {
		t.Fatalf("GetByID = %+v, %v", byID, err)
	}
}

// Rows saved before the migration read back with an unknown license, and
// the down migration removes the column again.
func TestDependencyLicenseMigration(t *testing.T) {
	ctx := context.Background()
	pool := newTestPoolAtVersion(t, dependencyLicensesMigration-1)
	if _, err := pool.Exec(ctx, `INSERT INTO repositories (id, name, url, provider) VALUES ('00000000-0000-0000-0000-000000000001', 'old', 'https://github.com/o/old', 'github')`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO scan_results (id, repository_id, status) VALUES ('00000000-0000-0000-0000-000000000002', '00000000-0000-0000-0000-000000000001', 'completed')`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO dependencies (id, repository_id, scan_result_id, name, current_version, ecosystem, manifest_file)
		VALUES ('00000000-0000-0000-0000-000000000003', '00000000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-000000000002', 'old', '1.0.0', 'npm', 'package-lock.json')`); err != nil {
		t.Fatal(err)
	}
	migrateTestPoolToLatest(t, pool)
	var license string
	if err := pool.QueryRow(ctx, `SELECT license FROM dependencies WHERE name = 'old'`).Scan(&license); err != nil || license != "" {
		t.Fatalf("license = %q, %v; want \"\"", license, err)
	}
	if err := newTestMigrator(t, pool.Config().ConnString()).Migrate(dependencyLicensesMigration - 1); err != nil {
		t.Fatalf("migrate down to %d: %v", dependencyLicensesMigration-1, err)
	}
	var cols, rows int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM information_schema.columns WHERE table_name = 'dependencies' AND column_name = 'license'`).Scan(&cols); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM dependencies`).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if cols != 0 || rows != 1 {
		t.Fatalf("after down: %d license columns, %d rows; want 0 and 1", cols, rows)
	}
}
