package postgres

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/orchesta/orbit/internal/domain/entity"
	"github.com/orchesta/orbit/internal/domain/repository"
)

var _ repository.DependencyRepo = (*DependencyPostgresRepo)(nil)

// DependencyPostgresRepo implements DependencyRepo using PostgreSQL.
type DependencyPostgresRepo struct {
	pool *pgxpool.Pool
}

func NewDependencyPostgresRepo(pool *pgxpool.Pool) *DependencyPostgresRepo {
	return &DependencyPostgresRepo{pool: pool}
}

func (r *DependencyPostgresRepo) Create(ctx context.Context, dep *entity.Dependency) error {
	query := `
		INSERT INTO dependencies (id, repository_id, scan_result_id, name, current_version, latest_version, ecosystem, manifest_file, is_outdated, is_direct, is_resolved, is_dev, update_type, license, last_checked_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
	`
	_, err := r.pool.Exec(ctx, query,
		dep.ID, dep.RepositoryID, dep.ScanResultID, dep.Name, dep.CurrentVersion,
		dep.LatestVersion, dep.Ecosystem, dep.ManifestFile, dep.IsOutdated,
		dep.IsDirect, dep.IsResolved, dep.IsDev, dep.UpdateType, dep.License, dep.LastCheckedAt,
	)
	return err
}

func (r *DependencyPostgresRepo) CreateBatch(ctx context.Context, deps []*entity.Dependency) error {
	if len(deps) == 0 {
		return nil
	}

	_, err := r.pool.CopyFrom(ctx, pgx.Identifier{"dependencies"},
		[]string{"id", "repository_id", "scan_result_id", "name", "current_version", "latest_version", "ecosystem", "manifest_file", "is_outdated", "is_direct", "is_resolved", "is_dev", "update_type", "license", "last_checked_at"},
		pgx.CopyFromSlice(len(deps), func(i int) ([]any, error) {
			d := deps[i]
			return []any{d.ID, d.RepositoryID, d.ScanResultID, d.Name, d.CurrentVersion, d.LatestVersion,
				string(d.Ecosystem), d.ManifestFile, d.IsOutdated, d.IsDirect, d.IsResolved, d.IsDev, string(d.UpdateType), d.License, d.LastCheckedAt}, nil
		}))
	return err
}

func (r *DependencyPostgresRepo) GetByID(ctx context.Context, id uuid.UUID) (*entity.Dependency, error) {
	query := `
		SELECT id, repository_id, scan_result_id, name, current_version, latest_version, ecosystem, manifest_file, is_outdated, is_direct, is_resolved, is_dev, update_type, license, last_checked_at
		FROM dependencies WHERE id = $1
	`
	row := r.pool.QueryRow(ctx, query, id)
	var dep entity.Dependency
	err := row.Scan(
		&dep.ID, &dep.RepositoryID, &dep.ScanResultID, &dep.Name, &dep.CurrentVersion,
		&dep.LatestVersion, &dep.Ecosystem, &dep.ManifestFile, &dep.IsOutdated,
		&dep.IsDirect, &dep.IsResolved, &dep.IsDev, &dep.UpdateType, &dep.License, &dep.LastCheckedAt,
	)
	if err != nil {
		return nil, err
	}
	return &dep, nil
}

func (r *DependencyPostgresRepo) GetByScanResultID(ctx context.Context, scanResultID uuid.UUID) ([]*entity.Dependency, error) {
	query := `
		SELECT id, repository_id, scan_result_id, name, current_version, latest_version, ecosystem, manifest_file, is_outdated, is_direct, is_resolved, is_dev, update_type, license, last_checked_at
		FROM dependencies WHERE scan_result_id = $1 ORDER BY name, current_version, manifest_file, ecosystem
	`
	return r.queryDeps(ctx, query, scanResultID)
}

func (r *DependencyPostgresRepo) GetByRepositoryID(ctx context.Context, repoID uuid.UUID) ([]*entity.Dependency, error) {
	query := `
		SELECT d.id, d.repository_id, d.scan_result_id, d.name, d.current_version, d.latest_version, d.ecosystem, d.manifest_file, d.is_outdated, d.is_direct, d.is_resolved, d.is_dev, d.update_type, d.license, d.last_checked_at
		FROM dependencies d
		INNER JOIN scan_results s ON d.scan_result_id = s.id
		WHERE d.repository_id = $1
		AND s.id = (SELECT id FROM scan_results WHERE repository_id = $1 AND status = 'completed' ORDER BY started_at DESC, id DESC LIMIT 1)
		ORDER BY d.name, d.current_version, d.manifest_file, d.ecosystem
	`
	return r.queryDeps(ctx, query, repoID)
}

func (r *DependencyPostgresRepo) GetOutdatedByRepositoryID(ctx context.Context, repoID uuid.UUID) ([]*entity.Dependency, error) {
	query := `
		SELECT d.id, d.repository_id, d.scan_result_id, d.name, d.current_version, d.latest_version, d.ecosystem, d.manifest_file, d.is_outdated, d.is_direct, d.is_resolved, d.is_dev, d.update_type, d.license, d.last_checked_at
		FROM dependencies d
		INNER JOIN scan_results s ON d.scan_result_id = s.id
		WHERE d.repository_id = $1 AND d.is_outdated = true
		AND s.id = (SELECT id FROM scan_results WHERE repository_id = $1 AND status = 'completed' ORDER BY started_at DESC, id DESC LIMIT 1)
		ORDER BY d.update_type DESC, d.name, d.current_version, d.manifest_file, d.ecosystem
	`
	return r.queryDeps(ctx, query, repoID)
}

func (r *DependencyPostgresRepo) DeleteByScanResultID(ctx context.Context, scanResultID uuid.UUID) error {
	_, err := r.pool.Exec(ctx, "DELETE FROM dependencies WHERE scan_result_id = $1", scanResultID)
	return err
}

func (r *DependencyPostgresRepo) queryDeps(ctx context.Context, query string, args ...interface{}) ([]*entity.Dependency, error) {
	rows, err := r.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var deps []*entity.Dependency
	for rows.Next() {
		var dep entity.Dependency
		err := rows.Scan(
			&dep.ID, &dep.RepositoryID, &dep.ScanResultID, &dep.Name, &dep.CurrentVersion,
			&dep.LatestVersion, &dep.Ecosystem, &dep.ManifestFile, &dep.IsOutdated,
			&dep.IsDirect, &dep.IsResolved, &dep.IsDev, &dep.UpdateType, &dep.License, &dep.LastCheckedAt,
		)
		if err != nil {
			return nil, err
		}
		deps = append(deps, &dep)
	}
	return deps, rows.Err()
}
