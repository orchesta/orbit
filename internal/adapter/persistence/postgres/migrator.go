package postgres

import (
	"embed"
	"fmt"
	"log/slog"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/orchesta/orbit/internal/infrastructure/config"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// RunMigrations runs all pending database migrations.
func RunMigrations(cfg config.DatabaseConfig, logger *slog.Logger) error {
	source, err := iofs.New(migrationsFS, "migrations")
	if err != nil {
		return fmt.Errorf("failed to open migrations: %w", err)
	}

	m, err := migrate.NewWithSourceInstance("iofs", source, cfg.DSN())
	if err != nil {
		return fmt.Errorf("failed to create migrator: %w", err)
	}
	defer m.Close()

	err = m.Up()
	if err != nil && err != migrate.ErrNoChange {
		return fmt.Errorf("migration failed: %w", err)
	}

	version, dirty, _ := m.Version()
	if err == migrate.ErrNoChange {
		logger.Info("database migrations up to date", slog.Uint64("version", uint64(version)))
	} else {
		logger.Info("database migrations applied", slog.Uint64("version", uint64(version)), slog.Bool("dirty", dirty))
	}

	return nil
}
