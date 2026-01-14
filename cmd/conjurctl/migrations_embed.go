//go:build embed_migrations

package main

import (
	"fmt"
	"io/fs"

	"conjur-in-go/db"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/source/iofs"
)

func init() {
	fmt.Println("Using embedded migrations (production build)")
}

func createMigrateInstance(dbURL string) (*migrate.Migrate, error) {
	migrationsFS, err := fs.Sub(db.Migrations, "migrations")
	if err != nil {
		return nil, fmt.Errorf("failed to get embedded migrations: %w", err)
	}

	d, err := iofs.New(migrationsFS, ".")
	if err != nil {
		return nil, fmt.Errorf("failed to create iofs driver: %w", err)
	}

	return migrate.NewWithSourceInstance("iofs", d, dbURL)
}

func listMigrationFiles() ([]string, error) {
	migrationsFS, err := fs.Sub(db.Migrations, "migrations")
	if err != nil {
		return nil, fmt.Errorf("failed to get embedded migrations: %w", err)
	}

	entries, err := fs.ReadDir(migrationsFS, ".")
	if err != nil {
		return nil, fmt.Errorf("failed to read migrations directory: %w", err)
	}

	var files []string
	for _, entry := range entries {
		if len(entry.Name()) > 7 && entry.Name()[len(entry.Name())-7:] == ".up.sql" {
			files = append(files, entry.Name())
		}
	}
	return files, nil
}
