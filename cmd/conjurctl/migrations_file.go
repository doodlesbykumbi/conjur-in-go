//go:build !embed_migrations

package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/source/file"
)

const defaultMigrationsPath = "db/migrations"

func createMigrateInstance(dbURL string) (*migrate.Migrate, error) {
	path := defaultMigrationsPath
	fmt.Printf("Running migrations from file://%s\n", path)
	return migrate.New("file://"+path, dbURL)
}

func listMigrationFiles() ([]string, error) {
	entries, err := os.ReadDir(defaultMigrationsPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read migrations directory: %w", err)
	}

	var files []string
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".up.sql") {
			files = append(files, entry.Name())
		}
	}
	return files, nil
}
