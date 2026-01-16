package main

import (
	"conjur-in-go/pkg/db"
	"database/sql"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/lib/pq"
	"github.com/spf13/cobra"
)

// dbMigrateCmd represents the db migrate command
var dbMigrateCmd = &cobra.Command{
	Use:   "migrate",
	Short: "Create and/or upgrade the database schema",
	Long: `Create and/or upgrade the database schema.

This command runs all pending database migrations to bring the schema
up to date. Migrations are located in the db/migrations directory.

Example:
  conjurctl db migrate`,
	Run: func(cmd *cobra.Command, args []string) {
		if err := runMigrations(); err != nil {
			fmt.Println("Migration failed:", err)
			os.Exit(1)
		}
	},
}

var dbMigrateDownCmd = &cobra.Command{
	Use:   "down [steps]",
	Short: "Rollback database migrations",
	Long: `Rollback database migrations.

This command rolls back the specified number of migrations (default: 1).

Example:
  conjurctl db down      # Rollback 1 migration
  conjurctl db down 3    # Rollback 3 migrations`,
	Run: func(cmd *cobra.Command, args []string) {
		steps := 1
		if len(args) > 0 {
			_, _ = fmt.Sscanf(args[0], "%d", &steps)
		}

		if err := runMigrationsDown(steps); err != nil {
			fmt.Println("Rollback failed:", err)
			os.Exit(1)
		}
	},
}

var dbMigrateStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show current migration version",
	Long:  `Show the current database migration version.`,
	Run: func(cmd *cobra.Command, args []string) {
		if err := showMigrationStatus(); err != nil {
			fmt.Println("Failed to get status:", err)
			os.Exit(1)
		}
	},
}

func init() {
	dbCmd.AddCommand(dbMigrateCmd)
	dbCmd.AddCommand(dbMigrateDownCmd)
	dbCmd.AddCommand(dbMigrateStatusCmd)
}

func getDatabaseURL() string {
	return db.URL()
}

// getDatabaseURLWithMigrationsTable returns the database URL with custom migrations table
// This allows golang-migrate to use a different table name, leaving schema_migrations
// available for Sequel (Ruby Conjur) compatibility
func getDatabaseURLWithMigrationsTable() string {
	dbURL := getDatabaseURL()
	if dbURL == "" {
		return ""
	}
	// Add custom migrations table parameter
	if strings.Contains(dbURL, "?") {
		return dbURL + "&x-migrations-table=go_schema_migrations"
	}
	return dbURL + "?x-migrations-table=go_schema_migrations"
}

func runMigrations() error {
	dbURL := getDatabaseURL()
	if dbURL == "" {
		return fmt.Errorf("DATABASE_URL environment variable is required")
	}

	m, err := createMigrateInstance(getDatabaseURLWithMigrationsTable())
	if err != nil {
		return fmt.Errorf("failed to create migrate instance: %w", err)
	}
	defer func() { _, _ = m.Close() }()

	version, dirty, _ := m.Version()
	fmt.Printf("Current version: %d (dirty: %v)\n", version, dirty)

	if err := m.Up(); err != nil {
		if err == migrate.ErrNoChange {
			fmt.Println("No migrations to run - database is up to date")
			// Still sync Sequel schema_migrations for interoperability
			if err := syncSequelSchemaMigrations(dbURL); err != nil {
				fmt.Printf("Warning: Failed to sync Sequel schema_migrations: %v\n", err)
			}
			return nil
		}
		return fmt.Errorf("migration failed: %w", err)
	}

	newVersion, _, _ := m.Version()
	fmt.Printf("Migrated to version: %d\n", newVersion)

	// Sync Sequel-compatible schema_migrations table for Ruby Conjur interoperability
	if err := syncSequelSchemaMigrations(dbURL); err != nil {
		fmt.Printf("Warning: Failed to sync Sequel schema_migrations: %v\n", err)
	}

	fmt.Println("Migrations complete")
	return nil
}

// syncSequelSchemaMigrations creates/updates the Sequel-compatible schema_migrations table
// This allows Ruby Conjur (which uses Sequel) to recognize migrations run by Go
//
// golang-migrate now uses go_schema_migrations table (via x-migrations-table parameter)
// so we can safely create a Sequel-compatible schema_migrations table with filename column
func syncSequelSchemaMigrations(dbURL string) error {
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}
	defer func() { _ = db.Close() }()

	// Get the current version from golang-migrate's go_schema_migrations table
	var currentVersion int64
	err = db.QueryRow("SELECT version FROM go_schema_migrations WHERE dirty = false LIMIT 1").Scan(&currentVersion)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil // No migrations applied yet
		}
		return fmt.Errorf("failed to get current version: %w", err)
	}

	// Create Sequel-compatible schema_migrations table if it doesn't exist
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS schema_migrations (
			filename text PRIMARY KEY
		)
	`)
	if err != nil {
		return fmt.Errorf("failed to create schema_migrations table: %w", err)
	}

	// Get list of migration files (from build-tagged implementation)
	files, err := listMigrationFiles()
	if err != nil {
		return fmt.Errorf("failed to list migration files: %w", err)
	}
	// Sort files to process in order
	sort.Strings(files)

	// Insert each migration filename into Sequel's table
	for _, basename := range files {
		// Extract version number from filename (e.g., "20160628212347_create_roles.up.sql" -> 20160628212347)
		parts := strings.SplitN(basename, "_", 2)
		if len(parts) < 2 {
			continue
		}

		var fileVersion int64
		_, _ = fmt.Sscanf(parts[0], "%d", &fileVersion)

		// Only include migrations up to current version
		if fileVersion <= currentVersion {
			// Convert to Ruby migration filename format (without .up.sql, with .rb)
			rubyFilename := strings.TrimSuffix(basename, ".up.sql") + ".rb"

			_, err = db.Exec(`
				INSERT INTO schema_migrations (filename) 
				VALUES ($1) 
				ON CONFLICT (filename) DO NOTHING
			`, rubyFilename)
			if err != nil {
				return fmt.Errorf("failed to insert migration %s: %w", rubyFilename, err)
			}
		}
	}

	fmt.Println("Synced Sequel schema_migrations for Ruby Conjur interoperability")
	return nil
}

func runMigrationsDown(steps int) error {
	dbURL := getDatabaseURL()
	if dbURL == "" {
		return fmt.Errorf("DATABASE_URL environment variable is required")
	}

	m, err := createMigrateInstance(getDatabaseURLWithMigrationsTable())
	if err != nil {
		return fmt.Errorf("failed to create migrate instance: %w", err)
	}
	defer func() { _, _ = m.Close() }()

	fmt.Printf("Rolling back %d migration(s)...\n", steps)

	if err := m.Steps(-steps); err != nil {
		return fmt.Errorf("rollback failed: %w", err)
	}

	version, _, _ := m.Version()
	fmt.Printf("Rolled back to version: %d\n", version)
	return nil
}

func showMigrationStatus() error {
	dbURL := getDatabaseURL()
	if dbURL == "" {
		return fmt.Errorf("DATABASE_URL environment variable is required")
	}

	m, err := createMigrateInstance(getDatabaseURLWithMigrationsTable())
	if err != nil {
		return fmt.Errorf("failed to create migrate instance: %w", err)
	}
	defer func() { _, _ = m.Close() }()

	version, dirty, err := m.Version()
	if err != nil {
		if err == migrate.ErrNilVersion {
			fmt.Println("No migrations have been applied yet")
			return nil
		}
		return err
	}

	fmt.Printf("Current version: %d\n", version)
	if dirty {
		fmt.Println("Warning: Database is in a dirty state")
	}
	return nil
}
