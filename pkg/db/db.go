package db

import (
	"context"
	"fmt"
	"os"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/doodlesbykumbi/conjur-in-go/pkg/slosilo"
)

// Config holds database connection configuration
type Config struct {
	// URL is the database connection URL (defaults to DATABASE_URL env var)
	URL string
	// Cipher is optional - if provided, it will be added to the context
	Cipher slosilo.SymmetricCipher
}

// Connect establishes a database connection.
// If no URL is provided, it reads from DATABASE_URL environment variable.
func Connect(cfg Config) (*gorm.DB, error) {
	dbURL := cfg.URL
	if dbURL == "" {
		dbURL = os.Getenv("DATABASE_URL")
	}
	if dbURL == "" {
		return nil, fmt.Errorf("DATABASE_URL environment variable is required")
	}

	// Default to silent logging unless CONJUR_LOG_LEVEL=debug is set
	logMode := logger.Silent
	if os.Getenv("CONJUR_LOG_LEVEL") == "debug" {
		logMode = logger.Info
	}

	db, err := gorm.Open(
		postgres.New(postgres.Config{
			DSN:                  dbURL,
			PreferSimpleProtocol: true, // disables implicit prepared statement usage
		}),
		&gorm.Config{
			Logger: logger.Default.LogMode(logMode),
		},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	if cfg.Cipher != nil {
		ctx := context.WithValue(context.Background(), "cipher", cfg.Cipher)
		db = db.WithContext(ctx)
	}

	return db, nil
}

// URL returns the database URL from environment.
// Returns empty string if DATABASE_URL is not set.
func URL() string {
	return os.Getenv("DATABASE_URL")
}
