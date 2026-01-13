package integration

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
	gormpostgres "gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"conjur-in-go/pkg/server"
	"conjur-in-go/pkg/server/endpoints"
	"conjur-in-go/pkg/slosilo"
	"conjur-in-go/pkg/slosilo/store"
)

// TestContext holds all the resources needed for integration tests
type TestContext struct {
	Server     *server.Server
	DB         *gorm.DB
	RawDB      *sql.DB
	Container  testcontainers.Container
	ServerURL  string
	DataKey    []byte
	Cipher     slosilo.SymmetricCipher
	HTTPClient *http.Client
	Cancel     context.CancelFunc
}

// NewTestContext creates a new test context with PostgreSQL testcontainer
func NewTestContext(ctx context.Context) (*TestContext, error) {
	// Find migrations directory
	migrationsDir, err := findMigrationsDir()
	if err != nil {
		return nil, fmt.Errorf("failed to find migrations directory: %w", err)
	}

	// Start PostgreSQL container
	pgContainer, err := tcpostgres.Run(ctx,
		"postgres:16-alpine",
		tcpostgres.WithDatabase("conjur_test"),
		tcpostgres.WithUsername("conjur"),
		tcpostgres.WithPassword("conjur"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(60*time.Second),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to start postgres container: %w", err)
	}

	// Get connection string
	connStr, err := pgContainer.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		_ = pgContainer.Terminate(ctx)
		return nil, fmt.Errorf("failed to get connection string: %w", err)
	}

	// Connect with GORM
	db, err := gorm.Open(gormpostgres.New(gormpostgres.Config{
		DSN:                  connStr,
		PreferSimpleProtocol: true,
	}), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		_ = pgContainer.Terminate(ctx)
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	// Get raw SQL connection for migrations
	rawDB, err := db.DB()
	if err != nil {
		_ = pgContainer.Terminate(ctx)
		return nil, fmt.Errorf("failed to get raw db: %w", err)
	}

	// Run migrations
	if err := runMigrations(rawDB, migrationsDir); err != nil {
		_ = pgContainer.Terminate(ctx)
		return nil, fmt.Errorf("failed to run migrations: %w", err)
	}

	// Create data key and cipher
	dataKey := make([]byte, 32)
	for i := range dataKey {
		dataKey[i] = byte(i)
	}
	cipher, err := slosilo.NewSymmetric(dataKey)
	if err != nil {
		_ = pgContainer.Terminate(ctx)
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	// Add cipher to DB context for automatic decryption
	dbCtx := context.WithValue(context.Background(), "cipher", cipher)
	db = db.WithContext(dbCtx)

	// Create server
	keystore := store.NewKeyStore(db)
	srv := server.NewServer(keystore, cipher, db, "127.0.0.1", "0")

	// Register all endpoints
	endpoints.RegisterAuthenticateEndpoint(srv)
	endpoints.RegisterSecretsEndpoints(srv)
	endpoints.RegisterPoliciesEndpoints(srv)
	endpoints.RegisterResourcesEndpoints(srv)
	endpoints.RegisterRolesEndpoints(srv)
	endpoints.RegisterStatusEndpoints(srv)
	endpoints.RegisterWhoamiEndpoint(srv)
	endpoints.RegisterPublicKeysEndpoints(srv)
	endpoints.RegisterHostFactoryEndpoints(srv)
	endpoints.RegisterAnnotationsEndpoints(srv)

	// Create listener to get actual port
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		_ = pgContainer.Terminate(ctx)
		return nil, fmt.Errorf("failed to create listener: %w", err)
	}

	// Start server in background with the listener
	_, cancel := context.WithCancel(ctx)
	serverErr := make(chan error, 1)
	go func() {
		if err := srv.StartWithListener(ln); err != nil && err != http.ErrServerClosed {
			log.Printf("Server error: %v", err)
			serverErr <- err
		}
	}()

	// Wait for server to be ready and check for immediate errors
	time.Sleep(200 * time.Millisecond)
	select {
	case err := <-serverErr:
		cancel()
		_ = pgContainer.Terminate(ctx)
		return nil, fmt.Errorf("server failed to start: %w", err)
	default:
		// Server started successfully
	}

	serverURL := fmt.Sprintf("http://%s", ln.Addr().String())

	return &TestContext{
		Server:     srv,
		DB:         db,
		RawDB:      rawDB,
		Container:  pgContainer,
		ServerURL:  serverURL,
		DataKey:    dataKey,
		Cipher:     cipher,
		HTTPClient: &http.Client{Timeout: 10 * time.Second},
		Cancel:     cancel,
	}, nil
}

// Close cleans up all test resources
func (tc *TestContext) Close(ctx context.Context) {
	if tc.Cancel != nil {
		tc.Cancel()
	}
	if tc.RawDB != nil {
		_ = tc.RawDB.Close()
	}
	if tc.Container != nil {
		_ = tc.Container.Terminate(ctx)
	}
}

// findMigrationsDir locates the migrations directory
func findMigrationsDir() (string, error) {
	// Try relative paths from test directory
	paths := []string{
		"../../db/migrations",
		"../db/migrations",
		"db/migrations",
	}

	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			return filepath.Abs(p)
		}
	}

	return "", fmt.Errorf("migrations directory not found")
}

// runMigrations executes SQL migration files
func runMigrations(db *sql.DB, migrationsDir string) error {
	files, err := filepath.Glob(filepath.Join(migrationsDir, "*.sql"))
	if err != nil {
		return err
	}

	for _, file := range files {
		content, err := os.ReadFile(file)
		if err != nil {
			return fmt.Errorf("failed to read %s: %w", file, err)
		}

		if _, err := db.Exec(string(content)); err != nil {
			// Ignore errors for idempotent migrations
			log.Printf("Migration %s: %v (may be expected)", filepath.Base(file), err)
		}
	}

	return nil
}
