package integration

import (
	"context"
	"database/sql"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
	gormpostgres "gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"conjur-in-go/pkg/authenticator"
	"conjur-in-go/pkg/authenticator/authn"
	"conjur-in-go/pkg/server"
	"conjur-in-go/pkg/server/endpoints"
	"conjur-in-go/pkg/slosilo"
	"conjur-in-go/pkg/slosilo/store"
)

// TestContext holds all the resources needed for integration tests
type TestContext struct {
	DB            *gorm.DB
	RawDB         *sql.DB
	Container     testcontainers.Container
	ServerURL     string
	DatabaseURL   string // Connection string for the test database
	DataKey       []byte
	Cipher        slosilo.SymmetricCipher
	HTTPClient    *http.Client
	Cancel        context.CancelFunc
	ServerProcess *exec.Cmd
	InlineServer  *server.Server // For inline mode
}

// NewTestContext creates a new test context with PostgreSQL testcontainer.
// Modes:
//   - Binary mode (default): Set CONJUR_BINARY to the path of the conjurctl binary
//   - Inline mode: Set CONJUR_INLINE=1 to run the server in-process (no binary needed)
func NewTestContext(ctx context.Context) (*TestContext, error) {
	// Find project root and migrations directory
	projectRoot, err := findProjectRoot()
	if err != nil {
		return nil, fmt.Errorf("failed to find project root: %w", err)
	}
	migrationsDir := filepath.Join(projectRoot, "db", "migrations")

	// Check mode
	inlineMode := os.Getenv("CONJUR_INLINE") == "1"
	binaryPath := os.Getenv("CONJUR_BINARY")

	if !inlineMode && binaryPath == "" {
		return nil, fmt.Errorf("Either CONJUR_BINARY or CONJUR_INLINE=1 is required.\n\nBinary mode:\n  go build -o conjurctl ./cmd/conjurctl\n  INTEGRATION_TEST=1 CONJUR_BINARY=$(pwd)/conjurctl go test -v ./test/integration/...\n\nInline mode:\n  INTEGRATION_TEST=1 CONJUR_INLINE=1 go test -v ./test/integration/...")
	}

	if !inlineMode {
		// Verify the binary exists
		if _, err := os.Stat(binaryPath); err != nil {
			return nil, fmt.Errorf("CONJUR_BINARY path does not exist: %s", binaryPath)
		}
		log.Printf("Using binary: %s", binaryPath)
	} else {
		log.Println("Using inline server mode")
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

	// Get connection string for the host (not container network)
	host, err := pgContainer.Host(ctx)
	if err != nil {
		_ = pgContainer.Terminate(ctx)
		return nil, fmt.Errorf("failed to get container host: %w", err)
	}
	port, err := pgContainer.MappedPort(ctx, "5432")
	if err != nil {
		_ = pgContainer.Terminate(ctx)
		return nil, fmt.Errorf("failed to get container port: %w", err)
	}
	connStr := fmt.Sprintf("postgres://conjur:conjur@%s:%s/conjur_test?sslmode=disable", host, port.Port())

	// Connect with GORM for test setup/assertions
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

	// Add cipher to DB context for automatic decryption in test assertions
	dbCtx := context.WithValue(context.Background(), "cipher", cipher)
	db = db.WithContext(dbCtx)

	serverPort := "18080" // Use a fixed port for testing
	serverURL := fmt.Sprintf("http://127.0.0.1:%s", serverPort)

	var serverProcess *exec.Cmd
	var inlineServer *server.Server
	var cancel context.CancelFunc

	if inlineMode {
		// Start inline server
		inlineServer, cancel, err = startInlineServer(db, cipher, serverPort)
		if err != nil {
			_ = pgContainer.Terminate(ctx)
			return nil, fmt.Errorf("failed to start inline server: %w", err)
		}
	} else {
		// Start the actual binary
		serverProcess, cancel, err = startBinary(binaryPath, connStr, dataKey, serverPort)
		if err != nil {
			_ = pgContainer.Terminate(ctx)
			return nil, fmt.Errorf("failed to start server binary: %w", err)
		}
	}

	// Wait for server to be ready
	if err := waitForServer(serverURL, 30*time.Second); err != nil {
		cancel()
		if serverProcess != nil && serverProcess.Process != nil {
			_ = serverProcess.Process.Kill()
		}
		_ = pgContainer.Terminate(ctx)
		return nil, fmt.Errorf("server failed to become ready: %w", err)
	}

	return &TestContext{
		DB:            db,
		RawDB:         rawDB,
		Container:     pgContainer,
		ServerURL:     serverURL,
		DatabaseURL:   connStr,
		DataKey:       dataKey,
		Cipher:        cipher,
		HTTPClient:    &http.Client{Timeout: 10 * time.Second},
		Cancel:        cancel,
		ServerProcess: serverProcess,
		InlineServer:  inlineServer,
	}, nil
}

// startInlineServer starts the server in-process (no binary needed)
func startInlineServer(db *gorm.DB, cipher slosilo.SymmetricCipher, port string) (*server.Server, context.CancelFunc, error) {
	_, cancel := context.WithCancel(context.Background())

	// Create keystore
	keystore := store.NewKeyStore(db)

	// Register authenticators
	authnAuth := authn.New(db, cipher)
	authenticator.DefaultRegistry.Register(authnAuth)
	_ = authenticator.DefaultRegistry.Enable("authn")

	// Create and configure server
	s := server.NewServer(keystore, cipher, db, "127.0.0.1", port)
	endpoints.RegisterAll(s)

	// Start server in background
	go func() {
		_ = s.Start()
	}()

	return s, cancel, nil
}

// startBinary starts the conjurctl server binary
func startBinary(binaryPath, dbURL string, dataKey []byte, port string) (*exec.Cmd, context.CancelFunc, error) {
	ctx, cancel := context.WithCancel(context.Background())

	// Use --no-migrate since we already ran migrations in the test setup
	cmd := exec.CommandContext(ctx, binaryPath, "server", "--no-migrate", "-b", "127.0.0.1", "-p", port)
	cmd.Env = append(os.Environ(),
		"DATABASE_URL="+dbURL,
		"CONJUR_DATA_KEY="+base64.StdEncoding.EncodeToString(dataKey),
		// Enable JWT authenticator for integration tests
		"CONJUR_AUTHENTICATORS=authn,authn-jwt/raw",
		"CONJUR_ACCOUNT=cucumber",
	)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		cancel()
		return nil, nil, fmt.Errorf("failed to start binary: %w", err)
	}

	return cmd, cancel, nil
}

// waitForServer polls the server until it responds or times out
func waitForServer(serverURL string, timeout time.Duration) error {
	client := &http.Client{Timeout: 2 * time.Second}
	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		resp, err := client.Get(serverURL + "/")
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
		}
		time.Sleep(100 * time.Millisecond)
	}

	return fmt.Errorf("server did not become ready within %v", timeout)
}

// Close cleans up all test resources
func (tc *TestContext) Close(ctx context.Context) {
	if tc.Cancel != nil {
		tc.Cancel()
	}
	if tc.ServerProcess != nil && tc.ServerProcess.Process != nil {
		_ = tc.ServerProcess.Process.Kill()
		_ = tc.ServerProcess.Wait()
	}
	if tc.RawDB != nil {
		_ = tc.RawDB.Close()
	}
	if tc.Container != nil {
		_ = tc.Container.Terminate(ctx)
	}
}

// findProjectRoot locates the project root directory
func findProjectRoot() (string, error) {
	// Try relative paths from test directory
	paths := []string{
		"../..",
		"..",
		".",
	}

	for _, p := range paths {
		goMod := filepath.Join(p, "go.mod")
		if _, err := os.Stat(goMod); err == nil {
			return filepath.Abs(p)
		}
	}

	return "", fmt.Errorf("project root not found (looking for go.mod)")
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
