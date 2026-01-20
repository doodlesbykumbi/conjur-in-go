package integration

import (
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
	"time"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/doodlesbykumbi/conjur-in-go/pkg/config"
	"github.com/doodlesbykumbi/conjur-in-go/pkg/server"
	"github.com/doodlesbykumbi/conjur-in-go/pkg/server/endpoints"
	"github.com/doodlesbykumbi/conjur-in-go/pkg/slosilo"
	"github.com/doodlesbykumbi/conjur-in-go/pkg/slosilo/store"
)

// portCounter is used to allocate unique ports for each test server
var portCounter int32 = 19000

// ServerConfig holds configuration for a test Conjur server instance
type ServerConfig struct {
	Authenticators []string
}

// DefaultServerConfig returns the default server configuration
func DefaultServerConfig() ServerConfig {
	return ServerConfig{
		Authenticators: []string{"authn"},
	}
}

// ServerInstance represents a running Conjur server for a single test
type ServerInstance struct {
	Server        *server.Server
	ServerURL     string
	Port          int
	Config        ServerConfig
	cancel        context.CancelFunc
	listener      net.Listener
	oldEnv        string    // Previous CONJUR_AUTHENTICATORS value for cleanup
	serverProcess *exec.Cmd // For binary mode
	inlineMode    bool
}

// StartServer creates and starts a new Conjur server instance with the given DB URL.
// This supports both inline and binary modes based on how the test suite was started.
func StartServer(tc *TestContext, dbURL string, cfg ServerConfig) (*ServerInstance, error) {
	if tc.InlineMode {
		return startInlineServerInstance(dbURL, tc.Cipher, cfg)
	}
	return startBinaryServerInstance(tc.BinaryPath, dbURL, tc.DataKey, cfg)
}

// startInlineServerInstance starts an in-process server
func startInlineServerInstance(dbURL string, cipher slosilo.SymmetricCipher, cfg ServerConfig) (*ServerInstance, error) {
	// Allocate a unique port
	port := int(atomic.AddInt32(&portCounter, 1))

	// Save old env and set new authenticators config
	oldEnv := os.Getenv("CONJUR_AUTHENTICATORS")
	_ = os.Setenv("CONJUR_AUTHENTICATORS", strings.Join(cfg.Authenticators, ","))

	// Force config reload to pick up new authenticators
	_ = config.Reload()

	// Create DB connection for this server instance
	db, err := gorm.Open(postgres.New(postgres.Config{
		DSN:                  dbURL,
		PreferSimpleProtocol: true,
	}), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	// Add cipher to DB context
	dbCtx := context.WithValue(context.Background(), "cipher", cipher)
	db = db.WithContext(dbCtx)

	// Create keystore
	keystore := store.NewKeyStore(db)

	// Create server
	s := server.NewServer(keystore, cipher, db, "127.0.0.1", fmt.Sprintf("%d", port))
	endpoints.RegisterAll(s)

	// Create a listener to get the actual port
	listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return nil, fmt.Errorf("failed to create listener on port %d: %w", port, err)
	}

	_, cancel := context.WithCancel(context.Background())

	instance := &ServerInstance{
		Server:     s,
		ServerURL:  fmt.Sprintf("http://127.0.0.1:%d", port),
		Port:       port,
		Config:     cfg,
		cancel:     cancel,
		listener:   listener,
		oldEnv:     oldEnv,
		inlineMode: true,
	}

	// Start server in background using the listener
	go func() {
		_ = s.StartWithListener(listener)
	}()

	// Wait for server to be ready
	if err := waitForServerWithTimeout(instance.ServerURL, 10*time.Second); err != nil {
		instance.Stop()
		return nil, fmt.Errorf("server failed to become ready: %w", err)
	}

	return instance, nil
}

// startBinaryServerInstance starts a server using the conjurctl binary
func startBinaryServerInstance(binaryPath, dbURL string, dataKey []byte, cfg ServerConfig) (*ServerInstance, error) {
	// Allocate a unique port
	port := int(atomic.AddInt32(&portCounter, 1))
	portStr := fmt.Sprintf("%d", port)

	ctx, cancel := context.WithCancel(context.Background())

	cmd := exec.CommandContext(ctx, binaryPath, "server", "--no-migrate", "-b", "127.0.0.1", "-p", portStr)
	cmd.Env = append(os.Environ(),
		"DATABASE_URL="+dbURL,
		"CONJUR_DATA_KEY="+base64.StdEncoding.EncodeToString(dataKey),
		"CONJUR_AUTHENTICATORS="+strings.Join(cfg.Authenticators, ","),
	)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		cancel()
		return nil, fmt.Errorf("failed to start binary: %w", err)
	}

	instance := &ServerInstance{
		ServerURL:     fmt.Sprintf("http://127.0.0.1:%d", port),
		Port:          port,
		Config:        cfg,
		cancel:        cancel,
		serverProcess: cmd,
		inlineMode:    false,
	}

	// Wait for server to be ready
	if err := waitForServerWithTimeout(instance.ServerURL, 30*time.Second); err != nil {
		instance.Stop()
		return nil, fmt.Errorf("server failed to become ready: %w", err)
	}

	return instance, nil
}

// Stop shuts down the server instance and restores environment
func (si *ServerInstance) Stop() {
	if si.cancel != nil {
		si.cancel()
	}
	if si.listener != nil {
		_ = si.listener.Close()
	}
	if si.serverProcess != nil && si.serverProcess.Process != nil {
		_ = si.serverProcess.Process.Kill()
		_ = si.serverProcess.Wait()
	}
	// Restore old environment (only for inline mode)
	if si.inlineMode {
		if si.oldEnv != "" {
			_ = os.Setenv("CONJUR_AUTHENTICATORS", si.oldEnv)
		} else {
			_ = os.Unsetenv("CONJUR_AUTHENTICATORS")
		}
	}
}

// waitForServerWithTimeout polls the server until it responds or times out
func waitForServerWithTimeout(serverURL string, timeout time.Duration) error {
	return waitForServer(serverURL, timeout)
}
