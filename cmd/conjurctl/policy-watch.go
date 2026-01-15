package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/spf13/cobra"
	gormpostgres "gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"conjur-in-go/pkg/policy"
	"conjur-in-go/pkg/slosilo"
)

// policyWatchCmd represents the policy watch command
var policyWatchCmd = &cobra.Command{
	Use:   "watch <account> <file>",
	Short: "Watch a file and reload the policy if it's modified",
	Long: `Watch a file and reload the policy when it changes.

To trigger a reload of the policy, replace the contents of the watched file
with the path to the policy. The path must be visible to the process running
"conjurctl watch".

Example:
  conjurctl policy watch myorg /run/conjur/policy/load`,
	Args: cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		account := args[0]
		filename := args[1]

		if err := watchPolicy(account, filename); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to watch policy: %v\n", err)
			os.Exit(1)
		}
	},
}

func init() {
	policyCmd.AddCommand(policyWatchCmd)
}

func watchPolicy(account, filename string) error {
	// Get data key for encryption
	dataKeyB64, ok := os.LookupEnv("CONJUR_DATA_KEY")
	if !ok {
		return fmt.Errorf("CONJUR_DATA_KEY environment variable is required")
	}

	dataKey, err := base64.StdEncoding.DecodeString(dataKeyB64)
	if err != nil {
		return fmt.Errorf("failed to decode CONJUR_DATA_KEY: %w", err)
	}

	// Get database URL
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		return fmt.Errorf("DATABASE_URL environment variable is required")
	}

	// Connect to database
	db, err := gorm.Open(gormpostgres.New(gormpostgres.Config{
		DSN:                  dbURL,
		PreferSimpleProtocol: true,
	}), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}

	// Create cipher
	cipher, err := slosilo.NewSymmetric(dataKey)
	if err != nil {
		return fmt.Errorf("failed to create cipher: %w", err)
	}

	// Add cipher to DB context
	ctx := context.WithValue(context.Background(), "cipher", cipher)
	db = db.WithContext(ctx)

	// Create file watcher
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("failed to create watcher: %w", err)
	}
	defer func() { _ = watcher.Close() }()

	// Add file to watcher
	if err := watcher.Add(filename); err != nil {
		return fmt.Errorf("failed to watch file %s: %w", filename, err)
	}

	fmt.Printf("Watching %s for policy changes (account: %s)\n", filename, account)

	// Handle signals for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	for {
		select {
		case event, ok := <-watcher.Events:
			if !ok {
				return nil
			}
			if event.Op&fsnotify.Write == fsnotify.Write || event.Op&fsnotify.Create == fsnotify.Create {
				fmt.Printf("[%s] File modified, reloading policy...\n", time.Now().Format(time.RFC3339))

				// Read the file to get the policy path
				content, err := os.ReadFile(filename)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Error reading file: %v\n", err)
					continue
				}

				policyPath := string(content)
				if policyPath == "" {
					continue
				}

				// Load the policy
				if err := loadPolicyFromPath(db, cipher, account, policyPath); err != nil {
					fmt.Fprintf(os.Stderr, "Error loading policy: %v\n", err)
				} else {
					fmt.Printf("Policy loaded successfully from %s\n", policyPath)
				}
			}
		case err, ok := <-watcher.Errors:
			if !ok {
				return nil
			}
			fmt.Fprintf(os.Stderr, "Watcher error: %v\n", err)
		case <-sigChan:
			fmt.Println("\nShutting down...")
			return nil
		}
	}
}

func loadPolicyFromPath(db *gorm.DB, cipher slosilo.SymmetricCipher, account, policyPath string) error {
	file, err := os.Open(policyPath)
	if err != nil {
		return fmt.Errorf("failed to open policy file: %w", err)
	}
	defer func() { _ = file.Close() }()

	loader := policy.NewLoader(db, cipher, account)
	_, err = loader.LoadFromReader(file)
	return err
}
