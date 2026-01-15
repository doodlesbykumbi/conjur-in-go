package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	gormpostgres "gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"conjur-in-go/pkg/slosilo"
)

// roleRetrieveKeyCmd represents the role retrieve-key command
var roleRetrieveKeyCmd = &cobra.Command{
	Use:   "retrieve-key <role_id>",
	Short: "Retrieve a role's API key",
	Long: `Retrieve the API key for a role.

The role_id should be in the format: account:kind:identifier
For example: myorg:user:admin or myorg:host:myapp

Example:
  conjurctl role retrieve-key myorg:user:admin
  conjurctl role retrieve-key myorg:host:myapp`,
	Args: cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		for _, roleID := range args {
			apiKey, err := retrieveKey(roleID)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Failed to retrieve key for %s: %v\n", roleID, err)
				os.Exit(1)
			}
			fmt.Println(apiKey)
		}
	},
}

func init() {
	roleCmd.AddCommand(roleRetrieveKeyCmd)
}

func retrieveKey(roleID string) (string, error) {
	// Get data key for encryption
	dataKeyB64, ok := os.LookupEnv("CONJUR_DATA_KEY")
	if !ok {
		return "", fmt.Errorf("CONJUR_DATA_KEY environment variable is required")
	}

	dataKey, err := base64.StdEncoding.DecodeString(dataKeyB64)
	if err != nil {
		return "", fmt.Errorf("failed to decode CONJUR_DATA_KEY: %w", err)
	}

	// Get database URL
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		return "", fmt.Errorf("DATABASE_URL environment variable is required")
	}

	// Connect to database
	db, err := gorm.Open(gormpostgres.New(gormpostgres.Config{
		DSN:                  dbURL,
		PreferSimpleProtocol: true,
	}), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		return "", fmt.Errorf("failed to connect to database: %w", err)
	}

	// Create cipher for key decryption
	cipher, err := slosilo.NewSymmetric(dataKey)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %w", err)
	}

	// Add cipher to DB context
	ctx := context.WithValue(context.Background(), "cipher", cipher)
	db = db.WithContext(ctx)

	// Get the encrypted API key
	var encryptedAPIKey []byte
	err = db.Raw(`SELECT api_key FROM credentials WHERE role_id = ?`, roleID).Scan(&encryptedAPIKey).Error
	if err != nil {
		return "", fmt.Errorf("role not found: %s", roleID)
	}

	if len(encryptedAPIKey) == 0 {
		return "", fmt.Errorf("no API key found for role: %s", roleID)
	}

	// Decrypt the API key
	apiKey, err := cipher.Decrypt([]byte(roleID), encryptedAPIKey)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt API key: %w", err)
	}

	return string(apiKey), nil
}
