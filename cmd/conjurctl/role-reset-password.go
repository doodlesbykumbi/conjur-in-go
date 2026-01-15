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

	"conjur-in-go/pkg/model"
	"conjur-in-go/pkg/slosilo"
)

// roleResetPasswordCmd represents the role reset-password command
var roleResetPasswordCmd = &cobra.Command{
	Use:   "reset-password <role_id>",
	Short: "Reset a role's password and rotate its API key",
	Long: `Reset the password for a role and generate a new API key.

The role_id should be in the format: account:kind:identifier
For example: myorg:user:admin or myorg:host:myapp

The new API key will be printed to stdout.

Example:
  conjurctl role reset-password myorg:user:admin`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		roleID := args[0]

		apiKey, err := resetPassword(roleID)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to reset password for %s: %v\n", roleID, err)
			os.Exit(1)
		}
		fmt.Println(apiKey)
	},
}

func init() {
	roleCmd.AddCommand(roleResetPasswordCmd)
}

func resetPassword(roleID string) (string, error) {
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

	// Create cipher for key encryption
	cipher, err := slosilo.NewSymmetric(dataKey)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %w", err)
	}

	// Add cipher to DB context
	ctx := context.WithValue(context.Background(), "cipher", cipher)
	db = db.WithContext(ctx)

	// Check if role exists
	var count int64
	db.Raw(`SELECT COUNT(*) FROM credentials WHERE role_id = ?`, roleID).Scan(&count)
	if count == 0 {
		return "", fmt.Errorf("role not found: %s", roleID)
	}

	// Generate new API key
	newAPIKey, err := model.GenerateAPIKey()
	if err != nil {
		return "", fmt.Errorf("failed to generate API key: %w", err)
	}

	// Encrypt the new API key
	encryptedAPIKey, err := cipher.Encrypt([]byte(roleID), newAPIKey)
	if err != nil {
		return "", fmt.Errorf("failed to encrypt API key: %w", err)
	}

	// Update the credentials
	if err := db.Exec(`UPDATE credentials SET api_key = ? WHERE role_id = ?`, encryptedAPIKey, roleID).Error; err != nil {
		return "", fmt.Errorf("failed to update credentials: %w", err)
	}

	return string(newAPIKey), nil
}
