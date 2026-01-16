package main

import (
	"encoding/base64"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"conjur-in-go/pkg/db"
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

	// Create cipher for key decryption
	cipher, err := slosilo.NewSymmetric(dataKey)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %w", err)
	}

	// Connect to database
	database, err := db.Connect(db.Config{Cipher: cipher})
	if err != nil {
		return "", err
	}

	// Get the encrypted API key
	var result struct {
		ApiKey []byte `gorm:"column:api_key"`
	}
	err = database.Raw(`SELECT api_key FROM credentials WHERE role_id = ?`, roleID).Scan(&result).Error
	if err != nil {
		return "", fmt.Errorf("role not found: %s", roleID)
	}

	if len(result.ApiKey) == 0 {
		return "", fmt.Errorf("no API key found for role: %s", roleID)
	}

	// Decrypt the API key
	apiKey, err := cipher.Decrypt([]byte(roleID), result.ApiKey)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt API key: %w", err)
	}

	return string(apiKey), nil
}
