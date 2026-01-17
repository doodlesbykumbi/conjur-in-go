package main

import (
	"encoding/base64"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/doodlesbykumbi/conjur-in-go/pkg/db"
	"github.com/doodlesbykumbi/conjur-in-go/pkg/slosilo"
	"github.com/doodlesbykumbi/conjur-in-go/pkg/slosilo/store"
)

// accountDeleteCmd represents the account delete command
var accountDeleteCmd = &cobra.Command{
	Use:   "delete <name>",
	Short: "Delete an organization account",
	Long: `Delete an organization account and all its associated data.

This command deletes the account's signing key, all roles, resources,
credentials, secrets, and permissions associated with the account.

Example:
  conjurctl account delete myorg`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		name := args[0]

		if err := deleteAccount(name); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to delete account: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("Deleted account '%s'\n", name)
	},
}

func init() {
	accountCmd.AddCommand(accountDeleteCmd)
}

func deleteAccount(accountName string) error {
	// Get data key for encryption
	dataKeyB64, ok := os.LookupEnv("CONJUR_DATA_KEY")
	if !ok {
		return fmt.Errorf("CONJUR_DATA_KEY environment variable is required")
	}

	dataKey, err := base64.StdEncoding.DecodeString(dataKeyB64)
	if err != nil {
		return fmt.Errorf("failed to decode CONJUR_DATA_KEY: %w", err)
	}

	// Create cipher for key decryption
	cipher, err := slosilo.NewSymmetric(dataKey)
	if err != nil {
		return fmt.Errorf("failed to create cipher: %w", err)
	}

	// Connect to database
	database, err := db.Connect(db.Config{Cipher: cipher})
	if err != nil {
		return err
	}

	// Create keystore
	keystore := store.NewKeyStore(database)

	// Check if account exists
	keyID := "authn:" + accountName
	if _, err := keystore.Get(keyID); err != nil {
		return fmt.Errorf("account '%s' does not exist", accountName)
	}

	// Delete in order to respect foreign key constraints
	// 1. Delete credentials for this account
	if err := database.Exec(`DELETE FROM credentials WHERE role_id LIKE ?`, accountName+":%").Error; err != nil {
		return fmt.Errorf("failed to delete credentials: %w", err)
	}

	// 2. Delete secrets for this account
	if err := database.Exec(`DELETE FROM secrets WHERE resource_id LIKE ?`, accountName+":%").Error; err != nil {
		return fmt.Errorf("failed to delete secrets: %w", err)
	}

	// 3. Delete permissions for this account
	if err := database.Exec(`DELETE FROM permissions WHERE role_id LIKE ? OR resource_id LIKE ?`, accountName+":%", accountName+":%").Error; err != nil {
		return fmt.Errorf("failed to delete permissions: %w", err)
	}

	// 4. Delete role memberships for this account
	if err := database.Exec(`DELETE FROM role_memberships WHERE role_id LIKE ? OR member_id LIKE ?`, accountName+":%", accountName+":%").Error; err != nil {
		return fmt.Errorf("failed to delete role memberships: %w", err)
	}

	// 5. Delete annotations for this account
	if err := database.Exec(`DELETE FROM annotations WHERE resource_id LIKE ?`, accountName+":%").Error; err != nil {
		return fmt.Errorf("failed to delete annotations: %w", err)
	}

	// 6. Delete resources for this account
	if err := database.Exec(`DELETE FROM resources WHERE resource_id LIKE ?`, accountName+":%").Error; err != nil {
		return fmt.Errorf("failed to delete resources: %w", err)
	}

	// 7. Delete roles for this account
	if err := database.Exec(`DELETE FROM roles WHERE role_id LIKE ?`, accountName+":%").Error; err != nil {
		return fmt.Errorf("failed to delete roles: %w", err)
	}

	// 8. Delete the signing key from the keystore
	if err := keystore.Delete(keyID); err != nil {
		return fmt.Errorf("failed to delete signing key: %w", err)
	}

	return nil
}
