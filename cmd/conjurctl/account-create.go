package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/doodlesbykumbi/conjur-in-go/pkg/db"
	"github.com/doodlesbykumbi/conjur-in-go/pkg/model"
	"github.com/doodlesbykumbi/conjur-in-go/pkg/slosilo"
)

// accountCreateCmd represents the account create command
var accountCreateCmd = &cobra.Command{
	Use:   "create [name]",
	Short: "Create an organization account",
	Long: `Create an organization account.

This command creates a new account with a 2048-bit RSA private key for signing
auth tokens. The CONJUR_DATA_KEY must be available in the environment since it's
used to encrypt the token-signing key in the database.

If no account name is provided, 'default' will be used.

The admin user's API key will be output to STDOUT.

Example:
  conjurctl account create
  conjurctl account create myorg
  conjurctl account create --name myorg`,
	Run: func(cmd *cobra.Command, args []string) {
		name, _ := cmd.Flags().GetString("name")
		if name == "" && len(args) > 0 {
			name = args[0]
		}
		if name == "" {
			name = "default"
		}

		apiKey, publicKey, err := createAccount(name)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to create account: %v\n", err)
			os.Exit(1)
		}

		fmt.Fprintf(os.Stderr, "Created new account '%s'\n", name)
		fmt.Printf("Token-Signing Public Key: %s", publicKey)
		fmt.Printf("API key for admin: %s\n", apiKey)
	},
}

func init() {
	accountCmd.AddCommand(accountCreateCmd)
	accountCreateCmd.Flags().StringP("name", "n", "", "Account name (default: 'default')")
}

func createAccount(accountName string) (apiKey string, publicKey string, err error) {
	// Get data key for encryption
	dataKeyB64, ok := os.LookupEnv("CONJUR_DATA_KEY")
	if !ok {
		return "", "", fmt.Errorf("CONJUR_DATA_KEY environment variable is required")
	}

	dataKey, err := base64.StdEncoding.DecodeString(dataKeyB64)
	if err != nil {
		return "", "", fmt.Errorf("invalid CONJUR_DATA_KEY: %w", err)
	}

	cipher, err := slosilo.NewSymmetric(dataKey)
	if err != nil {
		return "", "", fmt.Errorf("failed to create cipher: %w", err)
	}

	// Connect to database
	database, err := db.Connect(db.Config{Cipher: cipher})
	if err != nil {
		return "", "", err
	}

	// Check if account already exists
	var existingKey model.Key
	keyId := "authn:" + accountName
	if err := database.Where("id = ?", keyId).First(&existingKey).Error; err == nil {
		return "", "", fmt.Errorf("account '%s' already exists", accountName)
	}

	// Generate a new RSA key for token signing
	key, err := slosilo.GenerateKey()
	if err != nil {
		return "", "", fmt.Errorf("failed to generate signing key: %w", err)
	}

	// Serialize and encrypt the key
	keyBytes, err := key.Serialize()
	if err != nil {
		return "", "", fmt.Errorf("failed to serialize key: %w", err)
	}

	encryptedKey, err := cipher.Encrypt([]byte(keyId), keyBytes)
	if err != nil {
		return "", "", fmt.Errorf("failed to encrypt key: %w", err)
	}

	// Store the key in slosilo_keystore
	storedKey := model.Key{
		Id:          keyId,
		Key:         encryptedKey,
		Fingerprint: key.Fingerprint(),
	}

	if err := database.Create(&storedKey).Error; err != nil {
		return "", "", fmt.Errorf("failed to store signing key: %w", err)
	}

	// Get the public key in PEM format
	publicKeyPEM := string(key.PublicPem())

	// Create the admin user role
	adminRoleId := fmt.Sprintf("%s:user:admin", accountName)
	adminRole := struct {
		RoleId string `gorm:"column:role_id;primaryKey"`
	}{
		RoleId: adminRoleId,
	}

	if err := database.Table("roles").Create(&adminRole).Error; err != nil {
		return "", "", fmt.Errorf("failed to create admin role: %w", err)
	}

	// Create the root policy role
	policyRoleId := fmt.Sprintf("%s:policy:root", accountName)
	policyRole := struct {
		RoleId string `gorm:"column:role_id;primaryKey"`
	}{
		RoleId: policyRoleId,
	}

	if err := database.Table("roles").Create(&policyRole).Error; err != nil {
		return "", "", fmt.Errorf("failed to create policy role: %w", err)
	}

	// Create the admin user resource (owned by admin role)
	adminResourceId := fmt.Sprintf("%s:user:admin", accountName)
	adminResource := struct {
		ResourceId string `gorm:"column:resource_id;primaryKey"`
		OwnerId    string `gorm:"column:owner_id"`
	}{
		ResourceId: adminResourceId,
		OwnerId:    adminRoleId,
	}

	if err := database.Table("resources").Create(&adminResource).Error; err != nil {
		return "", "", fmt.Errorf("failed to create admin resource: %w", err)
	}

	// Create the root policy resource (owned by admin role)
	policyResourceId := fmt.Sprintf("%s:policy:root", accountName)
	policyResource := struct {
		ResourceId string `gorm:"column:resource_id;primaryKey"`
		OwnerId    string `gorm:"column:owner_id"`
	}{
		ResourceId: policyResourceId,
		OwnerId:    adminRoleId,
	}

	if err := database.Table("resources").Create(&policyResource).Error; err != nil {
		return "", "", fmt.Errorf("failed to create policy resource: %w", err)
	}

	// Generate API key for admin
	apiKeyBytes := make([]byte, 32)
	if _, err := rand.Read(apiKeyBytes); err != nil {
		return "", "", fmt.Errorf("failed to generate API key: %w", err)
	}
	generatedAPIKey := base64.URLEncoding.EncodeToString(apiKeyBytes)

	// Encrypt the API key before storing
	encryptedApiKey, err := cipher.Encrypt([]byte(adminRoleId), []byte(generatedAPIKey))
	if err != nil {
		return "", "", fmt.Errorf("failed to encrypt API key: %w", err)
	}

	// Store credentials for admin using raw SQL to avoid GORM issues with bytea
	if err := database.Exec(`
		INSERT INTO credentials (role_id, api_key) VALUES (?, ?)
		ON CONFLICT (role_id) DO UPDATE SET api_key = EXCLUDED.api_key
	`, adminRoleId, encryptedApiKey).Error; err != nil {
		return "", "", fmt.Errorf("failed to create admin credentials: %w", err)
	}

	return generatedAPIKey, publicKeyPEM, nil
}
