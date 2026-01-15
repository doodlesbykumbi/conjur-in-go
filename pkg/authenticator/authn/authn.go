package authn

import (
	"context"
	"errors"

	"conjur-in-go/pkg/authenticator"
	"conjur-in-go/pkg/slosilo"

	"gorm.io/gorm"
)

// Authenticator implements API key authentication
type Authenticator struct {
	db     *gorm.DB
	cipher slosilo.SymmetricCipher
}

// New creates a new API key authenticator
func New(db *gorm.DB, cipher slosilo.SymmetricCipher) *Authenticator {
	return &Authenticator{
		db:     db,
		cipher: cipher,
	}
}

// Name returns the authenticator name
func (a *Authenticator) Name() string {
	return "authn"
}

// Authenticate validates an API key and returns the role ID
func (a *Authenticator) Authenticate(ctx context.Context, input authenticator.AuthenticatorInput) (string, error) {
	roleID := input.Account + ":user:" + input.Login
	if input.Login == "" {
		return "", errors.New("login is required")
	}

	// Handle host login format
	if len(input.Login) > 5 && input.Login[:5] == "host/" {
		roleID = input.Account + ":host:" + input.Login[5:]
	}

	// Get stored API key
	var result struct {
		APIKey []byte `gorm:"column:api_key"`
	}
	dbResult := a.db.Raw(`SELECT api_key FROM credentials WHERE role_id = ?`, roleID).Scan(&result)
	if dbResult.Error != nil {
		return "", errors.New("authentication failed")
	}
	if dbResult.RowsAffected == 0 {
		return "", errors.New("role not found")
	}

	if len(result.APIKey) == 0 {
		return "", errors.New("authentication failed")
	}
	storedAPIKey := result.APIKey

	// Decrypt and compare
	decryptedAPIKey, err := a.cipher.Decrypt([]byte(roleID), storedAPIKey)
	if err != nil {
		return "", errors.New("authentication failed")
	}

	if string(decryptedAPIKey) != string(input.Credentials) {
		return "", errors.New("authentication failed")
	}

	return roleID, nil
}

// Status checks if the authenticator is healthy
func (a *Authenticator) Status(ctx context.Context, account string, serviceID string) error {
	// Basic authn is always healthy if we can reach the database
	return a.db.Exec("SELECT 1").Error
}

func init() {
	// Note: The actual registration happens in server setup since we need db/cipher
}
