package gorm

import (
	"crypto/subtle"

	"gorm.io/gorm"

	"github.com/doodlesbykumbi/conjur-in-go/pkg/model"
	"github.com/doodlesbykumbi/conjur-in-go/pkg/server/store"
	"github.com/doodlesbykumbi/conjur-in-go/pkg/slosilo"
)

// Ensure AuthenticateStore implements store.AuthenticateStore
var _ store.AuthenticateStore = (*AuthenticateStore)(nil)

// AuthenticateStore implements store.AuthenticateStore using GORM
type AuthenticateStore struct {
	db     *gorm.DB
	cipher slosilo.SymmetricCipher
}

// NewAuthenticateStore creates a new AuthenticateStore
func NewAuthenticateStore(db *gorm.DB, cipher slosilo.SymmetricCipher) *AuthenticateStore {
	return &AuthenticateStore{db: db, cipher: cipher}
}

// GetCredential retrieves credentials for a role
func (s *AuthenticateStore) GetCredential(roleID string) (*model.Credential, error) {
	var credential model.Credential
	tx := s.db.Where(&struct{ RoleId string }{RoleId: roleID}).First(&credential)
	if tx.Error != nil {
		return nil, tx.Error
	}
	return &credential, nil
}

// ValidateAPIKey validates an API key against stored credentials
func (s *AuthenticateStore) ValidateAPIKey(credential *model.Credential, apiKey []byte) bool {
	return subtle.ConstantTimeCompare(credential.ApiKey, apiKey) == 1
}

// RotateAPIKey generates and stores a new API key for a role
func (s *AuthenticateStore) RotateAPIKey(roleID string) ([]byte, error) {
	newApiKey, err := model.GenerateAPIKey()
	if err != nil {
		return nil, err
	}

	encryptedKey, err := s.cipher.Encrypt([]byte(roleID), newApiKey)
	if err != nil {
		return nil, err
	}

	tx := s.db.Model(&model.Credential{}).Where("role_id = ?", roleID).Updates(map[string]interface{}{
		"api_key":        encryptedKey,
		"encrypted_hash": encryptedKey,
	})
	if tx.Error != nil {
		return nil, tx.Error
	}

	return newApiKey, nil
}

// UpdatePassword updates the password/API key for a role
func (s *AuthenticateStore) UpdatePassword(roleID string, newPassword []byte) error {
	encryptedKey, err := s.cipher.Encrypt([]byte(roleID), newPassword)
	if err != nil {
		return err
	}

	tx := s.db.Model(&model.Credential{}).Where("role_id = ?", roleID).Updates(map[string]interface{}{
		"api_key":        encryptedKey,
		"encrypted_hash": encryptedKey,
	})
	return tx.Error
}
