package gorm

import (
	"strings"

	"gorm.io/gorm"

	"github.com/doodlesbykumbi/conjur-in-go/pkg/model"
	"github.com/doodlesbykumbi/conjur-in-go/pkg/server/store"
	"github.com/doodlesbykumbi/conjur-in-go/pkg/slosilo"
	slstore "github.com/doodlesbykumbi/conjur-in-go/pkg/slosilo/store"
)

// Ensure AccountsStore implements store.AccountsStore
var _ store.AccountsStore = (*AccountsStore)(nil)

// AccountsStore implements store.AccountsStore using GORM
type AccountsStore struct {
	db       *gorm.DB
	keystore *slstore.KeyStore
	cipher   slosilo.SymmetricCipher
}

// NewAccountsStore creates a new AccountsStore
func NewAccountsStore(db *gorm.DB, keystore *slstore.KeyStore, cipher slosilo.SymmetricCipher) *AccountsStore {
	return &AccountsStore{db: db, keystore: keystore, cipher: cipher}
}

// ListAccounts returns all account names
func (s *AccountsStore) ListAccounts() ([]string, error) {
	keys, err := s.keystore.List()
	if err != nil {
		return nil, err
	}

	accounts := make([]string, 0)
	for _, keyID := range keys {
		if strings.HasPrefix(keyID, "authn:") {
			accountName := strings.TrimPrefix(keyID, "authn:")
			if accountName != "!" {
				accounts = append(accounts, accountName)
			}
		}
	}
	return accounts, nil
}

// AccountExists checks if an account exists
func (s *AccountsStore) AccountExists(accountName string) bool {
	keyID := "authn:" + accountName
	_, err := s.keystore.Get(keyID)
	return err == nil
}

// CreateAccount creates a new account with signing key and admin user
func (s *AccountsStore) CreateAccount(accountName string) (string, error) {
	key, err := slosilo.GenerateKey()
	if err != nil {
		return "", err
	}

	keyID := "authn:" + accountName
	if err := s.keystore.Put(keyID, key); err != nil {
		return "", err
	}

	adminRoleID := accountName + ":user:admin"
	if err := s.db.Exec(`INSERT INTO roles (role_id) VALUES (?) ON CONFLICT DO NOTHING`, adminRoleID).Error; err != nil {
		return "", err
	}

	policyRoleID := accountName + ":policy:root"
	if err := s.db.Exec(`INSERT INTO roles (role_id) VALUES (?) ON CONFLICT DO NOTHING`, policyRoleID).Error; err != nil {
		return "", err
	}

	if err := s.db.Exec(`INSERT INTO resources (resource_id, owner_id) VALUES (?, ?) ON CONFLICT DO NOTHING`, adminRoleID, adminRoleID).Error; err != nil {
		return "", err
	}

	if err := s.db.Exec(`INSERT INTO resources (resource_id, owner_id) VALUES (?, ?) ON CONFLICT DO NOTHING`, policyRoleID, adminRoleID).Error; err != nil {
		return "", err
	}

	apiKey, err := model.GenerateAPIKey()
	if err != nil {
		return "", err
	}

	encryptedAPIKey, err := s.cipher.Encrypt([]byte(adminRoleID), apiKey)
	if err != nil {
		return "", err
	}

	if err := s.db.Exec(`
		INSERT INTO credentials (role_id, api_key) VALUES (?, ?)
		ON CONFLICT (role_id) DO UPDATE SET api_key = EXCLUDED.api_key
	`, adminRoleID, encryptedAPIKey).Error; err != nil {
		return "", err
	}

	return string(apiKey), nil
}

// DeleteAccount deletes an account and all its associated data
func (s *AccountsStore) DeleteAccount(accountName string) error {
	if err := s.db.Exec(`DELETE FROM credentials WHERE role_id LIKE ?`, accountName+":%").Error; err != nil {
		return err
	}

	if err := s.db.Exec(`DELETE FROM secrets WHERE resource_id LIKE ?`, accountName+":%").Error; err != nil {
		return err
	}

	if err := s.db.Exec(`DELETE FROM permissions WHERE role_id LIKE ? OR resource_id LIKE ?`, accountName+":%", accountName+":%").Error; err != nil {
		return err
	}

	if err := s.db.Exec(`DELETE FROM role_memberships WHERE role_id LIKE ? OR member_id LIKE ?`, accountName+":%", accountName+":%").Error; err != nil {
		return err
	}

	if err := s.db.Exec(`DELETE FROM annotations WHERE resource_id LIKE ?`, accountName+":%").Error; err != nil {
		return err
	}

	if err := s.db.Exec(`DELETE FROM resources WHERE resource_id LIKE ?`, accountName+":%").Error; err != nil {
		return err
	}

	if err := s.db.Exec(`DELETE FROM roles WHERE role_id LIKE ?`, accountName+":%").Error; err != nil {
		return err
	}

	keyID := "authn:" + accountName
	if err := s.keystore.Delete(keyID); err != nil {
		return err
	}

	return nil
}
