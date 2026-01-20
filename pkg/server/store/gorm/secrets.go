package gorm

import (
	"github.com/doodlesbykumbi/conjur-in-go/pkg/model"
	"github.com/doodlesbykumbi/conjur-in-go/pkg/server/store"

	"gorm.io/gorm"
)

// Ensure SecretsStore implements store.SecretsStore
var _ store.SecretsStore = (*SecretsStore)(nil)

// SecretsStore implements store.SecretsStore using GORM
type SecretsStore struct {
	db *gorm.DB
}

// NewSecretsStore creates a new SecretsStore
func NewSecretsStore(db *gorm.DB) *SecretsStore {
	return &SecretsStore{db: db}
}

// FetchSecret retrieves a secret by resource ID and optional version.
func (s *SecretsStore) FetchSecret(resourceID string, version string) (*store.Secret, error) {
	var secret model.Secret
	query := map[string]interface{}{"resource_id": resourceID}
	if version != "" {
		query["version"] = version
	}

	tx := s.db.Order("version desc").Where(query).First(&secret)
	if tx.Error != nil {
		if tx.Error == gorm.ErrRecordNotFound {
			return nil, store.ErrSecretNotFound
		}
		return nil, tx.Error
	}

	if secret.IsExpired() {
		return nil, store.ErrSecretExpired
	}

	return &store.Secret{
		ResourceID: secret.ResourceId,
		Value:      secret.Value,
		Version:    secret.Version,
		ExpiresAt:  secret.ExpiresAt,
	}, nil
}

// CreateSecret creates a new version of a secret.
func (s *SecretsStore) CreateSecret(resourceID string, value []byte) error {
	return s.db.Create(&model.Secret{
		ResourceId: resourceID,
		Value:      value,
	}).Error
}

// ExpireSecret clears the expiration on all versions of a secret.
func (s *SecretsStore) ExpireSecret(resourceID string) error {
	return s.db.Model(&model.Secret{}).Where("resource_id = ?", resourceID).Update("expires_at", nil).Error
}
