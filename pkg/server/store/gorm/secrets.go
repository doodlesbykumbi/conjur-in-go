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

// FetchSecretsWithPrefix retrieves the latest version of all secrets matching a prefix pattern.
func (s *SecretsStore) FetchSecretsWithPrefix(prefix string) ([]store.Secret, error) {
	type secretRow struct {
		ResourceID string `gorm:"column:resource_id"`
		Value      []byte
		Version    int
	}
	var rows []secretRow

	// Get the latest version of each secret matching the pattern
	err := s.db.Raw(`
		WITH max_versions AS (
			SELECT resource_id, MAX(version) as version
			FROM secrets
			WHERE resource_id LIKE ?
			GROUP BY resource_id
		)
		SELECT s.resource_id, s.value, s.version
		FROM secrets s
		JOIN max_versions mv ON s.resource_id = mv.resource_id AND s.version = mv.version
		ORDER BY s.resource_id
	`, prefix+"%").Scan(&rows).Error
	if err != nil {
		return nil, err
	}

	secrets := make([]store.Secret, 0, len(rows))
	for _, row := range rows {
		secrets = append(secrets, store.Secret{
			ResourceID: row.ResourceID,
			Value:      row.Value,
			Version:    row.Version,
		})
	}
	return secrets, nil
}
