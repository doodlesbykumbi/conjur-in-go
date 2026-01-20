package gorm

import (
	"fmt"
	"strings"
	"time"

	"gorm.io/gorm"

	"github.com/doodlesbykumbi/conjur-in-go/pkg/model"
	"github.com/doodlesbykumbi/conjur-in-go/pkg/server/store"
	"github.com/doodlesbykumbi/conjur-in-go/pkg/slosilo"
)

// Ensure HostFactoryStore implements store.HostFactoryStore
var _ store.HostFactoryStore = (*HostFactoryStore)(nil)

// HostFactoryStore implements store.HostFactoryStore using GORM
type HostFactoryStore struct {
	db     *gorm.DB
	cipher slosilo.SymmetricCipher
}

// NewHostFactoryStore creates a new HostFactoryStore
func NewHostFactoryStore(db *gorm.DB, cipher slosilo.SymmetricCipher) *HostFactoryStore {
	return &HostFactoryStore{db: db, cipher: cipher}
}

// GetResourceKind returns the kind of a resource
func (s *HostFactoryStore) GetResourceKind(resourceID string) string {
	var kind string
	s.db.Raw(`SELECT kind(resource_id) FROM resources WHERE resource_id = ?`, resourceID).Scan(&kind)
	return kind
}

// CreateToken creates a host factory token and returns the plain token
func (s *HostFactoryStore) CreateToken(hostFactoryID string, expiration time.Time, cidr []string) (store.HostFactoryToken, error) {
	plainToken := model.GenerateToken()
	tokenHash := model.HashToken(plainToken)

	encryptedToken, err := s.cipher.Encrypt([]byte(tokenHash), []byte(plainToken))
	if err != nil {
		return store.HostFactoryToken{}, fmt.Errorf("failed to encrypt token: %w", err)
	}

	cidrArray := "{}"
	if len(cidr) > 0 {
		cidrArray = "{" + strings.Join(cidr, ",") + "}"
	}

	hfToken := model.HostFactoryToken{
		TokenSHA256: tokenHash,
		Token:       encryptedToken,
		ResourceID:  hostFactoryID,
		CIDR:        cidrArray,
		Expiration:  expiration,
		PlainToken:  plainToken,
	}

	if err := s.db.Create(&hfToken).Error; err != nil {
		return store.HostFactoryToken{}, fmt.Errorf("failed to create token: %w", err)
	}

	return store.HostFactoryToken{
		Token:      plainToken,
		Expiration: expiration,
		CIDR:       cidr,
		ResourceID: hostFactoryID,
	}, nil
}

// FindToken finds a token by plain token value
func (s *HostFactoryStore) FindToken(plainToken string) (*model.HostFactoryToken, error) {
	tokenHash := model.HashToken(plainToken)
	var hfToken model.HostFactoryToken
	if err := s.db.Where("token_sha256 = ?", tokenHash).First(&hfToken).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, nil
		}
		return nil, err
	}
	return &hfToken, nil
}

// ValidateToken validates and decrypts a token
func (s *HostFactoryStore) ValidateToken(hfToken *model.HostFactoryToken, plainToken string) bool {
	decryptedToken, err := s.cipher.Decrypt([]byte(hfToken.TokenSHA256), hfToken.Token)
	if err != nil || string(decryptedToken) != plainToken {
		return false
	}
	return true
}

// DeleteToken deletes a host factory token
func (s *HostFactoryStore) DeleteToken(hfToken *model.HostFactoryToken) error {
	return s.db.Delete(hfToken).Error
}

// RoleExists checks if a role exists
func (s *HostFactoryStore) RoleExists(roleID string) bool {
	var exists bool
	s.db.Raw(`SELECT EXISTS(SELECT 1 FROM roles WHERE role_id = ?)`, roleID).Scan(&exists)
	return exists
}

// GetResourceOwner gets the owner of a resource
func (s *HostFactoryStore) GetResourceOwner(resourceID string) string {
	var ownerID string
	s.db.Raw(`SELECT owner_id FROM resources WHERE resource_id = ?`, resourceID).Scan(&ownerID)
	return ownerID
}

// CreateHost creates a host with role, resource, and credentials
func (s *HostFactoryStore) CreateHost(hostRoleID, ownerID, apiKey string) error {
	encryptedAPIKey, err := s.cipher.Encrypt([]byte(hostRoleID), []byte(apiKey))
	if err != nil {
		return fmt.Errorf("failed to encrypt API key: %w", err)
	}

	if err := s.db.Exec(`INSERT INTO roles (role_id, created_at) VALUES (?, NOW())`, hostRoleID).Error; err != nil {
		return fmt.Errorf("failed to create host role: %w", err)
	}

	if err := s.db.Exec(`INSERT INTO resources (resource_id, owner_id, created_at) VALUES (?, ?, NOW())`,
		hostRoleID, ownerID).Error; err != nil {
		return fmt.Errorf("failed to create host resource: %w", err)
	}

	if err := s.db.Exec(`INSERT INTO credentials (role_id, api_key, encrypted_hash) VALUES (?, ?, ?)`,
		hostRoleID, encryptedAPIKey, encryptedAPIKey).Error; err != nil {
		return fmt.Errorf("failed to create host credential: %w", err)
	}

	return nil
}

// AddHostToLayers adds a host to layers associated with a host factory
func (s *HostFactoryStore) AddHostToLayers(hostFactoryID, hostRoleID, account string) error {
	var layers []string
	s.db.Raw(`
		SELECT rm.member_id FROM role_memberships rm
		WHERE rm.role_id = ? AND rm.member_id LIKE ?
	`, hostFactoryID, account+":%:layer:%").Pluck("member_id", &layers)

	for _, layerID := range layers {
		s.db.Exec(`INSERT INTO role_memberships (role_id, member_id, admin_option, ownership) VALUES (?, ?, false, false)
			ON CONFLICT DO NOTHING`, layerID, hostRoleID)
	}
	return nil
}

// CreateAnnotations creates annotations for a resource
func (s *HostFactoryStore) CreateAnnotations(resourceID string, annotations map[string]string) error {
	for name, value := range annotations {
		if err := s.db.Exec(`INSERT INTO annotations (resource_id, name, value) VALUES (?, ?, ?)`,
			resourceID, name, value).Error; err != nil {
			return err
		}
	}
	return nil
}

// GenerateAPIKey generates a new API key
func (s *HostFactoryStore) GenerateAPIKey() (string, error) {
	apiKeyBytes, err := model.GenerateAPIKey()
	if err != nil {
		return "", err
	}
	return string(apiKeyBytes), nil
}
