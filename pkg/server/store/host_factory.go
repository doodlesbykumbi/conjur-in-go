package store

import (
	"time"

	"github.com/doodlesbykumbi/conjur-in-go/pkg/model"
)

// HostFactoryToken represents a host factory token for the store layer
type HostFactoryToken struct {
	Token      string
	Expiration time.Time
	CIDR       []string
	ResourceID string
}

// HostFactoryStore abstracts host factory storage operations
type HostFactoryStore interface {
	// GetResourceKind returns the kind of a resource
	GetResourceKind(resourceID string) string

	// CreateToken creates a host factory token and returns the plain token
	CreateToken(hostFactoryID string, expiration time.Time, cidr []string) (HostFactoryToken, error)

	// FindToken finds a token by plain token value, returns nil if not found
	FindToken(plainToken string) (*model.HostFactoryToken, error)

	// ValidateToken validates and decrypts a token
	ValidateToken(hfToken *model.HostFactoryToken, plainToken string) bool

	// DeleteToken deletes a host factory token
	DeleteToken(hfToken *model.HostFactoryToken) error

	// RoleExists checks if a role exists
	RoleExists(roleID string) bool

	// GetResourceOwner gets the owner of a resource
	GetResourceOwner(resourceID string) string

	// CreateHost creates a host with role, resource, and credentials
	CreateHost(hostRoleID, ownerID, apiKey string) error

	// AddHostToLayers adds a host to layers associated with a host factory
	AddHostToLayers(hostFactoryID, hostRoleID, account string) error

	// CreateAnnotations creates annotations for a resource
	CreateAnnotations(resourceID string, annotations map[string]string) error

	// GenerateAPIKey generates a new API key
	GenerateAPIKey() (string, error)
}
