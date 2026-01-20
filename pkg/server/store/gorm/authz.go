package gorm

import (
	"gorm.io/gorm"

	"github.com/doodlesbykumbi/conjur-in-go/pkg/server/store"
)

// Ensure AuthzStore implements store.AuthzStore
var _ store.AuthzStore = (*AuthzStore)(nil)

// AuthzStore implements store.AuthzStore using GORM
type AuthzStore struct {
	db *gorm.DB
}

// NewAuthzStore creates a new AuthzStore
func NewAuthzStore(db *gorm.DB) *AuthzStore {
	return &AuthzStore{db: db}
}

// IsRoleAllowedTo checks if a role has a privilege on a resource.
func (s *AuthzStore) IsRoleAllowedTo(roleID, privilege, resourceID string) bool {
	var permitted bool
	s.db.Raw(`SELECT is_role_allowed_to(?, ?, ?)`, roleID, privilege, resourceID).Scan(&permitted)
	return permitted
}

// IsResourceVisible checks if a resource is visible to a role.
func (s *AuthzStore) IsResourceVisible(resourceID, roleID string) bool {
	var visible bool
	s.db.Raw(`SELECT is_resource_visible(?, ?)`, resourceID, roleID).Scan(&visible)
	return visible
}
