package store

// AuthzStore abstracts authorization checks
type AuthzStore interface {
	// IsRoleAllowedTo checks if a role has a privilege on a resource.
	IsRoleAllowedTo(roleID, privilege, resourceID string) bool

	// IsResourceVisible checks if a resource is visible to a role.
	IsResourceVisible(resourceID, roleID string) bool
}
