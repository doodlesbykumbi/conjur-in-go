package loader

import "time"

// PolicyVersion represents a version of a loaded policy.
type PolicyVersion struct {
	ResourceID   string
	RoleID       string
	Version      int
	CreatedAt    time.Time
	FinishedAt   *time.Time
	PolicyText   string
	PolicySHA256 string
	ClientIP     string
}

// Store abstracts the storage operations for policy loading.
// This allows the loader to work with different backends (e.g., database, mock for testing).
type Store interface {
	// Transaction wraps operations in a database transaction.
	// The provided function receives a transactional Store.
	// If the function returns an error, the transaction is rolled back.
	Transaction(fn func(Store) error) error

	// CreatePolicyVersion creates a policy version record.
	// Returns the created version with auto-generated fields populated.
	CreatePolicyVersion(pv *PolicyVersion) error

	// GetPolicyVersion retrieves the current (unfinished) policy version for a resource.
	GetPolicyVersion(resourceID string) (*PolicyVersion, error)

	// CreateRole creates a role with the given ID.
	CreateRole(roleID string) error

	// CreateResource creates a resource with owner and annotations.
	CreateResource(resourceID, ownerID string, annotations map[string]interface{}) error

	// CreateCredentials creates credentials for a role with optional CIDR restrictions.
	// The apiKey should be stored encrypted.
	CreateCredentials(roleID, apiKey string, restrictedTo []string) error

	// CreateRoleMembership creates a membership relationship between a role and member.
	CreateRoleMembership(roleID, memberID string, adminOption, ownership bool) error

	// CreatePermission grants a privilege on a resource to a role.
	CreatePermission(privilege, resourceID, roleID string) error

	// DeletePermission removes a privilege on a resource from a role.
	DeletePermission(privilege, resourceID, roleID string) error

	// DeleteResource removes a resource and its associated data.
	DeleteResource(resourceID string) error

	// DeleteRole removes a role and its associated data.
	DeleteRole(roleID string) error
}
