package store

// Resource represents a resource with its metadata
type Resource struct {
	ID          string
	Owner       string
	CreatedAt   *string
	Permissions []Permission
	Annotations map[string]string
	Secrets     []SecretMeta
}

// Permission represents a permission on a resource
type Permission struct {
	Privilege string
	Role      string
	Policy    string
}

// SecretMeta represents secret metadata (not the value)
type SecretMeta struct {
	Version   int
	ExpiresAt string
}

// ResourcesStore abstracts resource storage operations
type ResourcesStore interface {
	// ListResources returns resources visible to a role with optional filtering
	ListResources(account, kind, roleID, search string, limit, offset int) []Resource

	// CountResources returns the count of resources matching the criteria
	CountResources(account, kind, roleID, search string) int

	// FetchResource retrieves a single resource by ID
	FetchResource(resourceID string) *Resource

	// IsResourceVisible checks if a resource is visible to a role
	IsResourceVisible(resourceID, roleID string) bool

	// ResourceExists checks if a resource exists
	ResourceExists(resourceID string) bool

	// RoleExists checks if a role exists
	RoleExists(roleID string) bool

	// PermittedRoles returns all roles that have a given privilege on a resource
	PermittedRoles(privilege, resourceID string) []string
}
