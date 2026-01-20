package store

// Role represents a role with its memberships
type Role struct {
	ID      string
	Members []Membership
}

// Membership represents a role membership grant
type Membership struct {
	Role        string
	Member      string
	AdminOption bool
	Ownership   bool
	Policy      string
}

// RolesStore abstracts role storage operations
type RolesStore interface {
	// RoleExists checks if a role exists
	RoleExists(roleID string) bool

	// FetchRole retrieves a role with its memberships
	FetchRole(roleID string) *Role

	// FetchRoleMembers returns members of a role (who is IN this role)
	FetchRoleMembers(roleID, search, kind string, limit, offset int) []Membership

	// CountRoleMembers counts members of a role
	CountRoleMembers(roleID, search, kind string) int

	// FetchRoleMemberships returns what roles this role is a member of
	FetchRoleMemberships(roleID string) []Membership

	// CountRoleMemberships counts direct memberships
	CountRoleMemberships(roleID string) int

	// FetchAllMemberships returns all roles recursively
	FetchAllMemberships(roleID string) []string

	// CountAllMemberships counts all recursive memberships
	CountAllMemberships(roleID string) int

	// GetRolePolicyID gets the policy ID for a role
	GetRolePolicyID(roleID string) string

	// AddMembership adds a member to a role
	AddMembership(roleID, memberID, policyID string) error

	// DeleteMembership removes a member from a role
	DeleteMembership(roleID, memberID string) error

	// MembershipExists checks if a membership exists
	MembershipExists(roleID, memberID string) bool
}
