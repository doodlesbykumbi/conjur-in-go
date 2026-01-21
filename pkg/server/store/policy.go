package store

import "time"

// PolicyVersion represents a policy version
type PolicyVersion struct {
	Version      int
	CreatedAt    time.Time
	PolicySHA256 string
	FinishedAt   *time.Time
	ClientIP     string
	RoleID       string
	PolicyText   string
}

// PolicyStore abstracts policy version storage operations
type PolicyStore interface {
	// GetPolicyVersion retrieves a specific policy version
	GetPolicyVersion(policyID string, version int) (*PolicyVersion, error)

	// ListPolicyVersions returns all versions for a policy
	ListPolicyVersions(policyID string) []PolicyVersion
}
