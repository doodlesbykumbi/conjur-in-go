package gorm

import (
	"time"

	"gorm.io/gorm"

	"github.com/doodlesbykumbi/conjur-in-go/pkg/model"
	"github.com/doodlesbykumbi/conjur-in-go/pkg/server/store"
)

// PolicyStore provides policy version operations using GORM
type PolicyStore struct {
	db *gorm.DB
}

// NewPolicyStore creates a new PolicyStore
func NewPolicyStore(db *gorm.DB) *PolicyStore {
	return &PolicyStore{db: db}
}

// GetPolicyVersion retrieves a specific policy version
func (s *PolicyStore) GetPolicyVersion(policyID string, version int) (*store.PolicyVersion, error) {
	var pv model.PolicyVersion
	result := s.db.Where("resource_id = ? AND version = ?", policyID, version).First(&pv)
	if result.Error != nil {
		return nil, result.Error
	}

	return &store.PolicyVersion{
		Version:      pv.Version,
		CreatedAt:    pv.CreatedAt,
		PolicySHA256: pv.PolicySHA256,
		FinishedAt:   pv.FinishedAt,
		ClientIP:     pv.ClientIP,
		RoleID:       pv.RoleID,
		PolicyText:   pv.PolicyText,
	}, nil
}

// ListPolicyVersions returns all versions for a policy
func (s *PolicyStore) ListPolicyVersions(policyID string) []store.PolicyVersion {
	type versionRow struct {
		Version      int
		CreatedAt    time.Time
		PolicySHA256 string
		FinishedAt   *time.Time
		ClientIP     string
		RoleID       string
	}
	var rows []versionRow
	s.db.Raw(`
		SELECT version, created_at, policy_sha256, finished_at, client_ip, role_id
		FROM policy_versions
		WHERE resource_id = ?
		ORDER BY version DESC
	`, policyID).Scan(&rows)

	versions := make([]store.PolicyVersion, 0, len(rows))
	for _, row := range rows {
		versions = append(versions, store.PolicyVersion{
			Version:      row.Version,
			CreatedAt:    row.CreatedAt,
			PolicySHA256: row.PolicySHA256,
			FinishedAt:   row.FinishedAt,
			ClientIP:     row.ClientIP,
			RoleID:       row.RoleID,
		})
	}
	return versions
}
