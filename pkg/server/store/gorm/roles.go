package gorm

import (
	"gorm.io/gorm"

	"github.com/doodlesbykumbi/conjur-in-go/pkg/server/store"
)

// Ensure RolesStore implements store.RolesStore
var _ store.RolesStore = (*RolesStore)(nil)

// RolesStore implements store.RolesStore using GORM
type RolesStore struct {
	db *gorm.DB
}

// NewRolesStore creates a new RolesStore
func NewRolesStore(db *gorm.DB) *RolesStore {
	return &RolesStore{db: db}
}

// RoleExists checks if a role exists
func (s *RolesStore) RoleExists(roleID string) bool {
	var exists bool
	s.db.Raw(`SELECT EXISTS(SELECT 1 FROM roles WHERE role_id = ?)`, roleID).Scan(&exists)
	return exists
}

// FetchRole retrieves a role with its memberships
func (s *RolesStore) FetchRole(roleID string) *store.Role {
	if !s.RoleExists(roleID) {
		return nil
	}
	return &store.Role{
		ID:      roleID,
		Members: s.FetchRoleMemberships(roleID),
	}
}

// FetchRoleMembers returns members of a role
func (s *RolesStore) FetchRoleMembers(roleID, search, kind string, limit, offset int) []store.Membership {
	query := `
		SELECT role_id, member_id, admin_option, ownership, policy_id
		FROM role_memberships
		WHERE role_id = ?
	`
	args := []interface{}{roleID}

	if search != "" {
		query += ` AND member_id ILIKE ?`
		args = append(args, "%"+search+"%")
	}

	if kind != "" {
		query += ` AND kind(member_id) = ?`
		args = append(args, kind)
	}

	query += ` ORDER BY member_id`

	if limit > 0 {
		query += ` LIMIT ?`
		args = append(args, limit)
	}
	if offset > 0 {
		query += ` OFFSET ?`
		args = append(args, offset)
	}

	return s.scanMemberships(query, args...)
}

// CountRoleMembers counts members of a role
func (s *RolesStore) CountRoleMembers(roleID, search, kind string) int {
	query := `SELECT COUNT(*) FROM role_memberships WHERE role_id = ?`
	args := []interface{}{roleID}

	if search != "" {
		query += ` AND member_id ILIKE ?`
		args = append(args, "%"+search+"%")
	}

	if kind != "" {
		query += ` AND kind(member_id) = ?`
		args = append(args, kind)
	}

	var count int
	s.db.Raw(query, args...).Scan(&count)
	return count
}

// FetchRoleMemberships returns what roles this role is a member of
func (s *RolesStore) FetchRoleMemberships(roleID string) []store.Membership {
	return s.scanMemberships(`
		SELECT role_id, member_id, admin_option, ownership, policy_id
		FROM role_memberships
		WHERE member_id = ?
		ORDER BY role_id
	`, roleID)
}

// CountRoleMemberships counts direct memberships
func (s *RolesStore) CountRoleMemberships(roleID string) int {
	var count int
	s.db.Raw(`SELECT COUNT(*) FROM role_memberships WHERE member_id = ?`, roleID).Scan(&count)
	return count
}

// FetchAllMemberships returns all roles recursively
func (s *RolesStore) FetchAllMemberships(roleID string) []string {
	type roleRow struct {
		RoleId string `gorm:"column:role_id"`
	}
	var rows []roleRow
	s.db.Raw(`SELECT role_id FROM all_roles(?)`, roleID).Scan(&rows)

	roleIds := make([]string, 0, len(rows))
	for _, row := range rows {
		roleIds = append(roleIds, row.RoleId)
	}
	return roleIds
}

// CountAllMemberships counts all recursive memberships
func (s *RolesStore) CountAllMemberships(roleID string) int {
	var count int
	s.db.Raw(`SELECT COUNT(*) FROM all_roles(?)`, roleID).Scan(&count)
	return count
}

// GetRolePolicyID gets the policy ID for a role
func (s *RolesStore) GetRolePolicyID(roleID string) string {
	var policyId string
	s.db.Raw(`SELECT policy_id FROM resources WHERE resource_id = ?`, roleID).Scan(&policyId)
	return policyId
}

// AddMembership adds a member to a role
func (s *RolesStore) AddMembership(roleID, memberID, policyID string) error {
	return s.db.Exec(`
		INSERT INTO role_memberships (role_id, member_id, admin_option, ownership, policy_id)
		VALUES (?, ?, false, false, ?)
		ON CONFLICT DO NOTHING
	`, roleID, memberID, policyID).Error
}

// DeleteMembership removes a member from a role
func (s *RolesStore) DeleteMembership(roleID, memberID string) error {
	return s.db.Exec(`DELETE FROM role_memberships WHERE role_id = ? AND member_id = ?`, roleID, memberID).Error
}

// MembershipExists checks if a membership exists
func (s *RolesStore) MembershipExists(roleID, memberID string) bool {
	var exists bool
	s.db.Raw(`SELECT EXISTS(SELECT 1 FROM role_memberships WHERE role_id = ? AND member_id = ?)`,
		roleID, memberID).Scan(&exists)
	return exists
}

func (s *RolesStore) scanMemberships(query string, args ...interface{}) []store.Membership {
	type memberRow struct {
		RoleId      string
		MemberId    string
		AdminOption bool
		Ownership   bool
		PolicyId    *string
	}

	var rows []memberRow
	s.db.Raw(query, args...).Scan(&rows)

	memberships := make([]store.Membership, 0, len(rows))
	for _, row := range rows {
		m := store.Membership{
			Role:        row.RoleId,
			Member:      row.MemberId,
			AdminOption: row.AdminOption,
			Ownership:   row.Ownership,
		}
		if row.PolicyId != nil {
			m.Policy = *row.PolicyId
		}
		memberships = append(memberships, m)
	}
	return memberships
}
