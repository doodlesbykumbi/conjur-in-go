package gorm

import (
	"strings"

	"gorm.io/gorm"

	"github.com/doodlesbykumbi/conjur-in-go/pkg/server/store"
)

// Ensure ResourcesStore implements store.ResourcesStore
var _ store.ResourcesStore = (*ResourcesStore)(nil)

// ResourcesStore implements store.ResourcesStore using GORM
type ResourcesStore struct {
	db *gorm.DB
}

// NewResourcesStore creates a new ResourcesStore
func NewResourcesStore(db *gorm.DB) *ResourcesStore {
	return &ResourcesStore{db: db}
}

// ListResources returns resources visible to a role with optional filtering
func (s *ResourcesStore) ListResources(account, kind, roleID, search string, limit, offset int) []store.Resource {
	query := `
		SELECT resource_id, owner_id, created_at
		FROM visible_resources(?)
		WHERE account(resource_id) = ?
	`
	args := []interface{}{roleID, account}

	if kind != "" {
		query += ` AND kind(resource_id) = ?`
		args = append(args, kind)
	}

	if search != "" {
		query += ` AND resource_id ILIKE ?`
		args = append(args, "%"+search+"%")
	}

	query += ` ORDER BY resource_id`

	if limit > 0 {
		query += ` LIMIT ?`
		args = append(args, limit)
	}
	if offset > 0 {
		query += ` OFFSET ?`
		args = append(args, offset)
	}

	type resourceRow struct {
		ResourceId string
		OwnerId    string
		CreatedAt  *string
	}

	var rows []resourceRow
	s.db.Raw(query, args...).Scan(&rows)

	resources := make([]store.Resource, 0, len(rows))
	for _, row := range rows {
		resource := store.Resource{
			ID:    row.ResourceId,
			Owner: row.OwnerId,
		}

		resource.Permissions = s.fetchPermissions(row.ResourceId)
		resource.Annotations = s.fetchAnnotations(row.ResourceId)

		if strings.Contains(row.ResourceId, ":variable:") {
			resource.Secrets = s.fetchSecretMeta(row.ResourceId)
		}

		resources = append(resources, resource)
	}

	return resources
}

// CountResources returns the count of resources matching the criteria
func (s *ResourcesStore) CountResources(account, kind, roleID, search string) int {
	query := `
		SELECT COUNT(*)
		FROM visible_resources(?)
		WHERE account(resource_id) = ?
	`
	args := []interface{}{roleID, account}

	if kind != "" {
		query += ` AND kind(resource_id) = ?`
		args = append(args, kind)
	}

	if search != "" {
		query += ` AND resource_id ILIKE ?`
		args = append(args, "%"+search+"%")
	}

	var count int
	s.db.Raw(query, args...).Scan(&count)
	return count
}

// FetchResource retrieves a single resource by ID
func (s *ResourcesStore) FetchResource(resourceID string) *store.Resource {
	type resourceRow struct {
		ResourceId string
		OwnerId    string
		CreatedAt  *string
	}

	var row resourceRow
	result := s.db.Raw(`
		SELECT resource_id, owner_id, created_at
		FROM resources WHERE resource_id = ?
	`, resourceID).Scan(&row)

	if result.Error != nil || row.ResourceId == "" {
		return nil
	}

	resource := &store.Resource{
		ID:    row.ResourceId,
		Owner: row.OwnerId,
	}

	resource.Permissions = s.fetchPermissions(resourceID)
	resource.Annotations = s.fetchAnnotations(resourceID)

	if strings.Contains(resourceID, ":variable:") {
		resource.Secrets = s.fetchSecretMeta(resourceID)
	}

	return resource
}

// IsResourceVisible checks if a resource is visible to a role
func (s *ResourcesStore) IsResourceVisible(resourceID, roleID string) bool {
	var visible bool
	s.db.Raw(`SELECT is_resource_visible(?, ?)`, resourceID, roleID).Scan(&visible)
	return visible
}

// ResourceExists checks if a resource exists
func (s *ResourcesStore) ResourceExists(resourceID string) bool {
	var exists bool
	s.db.Raw(`SELECT EXISTS(SELECT 1 FROM resources WHERE resource_id = ?)`, resourceID).Scan(&exists)
	return exists
}

// RoleExists checks if a role exists
func (s *ResourcesStore) RoleExists(roleID string) bool {
	var exists bool
	s.db.Raw(`SELECT EXISTS(SELECT 1 FROM roles WHERE role_id = ?)`, roleID).Scan(&exists)
	return exists
}

// ResourceExistsWithPrefix checks if any resource exists with the given prefix
func (s *ResourcesStore) ResourceExistsWithPrefix(prefix string) bool {
	var exists bool
	s.db.Raw(`SELECT EXISTS(SELECT 1 FROM resources WHERE resource_id LIKE ?)`, prefix+"%").Scan(&exists)
	return exists
}

// PermittedRoles returns all roles that have a given privilege on a resource
func (s *ResourcesStore) PermittedRoles(privilege, resourceID string) []string {
	type roleRow struct {
		RoleID string `gorm:"column:role_id"`
	}
	var rows []roleRow
	s.db.Raw(`SELECT role_id FROM roles_that_can(?, ?)`, privilege, resourceID).Scan(&rows)

	roleIds := make([]string, 0, len(rows))
	for _, row := range rows {
		roleIds = append(roleIds, row.RoleID)
	}
	return roleIds
}

func (s *ResourcesStore) fetchPermissions(resourceID string) []store.Permission {
	type permRow struct {
		Privilege string
		RoleId    string
		PolicyId  *string
	}

	var rows []permRow
	s.db.Raw(`
		SELECT privilege, role_id, policy_id
		FROM permissions WHERE resource_id = ?
		ORDER BY role_id, privilege
	`, resourceID).Scan(&rows)

	perms := make([]store.Permission, 0, len(rows))
	for _, row := range rows {
		perm := store.Permission{
			Privilege: row.Privilege,
			Role:      row.RoleId,
		}
		if row.PolicyId != nil {
			perm.Policy = *row.PolicyId
		}
		perms = append(perms, perm)
	}
	return perms
}

func (s *ResourcesStore) fetchAnnotations(resourceID string) map[string]string {
	type annRow struct {
		Name  string
		Value string
	}

	var rows []annRow
	s.db.Raw(`
		SELECT name, value FROM annotations WHERE resource_id = ?
	`, resourceID).Scan(&rows)

	annotations := make(map[string]string)
	for _, row := range rows {
		annotations[row.Name] = row.Value
	}
	return annotations
}

func (s *ResourcesStore) fetchSecretMeta(resourceID string) []store.SecretMeta {
	type secretRow struct {
		Version   int
		ExpiresAt *string
	}

	var rows []secretRow
	s.db.Raw(`
		SELECT version, expires_at FROM secrets WHERE resource_id = ? ORDER BY version
	`, resourceID).Scan(&rows)

	secrets := make([]store.SecretMeta, 0, len(rows))
	for _, row := range rows {
		secret := store.SecretMeta{
			Version: row.Version,
		}
		if row.ExpiresAt != nil {
			secret.ExpiresAt = *row.ExpiresAt
		}
		secrets = append(secrets, secret)
	}
	return secrets
}
