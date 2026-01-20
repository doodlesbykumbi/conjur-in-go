package endpoints

import "gorm.io/gorm"

// isRoleAllowedTo checks if a role has a privilege on a resource.
// This is a shared helper used by multiple endpoints.
func isRoleAllowedTo(db *gorm.DB, roleId, privilege, resourceId string) bool {
	var permitted bool
	db.Raw(`SELECT is_role_allowed_to(?, ?, ?)`, roleId, privilege, resourceId).Scan(&permitted)
	return permitted
}
