package model

// Permission represents an RBAC permission grant
type Permission struct {
	Privilege  string `gorm:"column:privilege;primaryKey"`
	ResourceID string `gorm:"column:resource_id;primaryKey"`
	RoleID     string `gorm:"column:role_id;primaryKey"`
}

func (Permission) TableName() string {
	return "permissions"
}
