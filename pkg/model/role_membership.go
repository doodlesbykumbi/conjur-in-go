package model

// RoleMembership represents a role hierarchy relationship
type RoleMembership struct {
	RoleID      string `gorm:"column:role_id;primaryKey"`
	MemberID    string `gorm:"column:member_id;primaryKey"`
	AdminOption bool   `gorm:"column:admin_option;not null;default:false"`
	Ownership   bool   `gorm:"column:ownership;primaryKey;not null;default:false"`
}

func (RoleMembership) TableName() string {
	return "role_memberships"
}
