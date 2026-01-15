package model

import "time"

// Role represents a principal/identity in Conjur
type Role struct {
	RoleID    string    `gorm:"column:role_id;primaryKey"`
	CreatedAt time.Time `gorm:"column:created_at;autoCreateTime"`
}

func (Role) TableName() string {
	return "roles"
}
