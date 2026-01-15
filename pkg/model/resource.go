package model

import "time"

// Resource represents a protected resource in Conjur (variables, webservices, etc.)
type Resource struct {
	ResourceID string    `gorm:"column:resource_id;primaryKey"`
	OwnerID    string    `gorm:"column:owner_id;not null"`
	CreatedAt  time.Time `gorm:"column:created_at;autoCreateTime"`
}

func (Resource) TableName() string {
	return "resources"
}
