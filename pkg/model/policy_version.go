package model

import "time"

// PolicyVersion represents a version of a loaded policy
type PolicyVersion struct {
	ResourceID   string     `gorm:"column:resource_id;primaryKey"`
	RoleID       string     `gorm:"column:role_id"`
	Version      int        `gorm:"column:version;primaryKey"`
	CreatedAt    time.Time  `gorm:"column:created_at"`
	PolicyText   string     `gorm:"column:policy_text"`
	PolicySHA256 string     `gorm:"column:policy_sha256"`
	FinishedAt   *time.Time `gorm:"column:finished_at"`
	ClientIP     string     `gorm:"column:client_ip"`
}

func (PolicyVersion) TableName() string {
	return "policy_versions"
}
