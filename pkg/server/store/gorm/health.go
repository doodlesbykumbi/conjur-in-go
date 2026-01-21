package gorm

import (
	"gorm.io/gorm"
)

// HealthStore provides health check operations using GORM
type HealthStore struct {
	db *gorm.DB
}

// NewHealthStore creates a new HealthStore
func NewHealthStore(db *gorm.DB) *HealthStore {
	return &HealthStore{db: db}
}

// CheckConnectivity verifies database connectivity
func (s *HealthStore) CheckConnectivity() error {
	return s.db.Exec("SELECT 1").Error
}
