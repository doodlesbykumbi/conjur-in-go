package gorm

import (
	"gorm.io/gorm"

	"github.com/doodlesbykumbi/conjur-in-go/pkg/server/store"
)

// Ensure AnnotationsStore implements store.AnnotationsStore
var _ store.AnnotationsStore = (*AnnotationsStore)(nil)

// AnnotationsStore implements store.AnnotationsStore using GORM
type AnnotationsStore struct {
	db *gorm.DB
}

// NewAnnotationsStore creates a new AnnotationsStore
func NewAnnotationsStore(db *gorm.DB) *AnnotationsStore {
	return &AnnotationsStore{db: db}
}

// GetAnnotations returns all annotations for a resource
func (s *AnnotationsStore) GetAnnotations(resourceID string) map[string]string {
	type annotationRow struct {
		Name  string
		Value string
	}
	var rows []annotationRow
	s.db.Raw(`SELECT name, value FROM annotations WHERE resource_id = ?`, resourceID).Scan(&rows)

	annotations := make(map[string]string)
	for _, row := range rows {
		annotations[row.Name] = row.Value
	}
	return annotations
}

// GetAnnotation returns a single annotation value
func (s *AnnotationsStore) GetAnnotation(resourceID, name string) (string, bool) {
	var value string
	result := s.db.Raw(`SELECT value FROM annotations WHERE resource_id = ? AND name = ?`, resourceID, name).Scan(&value)
	if result.Error != nil || result.RowsAffected == 0 {
		return "", false
	}
	return value, true
}

// SetAnnotation sets or updates an annotation
func (s *AnnotationsStore) SetAnnotation(resourceID, name, value string) error {
	return s.db.Exec(`
		INSERT INTO annotations (resource_id, name, value)
		VALUES (?, ?, ?)
		ON CONFLICT (resource_id, name) DO UPDATE SET value = EXCLUDED.value
	`, resourceID, name, value).Error
}

// DeleteAnnotation deletes an annotation, returns true if deleted
func (s *AnnotationsStore) DeleteAnnotation(resourceID, name string) (bool, error) {
	result := s.db.Exec(`DELETE FROM annotations WHERE resource_id = ? AND name = ?`, resourceID, name)
	if result.Error != nil {
		return false, result.Error
	}
	return result.RowsAffected > 0, nil
}
