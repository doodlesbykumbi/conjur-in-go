package store

// AnnotationsStore abstracts annotation storage operations
type AnnotationsStore interface {
	// GetAnnotations returns all annotations for a resource
	GetAnnotations(resourceID string) map[string]string

	// GetAnnotation returns a single annotation value
	GetAnnotation(resourceID, name string) (string, bool)

	// SetAnnotation sets or updates an annotation
	SetAnnotation(resourceID, name, value string) error

	// DeleteAnnotation deletes an annotation
	DeleteAnnotation(resourceID, name string) (bool, error)
}
