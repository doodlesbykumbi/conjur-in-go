package store

// HealthStore provides health check operations
type HealthStore interface {
	// CheckConnectivity verifies database connectivity
	CheckConnectivity() error
}
