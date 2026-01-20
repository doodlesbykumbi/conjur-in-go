package store

import (
	"errors"
	"time"
)

// ErrSecretNotFound is returned when a secret doesn't exist
var ErrSecretNotFound = errors.New("secret not found")

// ErrSecretExpired is returned when a secret has expired
var ErrSecretExpired = errors.New("secret has expired")

// Secret represents a secret value with metadata
type Secret struct {
	ResourceID string
	Value      []byte
	Version    int
	ExpiresAt  *time.Time
}

// SecretsStore abstracts secret storage operations
type SecretsStore interface {
	// FetchSecret retrieves a secret by resource ID and optional version.
	// Returns ErrSecretNotFound if the secret doesn't exist.
	// Returns ErrSecretExpired if the secret has expired.
	FetchSecret(resourceID string, version string) (*Secret, error)

	// CreateSecret creates a new version of a secret.
	CreateSecret(resourceID string, value []byte) error

	// ExpireSecret clears the expiration on all versions of a secret.
	ExpireSecret(resourceID string) error
}
