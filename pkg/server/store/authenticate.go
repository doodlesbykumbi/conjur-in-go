package store

import "github.com/doodlesbykumbi/conjur-in-go/pkg/model"

// AuthenticateStore abstracts authentication storage operations
type AuthenticateStore interface {
	// GetCredential retrieves credentials for a role
	GetCredential(roleID string) (*model.Credential, error)

	// ValidateAPIKey validates an API key against stored credentials
	ValidateAPIKey(credential *model.Credential, apiKey []byte) bool

	// RotateAPIKey generates and stores a new API key for a role
	RotateAPIKey(roleID string) ([]byte, error)

	// UpdatePassword updates the password/API key for a role
	UpdatePassword(roleID string, newPassword []byte) error
}
