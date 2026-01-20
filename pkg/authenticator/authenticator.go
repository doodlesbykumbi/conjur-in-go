package authenticator

import (
	"context"
	"net/http"
)

// Authenticator defines the interface for all authenticators
type Authenticator interface {
	// Name returns the authenticator name (e.g., "authn", "authn-jwt")
	Name() string

	// Authenticate validates credentials and returns a role ID on success
	Authenticate(ctx context.Context, input AuthenticatorInput) (string, error)

	// Status checks if the authenticator is healthy
	Status(ctx context.Context, account string, serviceID string) error
}

// AuthenticatorInput contains the input for authentication
type AuthenticatorInput struct {
	Account     string
	ServiceID   string
	Login       string
	Credentials []byte
	ClientIP    string
	Request     *http.Request // Original HTTP request for authenticators that need it
}
