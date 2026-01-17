// Package authenticator defines the interface and registry for Conjur authenticators.
//
// Conjur supports multiple authentication mechanisms. This package provides the
// common interface that all authenticators must implement, as well as a registry
// for managing enabled authenticators.
//
// # Authenticator Interface
//
// All authenticators implement the Authenticator interface:
//
//	type Authenticator interface {
//	    Authenticate(ctx context.Context, account, login string, credentials []byte) (*Result, error)
//	}
//
// # Built-in Authenticators
//
// The following authenticators are available:
//
//   - authn: API key authentication (default)
//   - authn-jwt: JWT-based authentication
//
// # Registry
//
// Authenticators are registered and retrieved via the global registry:
//
//	// Register an authenticator
//	authenticator.Register("authn-jwt/my-service", jwtAuthenticator)
//
//	// Get an authenticator
//	auth, ok := authenticator.Get("authn-jwt/my-service")
//
// # Configuration
//
// Enabled authenticators are configured via the CONJUR_AUTHENTICATORS environment
// variable as a comma-separated list:
//
//	CONJUR_AUTHENTICATORS=authn,authn-jwt/my-service
package authenticator
