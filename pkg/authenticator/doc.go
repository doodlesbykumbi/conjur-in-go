// Package authenticator defines the interface for Conjur authenticators.
//
// Conjur supports multiple authentication mechanisms. This package provides the
// common interface that all authenticators must implement.
//
// # Authenticator Interface
//
// All authenticators implement the Authenticator interface:
//
//	type Authenticator interface {
//	    Name() string
//	    Authenticate(ctx context.Context, input AuthenticatorInput) (string, error)
//	    Status(ctx context.Context, account, serviceID string) error
//	}
//
// # Built-in Authenticators
//
// The following authenticators are available in subpackages:
//
//   - authn: API key authentication (default) - see [github.com/doodlesbykumbi/conjur-in-go/pkg/authenticator/authn]
//   - authn-jwt: JWT-based authentication - see [github.com/doodlesbykumbi/conjur-in-go/pkg/authenticator/authn_jwt]
//
// # On-Demand Creation
//
// Authenticators are created on-demand during request handling rather than
// being pre-registered. This allows for dynamic configuration and reduces
// startup overhead.
//
// # Configuration
//
// Enabled authenticators are configured via the CONJUR_AUTHENTICATORS environment
// variable as a comma-separated list:
//
//	CONJUR_AUTHENTICATORS=authn,authn-jwt/my-service
//
// The authn (API key) authenticator is enabled by default unless explicitly
// disabled via CONJUR_AUTHN_API_KEY_DEFAULT=false.
package authenticator
