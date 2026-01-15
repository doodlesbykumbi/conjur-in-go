package authenticator

import (
	"context"
	"fmt"
	"sync"
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
	Request     interface{} // Original HTTP request for authenticators that need it
}

// Registry holds all registered authenticators
type Registry struct {
	mu             sync.RWMutex
	authenticators map[string]Authenticator
	enabled        map[string]bool
}

// NewRegistry creates a new authenticator registry
func NewRegistry() *Registry {
	return &Registry{
		authenticators: make(map[string]Authenticator),
		enabled:        make(map[string]bool),
	}
}

// Register adds an authenticator to the registry
func (r *Registry) Register(auth Authenticator) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.authenticators[auth.Name()] = auth
}

// Enable enables an authenticator by name
func (r *Registry) Enable(name string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.authenticators[name]; !ok {
		return fmt.Errorf("authenticator %q not found", name)
	}
	r.enabled[name] = true
	return nil
}

// Disable disables an authenticator by name
func (r *Registry) Disable(name string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.enabled, name)
}

// Get returns an authenticator by name
func (r *Registry) Get(name string) (Authenticator, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	auth, ok := r.authenticators[name]
	return auth, ok
}

// IsEnabled checks if an authenticator is enabled
func (r *Registry) IsEnabled(name string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.enabled[name]
}

// Installed returns all installed authenticator names
func (r *Registry) Installed() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	names := make([]string, 0, len(r.authenticators))
	for name := range r.authenticators {
		names = append(names, name)
	}
	return names
}

// Enabled returns all enabled authenticator names
func (r *Registry) Enabled() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	names := make([]string, 0, len(r.enabled))
	for name := range r.enabled {
		names = append(names, name)
	}
	return names
}

// DefaultRegistry is the global authenticator registry
var DefaultRegistry = NewRegistry()
