package authenticator

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

// mockAuthenticator is a simple mock for testing
type mockAuthenticator struct {
	name string
}

func (m *mockAuthenticator) Name() string {
	return m.name
}

func (m *mockAuthenticator) Authenticate(ctx context.Context, input AuthenticatorInput) (string, error) {
	return "test:user:mock", nil
}

func (m *mockAuthenticator) Status(ctx context.Context, account string, serviceID string) error {
	return nil
}

func TestRegistry_Register(t *testing.T) {
	r := NewRegistry()
	auth := &mockAuthenticator{name: "test-auth"}

	r.Register(auth)

	got, ok := r.Get("test-auth")
	assert.True(t, ok)
	assert.Equal(t, "test-auth", got.Name())
}

func TestRegistry_Get_NotFound(t *testing.T) {
	r := NewRegistry()

	_, ok := r.Get("nonexistent")
	assert.False(t, ok)
}

func TestRegistry_Enable(t *testing.T) {
	r := NewRegistry()
	auth := &mockAuthenticator{name: "test-auth"}
	r.Register(auth)

	err := r.Enable("test-auth")
	assert.NoError(t, err)
	assert.True(t, r.IsEnabled("test-auth"))
}

func TestRegistry_Enable_NotFound(t *testing.T) {
	r := NewRegistry()

	err := r.Enable("nonexistent")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestRegistry_Disable(t *testing.T) {
	r := NewRegistry()
	auth := &mockAuthenticator{name: "test-auth"}
	r.Register(auth)
	_ = r.Enable("test-auth")

	r.Disable("test-auth")
	assert.False(t, r.IsEnabled("test-auth"))
}

func TestRegistry_Installed(t *testing.T) {
	r := NewRegistry()
	r.Register(&mockAuthenticator{name: "auth1"})
	r.Register(&mockAuthenticator{name: "auth2"})

	installed := r.Installed()
	assert.Len(t, installed, 2)
	assert.Contains(t, installed, "auth1")
	assert.Contains(t, installed, "auth2")
}

func TestRegistry_Enabled(t *testing.T) {
	r := NewRegistry()
	r.Register(&mockAuthenticator{name: "auth1"})
	r.Register(&mockAuthenticator{name: "auth2"})
	_ = r.Enable("auth1")

	enabled := r.Enabled()
	assert.Len(t, enabled, 1)
	assert.Contains(t, enabled, "auth1")
}

func TestRegistry_IsEnabled_NotEnabled(t *testing.T) {
	r := NewRegistry()
	r.Register(&mockAuthenticator{name: "test-auth"})

	assert.False(t, r.IsEnabled("test-auth"))
}
