package identity

import (
	"context"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/doodlesbykumbi/conjur-in-go/pkg/slosilo/token"
)

func TestRoleID(t *testing.T) {
	tests := []struct {
		name     string
		account  string
		login    string
		expected string
	}{
		{
			name:     "simple user login",
			account:  "myorg",
			login:    "alice",
			expected: "myorg:user:alice",
		},
		{
			name:     "host login",
			account:  "myorg",
			login:    "host/myapp",
			expected: "myorg:host:myapp",
		},
		{
			name:     "nested host login",
			account:  "myorg",
			login:    "host/apps/frontend/web",
			expected: "myorg:host:apps/frontend/web",
		},
		{
			name:     "user with explicit kind",
			account:  "myorg",
			login:    "user/bob",
			expected: "myorg:user:bob",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := RoleID(tt.account, tt.login)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestIdentity_WithMethods(t *testing.T) {
	id := &Identity{
		RoleID:  "myorg:user:alice",
		Account: "myorg",
		Login:   "alice",
	}

	// Test chaining
	ip := net.ParseIP("192.168.1.100")
	id.WithPrivilege("elevate").
		WithRemoteIP(ip).
		WithAuditRoles([]string{"myorg:group:admins"}).
		WithAuditResources([]string{"myorg:variable:secrets/db-password"})

	assert.Equal(t, "elevate", id.Privilege)
	assert.Equal(t, ip, id.RemoteIP)
	assert.Equal(t, []string{"myorg:group:admins"}, id.AuditRoles)
	assert.Equal(t, []string{"myorg:variable:secrets/db-password"}, id.AuditResources)
}

func TestIdentity_IsElevated(t *testing.T) {
	tests := []struct {
		name      string
		privilege string
		expected  bool
	}{
		{
			name:      "elevated",
			privilege: "elevate",
			expected:  true,
		},
		{
			name:      "not elevated - empty",
			privilege: "",
			expected:  false,
		},
		{
			name:      "not elevated - other value",
			privilege: "something-else",
			expected:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id := &Identity{Privilege: tt.privilege}
			assert.Equal(t, tt.expected, id.IsElevated())
		})
	}
}

func TestContextGetSet(t *testing.T) {
	ctx := context.Background()

	// Initially no identity
	id, ok := Get(ctx)
	assert.False(t, ok)
	assert.Nil(t, id)

	// Set identity
	expected := &Identity{
		RoleID:  "myorg:user:alice",
		Account: "myorg",
		Login:   "alice",
	}
	ctx = Set(ctx, expected)

	// Get identity
	id, ok = Get(ctx)
	assert.True(t, ok)
	require.NotNil(t, id)
	assert.Equal(t, expected.RoleID, id.RoleID)
	assert.Equal(t, expected.Account, id.Account)
	assert.Equal(t, expected.Login, id.Login)
}

func TestFromToken(t *testing.T) {
	// We need to create a real parsed token for this test
	// Since token.Parsed requires actual parsing, we'll test the logic indirectly
	// by verifying the RoleID construction which is the main logic in FromToken

	t.Run("constructs correct role ID for user", func(t *testing.T) {
		// Test the RoleID function which is called by FromToken
		roleID := RoleID("myorg", "alice")
		assert.Equal(t, "myorg:user:alice", roleID)
	})

	t.Run("constructs correct role ID for host", func(t *testing.T) {
		roleID := RoleID("myorg", "host/myapp")
		assert.Equal(t, "myorg:host:myapp", roleID)
	})

	// Test FromToken with a nil-safe approach
	t.Run("FromToken with mock token", func(t *testing.T) {
		// Create a minimal token for testing
		// This tests that FromToken correctly extracts fields
		mockToken := &token.Parsed{}

		id := FromToken(mockToken, "testaccount")
		assert.Equal(t, "testaccount", id.Account)
		assert.Equal(t, mockToken, id.Token)
		// Login will be empty string from mock, so RoleID will be "testaccount:user:"
		assert.Equal(t, "testaccount:user:", id.RoleID)
		// Mock token returns zero IAT, and Exp falls back to IAT + 8 minutes
		assert.True(t, id.IssuedAt.IsZero())
		// ExpiresAt is IAT + 8 minutes, so it's 8 minutes after Unix epoch
		assert.False(t, id.ExpiresAt.IsZero())
	})
}
