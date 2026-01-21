package endpoints

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRoleIdFromLogin(t *testing.T) {
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
			name:     "explicit user login",
			account:  "myorg",
			login:    "user/alice",
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
			login:    "host/app/prod/server1",
			expected: "myorg:host:app/prod/server1",
		},
		{
			name:     "different account",
			account:  "other",
			login:    "admin",
			expected: "other:user:admin",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := roleIdFromLogin(tt.account, tt.login)
			assert.Equal(t, tt.expected, result)
		})
	}
}
