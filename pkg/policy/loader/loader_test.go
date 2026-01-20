package loader

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/doodlesbykumbi/conjur-in-go/pkg/policy/parser"
)

func TestCategorizeStatements(t *testing.T) {
	tests := []struct {
		name                  string
		statements            parser.Statements
		expectedCreates       int
		expectedRelationships int
	}{
		{
			name:                  "empty statements",
			statements:            parser.Statements{},
			expectedCreates:       0,
			expectedRelationships: 0,
		},
		{
			name: "only users",
			statements: parser.Statements{
				parser.User{Id: "alice"},
				parser.User{Id: "bob"},
			},
			expectedCreates:       2,
			expectedRelationships: 0,
		},
		{
			name: "only grants",
			statements: parser.Statements{
				parser.Grant{Role: parser.GroupRef("admins"), Members: []parser.ResourceRef{parser.UserRef("alice")}},
			},
			expectedCreates:       0,
			expectedRelationships: 1,
		},
		{
			name: "mixed creates and relationships",
			statements: parser.Statements{
				parser.User{Id: "alice"},
				parser.Group{Id: "developers"},
				parser.Grant{Role: parser.GroupRef("developers"), Members: []parser.ResourceRef{parser.UserRef("alice")}},
				parser.Variable{Id: "secret"},
				parser.Permit{Role: parser.GroupRef("developers"), Resources: []parser.ResourceRef{parser.VariableRef("secret")}},
			},
			expectedCreates:       3,
			expectedRelationships: 2,
		},
		{
			name: "nested policy with relationships",
			statements: parser.Statements{
				parser.Policy{
					Id: "app",
					Body: parser.Statements{
						parser.User{Id: "deployer"},
						parser.Group{Id: "admins"},
						parser.Grant{Role: parser.GroupRef("admins"), Members: []parser.ResourceRef{parser.UserRef("deployer")}},
					},
				},
				parser.Grant{Role: parser.GroupRef("app/admins"), Members: []parser.ResourceRef{parser.UserRef("admin")}},
			},
			expectedCreates:       3, // Policy + User + Group
			expectedRelationships: 2, // Grant inside policy + Grant outside
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var creates []parser.Statement
			var relationships []parser.Statement

			categorizeStatements(tt.statements, &creates, &relationships)

			assert.Len(t, creates, tt.expectedCreates)
			assert.Len(t, relationships, tt.expectedRelationships)
		})
	}
}

func TestQualifyID(t *testing.T) {
	tests := []struct {
		name       string
		account    string
		policyPath []string
		kind       string
		id         string
		expected   string
	}{
		{
			name:       "root level user",
			account:    "myorg",
			policyPath: []string{},
			kind:       "user",
			id:         "alice",
			expected:   "myorg:user:alice",
		},
		{
			name:       "nested in single policy",
			account:    "myorg",
			policyPath: []string{"app"},
			kind:       "user",
			id:         "deployer",
			expected:   "myorg:user:deployer@app",
		},
		{
			name:       "deeply nested variable",
			account:    "myorg",
			policyPath: []string{"app", "prod", "db"},
			kind:       "variable",
			id:         "password",
			expected:   "myorg:variable:app/prod/db/password",
		},
		{
			name:       "deeply nested user uses @ notation with - joined path",
			account:    "myorg",
			policyPath: []string{"app", "prod"},
			kind:       "user",
			id:         "deployer",
			expected:   "myorg:user:deployer@app-prod",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := &loadContext{
				account:    tt.account,
				policyPath: tt.policyPath,
			}

			result := ctx.qualifyID(tt.kind, tt.id)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestResolveRef(t *testing.T) {
	tests := []struct {
		name       string
		account    string
		policyPath []string
		ref        parser.ResourceRef
		expected   string
	}{
		{
			name:       "empty ref",
			account:    "myorg",
			policyPath: []string{},
			ref:        parser.ResourceRef{},
			expected:   "",
		},
		{
			name:       "simple user ref",
			account:    "myorg",
			policyPath: []string{},
			ref:        parser.UserRef("alice"),
			expected:   "myorg:user:alice",
		},
		{
			name:       "already qualified ref",
			account:    "myorg",
			policyPath: []string{},
			ref:        parser.ResourceRef{Id: "other:user:bob", Kind: parser.KindUser},
			expected:   "other:user:bob",
		},
		{
			name:       "ref in nested policy",
			account:    "myorg",
			policyPath: []string{"app"},
			ref:        parser.GroupRef("admins"),
			expected:   "myorg:group:app/admins",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := &loadContext{
				account:    tt.account,
				policyPath: tt.policyPath,
			}

			result := ctx.resolveRef(tt.ref)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestCurrentPolicyID(t *testing.T) {
	tests := []struct {
		name       string
		account    string
		policyPath []string
		expected   string
	}{
		{
			name:       "root policy",
			account:    "myorg",
			policyPath: []string{},
			expected:   "myorg:policy:root",
		},
		{
			name:       "single level policy",
			account:    "myorg",
			policyPath: []string{"app"},
			expected:   "myorg:policy:app",
		},
		{
			name:       "nested policy",
			account:    "myorg",
			policyPath: []string{"app", "prod"},
			expected:   "myorg:policy:app/prod",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := &loadContext{
				account:    tt.account,
				policyPath: tt.policyPath,
			}

			result := ctx.currentPolicyID()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGenerateAPIKey(t *testing.T) {
	key1, err := generateAPIKey()
	require.NoError(t, err)
	assert.NotEmpty(t, key1)

	// Generate another key and ensure they're different
	key2, err := generateAPIKey()
	require.NoError(t, err)
	assert.NotEqual(t, key1, key2)
}

func TestNewLoader(t *testing.T) {
	loader := NewLoader(nil, "myorg")

	require.NotNil(t, loader)
	assert.Equal(t, "myorg", loader.account)
	assert.Equal(t, "myorg:policy:root", loader.policyID)
	assert.Equal(t, "myorg:user:admin", loader.roleID)
}

func TestLoader_WithMethods(t *testing.T) {
	loader := NewLoader(nil, "myorg")

	// Test chaining
	loader.WithPolicyID("myorg:policy:app").
		WithRoleID("myorg:user:deployer").
		WithClientIP("192.168.1.100").
		WithDeletePermitted(true).
		WithDryRun(true)

	assert.Equal(t, "myorg:policy:app", loader.policyID)
	assert.Equal(t, "myorg:user:deployer", loader.roleID)
	assert.Equal(t, "192.168.1.100", loader.clientIP)
	assert.True(t, loader.deletePermitted)
	assert.True(t, loader.dryRun)
}

func TestLoader_LoadFromReader_ParseError(t *testing.T) {
	loader := NewLoader(nil, "myorg")

	// Invalid YAML
	reader := strings.NewReader("invalid: yaml: content: [")
	_, err := loader.LoadFromReader(reader)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse policy")
}
