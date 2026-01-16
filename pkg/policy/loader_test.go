package policy

import (
	"strings"
	"testing"
)

func TestCategorizeStatements(t *testing.T) {
	tests := []struct {
		name                  string
		statements            PolicyStatements
		expectedCreates       int
		expectedRelationships int
	}{
		{
			name:                  "empty statements",
			statements:            PolicyStatements{},
			expectedCreates:       0,
			expectedRelationships: 0,
		},
		{
			name: "only users",
			statements: PolicyStatements{
				User{Id: "alice"},
				User{Id: "bob"},
			},
			expectedCreates:       2,
			expectedRelationships: 0,
		},
		{
			name: "only grants",
			statements: PolicyStatements{
				Grant{Role: GroupRef("admins"), Members: []ResourceRef{UserRef("alice")}},
			},
			expectedCreates:       0,
			expectedRelationships: 1,
		},
		{
			name: "mixed creates and relationships",
			statements: PolicyStatements{
				User{Id: "alice"},
				Group{Id: "developers"},
				Grant{Role: GroupRef("developers"), Members: []ResourceRef{UserRef("alice")}},
				Variable{Id: "secret"},
				Permit{Role: GroupRef("developers"), Resources: []ResourceRef{VariableRef("secret")}},
			},
			expectedCreates:       3,
			expectedRelationships: 2,
		},
		{
			name: "nested policy with relationships",
			statements: PolicyStatements{
				Policy{
					Id: "app",
					Body: PolicyStatements{
						User{Id: "deployer"},
						Group{Id: "admins"},
						Grant{Role: GroupRef("admins"), Members: []ResourceRef{UserRef("deployer")}},
					},
				},
				Grant{Role: GroupRef("app/admins"), Members: []ResourceRef{UserRef("admin")}},
			},
			expectedCreates:       3, // Policy + User + Group
			expectedRelationships: 2, // Grant inside policy + Grant outside
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var creates []Resource
			var relationships []Resource

			categorizeStatements(tt.statements, &creates, &relationships)

			if len(creates) != tt.expectedCreates {
				t.Errorf("expected %d creates, got %d", tt.expectedCreates, len(creates))
			}
			if len(relationships) != tt.expectedRelationships {
				t.Errorf("expected %d relationships, got %d", tt.expectedRelationships, len(relationships))
			}
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

			if result != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, result)
			}
		})
	}
}

func TestResolveRef(t *testing.T) {
	tests := []struct {
		name       string
		account    string
		policyPath []string
		ref        ResourceRef
		expected   string
	}{
		{
			name:       "empty ref",
			account:    "myorg",
			policyPath: []string{},
			ref:        ResourceRef{},
			expected:   "",
		},
		{
			name:       "simple user ref",
			account:    "myorg",
			policyPath: []string{},
			ref:        UserRef("alice"),
			expected:   "myorg:user:alice",
		},
		{
			name:       "already qualified ref",
			account:    "myorg",
			policyPath: []string{},
			ref:        ResourceRef{Id: "other:user:bob", Kind: KindUser},
			expected:   "other:user:bob",
		},
		{
			name:       "ref in nested policy",
			account:    "myorg",
			policyPath: []string{"app"},
			ref:        GroupRef("admins"),
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

			if result != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, result)
			}
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

			if result != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, result)
			}
		})
	}
}

func TestGenerateAPIKey(t *testing.T) {
	key1, err := generateAPIKey()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(key1) == 0 {
		t.Error("expected non-empty API key")
	}

	// Generate another key and ensure they're different
	key2, err := generateAPIKey()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if key1 == key2 {
		t.Error("expected different API keys")
	}
}

func TestParse(t *testing.T) {
	tests := []struct {
		name        string
		yaml        string
		expectError bool
		checkFunc   func(t *testing.T, statements PolicyStatements)
	}{
		{
			name: "parse single user",
			yaml: `- !user
  id: alice`,
			expectError: false,
			checkFunc: func(t *testing.T, statements PolicyStatements) {
				if len(statements) != 1 {
					t.Fatalf("expected 1 statement, got %d", len(statements))
				}
				user, ok := statements[0].(User)
				if !ok {
					t.Fatalf("expected User, got %T", statements[0])
				}
				if user.Id != "alice" {
					t.Errorf("expected id 'alice', got %q", user.Id)
				}
			},
		},
		{
			name: "parse multiple resources",
			yaml: `- !user
  id: alice
- !group
  id: developers
- !variable
  id: secret`,
			expectError: false,
			checkFunc: func(t *testing.T, statements PolicyStatements) {
				if len(statements) != 3 {
					t.Fatalf("expected 3 statements, got %d", len(statements))
				}
			},
		},
		{
			name: "parse grant",
			yaml: `- !grant
  role: !group developers
  member: !user alice`,
			expectError: false,
			checkFunc: func(t *testing.T, statements PolicyStatements) {
				if len(statements) != 1 {
					t.Fatalf("expected 1 statement, got %d", len(statements))
				}
				grant, ok := statements[0].(Grant)
				if !ok {
					t.Fatalf("expected Grant, got %T", statements[0])
				}
				if grant.Role.Id != "developers" {
					t.Errorf("expected role 'developers', got %q", grant.Role.Id)
				}
				if grant.Member.Id != "alice" {
					t.Errorf("expected member 'alice', got %q", grant.Member.Id)
				}
			},
		},
		{
			name: "parse permit with privileges",
			yaml: `- !permit
  role: !group developers
  privileges: [read, execute]
  resource: !variable secret`,
			expectError: false,
			checkFunc: func(t *testing.T, statements PolicyStatements) {
				if len(statements) != 1 {
					t.Fatalf("expected 1 statement, got %d", len(statements))
				}
				permit, ok := statements[0].(Permit)
				if !ok {
					t.Fatalf("expected Permit, got %T", statements[0])
				}
				if len(permit.Privileges) != 2 {
					t.Errorf("expected 2 privileges, got %d", len(permit.Privileges))
				}
			},
		},
		{
			name: "parse nested policy",
			yaml: `- !policy
  id: app
  body:
    - !user
      id: deployer
    - !group
      id: admins`,
			expectError: false,
			checkFunc: func(t *testing.T, statements PolicyStatements) {
				if len(statements) != 1 {
					t.Fatalf("expected 1 statement, got %d", len(statements))
				}
				policy, ok := statements[0].(Policy)
				if !ok {
					t.Fatalf("expected Policy, got %T", statements[0])
				}
				if policy.Id != "app" {
					t.Errorf("expected id 'app', got %q", policy.Id)
				}
				if len(policy.Body) != 2 {
					t.Errorf("expected 2 body statements, got %d", len(policy.Body))
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			statements, err := Parse(strings.NewReader(tt.yaml))

			if tt.expectError && err == nil {
				t.Error("expected error, got nil")
			}
			if !tt.expectError && err != nil {
				t.Errorf("unexpected error: %v", err)
			}

			if tt.checkFunc != nil && err == nil {
				tt.checkFunc(t, statements)
			}
		})
	}
}
