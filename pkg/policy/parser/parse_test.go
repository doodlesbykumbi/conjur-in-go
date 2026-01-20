package parser

import (
	"strings"
	"testing"
)

func TestParse(t *testing.T) {
	tests := []struct {
		name        string
		yaml        string
		expectError bool
		checkFunc   func(t *testing.T, statements Statements)
	}{
		{
			name: "parse single user",
			yaml: `- !user
  id: alice`,
			expectError: false,
			checkFunc: func(t *testing.T, statements Statements) {
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
			checkFunc: func(t *testing.T, statements Statements) {
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
			checkFunc: func(t *testing.T, statements Statements) {
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
			checkFunc: func(t *testing.T, statements Statements) {
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
			checkFunc: func(t *testing.T, statements Statements) {
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
