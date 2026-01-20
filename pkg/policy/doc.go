// Package policy provides Conjur policy parsing and loading.
//
// Policies define the resources, roles, and permissions in a Conjur account.
// This package handles parsing YAML policy files and loading them into the database.
//
// # Policy Format
//
// Conjur policies are written in YAML with custom tags to define resources:
//
//   - !policy
//     id: myapp
//     body:
//   - !user alice
//   - !group
//     id: developers
//   - !variable
//     id: db-password
//   - !permit
//     role: !group developers
//     privileges: [read, execute]
//     resource: !variable db-password
//
// # Parsing Policies
//
// Use the parser package to parse policy YAML:
//
//	import "github.com/doodlesbykumbi/conjur-in-go/pkg/policy/parser"
//
//	statements, err := parser.Parse(reader)
//
// # Loading Policies
//
// Use the loader package to apply policies to a database:
//
//	import "github.com/doodlesbykumbi/conjur-in-go/pkg/policy/loader"
//
//	store := loader.NewGormStore(db, cipher)
//	l := loader.NewLoader(store, "myorg")
//	result, err := l.LoadFromString(policyYAML)
//
// # Supported Resource Types
//
//   - Users: Human identities (!user)
//   - Hosts: Machine identities (!host)
//   - Groups: Collections of roles (!group)
//   - Layers: Collections of hosts (!layer)
//   - Variables: Secrets storage (!variable)
//   - Policies: Nested policy namespaces (!policy)
//   - Webservice: Web service endpoint
//   - HostFactory: Factory for creating hosts
//
// # Supported Statements
//
//   - Grant: Assign role membership
//   - Permit: Grant permissions
//   - Deny: Revoke permissions
//   - Delete: Remove resources
//
// # Example Policy
//
//   - !policy
//     id: myapp
//     body:
//   - !user admin
//   - !host server
//   - !variable database-password
//   - !permit
//     role: !user admin
//     privileges: [read, update, execute]
//     resource: !variable database-password
//
// # Loading Policies
//
//	result, err := policy.Load(db, cipher, account, policyBranch, policyYAML)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	// result.CreatedRoles contains API keys for newly created roles
//	for roleID, creds := range result.CreatedRoles {
//	    fmt.Printf("Role %s: API key %s\n", roleID, creds.APIKey)
//	}
//
// # User ID Notation
//
// Users defined within a policy use the @ notation for their ID:
//
//   - User "alice" in policy "myapp" becomes "alice@myapp"
//   - User "bob" in nested policy "myapp/prod" becomes "bob@myapp-prod"
//
// This matches the Ruby Conjur behavior and allows the CLI login format "user@policy".
package policy
