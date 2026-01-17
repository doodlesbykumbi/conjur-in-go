// Package policy provides Conjur policy parsing and loading.
//
// Policies define the resources, roles, and permissions in a Conjur account.
// This package handles parsing YAML policy files and loading them into the database.
//
// # Policy Format
//
// Policies are written in YAML and can define:
//
//   - Users: Human identities (!user)
//   - Hosts: Machine identities (!host)
//   - Groups: Collections of roles (!group)
//   - Layers: Collections of hosts (!layer)
//   - Variables: Secrets storage (!variable)
//   - Policies: Nested policy namespaces (!policy)
//   - Permissions: Access grants (!permit, !deny)
//   - Memberships: Role relationships (!grant)
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
