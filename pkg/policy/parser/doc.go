// Package parser provides YAML parsing for Conjur policy files.
//
// This package handles the parsing of Conjur policy YAML into structured
// Go types. It does not perform any database operations - for loading
// policies into a database, see the loader package.
//
// # Basic Usage
//
//	statements, err := parser.Parse(reader)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
// # Supported Statement Types
//
// The parser supports all standard Conjur policy statement types:
//   - Policy: Container for nested statements
//   - User: User identity with optional credentials
//   - Group: Group for organizing roles
//   - Host: Machine identity with credentials
//   - Layer: Collection of hosts
//   - Variable: Secret storage
//   - Grant: Role membership assignment
//   - Permit: Permission grant
//   - Deny: Permission revocation
//   - Delete: Resource deletion
//   - HostFactory: Factory for creating hosts
//   - Webservice: Web service resource
package parser
