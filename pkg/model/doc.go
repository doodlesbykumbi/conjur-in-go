// Package model defines the database models for Conjur.
//
// This package contains GORM models that map to the Conjur database schema.
// The schema is designed to be compatible with Ruby Conjur's PostgreSQL database.
//
// # Core Models
//
//   - Key: RSA signing keys stored in slosilo_keystore
//   - Credential: API keys and passwords for roles
//   - Role: Identity principals (users, hosts, groups, layers, policies)
//   - Resource: Protected objects (variables, webservices, hosts, etc.)
//   - RoleMembership: Role hierarchy relationships
//   - Permission: Access control rules
//   - Secret: Encrypted secret values with versioning
//   - Annotation: Metadata key-value pairs on resources
//
// # Database Schema
//
// The database uses PostgreSQL with the following key tables:
//
//   - slosilo_keystore: RSA keys for token signing
//   - credentials: Encrypted API keys
//   - roles: All role identities
//   - resources: All resources
//   - role_memberships: Role hierarchy
//   - permissions: Access grants
//   - secrets: Versioned secret values
//   - annotations: Resource metadata
package model
