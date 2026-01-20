// Package audit provides RFC5424 syslog-compliant audit logging for Conjur operations.
//
// This package implements structured audit logging for security-relevant
// operations such as authentication attempts, secret access, and policy changes.
// Events are formatted according to RFC5424 with Conjur's Private Enterprise
// Number (43868) for structured data.
//
// # Event Types
//
// The package defines event types for various operations:
//
//   - AuthnEvent: Authentication attempts (success/failure)
//   - FetchEvent: Secret retrieval
//   - UpdateEvent: Secret updates
//   - PolicyEvent: Policy load operations
//   - CheckEvent: Permission checks
//   - ListEvent: Resource listing
//   - ShowEvent: Resource details
//   - MembersEvent: Role membership changes
//   - WhoamiEvent: Identity lookups
//   - HostFactoryEvent: Host factory token operations
//   - APIKeyEvent: API key rotation
//   - PasswordEvent: Password changes
//
// # Usage
//
//	// Log an authentication event
//	audit.Log(audit.NewAuthnEvent(account, roleID, authenticator, success))
//
//	// Log a secret fetch
//	audit.Log(audit.NewFetchEvent(account, roleID, resourceID, success))
//
// # Configuration
//
// Audit logging can be disabled via CONJUR_AUDIT_ENABLED=false.
// Events can optionally be persisted to a database via AUDIT_DATABASE_URL.
//
// # Output Format
//
// Events are written in RFC5424 syslog format:
//
//	<PRI>1 TIMESTAMP HOSTNAME conjur PID MSGID [SD] MESSAGE
package audit
