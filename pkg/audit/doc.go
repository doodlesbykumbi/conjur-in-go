// Package audit provides audit logging for Conjur operations.
//
// This package implements structured audit logging for security-relevant
// operations such as authentication attempts, secret access, and policy changes.
//
// # Event Types
//
// The package defines event types for various operations:
//
//   - Authentication events (success/failure)
//   - Secret fetch events
//   - Secret update events
//   - Policy load events
//   - Resource access events
//
// # Usage
//
//	event := audit.NewAuthEvent(account, roleID, success)
//	event.Log()
//
// Audit events are logged in a structured format suitable for security
// monitoring and compliance requirements.
package audit
