// Package identity provides authenticated identity management for Conjur requests.
//
// This package separates the concept of an authenticated identity from the
// raw token parsing. An Identity combines token claims (role, account, login)
// with request-specific context (privilege, remote IP, audit settings).
//
// # Basic Usage
//
//	// Create identity from a parsed token
//	id := identity.FromToken(parsedToken, account)
//
//	// Add request context
//	id.WithPrivilege(privilegeHeader).
//	   WithRemoteIP(clientIP).
//	   WithAuditRoles(auditRoles)
//
//	// Store in request context
//	ctx = identity.Set(ctx, id)
//
//	// Retrieve from context
//	id, ok := identity.Get(ctx)
//
// # Identity vs Token
//
// The token package handles parsing and validating the raw authentication token.
// The identity package builds on that to provide a richer context that includes:
//   - Token claims (role ID, account, login, timestamps)
//   - Request context (privilege elevation, client IP)
//   - Audit settings (audit roles, audit resources)
//
// This mirrors the Ruby Conjur distinction between the parsed token and the
// Conjur::Rack::User object.
package identity
