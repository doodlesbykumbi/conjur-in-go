package identity

import (
	"context"
	"net"
	"strings"
	"time"

	"github.com/doodlesbykumbi/conjur-in-go/pkg/slosilo/token"
)

// ContextKey is a type for context keys to avoid collisions.
type ContextKey string

const (
	// Key is the context key for Identity.
	Key ContextKey = "identity"
)

// Identity represents the authenticated identity for a request.
// It combines token claims with request-specific context.
type Identity struct {
	// Token claims
	RoleID    string
	Account   string
	Login     string
	IssuedAt  time.Time
	ExpiresAt time.Time

	// Request context
	Privilege      string   // X-Conjur-Privilege header (e.g., "elevate")
	RemoteIP       net.IP   // Client IP address
	AuditRoles     []string // X-Conjur-Audit-Roles header
	AuditResources []string // X-Conjur-Audit-Resources header

	// The underlying parsed token
	Token *token.Parsed
}

// FromToken creates an Identity from a parsed token and account.
func FromToken(tok *token.Parsed, account string) *Identity {
	login := tok.Sub()
	return &Identity{
		RoleID:    RoleID(account, login),
		Account:   account,
		Login:     login,
		IssuedAt:  tok.IAT(),
		ExpiresAt: tok.Exp(),
		Token:     tok,
	}
}

// WithPrivilege sets the privilege level.
func (i *Identity) WithPrivilege(privilege string) *Identity {
	i.Privilege = privilege
	return i
}

// WithRemoteIP sets the remote IP address.
func (i *Identity) WithRemoteIP(ip net.IP) *Identity {
	i.RemoteIP = ip
	return i
}

// WithAuditRoles sets the audit roles.
func (i *Identity) WithAuditRoles(roles []string) *Identity {
	i.AuditRoles = roles
	return i
}

// WithAuditResources sets the audit resources.
func (i *Identity) WithAuditResources(resources []string) *Identity {
	i.AuditResources = resources
	return i
}

// IsElevated returns true if the identity has elevated privileges.
func (i *Identity) IsElevated() bool {
	return i.Privilege == "elevate"
}

// RoleID constructs a role ID from account and login.
// If login contains a slash, it's treated as "kind/id".
// Otherwise, it's treated as a user login.
func RoleID(account string, login string) string {
	tokens := strings.Split(login, "/")
	if len(tokens) == 1 {
		tokens = []string{"user", login}
	}

	return strings.Join(
		[]string{
			account, tokens[0], strings.Join(tokens[1:], "/"),
		},
		":",
	)
}

// Get retrieves Identity from context.
func Get(ctx context.Context) (*Identity, bool) {
	id, ok := ctx.Value(Key).(*Identity)
	return id, ok
}

// Set stores Identity in context.
func Set(ctx context.Context, id *Identity) context.Context {
	return context.WithValue(ctx, Key, id)
}
