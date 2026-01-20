package authn

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"

	"gorm.io/gorm"

	"github.com/doodlesbykumbi/conjur-in-go/pkg/authenticator"
	"github.com/doodlesbykumbi/conjur-in-go/pkg/slosilo"
)

// Authenticator implements API key authentication
type Authenticator struct {
	db     *gorm.DB
	cipher slosilo.SymmetricCipher
}

// NewAPIKeyAuthenticator creates a new API key authenticator
func NewAPIKeyAuthenticator(db *gorm.DB, cipher slosilo.SymmetricCipher) *Authenticator {
	return &Authenticator{
		db:     db,
		cipher: cipher,
	}
}

// Name returns the authenticator name
func (a *Authenticator) Name() string {
	return "authn"
}

// Authenticate validates an API key and returns the role ID
func (a *Authenticator) Authenticate(ctx context.Context, input authenticator.AuthenticatorInput) (string, error) {
	roleID := input.Account + ":user:" + input.Login
	if input.Login == "" {
		return "", errors.New("login is required")
	}

	// Handle host login format
	if len(input.Login) > 5 && input.Login[:5] == "host/" {
		roleID = input.Account + ":host:" + input.Login[5:]
	}

	// Get stored API key and CIDR restrictions
	var apiKey []byte
	var restrictedToRaw string
	row := a.db.Raw(`SELECT api_key, COALESCE(array_to_string(restricted_to, ','), '') FROM credentials WHERE role_id = ?`, roleID).Row()
	if err := row.Scan(&apiKey, &restrictedToRaw); err != nil {
		if err.Error() == "sql: no rows in result set" {
			return "", errors.New("role not found")
		}
		return "", fmt.Errorf("authentication failed: %w", err)
	}

	// Parse comma-separated CIDR list
	var restrictedTo []string
	if restrictedToRaw != "" {
		restrictedTo = strings.Split(restrictedToRaw, ",")
	}

	if len(apiKey) == 0 {
		return "", errors.New("authentication failed")
	}

	// Decrypt and compare
	decryptedAPIKey, err := a.cipher.Decrypt([]byte(roleID), apiKey)
	if err != nil {
		return "", errors.New("authentication failed")
	}

	if string(decryptedAPIKey) != string(input.Credentials) {
		return "", errors.New("authentication failed")
	}

	// Check CIDR restrictions
	if len(restrictedTo) > 0 && input.ClientIP != "" {
		if !isOriginAllowed(input.ClientIP, restrictedTo) {
			return "", errors.New("origin is not in the list of allowed IP addresses")
		}
	}

	return roleID, nil
}

// isOriginAllowed checks if the client IP is allowed by CIDR restrictions
func isOriginAllowed(clientIP string, restrictedTo []string) bool {
	// Parse client IP (strip port if present)
	host, _, err := net.SplitHostPort(clientIP)
	if err != nil {
		// No port, use as-is
		host = clientIP
	}

	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}

	// Check if IP is in any of the allowed CIDRs
	for _, cidrStr := range restrictedTo {
		_, cidrNet, err := net.ParseCIDR(cidrStr)
		if err != nil {
			// Try parsing as single IP
			singleIP := net.ParseIP(cidrStr)
			if singleIP != nil && singleIP.Equal(ip) {
				return true
			}
			continue
		}
		if cidrNet.Contains(ip) {
			return true
		}
	}

	return false
}

// Status checks if the authenticator is healthy
func (a *Authenticator) Status(ctx context.Context, account string, serviceID string) error {
	// Basic authn is always healthy if we can reach the database
	return a.db.Exec("SELECT 1").Error
}

func init() {
	// Note: The actual registration happens in server setup since we need db/cipher
}
