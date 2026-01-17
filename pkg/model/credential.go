package model

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"fmt"
	"net"
	"time"

	"github.com/lib/pq"
	"gorm.io/gorm"

	"github.com/doodlesbykumbi/conjur-in-go/pkg/slosilo"
)

type Credential struct {
	RoleId       string
	ApiKey       sql.RawBytes
	RestrictedTo pq.StringArray `gorm:"column:restricted_to;type:cidr[]"`
	UpdatedAt    time.Time
}

// IsOriginAllowed checks if the given IP address is allowed by CIDR restrictions
func (c *Credential) IsOriginAllowed(clientIP string) bool {
	// If no restrictions, allow all
	if len(c.RestrictedTo) == 0 {
		return true
	}

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
	for _, cidrStr := range c.RestrictedTo {
		_, cidrNet, err := net.ParseCIDR(cidrStr)
		if err != nil {
			// Try parsing as single IP (e.g., "192.168.1.1/32")
			cidrNet = &net.IPNet{IP: net.ParseIP(cidrStr), Mask: net.CIDRMask(32, 32)}
		}
		if cidrNet != nil && cidrNet.Contains(ip) {
			return true
		}
	}

	return false
}

func (c Credential) TableName() string {
	return "credentials"
}

// GenerateAPIKey creates a new random API key
func GenerateAPIKey() ([]byte, error) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	if err != nil {
		return nil, err
	}
	// Return URL-safe base64 encoded key
	encoded := base64.URLEncoding.EncodeToString(key)
	return []byte(encoded), nil
}

func (c *Credential) AfterFind(tx *gorm.DB) (err error) {
	decrypt := getCipherForDb(tx).Decrypt

	c.ApiKey, err = decrypt([]byte(c.RoleId), c.ApiKey)
	if err != nil {
		err = fmt.Errorf("credential decryption failed for role_id=%q", c.RoleId)
	}
	return
}

func getCipherForDb(tx *gorm.DB) slosilo.SymmetricCipher {
	cipher, ok := tx.Statement.Context.Value("cipher").(slosilo.SymmetricCipher)
	if !ok || cipher == nil {
		panic("no cipher in database context")
	}

	return cipher
}
