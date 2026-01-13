package model

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"strings"
	"time"
)

// HostFactoryToken represents a token for automated host enrollment
type HostFactoryToken struct {
	TokenSHA256 string    `gorm:"column:token_sha256;primaryKey"`
	Token       []byte    `gorm:"column:token"`
	ResourceID  string    `gorm:"column:resource_id"`
	CIDR        string    `gorm:"column:cidr;type:cidr[]"`
	Expiration  time.Time `gorm:"column:expiration"`

	// Transient field for the plaintext token (not stored)
	PlainToken string `gorm:"-"`
}

func (HostFactoryToken) TableName() string {
	return "host_factory_tokens"
}

// GenerateToken creates a new random token
func GenerateToken() string {
	// Generate 32 random bytes and encode as hex (64 chars)
	randomBytes := make([]byte, 32)
	rand.Read(randomBytes)
	return hex.EncodeToString(randomBytes)
}

// HashToken returns the SHA256 hash of a token
func HashToken(token string) string {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}

// IsExpired checks if the token has expired
func (t *HostFactoryToken) IsExpired() bool {
	return time.Now().After(t.Expiration)
}

// IsValidOrigin checks if the given IP is allowed by the CIDR restrictions
func (t *HostFactoryToken) IsValidOrigin(ipStr string) bool {
	// If no CIDR restrictions, allow all
	if t.CIDR == "" || t.CIDR == "{}" {
		return true
	}

	// Parse the IP address (strip port if present)
	host := ipStr
	if strings.Contains(ipStr, ":") {
		var err error
		host, _, err = net.SplitHostPort(ipStr)
		if err != nil {
			// Maybe it's just an IP without port
			host = ipStr
		}
	}

	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}

	// Parse CIDR array from PostgreSQL format: {192.168.1.0/24,10.0.0.0/8}
	cidrStr := strings.Trim(t.CIDR, "{}")
	if cidrStr == "" {
		return true
	}

	cidrs := strings.Split(cidrStr, ",")
	for _, cidr := range cidrs {
		cidr = strings.TrimSpace(cidr)
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if network.Contains(ip) {
			return true
		}
	}

	return false
}

// IsValid checks if the token is valid (not expired and origin allowed)
func (t *HostFactoryToken) IsValid(origin string) bool {
	if t.IsExpired() {
		return false
	}
	if origin != "" {
		return t.IsValidOrigin(origin)
	}
	return true
}

// HostFactoryTokenResponse is the JSON response format
type HostFactoryTokenResponse struct {
	Token      string   `json:"token"`
	Expiration string   `json:"expiration"`
	CIDR       []string `json:"cidr"`
}

// ToResponse converts the token to a JSON response
func (t *HostFactoryToken) ToResponse() HostFactoryTokenResponse {
	cidr := []string{}
	if t.CIDR != "" && t.CIDR != "{}" {
		cidrStr := strings.Trim(t.CIDR, "{}")
		if cidrStr != "" {
			cidr = strings.Split(cidrStr, ",")
		}
	}

	return HostFactoryTokenResponse{
		Token:      t.PlainToken,
		Expiration: t.Expiration.UTC().Format(time.RFC3339),
		CIDR:       cidr,
	}
}
