package config

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	DefaultConfigPath = "/etc/conjur/config"
	ConfigFileName    = "conjur.yml"
)

// ValidAuthenticators is the list of valid authenticator types
var ValidAuthenticators = []string{
	"authn", "authn-k8s", "authn-oidc", "authn-iam",
	"authn-ldap", "authn-gcp", "authn-jwt", "authn-azure", "authn-cert",
}

// ConjurConfig holds all Conjur configuration settings
type ConjurConfig struct {
	// TrustedProxies is a list of CIDR ranges for trusted proxies
	TrustedProxies []string `yaml:"trusted_proxies" json:"trusted_proxies"`

	// APIResourceListLimitMax is the maximum number of results for listing requests
	APIResourceListLimitMax int `yaml:"api_resource_list_limit_max" json:"api_resource_list_limit_max"`

	// UserAuthorizationTokenTTL is the TTL for user tokens in seconds
	UserAuthorizationTokenTTL int `yaml:"user_authorization_token_ttl" json:"user_authorization_token_ttl"`

	// HostAuthorizationTokenTTL is the TTL for host tokens in seconds
	HostAuthorizationTokenTTL int `yaml:"host_authorization_token_ttl" json:"host_authorization_token_ttl"`

	// AuthnAPIKeyDefault enables API key authentication by default
	AuthnAPIKeyDefault bool `yaml:"authn_api_key_default" json:"authn_api_key_default"`

	// Authenticators is a list of enabled authenticators
	Authenticators []string `yaml:"authenticators" json:"authenticators"`

	// TelemetryEnabled enables telemetry
	TelemetryEnabled bool `yaml:"telemetry_enabled" json:"telemetry_enabled"`

	// AuthnJWTIgnoreMissingIssuerClaim ignores missing issuer claim in JWT
	AuthnJWTIgnoreMissingIssuerClaim bool `yaml:"authn_jwt_ignore_missing_issuer_claim" json:"authn_jwt_ignore_missing_issuer_claim"`

	// MaxRestrictedTo is the maximum number of CIDR restrictions
	MaxRestrictedTo int `yaml:"max_restricted_to" json:"max_restricted_to"`

	// HostFactoriesEnabled enables host factory operations
	HostFactoriesEnabled bool `yaml:"host_factories_enabled" json:"host_factories_enabled"`

	// sources tracks where each value came from
	sources map[string]string

	// configFilePath is the path to the config file
	configFilePath string
}

// Attribute represents a configuration attribute with its value and source
type Attribute struct {
	Name   string `json:"name"`
	Value  string `json:"value"`
	Source string `json:"source"`
}

// Global singleton config
var (
	globalConfig *ConjurConfig
	configMu     sync.RWMutex
)

// Get returns the global configuration, loading it if necessary
func Get() *ConjurConfig {
	configMu.RLock()
	if globalConfig != nil {
		configMu.RUnlock()
		return globalConfig
	}
	configMu.RUnlock()

	// Load config
	configMu.Lock()
	defer configMu.Unlock()

	if globalConfig == nil {
		cfg, err := Load()
		if err != nil {
			// Return defaults on error
			globalConfig = newDefault()
		} else {
			globalConfig = cfg
		}
	}
	return globalConfig
}

// Reload reloads the configuration from file and environment
func Reload() error {
	cfg, err := Load()
	if err != nil {
		return err
	}

	configMu.Lock()
	globalConfig = cfg
	configMu.Unlock()
	return nil
}

// newDefault returns a config with default values
func newDefault() *ConjurConfig {
	return &ConjurConfig{
		TrustedProxies:                   []string{},
		APIResourceListLimitMax:          1000,
		UserAuthorizationTokenTTL:        480,
		HostAuthorizationTokenTTL:        480,
		AuthnAPIKeyDefault:               true,
		Authenticators:                   []string{},
		TelemetryEnabled:                 false,
		AuthnJWTIgnoreMissingIssuerClaim: false,
		MaxRestrictedTo:                  1000,
		HostFactoriesEnabled:             true,
		sources:                          make(map[string]string),
	}
}

// Load loads configuration from file and environment variables
// Environment variables take precedence over file values
func Load() (*ConjurConfig, error) {
	config := newDefault()

	// Initialize all sources as "default"
	for _, name := range attributeNames() {
		config.sources[name] = "default"
	}

	// Determine config file path
	configPath := os.Getenv("CONJUR_CONFIG_PATH")
	if configPath == "" {
		configPath = DefaultConfigPath
	}
	config.configFilePath = filepath.Join(configPath, ConfigFileName)

	// Try to load from config file
	if data, err := os.ReadFile(config.configFilePath); err == nil {
		var fileConfig ConjurConfig
		if err := yaml.Unmarshal(data, &fileConfig); err != nil {
			return nil, fmt.Errorf("failed to parse config file %s: %w", config.configFilePath, err)
		}
		config.applyFileConfig(&fileConfig)
	}

	// Override with environment variables
	config.applyEnvConfig()

	return config, nil
}

func attributeNames() []string {
	return []string{
		"trusted_proxies", "api_resource_list_limit_max",
		"user_authorization_token_ttl", "host_authorization_token_ttl",
		"authn_api_key_default", "authenticators", "telemetry_enabled",
		"authn_jwt_ignore_missing_issuer_claim", "max_restricted_to",
		"host_factories_enabled",
	}
}

func (c *ConjurConfig) applyFileConfig(file *ConjurConfig) {
	if len(file.TrustedProxies) > 0 {
		c.TrustedProxies = file.TrustedProxies
		c.sources["trusted_proxies"] = "file"
	}
	if file.APIResourceListLimitMax != 0 {
		c.APIResourceListLimitMax = file.APIResourceListLimitMax
		c.sources["api_resource_list_limit_max"] = "file"
	}
	if file.UserAuthorizationTokenTTL != 0 {
		c.UserAuthorizationTokenTTL = file.UserAuthorizationTokenTTL
		c.sources["user_authorization_token_ttl"] = "file"
	}
	if file.HostAuthorizationTokenTTL != 0 {
		c.HostAuthorizationTokenTTL = file.HostAuthorizationTokenTTL
		c.sources["host_authorization_token_ttl"] = "file"
	}
	if len(file.Authenticators) > 0 {
		c.Authenticators = file.Authenticators
		c.sources["authenticators"] = "file"
	}
	if file.MaxRestrictedTo != 0 {
		c.MaxRestrictedTo = file.MaxRestrictedTo
		c.sources["max_restricted_to"] = "file"
	}
}

func (c *ConjurConfig) applyEnvConfig() {
	if val := os.Getenv("CONJUR_TRUSTED_PROXIES"); val != "" {
		c.TrustedProxies = splitAndTrim(val)
		c.sources["trusted_proxies"] = "environment"
	}
	if val := os.Getenv("CONJUR_API_RESOURCE_LIST_LIMIT_MAX"); val != "" {
		if i, err := strconv.Atoi(val); err == nil {
			c.APIResourceListLimitMax = i
			c.sources["api_resource_list_limit_max"] = "environment"
		}
	}
	if val := os.Getenv("CONJUR_USER_AUTHORIZATION_TOKEN_TTL"); val != "" {
		if i, err := strconv.Atoi(val); err == nil {
			c.UserAuthorizationTokenTTL = i
			c.sources["user_authorization_token_ttl"] = "environment"
		}
	}
	if val := os.Getenv("CONJUR_HOST_AUTHORIZATION_TOKEN_TTL"); val != "" {
		if i, err := strconv.Atoi(val); err == nil {
			c.HostAuthorizationTokenTTL = i
			c.sources["host_authorization_token_ttl"] = "environment"
		}
	}
	if val := os.Getenv("CONJUR_AUTHN_API_KEY_DEFAULT"); val != "" {
		c.AuthnAPIKeyDefault = val == "true" || val == "1"
		c.sources["authn_api_key_default"] = "environment"
	}
	if val := os.Getenv("CONJUR_AUTHENTICATORS"); val != "" {
		c.Authenticators = splitAndTrim(val)
		c.sources["authenticators"] = "environment"
	}
	if val := os.Getenv("CONJUR_TELEMETRY_ENABLED"); val != "" {
		c.TelemetryEnabled = val == "true" || val == "1"
		c.sources["telemetry_enabled"] = "environment"
	}
	if val := os.Getenv("CONJUR_AUTHN_JWT_IGNORE_MISSING_ISSUER_CLAIM"); val != "" {
		c.AuthnJWTIgnoreMissingIssuerClaim = val == "true" || val == "1"
		c.sources["authn_jwt_ignore_missing_issuer_claim"] = "environment"
	}
	if val := os.Getenv("CONJUR_MAX_RESTRICTED_TO"); val != "" {
		if i, err := strconv.Atoi(val); err == nil {
			c.MaxRestrictedTo = i
			c.sources["max_restricted_to"] = "environment"
		}
	}
	if val := os.Getenv("CONJUR_HOST_FACTORIES_ENABLED"); val != "" {
		c.HostFactoriesEnabled = val == "true" || val == "1"
		c.sources["host_factories_enabled"] = "environment"
	}
}

// ConfigFilePath returns the path to the config file
func (c *ConjurConfig) ConfigFilePath() string {
	return c.configFilePath
}

// Source returns the source of a configuration attribute
func (c *ConjurConfig) Source(name string) string {
	if c.sources == nil {
		return "default"
	}
	if s, ok := c.sources[name]; ok {
		return s
	}
	return "default"
}

// UserTokenTTL returns the user token TTL as a duration
func (c *ConjurConfig) UserTokenTTL() time.Duration {
	return time.Duration(c.UserAuthorizationTokenTTL) * time.Second
}

// HostTokenTTL returns the host token TTL as a duration
func (c *ConjurConfig) HostTokenTTL() time.Duration {
	return time.Duration(c.HostAuthorizationTokenTTL) * time.Second
}

// IsAuthenticatorEnabled checks if an authenticator is enabled
func (c *ConjurConfig) IsAuthenticatorEnabled(authenticator string) bool {
	// authn is always enabled if authn_api_key_default is true
	if authenticator == "authn" && c.AuthnAPIKeyDefault {
		return true
	}
	for _, a := range c.Authenticators {
		if a == authenticator {
			return true
		}
		// Check prefix match for service-specific authenticators (e.g., authn-jwt/myservice)
		if strings.HasPrefix(authenticator, a+"/") || strings.HasPrefix(a, authenticator+"/") {
			return true
		}
	}
	return false
}

// IsTrustedProxy checks if an IP is from a trusted proxy
func (c *ConjurConfig) IsTrustedProxy(ip string) bool {
	if len(c.TrustedProxies) == 0 {
		return false
	}

	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}

	for _, cidr := range c.TrustedProxies {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			// Try as plain IP
			if net.ParseIP(cidr) != nil && cidr == ip {
				return true
			}
			continue
		}
		if network.Contains(parsedIP) {
			return true
		}
	}
	return false
}

// Validate validates the configuration
func (c *ConjurConfig) Validate() error {
	// Validate trusted proxies are valid CIDR ranges
	for _, cidr := range c.TrustedProxies {
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			if net.ParseIP(cidr) == nil {
				return fmt.Errorf("invalid trusted_proxies value: %s", cidr)
			}
		}
	}

	// Validate authenticators
	validAuthenticators := make(map[string]bool)
	for _, a := range ValidAuthenticators {
		validAuthenticators[a] = true
	}
	for _, auth := range c.Authenticators {
		authType := strings.Split(auth, "/")[0]
		if !validAuthenticators[authType] {
			return fmt.Errorf("invalid authenticator type: %s", authType)
		}
	}

	return nil
}

// Attributes returns all configuration attributes with their values and sources
func (c *ConjurConfig) Attributes() []Attribute {
	return []Attribute{
		{Name: "trusted_proxies", Value: strings.Join(c.TrustedProxies, ","), Source: c.Source("trusted_proxies")},
		{Name: "authenticators", Value: strings.Join(c.Authenticators, ","), Source: c.Source("authenticators")},
		{Name: "api_resource_list_limit_max", Value: strconv.Itoa(c.APIResourceListLimitMax), Source: c.Source("api_resource_list_limit_max")},
		{Name: "user_authorization_token_ttl", Value: strconv.Itoa(c.UserAuthorizationTokenTTL), Source: c.Source("user_authorization_token_ttl")},
		{Name: "host_authorization_token_ttl", Value: strconv.Itoa(c.HostAuthorizationTokenTTL), Source: c.Source("host_authorization_token_ttl")},
		{Name: "authn_api_key_default", Value: strconv.FormatBool(c.AuthnAPIKeyDefault), Source: c.Source("authn_api_key_default")},
		{Name: "telemetry_enabled", Value: strconv.FormatBool(c.TelemetryEnabled), Source: c.Source("telemetry_enabled")},
		{Name: "authn_jwt_ignore_missing_issuer_claim", Value: strconv.FormatBool(c.AuthnJWTIgnoreMissingIssuerClaim), Source: c.Source("authn_jwt_ignore_missing_issuer_claim")},
		{Name: "max_restricted_to", Value: strconv.Itoa(c.MaxRestrictedTo), Source: c.Source("max_restricted_to")},
		{Name: "host_factories_enabled", Value: strconv.FormatBool(c.HostFactoriesEnabled), Source: c.Source("host_factories_enabled")},
	}
}

// FormatText returns a text representation of the configuration
func (c *ConjurConfig) FormatText() string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Config file: %s\n\n", c.configFilePath))
	sb.WriteString(fmt.Sprintf("%-40s %-30s %s\n", "NAME", "VALUE", "SOURCE"))
	sb.WriteString(fmt.Sprintf("%-40s %-30s %s\n", "----", "-----", "------"))

	for _, attr := range c.Attributes() {
		value := attr.Value
		if value == "" {
			value = "(not set)"
		}
		sb.WriteString(fmt.Sprintf("%-40s %-30s %s\n", attr.Name, value, attr.Source))
	}
	return sb.String()
}

// FormatJSON returns a JSON representation of the configuration
func (c *ConjurConfig) FormatJSON() (string, error) {
	result := map[string]interface{}{
		"config_file": c.configFilePath,
		"attributes":  c.Attributes(),
	}
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func splitAndTrim(s string) []string {
	parts := strings.Split(s, ",")
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			result = append(result, p)
		}
	}
	return result
}
