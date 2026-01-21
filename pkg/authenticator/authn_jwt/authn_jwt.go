package authn_jwt

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/doodlesbykumbi/conjur-in-go/pkg/authenticator"
)

// Config holds JWT authenticator configuration
type Config struct {
	// ServiceID is the unique identifier for this JWT authenticator instance
	ServiceID string

	// ProviderURI is the OIDC provider URI (e.g., https://accounts.google.com)
	// Used to fetch JWKS from {provider-uri}/.well-known/openid-configuration
	ProviderURI string

	// JWKSURI is a direct URI to fetch JWKS (alternative to ProviderURI)
	JWKSURI string

	// PublicKeys is inline JWKS in format: {"type": "jwks", "value": {"keys": [...]}}
	// This is an alternative to JWKSURI/ProviderURI for static key configuration
	PublicKeys string

	// Issuer is the expected issuer claim value (optional, defaults to ProviderURI)
	Issuer string

	// TokenAppProperty is the JWT claim containing the identity (e.g., "sub", "email")
	TokenAppProperty string

	// Audience is the expected audience claim (optional)
	Audience string
}

// Store abstracts the storage operations needed by the JWT authenticator
type Store interface {
	// FetchSecret retrieves a decrypted secret value by resource ID
	FetchSecret(resourceID string) (string, error)
	// RoleExists checks if a role exists
	RoleExists(roleID string) bool
}

// Authenticator implements JWT authentication
type Authenticator struct {
	store     Store
	config    Config
	account   string // Account for reading config from store
	jwksCache *jwksCache
}

// jwksCache caches JWKS keys
type jwksCache struct {
	mu        sync.RWMutex
	keys      map[string]*rsa.PublicKey
	expiresAt time.Time
}

// NewJWTAuthenticator creates a new JWT authenticator with static config
func NewJWTAuthenticator(store Store, config Config) *Authenticator {
	return &Authenticator{
		store:  store,
		config: config,
		jwksCache: &jwksCache{
			keys: make(map[string]*rsa.PublicKey),
		},
	}
}

// NewFromStore creates a JWT authenticator that reads config from Conjur variables
func NewFromStore(store Store, serviceID, account string) *Authenticator {
	return &Authenticator{
		store: store,
		config: Config{
			ServiceID: serviceID,
		},
		account: account,
		jwksCache: &jwksCache{
			keys: make(map[string]*rsa.PublicKey),
		},
	}
}

// Name returns the authenticator name
func (a *Authenticator) Name() string {
	if a.config.ServiceID != "" {
		return "authn-jwt/" + a.config.ServiceID
	}
	return "authn-jwt"
}

// Authenticate validates a JWT token and returns the role ID
func (a *Authenticator) Authenticate(ctx context.Context, input authenticator.AuthenticatorInput) (string, error) {
	tokenString := string(input.Credentials)
	if tokenString == "" {
		return "", errors.New("JWT token is required")
	}

	// Parse and validate the token
	token, err := a.parseAndValidateToken(ctx, tokenString)
	if err != nil {
		return "", fmt.Errorf("token validation failed: %w", err)
	}

	// Extract identity from token
	identity, err := a.extractIdentity(token, input.Login)
	if err != nil {
		return "", fmt.Errorf("failed to extract identity: %w", err)
	}

	// Build role ID
	// If identity already contains account prefix (e.g., "myorg:host:myapp"), use it directly
	var roleID string
	if strings.Contains(identity, ":") {
		roleID = identity
	} else {
		roleID = input.Account + ":host:" + identity
	}

	// Verify the role exists and has access to this authenticator
	if !a.store.RoleExists(roleID) {
		return "", errors.New("role not found or not authorized")
	}

	// TODO: Validate host annotations/restrictions against token claims

	return roleID, nil
}

// parseAndValidateToken parses and validates the JWT token
func (a *Authenticator) parseAndValidateToken(ctx context.Context, tokenString string) (*jwt.Token, error) {
	// Fetch JWKS if needed
	if err := a.refreshJWKSIfNeeded(ctx); err != nil {
		return nil, fmt.Errorf("failed to fetch signing keys: %w", err)
	}

	// Parse token with key lookup
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Verify signing method
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		// Get key ID from header
		kid, ok := token.Header["kid"].(string)
		if !ok {
			return nil, errors.New("missing kid in token header")
		}

		// Look up key
		a.jwksCache.mu.RLock()
		key, ok := a.jwksCache.keys[kid]
		a.jwksCache.mu.RUnlock()
		if !ok {
			// Try refreshing keys
			if err := a.refreshJWKS(ctx); err != nil {
				return nil, err
			}
			a.jwksCache.mu.RLock()
			key, ok = a.jwksCache.keys[kid]
			a.jwksCache.mu.RUnlock()
			if !ok {
				return nil, fmt.Errorf("key %s not found", kid)
			}
		}

		return key, nil
	}, jwt.WithValidMethods([]string{"RS256", "RS384", "RS512"}))

	if err != nil {
		return nil, err
	}

	// Validate standard claims
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("invalid claims format")
	}

	// Validate issuer if configured
	if a.config.Issuer != "" {
		iss, _ := claims["iss"].(string)
		if iss != a.config.Issuer {
			return nil, fmt.Errorf("invalid issuer: expected %s, got %s", a.config.Issuer, iss)
		}
	}

	// Validate audience if configured
	if a.config.Audience != "" {
		aud, _ := claims["aud"].(string)
		audList, _ := claims["aud"].([]interface{})
		validAud := aud == a.config.Audience
		for _, audItem := range audList {
			if audItem.(string) == a.config.Audience {
				validAud = true
				break
			}
		}
		if !validAud {
			return nil, errors.New("invalid audience")
		}
	}

	return token, nil
}

// extractIdentity extracts the identity from the token
func (a *Authenticator) extractIdentity(token *jwt.Token, loginFromURL string) (string, error) {
	claims, _ := token.Claims.(jwt.MapClaims)

	// If token-app-property is configured, use it
	if a.config.TokenAppProperty != "" {
		identity, ok := claims[a.config.TokenAppProperty].(string)
		if !ok || identity == "" {
			return "", fmt.Errorf("claim %s not found in token", a.config.TokenAppProperty)
		}
		return identity, nil
	}

	// Otherwise, use login from URL if provided
	if loginFromURL != "" {
		return loginFromURL, nil
	}

	// Default to "sub" claim
	sub, ok := claims["sub"].(string)
	if !ok || sub == "" {
		return "", errors.New("no identity found in token")
	}
	return sub, nil
}

// refreshJWKSIfNeeded refreshes JWKS if cache is expired
func (a *Authenticator) refreshJWKSIfNeeded(ctx context.Context) error {
	a.jwksCache.mu.RLock()
	expired := time.Now().After(a.jwksCache.expiresAt)
	a.jwksCache.mu.RUnlock()

	if expired {
		return a.refreshJWKS(ctx)
	}
	return nil
}

// refreshJWKS fetches fresh JWKS from the provider or uses inline public keys
func (a *Authenticator) refreshJWKS(ctx context.Context) error {
	// If account is set, load config from DB variables
	if a.account != "" {
		if err := a.loadConfigFromStore(); err != nil {
			return fmt.Errorf("failed to load config from DB: %w", err)
		}
	}

	// Check for inline public keys first
	if a.config.PublicKeys != "" {
		return a.loadInlinePublicKeys()
	}

	jwksURI := a.config.JWKSURI

	// If no direct JWKS URI, discover from provider
	if jwksURI == "" && a.config.ProviderURI != "" {
		discoveryURL := strings.TrimSuffix(a.config.ProviderURI, "/") + "/.well-known/openid-configuration"
		resp, err := http.Get(discoveryURL)
		if err != nil {
			return fmt.Errorf("failed to fetch OIDC discovery: %w", err)
		}
		defer func() { _ = resp.Body.Close() }()

		var discovery struct {
			JWKSURI string `json:"jwks_uri"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&discovery); err != nil {
			return fmt.Errorf("failed to parse OIDC discovery: %w", err)
		}
		jwksURI = discovery.JWKSURI
	}

	if jwksURI == "" {
		return errors.New("no JWKS URI configured")
	}

	// Fetch JWKS
	resp, err := http.Get(jwksURI)
	if err != nil {
		return fmt.Errorf("failed to fetch JWKS: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read JWKS: %w", err)
	}

	return a.parseJWKSBody(body)
}

// loadConfigFromStore loads authenticator configuration from Conjur variables
func (a *Authenticator) loadConfigFromStore() error {
	prefix := a.account + ":variable:conjur/authn-jwt/" + a.config.ServiceID + "/"

	// Helper to get decrypted variable value
	getVar := func(name string) (string, error) {
		resourceID := prefix + name
		value, err := a.store.FetchSecret(resourceID)
		if err != nil {
			return "", nil // Variable not set
		}
		return value, nil
	}

	// Load public-keys
	if pk, err := getVar("public-keys"); err != nil {
		return err
	} else if pk != "" {
		a.config.PublicKeys = pk
	}

	// Load issuer
	if issuer, err := getVar("issuer"); err != nil {
		return err
	} else if issuer != "" {
		a.config.Issuer = issuer
	}

	// Load token-app-property
	if tap, err := getVar("token-app-property"); err != nil {
		return err
	} else if tap != "" {
		a.config.TokenAppProperty = tap
	}

	// Load jwks-uri
	if jwksURI, err := getVar("jwks-uri"); err != nil {
		return err
	} else if jwksURI != "" {
		a.config.JWKSURI = jwksURI
	}

	// Load provider-uri
	if providerURI, err := getVar("provider-uri"); err != nil {
		return err
	} else if providerURI != "" {
		a.config.ProviderURI = providerURI
	}

	return nil
}

// loadInlinePublicKeys parses inline public keys in format: {"type": "jwks", "value": {"keys": [...]}}
func (a *Authenticator) loadInlinePublicKeys() error {
	var publicKeys struct {
		Type  string          `json:"type"`
		Value json.RawMessage `json:"value"`
	}
	if err := json.Unmarshal([]byte(a.config.PublicKeys), &publicKeys); err != nil {
		return fmt.Errorf("failed to parse public-keys: %w", err)
	}

	if publicKeys.Type != "jwks" {
		return fmt.Errorf("unsupported public-keys type: %s", publicKeys.Type)
	}

	return a.parseJWKSBody(publicKeys.Value)
}

// parseJWKSBody parses JWKS JSON and populates the key cache
func (a *Authenticator) parseJWKSBody(body []byte) error {
	// Parse JWKS
	var jwks struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(body, &jwks); err != nil {
		return fmt.Errorf("failed to parse JWKS: %w", err)
	}

	// Parse each key
	keys := make(map[string]*rsa.PublicKey)
	for _, keyData := range jwks.Keys {
		var keyInfo struct {
			Kid string `json:"kid"`
			Kty string `json:"kty"`
			N   string `json:"n"`
			E   string `json:"e"`
		}
		if err := json.Unmarshal(keyData, &keyInfo); err != nil {
			continue
		}
		if keyInfo.Kty != "RSA" {
			continue
		}

		// Parse RSA public key from JWK
		pubKey, err := parseRSAPublicKey(keyInfo.N, keyInfo.E)
		if err != nil {
			continue
		}
		keys[keyInfo.Kid] = pubKey
	}

	// Update cache
	a.jwksCache.mu.Lock()
	a.jwksCache.keys = keys
	a.jwksCache.expiresAt = time.Now().Add(5 * time.Minute)
	a.jwksCache.mu.Unlock()

	return nil
}

// Status checks if the authenticator is healthy
func (a *Authenticator) Status(ctx context.Context, account string, serviceID string) error {
	// Check if we can fetch JWKS
	return a.refreshJWKS(ctx)
}

// parseRSAPublicKey parses an RSA public key from JWK components
func parseRSAPublicKey(nBase64, eBase64 string) (*rsa.PublicKey, error) {
	// Decode N (modulus)
	nBytes, err := jwt.NewParser().DecodeSegment(nBase64)
	if err != nil {
		return nil, err
	}

	// Decode E (exponent)
	eBytes, err := jwt.NewParser().DecodeSegment(eBase64)
	if err != nil {
		return nil, err
	}

	// Convert exponent bytes to int
	var e int
	for _, b := range eBytes {
		e = e<<8 + int(b)
	}

	return &rsa.PublicKey{
		N: new(big.Int).SetBytes(nBytes),
		E: e,
	}, nil
}
